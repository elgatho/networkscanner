import asyncio
import ipaddress
import logging
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import or_, select

import csv
import io
from . import auth as authmod, config, notifier, database as db, device_discovery as dd, ip_manager as ipm, scheduler, services
from .database import ConflictRule, Event, Reservation, ScanResult, ScanRun, SourceRecord, SourceStatus, Subnet
from .util import iso, norm_ip, norm_mac

logging.basicConfig(level=config.LOG_LEVEL, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
STATIC = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app):
    db.init_db()
    scheduler.sched.start()
    scheduler.reschedule()
    # warm up: first source pull + discovery shortly after start
    loop = asyncio.get_running_loop()
    for n in dd.CONNECTORS:
        loop.run_in_executor(None, dd.refresh_source, n)
    yield
    scheduler.sched.shutdown(wait=False)


app = FastAPI(title="Network Discovery & IP Scanner", lifespan=lifespan)


@app.middleware("http")
async def auth(request: Request, call_next):
    if config.ACCESS_TOKEN and request.url.path.startswith("/api/") and request.url.path != "/api/health":
        tok = request.headers.get("x-access-token") or request.query_params.get("token")
        if tok != config.ACCESS_TOKEN:
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return await call_next(request)


def session():
    s = db.SessionLocal()
    try:
        yield s
    finally:
        s.close()


def need_settings_auth(request: Request, s=Depends(session)):
    """Settings area: requires a login session once a password has been configured."""
    if authmod.configured(s) and not authmod.valid(request.cookies.get("sess")):
        raise HTTPException(401, "settings login required")


class PwIn(BaseModel):
    password: str
    new_password: str | None = None


@app.get("/api/auth/status")
def auth_status(request: Request, s=Depends(session)):
    cfgd = authmod.configured(s)
    return {"configured": cfgd, "env_managed": authmod.env_managed(),
            "authenticated": (not cfgd) or authmod.valid(request.cookies.get("sess"))}


def _login_cookie(resp, tok):
    resp.set_cookie("sess", tok, httponly=True, samesite="strict", max_age=config.SESSION_HOURS * 3600,
                    secure=False)  # HTTPS is typically terminated by a proxy; SameSite=Strict + HttpOnly set
    return resp


@app.post("/api/auth/login")
def auth_login(d: PwIn, request: Request, s=Depends(session)):
    who = request.client.host if request.client else "?"
    if authmod.throttled(who):
        raise HTTPException(429, "too many failed attempts, try again in a few minutes")
    if not authmod.configured(s) or not authmod.verify(s, d.password):
        authmod.record_fail(who)
        raise HTTPException(401, "wrong password")
    return _login_cookie(JSONResponse({"ok": True}), authmod.new_session())


@app.post("/api/auth/logout")
def auth_logout(request: Request):
    authmod.drop(request.cookies.get("sess"))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("sess")
    return resp


@app.post("/api/auth/password")
def auth_password(d: PwIn, request: Request, s=Depends(session)):
    """First-time setup (no password yet) or change (needs the current one in `password`)."""
    if authmod.env_managed():
        raise HTTPException(409, "password is managed by the SETTINGS_PASSWORD environment variable")
    try:
        if authmod.configured(s):
            who = request.client.host if request.client else "?"
            if authmod.throttled(who):
                raise HTTPException(429, "too many failed attempts")
            if not authmod.verify(s, d.password):
                authmod.record_fail(who)
                raise HTTPException(401, "wrong current password")
            authmod.set_password(s, d.new_password or "")
        else:
            authmod.set_password(s, d.new_password or d.password)
    except ValueError as e:
        raise HTTPException(422, str(e))
    return _login_cookie(JSONResponse({"ok": True}), authmod.new_session())


@app.get("/api/health")
def health(s=Depends(session)):
    s.execute(select(1))
    return {"status": "ok", "version": config.APP_VERSION}


@app.get("/api/summary")
def get_summary(s=Depends(session)):
    return ipm.summary(s)


@app.get("/api/dashboard")
def get_dashboard(s=Depends(session)):
    return services.dashboard(s)


@app.get("/api/ips")
def get_ips(s=Depends(session)):
    entries, _ = ipm.build_inventory(s)
    out = []
    for e in entries.values():
        e = {k: v for k, v in e.items() if k not in ("last_seen",)}
        out.append(e)
    out.sort(key=lambda e: (ipaddress.ip_address(e["ip"]).version, int(ipaddress.ip_address(e["ip"]))))
    return out


# ---- subnets
class SubnetIn(BaseModel):
    name: str
    cidr: str
    gateway: str | None = None
    vlan: int | None = None
    description: str = ""
    scan_interval: int | None = None
    enabled: bool = True
    exclusions: list[str] = []


def _apply(sn, d: SubnetIn):
    try:
        net = ipaddress.ip_network(d.cidr.strip(), strict=False)
    except ValueError as e:
        raise HTTPException(422, f"invalid CIDR: {e}")
    gw = norm_ip(d.gateway) if d.gateway else None
    if d.gateway and (not gw or ipaddress.ip_address(gw) not in net):
        raise HTTPException(422, "gateway must be an address inside the subnet")
    sn.name, sn.cidr, sn.gateway, sn.vlan = d.name, str(net), gw, d.vlan
    sn.description, sn.scan_interval, sn.enabled, sn.exclusions = d.description, d.scan_interval, d.enabled, d.exclusions


@app.get("/api/subnets")
def list_subnets(s=Depends(session)):
    entries, subnets = ipm.build_inventory(s)
    st = db.get_settings(s)
    return [ipm.subnet_view(s, sn, entries, st) | {"scan_running": dd.scan_running(sn.id)} for sn in subnets]


@app.post("/api/subnets")
def add_subnet(d: SubnetIn, s=Depends(session)):
    sn = Subnet()
    _apply(sn, d)
    if s.scalar(select(Subnet).where(Subnet.cidr == sn.cidr)):
        raise HTTPException(409, "subnet already exists")
    s.add(sn)
    s.commit()
    scheduler.reschedule()
    return {"id": sn.id}


@app.put("/api/subnets/{sid}")
def edit_subnet(sid: int, d: SubnetIn, s=Depends(session)):
    sn = s.get(Subnet, sid) or _404()
    _apply(sn, d)
    s.commit()
    scheduler.reschedule()
    return {"ok": True}


@app.delete("/api/subnets/{sid}")
def del_subnet(sid: int, s=Depends(session)):
    sn = s.get(Subnet, sid) or _404()
    s.query(ScanResult).filter(ScanResult.subnet_id == sid).delete()
    s.delete(sn)
    s.commit()
    scheduler.reschedule()
    return {"ok": True}


def _404():
    raise HTTPException(404, "not found")


# ---- scans / sources
@app.post("/api/scan")
def manual_scan(subnet_id: int | None = None, kind: str = "full", s=Depends(session)):
    if kind not in ("full", "discovery"):
        raise HTTPException(422, "kind must be full|discovery")
    ids = [subnet_id] if subnet_id else list(s.scalars(select(Subnet.id).where(Subnet.enabled)))
    started = []
    for i in ids:
        if dd.scan_running(i):
            continue
        threading.Thread(target=dd.scan_subnet, args=(i, kind), daemon=True).start()
        started.append(i)
    if subnet_id and not started:
        raise HTTPException(409, "scan already running for this subnet")
    return {"started": started}


@app.post("/api/refresh/{name}")
def refresh(name: str):
    if name not in dd.CONNECTORS:
        _404()
    threading.Thread(target=dd.refresh_source, args=(name,), daemon=True).start()
    return {"started": name}


@app.get("/api/sources")
def sources(s=Depends(session)):
    return [{"source": x.source, "ok": x.ok, "error": x.error, "count": x.count,
             "last_run": iso(x.last_run), "last_ok": iso(x.last_ok)} for x in s.scalars(select(SourceStatus))]


@app.get("/api/records", dependencies=[Depends(need_settings_auth)])
def records(source: str | None = None, s=Depends(session)):
    """Raw per-source records (what each integration returned), for troubleshooting."""
    q = select(SourceRecord)
    if source:
        q = q.where(SourceRecord.source == source)
    return [{"source": r.source, "kind": r.kind, "name": r.name, "ip": r.ip, "mac": r.mac, "ip_origin": r.ip_origin,
             "vlan": r.vlan, "state": r.state, "extra": r.extra} for r in s.scalars(q)]


@app.get("/api/scans")
def scans(limit: int = 50, s=Depends(session)):
    rows = s.scalars(select(ScanRun).order_by(ScanRun.id.desc()).limit(limit))
    return [{"id": r.id, "subnet_id": r.subnet_id, "kind": r.kind, "started": iso(r.started), "finished": iso(r.finished),
             "status": r.status, "found": r.found, "message": r.message} for r in rows]


@app.get("/api/events")
def events(limit: int = 200, s=Depends(session)):
    return [_ev(e) for e in s.scalars(select(Event).order_by(Event.id.desc()).limit(limit))]


def _ev(e):
    return {"ts": iso(e.ts), "kind": e.kind, "ip": e.ip, "mac": e.mac, "detail": e.detail}


# ---- device
@app.get("/api/device")
def device(key: str, s=Depends(session)):
    entries, _ = ipm.build_inventory(s)
    mine = [e for e in entries.values() if e["device_key"] == key]
    if not mine:
        _404()
    macs = {e["mac"] for e in mine if e["mac"]}
    ips = {e["ip"] for e in mine}
    all_ips = set(ips)
    if macs:  # every IP carrying one of the MACs (multi-homed devices)
        mine = [e for e in entries.values() if e["mac"] in macs]
        all_ips = {e["ip"] for e in mine}
    recs = s.scalars(select(SourceRecord).where(or_(SourceRecord.mac.in_(macs), SourceRecord.ip.in_(all_ips))))
    evs = s.scalars(select(Event).where(or_(Event.mac.in_(macs), Event.ip.in_(all_ips))).order_by(Event.id.desc()).limit(200))
    e0 = mine[0]
    return {"key": key, "ips": sorted(all_ips), "macs": sorted(macs), "hostnames": sorted({e["hostname"] for e in mine if e["hostname"]}),
            "names": sorted({e["device_name"] for e in mine if e["device_name"]}), "manufacturer": e0["manufacturer"],
            "sources": sorted({x for e in mine for x in e["sources"]}), "entries": mine,
            "records": [{"source": r.source, "kind": r.kind, "name": r.name, "ip": r.ip, "ip_origin": r.ip_origin,
                         "state": r.state, "extra": r.extra} for r in recs],
            "last_seen": max((e["last_seen_iso"] for e in mine if e["last_seen_iso"]), default=None),
            "events": [_ev(e) for e in evs]}


# ---- reservations
class ResIn(BaseModel):
    ip: str
    note: str = ""


@app.get("/api/reservations")
def res_list(s=Depends(session)):
    return [{"id": r.id, "ip": r.ip, "note": r.note} for r in s.scalars(select(Reservation))]


@app.post("/api/reservations")
def res_add(d: ResIn, s=Depends(session)):
    ip = norm_ip(d.ip) or HTTPException(422, "invalid IP")
    if isinstance(ip, HTTPException):
        raise ip
    if s.scalar(select(Reservation).where(Reservation.ip == ip)):
        raise HTTPException(409, "already reserved")
    s.add(Reservation(ip=ip, note=d.note))
    s.commit()
    return {"ok": True}


@app.delete("/api/reservations/{rid}")
def res_del(rid: int, s=Depends(session)):
    r = s.get(Reservation, rid) or _404()
    s.delete(r)
    s.commit()
    return {"ok": True}


# ---- settings
MASK = "********"


@app.get("/api/settings", dependencies=[Depends(need_settings_auth)])
def get_settings(s=Depends(session)):
    st = db.get_settings(s)
    return {k: (MASK if k in config.SECRETS and v else v) for k, v in st.items()}


@app.put("/api/settings", dependencies=[Depends(need_settings_auth)])
def put_settings(body: dict, s=Depends(session)):
    upd = {k: v for k, v in body.items() if not (k in config.SECRETS and v == MASK)}
    try:
        db.set_settings(s, upd)
    except (ValueError, TypeError) as e:
        raise HTTPException(422, str(e))
    scheduler.reschedule()
    return {"ok": True}


@app.post("/api/test/{name}", dependencies=[Depends(need_settings_auth)])
def test_conn(name: str, body: dict | None = None, s=Depends(session)):
    if name not in dd.CONNECTORS:
        _404()
    st = db.get_settings(s)
    for k, v in (body or {}).items():  # allow testing unsaved form values
        if k in st and not (k in config.SECRETS and v == MASK):
            st[k] = v
    return dd.test_source(name, st)


@app.post("/api/webhook/test", dependencies=[Depends(need_settings_auth)])
def webhook_test(body: dict | None = None, s=Depends(session)):
    st = db.get_settings(s)
    for k, v in (body or {}).items():
        if k.startswith("webhook_") and k in st and not (k in config.SECRETS and v == MASK):
            st[k] = v
    return notifier.test(st)


# ---- conflict silencing
class RuleIn(BaseModel):
    ip: str | None = None
    mac: str | None = None
    note: str = ""


@app.get("/api/conflict-rules")
def rules_list(s=Depends(session)):
    return [{"id": r.id, "ip": r.ip, "mac": r.mac, "note": r.note, "created_at": iso(r.created_at)}
            for r in s.scalars(select(ConflictRule))]


@app.post("/api/conflict-rules")
def rules_add(d: RuleIn, s=Depends(session)):
    ip = norm_ip(d.ip) if d.ip else None
    mac = norm_mac(d.mac) if d.mac else None
    if (d.ip and not ip) or (d.mac and not mac) or not (ip or mac):
        raise HTTPException(422, "provide a valid IP and/or MAC")
    s.add(ConflictRule(ip=ip, mac=mac, note=d.note[:500]))
    s.commit()
    return {"ok": True}


@app.delete("/api/conflict-rules/{rid}")
def rules_del(rid: int, s=Depends(session)):
    r = s.get(ConflictRule, rid) or _404()
    s.delete(r)
    s.commit()
    return {"ok": True}


# ---- CSV export
CSV_COLS = [("ip", "IP Address"), ("hostname", "Hostname"), ("device_name", "Device Name"), ("mac", "MAC Address"),
            ("manufacturer", "Manufacturer"), ("device_type", "Device Type"), ("sources", "Source"),
            ("subnet", "Subnet"), ("vlan", "VLAN"), ("status", "Status"), ("last_seen_iso", "Last Seen")]


def csv_safe(v):
    """Neutralise spreadsheet formula injection (=, +, -, @, tab, CR at the start of a cell)."""
    if v is None:
        return ""
    if isinstance(v, (list, tuple, set)):
        v = ", ".join(map(str, v))
    v = str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def render_csv(rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([h for _, h in CSV_COLS])
    for e in rows:
        w.writerow([csv_safe(e.get(k)) for k, _ in CSV_COLS])
    return "\ufeff" + buf.getvalue()  # BOM so Excel reads UTF-8


@app.get("/api/export/ips.csv")
def export_csv(q: str = "", subnet: str = "", vlan: str = "", status: str = "", source: str = "", s=Depends(session)):
    rows = get_ips(s)
    ql = q.lower().strip()
    def ok(e):
        if subnet and str(e.get("subnet")) != subnet:
            return False
        if vlan and str(e.get("vlan") or "") != vlan:
            return False
        if status and e.get("status") != status:
            return False
        if source and source not in e.get("sources", []):
            return False
        if ql and ql not in " ".join(str(e.get(k) or "") for k, _ in CSV_COLS).lower():
            return False
        return True
    body = render_csv([e for e in rows if ok(e)])
    return Response(body, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="ip-addresses.csv"'})


app.mount("/assets", StaticFiles(directory=STATIC), name="assets")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
