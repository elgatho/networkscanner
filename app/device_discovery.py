"""Runs scans and integration refreshes and persists results + history."""
import ipaddress
import logging
import threading
from sqlalchemy import delete, select

from . import database as db
from . import network_scanner as ns
from .database import Event, Reservation, ScanResult, ScanRun, SourceRecord, SourceStatus, Subnet
from .dockhand_connector import DockhandConnector
from .esphome_connector import ESPHomeConnector
from .opnsense_connector import OPNsenseConnector
from .unifi_connector import UniFiConnector
from .ip_manager import net_of
from .proxmox_connector import ProxmoxConnector
from .util import norm_ip, utcnow

log = logging.getLogger(__name__)
_locks: dict[int, threading.Lock] = {}
_src_locks = {k: threading.Lock() for k in ("dockhand", "proxmox", "esphome", "opnsense", "unifi")}
CONNECTORS = {"dockhand": DockhandConnector, "proxmox": ProxmoxConnector, "esphome": ESPHomeConnector,
              "opnsense": OPNsenseConnector, "unifi": UniFiConnector}


def scan_running(subnet_id):
    lk = _locks.get(subnet_id)
    return bool(lk and lk.locked())


def known_targets(s, sn, net):
    ips = set()
    ips |= set(s.scalars(select(ScanResult.ip).where(ScanResult.subnet_id == sn.id)))
    ips |= {i for i in s.scalars(select(SourceRecord.ip).where(SourceRecord.ip.is_not(None)))}
    ips |= set(s.scalars(select(Reservation.ip)))
    if sn.gateway:
        ips.add(norm_ip(sn.gateway))
    # never probe anything outside the configured subnet
    return sorted(i for i in ips if i and ipaddress.ip_address(i) in net)


def scan_subnet(subnet_id, kind="discovery"):
    """kind: 'discovery' (known addresses + neighbour table) or 'full' (whole subnet)."""
    lock = _locks.setdefault(subnet_id, threading.Lock())
    if not lock.acquire(blocking=False):
        return {"skipped": "scan already running for this subnet"}
    s = db.SessionLocal()
    run = None
    try:
        sn = s.get(Subnet, subnet_id)
        if not sn or not sn.enabled:
            return {"skipped": "subnet missing or disabled"}
        st = db.get_settings(s)
        net = net_of(sn)
        run = ScanRun(subnet_id=sn.id, kind=kind)
        s.add(run)
        s.commit()
        now = utcnow()
        full = kind == "full"
        v6 = net.version == 6
        if full and (v6 or net.num_addresses > st["max_scan_hosts"]):
            if v6:
                full = False  # IPv6 ranges cannot be swept: known addresses + NDP only
            else:
                raise RuntimeError(f"{sn.cidr} has more than max_scan_hosts={st['max_scan_hosts']} addresses")
        targets = str(net) if full else known_targets(s, sn, net)
        found = ns.nmap_sweep(targets, ipv6=v6, max_rate=st["nmap_max_rate"]) if targets else {}
        methods = ["nmap"]
        if full and st["arp_scan"] and not v6 and ns.available("arp-scan"):
            try:
                for ip, d in ns.arp_scan(str(net)).items():
                    found.setdefault(ip, d)
                methods.append("arp-scan")
            except Exception as e:
                log.warning("arp-scan failed: %s", e)
        found = {ip: d for ip, d in found.items() if ipaddress.ip_address(ip) in net}
        neigh = {ip: n for ip, n in ns.neigh_table().items() if ipaddress.ip_address(ip) in net}
        for ip, n in neigh.items():  # ARP/NDP evidence also gives us a MAC for hosts nmap saw
            if ip in found and not found[ip].get("mac"):
                found[ip]["mac"] = n["mac"]
        if st["reverse_dns"]:
            names = ns.reverse_dns([ip for ip, d in found.items() if not d.get("hostname")])
            for ip, n in names.items():
                found[ip]["hostname"] = n
        if full and st["port_scan"] and found:
            for ip, ports in ns.port_scan(list(found), st["port_list"]).items():
                if ip in found:
                    found[ip]["ports"] = ports
        existing = {r.ip: r for r in s.scalars(select(ScanResult).where(ScanResult.subnet_id == sn.id))}
        checked = set(found) | (set(existing) if full else set(targets if isinstance(targets, list) else []))
        for ip in set(found) | set(neigh) | checked:
            r = existing.get(ip)
            d = found.get(ip)
            n = neigh.get(ip)
            if r is None:
                if not d and not n:
                    continue
                r = ScanResult(ip=ip, subnet_id=sn.id, alive=False)
                s.add(r)
                existing[ip] = r
            was_alive = bool(r.alive)
            if d:
                mac = d.get("mac") or (n or {}).get("mac") or r.mac
                if r.mac and mac and r.mac != mac:
                    s.add(Event(kind="mac_changed", ip=ip, mac=mac, subnet_id=sn.id, detail=f"{r.mac} -> {mac}"))
                if not r.first_seen:
                    s.add(Event(kind="new_host", ip=ip, mac=mac, subnet_id=sn.id, detail=d.get("hostname") or ""))
                    for o in existing.values():  # same MAC seen on another, now-silent IP
                        if mac and o.ip != ip and o.mac == mac and not o.alive:
                            s.add(Event(kind="ip_changed", ip=ip, mac=mac, subnet_id=sn.id, detail=f"{o.ip} -> {ip}"))
                            break
                r.mac, r.vendor = mac, d.get("vendor") or ns.oui_lookup(mac) or r.vendor
                r.hostname = d.get("hostname") or r.hostname
                if "ports" in d:
                    r.ports = d["ports"]
                r.alive, r.last_seen = True, now
                r.first_seen = r.first_seen or now
                if not was_alive and r.first_seen != now:
                    s.add(Event(kind="online", ip=ip, mac=r.mac, subnet_id=sn.id))
            elif ip in checked:
                r.alive = False
                if was_alive:
                    s.add(Event(kind="offline", ip=ip, mac=r.mac, subnet_id=sn.id))
            if ip in checked:
                r.last_checked = now
            if n:
                r.neigh_state = n["state"]
                r.mac = r.mac or n["mac"]
            elif ip in checked:
                r.neigh_state = None
        if not (ns.available("nmap")):
            raise RuntimeError("nmap not installed")
        sn.last_scan_at = utcnow()
        sn.last_scan_status = f"ok ({kind}): {len(found)} host(s) up"
        if full:
            sn.last_full_scan_at, sn.last_full_scan_ok = sn.last_scan_at, True
            sn.l2 = any(d.get("mac") for d in found.values()) or bool(neigh and found) or sn.l2
        run.status, run.found = "ok", len(found)
        run.finished = utcnow()
        s.commit()
        return {"ok": True, "found": len(found)}
    except Exception as e:
        s.rollback()
        log.exception("scan %s/%s failed", subnet_id, kind)
        sn = s.get(Subnet, subnet_id)
        if sn:
            sn.last_scan_at, sn.last_scan_status = utcnow(), f"error ({kind}): {e}"[:190]
            if kind == "full":
                sn.last_full_scan_ok = False
        if run is not None and run.id:
            r2 = s.get(ScanRun, run.id)
            r2.status, r2.message, r2.finished = "error", str(e)[:500], utcnow()
        s.commit()
        return {"ok": False, "error": str(e)}
    finally:
        s.close()
        lock.release()


def refresh_source(name):
    lk = _src_locks[name]
    if not lk.acquire(blocking=False):
        return {"skipped": "already running"}
    s = db.SessionLocal()
    try:
        st = db.get_settings(s)
        status = s.get(SourceStatus, name) or SourceStatus(source=name)
        s.add(status)
        status.last_run = utcnow()
        if not st[f"{name}_enabled"]:
            status.ok, status.error = False, "disabled"
            s.commit()
            return {"skipped": "disabled"}
        try:
            recs = CONNECTORS[name](st).fetch()
        except Exception as e:  # keep previous snapshot on failure
            status.ok, status.error = False, f"{type(e).__name__}: {e}"[:500]
            s.commit()
            log.warning("source %s failed: %s", name, status.error)
            return {"ok": False, "error": status.error}
        old = s.scalars(select(SourceRecord).where(SourceRecord.source == name)).all()
        old_map = {(o.kind, o.name, o.mac or ""): o.ip for o in old}
        s.execute(delete(SourceRecord).where(SourceRecord.source == name))
        now = utcnow()
        for r in recs:
            s.add(SourceRecord(source=name, kind=r["kind"], name=r["name"] or "?", ip=norm_ip(r.get("ip")),
                               mac=r.get("mac"), hostname=r.get("hostname"), ip_origin=r.get("ip_origin", "configured"),
                               state=r.get("state"), vlan=r.get("vlan"), extra=r.get("extra") or {}, updated_at=now))
            k = (r["kind"], r["name"] or "?", r.get("mac") or "")
            ip = norm_ip(r.get("ip"))
            if k in old_map and old_map[k] != ip and ip:
                s.add(Event(kind="ip_changed", ip=ip, mac=r.get("mac"),
                            detail=f"{name}:{r['name']} {old_map[k]} -> {ip}"))
            elif k not in old_map and old:
                s.add(Event(kind="source_new", ip=ip, mac=r.get("mac"), detail=f"{name}:{r['name']}"))
        status.ok, status.error, status.last_ok, status.count = True, "", now, len(recs)
        s.commit()
        return {"ok": True, "count": len(recs)}
    finally:
        s.close()
        lk.release()


def test_source(name, st):
    try:
        return CONNECTORS[name](st).test()
    except Exception as e:
        return {"ok": False, "message": f"{type(e).__name__}: {e}"[:400]}
