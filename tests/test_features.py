import httpx
import pytest
from fastapi.testclient import TestClient

from app import auth, config, notifier
from app import database as db
from app import ip_manager as ipm
from app.database import ConflictRule, Event, Reservation, SourceRecord, SourceStatus, Subnet
from app.opnsense_connector import OPNsenseConnector
from app.unifi_connector import UniFiConnector
from app.util import utcnow


@pytest.fixture()
def s():
    db.init_db("sqlite://")
    with db.SessionLocal() as s:
        yield s


def subnet(s):
    sn = Subnet(name="lan", cidr="192.168.1.0/28", gateway="192.168.1.1", l2=True,
                last_full_scan_at=utcnow(), last_full_scan_ok=True)
    s.add(sn); s.commit()
    return sn


def R(s, ip, src, name, mac=None, **kw):
    s.add(SourceRecord(source=src, kind=kw.pop("kind", "container"), name=name, ip=ip, mac=mac, **kw)); s.commit()


def inv(s):
    return ipm.build_inventory(s)[0]


def test_name_conflict_then_silenced_by_rule(s):
    subnet(s)
    R(s, "192.168.1.5", "dockhand", "a", "aa:aa:aa:aa:aa:01")
    R(s, "192.168.1.5", "proxmox", "b", "aa:aa:aa:aa:aa:02", kind="vm")
    assert inv(s)["192.168.1.5"]["conflict"]
    s.add(ConflictRule(ip="192.168.1.5", note="ok")); s.commit()
    e = inv(s)["192.168.1.5"]
    assert e["conflict"] is None and e["conflict_ignored"]


def test_rule_by_mac(s):
    subnet(s)
    R(s, "192.168.1.5", "dockhand", "a", "aa:aa:aa:aa:aa:01")
    R(s, "192.168.1.5", "proxmox", "b", "aa:aa:aa:aa:aa:02", kind="vm")
    s.add(ConflictRule(mac="aa:aa:aa:aa:aa:02")); s.commit()
    assert inv(s)["192.168.1.5"]["conflict"] is None


def test_host_mode_container_does_not_conflict(s):
    subnet(s)
    R(s, "192.168.1.5", "proxmox", "pve-host", "aa:aa:aa:aa:aa:02", kind="vm")
    R(s, "192.168.1.5", "dockhand", "nginx", "aa:aa:aa:aa:aa:09", extra={"network_mode": "host"})
    assert inv(s)["192.168.1.5"]["conflict"] is None


def test_dhcp_records_do_not_create_name_conflict(s):
    subnet(s)
    R(s, "192.168.1.5", "proxmox", "vm1", "aa:aa:aa:aa:aa:02", kind="vm")
    R(s, "192.168.1.5", "opnsense", "vm1-dhcp", "aa:aa:aa:aa:aa:02", kind="dhcp-lease", ip_origin="dhcp-lease")
    e = inv(s)["192.168.1.5"]
    assert e["conflict"] is None and set(e["sources"]) == {"proxmox", "opnsense"}


def test_dhcp_lease_marks_ip_used_for_first_free(s):
    sn = subnet(s)
    R(s, "192.168.1.2", "opnsense", "phone", "aa:aa:aa:aa:aa:03", kind="dhcp-lease", ip_origin="dhcp-lease")
    assert ipm.first_free(s, sn)["ip"] == "192.168.1.3"


# ---- auth
def test_password_hash_verify_and_sessions(s):
    assert not auth.configured(s)
    with pytest.raises(ValueError):
        auth.set_password(s, "short")
    auth.set_password(s, "correct horse")
    assert auth.configured(s) and auth.verify(s, "correct horse") and not auth.verify(s, "nope")
    assert "correct horse" not in str(db.meta_get(s, "settings_pw"))
    t = auth.new_session()
    assert auth.valid(t)
    auth.drop(t)
    assert not auth.valid(t)


def test_login_throttle():
    for _ in range(5):
        auth.record_fail("1.2.3.4")
    assert auth.throttled("1.2.3.4") and not auth.throttled("9.9.9.9")


def test_settings_endpoints_gated(tmp_path, monkeypatch):
    from app import main
    monkeypatch.setattr(main.scheduler.sched, "start", lambda: None)
    monkeypatch.setattr(main.scheduler.sched, "shutdown", lambda **k: None)
    monkeypatch.setattr(main.scheduler, "reschedule", lambda: None)
    monkeypatch.setattr(main.dd, "refresh_source", lambda n: None)
    monkeypatch.setattr(config, "DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
    with TestClient(main.app) as c:
        assert c.get("/api/settings").status_code == 200            # no password yet
        assert c.post("/api/auth/password", json={"password": "longenough1", "new_password": "longenough1"}).status_code == 200
        c.cookies.clear()
        assert c.get("/api/settings").status_code == 401
        assert c.get("/api/records").status_code == 401
        assert c.post("/api/test/proxmox", json={}).status_code == 401
        assert c.post("/api/auth/login", json={"password": "bad"}).status_code == 401
        assert c.post("/api/auth/login", json={"password": "longenough1"}).status_code == 200
        assert c.get("/api/settings").status_code == 200
        assert c.get("/api/settings").json()["webhook_url"] == ""   # empty secrets are not masked
        # conflict rules + csv
        assert c.post("/api/conflict-rules", json={"ip": "10.0.0.9"}).status_code == 200
        assert c.get("/api/conflict-rules").json()[0]["ip"] == "10.0.0.9"
        assert c.post("/api/conflict-rules", json={}).status_code == 422
        r = c.get("/api/export/ips.csv")
        assert r.status_code == 200 and r.text.startswith("﻿IP Address,Hostname")


def test_csv_injection_guard():
    from app.main import csv_safe, render_csv
    assert csv_safe("=1+1") == "'=1+1" and csv_safe("@x") == "'@x" and csv_safe("-2") == "'-2"
    assert csv_safe(["a", "b"]) == "a, b" and csv_safe(None) == "" and csv_safe("ok") == "ok"
    out = render_csv([{"ip": "1.1.1.1", "hostname": "=HYPERLINK(\"x\")", "sources": ["proxmox", "unifi"], "vlan": 20}])
    assert "'=HYPERLINK" in out and '"proxmox, unifi"' in out


# ---- notifier
def test_notifier_first_run_silent_then_events(s):
    subnet(s)
    s.add(Event(kind="new_host", ip="192.168.1.9", detail="old")); s.commit()
    st = db.get_settings(s)
    p, cur = notifier.collect(s, st)
    assert p == []
    db.meta_set(s, "notify_event_id", cur["event"]); db.meta_set(s, "notify_conflicts", cur["conflicts"]); db.meta_set(s, "notify_down", cur["down"])
    s.add(Event(kind="new_host", ip="192.168.1.10", detail="new")); s.add(Event(kind="online", ip="192.168.1.11")); s.commit()
    p, cur = notifier.collect(s, st)
    assert [x["event"] for x in p] == ["new_host"] and p[0]["ip"] == "192.168.1.10"   # 'online' not subscribed
    s.add(SourceStatus(source="proxmox", ok=False, error="timeout")); s.commit()
    db.meta_set(s, "notify_event_id", cur["event"])
    p, _ = notifier.collect(s, st)
    assert [x["event"] for x in p] == ["source_down"]


def test_notifier_posts_json(s, monkeypatch):
    seen = {}
    def fake_post(url, content, headers, **kw):
        seen.update(url=url, body=content, headers=headers)
        return httpx.Response(200, request=httpx.Request("POST", url))
    monkeypatch.setattr(notifier.httpx, "post", fake_post)
    st = db.get_settings(s) | {"webhook_url": "http://hook/x", "webhook_auth_header": "Bearer t"}
    assert notifier.test(st)["ok"]
    assert seen["headers"]["Authorization"] == "Bearer t" and '"event": "test"' in seen["body"]


# ---- connectors parse real HTTP shapes via httpx.MockTransport (transport-level, no fake connector)
def with_transport(conn, handler):
    conn.c = httpx.Client(base_url=str(conn.c.base_url), transport=httpx.MockTransport(handler), auth=conn.c.auth, headers=conn.c.headers)
    return conn


def test_opnsense_parsing_and_skipping():
    cfg = db_cfg(opnsense_url="https://fw", opnsense_key="k", opnsense_secret="s")
    def h(req):
        p = req.url.path
        if p == "/api/kea/leases4/search":
            return httpx.Response(200, json={"rows": [{"address": "192.168.1.50", "hwaddr": "AA:BB:CC:00:00:01", "hostname": "tv", "state": "0"},
                                                      {"address": "192.168.1.51", "hwaddr": "AA:BB:CC:00:00:02", "state": "expired"}]})
        if p == "/api/kea/dhcpv4/search_reservation":
            return httpx.Response(200, json={"rows": [{"ip_address": "192.168.1.60", "hw_address": "AA:BB:CC:00:00:03", "hostname": "nas"}]})
        return httpx.Response(404)
    c = with_transport(OPNsenseConnector(cfg), h)
    recs = c.fetch()
    ips = {r["ip"]: r for r in recs}
    assert set(ips) == {"192.168.1.50", "192.168.1.60"}   # expired lease skipped
    assert "192.168.1.60" in ips and ips["192.168.1.60"]["ip_origin"] == "dhcp-reservation"
    assert ips["192.168.1.50"]["mac"] == "aa:bb:cc:00:00:01"


def test_opnsense_auth_failure_reported():
    cfg = db_cfg(opnsense_url="https://fw", opnsense_key="k", opnsense_secret="s")
    c = with_transport(OPNsenseConnector(cfg), lambda r: httpx.Response(401))
    with pytest.raises(PermissionError):
        c.fetch()


def test_unifi_parsing_and_paging():
    cfg = db_cfg(unifi_url="https://u", unifi_api_key="k")
    def h(req):
        assert req.headers["x-api-key"] == "k"
        if req.url.path.endswith("/sites"):
            return httpx.Response(200, json={"data": [{"id": "s1", "name": "Default"}]})
        off = int(req.url.params["offset"])
        rows = [{"name": "cam", "ipAddress": "192.168.1.70", "macAddress": "AA:BB:CC:00:00:07", "type": "WIRED"},
                {"name": "noip", "macAddress": None}] if off == 0 else []
        return httpx.Response(200, json={"data": rows, "totalCount": 2})
    recs = with_transport(UniFiConnector(cfg), h).fetch()
    assert len(recs) == 1 and recs[0]["ip"] == "192.168.1.70" and recs[0]["ip_origin"] == "dhcp-client"


def db_cfg(**kw):
    d = dict(config.DEFAULTS)
    d.update(kw)
    return d


# ---- Dashboard: Docker ports / labels, services tiles, Proxmox overview ----

from app import services  # noqa: E402
from app.dockhand_connector import parse_container, parse_ports  # noqa: E402


def test_parse_ports_all_docker_shapes():
    assert parse_ports(["0.0.0.0:8080->80/tcp", "5432/tcp"]) == [
        {"ip": "0.0.0.0", "public": 8080, "private": 80, "type": "tcp"}]
    assert parse_ports([{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8096, "Type": "tcp"},
                        {"PrivatePort": 22}]) == [{"ip": "0.0.0.0", "public": 8096, "private": 80, "type": "tcp"}]
    assert parse_ports({"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8081"}], "9/tcp": None})[0]["public"] == 8081


def test_parse_container_keeps_only_dashboard_labels():
    c = {"Id": "abc", "Names": ["/jelly"], "Image": "jellyfin/jellyfin:latest", "State": {"Status": "running"},
         "Ports": [{"IP": "0.0.0.0", "PrivatePort": 8096, "PublicPort": 8096, "Type": "tcp"}],
         "Labels": {"dashboard.category": "Media", "other": "x"},
         "NetworkSettings": {"Networks": {"bridge": {"IPAddress": "172.17.0.2"}}}}
    recs, _ = parse_container(c, "local", {}, "docker1.lan")
    assert recs[0]["extra"]["labels"] == {"dashboard.category": "Media"}
    assert recs[0]["extra"]["env_host"] == "docker1.lan"
    assert recs[0]["ip"] == "172.17.0.2"


def test_categorize_and_icon():
    assert services.categorize("lscr.io/linuxserver/sonarr:4", "sonarr") == "Media"
    assert services.categorize("unknownthing", "x") == "Other"
    assert services.categorize("unknownthing", "x", "Custom") == "Custom"
    assert services.icon_url(None, "ghcr.io/x/jellyfin:10", "j").endswith("/jellyfin.png")
    assert services.icon_url("https://e.x/i.svg", "", "") == "https://e.x/i.svg"


def _container(s, cid, name, image, ports, labels=None, host="docker1.lan"):
    extra = {"container_id": cid, "image": image, "environment": "local", "labels": labels or {},
             "ports": ports, "env_host": host}
    s.add(SourceRecord(source="dockhand", kind="container", name=name, state="running", extra=extra))
    s.commit()


def test_build_services_links_labels_and_hide(s):
    pub = [{"ip": "0.0.0.0", "public": 8096, "private": 8096, "type": "tcp"}]
    _container(s, "c1", "jellyfin", "jellyfin/jellyfin", pub)
    _container(s, "c1", "jellyfin", "jellyfin/jellyfin", pub)  # second network record, same container
    _container(s, "c2", "db", "postgres", [{"ip": "0.0.0.0", "public": 5432, "private": 5432, "type": "tcp"}],
               labels={"dashboard.hide": "true"})
    _container(s, "c3", "nas", "nginx", [{"ip": "127.0.0.1", "public": 9000, "private": 80, "type": "tcp"}])
    _container(s, "c4", "wiki", "bookstack", [], labels={"dashboard.url": "https://wiki.lan",
                                                         "dashboard.description": "Docs"})
    out = services.build_services(s)
    names = [x["name"] for x in out]
    assert names == ["jellyfin", "wiki"]  # db hidden, nas loopback-only and no url -> skipped, c1 deduped
    jelly = out[0]
    assert jelly["url"] == "http://docker1.lan:8096" and jelly["category"] == "Media"
    assert out[1]["url"] == "https://wiki.lan" and out[1]["description"] == "Docs"


def test_build_proxmox_stats_and_node_excluded_from_devices(s):
    subnet(s)
    s.add(SourceStatus(source="proxmox", ok=True, last_ok=utcnow(), count=3))
    s.add(SourceRecord(source="proxmox", kind="node", name="pve1", ip=None, state="online",
                       extra={"cluster": "home", "cpu": 0.5, "maxcpu": 4, "mem": 2 * 2**30, "maxmem": 8 * 2**30,
                              "disk": 10 * 2**30, "maxdisk": 100 * 2**30, "uptime": 90000}))
    s.add(SourceRecord(source="proxmox", kind="node", name="pve2", ip=None, state="offline",
                       extra={"cluster": "home", "cpu": 0, "maxcpu": 8, "mem": 0, "maxmem": 2**30,
                              "disk": 0, "maxdisk": 2**30}))
    R(s, "192.168.1.10", "proxmox", "web", "aa:aa:aa:aa:aa:10", kind="vm", state="running", extra={"vmid": 100, "node": "pve1"})
    R(s, "192.168.1.10", "proxmox", "web", "aa:aa:aa:aa:aa:10", kind="vm", state="running", extra={"vmid": 100, "node": "pve1"})
    R(s, None, "proxmox", "ct", None, kind="lxc", state="stopped", extra={"ctid": 101, "node": "pve1"})
    p = services.build_proxmox(s)
    assert p["nodes_total"] == 2 and p["nodes_online"] == 1
    assert p["vms_running"] == 1 and p["vms_total"] == 1  # deduped NIC records
    assert p["lxc_running"] == 0 and p["lxc_total"] == 1
    assert p["cpu_pct"] == 50.0 and p["cores"] == 4  # cpu is a 0..1 fraction; only online nodes count
    assert p["mem_total"] == 8 * 2**30 and p["ok"] is True
    # node records have no IP: they must not be listed as devices without IP
    assert all(x["name"] != "pve1" for x in ipm.summary(s).get("no_ip", []))


def test_dashboard_api_route(tmp_path, monkeypatch):
    from app import main
    monkeypatch.setattr(main.scheduler.sched, "start", lambda: None)
    monkeypatch.setattr(main.scheduler.sched, "shutdown", lambda **k: None)
    monkeypatch.setattr(main.scheduler, "reschedule", lambda: None)
    monkeypatch.setattr(main.dd, "refresh_source", lambda n: None)
    monkeypatch.setattr(config, "DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
    with TestClient(main.app) as c:
        with db.SessionLocal() as s:
            _container(s, "c1", "jellyfin", "jellyfin/jellyfin",
                       [{"ip": "0.0.0.0", "public": 8096, "private": 8096, "type": "tcp"}])
        r = c.get("/api/dashboard")
        assert r.status_code == 200
        body = r.json()
        assert body["proxmox"]["configured"] is False
        assert body["services"][0]["name"] == "jellyfin"
