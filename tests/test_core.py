from datetime import timedelta

import pytest

from app import database as db
from app import ip_manager as ipm
from app.database import Reservation, ScanResult, SourceRecord, SourceStatus, Subnet
from app.dockhand_connector import parse_container, parse_networks
from app.network_scanner import parse_nmap_xml
from app.proxmox_connector import conf_ip, parse_lxc_net, parse_qemu_net
from app.util import norm_ip, norm_mac, utcnow


@pytest.fixture()
def s():
    db.init_db("sqlite://")
    with db.SessionLocal() as s:
        yield s


def mk(s, cidr="192.168.1.0/29", gw="192.168.1.1", scanned=True, **kw):
    sn = Subnet(name="lan", cidr=cidr, gateway=gw, vlan=10, exclusions=kw.get("excl", []), l2=kw.get("l2", True))
    if scanned:
        sn.last_full_scan_at, sn.last_full_scan_ok = utcnow(), True
    s.add(sn)
    s.commit()
    return sn


def rec(s, ip, src="dockhand", name="x", **kw):
    s.add(SourceRecord(source=src, kind="container", name=name, ip=ip, **kw))
    s.commit()


def test_normalization():
    assert norm_ip("::ffff:10.0.0.5") == "10.0.0.5"
    assert norm_ip("fe80::1") is None and norm_ip("127.0.0.1") is None
    assert norm_ip("192.168.1.5/24") == "192.168.1.5"
    assert norm_mac("BC-24-11-AA-BB-CC") == "bc:24:11:aa:bb:cc"
    assert norm_mac("00:00:00:00:00:00") is None


def test_first_free_skips_gateway_sources_reservation_and_scan(s):
    sn = mk(s)  # hosts .1-.6
    rec(s, "192.168.1.2")                                   # source
    s.add(Reservation(ip="192.168.1.3")); s.commit()        # manual
    s.add(ScanResult(ip="192.168.1.4", subnet_id=sn.id, alive=True, last_seen=utcnow())); s.commit()
    r = ipm.first_free(s, sn)
    assert r["ip"] == "192.168.1.5" and r["confidence"] == "HIGH" and r["vlan"] == 10


def test_ping_silence_alone_is_not_free_when_known_offline(s):
    sn = mk(s)
    s.add(ScanResult(ip="192.168.1.2", subnet_id=sn.id, alive=False, last_seen=utcnow() - timedelta(hours=2))); s.commit()
    assert ipm.first_free(s, sn)["ip"] == "192.168.1.3"


def test_neighbour_entry_blocks(s):
    sn = mk(s)
    s.add(ScanResult(ip="192.168.1.2", subnet_id=sn.id, alive=False, neigh_state="STALE")); s.commit()
    assert ipm.first_free(s, sn)["ip"] == "192.168.1.3"


def test_long_gone_address_is_offered_with_low_confidence(s):
    sn = mk(s)
    s.add(ScanResult(ip="192.168.1.2", subnet_id=sn.id, alive=False, last_seen=utcnow() - timedelta(days=30))); s.commit()
    r = ipm.first_free(s, sn)
    assert r["ip"] == "192.168.1.2" and r["confidence"] == "LOW"


def test_confidence_levels(s):
    assert ipm.first_free(s, mk(s, scanned=False))["confidence"] == "LOW"
    s2 = mk(s, cidr="10.0.0.0/29", gw="10.0.0.1", l2=False)
    assert ipm.first_free(s, s2)["confidence"] == "MEDIUM"


def test_failed_enabled_source_downgrades(s):
    sn = mk(s)
    db.set_settings(s, {"proxmox_enabled": True})
    s.add(SourceStatus(source="proxmox", ok=False, error="boom")); s.commit()
    r = ipm.first_free(s, sn)
    assert r["confidence"] == "MEDIUM" and any("proxmox" in w for w in r["warnings"])


def test_exclusions_and_full_subnet(s):
    sn = mk(s, excl=["192.168.1.2-192.168.1.5"])
    assert ipm.first_free(s, sn)["ip"] == "192.168.1.6"
    rec(s, "192.168.1.6")
    assert ipm.first_free(s, sn)["ip"] is None


def test_multiple_subnets_and_duplicates(s):
    mk(s); mk(s, cidr="10.10.10.0/29", gw="10.10.10.1")
    rec(s, "192.168.1.2", name="a"); rec(s, "192.168.1.2", src="proxmox", name="b")
    entries, subs = ipm.build_inventory(s)
    assert entries["192.168.1.2"]["conflict"]
    ff = ipm.summary(s)["first_free"]
    assert {f["cidr"]: f["ip"] for f in ff} == {"192.168.1.0/29": "192.168.1.3", "10.10.10.0/29": "10.10.10.2"}


def test_out_of_subnet_ips_ignored_and_stats(s):
    sn = mk(s)
    rec(s, "172.17.0.2")
    rec(s, "192.168.1.2")
    v = ipm.subnet_view(s, sn)
    assert v["usable"] == 6 and v["used"] == 2 and v["free"] == 4  # source + gateway
    assert v["cells"] == "G" + "R" + "...."[:4]


def test_persistence_across_engine_restart(tmp_path):
    url = f"sqlite:///{tmp_path}/t.db"
    db.init_db(url)
    with db.SessionLocal() as s:
        s.add(Reservation(ip="10.0.0.9")); s.commit()
    db.engine.dispose(); db.init_db(url)
    with db.SessionLocal() as s:
        assert s.query(Reservation).one().ip == "10.0.0.9"


def test_parse_nmap_xml():
    x = """<nmaprun><host><status state="up"/><address addr="192.168.1.9" addrtype="ipv4"/>
    <address addr="AA:BB:CC:00:11:22" addrtype="mac" vendor="Acme"/></host>
    <host><status state="down"/><address addr="192.168.1.10" addrtype="ipv4"/></host></nmaprun>"""
    assert parse_nmap_xml(x) == {"192.168.1.9": {"mac": "aa:bb:cc:00:11:22", "vendor": "Acme", "hostname": None}}


def test_proxmox_parsers():
    n = parse_qemu_net("virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=20,firewall=1")
    assert n["mac"] == "bc:24:11:aa:bb:cc" and n["bridge"] == "vmbr0" and n["vlan"] == 20
    l = parse_lxc_net("name=eth0,bridge=vmbr1,hwaddr=BC:24:11:00:00:01,ip=192.168.1.50/24,gw=192.168.1.1,type=veth")
    assert conf_ip(l["ip"]) == "192.168.1.50" and conf_ip("dhcp") is None


def test_dockhand_multi_interface_and_hostmode():
    c = {"Id": "abc123", "Names": ["/web"], "Image": "nginx", "State": "running",
         "HostConfig": {"NetworkMode": "bridge"},
         "NetworkSettings": {"Networks": {"br": {"IPAddress": "172.18.0.2", "MacAddress": "02:42:ac:12:00:02"},
                                          "lan": {"IPAddress": "192.168.1.20", "MacAddress": "02:42:c0:a8:01:14",
                                                  "GlobalIPv6Address": "fd00::20"}}}}
    nets = parse_networks([{"Name": "lan", "Driver": "macvlan", "IPAM": {"Config": [{"Subnet": "192.168.1.0/24", "Gateway": "192.168.1.1"}]}}])
    recs, had = parse_container(c, "env1", nets)
    assert had and {r["ip"] for r in recs} == {"172.18.0.2", "192.168.1.20", "fd00::20"}
    assert [r for r in recs if r["ip"] == "192.168.1.20"][0]["extra"]["net_driver"] == "macvlan"
    host = {"Id": "d", "Names": ["/h"], "HostConfig": {"NetworkMode": "host"}, "NetworkSettings": {"Networks": {"host": {}}}}
    recs, _ = parse_container(host, "env1", {})
    assert recs[0]["ip"] is None and recs[0]["extra"]["network_mode"] == "host"


def test_cert_pinning():
    import datetime, ssl, subprocess, threading, hashlib, socket, os, tempfile
    from app.util import pinned_ssl_context
    d = tempfile.mkdtemp()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", d + "/k", "-out", d + "/c",
                    "-subj", "/CN=pve", "-days", "1"], check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(d + "/c", d + "/k")
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5); port = srv.getsockname()[1]
    def serve():
        while True:
            try:
                c, _ = srv.accept(); t = ctx.wrap_socket(c, server_side=True); t.recv(1); t.close()
            except Exception:
                pass
    threading.Thread(target=serve, daemon=True).start()
    fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(d + "/c").read())).hexdigest()
    pinned_ssl_context(f"https://127.0.0.1:{port}", ":".join(fp[i:i+2] for i in range(0, 64, 2)).upper())
    with pytest.raises(ssl.SSLError):
        pinned_ssl_context(f"https://127.0.0.1:{port}", "00" * 32)


def test_ipless_source_matched_by_mac(s):
    sn = mk(s)
    s.add(ScanResult(ip="192.168.1.4", subnet_id=sn.id, alive=True, mac="bc:24:11:aa:bb:cc", last_seen=utcnow()))
    s.add(SourceRecord(source="proxmox", kind="vm", name="vm100", ip=None, mac="bc:24:11:aa:bb:cc", ip_origin="unconfirmed"))
    s.add(SourceRecord(source="proxmox", kind="vm", name="vm101", ip=None, mac="bc:24:11:00:00:01", ip_origin="unconfirmed"))
    s.commit()
    entries, _ = ipm.build_inventory(s)
    e = entries["192.168.1.4"]
    assert "proxmox" in e["sources"] and e["device_name"] == "vm100" and e["ip_origin"] == "observed"
    assert [d["name"] for d in ipm.summary(s)["no_ip"]] == ["vm101"]
