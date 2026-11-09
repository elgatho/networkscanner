"""Inventory building, status model and the FIRST AVAILABLE IP algorithm."""
import ipaddress
from datetime import timedelta
from sqlalchemy import select

from .database import (ConflictRule, Reservation, ScanResult, SourceRecord, SourceStatus, Subnet, get_settings)
from .dhcp_common import DHCP_SOURCES
from .network_scanner import ACTIVE_NEIGH, oui_lookup
from .util import iso, norm_ip, utcnow

MAX_ENUM = 1 << 17


def parse_exclusions(items):
    """'10.0.0.1', '10.0.0.10-10.0.0.50' or a CIDR -> [(lo, hi)] ints."""
    out = []
    for it in items or []:
        it = str(it).strip()
        try:
            if "-" in it:
                a, b = (ipaddress.ip_address(x.strip()) for x in it.split("-", 1))
                out.append((int(a), int(b)))
            elif "/" in it:
                n = ipaddress.ip_network(it, strict=False)
                out.append((int(n.network_address), int(n.broadcast_address)))
            elif it:
                a = ipaddress.ip_address(it)
                out.append((int(a), int(a)))
        except ValueError:
            continue
    return out


def in_ranges(i, ranges):
    return any(lo <= i <= hi for lo, hi in ranges)


def net_of(sn):
    return ipaddress.ip_network(sn.cidr, strict=False)


def usable_count(net):
    if net.version == 4:
        return net.num_addresses - 2 if net.prefixlen < 31 else net.num_addresses
    return net.num_addresses - 1


def locate(ip, nets):
    a = ipaddress.ip_address(ip)
    best = None
    for sn, n in nets:
        if n.version == a.version and a in n and (best is None or n.prefixlen > best[1].prefixlen):
            best = (sn, n)
    return best[0] if best else None


def build_inventory(s):
    """-> (entries: {ip: dict}, subnets list)"""
    subnets = list(s.scalars(select(Subnet)))
    nets = [(sn, net_of(sn)) for sn in subnets]
    scans = {r.ip: r for r in s.scalars(select(ScanResult))}
    recs = list(s.scalars(select(SourceRecord).where(SourceRecord.ip.is_not(None))))
    resv = {r.ip: r for r in s.scalars(select(Reservation))}
    rules = list(s.scalars(select(ConflictRule)))
    ignore_host = get_settings(s).get("ignore_host_mode_conflicts", True)
    entries = {}

    def ent(ip, sn):
        return entries.setdefault(ip, {
            "ip": ip, "subnet": sn.name, "subnet_id": sn.id, "vlan": sn.vlan, "hostname": None,
            "device_name": None, "mac": None, "manufacturer": None, "device_type": None,
            "sources": [], "status": "UNKNOWN", "last_seen": None, "ip_origin": None,
            "conflict": None, "reserved": False, "ports": [], "kinds": [], "_macs": set(), "_names": set()})

    recs.sort(key=lambda r: r.source in DHCP_SOURCES)  # authoritative inventories first, DHCP views last
    for r in recs:
        sn = locate(r.ip, nets)
        if not sn:
            continue
        e = ent(r.ip, sn)
        dhcp = r.source in DHCP_SOURCES
        # a container in host network mode legitimately shares its host's IP/MAC
        shared = ignore_host and (r.extra or {}).get("network_mode") == "host"
        if r.source not in e["sources"]:
            e["sources"].append(r.source)
        e["device_name"] = e["device_name"] or r.name
        e["hostname"] = e["hostname"] or r.hostname
        e["mac"] = e["mac"] or r.mac
        if not dhcp:
            e["vlan"] = r.vlan if r.vlan is not None else e["vlan"]
            e["device_type"] = e["device_type"] or r.kind
        if dhcp:
            e["ip_origin"] = e["ip_origin"] or r.ip_origin
        else:
            e["ip_origin"] = e["ip_origin"] if e["ip_origin"] in ("guest-agent", "lxc-interface") else r.ip_origin
        if r.mac and not shared:
            e["_macs"].add(r.mac)
        if not dhcp and not shared:
            e["_names"].add((r.source, r.name))
    for ip, sr in scans.items():
        sn = locate(ip, nets)
        if not sn or not (sr.alive or sr.last_seen or sr.neigh_state in ACTIVE_NEIGH):
            continue
        e = ent(ip, sn)
        if sr.alive or sr.last_seen:
            e["sources"].append("scanner")
        e["hostname"] = e["hostname"] or sr.hostname
        e["mac"] = e["mac"] or sr.mac
        e["manufacturer"] = sr.vendor
        e["ports"] = sr.ports or []
        e["last_seen"] = sr.last_seen
        if sr.mac:
            e["_macs"].add(sr.mac)
    for ip, r in resv.items():
        sn = locate(ip, nets)
        if sn:
            e = ent(ip, sn)
            e["reserved"] = True
            if "reservation" not in e["sources"]:
                e["sources"].append("reservation")
            e["device_name"] = e["device_name"] or (r.note or "reserved")
    # Source records without an IP (e.g. VM without guest agent) are matched to scanned hosts by MAC
    by_mac = {}
    for e in entries.values():
        for m in e["_macs"]:
            by_mac.setdefault(m, []).append(e)
    for r in s.scalars(select(SourceRecord).where(SourceRecord.ip.is_(None), SourceRecord.mac.is_not(None))):
        for e in by_mac.get(r.mac, []):
            if r.source not in e["sources"]:
                e["sources"].append(r.source)
            e["device_name"] = r.name if (not e["device_name"] or e["device_name"] == "reserved") else e["device_name"]
            e["device_type"] = e["device_type"] if e["device_type"] not in (None, "host") else r.kind
            if e["ip_origin"] not in ("guest-agent", "lxc-interface"):
                e["ip_origin"] = "observed"
    snmap = {sn.id: sn for sn in subnets}
    for ip, e in entries.items():
        sr = scans.get(ip)
        sn = snmap[e["subnet_id"]]
        if sr and sr.alive:
            e["status"] = "ONLINE"
        elif sr and sr.last_seen:
            e["status"] = "OFFLINE"
        elif e["reserved"] or (sn.last_full_scan_at and e["sources"]):
            e["status"] = "RESERVED"
        else:
            e["status"] = "UNKNOWN"
        if e["ip_origin"] == "configured" and e["status"] != "ONLINE" and "proxmox" in e["sources"]:
            e["ip_origin"] = "unconfirmed"
        if not e["manufacturer"] and e["mac"]:
            e["manufacturer"] = oui_lookup(e["mac"])
        if not e["device_type"]:
            e["device_type"] = "host"
        if len(e["_macs"]) > 1:
            e["conflict"] = "multiple MACs claim this IP: " + ", ".join(sorted(e["_macs"]))
        elif len({n for _, n in e["_names"]}) > 1:
            e["conflict"] = "multiple devices claim this IP: " + ", ".join(sorted(f"{s}:{n}" for s, n in e["_names"]))
        e["conflict_ignored"] = None
        if e["conflict"]:
            hit = next((r for r in rules if (r.ip and r.ip == ip) or (r.mac and r.mac in e["_macs"])), None)
            if hit:
                e["conflict_ignored"], e["conflict"] = e["conflict"], None
        e["last_seen_iso"] = iso(e["last_seen"])
        e["device_key"] = e["mac"] or f"ip:{ip}"
        del e["_macs"], e["_names"]
    return entries, subnets


def gather_blocked(s, sn, entries):
    """IPs that must never be proposed (besides scan evidence)."""
    net = net_of(sn)
    blocked = set()
    if sn.gateway:
        g = norm_ip(sn.gateway)
        if g:
            blocked.add(g)
    for ip, e in entries.items():
        if e["subnet_id"] == sn.id and (e["sources"] and e["sources"] != ["scanner"] or e["reserved"]):
            blocked.add(ip)
    return blocked


def first_free(s, sn, entries=None, now=None, st=None):
    """Return the recommended first free address of a subnet (or reason none)."""
    now = now or utcnow()
    st = st or get_settings(s)
    entries = entries if entries is not None else build_inventory(s)[0]
    net = net_of(sn)
    base = {"subnet": sn.name, "subnet_id": sn.id, "cidr": sn.cidr, "vlan": sn.vlan}
    if net.num_addresses > MAX_ENUM:
        return {**base, "ip": None, "confidence": None, "warnings": ["Subnet too large to enumerate"]}
    blocked = gather_blocked(s, sn, entries)
    excl = parse_exclusions(sn.exclusions)
    scans = {r.ip: r for r in s.scalars(select(ScanResult).where(ScanResult.subnet_id == sn.id))}
    free_after = timedelta(hours=st["free_after_hours"])
    interval = sn.scan_interval or st["full_scan_interval"]
    fresh = bool(sn.last_full_scan_at and sn.last_full_scan_ok and
                 now - sn.last_full_scan_at <= timedelta(minutes=interval * 3))
    warnings, failing = [], []
    if not sn.last_full_scan_at:
        warnings.append("Subnet has never been fully scanned - availability not verified.")
    elif not fresh:
        warnings.append("Last full scan is stale or failed - availability not verified.")
    if sn.last_full_scan_at and not sn.l2:
        warnings.append("No ARP/NDP evidence (subnet is not on the scanner's L2 segment): ICMP/TCP probes only.")
    enabled = {"dockhand": st["dockhand_enabled"], "proxmox": st["proxmox_enabled"], "esphome": st["esphome_enabled"]}
    for stt in s.scalars(select(SourceStatus)):
        if enabled.get(stt.source) and not stt.ok:
            failing.append(stt.source)
    known = {r.source for r in s.scalars(select(SourceStatus)) if r.ok}
    for src, en in enabled.items():
        if en and src not in known and src not in failing:
            failing.append(src)
    for f in failing:
        warnings.append(f"Source '{f}' is unavailable - its addresses may be missing.")
    hosts = net.hosts() if net.version == 4 else (ipaddress.ip_address(int(net.network_address) + i)
                                                   for i in range(1, min(net.num_addresses, MAX_ENUM)))
    for a in hosts:
        ip = str(a)
        if ip in blocked or in_ranges(int(a), excl):
            continue
        sr = scans.get(ip)
        recent_loss = False
        if sr:
            if sr.alive or sr.neigh_state in ACTIVE_NEIGH:
                continue
            if sr.last_seen:
                if now - sr.last_seen < free_after:
                    continue  # offline but known: still considered taken
                recent_loss = True
        conf = "HIGH"
        w = list(warnings)
        if failing or (sn.last_full_scan_at and not sn.l2):
            conf = "MEDIUM"
        if not fresh or recent_loss:
            conf = "LOW"
        if recent_loss:
            w.append("Address was seen on the network in the past.")
        w.append("Recommendation only - cannot rule out a DHCP reservation on an external server.")
        return {**base, "ip": ip, "confidence": conf, "warnings": w,
                "verified_at": iso(sn.last_full_scan_at)}
    return {**base, "ip": None, "confidence": None, "warnings": ["No free address in this subnet."]}


def subnet_view(s, sn, entries=None, st=None):
    st = st or get_settings(s)
    entries = entries if entries is not None else build_inventory(s)[0]
    net = net_of(sn)
    usable = usable_count(net)
    ex = parse_exclusions(sn.exclusions)
    mine = {ip: e for ip, e in entries.items() if e["subnet_id"] == sn.id}
    gw = norm_ip(sn.gateway) if sn.gateway else None
    used_ips = set(mine) | ({gw} if gw else set())
    excluded = 0
    if net.num_addresses <= MAX_ENUM:
        for lo, hi in ex:
            lo, hi = max(lo, int(net.network_address)), min(hi, int(net.broadcast_address))
            excluded += max(0, hi - lo + 1)
        excluded -= sum(1 for ip in used_ips if in_ranges(int(ipaddress.ip_address(ip)), ex))
    used = len(used_ips)
    free = max(0, usable - used - excluded)
    cnt = {k: sum(1 for e in mine.values() if e["status"] == k) for k in ("ONLINE", "OFFLINE", "RESERVED", "UNKNOWN")}
    view = {"id": sn.id, "name": sn.name, "cidr": sn.cidr, "gateway": sn.gateway, "vlan": sn.vlan,
            "description": sn.description, "scan_interval": sn.scan_interval, "enabled": sn.enabled,
            "exclusions": sn.exclusions or [], "range": f"{net.network_address} - {net.broadcast_address}" if net.version == 4 else str(net),
            "usable": usable, "used": used, "free": free, "excluded": excluded,
            "utilization": round(100 * used / usable, 1) if usable else 0, "counts": cnt,
            "last_scan_at": iso(sn.last_scan_at), "last_scan_status": sn.last_scan_status,
            "last_full_scan_at": iso(sn.last_full_scan_at), "l2": sn.l2, "cells": None}
    if net.version == 4 and net.num_addresses <= 1024:
        code = {"ONLINE": "O", "OFFLINE": "F", "RESERVED": "R", "UNKNOWN": "U"}
        cells = []
        for a in net.hosts() if net.prefixlen < 31 else net:
            ip = str(a)
            if ip == gw:
                cells.append("G")
            elif ip in mine:
                cells.append(code[mine[ip]["status"]])
            elif in_ranges(int(a), ex):
                cells.append("X")
            else:
                cells.append(".")
        view["cells"] = "".join(cells)
        view["first_host"] = str(next(iter(net.hosts()))) if net.prefixlen < 31 else str(net.network_address)
    return view


def no_ip_records(s, entries):
    """Source devices (Proxmox VM/LXC, containers...) that have no usable IP and were not matched by MAC."""
    seen_macs = {e["mac"] for e in entries.values() if e["mac"]}
    out = {}
    for r in s.scalars(select(SourceRecord).where(SourceRecord.ip.is_(None), SourceRecord.kind != "node")):
        if r.mac and r.mac in seen_macs:
            continue
        out[(r.source, r.kind, r.name)] = {"source": r.source, "kind": r.kind, "name": r.name, "mac": r.mac,
                                           "state": r.state, "extra": r.extra or {}}
    return sorted(out.values(), key=lambda x: (x["source"], x["name"]))


def summary(s):
    st = get_settings(s)
    entries, subnets = build_inventory(s)
    views = [subnet_view(s, sn, entries, st) for sn in subnets if sn.enabled]
    last = max((sn.last_scan_at for sn in subnets if sn.last_scan_at), default=None)
    ff = [first_free(s, sn, entries, st=st) for sn in subnets if sn.enabled]
    return {"subnets": len(subnets), "used": sum(v["used"] for v in views), "free": sum(v["free"] for v in views),
            "online": sum(v["counts"]["ONLINE"] for v in views), "offline": sum(v["counts"]["OFFLINE"] for v in views),
            "last_scan": iso(last), "first_free": ff,
            "conflicts": sum(1 for e in entries.values() if e["conflict"]),
            "no_ip": no_ip_records(s, entries)}
