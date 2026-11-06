"""Thin wrappers around nmap / arp-scan / ip neigh. No shell is ever used."""
import json
import os
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

from .util import norm_ip, norm_mac

ACTIVE_NEIGH = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}
_oui = None


def available(tool):
    return shutil.which(tool) is not None


def _run(cmd, inp=None, timeout=1800):
    return subprocess.run(cmd, input=inp, capture_output=True, text=True, timeout=timeout, check=False)


def oui_lookup(mac):
    global _oui
    if _oui is None:
        _oui = {}
        for p in ("/usr/share/nmap/nmap-mac-prefixes", "/usr/share/arp-scan/ieee-oui.txt"):
            if os.path.exists(p):
                for line in open(p, encoding="utf-8", errors="ignore"):
                    if line.startswith("#") or len(line) < 7:
                        continue
                    parts = line.strip().replace("\t", " ").split(" ", 1)
                    if len(parts) == 2 and len(parts[0]) == 6:
                        _oui.setdefault(parts[0].upper(), parts[1].strip())
    mac = norm_mac(mac)
    return _oui.get(mac.replace(":", "")[:6].upper()) if mac else None


def parse_nmap_xml(text):
    """-> {ip: {mac, vendor, hostname}} for hosts that are up."""
    out = {}
    root = ET.fromstring(text)
    for h in root.iter("host"):
        st = h.find("status")
        if st is None or st.get("state") != "up":
            continue
        ip = mac = vendor = None
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                ip = norm_ip(a.get("addr"))
            elif a.get("addrtype") == "mac":
                mac, vendor = norm_mac(a.get("addr")), a.get("vendor")
        hn = h.find("hostnames/hostname")
        if ip:
            out[ip] = {"mac": mac, "vendor": vendor or oui_lookup(mac),
                       "hostname": hn.get("name") if hn is not None else None}
    return out


def nmap_sweep(targets, ipv6=False, max_rate=100):
    """Host discovery only (-sn: ICMP echo/timestamp, TCP 443/80 probes, ARP/NDP on
    local segments). `targets` is a CIDR string or a list of addresses (fed via stdin)."""
    cmd = ["nmap", "-sn", "-n", "-T3", "--max-rate", str(max_rate), "-oX", "-"]
    if ipv6:
        cmd.append("-6")
    if isinstance(targets, str):
        cmd.append(targets)
        inp = None
    else:
        if not targets:
            return {}
        cmd += ["-iL", "-"]
        inp = "\n".join(targets)
    r = _run(cmd, inp)
    if not r.stdout.strip():
        raise RuntimeError(f"nmap failed: {r.stderr.strip()[:200]}")
    return parse_nmap_xml(r.stdout)


def arp_scan(cidr):
    """-> {ip: {mac, vendor}} (IPv4, same L2 segment only)."""
    r = _run(["arp-scan", "-x", "-r", "2", cidr], timeout=900)
    out = {}
    for line in r.stdout.splitlines():
        p = line.split("\t")
        if len(p) >= 2 and norm_ip(p[0]) and norm_mac(p[1]):
            out[norm_ip(p[0])] = {"mac": norm_mac(p[1]), "vendor": p[2] if len(p) > 2 else oui_lookup(p[1])}
    return out


def neigh_table():
    """-> {ip: {mac, state}} from `ip -j neigh` (v4 and v6)."""
    out = {}
    if not available("ip"):
        return out
    r = _run(["ip", "-j", "neigh", "show"], timeout=15)
    try:
        for e in json.loads(r.stdout or "[]"):
            ip = norm_ip(e.get("dst"))
            if ip:
                out[ip] = {"mac": norm_mac(e.get("lladdr")), "state": (e.get("state") or [""])[0]}
    except ValueError:
        pass
    return out


def port_scan(ips, ports):
    """Optional: open TCP ports on already-alive hosts only."""
    if not ips:
        return {}
    r = _run(["nmap", "-Pn", "-n", "-T3", "--open", "-p", ports, "-oX", "-", "-iL", "-"], "\n".join(ips))
    out = {}
    try:
        for h in ET.fromstring(r.stdout).iter("host"):
            a = h.find("address")
            ip = norm_ip(a.get("addr")) if a is not None else None
            out[ip] = [int(p.get("portid")) for p in h.iter("port")
                       if p.find("state") is not None and p.find("state").get("state") == "open"]
    except ET.ParseError:
        pass
    return out


def reverse_dns(ips, workers=16, budget=20):
    def one(ip):
        try:
            return ip, socket.gethostbyaddr(ip)[0]
        except OSError:
            return ip, None
    out = {}
    with ThreadPoolExecutor(workers) as ex:
        futs = [ex.submit(one, ip) for ip in ips]
        for f in futs:
            try:
                ip, n = f.result(timeout=budget)
                if n:
                    out[ip] = n
            except Exception:
                pass
    return out
