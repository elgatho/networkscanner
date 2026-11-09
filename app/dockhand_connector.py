"""Dockhand REST API connector (Bearer dh_... token).

Endpoints used (from https://dockhand.pro/manual/): GET /api/environments,
GET /api/containers?env=<id>, GET /api/containers/<id>/inspect?env=<id>,
GET /api/networks?env=<id>. Response schemas are not documented in the manual
(OpenAPI is served at /api/docs when FEAT_API_DOCS=true), so parsing is
tolerant: Docker-style (NetworkSettings.Networks) or flat 'networks' maps, any
key casing. When the list lacks network data, /inspect is used. An optional
Docker Engine API URL is used as fallback.
"""
import re
from urllib.parse import urlparse

import httpx
from .util import norm_ip, norm_mac


def g(d, *names, default=None):
    """Case/underscore-insensitive dict lookup."""
    if not isinstance(d, dict):
        return default
    want = {n.lower().replace("_", "") for n in names}
    for k, v in d.items():
        if k.lower().replace("_", "") in want:
            return v
    return default


def as_list(data, *keys):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in keys:
            v = g(data, k)
            if isinstance(v, list):
                return v
    return []


def client(url, verify, ca, headers, timeout=15, fingerprint=""):
    if fingerprint:
        from .util import pinned_ssl_context
        verify = pinned_ssl_context(url, fingerprint)
    return httpx.Client(base_url=url.rstrip("/"), headers=headers,
                        verify=verify if fingerprint else (ca if ca else verify), timeout=timeout)


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def parse_ports(v):
    """Published ports -> [{ip, public, private, type}]. Accepts Docker list form, "h:p->c/t" strings
    and inspect form {"80/tcp": [{"HostIp", "HostPort"}]}. Unpublished ports are dropped."""
    out = []
    if isinstance(v, list):
        for p in v:
            if isinstance(p, dict):
                pub = _int(g(p, "PublicPort"))
                if pub:
                    out.append({"ip": g(p, "IP") or "", "public": pub, "private": _int(g(p, "PrivatePort")),
                                "type": str(g(p, "Type") or "tcp").lower()})
            elif isinstance(p, str):
                m = re.match(r"(?:(\[[^\]]*\]|[\d.]+):)?(\d+)->(\d+)/(\w+)", p)
                if m:
                    out.append({"ip": (m.group(1) or "").strip("[]"), "public": int(m.group(2)),
                                "private": int(m.group(3)), "type": m.group(4).lower()})
    elif isinstance(v, dict):
        for key, binds in v.items():
            if not isinstance(binds, list):
                continue
            for b in binds:
                pub = _int(g(b, "HostPort")) if isinstance(b, dict) else None
                if pub:
                    out.append({"ip": g(b, "HostIp") or "", "public": pub,
                                "private": _int(str(key).split("/")[0]),
                                "type": str(key).split("/")[-1].lower()})
    return out


def parse_container(c, env_name, nets_info, env_host=""):
    """Turn a Docker-like container/inspect dict into records (one per IP)."""
    cid = g(c, "Id", "ID", "containerId") or ""
    names = g(c, "Names", "Name")
    name = names[0] if isinstance(names, list) and names else (names or cid[:12])
    name = str(name).lstrip("/")
    cfg = g(c, "Config") or {}
    image = g(c, "Image", "ImageName") or g(cfg, "Image") or ""
    st = g(c, "State", "Status")
    state = g(st, "Status") if isinstance(st, dict) else st
    host_cfg = g(c, "HostConfig") or {}
    mode = g(host_cfg, "NetworkMode") or g(c, "NetworkMode", "networkType") or ""
    labels = g(c, "Labels") or g(cfg, "Labels") or {}
    # only the dashboard.* labels are kept (links/category/icon/description for the Services page)
    dash = {str(k): str(v) for k, v in labels.items() if str(k).startswith("dashboard.")} if isinstance(labels, dict) else {}
    ports = parse_ports(g(c, "Ports") or g(ns_of(c), "Ports") or [])
    ns = g(c, "NetworkSettings") or {}
    networks = g(ns, "Networks") or g(c, "Networks") or {}
    if isinstance(networks, list):  # [{name:..., ip...}]
        networks = {str(g(n, "Name", "network") or i): n for i, n in enumerate(networks)}
    recs, base = [], dict(source="dockhand", kind="container", name=name, state=str(state or ""))
    for nname, n in (networks or {}).items():
        info = nets_info.get(nname, {})
        for fld, ip in (("v4", g(n, "IPAddress", "ipv4Address", "ip")),
                        ("v6", g(n, "GlobalIPv6Address", "ipv6Address"))):
            ip = norm_ip(ip)
            if ip:
                recs.append({**base, "ip": ip, "mac": norm_mac(g(n, "MacAddress", "mac")),
                             "extra": {"container_id": cid, "image": image, "environment": env_name,
                                       "network": nname, "network_mode": mode,
                                       "net_driver": info.get("driver"),
                                       "net_subnets": info.get("subnets"),
                                       "net_gateways": info.get("gateways"),
                                       "gateway": g(n, "Gateway", "IPv6Gateway"),
                                       "ports": ports, "labels": dash, "env_host": env_host}})
    if not recs:  # host mode / none / stopped: keep the container as a device without IP
        recs.append({**base, "ip": None, "mac": None,
                     "extra": {"container_id": cid, "image": image, "environment": env_name,
                               "network_mode": mode, "ports": ports, "labels": dash, "env_host": env_host}})
    return recs, bool(networks)


def ns_of(c):
    return g(c, "NetworkSettings") or {}


def parse_networks(nets):
    out = {}
    for n in nets:
        ipam = g(n, "IPAM") or {}
        cfgs = g(ipam, "Config") or []
        out[g(n, "Name")] = {"driver": g(n, "Driver"),
                             "subnets": [g(x, "Subnet") for x in cfgs if g(x, "Subnet")],
                             "gateways": [g(x, "Gateway") for x in cfgs if g(x, "Gateway")]}
    return out


class DockhandConnector:
    def __init__(self, cfg):
        self.cfg = cfg
        self.c = client(cfg["dockhand_url"], cfg["dockhand_verify_tls"], cfg["dockhand_ca_bundle"],
                        {"Authorization": f"Bearer {cfg['dockhand_token']}"},
                        fingerprint=cfg.get("dockhand_fingerprint", ""))

    def _get(self, path, **params):
        r = self.c.get(path, params=params or None)
        r.raise_for_status()
        return r.json()

    def environments(self):
        return as_list(self._get("/api/environments"), "environments", "data")

    def test(self):
        envs = self.environments()
        return {"ok": True, "message": f"Connected, {len(envs)} environment(s)",
                "details": [g(e, "name") for e in envs]}

    def fetch(self):
        out = []
        for env in self.environments():
            eid, ename = g(env, "id"), g(env, "name") or str(g(env, "id"))
            # host the containers' published ports live on; Dockhand URL host when the env does not say
            ehost = g(env, "host", "hostname", "address") or urlparse(self.cfg["dockhand_url"]).hostname or ""
            try:
                nets = parse_networks(as_list(self._get("/api/networks", env=eid), "networks", "data"))
            except Exception:
                nets = {}
            for c in as_list(self._get("/api/containers", env=eid), "containers", "data"):
                recs, had_nets = parse_container(c, ename, nets, ehost)
                if not had_nets:
                    cid = g(c, "Id", "ID")
                    try:
                        insp = self._get(f"/api/containers/{cid}/inspect", env=eid)
                        merged = {**c, **insp} if isinstance(insp, dict) else c
                        recs, _ = parse_container(merged, ename, nets, ehost)
                    except Exception:
                        pass
                out.extend(recs)
        return out
