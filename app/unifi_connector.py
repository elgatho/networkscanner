"""UniFi Network source (read-only), via the official local Integration API.

Auth header X-API-KEY (create under Network -> Settings -> Control Plane -> Integrations).
  GET {url}/proxy/network/integration/v1/sites                      -> {data:[{id,name}]}
  GET {url}/proxy/network/integration/v1/sites/{siteId}/clients     -> {data:[{id,name,type,ipAddress,macAddress,...}]}
Note: this API reports connected clients (their current IP), not the DHCP server's lease table or
fixed-IP reservations, so entries are tagged ip_origin='dhcp-client'.
"""
from .dhcp_common import http_client, pick
from .util import norm_ip, norm_mac

BASE = "/proxy/network/integration/v1"


class UniFiConnector:
    def __init__(self, cfg):
        self.cfg = cfg
        if not cfg["unifi_url"] or not cfg["unifi_api_key"]:
            raise ValueError("UniFi URL and API key are required")
        self.c = http_client(cfg["unifi_url"], {"X-API-KEY": cfg["unifi_api_key"], "Accept": "application/json"},
                             cfg["unifi_verify_tls"], cfg["unifi_ca_bundle"], cfg["unifi_fingerprint"])

    def _get(self, path, **params):
        r = self.c.get(BASE + path, params=params)
        if r.status_code in (401, 403):
            raise PermissionError(f"HTTP {r.status_code} - check the UniFi API key")
        r.raise_for_status()
        return r.json()

    def site(self):
        sites = (self._get("/sites") or {}).get("data", [])
        if not sites:
            raise RuntimeError("UniFi returned no sites")
        want = (self.cfg.get("unifi_site") or "").strip().lower()
        for s in sites:
            if not want or want in (str(s.get("name", "")).lower(), str(s.get("internalReference", "")).lower(), str(s.get("id"))):
                return s
        raise RuntimeError(f"site '{want}' not found; available: {[s.get('name') for s in sites]}")

    def clients(self, site_id):
        out, offset = [], 0
        while True:
            p = self._get(f"/sites/{site_id}/clients", limit=200, offset=offset)
            rows = p.get("data", [])
            out += rows
            offset += len(rows)
            if not rows or offset >= int(p.get("totalCount", offset) or offset):
                return out

    def test(self):
        s = self.site()
        n = len(self.clients(s["id"]))
        return {"ok": True, "message": f"site '{s.get('name')}', {n} client(s)", "details": [s.get("name")]}

    def fetch(self):
        s = self.site()
        out = []
        for c in self.clients(s["id"]):
            ip = norm_ip(pick(c, "ipAddress", "ip"))
            mac = norm_mac(pick(c, "macAddress", "mac"))
            if not ip and not mac:
                continue
            name = pick(c, "name", "hostname") or ip or mac
            out.append({"source": "unifi", "kind": "dhcp-client", "name": name, "ip": ip, "mac": mac,
                        "hostname": pick(c, "hostname", "name"), "ip_origin": "dhcp-client", "state": "connected",
                        "extra": {"type": c.get("type"), "site": s.get("name")}})
        return out
