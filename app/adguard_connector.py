"""AdGuard Home source (read-only): DNS rewrite entries (domain -> address).

Auth: HTTP Basic with the AdGuard Home web UI username/password (optional if AdGuard runs without auth).
  GET {url}/control/status        -> {version, ...}          (used by test())
  GET {url}/control/rewrite/list  -> [{domain, answer}, ...]

Each rewrite whose answer is an IP address becomes a record of kind 'dns-rewrite' with ip_origin 'configured'
(static DNS entry, like a fixed reservation). Rewrites with non-IP answers (CNAME targets, '*' etc.) are skipped.
"""
from .dhcp_common import http_client
from .util import norm_ip


class AdGuardConnector:
    def __init__(self, cfg):
        self.cfg = cfg
        if not cfg["adguard_url"]:
            raise ValueError("AdGuard Home URL is required")
        user = cfg.get("adguard_username") or ""
        auth = (user, cfg.get("adguard_password") or "") if user else None
        self.c = http_client(cfg["adguard_url"], {"Accept": "application/json"}, cfg["adguard_verify_tls"],
                             cfg["adguard_ca_bundle"], cfg["adguard_fingerprint"], auth=auth)

    def _get(self, path):
        r = self.c.get("/control" + path)
        if r.status_code in (401, 403):
            raise PermissionError(f"HTTP {r.status_code} - check the AdGuard Home username/password")
        r.raise_for_status()
        return r.json()

    def rewrites(self):
        data = self._get("/rewrite/list")
        return data if isinstance(data, list) else []

    def test(self):
        status = self._get("/status")
        n = len(self.rewrites())
        return {"ok": True, "message": f"AdGuard Home {status.get('version', '?')}, {n} DNS rewrite(s)",
                "details": [str(status.get("version", ""))]}

    def fetch(self):
        out = []
        for row in self.rewrites():
            domain = str(row.get("domain") or "").strip().rstrip(".")
            ip = norm_ip(row.get("answer"))
            if not domain or not ip:
                continue
            out.append({"source": "adguard", "kind": "dns-rewrite", "name": domain, "ip": ip, "mac": None,
                        "hostname": domain, "ip_origin": "configured", "state": "rewrite",
                        "extra": {"answer": row.get("answer")}})
        return out
