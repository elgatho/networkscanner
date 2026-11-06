"""OPNsense DHCP source (read-only). Auth: HTTP Basic with API key:secret.

Endpoints tried (OPNsense splits DHCP across plugins/services; each present one is read):
  Kea leases        GET /api/kea/leases4/search   (older docs: /api/kea/leases/search)
  Kea reservations  GET /api/kea/dhcpv4/search_reservation
  ISC leases        GET /api/dhcpv4/leases/search_lease  (older: searchLease)
  Dnsmasq leases    GET /api/dnsmasq/leases/search
Row field names differ between versions, so parsing is tolerant. Endpoints that return 404 are skipped.
"""
import httpx
from .dhcp_common import http_client, pick, rows_of
from .util import norm_ip, norm_mac

LEASES = [("kea", "/api/kea/leases4/search"), ("kea", "/api/kea/leases/search"),
          ("isc", "/api/dhcpv4/leases/search_lease"), ("isc", "/api/dhcpv4/leases/searchLease"),
          ("dnsmasq", "/api/dnsmasq/leases/search")]
RESERVATIONS = [("kea", "/api/kea/dhcpv4/search_reservation")]


class OPNsenseConnector:
    def __init__(self, cfg):
        self.cfg = cfg
        if not cfg["opnsense_url"] or not cfg["opnsense_key"]:
            raise ValueError("OPNsense URL and API key are required")
        self.c = http_client(cfg["opnsense_url"], {"Accept": "application/json"}, cfg["opnsense_verify_tls"],
                             cfg["opnsense_ca_bundle"], cfg["opnsense_fingerprint"],
                             auth=(cfg["opnsense_key"], cfg["opnsense_secret"]))

    def _rows(self, path):
        """-> (rows | None if endpoint unavailable)."""
        r = self.c.get(path, params={"current": 1, "rowCount": -1})
        if r.status_code in (400, 404, 405):
            return None
        if r.status_code in (401, 403):
            raise PermissionError(f"HTTP {r.status_code} on {path} - check API key/secret and user privileges")
        r.raise_for_status()
        return rows_of(r.json())

    def _collect(self, table, origin, kind, state_default):
        out, used, seen = [], [], set()
        for flavour, path in table:
            if flavour in seen:
                continue
            rows = self._rows(path)
            if rows is None:
                continue
            seen.add(flavour)
            used.append(path)
            for row in rows:
                ip = norm_ip(pick(row, "address", "ip_address", "ip", "ipaddr", "ip-address"))
                if not ip:
                    continue
                state = str(pick(row, "state", "binding_state", "status") or state_default)
                if origin == "dhcp-lease" and state.lower() in ("expired", "free", "abandoned", "released", "backup"):
                    continue
                out.append({"source": "opnsense", "kind": kind,
                            "name": pick(row, "hostname", "client_hostname", "descr", "description") or ip,
                            "ip": ip, "mac": norm_mac(pick(row, "hwaddr", "hw_address", "mac", "hw-address")),
                            "hostname": pick(row, "hostname", "client_hostname"), "ip_origin": origin,
                            "state": state, "extra": {"flavour": flavour, "interface": pick(row, "if", "interface", "if_descr"),
                                                      "expire": pick(row, "ends", "expire", "expires", "valid_lifetime")}})
        return out, used

    def test(self):
        leases, used = self._collect(LEASES, "dhcp-lease", "dhcp-lease", "active")
        if not used:
            return {"ok": False, "message": "No DHCP lease endpoint answered (tried Kea, ISC, Dnsmasq). Is a DHCP service "
                    "installed, and does the API user have the matching privilege (e.g. 'Services: Kea DHCP', "
                    "'Services: ISC DHCPv4: Leases')?"}
        return {"ok": True, "message": f"{len(leases)} active lease(s) via {', '.join(used)}", "details": used}

    def fetch(self):
        out, used = self._collect(LEASES, "dhcp-lease", "dhcp-lease", "active")
        if not used:
            raise RuntimeError("no DHCP lease endpoint available on this OPNsense")
        if self.cfg.get("opnsense_reservations", True):
            res, _ = self._collect(RESERVATIONS, "dhcp-reservation", "dhcp-reservation", "reserved")
            keys = {(r["ip"], r["mac"]) for r in out}
            out += [r for r in res if (r["ip"], r["mac"]) not in keys]
        return out
