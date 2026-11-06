"""Optional ESPHome integration: Dashboard API (GET /devices, /ping) + native API device_info."""
import asyncio
import socket
import httpx
from .util import norm_ip, norm_mac


def resolve(host):
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(host, None, socket.AF_INET):
            ip = norm_ip(sa[0])
            if ip:
                return ip
    except OSError:
        pass
    return None


async def _native(host, port, password, psk):
    from aioesphomeapi import APIClient
    cli = APIClient(host, port, password or None, noise_psk=psk or None)
    try:
        await asyncio.wait_for(cli.connect(login=False), 6)
        info = await asyncio.wait_for(cli.device_info(), 6)
        return {"name": info.name, "mac": norm_mac(info.mac_address), "version": info.esphome_version,
                "model": info.model, "project": getattr(info, "project_name", "") or ""}
    finally:
        try:
            await cli.disconnect()
        except Exception:
            pass


def native_info(host, cfg):
    try:
        return asyncio.run(_native(host, 6053, cfg.get("esphome_api_password"), cfg.get("esphome_noise_psk"))), None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"[:160]


class ESPHomeConnector:
    def __init__(self, cfg):
        self.cfg = cfg
        url = cfg["esphome_dashboard_url"].rstrip("/")
        auth = (cfg["esphome_dashboard_user"], cfg["esphome_dashboard_password"]) if cfg["esphome_dashboard_user"] else None
        self.c = httpx.Client(base_url=url, auth=auth, timeout=10) if url else None

    def test(self):
        if not self.c:
            raise RuntimeError("ESPHome Dashboard URL not set (only manual hosts will be used)")
        r = self.c.get("/devices")
        r.raise_for_status()
        n = len(r.json().get("configured", []))
        return {"ok": True, "message": f"Dashboard reachable, {n} configured device(s)"}

    def _targets(self):
        t = []  # (name, host, extra)
        if self.c:
            data = self.c.get("/devices")
            data.raise_for_status()
            ping = {}
            try:
                ping = self.c.get("/ping").json()
            except Exception:
                pass
            for d in data.json().get("configured", []):
                name = d.get("name")
                host = d.get("address") or f"{name}.local"
                st = ping.get(d.get("configuration"))
                t.append((name, host, {"dashboard_online": st, "deployed_version": d.get("deployed_version"),
                                       "current_version": d.get("current_version"),
                                       "platform": d.get("target_platform"), "config": d.get("configuration")}))
        for item in [x.strip() for x in self.cfg.get("esphome_hosts", "").split(",") if x.strip()]:
            name, _, host = item.partition("=")
            t.append((name, host, {}) if host else (None, name, {}))
            if not host:
                t[-1] = (item, item, {})
        return t

    def fetch(self):
        out = []
        for name, host, ex in self._targets():
            ip = norm_ip(host) or resolve(host)
            info, err = (None, "native api disabled")
            if ip and self.cfg.get("esphome_native_api", True):
                info, err = native_info(ip, self.cfg)
            online = bool(info) or ex.get("dashboard_online")
            if info:
                ex.update(esphome_version=info["version"], model=info["model"], project=info["project"])
            if err:
                ex["native_error"] = err
            out.append({"source": "esphome", "kind": "esphome", "name": (info or {}).get("name") or name,
                        "ip": ip, "mac": (info or {}).get("mac"), "hostname": host if not norm_ip(host) else None,
                        "ip_origin": "configured" if not ip or err else "observed",
                        "state": "online" if online else "offline", "extra": ex})
        return out
