"""Proxmox VE REST API connector (API token auth: Authorization: PVEAPIToken=...).

Needs a token with PVEAuditor (VM.Audit, Sys.Audit); the QEMU guest agent
call additionally needs VM.Monitor (PVE<9) / VM.GuestAgent.Audit (PVE>=9).
"""
import re
import httpx
from .util import norm_ip, norm_mac, pinned_ssl_context


def kv(s):
    d = {}
    for part in str(s).split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            d[k.strip()] = v.strip()
    return d


def parse_qemu_net(val):
    """'virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=10' -> dict"""
    d = kv(val)
    mac = None
    for model in ("virtio", "e1000", "e1000e", "rtl8139", "vmxnet3", "ne2k_pci", "pcnet"):
        if model in d:
            mac = norm_mac(d[model])
    if not mac and "macaddr" in d:
        mac = norm_mac(d["macaddr"])
    return {"mac": mac, "bridge": d.get("bridge"), "vlan": int(d["tag"]) if d.get("tag", "").isdigit() else None,
            "firewall": d.get("firewall") == "1"}


def parse_lxc_net(val):
    d = kv(val)
    return {"name": d.get("name"), "mac": norm_mac(d.get("hwaddr")), "bridge": d.get("bridge"),
            "vlan": int(d["tag"]) if d.get("tag", "").isdigit() else None,
            "ip": d.get("ip"), "ip6": d.get("ip6"), "gw": d.get("gw")}


DASH_LABEL = re.compile(r"^\s*(dashboard\.[a-z]+)\s*[:=]\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)


def dashboard_labels(description):
    """Lines 'dashboard.url: http://...' (or '=') in a guest's Notes -> {'dashboard.url': 'http://...'}.
    Same keys as the Docker container labels, so one tile can be tuned the same way for both."""
    return {k.lower(): v for k, v in DASH_LABEL.findall(description or "")}


def conf_ip(v):
    """'192.168.1.5/24' -> ip; 'dhcp'/'auto'/'manual' -> None"""
    if not v or v in ("dhcp", "auto", "manual"):
        return None
    return norm_ip(v)


class ProxmoxConnector:
    def __init__(self, cfg):
        self.cfg = cfg
        tok = f"PVEAPIToken={cfg['proxmox_token_id']}={cfg['proxmox_token_secret']}"
        url = cfg["proxmox_url"].rstrip("/")
        self.c = httpx.Client(base_url=url + "/api2/json", headers={"Authorization": tok},
                              verify=(pinned_ssl_context(url, cfg["proxmox_fingerprint"]) if cfg.get("proxmox_fingerprint") else cfg["proxmox_ca_bundle"] or cfg["proxmox_verify_tls"]), timeout=20)

    def get(self, path):
        r = self.c.get(path)
        r.raise_for_status()
        return r.json().get("data")

    def cluster_name(self):
        try:
            for x in self.get("/cluster/status") or []:
                if x.get("type") == "cluster":
                    return x.get("name")
        except Exception:
            pass
        return self.cfg.get("proxmox_cluster_name") or ""

    def test(self):
        ver = self.get("/version")
        nodes = self.get("/nodes") or []
        vms = lxc = 0
        for n in nodes:
            if n.get("status") == "online":
                vms += len(self.get(f"/nodes/{n['node']}/qemu") or [])
                lxc += len(self.get(f"/nodes/{n['node']}/lxc") or [])
        msg = f"Proxmox VE {ver.get('version')}, {len(nodes)} node(s), {vms} VM, {lxc} LXC visible to this token"
        if not vms and not lxc:
            return {"ok": False, "message": msg + " - token lacks VM.Audit (role PVEAuditor on path /, Propagate) "
                    "or privilege separation hides guests", "details": [n.get("node") for n in nodes]}
        return {"ok": True, "message": msg, "details": [n.get("node") for n in nodes]}

    def fetch(self):
        out = []
        cluster = self.cluster_name()
        for n in self.get("/nodes") or []:
            node = n["node"]
            if n.get("status") != "online":
                continue
            for kind, path in (("vm", "qemu"), ("lxc", "lxc")):
                for g_ in self.get(f"/nodes/{node}/{path}") or []:
                    try:
                        out.extend(self._guest(cluster, node, kind, path, g_))
                    except Exception as e:  # one broken guest must not hide the others
                        out.append({"source": "proxmox", "kind": kind, "name": g_.get("name") or str(g_["vmid"]),
                                    "ip": None, "mac": None, "state": g_.get("status"),
                                    "extra": {"vmid": g_["vmid"], "node": node, "cluster": cluster,
                                              "error": str(e)}})
        out.extend(self._node_stats(cluster))
        return out

    def _node_stats(self, cluster):
        """kind=node records (no IP, so they never show up as devices) carry CPU/RAM/disk for the dashboard."""
        try:
            nodes = self.get("/cluster/resources?type=node") or []
        except Exception:
            return []
        return [{"source": "proxmox", "kind": "node", "name": n.get("node") or "?", "ip": None, "mac": None,
                 "state": n.get("status"),
                 "extra": {"cluster": cluster, "cpu": n.get("cpu"), "maxcpu": n.get("maxcpu"),
                           "mem": n.get("mem"), "maxmem": n.get("maxmem"), "disk": n.get("disk"),
                           "maxdisk": n.get("maxdisk"), "uptime": n.get("uptime")}}
                for n in nodes]

    def _guest(self, cluster, node, kind, path, gst):
        vmid, running = gst["vmid"], gst.get("status") == "running"
        cfg = self.get(f"/nodes/{node}/{path}/{vmid}/config") or {}
        name = gst.get("name") or cfg.get("name") or cfg.get("hostname") or str(vmid)
        base = dict(source="proxmox", kind=kind, name=name, state=gst.get("status"))
        ex0 = {"vmid" if kind == "vm" else "ctid": vmid, "node": node, "cluster": cluster,
               "labels": dashboard_labels(cfg.get("description"))}
        nets = {}  # idx -> info
        for k, v in cfg.items():
            m = re.fullmatch(r"net(\d+)", k)
            if not m:
                continue
            idx = int(m.group(1))
            info = parse_qemu_net(v) if kind == "vm" else parse_lxc_net(v)
            info["idx"] = idx
            info["conf_ips"] = []
            if kind == "lxc":
                info["conf_ips"] = [i for i in (conf_ip(info.get("ip")), conf_ip(info.get("ip6"))) if i]
                info["gw"] = info.get("gw")
            else:
                ic = kv(cfg.get(f"ipconfig{idx}", ""))
                info["conf_ips"] = [i for i in (conf_ip(ic.get("ip")), conf_ip(ic.get("ip6"))) if i]
                info["gw"] = ic.get("gw")
            nets[idx] = info
        runtime = []  # (mac, ip, origin)
        err = None
        if running:
            try:
                if kind == "vm":
                    res = (self.get(f"/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces") or {}).get("result", [])
                    for itf in res:
                        for a in itf.get("ip-addresses", []):
                            runtime.append((norm_mac(itf.get("hardware-address")), norm_ip(a.get("ip-address")),
                                            "guest-agent"))
                else:
                    for itf in self.get(f"/nodes/{node}/lxc/{vmid}/interfaces") or []:
                        for a in (itf.get("inet"), itf.get("inet6")):
                            runtime.append((norm_mac(itf.get("hwaddr")), norm_ip(a), "lxc-interface"))
            except Exception as e:
                err = f"{type(e).__name__}: {e}"[:200]  # e.g. guest agent not running
        recs = []
        for idx, info in sorted(nets.items()):
            ex = {**ex0, "bridge": info.get("bridge"), "net": f"net{idx}", "gateway": info.get("gw"),
                  "agent_error": err}
            ips = {}
            for ip in info["conf_ips"]:
                ips[ip] = "configured"
            for mac, ip, origin in runtime:
                if ip and mac and mac == info["mac"]:
                    ips[ip] = origin  # runtime evidence wins over config
            for ip, origin in ips.items():
                recs.append({**base, "ip": ip, "mac": info["mac"], "vlan": info["vlan"],
                             "ip_origin": origin, "extra": ex})
            if not ips:  # keep the device even without any IP (no guest agent etc.)
                recs.append({**base, "ip": None, "mac": info["mac"], "vlan": info["vlan"],
                             "ip_origin": "unconfirmed", "extra": ex})
        if not nets:
            recs.append({**base, "ip": None, "mac": None, "ip_origin": "unconfirmed", "extra": {**ex0, "agent_error": err}})
        return recs
