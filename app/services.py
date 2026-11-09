"""Dashboard data: Proxmox overview and Docker service tiles, built from the stored source records.

Service tiles come from Dockhand containers that publish a port (or set a `dashboard.url` label).
Optional labels on the container (set in docker-compose / the container itself) override the defaults:
  dashboard.url          full link (default: http://<environment host>:<port>)
  dashboard.port         port used in the default link (default: first published port, else 80)
  dashboard.name         tile title (default: container name)
  dashboard.category     category (default: guessed from the image name)
  dashboard.description  text (default: image name)
  dashboard.icon         dashboard-icons slug (e.g. jellyfin) or a full image URL (default: from image name)
  dashboard.hide         "true" to hide the container from the dashboard
"""
import ipaddress
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select

from .database import SourceRecord, SourceStatus
from .util import iso

ICON_CDN = "https://cdn.jsdelivr.net/gh/walkxcode/dashboard-icons/png/"
DEFAULT_CATEGORY = "Other"

# category -> image/name keywords (matched as substrings of the lowercased image and container name)
CATEGORY_RULES = [
    ("Media", ["jellyfin", "plex", "emby", "sonarr", "radarr", "lidarr", "bazarr", "prowlarr", "readarr",
               "jellyseerr", "overseerr", "navidrome", "audiobookshelf", "calibre", "kavita", "tautulli"]),
    ("Downloads", ["qbittorrent", "transmission", "sabnzbd", "nzbget", "deluge", "amule", "slskd"]),
    ("Network", ["pihole", "pi-hole", "adguard", "unbound", "nginx-proxy", "npm", "traefik", "caddy",
                 "wireguard", "wg-easy", "cloudflared", "tailscale", "nginx", "haproxy"]),
    ("Monitoring", ["grafana", "prometheus", "uptime-kuma", "uptime", "netdata", "dozzle", "influxdb", "loki",
                    "beszel", "glances", "speedtest", "healthchecks"]),
    ("Home automation", ["homeassistant", "home-assistant", "node-red", "nodered", "mosquitto", "zigbee2mqtt",
                         "esphome", "frigate", "homebridge", "music-assistant"]),
    ("Files & storage", ["nextcloud", "syncthing", "filebrowser", "minio", "samba", "duplicati", "seafile",
                         "immich", "photoprism", "paperless"]),
    ("Development", ["gitea", "forgejo", "gitlab", "portainer", "dockhand", "code-server", "jenkins", "registry",
                     "vscode", "n8n"]),
    ("Tools", ["vaultwarden", "bitwarden", "it-tools", "dashy", "homepage", "heimdall", "homarr", "joplin",
               "stirling", "wikijs", "bookstack", "hedgedoc", "linkwarden", "freshrss", "miniflux"]),
]


def _image_base(image: str) -> str:
    """'ghcr.io/x/jellyfin:10.9' -> 'jellyfin'"""
    return (image or "").split("@")[0].rsplit("/", 1)[-1].split(":")[0].lower()


def categorize(image: str, name: str, label: str | None = None) -> str:
    if label:
        return label
    hay = f"{(image or '').lower()} {(name or '').lower()}"
    for cat, words in CATEGORY_RULES:
        if any(w in hay for w in words):
            return cat
    return DEFAULT_CATEGORY


def icon_url(icon: str | None, image: str, name: str) -> str:
    if icon and icon.startswith(("http://", "https://")):
        return icon
    slug = (icon or _image_base(image) or name or "").lower().replace(" ", "-")
    return f"{ICON_CDN}{slug}.png" if slug else ""


def name_to_ip_map(s) -> dict[str, str]:
    """Hostname -> IP from AdGuard DNS rewrites (exact names only) and from scanner/integration records."""
    out = {}
    recs = s.scalars(select(SourceRecord).where(SourceRecord.ip.is_not(None)))
    # AdGuard rewrites first (authoritative DNS), then other sources fill the gaps
    for r in sorted(recs, key=lambda r: r.source != "adguard"):
        if r.source == "dockhand" or not r.name or "*" in r.name:
            continue
        out.setdefault(r.name.lower().rstrip("."), r.ip)
    return out


def _resolve(host: str, names: dict[str, str]) -> str:
    """Host as an IP literal. Names are matched to an IP via the map; unknown names stay as they are."""
    if not host:
        return host
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    ip = names.get(host.lower().rstrip("."))
    return ip or host


def _ip_url(url: str, names: dict[str, str]) -> str:
    """Rewrite the host part of a link to its IP, keeping scheme, port and path."""
    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        return url
    ip = _resolve(host, names)
    if ip == host:
        return url
    if ":" in ip:  # IPv6 literal needs brackets in a URL
        ip = f"[{ip}]"
    netloc = ip + (f":{parts.port}" if parts.port else "")
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def _service_url(extra: dict, labels: dict, names: dict[str, str] | None = None) -> str | None:
    names = names or {}
    if labels.get("dashboard.url"):
        return _ip_url(labels["dashboard.url"], names)
    host = extra.get("env_host")
    if not host:
        return None
    host = _resolve(host, names)
    if labels.get("dashboard.port"):  # explicit port chosen by the user
        return f"http://{host}:{labels['dashboard.port']}"
    for p in extra.get("ports") or []:
        if p.get("ip") in ("127.0.0.1", "::1"):  # bound to loopback only: not reachable from the LAN
            continue
        if p.get("public"):
            return f"http://{host}:{p['public']}"
    return f"http://{host}:80"  # no published port: assume the web UI is on 80


def build_services(s) -> list[dict]:
    seen, out = set(), []
    names = name_to_ip_map(s)
    for r in s.scalars(select(SourceRecord).where(SourceRecord.source == "dockhand", SourceRecord.kind == "container")):
        extra = r.extra or {}
        cid = extra.get("container_id") or f"{r.name}"
        if cid in seen:  # one container with several networks yields several records
            continue
        seen.add(cid)
        labels = extra.get("labels") or {}
        if str(labels.get("dashboard.hide", "")).lower() == "true":
            continue
        url = _service_url(extra, labels, names)
        if not url:
            continue
        image = extra.get("image") or ""
        name = labels.get("dashboard.name") or r.name
        desc = labels.get("dashboard.description") or image or "container"
        out.append({
            "name": name,
            "category": categorize(image, r.name, labels.get("dashboard.category")),
            "description": desc,
            "url": url,
            "icon": icon_url(labels.get("dashboard.icon"), image, r.name),
            "state": r.state or "",
            "environment": extra.get("environment") or "",
        })
    out.sort(key=lambda x: (x["category"].lower(), x["name"].lower()))
    return out


def build_proxmox(s) -> dict:
    st = s.get(SourceStatus, "proxmox")
    recs = list(s.scalars(select(SourceRecord).where(SourceRecord.source == "proxmox")))
    nodes = [r for r in recs if r.kind == "node"]
    guests, seen = {}, set()
    for r in recs:
        if r.kind not in ("vm", "lxc"):
            continue
        ex = r.extra or {}
        key = (r.kind, ex.get("node"), ex.get("vmid", ex.get("ctid")), r.name)  # one guest, many NIC records
        if key in seen:
            continue
        seen.add(key)
        guests.setdefault(r.kind, []).append(r.state)

    def run(kind):
        g = guests.get(kind, [])
        return sum(1 for x in g if x == "running"), len(g)

    vm_run, vm_all = run("vm")
    lxc_run, lxc_all = run("lxc")
    online = [n for n in nodes if n.state == "online"]
    cpu_sum = sum((n.extra.get("cpu") or 0) * (n.extra.get("maxcpu") or 0) for n in online)
    cores = sum(n.extra.get("maxcpu") or 0 for n in online)
    sum_ = lambda k: sum(n.extra.get(k) or 0 for n in online)
    per_node = [{"node": n.name, "status": n.state or "", "cpu": n.extra.get("cpu"),
                 "maxcpu": n.extra.get("maxcpu"), "mem": n.extra.get("mem"), "maxmem": n.extra.get("maxmem"),
                 "disk": n.extra.get("disk"), "maxdisk": n.extra.get("maxdisk"), "uptime": n.extra.get("uptime")}
                for n in sorted(nodes, key=lambda n: n.name)]
    cluster = next((n.extra.get("cluster") for n in nodes if n.extra.get("cluster")), "")
    return {
        "configured": bool(st) or bool(recs),
        "ok": bool(st and st.ok),
        "error": (st.error if st else "") or "",
        "last_ok": iso(st.last_ok) if st else None,
        "cluster": cluster,
        "nodes_online": len(online), "nodes_total": len(nodes),
        "vms_running": vm_run, "vms_total": vm_all,
        "lxc_running": lxc_run, "lxc_total": lxc_all,
        "cpu_pct": round(100 * cpu_sum / cores, 1) if cores else None,
        "cores": cores,
        "mem_used": sum_("mem"), "mem_total": sum_("maxmem"),
        "disk_used": sum_("disk"), "disk_total": sum_("maxdisk"),
        "nodes": per_node,
    }


def dashboard(s) -> dict:
    return {"proxmox": build_proxmox(s), "services": build_services(s)}
