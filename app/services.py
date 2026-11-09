"""Dashboard data: Proxmox overview and Docker service tiles.

Tiles are one row per Docker container (table `service_links`). The `auto` part is read from Dockhand
only when a container first appears, or on an explicit refresh (Settings -> Refresh). The `override`
part holds fields edited by hand on the dashboard and always wins over `auto`; a refresh never touches it.

Optional labels on the container override the defaults:
  dashboard.url          full link (default: http://<LAN address or environment host>:<port>)
  dashboard.port         port used in the default link
  dashboard.name         tile title (default: container name)
  dashboard.category     category (default: guessed from the image name)
  dashboard.description  text (default: image name)
  dashboard.icon         dashboard-icons slug (e.g. jellyfin) or a full image URL (default: from image name)
  dashboard.hide         "true" to hide the tile (still listed in edit mode)

Hand-made tiles (not from any container) are rows with key "custom|<uuid>" and no `auto` part.

Default link: a container with its own LAN address (macvlan) links to that address on port 80, or https if
only 443 is exposed; otherwise the published port on the Docker host; otherwise the host on port 80.
"""
import ipaddress
import logging
import uuid

from sqlalchemy import select

from .database import ServiceLink, ServiceUse, SourceRecord, SourceStatus
from . import icons
from .util import iso, utcnow

log = logging.getLogger(__name__)

ICON_CDN = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/"  # the repo behind dashboardicons.com
DEFAULT_CATEGORY = "Other"
EDITABLE = ("name", "category", "description", "url", "icon", "hidden", "linkable")
CUSTOM_PREFIX = "custom|"

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


def ip_names(s) -> dict[str, str]:
    """IP -> DNS name from AdGuard rewrites (exact names only; shortest name wins). Used to show names in links."""
    out: dict[str, str] = {}
    recs = s.scalars(select(SourceRecord).where(SourceRecord.source == "adguard", SourceRecord.ip.is_not(None)))
    for r in sorted(recs, key=lambda r: (len(r.name or ""), r.name or "")):
        if not r.name or "*" in r.name:
            continue
        out.setdefault(r.ip, r.name.lower().rstrip("."))
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


def _lan_ip(host: str, ips: list[str]) -> str | None:
    """Container's own LAN address: first one on the Docker host's /24 (macvlan), else any address
    outside Docker's default bridge range (172.16.0.0/12) and not the host itself."""
    try:
        h = ipaddress.ip_network(f"{host}/24", strict=False)
    except ValueError:
        return None
    bridge = ipaddress.ip_network("172.16.0.0/12")
    parsed = []
    for ip in ips:
        try:
            parsed.append(ipaddress.ip_address(ip))
        except ValueError:
            continue
    for ip in parsed:
        if ip.version == 4 and ip in h and str(ip) != host:
            return str(ip)
    for ip in parsed:
        if ip.version == 4 and ip.is_private and not ip.is_loopback and ip not in bridge and str(ip) != host:
            return str(ip)
    return None


def _scheme(port: int) -> str:
    return "https" if port == 443 else "http"


def _service_url(extra: dict, labels: dict, names: dict[str, str] | None = None,
                 lan_ip: str | None = None, dns: dict[str, str] | None = None) -> str | None:
    """Link for a tile. dashboard.url is used exactly as typed. Otherwise the address is the DNS name
    from AdGuard when one exists for that IP, else the IP."""
    names = names or {}
    dns = dns or {}
    if labels.get("dashboard.url"):
        return labels["dashboard.url"]
    host = extra.get("env_host")
    if not host:
        return None
    shown = dns.get(_resolve(host, names), host)
    if labels.get("dashboard.port"):  # explicit port; a LAN-attached container answers on its own address
        try:
            port = int(labels["dashboard.port"])
        except ValueError:
            port = 80
        return f"{_scheme(port)}://{dns.get(lan_ip, lan_ip) if lan_ip else shown}:{port}"
    for p in extra.get("ports") or []:
        if p.get("ip") in ("127.0.0.1", "::1"):  # bound to loopback only: not reachable from the LAN
            continue
        if p.get("public"):  # published on the Docker host, so the host address is the one to use
            return f"{_scheme(p['public'])}://{shown}:{p['public']}"
    if not lan_ip:
        return f"http://{shown}:80"  # no published port and no LAN address: assume the web UI is on 80
    lan = dns.get(lan_ip, lan_ip)
    exposed = sorted(set(extra.get("exposed") or []))
    if not exposed or 80 in exposed:
        return f"http://{lan}:80"
    if 443 in exposed:
        return f"https://{lan}"
    return f"http://{lan}:{exposed[0]}"


def _groups(recs: list[dict]) -> dict[str, dict]:
    """Container records (one per network) -> {"<environment>|<container id>": {extra, name, state, ips}}."""
    groups = {}
    for r in recs:
        ex = r.get("extra") or {}
        key = f"{ex.get('environment', '')}|{ex.get('container_id') or r.get('name')}"
        g = groups.setdefault(key, {"extra": ex, "name": r.get("name") or "", "state": r.get("state") or "", "ips": []})
        if r.get("ip"):
            g["ips"].append(r["ip"])
    return groups


def auto_fields(grp: dict, names: dict[str, str], dns: dict[str, str] | None = None) -> dict:
    extra = grp["extra"]
    labels = extra.get("labels") or {}
    image = extra.get("image") or ""
    name = grp["name"]
    raw = extra.get("env_host") or ""
    host = _resolve(raw, names) if raw else ""
    lan = _lan_ip(host, grp["ips"]) if host else None
    url = _service_url(extra, labels, names, lan, dns) or ""
    return {
        "name": labels.get("dashboard.name") or name,
        "category": categorize(image, name, labels.get("dashboard.category")),
        "description": labels.get("dashboard.description") or image or "container",
        "icon": icon_url(labels.get("dashboard.icon"), image, name),
        "url": url, "linkable": bool(url),
        "hidden": str(labels.get("dashboard.hide", "")).lower() == "true",
        "state": grp["state"], "environment": extra.get("environment") or "", "host": lan or host,
    }


def sync_links(s, st: dict | None = None, refresh: bool = False) -> set[str]:
    """Create tiles for new containers (reading their details from Dockhand once), or refresh all of them.
    Returns the keys of the containers currently known to Dockhand."""
    recs = [{"name": r.name, "state": r.state, "ip": r.ip, "extra": r.extra or {}}
            for r in s.scalars(select(SourceRecord).where(SourceRecord.source == "dockhand",
                                                          SourceRecord.kind == "container"))]
    groups = _groups(recs)
    rows = {r.key: r for r in s.scalars(select(ServiceLink))}
    targets = set(groups) if refresh else {k for k in groups if k not in rows}
    if st and st.get("dockhand_enabled") and targets:
        try:
            from .dockhand_connector import DockhandConnector
            detail = _groups(DockhandConnector(st).describe(targets))
            for key, dg in detail.items():  # inspect data: exposed ports and all addresses
                if key in groups:
                    groups[key]["extra"] = {**groups[key]["extra"], "exposed": dg["extra"].get("exposed", [])}
                    groups[key]["ips"] = sorted(set(groups[key]["ips"]) | set(dg["ips"]))
        except Exception as e:  # tiles still get created from the records we already have
            log.warning("Dockhand container details unavailable: %s", e)
    names, dns = name_to_ip_map(s), ip_names(s)
    now = utcnow()
    for key in targets:
        auto = auto_fields(groups[key], names, dns)
        auto["icon"] = icons.localize(auto["icon"])  # download once; the tile keeps the local /icons/ path
        row = rows.get(key)
        if row is None:
            s.add(ServiceLink(key=key, auto=auto, override={}, seen_at=now))
        elif refresh:
            row.auto, row.seen_at = auto, now
    s.commit()
    return set(groups)


def _icon_value(v: str) -> str:
    """Slug or URL typed by the user -> local /icons/ path (already local values are kept)."""
    if not v or v.startswith("/"):
        return v
    return icons.localize(icon_url(v, "", ""))


def _clean(data: dict) -> dict:
    """Keep only editable fields that were sent and are not empty; validates the URL."""
    clean = {}
    for k in EDITABLE:
        if k not in data or data[k] is None:
            continue
        if k in ("hidden", "linkable"):
            clean[k] = bool(data[k])
        else:
            v = str(data[k]).strip()
            if k == "icon":
                v = _icon_value(v)
            if v:
                clean[k] = v
    if clean.get("url") and not clean["url"].startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    return clean


def set_override(s, key: str, data: dict) -> dict:
    """Store the hand-edited fields of a tile (fields equal to the auto value are not sent). Empty -> reset."""
    row = s.get(ServiceLink, key)
    if row is None:
        raise LookupError(key)
    clean = _clean(data)
    if key.startswith(CUSTOM_PREFIX) and not clean.get("name"):
        raise ValueError("Podaj nazwę kafelka")  # a hand-made tile has no container data to fall back to
    row.override = clean
    s.commit()
    return clean


def set_category(s, key: str, category: str) -> dict:
    """Move one tile to another category (drag and drop). Other hand-made fields of the tile are kept."""
    row = s.get(ServiceLink, key)
    if row is None:
        raise LookupError(key)
    category = str(category or "").strip()
    if not category:
        raise ValueError("Podaj nazwę kategorii")
    row.override = {**(row.override or {}), "category": category}  # new dict so the JSON change is saved
    s.commit()
    return row.override


def record_open(s, key: str) -> int:
    """Count one click on a tile. Returns the new total."""
    if s.get(ServiceLink, key) is None:
        raise LookupError(key)
    row = s.get(ServiceUse, key)
    if row is None:
        row = ServiceUse(key=key, count=0)
        s.add(row)
    row.count = (row.count or 0) + 1
    row.last_at = utcnow()
    s.commit()
    return row.count


def rename_category(s, old: str, new: str) -> int:
    """Rename a category: every tile in `old` moves to `new` (stored as an override). Returns tiles changed."""
    new = str(new or "").strip()
    if not new:
        raise ValueError("Podaj nazwę kategorii")
    n = 0
    for row in s.scalars(select(ServiceLink)):
        ov = row.override or {}
        m = {**(row.auto or {}), **ov}
        if (m.get("category") or DEFAULT_CATEGORY) == old and old != new:
            row.override = {**ov, "category": new}  # new dict so the JSON change is saved
            n += 1
    s.commit()
    return n


def add_custom(s, data: dict) -> str:
    """Create a hand-made tile (not tied to any container). Returns its key."""
    clean = _clean(data)
    if not clean.get("name"):
        raise ValueError("Podaj nazwę kafelka")
    key = CUSTOM_PREFIX + uuid.uuid4().hex
    s.add(ServiceLink(key=key, auto={}, override=clean, seen_at=utcnow()))
    s.commit()
    return key


def delete_custom(s, key: str) -> None:
    """Remove a hand-made tile. Container tiles only come back from Dockhand, so they cannot be deleted."""
    if not key.startswith(CUSTOM_PREFIX):
        raise ValueError("Only hand-made tiles can be deleted")
    row = s.get(ServiceLink, key)
    if row is None:
        raise LookupError(key)
    s.delete(row)
    use = s.get(ServiceUse, key)
    if use is not None:
        s.delete(use)
    s.commit()


def build_services(s, st: dict | None = None) -> list[dict]:
    current = sync_links(s, st)
    uses = {u.key: u.count or 0 for u in s.scalars(select(ServiceUse))}
    out = []
    for row in s.scalars(select(ServiceLink)):
        custom = row.key.startswith(CUSTOM_PREFIX)
        if not custom and row.key not in current:  # container no longer present in Dockhand
            continue
        auto, ov = row.auto or {}, row.override or {}
        m = {**auto, **ov}
        url = m.get("url") or ""
        out.append({
            "key": row.key, "name": m.get("name") or "?", "category": m.get("category") or DEFAULT_CATEGORY,
            "description": m.get("description") or "", "url": url,
            "linkable": bool(m.get("linkable", True)) and bool(url),
            "icon": m.get("icon") or "", "hidden": bool(m.get("hidden")), "state": m.get("state") or "",
            "environment": m.get("environment") or "", "host": m.get("host") or "",
            "edited": bool(ov) and not custom, "custom": custom, "uses": uses.get(row.key, 0),
            "auto": {k: auto.get(k) for k in EDITABLE},
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


def dashboard(s, st: dict | None = None) -> dict:
    st = st or {}
    return {
        "proxmox": build_proxmox(s),
        "services": build_services(s, st),
        "search": {"enabled": bool(st.get("search_fallback_enabled")), "url": st.get("search_url") or ""},
        "top_used": {"enabled": bool(st.get("top_used_enabled", True)),
                     "count": min(24, max(1, int(st.get("top_used_count", 6) or 6)))},
    }
