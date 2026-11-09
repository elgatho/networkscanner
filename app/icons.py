"""Local cache for tile icons.

Icons are downloaded once into DATA_DIR/icons (default: ./data/icons, /data/icons in the container)
and served from /icons/<file>. Tiles store the local path, so the dashboard never fetches from the internet.
A download that fails leaves the remote URL in place; the next refresh or save tries again.
"""
import hashlib
import logging
import os
from pathlib import Path

import httpx

log = logging.getLogger(__name__)

DATA_DIR = Path(os.environ.get("DATA_DIR", "data"))
ICON_DIR = DATA_DIR / "icons"
URL_PREFIX = "/icons/"
MAX_BYTES = 512 * 1024
TYPES = {
    "image/png": ".png", "image/svg+xml": ".svg", "image/jpeg": ".jpg", "image/webp": ".webp",
    "image/gif": ".gif", "image/x-icon": ".ico", "image/vnd.microsoft.icon": ".ico",
}

ICON_DIR.mkdir(parents=True, exist_ok=True)


def _stem(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:32]


def _cached(url: str) -> str | None:
    stem = _stem(url)
    for ext in set(TYPES.values()):
        if (ICON_DIR / (stem + ext)).is_file():
            return URL_PREFIX + stem + ext
    return None


def _download(url: str) -> tuple[bytes, str] | None:
    """(bytes, extension) of an image, or None when the URL is not a reachable image of allowed size."""
    try:
        with httpx.Client(timeout=10, follow_redirects=True) as c:
            with c.stream("GET", url) as r:
                if r.status_code != 200:
                    return None
                ctype = r.headers.get("content-type", "").split(";")[0].strip().lower()
                ext = TYPES.get(ctype)
                if not ext:
                    return None
                body = bytearray()
                for chunk in r.iter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_BYTES:
                        return None
                return bytes(body), ext
    except httpx.HTTPError as e:
        log.warning("icon download failed %s: %s", url, e)
        return None


def localize(icon: str | None) -> str:
    """Return a /icons/... path for an http(s) icon URL, downloading it if it is not cached yet.
    Other values (empty, already local) are returned unchanged. Falls back to the remote URL on failure."""
    if not icon or not icon.startswith(("http://", "https://")):
        return icon or ""
    hit = _cached(icon)
    if hit:
        return hit
    got = _download(icon)
    if got is None:
        return icon
    body, ext = got
    name = _stem(icon) + ext
    tmp = ICON_DIR / (name + ".part")
    tmp.write_bytes(body)
    os.replace(tmp, ICON_DIR / name)  # atomic: a half-written file is never served
    return URL_PREFIX + name
