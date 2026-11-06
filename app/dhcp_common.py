"""Shared helpers for DHCP-style sources (OPNsense, UniFi)."""
import httpx
from .util import pinned_ssl_context

DHCP_SOURCES = {"opnsense", "unifi"}


def http_client(url, headers, verify, ca, fingerprint, auth=None, timeout=20):
    v = pinned_ssl_context(url, fingerprint) if fingerprint else (ca or verify)
    return httpx.Client(base_url=url.rstrip("/"), headers=headers, auth=auth, verify=v, timeout=timeout,
                        follow_redirects=False)


def pick(d, *keys):
    """First non-empty value among several possible field names (response schemas vary by version)."""
    for k in keys:
        v = d.get(k)
        if v not in (None, "", []):
            return v
    return None


def rows_of(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for k in ("rows", "data", "items", "leases", "result"):
            if isinstance(payload.get(k), list):
                return payload[k]
    return []
