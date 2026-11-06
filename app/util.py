import ipaddress
import re
from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt):
    return dt.isoformat(timespec="seconds") + "Z" if dt else None


def norm_ip(v):
    """Normalise an IP string; drops loopback/link-local/multicast/unspecified."""
    if not v:
        return None
    v = str(v).strip().split("%")[0].split("/")[0]
    try:
        a = ipaddress.ip_address(v)
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    if a.is_loopback or a.is_unspecified or a.is_multicast or a.is_link_local:
        return None
    return str(a)


def norm_mac(v):
    if not v:
        return None
    h = re.sub(r"[^0-9a-fA-F]", "", str(v))
    if len(h) != 12 or int(h, 16) == 0:
        return None
    h = h.lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def pinned_ssl_context(url, fingerprint):
    """TLS context trusting exactly the server certificate whose SHA-256 matches `fingerprint`.

    The leaf is fetched, hash-checked, then installed as the only trust anchor, so the
    real connection is verified against that exact certificate (no check-then-connect gap).
    Hostname matching is skipped because pinning identifies the certificate itself.
    """
    import hashlib, socket, ssl
    from urllib.parse import urlparse
    fp = re.sub(r"[^0-9a-fA-F]", "", fingerprint or "").lower()
    if len(fp) != 64:
        raise ValueError("TLS fingerprint must be a SHA-256 value (64 hex chars)")
    u = urlparse(url)
    host, port = u.hostname, u.port or 443
    probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    probe.check_hostname, probe.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as sock, probe.wrap_socket(sock, server_hostname=host) as t:
        der = t.getpeercert(binary_form=True)
    actual = hashlib.sha256(der).hexdigest()
    if actual != fp:
        raise ssl.SSLError("certificate fingerprint mismatch: server presents " + ":".join(actual[i:i + 2] for i in range(0, 64, 2)).upper())
    ctx = ssl.create_default_context(cadata=ssl.DER_cert_to_PEM_cert(der))
    ctx.check_hostname = False
    ctx.verify_flags |= getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)
    return ctx
