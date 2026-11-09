"""Own TLS certificate for the web UI.

The PEM certificate chain and private key are stored in DATA_DIR/tls/ (key mode 0600).
When both files exist the server starts with HTTPS (see app/serve.py); the switch takes
effect on the next start of the process/container.
"""
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization


def tls_dir() -> Path:
    return Path(os.environ.get("DATA_DIR", "data")) / "tls"


def paths() -> tuple[Path, Path] | None:
    d = tls_dir()
    cert, key = d / "cert.pem", d / "key.pem"
    return (cert, key) if cert.is_file() and key.is_file() else None


def enabled() -> bool:
    """HTTPS env switch: HTTPS=auto (default: on when a certificate is installed),
    HTTPS=0/off/http forces HTTP, HTTPS=1/on/https requires the certificate."""
    v = os.environ.get("HTTPS", "auto").strip().lower()
    if v in ("0", "false", "no", "off", "http"):
        return False
    if v in ("1", "true", "yes", "on", "https"):
        if paths() is None:
            raise RuntimeError("HTTPS=1, ale brak certyfikatu w DATA_DIR/tls (cert.pem, key.pem)")
        return True
    return paths() is not None


def status() -> dict:
    p = paths()
    info = {"installed": p is not None, "subject": "", "not_after": "", "names": []}
    if p:
        try:
            cert = x509.load_pem_x509_certificate(p[0].read_bytes())
            info["subject"] = cert.subject.rfc4514_string()
            info["not_after"] = cert.not_valid_after_utc.isoformat()
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                info["names"] = [str(n.value) for n in san]
            except x509.ExtensionNotFound:
                pass
        except (ValueError, OSError):
            info["error"] = "Nie można odczytać zapisanego certyfikatu"
    return info


def save(cert_pem: str, key_pem: str) -> dict:
    """Validate that the key matches the certificate, then store both. Raises ValueError."""
    cert_b = (cert_pem or "").strip().encode()
    key_b = (key_pem or "").strip().encode()
    if not cert_b or not key_b:
        raise ValueError("Podaj certyfikat i klucz prywatny (PEM)")
    try:
        cert = x509.load_pem_x509_certificate(cert_b)
    except ValueError:
        raise ValueError("Certyfikat nie jest poprawnym plikiem PEM")
    try:
        key = serialization.load_pem_private_key(key_b, password=None)
    except (ValueError, TypeError):
        raise ValueError("Klucz prywatny nie jest poprawnym plikiem PEM (bez hasła)")
    pub_fmt = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if key.public_key().public_bytes(*pub_fmt) != cert.public_key().public_bytes(*pub_fmt):
        raise ValueError("Klucz nie pasuje do certyfikatu")
    d = tls_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / "cert.pem").write_bytes(cert_b + b"\n")
    key_path = d / "key.pem"
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key_b + b"\n")
    os.chmod(key_path, 0o600)
    return status()


def remove() -> dict:
    for name in ("cert.pem", "key.pem"):
        (tls_dir() / name).unlink(missing_ok=True)
    return status()
