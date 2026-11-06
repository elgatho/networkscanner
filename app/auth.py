"""Password protection for the Settings area (session cookie, PBKDF2 hash, login throttling)."""
import hashlib
import hmac
import secrets
import threading
import time

from . import config, database as db

_sessions: dict[str, float] = {}
_fails: dict[str, list] = {}
_lock = threading.Lock()
PBKDF2_ITER = 240_000


def _hash(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, PBKDF2_ITER).hex()


def configured(s):
    return bool(config.SETTINGS_PASSWORD or db.meta_get(s, "settings_pw"))


def env_managed():
    return bool(config.SETTINGS_PASSWORD)


def set_password(s, pw):
    if len(pw) < 8:
        raise ValueError("password must be at least 8 characters")
    salt = secrets.token_bytes(16)
    db.meta_set(s, "settings_pw", {"salt": salt.hex(), "hash": _hash(pw, salt)})
    with _lock:
        _sessions.clear()  # log everyone out


def verify(s, pw):
    if config.SETTINGS_PASSWORD:
        return hmac.compare_digest(pw.encode(), config.SETTINGS_PASSWORD.encode())
    rec = db.meta_get(s, "settings_pw")
    if not rec:
        return False
    return hmac.compare_digest(_hash(pw, bytes.fromhex(rec["salt"])), rec["hash"])


def throttled(client):
    now = time.time()
    with _lock:
        _fails[client] = [t for t in _fails.get(client, []) if now - t < 300]
        return len(_fails[client]) >= 5


def record_fail(client):
    with _lock:
        _fails.setdefault(client, []).append(time.time())


def new_session():
    tok = secrets.token_urlsafe(32)
    with _lock:
        now = time.time()
        for k in [k for k, v in _sessions.items() if v < now]:
            del _sessions[k]
        _sessions[tok] = now + config.SESSION_HOURS * 3600
    return tok


def valid(tok):
    with _lock:
        exp = _sessions.get(tok or "")
        return bool(exp and exp > time.time())


def drop(tok):
    with _lock:
        _sessions.pop(tok or "", None)
