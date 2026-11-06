"""Webhook notifications for changes. Generic JSON POST (also fine for ntfy/Gotify/HA/n8n webhooks).

Runs periodically: new history events since the last cursor + newly appeared IP conflicts + sources that went down.
The first run only sets the cursor so nothing is sent for historical data.
"""
import json
import logging

import httpx
from sqlalchemy import func, select

from . import database as db, ip_manager as ipm
from .database import Event, SourceStatus
from .util import iso

log = logging.getLogger(__name__)
EVENT_TYPES = ("new_host", "mac_changed", "ip_changed", "online", "offline", "conflict", "source_down", "source_new")
MAX_PER_RUN = 20


def _send(st, payload):
    headers = {"Content-Type": "application/json", "User-Agent": "ip-scanner"}
    if st["webhook_auth_header"]:
        headers["Authorization"] = st["webhook_auth_header"]
    r = httpx.post(st["webhook_url"], content=json.dumps(payload), headers=headers, timeout=10,
                   verify=st["webhook_verify_tls"], follow_redirects=False)
    r.raise_for_status()


def make_payload(event, title, message, ip=None, mac=None, ts=None):
    return {"event": event, "title": title, "message": message, "ip": ip, "mac": mac, "timestamp": ts, "source": "ip-scanner"}


def test(st):
    if not st["webhook_url"]:
        return {"ok": False, "message": "webhook URL is empty"}
    try:
        _send(st, make_payload("test", "IP Scanner test", "Webhook is working"))
        return {"ok": True, "message": "test notification delivered"}
    except Exception as e:
        return {"ok": False, "message": f"{type(e).__name__}: {e}"[:300]}


def collect(s, st):
    """-> list of payloads to send; updates cursors in meta (committed by meta_set)."""
    wanted = {x.strip() for x in st["webhook_events"].split(",") if x.strip()}
    out = []
    cursor = db.meta_get(s, "notify_event_id")
    top = s.scalar(select(func.max(Event.id))) or 0
    first = cursor is None
    if not first:
        for e in s.scalars(select(Event).where(Event.id > cursor).order_by(Event.id).limit(500)):
            if e.kind in wanted:
                out.append(make_payload(e.kind, f"{e.kind.replace('_', ' ')}: {e.ip or e.mac or ''}".strip(),
                                        e.detail or "", e.ip, e.mac, iso(e.ts)))
        last = s.scalar(select(func.max(Event.id))) or 0
    else:
        last = top
    # conflicts
    entries, _ = ipm.build_inventory(s)
    now_conf = {ip: e["conflict"] for ip, e in entries.items() if e["conflict"]}
    prev = db.meta_get(s, "notify_conflicts")
    if "conflict" in wanted and prev is not None:
        for ip, why in now_conf.items():
            if ip not in prev:
                out.append(make_payload("conflict", f"IP conflict: {ip}", why, ip))
    # sources going down
    down = sorted(x.source for x in s.scalars(select(SourceStatus)) if not x.ok and x.error not in ("", "disabled"))
    prev_down = db.meta_get(s, "notify_down")
    if "source_down" in wanted and prev_down is not None:
        for name in down:
            if name not in prev_down:
                err = next(x.error for x in s.scalars(select(SourceStatus)) if x.source == name)
                out.append(make_payload("source_down", f"Source down: {name}", err))
    return out, {"event": last, "conflicts": now_conf, "down": down}


def run():
    with db.SessionLocal() as s:
        st = db.get_settings(s)
        if not st["webhook_enabled"] or not st["webhook_url"]:
            return 0
        payloads, cur = collect(s, st)
        sent = 0
        for p in payloads[:MAX_PER_RUN]:
            try:
                _send(st, p)
                sent += 1
            except Exception as e:
                log.warning("webhook delivery failed: %s", e)
                return sent  # keep cursors: retry on next run
        if len(payloads) > MAX_PER_RUN:
            try:
                _send(st, make_payload("summary", "More changes",
                                       f"{len(payloads) - MAX_PER_RUN} further notification(s) were suppressed"))
            except Exception:
                pass
        db.meta_set(s, "notify_event_id", cur["event"])
        db.meta_set(s, "notify_conflicts", cur["conflicts"])
        db.meta_set(s, "notify_down", cur["down"])
        return sent
