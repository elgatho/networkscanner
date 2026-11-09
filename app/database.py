import json
import logging
from sqlalchemy import (JSON, Boolean, DateTime, Integer, String, Text, create_engine,
                        event, select)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from . import config
from .util import utcnow

log = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class Subnet(Base):
    __tablename__ = "subnets"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    cidr: Mapped[str] = mapped_column(String(64), unique=True)
    gateway: Mapped[str | None] = mapped_column(String(64), nullable=True)
    vlan: Mapped[int | None] = mapped_column(Integer, nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    scan_interval: Mapped[int | None] = mapped_column(Integer, nullable=True)  # minutes, full scan
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    exclusions: Mapped[list] = mapped_column(JSON, default=list)  # DHCP pools etc.
    last_scan_at: Mapped[object] = mapped_column(DateTime, nullable=True)
    last_scan_status: Mapped[str] = mapped_column(String(200), default="never")
    last_full_scan_at: Mapped[object] = mapped_column(DateTime, nullable=True)
    last_full_scan_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    l2: Mapped[bool] = mapped_column(Boolean, default=False)  # ARP/NDP effective


class SourceRecord(Base):
    """Current snapshot of what an integration reports (replaced on each refresh)."""
    __tablename__ = "source_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(20), index=True)
    kind: Mapped[str] = mapped_column(String(20))  # container|vm|lxc|esphome
    name: Mapped[str] = mapped_column(String(200))
    ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    mac: Mapped[str | None] = mapped_column(String(17), index=True, nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(200), nullable=True)
    ip_origin: Mapped[str] = mapped_column(String(20), default="configured")
    state: Mapped[str | None] = mapped_column(String(40), nullable=True)
    vlan: Mapped[int | None] = mapped_column(Integer, nullable=True)
    extra: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[object] = mapped_column(DateTime, default=utcnow)


class ServiceLink(Base):
    """One dashboard tile per container. `auto` = read from Dockhand (on creation / refresh);
    `override` = fields edited by hand (never overwritten by a refresh)."""
    __tablename__ = "service_links"
    key: Mapped[str] = mapped_column(String(300), primary_key=True)  # "<environment>|<container id>"
    auto: Mapped[dict] = mapped_column(JSON, default=dict)
    override: Mapped[dict] = mapped_column(JSON, default=dict)
    seen_at: Mapped[object] = mapped_column(DateTime, default=utcnow)


class ServiceUse(Base):
    """How often a dashboard tile was opened (feeds the 'most used' row)."""
    __tablename__ = "service_uses"
    key: Mapped[str] = mapped_column(String(300), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0)
    last_at: Mapped[object] = mapped_column(DateTime, nullable=True)


class SourceStatus(Base):
    __tablename__ = "source_status"
    source: Mapped[str] = mapped_column(String(20), primary_key=True)
    last_run: Mapped[object] = mapped_column(DateTime, nullable=True)
    last_ok: Mapped[object] = mapped_column(DateTime, nullable=True)
    ok: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str] = mapped_column(Text, default="")
    count: Mapped[int] = mapped_column(Integer, default=0)


class ScanResult(Base):
    __tablename__ = "scan_results"
    ip: Mapped[str] = mapped_column(String(64), primary_key=True)
    subnet_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    mac: Mapped[str | None] = mapped_column(String(17), nullable=True, index=True)
    vendor: Mapped[str | None] = mapped_column(String(200), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(200), nullable=True)
    alive: Mapped[bool] = mapped_column(Boolean, default=False)
    neigh_state: Mapped[str | None] = mapped_column(String(20), nullable=True)
    ports: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[object] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[object] = mapped_column(DateTime, nullable=True)
    last_checked: Mapped[object] = mapped_column(DateTime, nullable=True)


class Reservation(Base):
    __tablename__ = "reservations"
    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), unique=True)
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow)


class Event(Base):
    """History: new_host, online, offline, ip_changed, mac_changed, source_change."""
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[object] = mapped_column(DateTime, default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(30), index=True)
    ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    mac: Mapped[str | None] = mapped_column(String(17), index=True, nullable=True)
    subnet_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[str] = mapped_column(Text, default="")


class ScanRun(Base):
    __tablename__ = "scan_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    subnet_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    kind: Mapped[str] = mapped_column(String(20))
    started: Mapped[object] = mapped_column(DateTime, default=utcnow)
    finished: Mapped[object] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="running")
    found: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[str] = mapped_column(Text, default="")


class ConflictRule(Base):
    """Silences IP-conflict warnings for an IP and/or MAC (known-harmless duplicates)."""
    __tablename__ = "conflict_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    mac: Mapped[str | None] = mapped_column(String(17), nullable=True, index=True)
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[object] = mapped_column(DateTime, default=utcnow)


class Meta(Base):
    """Internal key/value state (password hash, notifier cursors)."""
    __tablename__ = "meta"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str] = mapped_column(Text)  # JSON


def meta_get(s, key, default=None):
    r = s.get(Meta, key)
    try:
        return json.loads(r.value) if r else default
    except ValueError:
        return default


def meta_set(s, key, value):
    r = s.get(Meta, key)
    if r:
        r.value = json.dumps(value)
    else:
        s.add(Meta(key=key, value=json.dumps(value)))
    s.commit()


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str] = mapped_column(Text)  # JSON encoded


engine = None
SessionLocal = None


def init_db(url: str | None = None):
    global engine, SessionLocal
    url = url or config.DATABASE_URL
    kw = {}
    if url.startswith("sqlite"):
        kw["connect_args"] = {"check_same_thread": False, "timeout": 30}
        if ":memory:" in url:
            from sqlalchemy.pool import StaticPool
            kw["poolclass"] = StaticPool
    engine = create_engine(url, **kw)
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _pragma(dbapi, _):
            c = dbapi.cursor()
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA foreign_keys=ON")
            c.close()
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(engine, expire_on_commit=False)
    return engine


def get_settings(s) -> dict:
    import os
    out = {}
    stored = {r.key: r.value for r in s.scalars(select(Setting))}
    for k, d in config.DEFAULTS.items():
        if k in stored:
            try:
                out[k] = json.loads(stored[k])
                continue
            except ValueError:
                pass
        env = os.environ.get(k.upper())
        if env is not None and env != "":
            if isinstance(d, bool):
                out[k] = env.lower() in ("1", "true", "yes", "on")
            elif isinstance(d, int):
                try:
                    out[k] = int(env)
                except ValueError:
                    out[k] = d
            else:
                out[k] = env
        else:
            out[k] = d
    return out


def set_settings(s, updates: dict):
    for k, v in updates.items():
        if k not in config.DEFAULTS:
            continue
        d = config.DEFAULTS[k]
        if isinstance(d, bool):
            v = bool(v)
        elif isinstance(d, int):
            v = int(v)
        else:
            v = str(v).strip()
        row = s.get(Setting, k)
        if row:
            row.value = json.dumps(v)
        else:
            s.add(Setting(key=k, value=json.dumps(v)))
    s.commit()
