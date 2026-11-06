import asyncio
import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import select

from . import database as db
from .database import Subnet
from . import device_discovery as dd

log = logging.getLogger(__name__)
sched = AsyncIOScheduler(job_defaults={"coalesce": True, "max_instances": 1, "misfire_grace_time": 120})


async def _in_thread(fn, *a):
    await asyncio.get_running_loop().run_in_executor(None, fn, *a)


async def job_source(name):
    await _in_thread(dd.refresh_source, name)


async def job_scan(subnet_id, kind):
    await _in_thread(dd.scan_subnet, subnet_id, kind)


async def job_discovery_all():
    with db.SessionLocal() as s:
        ids = list(s.scalars(select(Subnet.id).where(Subnet.enabled)))
    for i in ids:  # sequential: gentle on the network
        await job_scan(i, "discovery")


def reschedule():
    """(Re)create all jobs from current settings/subnets."""
    with db.SessionLocal() as s:
        st = db.get_settings(s)
        subs = list(s.scalars(select(Subnet).where(Subnet.enabled)))
    for j in sched.get_jobs():
        j.remove()
    for name in dd.CONNECTORS:
        if st[f"{name}_enabled"]:
            sched.add_job(job_source, "interval", minutes=max(1, st[f"{name}_interval"]), args=[name], id=name)
    sched.add_job(job_discovery_all, "interval", minutes=max(1, st["discovery_interval"]), id="discovery")
    sched.add_job(job_notify, "interval", minutes=1, id="notify")
    for sn in subs:
        sched.add_job(job_scan, "interval", minutes=max(5, sn.scan_interval or st["full_scan_interval"]),
                      args=[sn.id, "full"], id=f"full-{sn.id}")


async def job_notify():
    from . import notifier
    await _in_thread(notifier.run)
