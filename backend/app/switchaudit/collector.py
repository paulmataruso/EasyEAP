"""The switch audit collector: polls every switch with monitoring on over SNMP (docs/plans/switch-audit.md §0).

Runs as its own container (`entrypoint.sh collector`) from the API image, so a slow or failing switch never delays a
RADIUS answer or a worker job. At most MAX_PARALLEL switches are polled at once, each in its own thread with its own
time budget; a switch is due when its next_poll_at has passed or an admin pressed "Poll now".

    python -m app.switchaudit.collector              # the service
    python -m app.switchaudit.collector --once ID    # poll one switch now and print the result (support, tests)
"""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime

from sqlalchemy import or_, select

from app import models as m
from app.db import platform_session
from app.security.redact import configure_logging
from app.switchaudit import service

log = logging.getLogger("easyeap.collector")
MAX_PARALLEL = 8
TICK_SECONDS = 5
HEARTBEAT_SECONDS = 30
PRUNE_SECONDS = 24 * 3600
_stop = False


def due(now: datetime) -> list[tuple[uuid.UUID, uuid.UUID]]:
    """(client id, tenant id) of every switch to poll now, oldest first."""
    with platform_session() as s:
        q = (select(m.RadiusClient.id, m.RadiusClient.tenant_id)
             .join(m.Tenant, m.Tenant.id == m.RadiusClient.tenant_id)
             .outerjoin(m.SwitchState, m.SwitchState.client_id == m.RadiusClient.id)
             .where(m.RadiusClient.monitoring["enabled"].as_boolean().is_(True), m.RadiusClient.snmp_secret_ct.is_not(None),
                    m.Tenant.status.in_(("active", "setup")),
                    or_(m.SwitchState.client_id.is_(None), m.SwitchState.next_poll_at.is_(None), m.SwitchState.next_poll_at <= now,
                        m.SwitchState.poll_requested_at.is_not(None)))
             .order_by(m.SwitchState.poll_requested_at.desc().nulls_last(), m.SwitchState.next_poll_at.asc().nulls_first())
             .limit(200))
        return [(r[0], r[1]) for r in s.execute(q)]


def heartbeat(inflight: int, polled: int) -> None:
    with platform_session() as s:
        hb = s.get(m.PlatformSetting, "collector_heartbeat") or m.PlatformSetting(key="collector_heartbeat", value={})
        hb.value = {"at": datetime.now(UTC).isoformat(), "inflight": inflight, "polled": polled}
        s.add(hb)


def _poll(cid: uuid.UUID, tid: uuid.UUID) -> bool:
    try:
        res = service.poll_client(cid, tid)
        if not res.get("ok"):
            log.info("Switch %s: %s", cid, res.get("error"))
        return True
    except Exception as exc:  # noqa: BLE001 — one switch's failure never stops the others
        log.warning("Switch %s poll failed: %s: %s", cid, type(exc).__name__, exc)
        return False


def main() -> None:
    configure_logging()

    def stop(*_: object) -> None:
        global _stop
        _stop = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    from app.backup.engine import maintenance
    from app.logs.dbhandler import install as install_db_logging
    install_db_logging("collector")
    log.info("EasyEAP collector started")
    pool = ThreadPoolExecutor(MAX_PARALLEL, thread_name_prefix="poll")
    inflight: dict[uuid.UUID, Future] = {}
    cooldown: dict[uuid.UUID, float] = {}  # a poll that raised (database trouble) waits a minute before the next try
    polled, last_beat, last_prune = 0, 0.0, 0.0
    while not _stop:
        try:
            for cid in [k for k, f in inflight.items() if f.done()]:
                if inflight.pop(cid).result() is False:
                    cooldown[cid] = time.monotonic() + 60
                polled += 1
            for cid in [k for k, until in cooldown.items() if until < time.monotonic()]:
                cooldown.pop(cid)
            if maintenance():  # a restore is replacing the database: resume when it's done
                time.sleep(3)
                continue
            if time.monotonic() - last_beat > HEARTBEAT_SECONDS:
                heartbeat(len(inflight), polled)
                last_beat = time.monotonic()
            if time.monotonic() - last_prune > PRUNE_SECONDS:
                with platform_session() as s:
                    service.prune(s)
                last_prune = time.monotonic()
            free = MAX_PARALLEL - len(inflight)
            if free > 0:
                for cid, tid in due(datetime.now(UTC)):
                    if cid in inflight or cid in cooldown:
                        continue
                    inflight[cid] = pool.submit(_poll, cid, tid)
                    free -= 1
                    if free == 0:
                        break
        except Exception as exc:  # noqa: BLE001 — keep the collector alive; the database may be restarting
            log.error("Collector loop error: %s", exc)
            time.sleep(TICK_SECONDS)
        time.sleep(TICK_SECONDS)
    pool.shutdown(wait=False, cancel_futures=True)
    log.info("EasyEAP collector stopped")


def once(client_id: str) -> int:
    cid = uuid.UUID(client_id)
    with platform_session() as s:
        c = s.get(m.RadiusClient, cid)
        if c is None:
            print(json.dumps({"ok": False, "error": "No such switch."}))
            return 2
        tid = c.tenant_id
    res = service.poll_client(cid, tid)
    print(json.dumps(res, default=str))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", metavar="CLIENT_ID")
    args = ap.parse_args()
    if args.once:
        configure_logging()
        sys.exit(once(args.once))
    main()
