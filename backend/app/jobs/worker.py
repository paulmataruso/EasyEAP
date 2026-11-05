"""Background worker: scheduled maintenance plus queued jobs.

Schedule (per tenant unless noted):
* directory sync every `sync_interval_minutes`;
* decision refresh hourly while the directory is healthy (so RADIUS data stays inside its staleness limit; if the
  directory has been failing longer than the limit, the refresh stops and RADIUS fails closed);
* CRL rotation daily (OpenBao CRLs are issued with a 72h lifetime);
* expiry of enrollment links, purge of undelivered server-generated keys (and revocation of their certificates);
* OpenBao token renewal, job pruning, event retention (platform).
"""
from __future__ import annotations

import logging
import signal
import time
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text

from app import audit
from app import models as m
from app.db import new_session, platform_session, set_platform, set_tenant
from app.jobs import queue
from app.security.redact import configure_logging

log = logging.getLogger("easyeap.worker")
_stop = False
EVENT_RETENTION_DAYS = 180


def _handle(job: m.Job) -> None:
    tid = job.tenant_id
    s = new_session()
    try:
        if tid:
            set_tenant(s, tid)
        else:
            set_platform(s)
        if job.kind == "directory.sync":
            from app.directory.sync import sync_tenant
            res = sync_tenant(s, tid, force=bool(job.payload.get("force")))
            if res.get("ok") is False:
                audit.record(s, audit.Actor.system("Directory sync"), "directory.sync_failed", tenant_id=tid, target_type="directory", detail={"error": res.get("error")})
        elif job.kind == "policy.recompute":
            from app.policy.service import recompute_tenant
            recompute_tenant(s, tid)
        elif job.kind == "crl.rotate":
            from app.pki.openbao import OpenBao
            from app.pki.service import rotate_crl
            from app.radius.state import bump
            if s.scalars(select(m.CertificateAuthority).where(m.CertificateAuthority.tenant_id == tid, m.CertificateAuthority.role == "issuing")).first():
                rotate_crl(OpenBao(), tid)
                bump(s, tid)
        elif job.kind == "enrollment.purge":
            _purge_escrow(s)
        elif job.kind == "events.retention":
            s.execute(text("DELETE FROM auth_events WHERE at < now() - make_interval(days => :d)"), {"d": EVENT_RETENTION_DAYS})
            s.execute(text("DELETE FROM accounting_sessions WHERE updated_at < now() - make_interval(days => :d)"), {"d": EVENT_RETENTION_DAYS})
            queue.prune(s)
        elif job.kind == "openbao.renew":
            from app.pki.openbao import renew_token
            renew_token()
        else:
            raise ValueError(f"Unknown job kind {job.kind}")
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def _purge_escrow(s) -> None:
    from app.pki.openbao import OpenBao
    from app.pki.service import revoke
    from app.policy.service import recompute_tenant
    now = datetime.now(UTC)
    touched: set[uuid.UUID] = set()
    for esc in s.scalars(select(m.KeyEscrow).where(m.KeyEscrow.expires_at <= now)):
        e = s.get(m.Enrollment, esc.enrollment_id)
        if e and e.certificate_id:
            cert = s.get(m.Certificate, e.certificate_id)
            if cert and cert.status == "active":
                revoke(s, OpenBao(), cert, "cessationOfOperation", "EasyEAP (undelivered package expired)")
                touched.add(cert.tenant_id)
        if e:
            e.status, e.token_hash = "expired", None
        s.delete(esc)
    for e in s.scalars(select(m.Enrollment).where(m.Enrollment.status == "pending", m.Enrollment.expires_at <= now)):
        e.status, e.token_hash = "expired", None
    for tid in touched:
        recompute_tenant(s, tid)


def schedule() -> None:
    """Enqueue due periodic jobs (deduplicated, so running this every loop is cheap)."""
    now = datetime.now(UTC)
    with platform_session() as s:
        hb = s.get(m.PlatformSetting, "worker_heartbeat") or m.PlatformSetting(key="worker_heartbeat", value={})
        last = hb.value or {}
        hb.value = {**last, "at": now.isoformat()}
        s.add(hb)

        def due(key: str, every: timedelta) -> bool:
            prev = last.get(key)
            if prev and now - datetime.fromisoformat(prev) < every:
                return False
            hb.value = {**hb.value, key: now.isoformat()}
            return True

        if due("platform:purge", timedelta(minutes=10)):
            queue.enqueue(s, "enrollment.purge", dedupe_key="enrollment.purge")
        if due("platform:retention", timedelta(hours=24)):
            queue.enqueue(s, "events.retention", dedupe_key="events.retention")
        if due("platform:renew", timedelta(hours=12)):
            queue.enqueue(s, "openbao.renew", dedupe_key="openbao.renew")
        queue.recover_stuck(s)
        for t in s.scalars(select(m.Tenant).where(m.Tenant.status.in_(("active", "setup")))):
            dc = s.get(m.DirectoryConfig, t.id)
            ps = s.get(m.PolicySettings, t.id)
            max_age = timedelta(seconds=ps.max_snapshot_age_seconds if ps else 86_400)
            if dc and dc.enabled and (dc.last_sync_at is None or now - dc.last_sync_at >= timedelta(minutes=dc.sync_interval_minutes)):
                queue.enqueue(s, "directory.sync", tenant_id=t.id, dedupe_key=f"directory.sync:{t.id}")
            directory_fresh = dc is None or not dc.enabled or (dc.last_sync_status == "ok" and dc.last_sync_at and now - dc.last_sync_at < max_age)
            if directory_fresh and due(f"refresh:{t.id}", timedelta(hours=1)):
                queue.enqueue(s, "policy.recompute", tenant_id=t.id, dedupe_key=f"policy.recompute:{t.id}")
            if due(f"crl:{t.id}", timedelta(hours=24)):
                queue.enqueue(s, "crl.rotate", tenant_id=t.id, dedupe_key=f"crl.rotate:{t.id}")


def run_once() -> bool:
    """Claim and run one job. Returns True when a job ran."""
    s = new_session()
    try:
        set_platform(s)
        job = queue.claim(s)
        if job is None:
            s.commit()
            return False
        s.commit()
        job_id = job.id
    finally:
        s.close()
    error = None
    try:
        _handle(job)
    except Exception as exc:  # noqa: BLE001
        error = f"{type(exc).__name__}: {exc}"
        log.warning("Job %s (%s) failed: %s", job_id, job.kind, error)
    with platform_session() as s:
        j = s.get(m.Job, job_id)
        if j:
            queue.finish(s, j, error)
    return True


def main() -> None:
    configure_logging()

    def stop(*_):
        global _stop
        _stop = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    log.info("EasyEAP worker started")
    last_schedule = 0.0
    while not _stop:
        try:
            if time.monotonic() - last_schedule > 30:
                schedule()
                last_schedule = time.monotonic()
            if not run_once():
                time.sleep(2)
        except Exception as exc:  # noqa: BLE001 — keep the worker alive; DB may be restarting
            log.error("Worker loop error: %s", exc)
            time.sleep(5)
    log.info("EasyEAP worker stopped")


if __name__ == "__main__":
    main()
