"""Background worker: scheduled maintenance plus queued jobs.

Schedule (per tenant unless noted):
* directory sync every `sync_interval_minutes`;
* decision refresh hourly while the directory is healthy (so RADIUS data stays inside its staleness limit; if the
  directory has been failing longer than the limit, the refresh stops and RADIUS fails closed);
* CRL rotation daily (OpenBao CRLs are issued with a 72h lifetime);
* the RADIUS server certificate's rotation, checked every 6 hours, and superseded client certificates (flagged when
  still used, retired once their device uses the successor), daily (app/pki/renewal.py);
* expiry of enrollment links, purge of undelivered server-generated keys (and revocation of their certificates);
* OpenBao token renewal, job pruning, event and system log retention (platform);
* MAC allow list: devices whose entry expired are disconnected (CoA) every 10 minutes; sightings kept 90 days.

A second thread forwards the audit trail, authentication events and the system log to remote syslog (app.logs.syslog).
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
SYSTEM_LOG_RETENTION_DAYS = 30


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
                rotate_crl(OpenBao(), tid, s)
                bump(s, tid)
        elif job.kind == "enrollment.purge":
            _purge_escrow(s)
        elif job.kind == "events.retention":
            s.execute(text("DELETE FROM auth_events WHERE at < now() - make_interval(days => :d)"), {"d": EVENT_RETENTION_DAYS})
            s.execute(text("DELETE FROM accounting_sessions WHERE updated_at < now() - make_interval(days => :d)"), {"d": EVENT_RETENTION_DAYS})
            s.execute(text("DELETE FROM system_logs WHERE at < now() - make_interval(days => :d)"), {"d": SYSTEM_LOG_RETENTION_DAYS})
            # Device-administration log: each tenant's own retention (180 days unless set; 30 to 730).
            s.execute(text("DELETE FROM admin_events e WHERE e.at < now() - make_interval(days => coalesce("
                           "(SELECT a.retention_days FROM admin_settings a WHERE a.tenant_id = e.tenant_id), 180))"))
            from app.radius.mab import prune_sightings
            prune_sightings(s)
            queue.prune(s)
        elif job.kind == "mac.sweep":
            # RADIUS refuses an expired entry by itself; this ends the sessions it admitted before the expiry.
            from app.radius.mab import sweep_expired
            mark = s.get(m.PlatformSetting, "mac_sweep") or m.PlatformSetting(key="mac_sweep", value={})
            now = datetime.now(UTC)
            since = datetime.fromisoformat(mark.value["at"]) if (mark.value or {}).get("at") else now - timedelta(minutes=15)
            sweep_expired(s, since, now)
            mark.value = {"at": now.isoformat()}
            s.add(mark)
        elif job.kind == "renewal.server_cert":
            _rotate_server_cert(s, tid)
        elif job.kind == "renewal.retire":
            _tend_superseded(s, tid)
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


def _rotate_server_cert(s, tid: uuid.UUID) -> None:
    """The RADIUS server certificate rotates by itself once due (docs/plans/cert-renewal.md §5); the previous one is kept
    14 days so it can be put back."""
    from app.pki.openbao import OpenBao
    from app.pki.renewal import rotate_server_cert_if_due
    tenant = s.get(m.Tenant, tid)
    if tenant is None:
        return
    cert = rotate_server_cert_if_due(s, OpenBao(), tenant)
    if cert is None:
        return
    rs = s.get(m.RadiusSettings, tid)
    prev = s.get(m.Certificate, rs.previous_server_certificate_id) if rs and rs.previous_server_certificate_id else None
    audit.record(s, audit.Actor.system("Certificate renewal"), "radius.server_certificate_rotated", tenant_id=tid, target_type="certificate",
                 target_id=cert.id, target_label=cert.common_name,
                 detail={"serial": cert.serial, "automatic": True, "previous_serial": prev.serial if prev else None,
                         "not_after": cert.not_after.isoformat()})


def _tend_superseded(s, tid: uuid.UUID) -> None:
    """Superseded certificates: flag one still used after its successor, retire (revoke) one its device no longer uses
    (docs/plans/cert-renewal.md §15b items 5, 6)."""
    from app.pki.openbao import OpenBao
    from app.pki.renewal import tend_superseded
    from app.policy.service import recompute_tenant
    from app.radius.state import bump
    res = tend_superseded(s, OpenBao(), tid)
    if res["retired"]:  # before the audit rows: auditing holds a lock that every tenant's audit writes wait on
        recompute_tenant(s, tid)
        bump(s, tid)  # pushes the new CRL to RADIUS
    if res["failed"]:
        log.warning("Retirement: %d superseded certificates couldn't be revoked in tenant %s; retried tomorrow", res["failed"], tid)
    actor = audit.Actor.system("Certificate renewal")
    for cert, succ_serial, last in res["used"]:
        audit.record(s, actor, "certificate.superseded_used", tenant_id=tid, target_type="certificate", target_id=cert.id,
                     target_label=f"{cert.common_name} ({cert.serial})", detail={"successor_serial": succ_serial, "last_used": last.isoformat()})
    for cert, succ_serial in res["retired"]:
        audit.record(s, actor, "certificate.superseded_retired", tenant_id=tid, target_type="certificate", target_id=cert.id,
                     target_label=f"{cert.common_name} ({cert.serial})", detail={"successor_serial": succ_serial})


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
            e.status, e.token_hash, e.token_ct = "expired", None, None
        s.delete(esc)
    for e in s.scalars(select(m.Enrollment).where(m.Enrollment.status == "pending", m.Enrollment.expires_at <= now)):
        e.status, e.token_hash, e.token_ct = "expired", None, None
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
        if due("platform:mac-sweep", timedelta(minutes=10)):
            queue.enqueue(s, "mac.sweep", dedupe_key="mac.sweep")
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
            issuing = s.scalars(select(m.CertificateAuthority).where(m.CertificateAuthority.tenant_id == t.id, m.CertificateAuthority.role == "issuing")).first()
            # Installs from before the CRL's expiry was recorded catch up within an hour instead of a day.
            unrecorded = issuing is not None and issuing.crl_next_update is None
            if due(f"crl:{t.id}", timedelta(hours=24)) or (unrecorded and due(f"crl-record:{t.id}", timedelta(hours=1))):
                queue.enqueue(s, "crl.rotate", tenant_id=t.id, dedupe_key=f"crl.rotate:{t.id}")
            if issuing is not None and due(f"server-cert:{t.id}", timedelta(hours=6)):
                queue.enqueue(s, "renewal.server_cert", tenant_id=t.id, dedupe_key=f"renewal.server_cert:{t.id}")
            if issuing is not None and due(f"retire:{t.id}", timedelta(hours=24)):
                queue.enqueue(s, "renewal.retire", tenant_id=t.id, dedupe_key=f"renewal.retire:{t.id}")


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
    from app.logs.dbhandler import install as install_db_logging
    from app.logs.syslog import Forwarder
    install_db_logging("worker")
    log.info("EasyEAP worker started")
    forwarder = Forwarder()
    forwarder.start()
    last_schedule = 0.0
    from app.backup.engine import maintenance
    while not _stop:
        if maintenance():  # a restore is replacing the database and PKI; resume when it is done
            time.sleep(3)
            continue
        try:
            if time.monotonic() - last_schedule > 30:
                schedule()
                last_schedule = time.monotonic()
            if not run_once():
                time.sleep(2)
        except Exception as exc:  # noqa: BLE001 — keep the worker alive; DB may be restarting
            log.error("Worker loop error: %s", exc)
            time.sleep(5)
    forwarder.stop_event.set()
    log.info("EasyEAP worker stopped")


if __name__ == "__main__":
    main()
