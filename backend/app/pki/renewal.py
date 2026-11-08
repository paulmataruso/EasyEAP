"""Certificate renewal, phase 1 (docs/plans/cert-renewal.md §3, §5, §15a).

Per tenant: whether user, machine and RADIUS server certificates renew by themselves, and at what share of each
certificate's own lifetime (`renew_from = not_before + p % × lifetime`). Templates other than Group Policy's take
their renewal period in days from that share, for the setup file and the Linux script, which bake it in.

The RADIUS server certificate rotates by itself once it's due (a worker job), keeps the previous certificate and key
for 14 days so it can be put back, and the dashboard watches for devices that stop accepting the new one.
"""
from __future__ import annotations

import math
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import exists, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app import models as m

DEFAULT_PERCENT = 80
MIN_PERCENT, MAX_PERCENT = 50, 90
ROLLBACK_DAYS = 14          # the previous server certificate can be put back this long after a rotation
WATCH_DAYS = 14             # the dashboard compares devices before and after a rotation this long
MIN_SERVER_DAYS = 30        # a rotation must give the server at least this long (else the CA must be renewed first)
OVERDUE_DAYS = 14           # an automatic renewer this long past its certificate's renew_from is overdue,
OVERDUE_LEFT_DAYS = 14      # and only once this little is left: setup files and scripts made before 0014 baked in 30 or
                            # 45 days and ask only from then (phase 2 records each device's own period)
CA_MARGIN_DAYS = 90         # §6.1 M
WATCH_REASONS = ("tls_handshake", "client_timeout")


class RenewalError(ValueError):
    pass


def settings(session: Session, tenant_id: uuid.UUID) -> m.RenewalSettings:
    """The tenant's renewal settings, made with the defaults when missing (a tenant created after 0014). Two requests
    making the row at once don't collide: the insert does nothing when the other got there first."""
    st = session.get(m.RenewalSettings, tenant_id)
    if st is None:
        session.execute(pg_insert(m.RenewalSettings).values(tenant_id=tenant_id).on_conflict_do_nothing(index_elements=["tenant_id"]))
        st = session.get(m.RenewalSettings, tenant_id)
    return st


def enabled_for(st: m.RenewalSettings, purpose: str | None) -> bool:
    return {"user": st.user_certs, "device": st.machine_certs, "computer": st.machine_certs, "radius-server": st.server_cert}.get(purpose or "", False)


def renew_from(cert: m.Certificate, percent: int) -> datetime:
    """When renewal starts for this certificate: `percent` of its own lifetime, so a shortened certificate renews in
    proportion instead of at once."""
    return cert.not_before + (cert.not_after - cert.not_before) * (percent / 100)


def derived_days(validity_days: int, percent: int) -> int:
    """A template's renewal period in days for a percentage (what the setup file and the Linux script bake in)."""
    return max(1, math.ceil(validity_days * (100 - percent) / 100))


def apply_to_templates(session: Session, tenant_id: uuid.UUID, percent: int) -> dict[str, str]:
    """Every template except Group Policy's takes its renewal period from the percentage. Returns what changed."""
    changes = {}
    for tpl in session.scalars(select(m.CertificateTemplate).where(m.CertificateTemplate.tenant_id == tenant_id,
                                                                   m.CertificateTemplate.autoenroll_kind.is_(None))):
        days = derived_days(tpl.validity_days, percent)
        if tpl.renew_before_days != days:
            changes[tpl.name] = f"{tpl.renew_before_days} → {days} days"
            tpl.renew_before_days = days
    return changes


# ── Who renews a client certificate ───────────────────────────────────────────

def renewer(cert, enrollment, tpl) -> str | None:
    """What renews this certificate without anyone, or None when it needs the user (a new link). Until phase 2 records
    it, this is read from how it was issued (§15a item 7). Takes rows or objects with the same attribute names."""
    if cert.enrollment_source == "gpo" or (tpl is not None and tpl.autoenroll_kind):
        return "gpo"
    if enrollment is not None and enrollment.method == "windows-setup":
        return "windows-setup"
    if enrollment is not None and enrollment.platform == "linux" and cert.key_origin == "device":
        return "linux"           # the setup script makes the key on the computer; the portal's by-hand route doesn't
    if cert.renewal_of is not None:
        return "renewed"         # renewed with its own key before: whatever did that will again
    return None


def overdue_at(cert, percent: int) -> datetime:
    """When an automatic renewer that hasn't renewed is overdue: two weeks into its window, and no earlier than two weeks
    before expiry (copies made before 0014 start asking only 30 or 45 days before)."""
    return max(renew_from(cert, percent) + timedelta(days=OVERDUE_DAYS), cert.not_after - timedelta(days=OVERDUE_LEFT_DAYS))


def client_renewal(session: Session, tenant_id: uuid.UUID, warning_days: int, now: datetime | None = None) -> dict:
    """Active client certificates that need someone soon (no renewer, or renewal off for their purpose, inside the
    warning period), and automatic ones that are overdue. For the dashboard: rows with id, identity_id and not_after."""
    now = now or datetime.now(UTC)
    st = settings(session, tenant_id)
    p = st.renew_at_percent
    c, e, t = m.Certificate, m.Enrollment, m.CertificateTemplate
    horizon = now + timedelta(days=max(warning_days, OVERDUE_LEFT_DAYS))
    rows = session.execute(
        select(c.id, c.identity_id, c.not_before, c.not_after, c.purpose, c.key_origin, c.renewal_of, c.enrollment_source,
               e.method, e.platform, t.autoenroll_kind)
        .outerjoin(e, e.id == c.enrollment_id).outerjoin(t, t.id == c.template_id)
        .where(c.tenant_id == tenant_id, c.status == "active", c.not_after > now, c.not_after <= horizon,
               c.purpose.in_(m.CLIENT_PURPOSES))).all()
    manual, overdue = [], []
    for r in rows:
        who = renewer(r, r if r.method is not None else None, r)
        automatic = who is not None and (who == "gpo" or enabled_for(st, r.purpose))
        if not automatic:
            if r.not_after <= now + timedelta(days=warning_days):
                manual.append(r)
        elif now >= overdue_at(r, p):
            overdue.append(r)
    return {"manual": manual, "overdue": overdue}


# ── The RADIUS server certificate ─────────────────────────────────────────────

def server_status(session: Session, tenant_id: uuid.UUID, now: datetime | None = None) -> dict | None:
    """The server certificate, when it rotates by itself, and whether the previous one can be put back."""
    now = now or datetime.now(UTC)
    rs = session.get(m.RadiusSettings, tenant_id)
    if rs is None or rs.server_certificate_id is None:
        return None
    cur = session.get(m.Certificate, rs.server_certificate_id)
    if cur is None:
        return None
    st = settings(session, tenant_id)
    prev = rollback_candidate(session, rs, now)
    return {"serial": cur.serial, "not_before": cur.not_before.isoformat(), "not_after": cur.not_after.isoformat(),
            "rotates_at": renew_from(cur, st.renew_at_percent).isoformat() if st.server_cert else None,
            # True: the issuing CA expires too soon to give a new one MIN_SERVER_DAYS, so a due rotation waits for a new CA
            "ca_too_short": ca_too_short(session, tenant_id, now),
            "rotated_at": rs.server_cert_rotated_at.isoformat() if rs.server_cert_rotated_at else None,
            "previous": {"serial": prev.serial, "not_after": prev.not_after.isoformat(),
                         "until": (rs.server_cert_rotated_at + timedelta(days=ROLLBACK_DAYS)).isoformat()} if prev else None}


def ca_too_short(session: Session, tenant_id: uuid.UUID, now: datetime) -> bool:
    from app.pki import service as pki
    try:
        ca = pki.issuing_ca(session, tenant_id)
    except pki.PkiError:
        return True
    return ca.not_after - now < timedelta(days=MIN_SERVER_DAYS + 1)


def rollback_candidate(session: Session, rs: m.RadiusSettings, now: datetime) -> m.Certificate | None:
    """The previous server certificate while it can still be put back: kept (with its key), within 14 days of the
    change, valid for another day, and for the server name RADIUS uses now."""
    if rs.previous_server_certificate_id is None or not rs.previous_server_key_ct or rs.server_cert_rotated_at is None:
        return None
    if now - rs.server_cert_rotated_at > timedelta(days=ROLLBACK_DAYS):
        return None
    prev = session.get(m.Certificate, rs.previous_server_certificate_id)
    if prev is None or prev.status == "revoked" or prev.not_after <= now + timedelta(days=1):
        return None
    if (prev.common_name or "").lower() != (rs.server_hostname or "").lower():
        return None
    return prev


def _locked_settings(session: Session, tenant_id: uuid.UUID) -> m.RadiusSettings | None:
    """The RADIUS settings row, locked and re-read: the rotation job and a rollback mustn't overwrite each other."""
    return session.get(m.RadiusSettings, tenant_id, with_for_update=True, populate_existing=True)


def rotate_server_cert_if_due(session: Session, bao, tenant: m.Tenant, now: datetime | None = None) -> m.Certificate | None:
    """The worker's job: a new server certificate once `p %` of the current one's lifetime has passed, if the issuing CA
    can give the new one at least 30 days. Also drops a previous key older than the rollback period."""
    from app.radius.state import ensure_server_certificate
    now = now or datetime.now(UTC)
    rs = _locked_settings(session, tenant.id)
    if rs is None:
        return None
    if rs.server_cert_rotated_at is not None and now - rs.server_cert_rotated_at > timedelta(days=ROLLBACK_DAYS):
        rs.previous_server_certificate_id, rs.previous_server_key_ct = None, None
    st = settings(session, tenant.id)
    if not st.server_cert or not rs.server_hostname or rs.server_certificate_id is None:
        return None
    cur = session.get(m.Certificate, rs.server_certificate_id)
    if cur is None or now < renew_from(cur, st.renew_at_percent):
        return None
    if ca_too_short(session, tenant.id, now):
        return None  # the CA items on the dashboard say why; a short certificate would rotate again and again
    return ensure_server_certificate(session, bao, tenant, rs.server_hostname, now=now)


def rollback_server_cert(session: Session, tenant_id: uuid.UUID, by: str, now: datetime | None = None) -> tuple[m.Certificate, m.Certificate]:
    """Put the previous server certificate back (devices refuse the new one). Swaps the two, so it can be undone the same
    way, and pauses automatic rotation, which would otherwise rotate again at once (part of undoing the rotation, so
    radius:write is enough; the Renewal panel shows who paused it). Returns (restored, set aside)."""
    now = now or datetime.now(UTC)
    rs = _locked_settings(session, tenant_id)
    if rs is None:
        raise RenewalError("Save the RADIUS settings first.")
    prev = rollback_candidate(session, rs, now)
    if prev is None:
        raise RenewalError(f"There's no previous server certificate to put back: it's kept for {ROLLBACK_DAYS} days after a rotation, "
                           "while it's still valid.")
    cur = session.get(m.Certificate, rs.server_certificate_id) if rs.server_certificate_id else None
    rs.server_certificate_id, rs.previous_server_certificate_id = prev.id, cur.id if cur else None
    rs.server_key_ct, rs.previous_server_key_ct = rs.previous_server_key_ct, rs.server_key_ct if cur else None
    prev.status = "active"
    if cur is not None and cur.status == "active":
        cur.status = "superseded"
    rs.config_version += 1
    st = settings(session, tenant_id)
    st.server_cert, st.updated_at, st.updated_by = False, now, by
    return prev, cur


def devices_refusing(session: Session, tenant_id: uuid.UUID, now: datetime | None = None) -> tuple[int, datetime | None]:
    """Devices that stopped accepting the server after its last rotation (§5, §15a item 5): accepted in the week before
    it, and since then two or more handshake or timeout rejects and no accept. (count, last reject)."""
    now = now or datetime.now(UTC)
    rs = session.get(m.RadiusSettings, tenant_id)
    if rs is None or rs.server_cert_rotated_at is None or now - rs.server_cert_rotated_at > timedelta(days=WATCH_DAYS):
        return 0, None
    t0 = rs.server_cert_rotated_at
    ev = m.AuthEvent
    tls = (ev.method.is_(None)) | (ev.method == "eap-tls")
    a = m.AuthEvent.__table__.alias("a")
    accepted = lambda since, until: exists().where(  # noqa: E731
        a.c.tenant_id == tenant_id, a.c.mac == ev.mac, a.c.result == "accept", (a.c.method.is_(None)) | (a.c.method == "eap-tls"),
        a.c.at >= since, *([a.c.at < until] if until is not None else []))
    rows = session.execute(
        select(ev.mac, func.max(ev.at))
        .where(ev.tenant_id == tenant_id, ev.result == "reject", tls, ev.reason_code.in_(WATCH_REASONS), ev.at >= t0, ev.mac.is_not(None),
               accepted(t0 - timedelta(days=7), t0), ~accepted(t0, None))
        .group_by(ev.mac).having(func.count() >= 2)).all()
    return len(rows), max((r[1] for r in rows), default=None)


# ── The CA schedule (read-only in phase 1, §6.1) ─────────────────────────────

def ca_schedule(session: Session, tenant_id: uuid.UUID, now: datetime | None = None) -> dict | None:
    """When the issuing CA starts shortening certificates, when the next one should be prepared (P) and take over (S),
    when it expires (E); the root's expiry and its CRL's next update."""
    now = now or datetime.now(UTC)
    cas = session.scalars(select(m.CertificateAuthority).where(m.CertificateAuthority.tenant_id == tenant_id, m.CertificateAuthority.status == "active")).all()
    issuing = next((c for c in cas if c.role == "issuing"), None)
    root = next((c for c in cas if c.role == "root"), None)
    if issuing is None:
        return None
    longest = session.scalar(select(func.max(m.CertificateTemplate.validity_days)).where(m.CertificateTemplate.tenant_id == tenant_id)) or 0
    e = issuing.not_after
    switch = e - timedelta(days=longest + CA_MARGIN_DAYS)
    prepare = min(switch - timedelta(days=180), issuing.not_before + (e - issuing.not_before) / 2)
    return {"issuing": {"common_name": issuing.common_name, "expires": e.isoformat(), "prepare_by": prepare.isoformat(), "switch_by": switch.isoformat(),
                        "shortens_from": (e - timedelta(days=longest)).isoformat(), "shortening": e - now < timedelta(days=longest)},
            "root": {"common_name": root.common_name, "expires": root.not_after.isoformat(),
                     "crl_next_update": root.crl_next_update.isoformat() if root.crl_next_update else None} if root else None,
            "longest_validity_days": longest}
