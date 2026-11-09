"""Issued certificates: list, detail, revoke."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import func, or_, select

from app import audit
from app import models as m
from app.deps import TenantCtx, require
from app.enrollment import service as enr
from app.pki import renewal
from app.pki import service as pki
from app.pki.openbao import OpenBao
from app.policy.service import policy_settings, recompute_tenant
from app.radius import coa

router = APIRouter(prefix="/api/tenants/{tenant_id}/certificates", tags=["certificates"])
REASONS = ("unspecified", "keyCompromise", "affiliationChanged", "superseded", "cessationOfOperation")


def cert_out(c: m.Certificate, warn_days: int, identity: m.Identity | None = None, device: m.Device | None = None,
             renewer: str | None = None) -> dict:
    return {
        "id": str(c.id), "serial": c.serial, "common_name": c.common_name, "subject": c.subject, "sans": c.sans, "purpose": c.purpose,
        "not_before": c.not_before.isoformat(), "not_after": c.not_after.isoformat(), "key_algorithm": c.key_algorithm,
        "key_origin": c.key_origin, "fingerprint_sha256": c.fingerprint_sha256, "status": pki.effective_status(c, warn_days),
        "stored_status": c.status, "revoked_at": c.revoked_at.isoformat() if c.revoked_at else None,
        "revocation_reason": c.revocation_reason, "revoked_by": c.revoked_by, "template_id": str(c.template_id) if c.template_id else None,
        "identity": {"id": str(identity.id), "username": identity.username, "display_name": identity.display_name} if identity else None,
        "device": {"id": str(device.id), "name": device.name, "platform": device.platform} if device else None,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        # Where Windows keeps the key (tpm | software | None: not reported), and the renewal chain.
        "key_storage": c.key_storage, "renewal_of": str(c.renewal_of) if c.renewal_of else None,
        "renewed_at": c.renewed_at.isoformat() if c.renewed_at else None,
        # What renews it (windows-setup | windows-helper | linux | gpo | renewed | None: a new link), as recorded or
        # read from how it was issued, the renewer's last signed check-in (v2), and when it was retired.
        "renewer": renewer, "renewer_version": c.renewer_version,
        "renewal_checked_at": c.renewal_checked_at.isoformat() if c.renewal_checked_at else None,
        "retired_at": c.retired_at.isoformat() if c.retired_at else None,
    }


@router.get("")
def list_certs(ctx: TenantCtx = Depends(require("certificates:read")), q: str = "", status_filter: str = Query(default="", alias="status"),
               purpose: str = "", identity_id: uuid.UUID | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)) -> dict:
    s = ctx.session
    warn = policy_settings(s, ctx.id).expiry_warning_days
    now = datetime.now(UTC)
    stmt = select(m.Certificate, m.Identity, m.Device).outerjoin(m.Identity, m.Identity.id == m.Certificate.identity_id)\
        .outerjoin(m.Device, m.Device.id == m.Certificate.device_id).where(m.Certificate.tenant_id == ctx.id)
    if purpose:
        stmt = stmt.where(m.Certificate.purpose == purpose)
    else:
        stmt = stmt.where(m.Certificate.purpose.in_(m.CLIENT_PURPOSES))
    if identity_id:
        stmt = stmt.where(m.Certificate.identity_id == identity_id)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(m.Certificate.serial.ilike(like.replace(":", "")), m.Certificate.common_name.ilike(like),
                              m.Identity.username.ilike(like), m.Identity.display_name.ilike(like), m.Device.name.ilike(like)))
    if status_filter == "revoked":
        stmt = stmt.where(m.Certificate.status == "revoked")
    elif status_filter == "expired":
        stmt = stmt.where(m.Certificate.status != "revoked", m.Certificate.not_after <= now)
    elif status_filter == "expiring":
        stmt = stmt.where(m.Certificate.status == "active", m.Certificate.not_after > now, m.Certificate.not_after <= now + timedelta(days=warn))
    elif status_filter == "active":
        stmt = stmt.where(m.Certificate.status == "active", m.Certificate.not_after > now + timedelta(days=warn))
    elif status_filter == "superseded":
        stmt = stmt.where(m.Certificate.status == "superseded", m.Certificate.not_after > now)
    elif status_filter == "renewal":  # the dashboard's: automatic renewals that are overdue or whose renewer went silent
        cr = renewal.client_renewal(s, ctx.id, warn, now)
        stmt = stmt.where(m.Certificate.id.in_([r.id for r in cr["overdue"] + cr["silent"]]))
    total = s.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = s.execute(stmt.order_by(m.Certificate.not_after.asc()).offset((page - 1) * page_size).limit(page_size)).all()
    base = select(func.count()).select_from(m.Certificate).where(m.Certificate.tenant_id == ctx.id, m.Certificate.purpose.in_(m.CLIENT_PURPOSES))
    counts = {
        "revoked": s.scalar(base.where(m.Certificate.status == "revoked")) or 0,
        "expired": s.scalar(base.where(m.Certificate.status != "revoked", m.Certificate.not_after <= now)) or 0,
        "expiring": s.scalar(base.where(m.Certificate.status == "active", m.Certificate.not_after > now, m.Certificate.not_after <= now + timedelta(days=warn))) or 0,
        "active": s.scalar(base.where(m.Certificate.status == "active", m.Certificate.not_after > now + timedelta(days=warn))) or 0,
        # Same definitions as effective_status(), so the counts add up to the total and match each certificate's chip.
        "superseded": s.scalar(base.where(m.Certificate.status == "superseded", m.Certificate.not_after > now)) or 0,
    }
    return {"total": total, "page": page, "page_size": page_size, "counts": counts, "warning_days": warn,
            "items": [cert_out(c, warn, i, d, _renewer(c)) for c, i, d in rows]}


def _renewer(c: m.Certificate) -> str | None:
    """Recorded since 0015 for everything that renews by itself (renewal.renewer() reads the rest from how it was issued)."""
    if c.renewer or c.purpose not in m.CLIENT_PURPOSES:
        return c.renewer
    return "renewed" if c.renewal_of else None


def _get(ctx: TenantCtx, cert_id: uuid.UUID) -> m.Certificate:
    c = ctx.session.get(m.Certificate, cert_id)
    if c is None or c.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Certificate not found.")
    return c


@router.get("/{cert_id}")
def get_cert(cert_id: uuid.UUID, ctx: TenantCtx = Depends(require("certificates:read"))) -> dict:
    c = _get(ctx, cert_id)
    warn = policy_settings(ctx.session, ctx.id).expiry_warning_days
    ident = ctx.session.get(m.Identity, c.identity_id) if c.identity_id else None
    dev = ctx.session.get(m.Device, c.device_id) if c.device_id else None
    dec = ctx.session.get(m.Decision, c.id)
    out = cert_out(c, warn, ident, dev, _renewer(c))
    st = renewal.settings(ctx.session, ctx.id)
    out["renewal"] = {"renew_from": renewal.renew_from(c, st.renew_at_percent).isoformat(),
                      "enabled": renewal.enabled_for(st, c.purpose) or out["renewer"] == "gpo",
                      "state": renewal.classify(c, st, datetime.now(UTC), who=out["renewer"]) if c.status == "active" else None} \
        if c.purpose in m.CLIENT_PURPOSES else None
    nxt = ctx.session.scalars(select(m.Certificate).where(m.Certificate.tenant_id == ctx.id, m.Certificate.renewal_of == c.id)
                              .order_by(m.Certificate.created_at.desc())).all()
    out["successors"] = [{"id": str(n.id), "serial": n.serial, "status": pki.effective_status(n, warn), "not_after": n.not_after.isoformat(),
                          "revoked_by": n.revoked_by, "replaced": n.revoked_by == enr.REPLACED_BY,
                          "renewal": renewal.is_key_renewal(n, c)} for n in nxt]
    # What revoking it would revoke too (its renewals' whole chain, unrevoked): the revoke dialog lists them.
    out["revoke_also"] = [{"id": str(n.id), "serial": n.serial} for n in renewal.successors(ctx.session, c)] if c.status != "revoked" else []
    out["decision"] = {"outcome": dec.outcome, "reason_code": dec.reason_code, "vlan_id": dec.vlan_id, "wired_vlan_id": dec.wired_vlan_id, "deciding_rule_id": str(dec.deciding_rule_id) if dec.deciding_rule_id else None,
                       "attributes": dec.attributes, "steps": dec.steps, "computed_at": dec.computed_at.isoformat()} if dec else None
    out["issuer"] = ctx.session.get(m.CertificateAuthority, c.issuer_ca_id).common_name if c.issuer_ca_id else None
    # The holder's current groups, so the decision ledger can say which membership matched.
    out["holder_groups"] = [{"id": str(g.id), "name": g.name} for g in ident.groups if not g.deleted] if ident else []
    return out


@router.get("/{cert_id}/pem", response_class=PlainTextResponse)
def get_pem(cert_id: uuid.UUID, ctx: TenantCtx = Depends(require("certificates:read"))) -> str:
    return _get(ctx, cert_id).certificate_pem


class RevokeIn(BaseModel):
    reason: str = "unspecified"
    disconnect: bool = True
    successors: bool = True  # also revoke the certificates renewed from it (§15b item 4)


@router.post("/{cert_id}/revoke")
def revoke(cert_id: uuid.UUID, body: RevokeIn, ctx: TenantCtx = Depends(require("certificates:revoke"))) -> dict:
    if body.reason not in REASONS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Choose a revocation reason.")
    c = _get(ctx, cert_id)
    if c.purpose == "radius-server":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Rotate the RADIUS server certificate from RADIUS settings instead.")
    if c.status == "revoked":
        raise HTTPException(status.HTTP_409_CONFLICT, "This certificate is already revoked.")
    later = renewal.successors(ctx.session, c) if body.successors else []
    bao = OpenBao()
    pki.revoke(ctx.session, bao, c, body.reason, ctx.principal.admin.email)
    for n in later:
        pki.revoke(ctx.session, bao, n, body.reason, f"{ctx.principal.admin.email} (renewed from {c.serial})")
    recompute_tenant(ctx.session, ctx.id)
    from app.radius.state import bump
    bump(ctx.session, ctx.id)  # pushes the new CRL to RADIUS
    result = coa.disconnect_for_certificate(ctx.session, c, f"Certificate {c.serial} revoked", also=later) if body.disconnect \
        else {"sessions": 0, "queued": 0, "without_coa": 0}
    audit.record(ctx.session, ctx.actor, "certificate.revoked", tenant_id=ctx.id, target_type="certificate", target_id=c.id,
                 target_label=f"{c.common_name} ({c.serial})",
                 detail={"reason": body.reason, "disconnect": result, "successors": [n.serial for n in later]})
    rs = ctx.session.get(m.RadiusSettings, ctx.id)
    return {"ok": True, "disconnect": result, "successors": [n.serial for n in later], "session_timeout_seconds": rs.session_timeout_seconds if rs else None,
            "note": "New connections are refused as soon as RADIUS receives the update (normally within seconds). "
                    + ("A disconnect was sent to the controller for active sessions." if result["queued"] else
                       "Devices already connected stay online until the controller re-authenticates them (Session-Timeout) unless CoA is enabled.")}
