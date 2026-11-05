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
from app.pki import service as pki
from app.pki.openbao import OpenBao
from app.policy.service import policy_settings, recompute_tenant
from app.radius import coa

router = APIRouter(prefix="/api/tenants/{tenant_id}/certificates", tags=["certificates"])
REASONS = ("unspecified", "keyCompromise", "affiliationChanged", "superseded", "cessationOfOperation")


def cert_out(c: m.Certificate, warn_days: int, identity: m.Identity | None = None, device: m.Device | None = None) -> dict:
    return {
        "id": str(c.id), "serial": c.serial, "common_name": c.common_name, "subject": c.subject, "sans": c.sans, "purpose": c.purpose,
        "not_before": c.not_before.isoformat(), "not_after": c.not_after.isoformat(), "key_algorithm": c.key_algorithm,
        "key_origin": c.key_origin, "fingerprint_sha256": c.fingerprint_sha256, "status": pki.effective_status(c, warn_days),
        "stored_status": c.status, "revoked_at": c.revoked_at.isoformat() if c.revoked_at else None,
        "revocation_reason": c.revocation_reason, "revoked_by": c.revoked_by, "template_id": str(c.template_id) if c.template_id else None,
        "identity": {"id": str(identity.id), "username": identity.username, "display_name": identity.display_name} if identity else None,
        "device": {"id": str(device.id), "name": device.name, "platform": device.platform} if device else None,
        "created_at": c.created_at.isoformat() if c.created_at else None,
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
        stmt = stmt.where(m.Certificate.purpose.in_(("user", "device")))
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
        stmt = stmt.where(m.Certificate.status != "revoked", m.Certificate.not_after > now, m.Certificate.not_after <= now + timedelta(days=warn))
    elif status_filter == "active":
        stmt = stmt.where(m.Certificate.status != "revoked", m.Certificate.not_after > now + timedelta(days=warn))
    total = s.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = s.execute(stmt.order_by(m.Certificate.not_after.asc()).offset((page - 1) * page_size).limit(page_size)).all()
    base = select(func.count()).select_from(m.Certificate).where(m.Certificate.tenant_id == ctx.id, m.Certificate.purpose.in_(("user", "device")))
    counts = {
        "revoked": s.scalar(base.where(m.Certificate.status == "revoked")) or 0,
        "expired": s.scalar(base.where(m.Certificate.status != "revoked", m.Certificate.not_after <= now)) or 0,
        "expiring": s.scalar(base.where(m.Certificate.status != "revoked", m.Certificate.not_after > now, m.Certificate.not_after <= now + timedelta(days=warn))) or 0,
        "active": s.scalar(base.where(m.Certificate.status != "revoked", m.Certificate.not_after > now + timedelta(days=warn))) or 0,
    }
    return {"total": total, "page": page, "page_size": page_size, "counts": counts, "warning_days": warn,
            "items": [cert_out(c, warn, i, d) for c, i, d in rows]}


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
    out = cert_out(c, warn, ident, dev)
    out["decision"] = {"outcome": dec.outcome, "reason_code": dec.reason_code, "vlan_id": dec.vlan_id, "deciding_rule_id": str(dec.deciding_rule_id) if dec.deciding_rule_id else None,
                       "attributes": dec.attributes, "steps": dec.steps, "computed_at": dec.computed_at.isoformat()} if dec else None
    out["issuer"] = ctx.session.get(m.CertificateAuthority, c.issuer_ca_id).common_name if c.issuer_ca_id else None
    return out


@router.get("/{cert_id}/pem", response_class=PlainTextResponse)
def get_pem(cert_id: uuid.UUID, ctx: TenantCtx = Depends(require("certificates:read"))) -> str:
    return _get(ctx, cert_id).certificate_pem


class RevokeIn(BaseModel):
    reason: str = "unspecified"
    disconnect: bool = True


@router.post("/{cert_id}/revoke")
def revoke(cert_id: uuid.UUID, body: RevokeIn, ctx: TenantCtx = Depends(require("certificates:revoke"))) -> dict:
    if body.reason not in REASONS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Choose a revocation reason.")
    c = _get(ctx, cert_id)
    if c.purpose == "radius-server":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Rotate the RADIUS server certificate from RADIUS settings instead.")
    if c.status == "revoked":
        raise HTTPException(status.HTTP_409_CONFLICT, "This certificate is already revoked.")
    pki.revoke(ctx.session, OpenBao(), c, body.reason, ctx.principal.admin.email)
    recompute_tenant(ctx.session, ctx.id)
    from app.radius.state import bump
    bump(ctx.session, ctx.id)  # pushes the new CRL to RADIUS
    result = coa.disconnect_for_certificate(ctx.session, c, f"Certificate {c.serial} revoked") if body.disconnect else {"sessions": 0, "queued": 0, "without_coa": 0}
    audit.record(ctx.session, ctx.actor, "certificate.revoked", tenant_id=ctx.id, target_type="certificate", target_id=c.id,
                 target_label=f"{c.common_name} ({c.serial})", detail={"reason": body.reason, "disconnect": result})
    rs = ctx.session.get(m.RadiusSettings, ctx.id)
    return {"ok": True, "disconnect": result, "session_timeout_seconds": rs.session_timeout_seconds if rs else None,
            "note": "New connections are refused as soon as RADIUS receives the update (normally within seconds). "
                    + ("A disconnect was sent to the controller for active sessions." if result["queued"] else
                       "Devices already connected stay online until the controller re-authenticates them (Session-Timeout) unless CoA is enabled.")}
