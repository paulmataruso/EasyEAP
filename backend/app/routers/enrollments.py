"""Administrator side of enrollment: create links, server-generated packages (opt-in), list, cancel."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select

from app import audit
from app import models as m
from app.config import get_settings
from app.deps import TenantCtx, require
from app.enrollment import service as enr
from app.pki.openbao import OpenBao

router = APIRouter(prefix="/api/tenants/{tenant_id}/enrollments", tags=["enrollment"])


def enrollment_out(e: m.Enrollment, identity: m.Identity | None = None) -> dict:
    return {"id": str(e.id), "identity_id": str(e.identity_id), "identity": {"display_name": identity.display_name, "username": identity.username} if identity else None,
            "device_name": e.device_name, "platform": e.platform, "method": e.method, "status": e.status, "created_by": e.created_by,
            "created_at": e.created_at.isoformat() if e.created_at else None, "expires_at": e.expires_at.isoformat(),
            "completed_at": e.completed_at.isoformat() if e.completed_at else None, "certificate_id": str(e.certificate_id) if e.certificate_id else None}


def link_for(token: str) -> str:
    return f"{get_settings().public_url.rstrip('/')}/enroll.html#/t/{token}"


class EnrollIn(BaseModel):
    identity_id: uuid.UUID
    template_id: uuid.UUID | None = None
    device_name: str = Field(min_length=1, max_length=120)
    platform: str = Field(pattern="^(windows|macos|ios|android|linux)$")
    method: str = Field(default="link", pattern="^(link|server)$")
    legacy_p12: bool = False
    ttl_hours: int = Field(default=72, ge=1, le=24 * 14)
    renewal_of: uuid.UUID | None = None


def _template(ctx: TenantCtx, template_id: uuid.UUID | None, purpose: str = "user") -> m.CertificateTemplate:
    s = ctx.session
    if template_id:
        t = s.get(m.CertificateTemplate, template_id)
        if t is None or t.tenant_id != ctx.id or t.purpose == "radius-server":
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Choose a certificate template.")
        return t
    t = s.scalars(select(m.CertificateTemplate).where(m.CertificateTemplate.tenant_id == ctx.id, m.CertificateTemplate.purpose == purpose)).first()
    if t is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Initialize the tenant's PKI first.")
    return t


@router.post("", status_code=201)
def create(body: EnrollIn, ctx: TenantCtx = Depends(require("enrollment:manage"))) -> dict:
    s = ctx.session
    ident = s.get(m.Identity, body.identity_id)
    if ident is None or ident.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    tpl = _template(ctx, body.template_id)
    if body.method == "server":
        if "enrollment:server_keygen" not in ctx.perms:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Only a Tenant Administrator can create server-generated packages.")
        e, token, password = enr.issue_server_side(s, OpenBao(), ctx.tenant, ident, tpl, body.device_name, body.platform, ctx.principal.admin.email,
                                                   legacy_p12=body.legacy_p12, ttl_hours=body.ttl_hours)
        audit.record(s, ctx.actor, "enrollment.server_package_created", tenant_id=ctx.id, target_type="identity", target_id=ident.id,
                     target_label=ident.username, detail={"device": body.device_name, "platform": body.platform, "legacy_p12": body.legacy_p12, "enrollment_id": str(e.id)})
        return {"enrollment": enrollment_out(e, ident), "download_url": link_for(token), "pkcs12_password": password,
                "note": "Share the link and the password through different channels. The package can be downloaded once."}
    e, token = enr.create_link(s, ctx.tenant, ident, tpl, body.device_name, body.platform, ctx.principal.admin.email, body.ttl_hours, body.renewal_of)
    audit.record(s, ctx.actor, "enrollment.link_created", tenant_id=ctx.id, target_type="identity", target_id=ident.id, target_label=ident.username,
                 detail={"device": body.device_name, "platform": body.platform, "enrollment_id": str(e.id), "expires_at": e.expires_at.isoformat()})
    return {"enrollment": enrollment_out(e, ident), "link": link_for(token)}


@router.get("")
def list_enrollments(ctx: TenantCtx = Depends(require("certificates:read")), status_filter: str = "") -> dict:
    stmt = select(m.Enrollment, m.Identity).join(m.Identity, m.Identity.id == m.Enrollment.identity_id).where(m.Enrollment.tenant_id == ctx.id)
    if status_filter:
        stmt = stmt.where(m.Enrollment.status == status_filter)
    rows = ctx.session.execute(stmt.order_by(m.Enrollment.created_at.desc()).limit(200)).all()
    return {"items": [enrollment_out(e, i) for e, i in rows]}


@router.post("/{enrollment_id}/cancel")
def cancel(enrollment_id: uuid.UUID, ctx: TenantCtx = Depends(require("enrollment:manage"))) -> dict:
    s = ctx.session
    e = s.get(m.Enrollment, enrollment_id)
    if e is None or e.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Enrollment not found.")
    if e.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, "Only pending enrollments can be cancelled.")
    e.status, e.token_hash = "cancelled", None
    esc = s.scalars(select(m.KeyEscrow).where(m.KeyEscrow.enrollment_id == e.id)).first()
    if esc:
        s.delete(esc)
    if e.method == "server" and e.certificate_id:
        cert = s.get(m.Certificate, e.certificate_id)
        if cert and cert.status == "active":
            from app.pki import service as pki
            from app.policy.service import recompute_tenant
            pki.revoke(s, OpenBao(), cert, "cessationOfOperation", ctx.principal.admin.email)  # undelivered key: revoke
            recompute_tenant(s, ctx.id)
    audit.record(s, ctx.actor, "enrollment.cancelled", tenant_id=ctx.id, target_type="enrollment", target_id=e.id, target_label=e.device_name)
    return {"ok": True}


@router.post("/{enrollment_id}/download")
def admin_download(enrollment_id: uuid.UUID, ctx: TenantCtx = Depends(require("enrollment:server_keygen"))) -> Response:
    """The administrator can take the one-time PKCS#12 directly (for hand-delivery). This consumes the download."""
    s = ctx.session
    e = s.get(m.Enrollment, enrollment_id)
    if e is None or e.tenant_id != ctx.id or e.method != "server":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Package not found.")
    try:
        data = enr.take_escrow(s, OpenBao(), e)
    except enr.EnrollmentError as exc:
        raise HTTPException(status.HTTP_410_GONE, str(exc)) from exc
    audit.record(s, ctx.actor, "enrollment.package_downloaded", tenant_id=ctx.id, target_type="enrollment", target_id=e.id, target_label=e.device_name, detail={"by": "admin"})
    return Response(data, media_type="application/x-pkcs12", headers={"Content-Disposition": f'attachment; filename="{e.device_name}.p12"', "Cache-Control": "no-store"})
