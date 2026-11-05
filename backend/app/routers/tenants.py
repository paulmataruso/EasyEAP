"""Tenants (customer organisations) and the MSP overview."""
from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app import models as m
from app.db import set_platform
from app.deps import Principal, TenantCtx, db, platform, principal, require
from app.pki import crypto
from app.pki import service as pki
from app.pki.openbao import OpenBao

router = APIRouter(prefix="/api", tags=["tenants"])
SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$")


def health_for(s: Session, t: m.Tenant) -> dict:
    """Cross-tenant summary; caller must be platform-scoped or scoped to this tenant."""
    now = datetime.now(UTC)
    day = now - timedelta(hours=24)
    accepts = s.scalar(select(func.count()).select_from(m.AuthEvent).where(m.AuthEvent.tenant_id == t.id, m.AuthEvent.at >= day, m.AuthEvent.result == "accept")) or 0
    rejects = s.scalar(select(func.count()).select_from(m.AuthEvent).where(m.AuthEvent.tenant_id == t.id, m.AuthEvent.at >= day, m.AuthEvent.result == "reject")) or 0
    ps = s.get(m.PolicySettings, t.id)
    warn = ps.expiry_warning_days if ps else 30
    active = s.scalar(select(func.count()).select_from(m.Certificate).where(m.Certificate.tenant_id == t.id, m.Certificate.status == "active",
                                                                            m.Certificate.not_after > now, m.Certificate.purpose.in_(("user", "device")))) or 0
    expiring = s.scalar(select(func.count()).select_from(m.Certificate).where(m.Certificate.tenant_id == t.id, m.Certificate.status == "active",
                                                                              m.Certificate.not_after > now, m.Certificate.not_after <= now + timedelta(days=warn),
                                                                              m.Certificate.purpose.in_(("user", "device")))) or 0
    users = s.scalar(select(func.count()).select_from(m.Identity).where(m.Identity.tenant_id == t.id, m.Identity.account_state != "deleted")) or 0
    dc = s.get(m.DirectoryConfig, t.id)
    rs = s.get(m.RadiusSettings, t.id)
    has_ca = s.scalar(select(func.count()).select_from(m.CertificateAuthority).where(m.CertificateAuthority.tenant_id == t.id, m.CertificateAuthority.role == "issuing")) or 0
    clients = s.scalar(select(func.count()).select_from(m.RadiusClient).where(m.RadiusClient.tenant_id == t.id)) or 0
    issues = []
    if not has_ca:
        issues.append({"severity": "warning", "code": "pki_missing", "message": "PKI not initialized"})
    if dc is None:
        issues.append({"severity": "info", "code": "directory_missing", "message": "No directory connected"})
    elif dc.last_sync_status == "failed":
        issues.append({"severity": "critical", "code": "directory_failed", "message": "Directory sync failing"})
    if rs is None or rs.server_certificate_id is None:
        issues.append({"severity": "warning", "code": "radius_cert_missing", "message": "RADIUS server certificate not issued"})
    if clients == 0:
        issues.append({"severity": "info", "code": "no_controllers", "message": "No wireless controllers added"})
    if expiring:
        issues.append({"severity": "warning", "code": "certs_expiring", "message": f"{expiring} certificate{'s' if expiring != 1 else ''} expiring soon"})
    total = accepts + rejects
    return {
        "auth_24h": {"accept": accepts, "reject": rejects, "success_rate": (accepts / total) if total else None},
        "certificates": {"active": active, "expiring": expiring}, "users": users, "controllers": clients,
        "directory": {"configured": dc is not None, "last_sync_at": dc.last_sync_at.isoformat() if dc and dc.last_sync_at else None,
                      "status": dc.last_sync_status if dc else None},
        "snapshot_built_at": rs.snapshot_built_at.isoformat() if rs and rs.snapshot_built_at else None,
        "pki_ready": bool(has_ca), "issues": issues,
    }


def tenant_out(t: m.Tenant) -> dict:
    return {"id": str(t.id), "slug": t.slug, "name": t.name, "domain": t.domain, "status": t.status, "created_at": t.created_at.isoformat() if t.created_at else None}


@router.get("/tenants")
def list_tenants(p: Principal = Depends(principal), s: Session = Depends(db)) -> dict:
    set_platform(s)
    allowed = p.accessible_tenant_ids()
    q = select(m.Tenant).order_by(m.Tenant.name)
    if allowed is not None:
        q = q.where(m.Tenant.id.in_(allowed or {uuid.UUID(int=0)}))
    return {"tenants": [{**tenant_out(t), "health": health_for(s, t), "roles": p.tenant_roles(t.id)} for t in s.scalars(q)]}


class TenantIn(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    slug: str = Field(min_length=2, max_length=48)
    domain: str = Field(default="", max_length=253)


@router.post("/tenants", status_code=201)
def create_tenant(body: TenantIn, p: Principal = Depends(platform("tenants:create")), s: Session = Depends(db)) -> dict:
    set_platform(s)
    slug = body.slug.lower().strip()
    if not SLUG.match(slug):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Use lowercase letters, numbers and hyphens for the short name.")
    if s.scalars(select(m.Tenant).where(m.Tenant.slug == slug)).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Another tenant already uses this short name.")
    t = m.Tenant(name=body.name.strip(), slug=slug, domain=body.domain.strip().lower(), status="setup")
    s.add(t)
    s.flush()
    crypto.ensure_tenant_key(OpenBao(), t.id)
    s.add(m.PolicySettings(tenant_id=t.id, default_action="deny", max_snapshot_age_seconds=86_400, allow_server_keygen=False, expiry_warning_days=30))
    audit.record(s, p.actor, "tenant.created", tenant_id=t.id, target_type="tenant", target_id=t.id, target_label=t.name)
    return tenant_out(t)


@router.get("/tenants/{tenant_id}")
def get_tenant(ctx: TenantCtx = Depends(require("tenant:read"))) -> dict:
    return {**tenant_out(ctx.tenant), "health": health_for(ctx.session, ctx.tenant), "permissions": sorted(ctx.perms)}


class TenantPatch(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=160)
    domain: str | None = Field(default=None, max_length=253)
    status: str | None = Field(default=None, pattern="^(active|suspended)$")


@router.patch("/tenants/{tenant_id}")
def update_tenant(body: TenantPatch, ctx: TenantCtx = Depends(require("tenant:write"))) -> dict:
    t = ctx.tenant
    changes = body.model_dump(exclude_none=True)
    if changes.get("status") == "active" and not ctx.session.scalars(select(m.CertificateAuthority).where(m.CertificateAuthority.tenant_id == t.id)).first():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Initialize the tenant's PKI before activating it.")
    for k, v in changes.items():
        setattr(t, k, v.strip() if isinstance(v, str) else v)
    from app.radius.state import bump
    bump(ctx.session, t.id)
    audit.record(ctx.session, ctx.actor, "tenant.updated", tenant_id=t.id, target_type="tenant", target_id=t.id, target_label=t.name, detail=changes)
    return tenant_out(t)


class DeleteIn(BaseModel):
    confirm_slug: str


@router.delete("/tenants/{tenant_id}")
def delete_tenant(tenant_id: uuid.UUID, body: DeleteIn, p: Principal = Depends(platform("tenants:delete")), s: Session = Depends(db)) -> dict:
    set_platform(s)
    t = s.get(m.Tenant, tenant_id)
    if t is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tenant not found.")
    if body.confirm_slug != t.slug:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Type the tenant's short name to confirm.")
    bao = OpenBao()
    pki.destroy_tenant_pki(bao, t.id)
    try:
        crypto.destroy_tenant_key(bao, t.id)  # crypto-shred all tenant secrets
    except Exception:  # noqa: BLE001
        pass
    name = t.name
    s.delete(t)
    audit.record(s, p.actor, "tenant.deleted", tenant_id=None, target_type="tenant", target_id=tenant_id, target_label=name,
                 detail={"crypto_shredded": True})
    return {"ok": True}
