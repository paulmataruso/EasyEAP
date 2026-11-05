"""Directory (Active Directory) connection, test, sync, groups and live search."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app import audit
from app import models as m
from app.deps import TenantCtx, require
from app.directory import ldap
from app.directory.sync import params, sync_tenant
from app.jobs.queue import enqueue
from app.pki import crypto

router = APIRouter(prefix="/api/tenants/{tenant_id}/directory", tags=["directory"])


def config_out(c: m.DirectoryConfig | None) -> dict | None:
    if c is None:
        return None
    return {"enabled": c.enabled, "hosts": c.hosts, "port": c.port, "transport": c.transport, "verify_certificate": c.verify_certificate,
            "has_ca_bundle": bool(c.ca_bundle_pem), "domain": c.domain, "base_dn": c.base_dn, "user_search_base": c.user_search_base,
            "group_search_base": c.group_search_base, "user_filter": c.user_filter, "group_filter": c.group_filter, "bind_dn": c.bind_dn,
            "password_set": bool(c.bind_password_ct), "sync_interval_minutes": c.sync_interval_minutes,
            "last_sync_at": c.last_sync_at.isoformat() if c.last_sync_at else None, "last_sync_status": c.last_sync_status,
            "last_sync_error": c.last_sync_error, "last_sync_stats": c.last_sync_stats}


@router.get("")
def get_config(ctx: TenantCtx = Depends(require("directory:read"))) -> dict:
    s = ctx.session
    groups = s.scalar(select(func.count()).select_from(m.DirectoryGroup).where(m.DirectoryGroup.tenant_id == ctx.id, m.DirectoryGroup.deleted.is_(False))) or 0
    return {"config": config_out(s.get(m.DirectoryConfig, ctx.id)), "group_count": groups}


class DirectoryIn(BaseModel):
    hosts: list[str] = Field(min_length=1, max_length=6)
    port: int = Field(default=636, ge=1, le=65535)
    transport: str = Field(default="ldaps", pattern="^(ldaps|starttls|plain)$")
    verify_certificate: bool = True
    ca_bundle_pem: str | None = Field(default=None, max_length=100_000)
    clear_ca_bundle: bool = False
    domain: str = Field(min_length=2, max_length=253)
    base_dn: str = Field(min_length=3, max_length=500)
    user_search_base: str = ""
    group_search_base: str = ""
    user_filter: str = "(&(objectCategory=person)(objectClass=user))"
    group_filter: str = "(objectClass=group)"
    bind_dn: str = Field(min_length=3, max_length=500)
    bind_password: str | None = Field(default=None, max_length=512)  # write-only; omit to keep the stored one
    sync_interval_minutes: int = Field(default=15, ge=5, le=1440)
    enabled: bool = True


def _apply(ctx: TenantCtx, body: DirectoryIn, existing: m.DirectoryConfig | None) -> tuple[ldap.DirectoryParams, str | None]:
    if body.ca_bundle_pem and "BEGIN CERTIFICATE" not in body.ca_bundle_pem:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The CA bundle must be PEM (-----BEGIN CERTIFICATE-----).")
    password = body.bind_password
    if not password:
        if existing is None or not existing.bind_password_ct:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Enter the service account password.")
        password = crypto.decrypt_str(ctx.id, existing.bind_password_ct)
    ca = None if body.clear_ca_bundle else (body.ca_bundle_pem or (existing.ca_bundle_pem if existing else None))
    p = ldap.DirectoryParams(hosts=[h.strip() for h in body.hosts if h.strip()], port=body.port, transport=body.transport,
                             verify_certificate=body.verify_certificate, ca_bundle_pem=ca, base_dn=body.base_dn,
                             user_search_base=body.user_search_base, group_search_base=body.group_search_base, user_filter=body.user_filter,
                             group_filter=body.group_filter, bind_dn=body.bind_dn, bind_password=password)
    return p, ca


@router.post("/test")
def test(body: DirectoryIn, ctx: TenantCtx = Depends(require("directory:write"))) -> dict:
    p, _ = _apply(ctx, body, ctx.session.get(m.DirectoryConfig, ctx.id))
    return ldap.test(p)


@router.put("")
def save(body: DirectoryIn, ctx: TenantCtx = Depends(require("directory:write"))) -> dict:
    s = ctx.session
    existing = s.get(m.DirectoryConfig, ctx.id)
    p, ca = _apply(ctx, body, existing)
    if body.transport == "plain":
        from app.config import get_settings
        if not get_settings().lab_mode:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Plain LDAP is disabled. Use LDAPS or StartTLS.")
    c = existing or m.DirectoryConfig(tenant_id=ctx.id)
    c.enabled, c.hosts, c.port, c.transport, c.verify_certificate, c.ca_bundle_pem = body.enabled, p.hosts, body.port, body.transport, body.verify_certificate, ca
    c.domain, c.base_dn, c.user_search_base, c.group_search_base = body.domain.lower(), body.base_dn, body.user_search_base, body.group_search_base
    c.user_filter, c.group_filter, c.bind_dn, c.sync_interval_minutes = body.user_filter, body.group_filter, body.bind_dn, body.sync_interval_minutes
    if body.bind_password:
        c.bind_password_ct = crypto.encrypt(ctx.id, body.bind_password)
    if existing is None:
        s.add(c)
    s.flush()
    if not ctx.tenant.domain:
        ctx.tenant.domain = body.domain.lower()
    audit.record(s, ctx.actor, "directory.saved", tenant_id=ctx.id, target_type="directory", target_label=body.domain,
                 detail={"hosts": p.hosts, "transport": body.transport, "verify_certificate": body.verify_certificate, "bind_dn": body.bind_dn,
                         "password_changed": bool(body.bind_password)})
    enqueue(s, "directory.sync", tenant_id=ctx.id, dedupe_key=f"directory.sync:{ctx.id}")
    return {"config": config_out(c)}


class SyncIn(BaseModel):
    force: bool = False


@router.post("/sync")
def sync_now(body: SyncIn, ctx: TenantCtx = Depends(require("directory:sync"))) -> dict:
    if ctx.session.get(m.DirectoryConfig, ctx.id) is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Connect a directory first.")
    result = sync_tenant(ctx.session, ctx.id, force=body.force)
    audit.record(ctx.session, ctx.actor, "directory.synced", tenant_id=ctx.id, target_type="directory", detail={"forced": body.force, **result})
    return result


@router.get("/groups")
def groups(ctx: TenantCtx = Depends(require("directory:read")), q: str = "") -> dict:
    stmt = select(m.DirectoryGroup, func.count(m.IdentityGroup.identity_id)).outerjoin(m.IdentityGroup, m.IdentityGroup.group_id == m.DirectoryGroup.id)\
        .where(m.DirectoryGroup.tenant_id == ctx.id, m.DirectoryGroup.deleted.is_(False)).group_by(m.DirectoryGroup.id).order_by(m.DirectoryGroup.name)
    if q:
        stmt = stmt.where(m.DirectoryGroup.name.ilike(f"%{q}%"))
    return {"groups": [{"id": str(g.id), "name": g.name, "dn": g.dn, "source": g.source, "members": n} for g, n in ctx.session.execute(stmt.limit(500))]}


class LocalGroupIn(BaseModel):
    name: str = Field(min_length=1, max_length=256)


@router.post("/groups", status_code=201)
def create_local_group(body: LocalGroupIn, ctx: TenantCtx = Depends(require("identities:write"))) -> dict:
    import uuid as _uuid
    g = m.DirectoryGroup(tenant_id=ctx.id, object_guid=f"local-{_uuid.uuid4()}", dn=f"local:{body.name}", name=body.name, source="local")
    ctx.session.add(g)
    ctx.session.flush()
    audit.record(ctx.session, ctx.actor, "group.created", tenant_id=ctx.id, target_type="group", target_id=g.id, target_label=g.name)
    return {"id": str(g.id), "name": g.name, "dn": g.dn, "source": g.source, "members": 0}


@router.get("/search")
def live_search(q: str, ctx: TenantCtx = Depends(require("identities:read"))) -> dict:
    cfg = ctx.session.get(m.DirectoryConfig, ctx.id)
    if cfg is None or len(q.strip()) < 2:
        return {"results": []}
    try:
        conn = ldap.connect(params(cfg))
        try:
            users = ldap.search_live(conn, params(cfg), q)
        finally:
            conn.unbind()
    except ldap.DirectoryError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"{exc} {exc.hint}".strip()) from exc
    known = {i.object_guid: i for i in ctx.session.scalars(select(m.Identity).where(m.Identity.tenant_id == ctx.id, m.Identity.object_guid.in_([u.object_guid for u in users])))}
    return {"results": [{"object_guid": u.object_guid, "username": u.username, "display_name": u.display_name, "email": u.email, "upn": u.upn,
                         "account_state": u.account_state, "identity_id": str(known[u.object_guid].id) if u.object_guid in known else None} for u in users]}
