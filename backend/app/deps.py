"""Request dependencies: database session, admin authentication, CSRF, tenant scoping and permissions."""
from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import models as m
from app.audit import Actor
from app.config import get_settings
from app.db import new_session, set_platform, set_tenant
from app.secrets_store import session_secret
from app.security.rbac import permissions_for
from app.security.tokens import constant_eq, hmac_hex, token_hash

SESSION_COOKIE = "easyeap_session"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


def db() -> Iterator[Session]:
    s = new_session()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def client_ip(request: Request) -> str | None:
    # The proxy overwrites X-Real-IP; the API is never published directly.
    return request.headers.get("x-real-ip") or (request.client.host if request.client else None)


def csrf_for(session_token_hash: str) -> str:
    return hmac_hex(session_secret(), "csrf:" + session_token_hash)


@dataclass
class Principal:
    admin: m.Admin
    session: m.AdminSession
    ip: str | None

    @property
    def actor(self) -> Actor:
        return Actor("admin", self.admin.email, str(self.admin.id), self.ip)

    def tenant_roles(self, tenant_id: uuid.UUID) -> list[str]:
        return [g.role for g in self.admin.grants if g.tenant_id == tenant_id]

    def perms(self, tenant_id: uuid.UUID | None) -> set[str]:
        return permissions_for(self.admin.platform_role, self.tenant_roles(tenant_id) if tenant_id else [])

    def can_access(self, tenant_id: uuid.UUID) -> bool:
        return bool(self.admin.platform_role) or bool(self.tenant_roles(tenant_id))

    def accessible_tenant_ids(self) -> set[uuid.UUID] | None:
        """None means all tenants (platform role)."""
        if self.admin.platform_role:
            return None
        return {g.tenant_id for g in self.admin.grants}


def principal(request: Request, s: Session = Depends(db), x_csrf_token: str | None = Header(default=None)) -> Principal:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in to continue.")
    set_platform(s)  # admin/session tables are platform tables
    th = token_hash(token)
    sess = s.get(m.AdminSession, th)
    now = datetime.now(UTC)
    settings = get_settings()
    if sess is None or sess.expires_at <= now or sess.last_seen_at <= now - timedelta(minutes=settings.session_idle_minutes):
        if sess is not None:
            s.delete(sess)
            s.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Your session has ended. Sign in again.")
    admin = s.get(m.Admin, sess.admin_id)
    if admin is None or not admin.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in to continue.")
    if admin.mfa_enabled and not sess.mfa_passed:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Two-factor verification is required.")
    if request.method in UNSAFE and not (x_csrf_token and constant_eq(x_csrf_token, csrf_for(th))):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Security token missing or invalid. Reload the page and try again.")
    # A page that refreshes itself (the live syslog view) says so: it mustn't keep an unattended console signed in.
    if now - sess.last_seen_at > timedelta(seconds=30) and request.headers.get("x-easyeap-passive") != "1":
        sess.last_seen_at = now
    return Principal(admin=admin, session=sess, ip=client_ip(request))


def platform(perm: str):
    def dep(p: Principal = Depends(principal)) -> Principal:
        if perm not in p.perms(None):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "You don't have permission to do this.")
        return p
    return dep


@dataclass
class TenantCtx:
    tenant: m.Tenant
    principal: Principal
    session: Session
    perms: set[str]

    @property
    def id(self) -> uuid.UUID:
        return self.tenant.id

    @property
    def actor(self) -> Actor:
        return self.principal.actor


def tenant_ctx(tenant_id: uuid.UUID, p: Principal = Depends(principal), s: Session = Depends(db)) -> TenantCtx:
    tenant = s.get(m.Tenant, tenant_id)
    if tenant is None or not p.can_access(tenant_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tenant not found.")
    set_tenant(s, tenant_id)
    return TenantCtx(tenant=tenant, principal=p, session=s, perms=p.perms(tenant_id))


def require(perm: str):
    def dep(ctx: TenantCtx = Depends(tenant_ctx)) -> TenantCtx:
        if perm not in ctx.perms:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "You don't have permission to do this in this tenant.")
        return ctx
    return dep


def agent_auth(authorization: str | None = Header(default=None)) -> None:
    expected = get_settings().agent_token
    if not expected:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Agent channel not configured.")
    if not authorization or not authorization.lower().startswith("bearer ") or not constant_eq(authorization[7:].strip(), expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid agent token.")
