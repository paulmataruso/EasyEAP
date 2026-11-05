"""Administrator sign-in, sessions, TOTP and password changes."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app import audit
from app import models as m
from app.config import get_settings
from app.db import set_platform
from app.deps import SESSION_COOKIE, Principal, client_ip, csrf_for, db, principal
from app.pki import crypto
from app.security.passwords import hash_password, needs_rehash, password_problems, verify_password
from app.security.ratelimit import limiter
from app.security.rbac import ROLE_LABELS
from app.security.tokens import new_token, token_hash

router = APIRouter(prefix="/api/auth", tags=["auth"])
LOCK_AFTER = 8
LOCK_MINUTES = 15


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    totp: str | None = Field(default=None, max_length=10)


def me_payload(s: Session, admin: m.Admin, sess: m.AdminSession) -> dict:
    tenants = {t.id: t for t in s.scalars(select(m.Tenant))}
    grants = [{"tenant_id": str(g.tenant_id), "tenant_name": tenants[g.tenant_id].name if g.tenant_id in tenants else "", "role": g.role,
               "role_label": ROLE_LABELS.get(g.role, g.role)} for g in admin.grants]
    return {
        "id": str(admin.id), "email": admin.email, "display_name": admin.display_name, "platform_role": admin.platform_role,
        "platform_role_label": ROLE_LABELS.get(admin.platform_role or "", None), "mfa_enabled": admin.mfa_enabled,
        "grants": grants, "csrf_token": csrf_for(sess.token_hash), "session_expires_at": sess.expires_at.isoformat(),
    }


def start_session(s: Session, response: Response, request: Request, admin: m.Admin, mfa_passed: bool) -> m.AdminSession:
    token = new_token(32)
    settings = get_settings()
    sess = m.AdminSession(token_hash=token_hash(token), admin_id=admin.id, expires_at=datetime.now(UTC) + timedelta(minutes=settings.session_ttl_minutes),
                          mfa_passed=mfa_passed, ip=client_ip(request), user_agent=(request.headers.get("user-agent") or "")[:300])
    s.add(sess)
    s.flush()
    response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=settings.cookie_secure, samesite="strict", path="/",
                        max_age=settings.session_ttl_minutes * 60)
    return sess


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, s: Session = Depends(db)) -> dict:
    set_platform(s)
    ip = client_ip(request) or "?"
    email = body.email.lower()
    if not limiter.hit(f"login:{ip}", get_settings().login_rate_limit_per_minute) or not limiter.hit(f"login:{email}", 20, 600):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many sign-in attempts. Wait a minute and try again.")
    admin = s.scalars(select(m.Admin).where(m.Admin.email == email)).first()
    now = datetime.now(UTC)
    if admin and admin.locked_until and admin.locked_until > now:
        raise HTTPException(status.HTTP_423_LOCKED, "This account is temporarily locked after repeated failed sign-ins. Try again later.")
    ok = verify_password(admin.password_hash if admin else None, body.password)
    if not ok or admin is None or not admin.is_active:
        if admin:
            admin.failed_logins += 1
            if admin.failed_logins >= LOCK_AFTER:
                admin.locked_until, admin.failed_logins = now + timedelta(minutes=LOCK_MINUTES), 0
            audit.record(s, audit.Actor("admin", email, str(admin.id), ip), "auth.login_failed", target_type="admin", target_id=admin.id, target_label=email)
        s.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Email or password is incorrect.")
    if admin.mfa_enabled:
        if not body.totp:
            return {"mfa_required": True}
        secret = crypto.decrypt_str(None, admin.mfa_secret_ct or "")
        if not pyotp.TOTP(secret).verify(body.totp.replace(" ", ""), valid_window=1):
            admin.failed_logins += 1
            s.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "The verification code is incorrect.")
    if needs_rehash(admin.password_hash):
        admin.password_hash = hash_password(body.password)
    admin.failed_logins, admin.locked_until, admin.last_login_at = 0, None, now
    sess = start_session(s, response, request, admin, mfa_passed=True)
    audit.record(s, audit.Actor("admin", admin.email, str(admin.id), ip), "auth.login", target_type="admin", target_id=admin.id, target_label=admin.email)
    return me_payload(s, admin, sess)


@router.post("/logout")
def logout(response: Response, p: Principal = Depends(principal), s: Session = Depends(db)) -> dict:
    s.delete(p.session)
    response.delete_cookie(SESSION_COOKIE, path="/")
    audit.record(s, p.actor, "auth.logout", target_type="admin", target_id=p.admin.id, target_label=p.admin.email)
    return {"ok": True}


@router.get("/me")
def me(p: Principal = Depends(principal), s: Session = Depends(db)) -> dict:
    return me_payload(s, p.admin, p.session)


class ProfileIn(BaseModel):
    display_name: str = Field(min_length=1, max_length=120)


@router.patch("/me")
def update_profile(body: ProfileIn, p: Principal = Depends(principal), s: Session = Depends(db)) -> dict:
    name = body.display_name.strip()
    if not name:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Enter your name.")
    p.admin.display_name = name
    audit.record(s, p.actor, "auth.profile_updated", target_type="admin", target_id=p.admin.id, target_label=p.admin.email)
    return me_payload(s, p.admin, p.session)


class PasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=256)


@router.post("/password")
def change_password(body: PasswordIn, p: Principal = Depends(principal), s: Session = Depends(db)) -> dict:
    if not verify_password(p.admin.password_hash, body.current_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Your current password is incorrect.")
    problems = password_problems(body.new_password, p.admin.email)
    if problems:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, " ".join(problems))
    p.admin.password_hash = hash_password(body.new_password)
    s.execute(delete(m.AdminSession).where(m.AdminSession.admin_id == p.admin.id, m.AdminSession.token_hash != p.session.token_hash))
    audit.record(s, p.actor, "auth.password_changed", target_type="admin", target_id=p.admin.id, target_label=p.admin.email)
    return {"ok": True}


@router.post("/mfa/setup")
def mfa_setup(p: Principal = Depends(principal), s: Session = Depends(db)) -> dict:
    if p.admin.mfa_enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Two-factor authentication is already on.")
    secret = pyotp.random_base32()
    p.admin.mfa_secret_ct = crypto.encrypt(None, secret)
    uri = pyotp.TOTP(secret).provisioning_uri(name=p.admin.email, issuer_name="EasyEAP")
    return {"secret": secret, "otpauth_uri": uri}


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=10)


@router.post("/mfa/enable")
def mfa_enable(body: CodeIn, p: Principal = Depends(principal), s: Session = Depends(db)) -> dict:
    if not p.admin.mfa_secret_ct:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Start two-factor setup first.")
    secret = crypto.decrypt_str(None, p.admin.mfa_secret_ct)
    if not pyotp.TOTP(secret).verify(body.code.replace(" ", ""), valid_window=1):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That code didn't match. Check your authenticator app's clock and try again.")
    p.admin.mfa_enabled = True
    p.session.mfa_passed = True
    audit.record(s, p.actor, "auth.mfa_enabled", target_type="admin", target_id=p.admin.id, target_label=p.admin.email)
    return {"ok": True}


@router.post("/mfa/disable")
def mfa_disable(body: CodeIn, p: Principal = Depends(principal), s: Session = Depends(db)) -> dict:
    if not p.admin.mfa_enabled:
        return {"ok": True}
    secret = crypto.decrypt_str(None, p.admin.mfa_secret_ct or "")
    if not pyotp.TOTP(secret).verify(body.code.replace(" ", ""), valid_window=1):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That code didn't match.")
    p.admin.mfa_enabled, p.admin.mfa_secret_ct = False, None
    audit.record(s, p.actor, "auth.mfa_disabled", target_type="admin", target_id=p.admin.id, target_label=p.admin.email)
    return {"ok": True}
