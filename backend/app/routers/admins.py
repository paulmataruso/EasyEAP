"""Administrator accounts and role grants (Super Administrator only)."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app import audit
from app import models as m
from app.db import set_platform
from app.deps import Principal, db, platform
from app.security.passwords import hash_password, password_problems
from app.security.rbac import PLATFORM_ROLES, ROLE_LABELS, TENANT_ROLES

router = APIRouter(prefix="/api/admins", tags=["admins"])


def admin_out(a: m.Admin) -> dict:
    return {"id": str(a.id), "email": a.email, "display_name": a.display_name, "platform_role": a.platform_role, "is_active": a.is_active,
            "mfa_enabled": a.mfa_enabled, "last_login_at": a.last_login_at.isoformat() if a.last_login_at else None,
            "grants": [{"tenant_id": str(g.tenant_id), "role": g.role} for g in a.grants]}


@router.get("")
def list_admins(p: Principal = Depends(platform("admins:manage")), s: Session = Depends(db)) -> dict:
    set_platform(s)
    return {"admins": [admin_out(a) for a in s.scalars(select(m.Admin).order_by(m.Admin.email))],
            "roles": {"platform": [{"id": r, "label": ROLE_LABELS[r]} for r in PLATFORM_ROLES],
                      "tenant": [{"id": r, "label": ROLE_LABELS[r]} for r in TENANT_ROLES]}}


class Grant(BaseModel):
    tenant_id: uuid.UUID
    role: str


class AdminIn(BaseModel):
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=12, max_length=256)
    platform_role: str | None = None
    grants: list[Grant] = []


def _validate_roles(platform_role: str | None, grants: list[Grant]) -> None:
    if platform_role and platform_role not in PLATFORM_ROLES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown platform role.")
    for g in grants:
        if g.role not in TENANT_ROLES:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown tenant role {g.role}.")


@router.post("", status_code=201)
def create_admin(body: AdminIn, p: Principal = Depends(platform("admins:manage")), s: Session = Depends(db)) -> dict:
    set_platform(s)
    _validate_roles(body.platform_role, body.grants)
    if s.scalars(select(m.Admin).where(m.Admin.email == body.email.lower())).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "An administrator with this email already exists.")
    problems = password_problems(body.password, body.email)
    if problems:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, " ".join(problems))
    a = m.Admin(email=body.email.lower(), display_name=body.display_name, password_hash=hash_password(body.password), platform_role=body.platform_role)
    a.grants = [m.RoleGrant(tenant_id=g.tenant_id, role=g.role) for g in body.grants]
    s.add(a)
    s.flush()
    audit.record(s, p.actor, "admin.created", target_type="admin", target_id=a.id, target_label=a.email,
                 detail={"platform_role": body.platform_role, "grants": [g.model_dump(mode="json") for g in body.grants]})
    return admin_out(a)


class AdminPatch(BaseModel):
    display_name: str | None = None
    platform_role: str | None = None
    clear_platform_role: bool = False
    is_active: bool | None = None
    grants: list[Grant] | None = None


@router.patch("/{admin_id}")
def update_admin(admin_id: uuid.UUID, body: AdminPatch, p: Principal = Depends(platform("admins:manage")), s: Session = Depends(db)) -> dict:
    set_platform(s)
    a = s.get(m.Admin, admin_id)
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Administrator not found.")
    _validate_roles(body.platform_role, body.grants or [])
    if a.id == p.admin.id and (body.is_active is False or body.clear_platform_role or (body.platform_role and body.platform_role != "platform_owner")):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You can't remove your own Super Administrator access.")
    if body.display_name:
        a.display_name = body.display_name
    if body.clear_platform_role:
        a.platform_role = None
    elif body.platform_role:
        a.platform_role = body.platform_role
    if body.is_active is not None:
        a.is_active = body.is_active
        if not body.is_active:
            s.execute(delete(m.AdminSession).where(m.AdminSession.admin_id == a.id))
    if body.grants is not None:
        a.grants = [m.RoleGrant(tenant_id=g.tenant_id, role=g.role) for g in body.grants]
    audit.record(s, p.actor, "admin.updated", target_type="admin", target_id=a.id, target_label=a.email, detail=body.model_dump(mode="json", exclude_none=True))
    return admin_out(a)


@router.delete("/{admin_id}")
def delete_admin(admin_id: uuid.UUID, p: Principal = Depends(platform("admins:manage")), s: Session = Depends(db)) -> dict:
    set_platform(s)
    a = s.get(m.Admin, admin_id)
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Administrator not found.")
    if a.id == p.admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You can't delete your own account.")
    email = a.email
    s.delete(a)
    audit.record(s, p.actor, "admin.deleted", target_type="admin", target_id=admin_id, target_label=email)
    return {"ok": True}
