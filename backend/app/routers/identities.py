"""Users (directory and local identities), their devices, certificates and access decisions."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, or_, select

from app import audit
from app import models as m
from app.deps import TenantCtx, require
from app.policy.engine import CertInput, evaluate
from app.policy.service import _default_vlan, evaluate_identity, load_rules, policy_settings, recompute_tenant
from app.radius import coa
from app.routers.certificates import cert_out

router = APIRouter(prefix="/api/tenants/{tenant_id}/identities", tags=["identities"])


def identity_out(i: m.Identity, certs: int | None = None, active_certs: int | None = None) -> dict:
    return {"id": str(i.id), "source": i.source, "username": i.username, "upn": i.upn, "email": i.email, "display_name": i.display_name,
            "department": i.department, "title": i.title, "account_state": i.account_state, "enrolled": i.enrolled,
            "last_auth_at": i.last_auth_at.isoformat() if i.last_auth_at else None,
            "last_synced_at": i.last_synced_at.isoformat() if i.last_synced_at else None,
            "groups": [{"id": str(g.id), "name": g.name} for g in i.groups if not g.deleted],
            **({"certificates": certs, "active_certificates": active_certs} if certs is not None else {})}


@router.get("")
def list_identities(ctx: TenantCtx = Depends(require("identities:read")), q: str = "", state: str = "", group_id: uuid.UUID | None = None,
                    enrolled: bool | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)) -> dict:
    s = ctx.session
    now = datetime.now(UTC)
    stmt = select(m.Identity).where(m.Identity.tenant_id == ctx.id)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(m.Identity.username.ilike(like), m.Identity.display_name.ilike(like), m.Identity.email.ilike(like), m.Identity.upn.ilike(like)))
    if state:
        stmt = stmt.where(m.Identity.account_state == state)
    else:
        stmt = stmt.where(m.Identity.account_state != "deleted")
    if enrolled is not None:
        stmt = stmt.where(m.Identity.enrolled.is_(enrolled))
    if group_id:
        stmt = stmt.where(m.Identity.id.in_(select(m.IdentityGroup.identity_id).where(m.IdentityGroup.group_id == group_id)))
    total = s.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = s.scalars(stmt.order_by(m.Identity.display_name).offset((page - 1) * page_size).limit(page_size)).all()
    ids = [i.id for i in rows]
    counts = dict(s.execute(select(m.Certificate.identity_id, func.count()).where(m.Certificate.identity_id.in_(ids)).group_by(m.Certificate.identity_id)).all()) if ids else {}
    active = dict(s.execute(select(m.Certificate.identity_id, func.count()).where(m.Certificate.identity_id.in_(ids), m.Certificate.status == "active",
                                                                                 m.Certificate.not_after > now).group_by(m.Certificate.identity_id)).all()) if ids else {}
    access = _access(ctx, rows, now)
    from app.posture import enforcement
    from app.routers.radius import agent_out
    enf = enforcement(s, ctx.tenant, agent_out(s), now)
    return {"total": total, "page": page, "page_size": page_size, "enforceable": enf["enforceable"], "enforcement_missing": enf["missing"],
            "items": [{**identity_out(i, counts.get(i.id, 0), active.get(i.id, 0)), "access": access[i.id]} for i in rows]}


def _access(ctx: TenantCtx, rows: list[m.Identity], now: datetime) -> dict[uuid.UUID, dict]:
    """Per user: can they connect now (allowed by policy *and* holding a valid certificate), or why not.

    "allowed_no_certificate" means the policy would allow them but they have no valid certificate yet.
    """
    s = ctx.session
    ids = [i.id for i in rows]
    if not ids:
        return {}
    decisions: dict[uuid.UUID, list] = {}
    for d in s.execute(select(m.Decision.identity_id, m.Decision.outcome, m.Decision.vlan_id, m.Decision.reason_code)
                       .join(m.Certificate, m.Certificate.id == m.Decision.certificate_id)
                       .where(m.Decision.identity_id.in_(ids), m.Certificate.status == "active", m.Certificate.not_after > now)):
        decisions.setdefault(d.identity_id, []).append(d)
    ps = policy_settings(s, ctx.id)
    rules, dv = load_rules(s, ctx.id), _default_vlan(s, ps)
    out = {}
    for i in rows:
        held = decisions.get(i.id)
        if held:
            allow = sorted((d for d in held if d.outcome == "allow"), key=lambda d: d.vlan_id or 0)
            out[i.id] = ({"status": "can_connect", "vlan_id": allow[0].vlan_id, "reason_code": None} if allow else
                         {"status": "denied", "vlan_id": None, "reason_code": held[0].reason_code})
            continue
        o = evaluate(i.account_state, {str(g.id) for g in i.groups if not g.deleted}, rules, ps.default_action, dv, now,
                     CertInput(serial="(preview)", status="active", not_after=now + timedelta(days=1), purpose="user"))
        out[i.id] = ({"status": "allowed_no_certificate", "vlan_id": o.vlan_id, "reason_code": None} if o.outcome == "allow" else
                     {"status": "denied", "vlan_id": None, "reason_code": o.reason_code})
    return out


def _get(ctx: TenantCtx, identity_id: uuid.UUID) -> m.Identity:
    i = ctx.session.get(m.Identity, identity_id)
    if i is None or i.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    return i


def _outcome_json(o) -> dict:
    return {"outcome": o.outcome, "reason_code": o.reason_code, "deciding_rule_id": o.deciding_rule_id, "vlan_id": o.vlan_id,
            "attributes": o.attributes, "steps": o.steps}


@router.get("/{identity_id}")
def get_identity(identity_id: uuid.UUID, ctx: TenantCtx = Depends(require("identities:read"))) -> dict:
    s = ctx.session
    i = _get(ctx, identity_id)
    warn = policy_settings(s, ctx.id).expiry_warning_days
    devices = s.scalars(select(m.Device).where(m.Device.identity_id == i.id).order_by(m.Device.created_at)).all()
    dev_by_id = {d.id: d for d in devices}
    certs = s.scalars(select(m.Certificate).where(m.Certificate.identity_id == i.id).order_by(m.Certificate.not_after.desc())).all()
    enrollments = s.scalars(select(m.Enrollment).where(m.Enrollment.identity_id == i.id).order_by(m.Enrollment.created_at.desc()).limit(20)).all()
    events = s.scalars(select(m.AuthEvent).where(m.AuthEvent.identity_id == i.id).order_by(m.AuthEvent.at.desc()).limit(20)).all()
    from app.routers.events import event_out
    return {
        **identity_out(i),
        "object_guid": i.object_guid,
        "devices": [{"id": str(d.id), "name": d.name, "platform": d.platform, "last_seen_mac": d.last_seen_mac, "created_at": d.created_at.isoformat() if d.created_at else None} for d in devices],
        "certificates": [cert_out(c, warn, None, dev_by_id.get(c.device_id)) for c in certs],
        "enrollments": [{"id": str(e.id), "device_name": e.device_name, "platform": e.platform, "method": e.method, "status": e.status,
                         "created_by": e.created_by, "created_at": e.created_at.isoformat() if e.created_at else None,
                         "expires_at": e.expires_at.isoformat(), "completed_at": e.completed_at.isoformat() if e.completed_at else None} for e in enrollments],
        "access": {"user": _outcome_json(evaluate_identity(s, i, purpose="user")), "device": _outcome_json(evaluate_identity(s, i, purpose="device"))},
        "events": [event_out(e) for e in events],
    }


class LocalIdentityIn(BaseModel):
    username: str = Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9._@-]+$")
    display_name: str = Field(min_length=1, max_length=256)
    email: EmailStr | None = None
    group_ids: list[uuid.UUID] = []


@router.post("", status_code=201)
def create_local(body: LocalIdentityIn, ctx: TenantCtx = Depends(require("identities:write"))) -> dict:
    s = ctx.session
    if s.scalars(select(m.Identity).where(m.Identity.tenant_id == ctx.id, func.lower(m.Identity.username) == body.username.lower())).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "A user with this username already exists.")
    groups = [g for g in s.scalars(select(m.DirectoryGroup).where(m.DirectoryGroup.tenant_id == ctx.id, m.DirectoryGroup.id.in_(body.group_ids)))]
    i = m.Identity(tenant_id=ctx.id, source="local", username=body.username, display_name=body.display_name, email=body.email,
                   upn=f"{body.username}@{ctx.tenant.domain}" if ctx.tenant.domain and "@" not in body.username else body.username, account_state="enabled")
    i.groups = groups
    s.add(i)
    s.flush()
    audit.record(s, ctx.actor, "identity.created", tenant_id=ctx.id, target_type="identity", target_id=i.id, target_label=i.username)
    return identity_out(i)


class IdentityPatch(BaseModel):
    account_state: str | None = Field(default=None, pattern="^(enabled|disabled)$")
    group_ids: list[uuid.UUID] | None = None
    display_name: str | None = None


@router.patch("/{identity_id}")
def update_identity(identity_id: uuid.UUID, body: IdentityPatch, ctx: TenantCtx = Depends(require("identities:write"))) -> dict:
    s = ctx.session
    i = _get(ctx, identity_id)
    if i.source != "local":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Directory users are managed in Active Directory; changes arrive with the next sync.")
    if body.account_state:
        i.account_state = body.account_state
    if body.display_name:
        i.display_name = body.display_name
    if body.group_ids is not None:
        i.groups = list(s.scalars(select(m.DirectoryGroup).where(m.DirectoryGroup.tenant_id == ctx.id, m.DirectoryGroup.id.in_(body.group_ids))))
    recompute_tenant(s, ctx.id)
    if body.account_state == "disabled":
        coa.disconnect_for_identity(s, ctx.id, i.id, "Account disabled")
    audit.record(s, ctx.actor, "identity.updated", tenant_id=ctx.id, target_type="identity", target_id=i.id, target_label=i.username, detail=body.model_dump(mode="json", exclude_none=True))
    return identity_out(i)


@router.post("/{identity_id}/disconnect")
def disconnect(identity_id: uuid.UUID, ctx: TenantCtx = Depends(require("identities:write"))) -> dict:
    i = _get(ctx, identity_id)
    result = coa.disconnect_for_identity(ctx.session, ctx.id, i.id, "Disconnected by administrator")
    audit.record(ctx.session, ctx.actor, "identity.disconnected", tenant_id=ctx.id, target_type="identity", target_id=i.id, target_label=i.username, detail=result)
    return result
