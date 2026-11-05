"""VLANs, access rules, tenant defaults and the decision simulator."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app import audit
from app import models as m
from app.deps import TenantCtx, require
from app.policy.engine import ALLOWED_EXTRA_ATTRIBUTES
from app.policy.service import evaluate_identity, policy_settings, recompute_tenant
from app.radius.state import bump

router = APIRouter(prefix="/api/tenants/{tenant_id}/policy", tags=["policy"])


def vlan_out(v: m.Vlan) -> dict:
    return {"id": str(v.id), "vlan_id": v.vlan_id, "name": v.name, "description": v.description, "color": v.color}


def rule_out(r: m.AccessRule) -> dict:
    return {"id": str(r.id), "name": r.name, "description": r.description, "priority": r.priority, "enabled": r.enabled, "action": r.action,
            "vlan_ref": str(r.vlan_ref) if r.vlan_ref else None, "purposes": r.purposes, "extra_attributes": r.extra_attributes,
            "groups": [{"id": str(g.id), "name": g.name, "deleted": g.deleted} for g in r.groups]}


def settings_out(ps: m.PolicySettings) -> dict:
    return {"default_action": ps.default_action, "default_vlan_ref": str(ps.default_vlan_ref) if ps.default_vlan_ref else None,
            "max_snapshot_age_seconds": ps.max_snapshot_age_seconds, "allow_server_keygen": ps.allow_server_keygen,
            "expiry_warning_days": ps.expiry_warning_days}


@router.get("")
def get_policy(ctx: TenantCtx = Depends(require("policy:read"))) -> dict:
    s = ctx.session
    vlans = s.scalars(select(m.Vlan).where(m.Vlan.tenant_id == ctx.id).order_by(m.Vlan.vlan_id)).all()
    rules = s.scalars(select(m.AccessRule).where(m.AccessRule.tenant_id == ctx.id).order_by(m.AccessRule.priority, m.AccessRule.id)).all()
    usage = dict(s.execute(select(m.Decision.vlan_id, func.count()).where(m.Decision.tenant_id == ctx.id, m.Decision.outcome == "allow").group_by(m.Decision.vlan_id)).all())
    return {"vlans": [{**vlan_out(v), "certificates": usage.get(v.vlan_id, 0)} for v in vlans], "rules": [rule_out(r) for r in rules],
            "settings": settings_out(policy_settings(s, ctx.id)), "allowed_extra_attributes": sorted(ALLOWED_EXTRA_ATTRIBUTES)}


def _changed(ctx: TenantCtx) -> None:
    recompute_tenant(ctx.session, ctx.id)
    bump(ctx.session, ctx.id)


class VlanIn(BaseModel):
    vlan_id: int = Field(ge=1, le=4094)
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=300)
    color: str = Field(default="blue", max_length=16)


@router.post("/vlans", status_code=201)
def create_vlan(body: VlanIn, ctx: TenantCtx = Depends(require("policy:write"))) -> dict:
    if ctx.session.scalars(select(m.Vlan).where(m.Vlan.tenant_id == ctx.id, m.Vlan.vlan_id == body.vlan_id)).first():
        raise HTTPException(status.HTTP_409_CONFLICT, f"VLAN {body.vlan_id} already exists.")
    v = m.Vlan(tenant_id=ctx.id, **body.model_dump())
    ctx.session.add(v)
    ctx.session.flush()
    audit.record(ctx.session, ctx.actor, "vlan.created", tenant_id=ctx.id, target_type="vlan", target_id=v.id, target_label=f"{v.vlan_id} {v.name}")
    return vlan_out(v)


@router.put("/vlans/{vlan_ref}")
def update_vlan(vlan_ref: uuid.UUID, body: VlanIn, ctx: TenantCtx = Depends(require("policy:write"))) -> dict:
    v = ctx.session.get(m.Vlan, vlan_ref)
    if v is None or v.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "VLAN not found.")
    for k, val in body.model_dump().items():
        setattr(v, k, val)
    _changed(ctx)
    audit.record(ctx.session, ctx.actor, "vlan.updated", tenant_id=ctx.id, target_type="vlan", target_id=v.id, target_label=f"{v.vlan_id} {v.name}")
    return vlan_out(v)


@router.delete("/vlans/{vlan_ref}")
def delete_vlan(vlan_ref: uuid.UUID, ctx: TenantCtx = Depends(require("policy:write"))) -> dict:
    v = ctx.session.get(m.Vlan, vlan_ref)
    if v is None or v.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "VLAN not found.")
    used = ctx.session.scalars(select(m.AccessRule).where(m.AccessRule.vlan_ref == v.id)).first()
    if used:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Rule “{used.name}” assigns this VLAN. Change the rule first.")
    ps = policy_settings(ctx.session, ctx.id)
    if ps.default_vlan_ref == v.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "This is the default VLAN. Choose another default first.")
    ctx.session.delete(v)
    audit.record(ctx.session, ctx.actor, "vlan.deleted", tenant_id=ctx.id, target_type="vlan", target_id=vlan_ref, target_label=f"{v.vlan_id} {v.name}")
    return {"ok": True}


class Attr(BaseModel):
    name: str
    value: str = Field(max_length=253)


class RuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    enabled: bool = True
    action: str = Field(pattern="^(allow|deny)$")
    vlan_ref: uuid.UUID | None = None
    group_ids: list[uuid.UUID] = Field(min_length=1)
    purposes: list[str] = []
    extra_attributes: list[Attr] = []
    priority: int | None = None


def _validate_rule(ctx: TenantCtx, body: RuleIn) -> list[m.DirectoryGroup]:
    if body.action == "allow" and body.vlan_ref is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Allow rules need a VLAN.")
    if body.vlan_ref:
        v = ctx.session.get(m.Vlan, body.vlan_ref)
        if v is None or v.tenant_id != ctx.id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Choose a VLAN from this tenant.")
    for p in body.purposes:
        if p not in ("user", "device"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Purposes are user and/or device.")
    for a in body.extra_attributes:
        if a.name not in ALLOWED_EXTRA_ATTRIBUTES:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{a.name} can't be set here. Allowed: {', '.join(sorted(ALLOWED_EXTRA_ATTRIBUTES))}.")
        if any(c in a.value for c in "\"'\\\n\r%{}"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"The value for {a.name} contains characters that aren't allowed.")
    groups = list(ctx.session.scalars(select(m.DirectoryGroup).where(m.DirectoryGroup.tenant_id == ctx.id, m.DirectoryGroup.id.in_(body.group_ids))))
    if len(groups) != len(set(body.group_ids)):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "One or more groups were not found.")
    return groups


@router.post("/rules", status_code=201)
def create_rule(body: RuleIn, ctx: TenantCtx = Depends(require("policy:write"))) -> dict:
    groups = _validate_rule(ctx, body)
    top = ctx.session.scalar(select(func.max(m.AccessRule.priority)).where(m.AccessRule.tenant_id == ctx.id)) or 0
    r = m.AccessRule(tenant_id=ctx.id, name=body.name, description=body.description, priority=top + 10, enabled=body.enabled, action=body.action,
                     vlan_ref=body.vlan_ref if body.action == "allow" else None, purposes=body.purposes,
                     extra_attributes=[a.model_dump() for a in body.extra_attributes] if body.action == "allow" else [])
    r.groups = groups
    ctx.session.add(r)
    ctx.session.flush()
    _changed(ctx)
    audit.record(ctx.session, ctx.actor, "rule.created", tenant_id=ctx.id, target_type="rule", target_id=r.id, target_label=r.name, detail=body.model_dump(mode="json"))
    return rule_out(r)


@router.put("/rules/{rule_id}")
def update_rule(rule_id: uuid.UUID, body: RuleIn, ctx: TenantCtx = Depends(require("policy:write"))) -> dict:
    r = ctx.session.get(m.AccessRule, rule_id)
    if r is None or r.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found.")
    groups = _validate_rule(ctx, body)
    r.name, r.description, r.enabled, r.action, r.purposes = body.name, body.description, body.enabled, body.action, body.purposes
    r.vlan_ref = body.vlan_ref if body.action == "allow" else None
    r.extra_attributes = [a.model_dump() for a in body.extra_attributes] if body.action == "allow" else []
    r.groups = groups
    ctx.session.flush()
    _changed(ctx)
    audit.record(ctx.session, ctx.actor, "rule.updated", tenant_id=ctx.id, target_type="rule", target_id=r.id, target_label=r.name, detail=body.model_dump(mode="json"))
    return rule_out(r)


@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: uuid.UUID, ctx: TenantCtx = Depends(require("policy:write"))) -> dict:
    r = ctx.session.get(m.AccessRule, rule_id)
    if r is None or r.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found.")
    name = r.name
    ctx.session.delete(r)
    ctx.session.flush()
    _changed(ctx)
    audit.record(ctx.session, ctx.actor, "rule.deleted", tenant_id=ctx.id, target_type="rule", target_id=rule_id, target_label=name)
    return {"ok": True}


class OrderIn(BaseModel):
    rule_ids: list[uuid.UUID]


@router.post("/rules/reorder")
def reorder(body: OrderIn, ctx: TenantCtx = Depends(require("policy:write"))) -> dict:
    rules = {r.id: r for r in ctx.session.scalars(select(m.AccessRule).where(m.AccessRule.tenant_id == ctx.id))}
    if set(body.rule_ids) != set(rules):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Send every rule exactly once.")
    for i, rid in enumerate(body.rule_ids):
        rules[rid].priority = (i + 1) * 10
    ctx.session.flush()
    _changed(ctx)
    audit.record(ctx.session, ctx.actor, "rule.reordered", tenant_id=ctx.id, target_type="policy", detail={"order": [rules[r].name for r in body.rule_ids]})
    return {"rules": [rule_out(rules[r]) for r in body.rule_ids]}


class SettingsIn(BaseModel):
    default_action: str = Field(pattern="^(allow|deny)$")
    default_vlan_ref: uuid.UUID | None = None
    max_snapshot_age_seconds: int = Field(ge=3600, le=7 * 86_400)
    allow_server_keygen: bool = False
    expiry_warning_days: int = Field(ge=1, le=180)


@router.put("/settings")
def update_settings(body: SettingsIn, ctx: TenantCtx = Depends(require("policy:write"))) -> dict:
    if body.allow_server_keygen and "enrollment:server_keygen" not in ctx.perms:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only a Tenant Administrator can turn on server-generated keys.")
    if body.default_action == "allow" and not body.default_vlan_ref:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Choose the VLAN that the default Allow assigns.")
    ps = policy_settings(ctx.session, ctx.id)
    before = settings_out(ps)
    for k, v in body.model_dump().items():
        setattr(ps, k, v)
    _changed(ctx)
    audit.record(ctx.session, ctx.actor, "policy.settings_updated", tenant_id=ctx.id, target_type="policy", detail={"before": before, "after": body.model_dump(mode="json")})
    return settings_out(ps)


class SimulateIn(BaseModel):
    identity_id: uuid.UUID
    purpose: str = Field(default="user", pattern="^(user|device)$")


@router.post("/simulate")
def simulate(body: SimulateIn, ctx: TenantCtx = Depends(require("policy:read"))) -> dict:
    i = ctx.session.get(m.Identity, body.identity_id)
    if i is None or i.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    o = evaluate_identity(ctx.session, i, purpose=body.purpose)
    return {"outcome": o.outcome, "reason_code": o.reason_code, "deciding_rule_id": o.deciding_rule_id, "vlan_id": o.vlan_id, "attributes": o.attributes, "steps": o.steps}
