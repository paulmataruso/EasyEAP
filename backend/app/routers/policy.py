"""VLANs, access rules, tenant defaults and the decision simulator."""
from __future__ import annotations

import json
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from app import audit
from app import models as m
from app.deps import TenantCtx, require
from app.policy import draft as policy_draft
from app.policy.engine import ALLOWED_EXTRA_ATTRIBUTES
from app.policy.service import evaluate_identity, policy_settings, recompute_tenant, wired_vlan, wired_vlan_map
from app.radius.state import bump

router = APIRouter(prefix="/api/tenants/{tenant_id}/policy", tags=["policy"])


def vlan_out(v: m.Vlan) -> dict:
    return {"id": str(v.id), "vlan_id": v.vlan_id, "name": v.name, "description": v.description, "color": v.color,
            "wired_mode": v.wired_mode, "wired_vlan_id": v.wired_vlan_id}


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
            "settings": settings_out(policy_settings(s, ctx.id)), "allowed_extra_attributes": sorted(ALLOWED_EXTRA_ATTRIBUTES),
            "revision": policy_draft.revision(s, ctx.id)}


def _changed(ctx: TenantCtx) -> None:
    recompute_tenant(ctx.session, ctx.id)
    bump(ctx.session, ctx.id)


# Same order as the console's palette (frontend ui/index.tsx VLAN_COLORS).
VLAN_COLORS = ("blue", "violet", "teal", "orange", "amber", "green", "rose", "slate")


class VlanIn(BaseModel):
    vlan_id: int = Field(ge=1, le=4094)
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=300)
    # None: a new VLAN gets the first colour no other VLAN in the tenant uses; an update keeps its colour.
    color: str | None = Field(default=None, pattern="^(" + "|".join(VLAN_COLORS) + ")$")
    # On switch ports: "same" VLAN ID, the "port"'s own VLAN, or another "vlan" (wired_vlan_id). None on update: keep.
    wired_mode: Literal["same", "port", "vlan"] | None = None
    wired_vlan_id: int | None = Field(default=None, ge=1, le=4094)


def _apply_wired(v: m.Vlan, body: VlanIn) -> None:
    if body.wired_mode is None:
        if body.wired_vlan_id is not None and v.wired_mode == "vlan":
            v.wired_vlan_id = body.wired_vlan_id
        return
    if body.wired_mode == "vlan" and body.wired_vlan_id is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Choose the VLAN that switch ports get instead.")
    v.wired_mode = body.wired_mode
    v.wired_vlan_id = body.wired_vlan_id if body.wired_mode == "vlan" else None


def _free_color(s, tenant_id: uuid.UUID) -> str:
    used = {v.color for v in s.scalars(select(m.Vlan).where(m.Vlan.tenant_id == tenant_id))}
    return next((c for c in VLAN_COLORS if c not in used), VLAN_COLORS[len(used) % len(VLAN_COLORS)])


@router.post("/vlans", status_code=201)
def create_vlan(body: VlanIn, ctx: TenantCtx = Depends(require("policy:write"))) -> dict:
    if ctx.session.scalars(select(m.Vlan).where(m.Vlan.tenant_id == ctx.id, m.Vlan.vlan_id == body.vlan_id)).first():
        raise HTTPException(status.HTTP_409_CONFLICT, f"VLAN {body.vlan_id} already exists.")
    v = m.Vlan(tenant_id=ctx.id, vlan_id=body.vlan_id, name=body.name, description=body.description,
               color=body.color or _free_color(ctx.session, ctx.id), wired_mode="same", wired_vlan_id=None)
    _apply_wired(v, body)
    ctx.session.add(v)
    ctx.session.flush()
    audit.record(ctx.session, ctx.actor, "vlan.created", tenant_id=ctx.id, target_type="vlan", target_id=v.id, target_label=f"{v.vlan_id} {v.name}")
    return vlan_out(v)


@router.put("/vlans/{vlan_ref}")
def update_vlan(vlan_ref: uuid.UUID, body: VlanIn, ctx: TenantCtx = Depends(require("policy:write"))) -> dict:
    v = ctx.session.get(m.Vlan, vlan_ref)
    if v is None or v.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "VLAN not found.")
    for k, val in body.model_dump(exclude_none=True, exclude={"wired_mode", "wired_vlan_id"}).items():
        setattr(v, k, val)
    _apply_wired(v, body)
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
    """Tenant policy settings. The default action and VLAN are part of the policy itself: they change only through a
    draft publish (with its revision check), never here, so a settings save can't silently undo a newer publish."""
    model_config = ConfigDict(extra="forbid")
    max_snapshot_age_seconds: int = Field(ge=3600, le=7 * 86_400)
    allow_server_keygen: bool = False
    expiry_warning_days: int = Field(ge=1, le=180)


@router.put("/settings")
def update_settings(body: SettingsIn, ctx: TenantCtx = Depends(require("policy:write"))) -> dict:
    ps = policy_settings(ctx.session, ctx.id)
    # Only changing the server-keygen setting needs the extra permission; saving other settings leaves it as it is.
    if body.allow_server_keygen != ps.allow_server_keygen and "enrollment:server_keygen" not in ctx.perms:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only a Tenant Administrator can change whether server-generated keys are allowed.")
    dc = ctx.session.get(m.DirectoryConfig, ctx.id)
    if dc is not None and dc.enabled and dc.sync_interval_minutes * 60 * 2 > body.max_snapshot_age_seconds:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"The directory syncs every {dc.sync_interval_minutes} minutes, so fail closed after at least "
                            f"{-(-dc.sync_interval_minutes * 2 // 60)} hours, or sync more often first (Directory).")
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
    return {"outcome": o.outcome, "reason_code": o.reason_code, "deciding_rule_id": o.deciding_rule_id, "vlan_id": o.vlan_id,
            "wired_vlan_id": wired_vlan(wired_vlan_map(ctx.session, ctx.id), o.outcome, o.vlan_id), "attributes": o.attributes, "steps": o.steps}


# ── Staged changes: preview and atomic publish ───────────────────────────────


class DraftRuleIn(RuleIn):
    id: uuid.UUID | None = None


class DraftIn(BaseModel):
    revision: str = Field(min_length=1, max_length=64)
    rules: list[DraftRuleIn] = Field(max_length=500)
    default_action: str = Field(pattern="^(allow|deny)$")
    default_vlan_ref: uuid.UUID | None = None


def _draft_data(ctx: TenantCtx, body: DraftIn) -> list[policy_draft.DraftRuleData]:
    seen: set[uuid.UUID] = set()
    out = []
    for r in body.rules:
        _validate_rule(ctx, r)
        if r.id is not None:
            if r.id in seen:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, f"“{r.name}” appears twice in the draft.")
            seen.add(r.id)
        out.append(policy_draft.DraftRuleData(id=r.id, name=r.name, enabled=r.enabled, action=r.action, vlan_ref=r.vlan_ref,
                                              group_ids=list(dict.fromkeys(r.group_ids)), purposes=r.purposes,
                                              extra_attributes=[a.model_dump() for a in r.extra_attributes]))
    if body.default_action == "allow":
        if not body.default_vlan_ref:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Choose the VLAN that the default Allow assigns.")
        v = ctx.session.get(m.Vlan, body.default_vlan_ref)
        if v is None or v.tenant_id != ctx.id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Choose a default VLAN from this tenant.")
    return out


def _check_revision(ctx: TenantCtx, body: DraftIn) -> str:
    current = policy_draft.revision(ctx.session, ctx.id)
    if body.revision != current:
        raise HTTPException(status.HTTP_409_CONFLICT, "Someone published a policy change after you started this draft. "
                                                      "Reload the policy to see it, then make your change again.")
    return current


@router.post("/preview")
def preview(body: DraftIn, ctx: TenantCtx = Depends(require("policy:read"))) -> dict:
    data = _draft_data(ctx, body)
    out = policy_draft.preview(ctx.session, ctx.id, data, body.default_action, body.default_vlan_ref if body.default_action == "allow" else None)
    out["revision_current"] = policy_draft.revision(ctx.session, ctx.id) == body.revision
    return out


def _fingerprint(r: m.AccessRule) -> tuple:
    return (r.name, r.description, r.enabled, r.action, r.vlan_ref, r.priority, tuple(sorted(str(g.id) for g in r.groups)),
            tuple(r.purposes or []), json.dumps(r.extra_attributes or [], sort_keys=True))


@router.post("/publish")
def publish(body: DraftIn, ctx: TenantCtx = Depends(require("policy:write"))) -> dict:
    s = ctx.session
    before_rev = _check_revision(ctx, body)
    data = _draft_data(ctx, body)
    default_vlan_ref = body.default_vlan_ref if body.default_action == "allow" else None
    impact = policy_draft.preview(s, ctx.id, data, body.default_action, default_vlan_ref)["summary"]

    existing = {r.id: r for r in s.scalars(select(m.AccessRule).where(m.AccessRule.tenant_id == ctx.id))}
    groups = {g.id: g for g in s.scalars(select(m.DirectoryGroup).where(m.DirectoryGroup.tenant_id == ctx.id))}
    created, updated, deleted = [], [], []
    keep: set[uuid.UUID] = set()
    for i, r in enumerate(data):
        if r.id is not None and r.id not in existing:
            raise HTTPException(status.HTTP_409_CONFLICT, f"“{r.name}” no longer exists. Reload the policy and try again.")
        row = existing[r.id] if r.id is not None else m.AccessRule(tenant_id=ctx.id)
        was = _fingerprint(row) if r.id is not None else None
        row.name, row.enabled, row.action, row.purposes = r.name, r.enabled, r.action, r.purposes
        row.description = body.rules[i].description
        row.vlan_ref = r.vlan_ref if r.action == "allow" else None
        row.extra_attributes = r.extra_attributes if r.action == "allow" else []
        row.priority = (i + 1) * 10
        row.groups = [groups[g] for g in r.group_ids]
        if r.id is None:
            s.add(row)
            created.append(r.name)
        else:
            keep.add(r.id)
            if was != _fingerprint(row):
                updated.append(r.name)
    for rid, row in existing.items():
        if rid not in keep:
            deleted.append(row.name)
            s.delete(row)
    ps = policy_settings(s, ctx.id)
    ps.default_action, ps.default_vlan_ref = body.default_action, default_vlan_ref
    s.flush()
    _changed(ctx)
    after_rev = policy_draft.revision(s, ctx.id)
    audit.record(s, ctx.actor, "policy.published", tenant_id=ctx.id, target_type="policy",
                 detail={"from_revision": before_rev, "to_revision": after_rev, "created": created, "updated": updated, "deleted": deleted,
                         "order": [r.name for r in data], "default_action": body.default_action, "impact": impact})
    rs = s.get(m.RadiusSettings, ctx.id)
    # The snapshot this publish produced: the console watches the agent's applied version reach it.
    snapshot = {"version": rs.snapshot_version, "built_at": rs.snapshot_built_at.isoformat() if rs.snapshot_built_at else None} if rs else None
    return {**get_policy(ctx), "impact": impact, "snapshot": snapshot}
