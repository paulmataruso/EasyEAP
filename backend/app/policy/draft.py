"""Staged policy changes: a revision fingerprint, an impact preview against the real directory, and atomic publish.

The console edits a draft locally (rules in evaluation order plus the tenant default), asks for a preview of who
changes decision or VLAN, then publishes the whole draft in one transaction. Publishing is refused when the live
policy changed after the draft was started (optimistic concurrency on the revision).
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import models as m
from app.policy.engine import CertInput, RuleInput, evaluate
from app.policy.service import _default_vlan, load_rules, policy_settings

MAX_LISTED_CHANGES = 500


def revision(session: Session, tenant_id: uuid.UUID) -> str:
    """Fingerprint of everything a draft replaces: the rules (in order) and the default action/VLAN."""
    rules = session.scalars(select(m.AccessRule).where(m.AccessRule.tenant_id == tenant_id).order_by(m.AccessRule.priority, m.AccessRule.id)).all()
    ps = policy_settings(session, tenant_id)
    body = {
        "rules": [{"id": str(r.id), "name": r.name, "description": r.description, "enabled": r.enabled, "action": r.action,
                   "vlan_ref": str(r.vlan_ref) if r.vlan_ref else None, "groups": sorted(str(g.id) for g in r.groups),
                   "purposes": sorted(r.purposes or []), "extra": r.extra_attributes or []} for r in rules],
        "default_action": ps.default_action, "default_vlan_ref": str(ps.default_vlan_ref) if ps.default_vlan_ref else None,
    }
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]


@dataclass
class DraftRuleData:
    id: uuid.UUID | None
    name: str
    enabled: bool
    action: str
    vlan_ref: uuid.UUID | None
    group_ids: list[uuid.UUID]
    purposes: list[str]
    extra_attributes: list[dict[str, str]]


def draft_inputs(session: Session, tenant_id: uuid.UUID, rules: list[DraftRuleData]) -> list[RuleInput]:
    vlans = {v.id: v.vlan_id for v in session.scalars(select(m.Vlan).where(m.Vlan.tenant_id == tenant_id))}
    live_groups = {g.id for g in session.scalars(select(m.DirectoryGroup).where(m.DirectoryGroup.tenant_id == tenant_id, m.DirectoryGroup.deleted.is_(False)))}
    return [RuleInput(id=str(r.id) if r.id else f"draft-{i}", name=r.name, priority=(i + 1) * 10, enabled=r.enabled, action=r.action,
                      group_ids={str(g) for g in r.group_ids if g in live_groups}, purposes=list(r.purposes),
                      vlan_id=vlans.get(r.vlan_ref) if r.action == "allow" and r.vlan_ref else None,
                      extra_attributes=list(r.extra_attributes) if r.action == "allow" else [])
            for i, r in enumerate(rules)]


def _brief(o, names: dict[str, str]) -> dict:
    return {"outcome": o.outcome, "vlan_id": o.vlan_id, "reason_code": o.reason_code, "rule_id": o.deciding_rule_id,
            "rule_name": names.get(o.deciding_rule_id) if o.deciding_rule_id else None}


def preview(session: Session, tenant_id: uuid.UUID, draft_rules: list[DraftRuleData], default_action: str,
            default_vlan_ref: uuid.UUID | None) -> dict:
    """Evaluate the live policy and the draft for every user (per certificate purpose they hold) and report differences."""
    now = datetime.now(UTC)
    ps = policy_settings(session, tenant_id)
    live = load_rules(session, tenant_id)
    live_default_vlan = _default_vlan(session, ps)
    draft = draft_inputs(session, tenant_id, draft_rules)
    draft_default_vlan = None
    if default_action == "allow" and default_vlan_ref:
        v = session.get(m.Vlan, default_vlan_ref)
        draft_default_vlan = v.vlan_id if v and v.tenant_id == tenant_id else None
    names = {r.id: r.name for r in live} | {r.id: r.name for r in draft}

    identities = session.scalars(select(m.Identity).where(m.Identity.tenant_id == tenant_id, m.Identity.account_state != "deleted")
                                 .order_by(m.Identity.display_name)).all()
    purposes: dict[uuid.UUID, set[str]] = {}
    for iid, purpose in session.execute(select(m.Certificate.identity_id, m.Certificate.purpose).where(
            m.Certificate.tenant_id == tenant_id, m.Certificate.status == "active", m.Certificate.not_after > now,
            m.Certificate.purpose.in_(("user", "device")), m.Certificate.identity_id.is_not(None))):
        purposes.setdefault(iid, set()).add(purpose)

    summary = {"evaluated": 0, "with_certificates": 0, "newly_allowed": 0, "newly_denied": 0, "vlan_changed": 0, "rule_only": 0, "unchanged": 0}
    changes: list[dict] = []
    for ident in identities:
        groups = {str(g.id) for g in ident.groups if not g.deleted}
        held = purposes.get(ident.id)
        summary["evaluated"] += 1
        if held:
            summary["with_certificates"] += 1
        for purpose in sorted(held or {"user"}):
            cin = CertInput(serial="(preview)", status="active", not_after=now + timedelta(days=1), purpose=purpose)
            before = evaluate(ident.account_state, groups, live, ps.default_action, live_default_vlan, now, cin)
            after = evaluate(ident.account_state, groups, draft, default_action, draft_default_vlan, now, cin)
            if before.outcome != after.outcome:
                kind = "newly_allowed" if after.outcome == "allow" else "newly_denied"
            elif before.outcome == "allow" and before.vlan_id != after.vlan_id:
                kind = "vlan_changed"
            elif before.deciding_rule_id != after.deciding_rule_id:
                summary["rule_only"] += 1
                continue
            else:
                summary["unchanged"] += 1
                continue
            summary[kind] += 1
            if len(changes) < MAX_LISTED_CHANGES:
                changes.append({"kind": kind, "purpose": purpose, "has_certificate": bool(held),
                                "identity": {"id": str(ident.id), "display_name": ident.display_name, "username": ident.username,
                                             "account_state": ident.account_state,
                                             "groups": [{"id": str(g.id), "name": g.name, "source": g.source} for g in ident.groups if not g.deleted]},
                                "before": _brief(before, names), "after": _brief(after, names), "steps": after.steps})
    order = {"newly_allowed": 0, "newly_denied": 1, "vlan_changed": 2}
    changes.sort(key=lambda c: (order[c["kind"]], not c["has_certificate"], c["identity"]["display_name"].lower()))

    warnings = []
    if default_action == "allow":
        warnings.append("The tenant default is Allow: anyone with a valid certificate who matches no rule gets network access.")
    for r, ri in zip(draft_rules, draft, strict=True):
        if r.enabled and not ri.group_ids:
            warnings.append(f"“{r.name}” has no groups that still exist in the directory, so it matches nobody.")
    return {"summary": summary, "changes": changes, "truncated": sum(summary[k] for k in order) > len(changes), "warnings": warnings,
            "computed_at": now.isoformat()}
