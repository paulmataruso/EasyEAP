"""Access-policy evaluation — the canonical implementation of ARCHITECTURE.md §6.

Mirrors frontend/src/domain/policy.ts (used for previews); both are tested against tests/fixtures/policy_cases.json.
Steps are stored in the same camelCase shape the console renders.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# Reply attributes an administrator may add to an Allow rule. Anything else is rejected at the API.
ALLOWED_EXTRA_ATTRIBUTES = {
    "Session-Timeout", "Filter-Id", "Reply-Message", "Class", "Termination-Action",
    "Airespace-ACL-Name", "Aruba-User-Role", "Cisco-AVPair",
}


@dataclass
class RuleInput:
    id: str
    name: str
    priority: int
    enabled: bool
    action: str  # allow | deny
    group_ids: set[str]
    purposes: list[str]
    vlan_id: int | None
    extra_attributes: list[dict[str, str]] = field(default_factory=list)


@dataclass
class CertInput:
    serial: str
    status: str  # active | revoked
    not_after: datetime
    purpose: str


@dataclass
class Outcome:
    outcome: str
    reason_code: str | None
    deciding_rule_id: str | None
    vlan_id: int | None
    attributes: list[dict[str, str]]
    steps: list[dict[str, Any]]


def vlan_attributes(vlan_id: int | None, extra: list[dict[str, str]]) -> list[dict[str, str]]:
    attrs: list[dict[str, str]] = []
    if vlan_id is not None:
        attrs = [
            {"name": "Tunnel-Type", "value": "VLAN (13)"},
            {"name": "Tunnel-Medium-Type", "value": "IEEE-802 (6)"},
            {"name": "Tunnel-Private-Group-ID", "value": str(vlan_id)},
        ]
    return attrs + [a for a in extra if a.get("name") in ALLOWED_EXTRA_ATTRIBUTES]


def evaluate(account_state: str, group_ids: set[str], rules: list[RuleInput], default_action: str,
             default_vlan_id: int | None, now: datetime, cert: CertInput | None = None) -> Outcome:
    steps: list[dict[str, Any]] = []

    def deny(reason: str, rule_id: str | None = None) -> Outcome:
        return Outcome("deny", reason, rule_id, None, [], steps)

    if account_state != "enabled":
        steps.append({"kind": "account", "ok": False, "detail": f"Directory account is {account_state}"})
        return deny("account_disabled")
    steps.append({"kind": "account", "ok": True, "detail": "Directory account is enabled"})

    if cert is not None:
        if cert.status == "revoked":
            steps.append({"kind": "certificate", "ok": False, "detail": f"Certificate {cert.serial} is revoked"})
            return deny("cert_revoked")
        if cert.not_after <= now:
            steps.append({"kind": "certificate", "ok": False, "detail": f"Certificate {cert.serial} has expired"})
            return deny("cert_expired")
        steps.append({"kind": "certificate", "ok": True, "detail": f"Certificate {cert.serial} is valid"})

    purpose = cert.purpose if cert else None
    ordered = sorted((r for r in rules if r.enabled), key=lambda r: (r.priority, r.id))

    def matches(r: RuleInput) -> bool:
        return bool(r.group_ids & group_ids) and (not purpose or not r.purposes or purpose in r.purposes)

    deny_rule = next((r for r in ordered if r.action == "deny" and matches(r)), None)
    for r in ordered:
        hit = matches(r)
        steps.append({"kind": "rule", "ruleId": r.id, "matched": hit, "action": r.action,
                      "detail": f"Matched “{r.name}”" if hit else f"No matching group for “{r.name}”"})
    if deny_rule:
        return deny("policy_deny", deny_rule.id)

    allow_rule = next((r for r in ordered if r.action == "allow" and matches(r)), None)
    if allow_rule:
        return Outcome("allow", None, allow_rule.id, allow_rule.vlan_id,
                       vlan_attributes(allow_rule.vlan_id, allow_rule.extra_attributes), steps)

    steps.append({"kind": "default", "action": default_action, "detail": "No rule matched; tenant default applies"})
    if default_action != "allow":
        return deny("identity_unauthorized")
    return Outcome("allow", None, None, default_vlan_id, vlan_attributes(default_vlan_id, []), steps)
