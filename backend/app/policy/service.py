"""Decision recomputation and the RADIUS authorization snapshot.

Whenever certificates, directory data, rules or account state change, every certificate holder in the tenant is
re-evaluated and the results are published as a versioned snapshot the radius-agent pulls. RADIUS never calls the
API during authentication.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app import models as m
from app.policy.engine import CertInput, Outcome, RuleInput, evaluate


def policy_settings(session: Session, tenant_id: uuid.UUID) -> m.PolicySettings:
    ps = session.get(m.PolicySettings, tenant_id)
    if ps is None:
        ps = m.PolicySettings(tenant_id=tenant_id, default_action="deny", max_snapshot_age_seconds=86_400,
                              allow_server_keygen=False, expiry_warning_days=30)
        session.add(ps)
        session.flush()
    return ps


def load_rules(session: Session, tenant_id: uuid.UUID) -> list[RuleInput]:
    vlans = {v.id: v.vlan_id for v in session.scalars(select(m.Vlan).where(m.Vlan.tenant_id == tenant_id))}
    rules = session.scalars(select(m.AccessRule).where(m.AccessRule.tenant_id == tenant_id)).all()
    return [RuleInput(id=str(r.id), name=r.name, priority=r.priority, enabled=r.enabled, action=r.action,
                      group_ids={str(g.id) for g in r.groups if not g.deleted}, purposes=list(r.purposes or []),
                      vlan_id=vlans.get(r.vlan_ref) if r.vlan_ref else None, extra_attributes=list(r.extra_attributes or []))
            for r in rules]


def wired_vlan_map(session: Session, tenant_id: uuid.UUID) -> dict[int, int | None]:
    """VLAN ID → what a switch port gets instead (docs/plans/wired-8021x.md §4): the same VLAN, none (the port keeps
    its own VLAN), or another VLAN."""
    out: dict[int, int | None] = {}
    for v in session.scalars(select(m.Vlan).where(m.Vlan.tenant_id == tenant_id)):
        out[v.vlan_id] = None if v.wired_mode == "port" else v.wired_vlan_id if v.wired_mode == "vlan" else v.vlan_id
    return out


def wired_vlan(mapping: dict[int, int | None], outcome: str, vlan_id: int | None) -> int | None:
    """The decision's VLAN on switch ports. A VLAN ID with no VLAN record (shouldn't happen) is passed through, as it
    was before wired 802.1X."""
    if outcome != "allow" or vlan_id is None:
        return None
    return mapping.get(vlan_id, vlan_id)


def _default_vlan(session: Session, ps: m.PolicySettings) -> int | None:
    if not ps.default_vlan_ref:
        return None
    v = session.get(m.Vlan, ps.default_vlan_ref)
    return v.vlan_id if v else None


def evaluate_identity(session: Session, identity: m.Identity, cert: m.Certificate | None = None,
                      purpose: str | None = None, now: datetime | None = None) -> Outcome:
    """Evaluate one identity, optionally for a concrete certificate or a certificate purpose (preview)."""
    ps = policy_settings(session, identity.tenant_id)
    now = now or datetime.now(UTC)
    groups = {str(g.id) for g in identity.groups if not g.deleted}
    if cert is not None:
        cin = CertInput(serial=cert.serial, status=cert.status, not_after=cert.not_after, purpose=cert.purpose)
    elif purpose:
        cin = CertInput(serial="(preview)", status="active", not_after=now + timedelta(days=1), purpose=purpose)
    else:
        cin = None
    outcome = evaluate(identity.account_state, groups, load_rules(session, identity.tenant_id), ps.default_action,
                       _default_vlan(session, ps), now, cin)
    if cert is None:
        outcome.steps = [s for s in outcome.steps if s["kind"] != "certificate"]
    return outcome


def recompute_tenant(session: Session, tenant_id: uuid.UUID) -> int:
    """Re-evaluate every certificate in the tenant and store decisions. Returns the count."""
    ps = policy_settings(session, tenant_id)
    rules = load_rules(session, tenant_id)
    default_vlan = _default_vlan(session, ps)
    wired = wired_vlan_map(session, tenant_id)
    now = datetime.now(UTC)
    identities = {i.id: i for i in session.scalars(select(m.Identity).where(m.Identity.tenant_id == tenant_id))}
    certs = session.scalars(select(m.Certificate).where(
        m.Certificate.tenant_id == tenant_id, m.Certificate.purpose.in_(("user", "device")))).all()
    session.execute(delete(m.Decision).where(m.Decision.tenant_id == tenant_id))
    count = 0
    for c in certs:
        ident = identities.get(c.identity_id) if c.identity_id else None
        cin = CertInput(serial=c.serial, status=c.status, not_after=c.not_after, purpose=c.purpose)
        if ident is None:
            out = Outcome("deny", "cert_unknown", None, None, [], [{"kind": "account", "ok": False, "detail": "No identity is linked to this certificate"}])
        else:
            groups = {str(g.id) for g in ident.groups if not g.deleted}
            out = evaluate(ident.account_state, groups, rules, ps.default_action, default_vlan, now, cin)
        session.add(m.Decision(certificate_id=c.id, tenant_id=tenant_id, identity_id=c.identity_id, outcome=out.outcome,
                               reason_code=out.reason_code, deciding_rule_id=uuid.UUID(out.deciding_rule_id) if out.deciding_rule_id else None,
                               vlan_id=out.vlan_id, wired_vlan_id=wired_vlan(wired, out.outcome, out.vlan_id),
                               attributes=out.attributes, steps=out.steps, computed_at=now))
        count += 1
    rs = session.get(m.RadiusSettings, tenant_id)
    if rs is not None:
        rs.snapshot_version = int(now.timestamp() * 1000)
        rs.snapshot_built_at = now
    session.flush()
    return count


def snapshot(session: Session, tenant_id: uuid.UUID) -> dict:
    """The authorization snapshot for one tenant, as served to the radius-agent.

    Revoked and expired certificates are included as explicit denials so RADIUS logs the precise reason; serials not
    present at all are rejected as `cert_unknown`.
    """
    ps = policy_settings(session, tenant_id)
    rs = session.get(m.RadiusSettings, tenant_id)
    built = rs.snapshot_built_at if rs and rs.snapshot_built_at else datetime.now(UTC)
    rows = session.execute(
        select(m.Certificate.serial, m.Certificate.not_after, m.Certificate.identity_id, m.Identity.username, m.Decision.outcome,
               m.Decision.reason_code, m.Decision.vlan_id, m.Decision.wired_vlan_id, m.Decision.attributes, m.Decision.deciding_rule_id)
        .join(m.Decision, m.Decision.certificate_id == m.Certificate.id)
        .outerjoin(m.Identity, m.Identity.id == m.Certificate.identity_id)
        .where(m.Certificate.tenant_id == tenant_id)
    ).all()
    entries = []
    now = datetime.now(UTC)
    for r in rows:
        if r.outcome == "deny" and r.reason_code == "cert_expired" and r.not_after < now - timedelta(days=90):
            continue  # keep the snapshot small; long-expired certs fail TLS validation anyway
        entries.append({
            "serial": r.serial, "outcome": r.outcome, "reason": r.reason_code, "vlan": r.vlan_id,
            # On switch ports (None = assign none). Agents before wired 802.1X ignore it.
            "wired_vlan": r.wired_vlan_id,
            "attributes": [a for a in (r.attributes or []) if a["name"] not in ("Tunnel-Type", "Tunnel-Medium-Type", "Tunnel-Private-Group-ID")],
            "rule_id": str(r.deciding_rule_id) if r.deciding_rule_id else None, "identity_id": str(r.identity_id) if r.identity_id else None,
            "username": r.username, "not_after": int(r.not_after.timestamp()),
        })
    entries.sort(key=lambda e: e["serial"])
    version = rs.snapshot_version if rs else 0
    body = {"tenant_id": str(tenant_id), "version": version, "built_at": int(built.timestamp()),
            "valid_until": int(built.timestamp()) + ps.max_snapshot_age_seconds, "entries": entries}
    body["digest"] = hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()
    return body
