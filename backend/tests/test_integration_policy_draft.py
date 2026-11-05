"""Staged policy changes against a real database: impact preview, atomic publish, and concurrent-edit refusal.

Enable with EASYEAP_TEST_INTEGRATION=1 (see DEVELOPMENT.md).
"""
import os
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import select, text

pytestmark = [pytest.mark.integration,
              pytest.mark.skipif(os.environ.get("EASYEAP_TEST_INTEGRATION") != "1", reason="integration stack not enabled")]

from app import models as m  # noqa: E402
from app.audit import Actor  # noqa: E402
from app.db import new_session, set_platform, set_tenant  # noqa: E402
from app.deps import TenantCtx  # noqa: E402
from app.routers import policy as policy_router  # noqa: E402


@pytest.fixture()
def tenant():
    """Groups IT / Staff / Contractors; alice (IT+Staff), bob (Staff), carol (Contractors+Staff); rules: deny Contractors, IT→120, Staff→100."""
    s = new_session()
    set_platform(s)
    t = m.Tenant(slug=f"draft-{uuid.uuid4().hex[:6]}", name="Draft test", status="setup")
    s.add(t)
    s.flush()
    tid = t.id
    s.add(m.PolicySettings(tenant_id=tid, default_action="deny", max_snapshot_age_seconds=86_400, allow_server_keygen=False, expiry_warning_days=30))
    g = {n: m.DirectoryGroup(tenant_id=tid, name=n, dn=f"CN={n},DC=test", object_guid=uuid.uuid4().hex) for n in ("IT", "Staff", "Contractors")}
    s.add_all(g.values())
    v120, v100 = m.Vlan(tenant_id=tid, vlan_id=120, name="IT"), m.Vlan(tenant_id=tid, vlan_id=100, name="Staff")
    s.add_all([v120, v100])
    s.flush()
    people = {}
    for user, groups in (("alice", ["IT", "Staff"]), ("bob", ["Staff"]), ("carol", ["Contractors", "Staff"])):
        i = m.Identity(tenant_id=tid, source="local", username=user, display_name=user.title(), account_state="enabled")
        i.groups = [g[x] for x in groups]
        s.add(i)
        people[user] = i
    rules = [("Block contractors", "deny", None, ["Contractors"]), ("IT", "allow", v120.id, ["IT"]), ("Staff", "allow", v100.id, ["Staff"])]
    for n, (name, action, vlan, groups) in enumerate(rules):
        r = m.AccessRule(tenant_id=tid, name=name, priority=(n + 1) * 10, enabled=True, action=action, vlan_ref=vlan, purposes=[], extra_attributes=[])
        r.groups = [g[x] for x in groups]
        s.add(r)
    s.commit()
    ids = {"tenant": tid, "groups": {k: v.id for k, v in g.items()}, "vlans": {120: v120.id, 100: v100.id},
           "people": {k: v.id for k, v in people.items()}}
    s.close()
    yield ids
    s = new_session()
    set_platform(s)
    s.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": tid})
    s.commit()
    s.close()


def _ctx(s, tid):
    set_tenant(s, tid)
    principal = SimpleNamespace(actor=Actor.system("policy-draft test"))
    return TenantCtx(tenant=s.get(m.Tenant, tid), principal=principal, session=s, perms={"policy:read", "policy:write"})


def _live_draft(ctx) -> policy_router.DraftIn:
    p = policy_router.get_policy(ctx)
    return policy_router.DraftIn(
        revision=p["revision"], default_action=p["settings"]["default_action"], default_vlan_ref=p["settings"]["default_vlan_ref"],
        rules=[policy_router.DraftRuleIn(id=r["id"], name=r["name"], enabled=r["enabled"], action=r["action"], vlan_ref=r["vlan_ref"],
                                         group_ids=[g["id"] for g in r["groups"]], purposes=r["purposes"], extra_attributes=r["extra_attributes"])
               for r in p["rules"]])


def test_unchanged_draft_has_no_impact(tenant):
    s = new_session()
    try:
        ctx = _ctx(s, tenant["tenant"])
        out = policy_router.preview(_live_draft(ctx), ctx)
        assert out["summary"]["evaluated"] == 3
        assert out["changes"] == [] and out["revision_current"] is True
    finally:
        s.rollback()
        s.close()


def test_disabling_deny_rule_previews_contractor_newly_allowed(tenant):
    s = new_session()
    try:
        ctx = _ctx(s, tenant["tenant"])
        d = _live_draft(ctx)
        d.rules[0].enabled = False
        out = policy_router.preview(d, ctx)
        assert out["summary"]["newly_allowed"] == 1 and out["summary"]["newly_denied"] == 0
        (c,) = out["changes"]
        assert c["identity"]["username"] == "carol" and c["kind"] == "newly_allowed"
        assert c["before"]["reason_code"] == "policy_deny" and c["after"]["vlan_id"] == 100 and c["after"]["rule_name"] == "Staff"
        # Preview never writes: the live policy is unchanged.
        assert policy_router.get_policy(ctx)["rules"][0]["enabled"] is True
    finally:
        s.rollback()
        s.close()


def test_reordering_allows_previews_vlan_change(tenant):
    s = new_session()
    try:
        ctx = _ctx(s, tenant["tenant"])
        d = _live_draft(ctx)
        d.rules = [d.rules[0], d.rules[2], d.rules[1]]  # Staff before IT
        out = policy_router.preview(d, ctx)
        assert out["summary"]["vlan_changed"] == 1
        assert out["changes"][0]["identity"]["username"] == "alice"
        assert (out["changes"][0]["before"]["vlan_id"], out["changes"][0]["after"]["vlan_id"]) == (120, 100)
    finally:
        s.rollback()
        s.close()


def test_publish_is_atomic_and_stale_drafts_are_refused(tenant):
    s = new_session()
    try:
        ctx = _ctx(s, tenant["tenant"])
        d = _live_draft(ctx)
        stale = d.revision
        # Remove "Block contractors", add a new deny for Contractors at the end, reorder Staff before IT.
        d.rules = [d.rules[2], d.rules[1], policy_router.DraftRuleIn(name="Contractors (new)", action="deny", group_ids=[tenant["groups"]["Contractors"]])]
        out = policy_router.publish(d, ctx)
        s.commit()
        names = [r["name"] for r in out["rules"]]
        assert names == ["Staff", "IT", "Contractors (new)"]
        assert [r["priority"] for r in out["rules"]] == [10, 20, 30]
        assert out["revision"] != stale
        assert out["impact"]["vlan_changed"] == 1  # alice now lands on Staff
        assert out["impact"]["newly_allowed"] == 0  # the new deny still blocks carol, wherever it sits
        ev = s.scalars(select(m.AuditEvent).where(m.AuditEvent.tenant_id == tenant["tenant"], m.AuditEvent.action == "policy.published")).one()
        assert ev.detail["deleted"] == ["Block contractors"] and ev.detail["created"] == ["Contractors (new)"]

        again = _live_draft(ctx)
        again.revision = stale
        with pytest.raises(HTTPException) as exc:
            policy_router.publish(again, ctx)
        assert exc.value.status_code == 409
    finally:
        s.rollback()
        s.close()


def test_access_states_separate_policy_from_certificate(tenant):
    from app.routers.identities import _access
    s = new_session()
    try:
        ctx = _ctx(s, tenant["tenant"])
        rows = s.scalars(select(m.Identity).where(m.Identity.tenant_id == tenant["tenant"])).all()
        acc = {i.username: a for i, a in ((i, _access(ctx, rows, datetime.now(UTC))[i.id]) for i in rows)}
        assert acc["alice"] == {"status": "allowed_no_certificate", "vlan_id": 120, "reason_code": None}
        assert acc["carol"]["status"] == "denied" and acc["carol"]["reason_code"] == "policy_deny"

        from app.posture import enforcement
        enf = enforcement(s, ctx.tenant, None, datetime.now(UTC) + timedelta(seconds=1))
        assert enf["enforceable"] is False and {x["code"] for x in enf["missing"]} >= {"pki", "radius_certificate", "controllers", "tenant_status"}
    finally:
        s.rollback()
        s.close()


def test_settings_cannot_change_the_default_and_keygen_needs_permission_only_to_change(tenant):
    from pydantic import ValidationError
    with pytest.raises(ValidationError):  # the default goes through draft + publish, never through settings
        policy_router.SettingsIn(default_action="allow", max_snapshot_age_seconds=86_400, expiry_warning_days=30)
    s = new_session()
    try:
        ctx = _ctx(s, tenant["tenant"])
        policy_router.policy_settings(s, ctx.id).allow_server_keygen = True
        # A Wi-Fi Admin (no enrollment:server_keygen) can still save other settings while keygen stays on...
        out = policy_router.update_settings(policy_router.SettingsIn(max_snapshot_age_seconds=43_200, allow_server_keygen=True, expiry_warning_days=14), ctx)
        assert out["expiry_warning_days"] == 14 and out["default_action"] == "deny"
        # ...but can't change it.
        with pytest.raises(HTTPException) as e:
            policy_router.update_settings(policy_router.SettingsIn(max_snapshot_age_seconds=43_200, allow_server_keygen=False, expiry_warning_days=14), ctx)
        assert e.value.status_code == 403
    finally:
        s.rollback()
        s.close()


def test_preview_lists_groups_and_tenant_audit_verify_discloses_only_this_tenant(tenant):
    from app.routers import events as events_router
    s = new_session()
    try:
        ctx = _ctx(s, tenant["tenant"])
        d = _live_draft(ctx)
        d.rules[0].enabled = False
        change = next(c for c in policy_router.preview(d, ctx)["changes"] if c["identity"]["username"] == "carol")
        assert {g["name"] for g in change["identity"]["groups"]} == {"Contractors", "Staff"}
        v = events_router.verify_tenant(ctx)
        assert set(v) == {"ok", "checked", "tenant_entries", "first_bad_id", "break_in_this_tenant"}
        assert v["ok"] is True and v["first_bad_id"] is None
    finally:
        s.rollback()
        s.close()
