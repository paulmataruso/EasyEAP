import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.policy.engine import ALLOWED_EXTRA_ATTRIBUTES, CertInput, RuleInput, evaluate, vlan_attributes

FIX = json.loads((Path(__file__).parent / "fixtures" / "policy_cases.json").read_text())
NOW = datetime.fromisoformat(FIX["now"].replace("Z", "+00:00"))
RULES = [RuleInput(id=r["id"], name=r["name"], priority=r["priority"], enabled=r["enabled"], action=r["action"], group_ids=set(r["groups"]),
                   purposes=r["purposes"], vlan_id=r["vlan"]) for r in FIX["rules"]]


@pytest.mark.parametrize("case", FIX["cases"], ids=[c["name"] for c in FIX["cases"]])
def test_shared_cases(case):
    default = case.get("default", {"action": "deny", "vlan": None})
    cert = None
    if case.get("cert"):
        c = case["cert"]
        cert = CertInput(serial="ABC", status=c["status"], not_after=datetime.fromisoformat(c["not_after"].replace("Z", "+00:00")), purpose=c["purpose"])
    elif case.get("purpose"):
        cert = CertInput(serial="ABC", status="active", not_after=NOW + timedelta(days=30), purpose=case["purpose"])
    out = evaluate(case["account"], set(case["groups"]), RULES, default["action"], default["vlan"], NOW, cert)
    exp = case["expect"]
    assert (out.outcome, out.vlan_id, out.deciding_rule_id, out.reason_code) == (exp["outcome"], exp["vlan"], exp["rule"], exp["reason"])
    if out.outcome == "deny":
        assert out.attributes == []


def test_trace_lists_every_enabled_rule_in_priority_order():
    out = evaluate("enabled", {"g-staff"}, RULES, "deny", None, NOW)
    rule_steps = [s["ruleId"] for s in out.steps if s["kind"] == "rule"]
    assert rule_steps == ["r-deny-contractors", "r-it", "r-staff", "r-devices", "r-guest-deny"]
    assert out.steps[0] == {"kind": "account", "ok": True, "detail": "Directory account is enabled"}


def test_vlan_attributes_rfc3580():
    attrs = vlan_attributes(120, [{"name": "Filter-Id", "value": "corp"}, {"name": "User-Password", "value": "x"}])
    assert attrs[:3] == [{"name": "Tunnel-Type", "value": "VLAN (13)"}, {"name": "Tunnel-Medium-Type", "value": "IEEE-802 (6)"},
                         {"name": "Tunnel-Private-Group-ID", "value": "120"}]
    assert {"name": "Filter-Id", "value": "corp"} in attrs
    assert all(a["name"] != "User-Password" for a in attrs), "non-allow-listed attributes are dropped"
    assert "User-Password" not in ALLOWED_EXTRA_ATTRIBUTES


def test_tie_broken_by_rule_id():
    rules = [RuleInput("b", "B", 10, True, "allow", {"g"}, [], 200), RuleInput("a", "A", 10, True, "allow", {"g"}, [], 100)]
    assert evaluate("enabled", {"g"}, rules, "deny", None, NOW).vlan_id == 100


def test_cert_expiry_boundary_is_denied():
    cert = CertInput("X", "active", NOW, "user")
    assert evaluate("enabled", {"g-it"}, RULES, "deny", None, NOW, cert).reason_code == "cert_expired"
    _ = UTC
