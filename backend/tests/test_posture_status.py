"""The one enforcement status every chip and panel shows (posture.status_of): each state, and which wins."""
from types import SimpleNamespace

import pytest

from app.posture import status_of


def healthy(**kw) -> dict:
    e = {"enforceable": True, "missing": [], "agent_online": True, "config_ok": True, "radius_state": "running", "served": True,
         "snapshot_built_at": "2026-11-06T08:00:00+00:00", "snapshot_expired": False, "agent_in_sync": True, "applying": False,
         "auto_refresh": True, "refresh_blocked_by": None, "refresh_overdue": False}
    e.update(kw)
    return e


def tenant(status="active"):
    return SimpleNamespace(status=status)


def dc(status="ok", last_sync_at="2026-11-06"):
    return SimpleNamespace(last_sync_status=status, last_sync_at=last_sync_at)


def test_healthy_tenant_is_enforcing():
    assert status_of(tenant(), healthy(), None) == {"state": "enforcing", "tone": "valid", "label": "Enforcing",
                                                    "detail": "RADIUS is enforcing this tenant's latest policy."}


@pytest.mark.parametrize(("kw", "state", "tone"), [
    ({"agent_online": False}, "radius_offline", "crit"),
    ({"config_ok": False}, "radius_config", "crit"),
    ({"radius_state": "stopped"}, "radius_stopped", "crit"),
    ({"radius_state": "starting"}, "starting", "neutral"),
    ({"snapshot_built_at": None}, "no_snapshot", "crit"),
    ({"snapshot_expired": True}, "expired", "crit"),
    ({"served": False}, "not_served", "crit"),
    ({"served": False, "applying": True}, "applying", "neutral"),
    ({"agent_in_sync": False, "applying": True}, "applying", "neutral"),
    ({"agent_in_sync": False}, "pending", "warn"),
    ({"refresh_overdue": True}, "overdue", "warn"),
    ({"auto_refresh": False, "refresh_blocked_by": "worker"}, "at_risk", "crit"),
])
def test_each_state(kw, state, tone):
    st = status_of(tenant(), healthy(**kw), dc())
    assert (st["state"], st["tone"]) == (state, tone)


def test_suspended_and_setup_are_by_design_not_faults():
    assert status_of(tenant("suspended"), healthy(enforceable=False), None)["state"] == "suspended"
    st = status_of(tenant("setup"), healthy(enforceable=False), None)
    assert st["state"] == "setup" and st["tone"] == "neutral"


def test_a_stopped_freeradius_is_never_enforcing():
    # The agent heartbeats and the snapshot is current, but FreeRADIUS itself is down.
    assert status_of(tenant(), healthy(radius_state="stopped"), None)["label"] == "RADIUS stopped"


def test_critical_wins_over_warning():
    st = status_of(tenant(), healthy(agent_in_sync=False, auto_refresh=False, refresh_blocked_by="worker"), None)
    assert st["tone"] == "crit"
    assert status_of(tenant(), healthy(snapshot_expired=True, agent_in_sync=False), None)["state"] == "expired"


@pytest.mark.parametrize(("d", "says"), [
    (dc("failed"), "Directory sync is failing"),
    (dc("ok", "2026-11-01"), "hasn't synced recently"),
    (dc(None, None), "never synced"),
])
def test_directory_cause_is_named(d, says):
    st = status_of(tenant(), healthy(auto_refresh=False, refresh_blocked_by="directory"), d)
    assert st["state"] == "at_risk" and says in st["detail"]


def test_worker_down_is_not_blamed_on_the_directory():
    st = status_of(tenant(), healthy(auto_refresh=False, refresh_blocked_by="worker"), dc("failed"))
    assert "worker" in st["detail"] and "Directory" not in st["detail"]


def test_unknown_served_does_not_alarm():
    # Older agents don't report which tenants they serve.
    assert status_of(tenant(), healthy(served=None), None)["state"] == "enforcing"
