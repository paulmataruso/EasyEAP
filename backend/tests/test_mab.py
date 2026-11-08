"""MAC authentication on switch ports (docs/plans/mac-auth.md): the generated switch configuration (content-hashed
control policies swapped, never edited in place; MAB after 802.1X gets no answer), the FreeRADIUS rendering, the
agent's MAC store, and ingest helpers. No database or OpenBao."""
import importlib.util
import re
import sqlite3
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.radius import mab, wired
from app.radius.explain import EXPLANATIONS
from app.radius.state import mab_mode

ROOT = Path(__file__).resolve().parents[2]
TENANT = SimpleNamespace(slug="corp", name="Corp")
SETTINGS = SimpleNamespace(dedicated_ports=False, auth_port=1812, acct_port=1813)
PLAN = {"interfaces": "Gi1/0/1-24", "exclude": "Gi1/0/24"}


def _load(name: str):
    path = ROOT / "services" / "radius" / "agent" / f"{name}.py"
    if not path.exists():
        pytest.skip("services/radius not available in this checkout")
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(f"mab_{name}", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[f"mab_{name}"] = mod
    spec.loader.exec_module(mod)
    return mod


def guide(profile: dict, vendor: str = "cisco-switch") -> dict:
    p = {**wired.validate_profile(vendor, profile), **{k: profile[k] for k in ("mode", "policy", "policy_prev", "last_change") if k in profile}}
    return wired.guide(vendor, client=SimpleNamespace(name="Floor 2"), profile=p, settings=SETTINGS, radius_ip="10.9.9.9", vlans=[], tenant=TENANT)


def P(**kw) -> wired.WiredProfile:
    return wired.WiredProfile.model_validate({**PLAN, **kw})


def policy_block(cli: str, name: str) -> str:
    """The lines of one policy-map definition."""
    start = cli.index(f"policy-map type control subscriber {name}\n")
    return cli[start:cli.index("\n!", start)]


# ── Control policies: never edited in place ──────────────────────────────────


def test_policy_names_follow_content():
    assert re.fullmatch(r"EASYEAP_MONITOR_[0-9A-F]{8}", wired.monitor_policy(P()))
    assert wired.monitor_policy(P()) == wired.monitor_policy(P(host_mode="single-host", access_vlan=10)), "port settings aren't in the policy"
    assert wired.monitor_policy(P()) != wired.monitor_policy(P(mab=True))
    names = {wired.closed_policy(P(no_supplicant=n, no_supplicant_vlan=99, server_down=d, server_down_vlan=98, mab=b))
             for n in ("block", "vlan") for d in ("wait", "open", "vlan") for b in (False, True)}
    assert len(names) == 12, "every different closed policy has its own name"


def test_re_enforce_after_a_plan_change_never_merges_into_the_old_policy():
    """The bug the naming fixes: enforce with an unknown-device VLAN, go back, switch to block, enforce again. IOS would
    merge a re-pasted EASYEAP_CLOSED, keeping `20 class DOT1X_NO_RESP … authorize` and leaving ports open."""
    first = guide({**PLAN, "no_supplicant": "vlan", "no_supplicant_vlan": 99, "mode": "monitor"})
    second = guide({**PLAN, "no_supplicant": "block", "mode": "monitor"})
    a, b = wired.closed_policy(P(no_supplicant="vlan", no_supplicant_vlan=99)), wired.closed_policy(P())
    assert a != b
    assert "DOT1X_NO_RESP" in policy_block(first["enforce_cli"], a)
    assert "DOT1X_NO_RESP" not in policy_block(second["enforce_cli"], b) and "authorize" not in policy_block(second["enforce_cli"], b).split("40 class")[1]
    # Going back to monitor removes the closed policy from the switch, so it never lingers to be merged into.
    back = guide({**PLAN, "no_supplicant": "vlan", "no_supplicant_vlan": 99, "mode": "enforce"})["monitor_cli"]
    assert f"no policy-map type control subscriber {a}" in back


def test_enforce_swaps_policies_on_every_range_then_removes_the_old_one():
    g = guide({**PLAN, "mode": "monitor"})
    mon, closed = wired.monitor_policy(P()), wired.closed_policy(P())
    enf = g["enforce_cli"]
    body = enf.split("interface range", 1)[1]
    assert body.index(f" no service-policy type control subscriber {mon}") < body.index(f" service-policy type control subscriber {closed}") < body.index(" access-session closed")
    assert enf.index(f"policy-map type control subscriber {closed}") < enf.index("interface range")
    assert enf.index(f"no policy-map type control subscriber {mon}") > enf.rindex("interface range") and enf.rstrip().endswith("clear access-session")
    m = g["monitor_cli"]
    assert f"policy-map type control subscriber {mon}" in m, "monitor mode defines its policy again (Enforce removed it)"
    assert f" no service-policy type control subscriber {closed}" in m and f"no policy-map type control subscriber {closed}" in m


def test_recorded_policy_is_what_gets_replaced():
    """A switch running a policy from an older EasyEAP (another hash) is swapped from what EasyEAP last gave it."""
    enf = guide({**PLAN, "mode": "monitor", "policy": "EASYEAP_MONITOR_0LDC0DE0"})["enforce_cli"]
    assert " no service-policy type control subscriber EASYEAP_MONITOR_0LDC0DE0" in enf
    # Shown again after the switch: still the change that was made.
    after = guide({**PLAN, "mode": "enforce", "policy": wired.closed_policy(P()), "policy_prev": "EASYEAP_MONITOR_0LDC0DE0", "last_change": "enforce"})
    assert " no service-policy type control subscriber EASYEAP_MONITOR_0LDC0DE0" in after["enforce_cli"]
    assert f" no service-policy type control subscriber {wired.closed_policy(P())}" in after["monitor_cli"]


# ── MAB in the switch configuration ──────────────────────────────────────────


def test_ibns2_mab_monitor():
    g = guide({**PLAN, "mab": True})
    cli, name = g["cli"], wired.monitor_policy(P(mab=True))
    pol = policy_block(cli, name)
    assert "class-map type control subscriber match-all MAB_FAILED\n match method mab\n match result-type method mab authoritative" in cli
    assert "20 class DOT1X_NO_RESP do-until-failure\n   10 terminate dot1x\n   20 authenticate using mab priority 20" in pol
    assert "30 class MAB_FAILED do-until-failure\n   10 terminate mab\n   20 authentication-restart 300" in pol
    assert "event agent-found match-all\n  10 class always do-until-failure\n   10 terminate mab\n   20 authenticate using dot1x priority 10" in pol
    # A device that answers 802.1X and fails never gets MAB: only "no response" leads to it.
    assert pol.count("authenticate using mab") == 1 and "40 class always do-until-failure\n   10 terminate dot1x\n   20 terminate mab" in pol
    assert "authorize" not in pol.split("30 class MAB_FAILED")[1].split("40 class")[0], "monitor mode never authorizes unknown devices"
    assert " mab\n dot1x max-reauth-req 2" in cli and "access-session closed" not in cli
    assert f" service-policy type control subscriber {name}" in cli
    assert "MAB_FAILED" not in guide(PLAN)["cli"] and "\n mab\n" not in guide(PLAN)["cli"]


def test_ibns2_mab_enforce_unknown_devices():
    blocked = guide({**PLAN, "mab": True})["enforce_cli"]
    pol = policy_block(blocked, wired.closed_policy(P(mab=True)))
    assert "30 class MAB_FAILED do-until-failure\n   10 terminate mab\n   20 authentication-restart 300" in pol
    vlan = guide({**PLAN, "mab": True, "no_supplicant": "vlan", "no_supplicant_vlan": 99})["enforce_cli"]
    pol = policy_block(vlan, wired.closed_policy(P(mab=True, no_supplicant="vlan", no_supplicant_vlan=99)))
    assert "30 class MAB_FAILED do-until-failure\n   10 terminate mab\n   20 activate service-template EASYEAP_NO_8021X\n   30 authorize" in pol
    assert "service-template EASYEAP_NO_8021X\n vlan 99" in vlan and pol.count("authenticate using mab") == 1


def test_turning_mab_on_and_off_is_a_swap_in_monitor_mode():
    on = guide({**PLAN, "mab": True, "mode": "monitor", "last_change": "mab", "policy_prev": wired.monitor_policy(P()),
                "policy": wired.monitor_policy(P(mab=True))})
    cli = on["mab_cli"]
    assert cli and on["mab"] is True
    assert f" no service-policy type control subscriber {wired.monitor_policy(P())}" in cli
    assert f" service-policy type control subscriber {wired.monitor_policy(P(mab=True))}\n mab\n dot1x max-reauth-req 2" in cli
    assert f"no policy-map type control subscriber {wired.monitor_policy(P())}" in cli and "MAB_FAILED" in cli and "access-session closed" not in cli
    off = guide({**PLAN, "mab": False, "mode": "monitor", "last_change": "mab"})["mab_cli"]
    assert f" no service-policy type control subscriber {wired.monitor_policy(P(mab=True))}" in off and " no mab\n no dot1x max-reauth-req" in off
    assert guide({**PLAN, "mab": True, "mode": "monitor", "last_change": "created"})["mab_cli"] is None


def test_classic_mab():
    g = guide({**PLAN, "platform": "classic", "mab": True, "last_change": "mab", "mode": "monitor"})
    for line in (" authentication order dot1x mab", " authentication priority dot1x mab", " mab", " dot1x max-reauth-req 2", " authentication timer restart 300"):
        assert line + "\n" in g["cli"] and line + "\n" in g["mab_cli"]
    assert "authentication event fail" not in g["cli"] + g["enforce_cli"], "an 802.1X failure must not move on to MAB"
    off = guide({**PLAN, "platform": "classic", "mab": False, "last_change": "mab", "mode": "monitor"})["mab_cli"]
    assert " no authentication order\n no authentication priority\n no mab" in off and off.rstrip().endswith("clear authentication sessions")


def test_mab_checks_and_unifi_steps():
    assert any("MAC allow list" in x for x in guide({**PLAN, "mab": True})["checks"])
    assert any("turn on MAC authentication" in x for x in guide(PLAN)["checks"])
    u = guide({"mab": True, "last_change": "mab", "mode": "monitor"}, vendor="unifi")
    assert any("MAC-Based" in x for x in u["steps"]) and u["mab_steps"] and any("MAC-Based" in x for x in u["checks"])
    assert wired.validate_profile("other", {"mab": True})["mab"] is False


def test_client_mab_mode():
    c = lambda vendor, mab_on, networks=("wired",): SimpleNamespace(vendor=vendor, networks=list(networks), wired_profile={"mab": mab_on})  # noqa: E731
    assert mab_mode(c("cisco-switch", True)) == "pap" and mab_mode(c("unifi", True)) == "eap"
    assert mab_mode(c("cisco-switch", False)) == "no" and mab_mode(c("other", True)) == "no" and mab_mode(c("unifi", True, ("wireless",))) == "no"


def test_reasons_explained():
    for code in ("mab_not_enabled", "mab_mismatch", "mab_password", "mac_unknown", "mac_disabled", "mac_expired", "mac_group_disabled"):
        assert EXPLANATIONS[code]["title"] and EXPLANATIONS[code]["fix"]
    ts = (ROOT / "frontend" / "src" / "domain" / "explain.ts")
    if ts.exists():
        text = ts.read_text()
        for code in ("mab_not_enabled", "mac_unknown", "mac_group_disabled"):
            assert f"{code}:" in text, f"{code} missing from the console's explanations"


# ── FreeRADIUS rendering ─────────────────────────────────────────────────────

RTENANT = {"id": "11111111-2222-3333-4444-555555555555", "slug": "corp", "name": "Corp", "auth_port": 1812, "acct_port": 1813, "dedicated_ports": False,
           "tls_min_version": "1.2", "tls_session_cache": False, "session_timeout": 28800, "server_cert_pem": "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----",
           "server_key_pem": "-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----", "ca_pem": "-----BEGIN CERTIFICATE-----\nBB\n-----END CERTIFICATE-----\n",
           "crl_pem": "-----BEGIN X509 CRL-----\nCC\n-----END X509 CRL-----\n",
           "clients": [{"id": "aaaaaaaa-0000-0000-0000-000000000001", "name": "Access 1", "vendor": "cisco-switch", "address": "10.0.0.11", "secret": "s",
                        "networks": ["wired"], "mab": "pap"},
                       {"id": "aaaaaaaa-0000-0000-0000-000000000002", "name": "UniFi", "vendor": "unifi", "address": "10.0.1.0/24", "secret": "s",
                        "networks": ["wireless", "wired"], "mab": "eap"},
                       {"id": "aaaaaaaa-0000-0000-0000-000000000003", "name": "Odd", "vendor": "other", "address": "10.0.2.1", "secret": "s", "mab": "yes; x"},
                       {"id": "aaaaaaaa-0000-0000-0000-000000000004", "name": "Old API", "vendor": "cisco-switch", "address": "10.0.2.2", "secret": "s"}]}


def test_render_mab(tmp_path):
    render = _load("render")
    render.render({"version": "x", "tenants": [RTENANT]}, tmp_path, "/state")
    s = render.short(RTENANT["id"])
    clients = (tmp_path / "clients.conf").read_text()
    assert clients.count('easyeap_mab = "pap"') == 1 and clients.count('easyeap_mab = "eap"') == 1 and clients.count('easyeap_mab = "no"') == 2
    md5 = (tmp_path / "mods-enabled" / f"eapmd5_{s}").read_text()
    assert "default_eap_type = md5" in md5 and "tls" not in md5
    eap = (tmp_path / "mods-enabled" / f"eap_{s}").read_text()
    assert "md5" not in eap.lower(), "certificates stay EAP-TLS only"
    main = (tmp_path / "sites-enabled" / f"t_{s}").read_text()
    assert "mab_unsupported" not in main and "mab_not_enabled" in main
    # MAB needs the client to allow it and evidence of a switch port.
    assert '("%{client:easyeap_mab}" == "pap") && &NAS-Port-Type && (&NAS-Port-Type == Ethernet)' in main
    assert '("%{client:easyeap_mab}" == "eap") && (&control:EasyEAP-Network == "wired")' in main
    # Every MAC lookup is keyed on the normalised identity only, for this tenant, current MAC version only.
    lookups = re.findall(r"%\{authz:SELECT[^\n]*authz_mac[^\n]*", main)
    assert len(lookups) == 1 and f"a.tenant = '{RTENANT['id']}' AND a.mac = '%{{control:EasyEAP-Mac}}'" in lookups[0]
    assert "m.version = a.version" in lookups[0] and "a.expires_at <= %l" in lookups[0]
    assert "%{User-Name}" not in lookups[0] and "Calling-Station-Id" not in lookups[0]
    for reason in ("mab_mismatch", "mab_password", "snapshot_stale", "mac_unknown", "mac_expired"):
        assert f'&EasyEAP-Reason := "{reason}"' in main
    assert re.search(r"authenticate \{\n\t\teap_\w+\n\t\teapmd5_\w+\n\t\}", main)
    assert 'if (&control:EasyEAP-Method == "mab-eap") {\n\t\t\t\teapmd5_' in main, "an EAP-MD5 refusal ends with EAP-Failure from its own module"
    # The VLAN goes on the Access-Accept in post-auth, withheld in monitor mode.
    post = main.split("post-auth {", 1)[1]
    assert "!&control:EasyEAP-Monitor" in post.split("Tunnel-Private-Group-Id")[0]
    assert "Cleartext-Password := \"%{User-Name}\"" in main
    dictionary = (tmp_path / "dictionary").read_text()
    for a in ("EasyEAP-Method", "EasyEAP-Mac", "EasyEAP-MacDevice", "EasyEAP-MacGroup"):
        assert a in dictionary and f"&control:{a}" in render.AUTH_ATTRS


def test_mac_capture_matches_app_normalisation():
    render = _load("render")
    from app.mac import try_mac
    rx = re.compile(render.MAC_CAPTURE)
    for v in ("020000000a01", "02-00-00-00-0A-01", "02:00:00:00:0a:01", "0200.0000.0a01"):
        mt = rx.match(v)
        assert mt and "".join(mt.groups()).upper() == try_mac(v) == "020000000A01"
    for v in ("printer01", "020000000a0", "020000000a011", "02-00-00-00-0A-01:Corp"):
        assert not rx.match(v)


# ── The agent's MAC store ────────────────────────────────────────────────────


def _agent(tmp_path, monkeypatch):
    monkeypatch.setenv("EASYEAP_RADIUS_STATE", str(tmp_path))
    return _load("easyeap_agent")


def test_agent_applies_the_mac_part(tmp_path, monkeypatch):
    agent = _agent(tmp_path, monkeypatch)
    conn = agent.db(tmp_path / "authz.db")
    tid = "t1"
    now = int(time.time())
    base = {"tenant_id": tid, "version": 1, "built_at": now, "valid_until": now + 60, "entries": []}
    agent.apply_snapshot(conn, {**base, "mac_version": 7, "mac_entries": [
        {"mac": "020000000A01", "outcome": "allow", "reason": None, "vlan": 120, "device_id": "d1", "group_id": "g1", "expires_at": None},
        {"mac": "020000000A05", "outcome": "allow", "reason": None, "vlan": None, "device_id": "d5", "group_id": "g2", "expires_at": now + 5},
        {"mac": "02000000a002", "outcome": "allow", "vlan": 1},  # lowercase: not canonical, refused
        {"mac": "020000000A03", "outcome": "maybe", "vlan": 1},
    ]})
    rows = conn.execute("SELECT mac, version, outcome, vlan, expires_at FROM authz_mac ORDER BY mac").fetchall()
    assert rows == [("020000000A01", 7, "allow", "120", None), ("020000000A05", 7, "allow", "", now + 5)]
    assert agent.applied_mac_versions(conn) == {tid: 7}
    # An unchanged certificate snapshot without a MAC part leaves the MAC store alone.
    agent.apply_snapshot(conn, {**base, "unchanged": True, "mac_version": 7})
    assert conn.execute("SELECT COUNT(*) FROM authz_mac").fetchone()[0] == 2
    # A new MAC version replaces the tenant's rows, even with an unchanged certificate snapshot.
    agent.apply_snapshot(conn, {**base, "unchanged": True, "mac_version": 8, "mac_entries": []})
    assert conn.execute("SELECT COUNT(*) FROM authz_mac").fetchone()[0] == 0 and agent.applied_mac_versions(conn) == {tid: 8}
    agent.drop_removed_tenants(conn, [])
    assert agent.applied_mac_versions(conn) == {}


def test_agent_store_from_an_older_agent_gains_mac_tables(tmp_path, monkeypatch):
    path = tmp_path / "authz.db"
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE meta (tenant TEXT PRIMARY KEY, version INTEGER NOT NULL, built_at INTEGER NOT NULL, valid_until INTEGER NOT NULL, "
                "applied_at INTEGER NOT NULL, digest TEXT)")
    old.commit()
    old.close()
    agent = _agent(tmp_path, monkeypatch)
    conn = agent.db(path)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"authz_mac", "meta_mac", "authz_wired"} <= names
    assert "mab" in agent.FEATURES and "coa-request" in agent.FEATURES


def test_agent_event_fields():
    agent = _load("easyeap_agent")
    rec = {"User-Name": "020000000a01", "control:EasyEAP-Method": "mab", "control:EasyEAP-Mac": "020000000A01",
           "control:EasyEAP-MacDevice": "d1", "control:EasyEAP-MacGroup": "g1", "Service-Type": "Call-Check", "Calling-Station-Id": "02-00-00-00-0A-01"}
    e = agent.transform("events", {"uid": "u", "ts": 1, "result": "accept", "rec": rec})
    assert (e["method"], e["device_mac"], e["mac_device"], e["mac_group"], e["service_type"]) == ("mab", "020000000A01", "d1", "g1", "Call-Check")
    assert agent.COA_KINDS["reauthenticate"][0] == "coa" and agent.COA_KINDS["disconnect"][0] == "disconnect"


# ── Ingest and snapshot helpers ──────────────────────────────────────────────


def test_event_mac_and_method():
    assert mab.event_mac({"device_mac": "020000000A01", "mac": "02-00-00-00-0A-99"}) == "020000000A01"
    assert mab.event_mac({"mac": "02-00-00-00-0a-99"}) == "020000000A99" and mab.event_mac({"mac": "garbage"}) is None
    assert mab.method_of({"method": "mab"}) == "mab" and mab.method_of({"method": "mab-eap"}) == "mab-eap" and mab.method_of({"method": "x"}) is None


def test_group_switch_vlan():
    import uuid
    v = uuid.uuid4()
    g = lambda **kw: SimpleNamespace(port_vlan=kw.get("port_vlan", False), vlan_ref=kw.get("vlan_ref"))  # noqa: E731
    assert mab.group_switch_vlan(g(vlan_ref=v), {v: 20}, {20: 120}) == 120
    assert mab.group_switch_vlan(g(vlan_ref=v), {v: 20}, {20: None}) is None, "the VLAN maps to the port's own on switch ports"
    assert mab.group_switch_vlan(g(port_vlan=True), {v: 20}, {}) is None and mab.group_switch_vlan(g(vlan_ref=v), {v: 20}, {}) == 20


def test_switch_from_before_named_policies():
    """Migration 0005 records EASYEAP_MONITOR / EASYEAP_CLOSED for switches configured by the first wired build."""
    enf = guide({**PLAN, "mode": "monitor", "policy": "EASYEAP_MONITOR"})["enforce_cli"]
    assert " no service-policy type control subscriber EASYEAP_MONITOR\n" in enf and enf.count("no policy-map type control subscriber EASYEAP_MONITOR\n") == 1
    mon = guide({**PLAN, "mode": "enforce", "policy": "EASYEAP_CLOSED"})["monitor_cli"]
    assert " no service-policy type control subscriber EASYEAP_CLOSED\n" in mon
    mig = (Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0005_mac_auth.py").read_text()
    assert "'EASYEAP_CLOSED' ELSE 'EASYEAP_MONITOR'" in mig and "NOT wired_profile ? 'policy'" in mig
