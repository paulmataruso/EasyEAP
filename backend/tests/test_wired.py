"""Wired 802.1X: port plans, the generated switch configuration, readiness parsing, VLAN mapping, wired enrollment
profiles and client attribution. No database or OpenBao."""
import importlib.util
import plistlib
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from app import models as m
from app.enrollment import profiles
from app.policy.service import wired_vlan
from app.radius import wired
from app.radius.events import _match_client, _ssid
from app.radius.explain import EXPLANATIONS
from app.radius.guides import SECRET_PLACEHOLDER


def _self_signed(cn="Test Root"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(0x00ABCDEF)
            .not_valid_before(now).not_valid_after(now.replace(year=now.year + 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    return key, cert.public_bytes(serialization.Encoding.PEM).decode()


TENANT = SimpleNamespace(slug="corp", name="Corp")
SETTINGS = SimpleNamespace(dedicated_ports=False, auth_port=1812, acct_port=1813)
PLAN = {"interfaces": "Gi1/0/1-24, GigabitEthernet2/0/1 - 48", "exclude": "Gi1/0/48, Te1/1/1"}


def switch(**kw) -> SimpleNamespace:
    return SimpleNamespace(name=kw.pop("name", "Floor 2"), **kw)


def guide(profile: dict, vendor: str = "cisco-switch", vlans=()) -> dict:
    p = wired.validate_profile(vendor, profile)
    return wired.guide(vendor, client=switch(), profile=p, settings=SETTINGS, radius_ip="10.9.9.9", vlans=list(vlans), tenant=TENANT)


# ── Port plans ───────────────────────────────────────────────────────────────


def test_ports_parse_and_normalise():
    r = wired.parse_ports("gi1/0/1-24, Te1/1/3;Fa0/5")
    assert wired.ranges_text(r) == "GigabitEthernet1/0/1 - 24, TenGigabitEthernet1/1/3, FastEthernet0/5"
    assert sum(len(x.ports()) for x in r) == 26


@pytest.mark.parametrize("text, words", [
    ("Port-channel1", "port channel"), ("Vlan10", "VLAN interface"), ("Gi0/0", "management port"), ("AppGigabitEthernet1/0/1", "application hosting"),
    ("Lo0", "loopback"), ("Gi1/0/24-1", "ends before"), ("Gi1/0/1; shutdown", "isn't an interface"), ("Gi1/0/1\nend\nreload", "isn't an interface"),
    ("Serial0/0/0", "doesn't know"), ("Gi1/0/1-24 description x", "isn't an interface"),
])
def test_ports_refused(text, words):
    with pytest.raises(wired.WiredConfigError) as e:
        wired.parse_ports(text)
    assert words in str(e.value)


def test_too_many_ports():
    with pytest.raises(wired.WiredConfigError, match="at most"):
        wired.parse_ports(", ".join(f"Gi{n}/0/1-100" for n in range(1, 30)))


def test_access_ports_required_and_left_alone_ports_skipped():
    with pytest.raises(wired.WiredConfigError) as e:
        wired.validate_profile("cisco-switch", {"interfaces": ""})
    assert e.value.field == "interfaces"
    # A port in both lists is left alone: the uplink inside "1-48", an AP in the middle of a range.
    p = wired.validate_profile("cisco-switch", {"interfaces": "Gi1/0/1-48, Gi2/0/1-4", "exclude": "GigabitEthernet1/0/48, Gi1/0/10, Te1/1/1"})
    assert p["interfaces"] == "GigabitEthernet1/0/1 - 48, GigabitEthernet2/0/1 - 4"  # kept as entered (normalised)
    assert [r.text() for r in wired.access_ranges(p["interfaces"], p["exclude"])] == [
        "GigabitEthernet1/0/1 - 9", "GigabitEthernet1/0/11 - 47", "GigabitEthernet2/0/1 - 4"]
    with pytest.raises(wired.WiredConfigError) as e:
        wired.validate_profile("cisco-switch", {"interfaces": "Gi1/0/1-2", "exclude": "Gi1/0/1, GigabitEthernet1/0/2"})
    assert e.value.field == "exclude"


@pytest.mark.parametrize("field, value", [("source_interface", "Vlan10\naaa new-model"), ("source_interface", "Vlan10 ; x"), ("vrf", "Mgmt vrf"),
                                          ("vrf", "a\nb"), ("access_vlan", 5000), ("mode", "open"), ("host_mode", "multi-domain")])
def test_profile_values_validated(field, value):
    with pytest.raises(ValidationError):
        wired.validate_profile("cisco-switch", {**PLAN, field: value})


def test_fallback_choices_need_their_vlan():
    with pytest.raises(ValidationError, match=r"devices without 802\.1X"):
        wired.validate_profile("cisco-switch", {**PLAN, "no_supplicant": "vlan"})
    with pytest.raises(ValidationError, match="unreachable"):
        wired.validate_profile("cisco-switch", {**PLAN, "server_down": "vlan"})


def test_unifi_plan_needs_no_ports():
    assert wired.validate_profile("unifi", {"fallback_vlan": 20})["fallback_vlan"] == 20


# ── Generated Cisco configuration ────────────────────────────────────────────


def lines(text: str) -> list[str]:
    return [x for x in text.splitlines() if x.strip() and not x.lstrip().startswith("!")]


def test_ibns2_monitor_is_passive_and_safe():
    g = guide(PLAN)
    cli = g["cli"]
    assert g["mode"] == "monitor" and g["preflight"] and g["safe_paste"][0].startswith("In exec mode: reload in 15")
    assert SECRET_PLACEHOLDER in cli and "10.9.9.9" in cli
    # Open ports, no fallback actions, connected devices kept while EasyEAP is unreachable.
    assert "access-session closed" not in cli and "DOT1X_NO_RESP do-until-failure" not in cli and "AAA_SVR_DOWN_UNAUTHD_HOST do-until-failure" not in cli
    assert "5 class AAA_SVR_DOWN_AUTHD_HOST do-until-failure" in cli and "authentication-restart 300" in cli
    assert "service-policy type control subscriber EASYEAP_MONITOR" in cli and " restrict" in cli
    # No MAB, no dead-server probe (EasyEAP drops requests without Message-Authenticator).
    assert "mab" not in cli.lower() and "automate-tester" not in cli
    assert "deadtime 3" in cli and "radius-server dead-criteria time 5 tries 3" in cli and "aaa accounting identity default" in cli
    # AAA is switched on for a switch that doesn't use it, with local logins kept; existing lists are never touched.
    assert "aaa new-model" in cli and "aaa authentication login default local" in cli
    assert "aaa new-model" not in guide({**PLAN, "has_aaa": True})["cli"].replace("doesn't use AAA", "")
    assert "aaa authentication login" not in guide({**PLAN, "has_aaa": True})["cli"]
    # Only the listed ports are configured; the left-alone ones are named in a comment only.
    assert "interface range GigabitEthernet1/0/1 - 24, GigabitEthernet2/0/1 - 48" in cli
    assert not any("TenGigabitEthernet1/1/1" in x for x in lines(cli))
    assert cli.rstrip().endswith("end")


def test_source_interface_and_vrf_stay_inside_the_group():
    cli = guide({**PLAN, "source_interface": "Vlan10", "vrf": "Mgmt-vrf"})["cli"]
    assert " ip radius source-interface Vlan10" in cli and " ip vrf forwarding Mgmt-vrf" in cli
    assert "\nip radius source-interface" not in cli, "a global source-interface would move other RADIUS traffic"
    assert f"client 10.9.9.9 vrf Mgmt-vrf server-key 0 {SECRET_PLACEHOLDER}" in cli
    assert any(p["command"] == "ping vrf Mgmt-vrf 10.9.9.9 source Vlan10" for p in guide({**PLAN, "source_interface": "Vlan10", "vrf": "Mgmt-vrf"})["preflight"])


def test_interface_range_lines_hold_at_most_five_ranges():
    plan = {"interfaces": ", ".join(f"Gi{n}/0/1-4" for n in range(1, 8))}
    cli = guide(plan)["cli"]
    ranges = [x for x in cli.splitlines() if x.startswith("interface range")]
    assert len(ranges) == 2 and all(x.count(",") <= 4 for x in ranges)


def test_ibns2_enforce_and_back():
    g = guide({**PLAN, "no_supplicant": "vlan", "no_supplicant_vlan": 99, "server_down": "vlan", "server_down_vlan": 98})
    enf, mon = g["enforce_cli"], g["monitor_cli"]
    assert "access-session closed" in enf and "service-policy type control subscriber EASYEAP_CLOSED" in enf
    assert "no service-policy type control subscriber EASYEAP_MONITOR" in enf and "clear access-session" in enf
    assert "service-template EASYEAP_NO_8021X\n vlan 99" in enf and "service-template EASYEAP_CRITICAL\n vlan 98" in enf
    assert "dot1x critical eapol" in enf and "20 class DOT1X_NO_RESP do-until-failure" in enf
    # The critical template exists only after Enforce defines it, so only then do the critical classes name it.
    assert "EASYEAP_CRITICAL" not in g["cli"]
    assert enf.index("service-template EASYEAP_CRITICAL") < enf.index("match activated-service-template EASYEAP_CRITICAL")
    assert "no access-session closed" in mon and "service-policy type control subscriber EASYEAP_MONITOR" in mon


def test_default_enforce_waits_for_easyeap_but_keeps_connected_devices():
    enf = guide(PLAN)["enforce_cli"]
    assert "AAA_SVR_DOWN_UNAUTHD_HOST do-until-failure" not in enf and "dot1x critical eapol" not in enf
    assert "AAA_SVR_DOWN_AUTHD_HOST do-until-failure" in enf and "DOT1X_NO_RESP do-until-failure" not in enf


def test_classic_configuration():
    g = guide({**PLAN, "platform": "classic", "server_down": "open", "no_supplicant": "vlan", "no_supplicant_vlan": 99})
    cli, enf, mon = g["cli"], g["enforce_cli"], g["monitor_cli"]
    assert "aaa accounting dot1x default start-stop group EASYEAP" in cli and "policy-map" not in cli and "access-session" not in cli
    assert " authentication open" in cli and " authentication violation restrict" in cli and "violation shutdown" not in cli
    assert "event server dead" not in cli and "no-response" not in cli, "monitor mode has no fallback actions"
    assert " no authentication open" in enf and " authentication event server dead action authorize" in enf
    assert " authentication event no-response action authorize vlan 99" in enf and "clear authentication sessions" in enf
    # Back to monitor removes exactly what Enforce added.
    assert " authentication open" in mon and " no authentication event no-response action authorize vlan 99" in mon
    assert " no authentication event server dead action authorize" in mon
    assert g["session_command"] == "show authentication sessions"


def test_vlan_checks_name_what_switch_ports_get():
    vlans = [SimpleNamespace(vlan_id=20, wired_mode="same", wired_vlan_id=None), SimpleNamespace(vlan_id=30, wired_mode="vlan", wired_vlan_id=130),
             SimpleNamespace(vlan_id=40, wired_mode="port", wired_vlan_id=None)]
    checks = " ".join(guide(PLAN, vlans=vlans)["checks"])
    assert "VLAN 20, 130" in checks and "40" not in checks.split("VLAN 20, 130")[1].split(".")[0]


def test_unifi_and_other_guides():
    u = guide({"fallback_vlan": 20}, vendor="unifi")
    assert u["cli"] is None and any("ONE test port" in x for x in u["steps"]) and any("Fallback VLAN = 20" in x for x in u["steps"])
    assert any("Not verified on UniFi hardware" in x for x in u["checks"]) and u["enforce_steps"]
    o = guide({}, vendor="other")
    assert any("NAS-Port-Type" in x for x in o["steps"])


# ── Readiness: pasted session lists ──────────────────────────────────────────

IBNS2_SESSIONS = """switch#show access-session
Interface                MAC Address    Method  Domain  Status Fg  Session ID
--------------------------------------------------------------------------------------------
Gi1/0/1                  0050.5690.1234 dot1x   DATA    Auth        0A0A0A0B000000123ABC0001
Gi1/0/2                  0050.5690.5678 dot1x   UNKNOWN Unauth      0A0A0A0B000000123ABC0002
Gi1/0/3                  aabb.cc00.0101 dot1x   DATA    Auth        0A0A0A0B000000123ABC0003

Session count = 3

Key to Session Events Blocked Status Flags:
  A - Applying Policy (multi-line status for details)
"""
CLASSIC_SESSIONS = """Interface  MAC Address     Method   Domain   Status         Session ID
Gi1/0/5    0050.5690.aaaa  dot1x    DATA     Authz Success  0A01010100000F2A01B2C3D4
Gi1/0/6    0050.5690.bbbb  dot1x    UNKNOWN  Running        0A01010100000F2B01B2C3D5
Gi1/0/7    (unknown)       dot1x    UNKNOWN  Authz Failed   0A01010100000F2C01B2C3D6
"""


def test_parse_access_sessions():
    rows = wired.parse_sessions(IBNS2_SESSIONS)
    assert [(r["interface"], r["authorized"]) for r in rows] == [("Gi1/0/1", True), ("Gi1/0/2", False), ("Gi1/0/3", True)]
    rows = wired.parse_sessions(CLASSIC_SESSIONS)
    assert [(r["interface"], r["status"], r["authorized"]) for r in rows] == [
        ("Gi1/0/5", "Authz Success", True), ("Gi1/0/6", "Running", False), ("Gi1/0/7", "Authz Failed", False)]
    assert wired.parse_sessions("random text\nswitch#") == []


# ── Policy: VLANs on switch ports ────────────────────────────────────────────


def test_wired_vlan_mapping():
    mapping = {20: 20, 30: 130, 40: None}
    assert wired_vlan(mapping, "allow", 20) == 20
    assert wired_vlan(mapping, "allow", 30) == 130
    assert wired_vlan(mapping, "allow", 40) is None, "the port keeps its own VLAN"
    assert wired_vlan(mapping, "allow", 50) == 50, "a VLAN ID without a record passes through, as before wired 802.1X"
    assert wired_vlan(mapping, "allow", None) is None and wired_vlan(mapping, "deny", 20) is None


# ── Events and attribution ───────────────────────────────────────────────────


def test_longest_prefix_attribution():
    unifi = m.RadiusClient(id=uuid.uuid4(), name="UniFi", address="10.1.0.0/24")
    sw = m.RadiusClient(id=uuid.uuid4(), name="Switch", address="10.1.0.20")
    for order in ([unifi, sw], [sw, unifi]):
        assert _match_client(order, "10.1.0.20") is sw
        assert _match_client(order, "10.1.0.21") is unifi
    assert _match_client([unifi], "10.2.0.1") is None


def test_ssid_from_called_station_matches_the_renderer():
    assert _ssid("00-11-22-33-44-55:Corp") == "Corp"
    assert _ssid("00-11-22-33-44-55:") is None and _ssid("00-11-22-33-44-55") is None


def test_render_detection_regex_agrees_with_events():
    root = Path(__file__).resolve().parents[2] / "services" / "radius" / "agent" / "render.py"
    spec = importlib.util.spec_from_file_location("render_wired", root)
    render = importlib.util.module_from_spec(spec)
    sys.modules["render_wired"] = render
    spec.loader.exec_module(render)
    ssid_re, wired_re = re.compile(f"^{render.MAC_RE}:.+$"), re.compile(f"^{render.MAC_RE}:$")
    for called in ("00-11-22-33-44-55:Corp", "001122334455:Guest Wi-Fi", "00:11:22:33:44:55:x"):
        assert ssid_re.match(called) and _ssid(called)
    for called in ("00-11-22-33-44-55:", "0011.2233.4455:"):
        assert wired_re.match(called) and not _ssid(called)


def test_new_reasons_are_explained():
    for code in ("network_not_enabled", "network_unknown", "mab_unsupported"):
        assert EXPLANATIONS[code]["title"] and EXPLANATIONS[code]["fix"]


# ── Enrollment profiles ──────────────────────────────────────────────────────


def test_windows_lan_profile():
    _, root = _self_signed()
    xml = profiles.windows_lan_xml("radius.corp.example", root)
    tree = ET.fromstring(xml)  # noqa: S314 — our own output
    ns = {"l": "http://www.microsoft.com/networking/LAN/profile/v1"}
    assert tree.find("l:MSM/l:security/l:OneXEnforced", ns).text == "false"
    assert tree.find("l:MSM/l:security/l:OneXEnabled", ns).text == "true"
    assert "<ServerNames>radius.corp.example</ServerNames>" in xml and "<TrustedRootCA>" in xml
    # The Wi-Fi profile is unchanged by sharing the EAP section.
    wlan = profiles.windows_wlan_xml("Corp", "radius.corp.example", root)
    ET.fromstring(wlan)  # noqa: S314 — our own output
    assert wlan.count("<EAPConfig>") == 1 and "</EAPConfig>\n    </OneX>" in wlan


def test_windows_wired_script():
    _, root = _self_signed()
    ps = profiles.windows_wired_script("radius.corp.example", root, root, "Corp")
    assert "#Requires -RunAsAdministrator" in ps and "dot3svc" in ps and "netsh lan add profile" in ps
    assert "Cert:\\LocalMachine\\Root" in ps and "BEGIN PRIVATE KEY" not in ps and "<LANProfile" in ps


def test_mac_profile_adds_ethernet_only_when_asked():
    _, root = _self_signed()
    kw = {"ssid": "Corp", "server_name": "radius.corp.example", "root_pem": root, "issuing_pem": root, "org": "Corp", "tenant_slug": "corp",
          "identity_label": "alice", "pkcs12_b64": "AAAA"}
    plain = plistlib.loads(profiles.apple_mobileconfig(**kw))
    assert all(p["PayloadType"] != "com.apple.globalethernet.managed" for p in plain["PayloadContent"])
    both = plistlib.loads(profiles.apple_mobileconfig(**kw, wired=True))
    eth = next(p for p in both["PayloadContent"] if p["PayloadType"] == "com.apple.globalethernet.managed")
    p12 = next(p for p in both["PayloadContent"] if p["PayloadType"] == "com.apple.security.pkcs12")
    assert eth["PayloadCertificateUUID"] == p12["PayloadUUID"] and eth["EAPClientConfiguration"]["TLSTrustedServerNames"] == ["radius.corp.example"]
    assert eth["EAPClientConfiguration"]["AcceptEAPTypes"] == [13] and "wired" in both["PayloadDisplayName"]


def test_linux_wired_profiles():
    nm = profiles.networkmanager_wired("radius.corp.example", "alice@corp")
    assert "type=ethernet" in nm and "optional=true" in nm and "domain-suffix-match=radius.corp.example" in nm
    wpa = profiles.wpa_supplicant_wired("radius.corp.example", "alice@corp")
    assert "key_mgmt=IEEE8021X" in wpa and "ap_scan=0" in wpa and "-D wired" in wpa


def test_instructions_mention_wired_only_when_enabled():
    assert not any("802.1X" in x for x in profiles.instructions("macos", "Corp", "r"))
    assert any("Network ports" in x for x in profiles.instructions("macos", "Corp", "r", wired=True))
    assert not any("Network ports" in x for x in profiles.instructions("ios", "Corp", "r", wired=True))
    assert any("IT team" in x for x in profiles.instructions("windows", "Corp", "r", wired=True))


@pytest.mark.parametrize("platform", ["ibns2", "classic"])
def test_left_alone_ports_never_configured(platform):
    plan = {"platform": platform, "interfaces": "Gi1/0/1-48", "exclude": "Gi1/0/48, Gi1/0/24"}
    for g in (guide(plan), guide({**plan, "mode": "enforce"})):
        for cli in (g["cli"], g.get("enforce_cli") or "", g.get("monitor_cli") or ""):
            for line in cli.splitlines():
                if line.startswith("interface range"):
                    assert line == "interface range GigabitEthernet1/0/1 - 23, GigabitEthernet1/0/25 - 47", line


def test_config_sync_tells_when_a_change_is_live():
    from app.routers.radius import config_sync
    tid, rs = uuid.uuid4(), SimpleNamespace(config_version=7)
    assert config_sync({"detail": {"config_versions": {str(tid): 7}}}, tid, rs) == {"tenant_config_applied": 7, "tenant_config_in_sync": True}
    assert config_sync({"detail": {"config_versions": {str(tid): 6}}}, tid, rs)["tenant_config_in_sync"] is False
    assert config_sync({"detail": {"config_versions": {}}}, tid, rs)["tenant_config_in_sync"] is False  # not served yet
    assert config_sync({"detail": {"tenant_ids": [str(tid)]}}, tid, rs)["tenant_config_in_sync"] is None  # an older agent


def test_group_policy_guide_has_the_tenants_values_and_no_secrets():
    _, root = _self_signed("Corp Root CA")
    _, issuing = _self_signed("Corp Issuing CA")
    g = profiles.group_policy_guide(server_name="radius.corp.example", ssid="CorpNet", wpa3=True, root_pem=root, issuing_pem=issuing, slug="corp")
    text = "\n".join(s for sec in g["sections"] for s in sec["steps"])
    assert g["root_cn"] == "Corp Root CA" and g["issuing_cn"] == "Corp Issuing CA" and len(g["root_thumbprint"].split()) == 20
    assert "radius.corp.example" in text and "CorpNet" in text and g["root_thumbprint"] in text
    assert "Wired AutoConfig" in text and "NTAuth" in text and "Don't prompt user" in text and "WPA3-Enterprise" in text
    names = [f["name"] for f in g["files"]]
    assert names == ["corp-root.cer", "corp-issuing.cer", "corp-wifi.xml", "corp-wired.xml"]
    wifi = g["files"][2]["content"]
    assert "<authentication>WPA3ENT</authentication>" in wifi and "<ServerNames>radius.corp.example</ServerNames>" in wifi
    assert "PRIVATE KEY" not in str(g)
    # The documentation mirrors the console's steps.
    doc = Path(__file__).resolve().parents[2] / "docs" / "windows-group-policy.md"
    if doc.exists():
        body = doc.read_text()
        for sec in g["sections"]:
            assert sec["title"] in body, f"docs/windows-group-policy.md lacks the section {sec['title']}"
