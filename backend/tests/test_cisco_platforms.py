"""Every Cisco switch family (docs/plans/cisco-platforms.md): recognising a switch from `show version`, what each family
and release can do, the 802.1X configuration for Nexus, Cisco Business, Meraki and pre-authentication-manager IOS, the
port-plan refusals, the switch audit's blocks, syslog from NX-OS and Cisco Business, and admin logins on NX-OS and
Cisco Business. No database or OpenBao."""
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.admin import cisco
from app.radius import cisco_platforms as cp
from app.radius import state, wired
from app.radius.guides import SECRET_PLACEHOLDER
from app.switchaudit import platforms, service
from app.switchaudit.syslog import kept, parse

TENANT = SimpleNamespace(slug="corp", name="Corp")
SETTINGS = SimpleNamespace(dedicated_ports=False, auth_port=1812, acct_port=1813)
ROOT = Path(__file__).resolve().parents[2]


def guide(profile: dict, vendor: str = "cisco-switch") -> dict:
    p = wired.validate_profile(vendor, profile)
    return wired.guide(vendor, client=SimpleNamespace(name="Floor 2"), profile=p, settings=SETTINGS, radius_ip="10.9.9.9", vlans=[], tenant=TENANT)


def refused(profile: dict, vendor: str = "cisco-switch") -> wired.WiredConfigError:
    with pytest.raises(wired.WiredConfigError) as exc:
        wired.validate_profile(vendor, profile)
    return exc.value


# ── show version ─────────────────────────────────────────────────────────────

XE_16 = """Cisco IOS XE Software, Version 16.06.01
Cisco IOS Software [Everest], Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 16.6.1, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
Model Number                       : WS-C3850-24P
"""
XE_3 = """Cisco IOS Software, IOS-XE Software, Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 03.06.06E RELEASE SOFTWARE (fc1)
"""
CLASSIC = """Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc3)
Model number                    : WS-C2960X-48FPD-L
"""
LAN_LITE = "Cisco IOS Software, C2960 Software (C2960-LANLITEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)\n"
OLD_122 = "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 12.2(44)SE6, RELEASE SOFTWARE (fc1)\n"
NEXUS_9K = """Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Software
  BIOS: version 07.69
  NXOS: version 9.3(8)
Hardware
  cisco Nexus9000 C93180YC-FX Chassis
"""
NEXUS_5K = """Cisco Nexus Operating System (NX-OS) Software
Software
  system:    version 7.3(8)N1(1)
Hardware
  cisco Nexus 5596 Chassis ("O2 48X10GE/Modular Supervisor")
"""
NEXUS_3600 = """Cisco Nexus Operating System (NX-OS) Software
  NXOS: version 9.3(9)
  cisco Nexus 3600 N3K-C36180YC-R Chassis
"""
CBS350 = """System Description:                       CBS350-24P-4G 24-Port Gigabit PoE Managed Switch
System Up Time (days,hour:min:sec):       03,02:11:49
Active-image: flash://system/images/image_cbs_ros_3.1.1.7_release_cisco_signed.bin
  Version: 3.1.1.7
"""


@pytest.mark.parametrize(("text", "platform", "series", "version", "model"), [
    (XE_16, "ibns2", "", "16.6.1", "WS-C3850-24P"),
    (XE_3, "ibns2", "", "03.06.06E", ""),
    (CLASSIC, "classic", "", "15.2(7)E3", "WS-C2960X-48FPD-L"),
    (OLD_122, "classic", "", "12.2(44)SE6", ""),
    (NEXUS_9K, "nxos", "n9k-fx", "9.3(8)", "Nexus9000 C93180YC-FX"),
    (NEXUS_5K, "nxos", "n5k", "7.3(8)N1(1)", "Nexus 5596"),
    (CBS350, "cbs", "sx350", "3.1.1.7", "CBS350-24P-4G"),
])
def test_detect(text, platform, series, version, model):
    d = cp.detect(text)
    assert (d.platform, d.series, d.version, d.model) == (platform, series, version, model)
    assert not d.unsupported and d.evidence


def test_detect_lan_lite_unsupported_and_unknown():
    assert cp.detect(LAN_LITE).lan_lite is True and cp.detect(CLASSIC).lan_lite is False
    n = cp.detect(NEXUS_3600)
    assert n.platform == "nxos" and n.unsupported and "3600" in n.unsupported
    assert cp.detect("Arista vEOS\nSoftware image version: 4.28").platform is None
    # A terminal that wrapped the banner line still reads.
    assert cp.detect(CLASSIC.replace(", Version", ",\n Version")).version == "15.2(7)E3"


# ── Releases ─────────────────────────────────────────────────────────────────


def test_classic_versions_compare_within_access_trains():
    assert cp.at_least("classic", "12.2(25)SEE4", "12.2(25)SEE") is True
    assert cp.at_least("classic", "12.2(25)SED", "12.2(25)SEE") is False
    assert cp.at_least("classic", "12.2(46)EX", "12.2(46)SE1") is True    # a parallel train of the same release
    assert cp.at_least("classic", "15.2(2)E9", "15.2(3)E") is False
    assert cp.at_least("classic", "15.1(2)SG", "15.0(2)SE") is None        # not an access-switch train: unknown
    assert cp.at_least("classic", "", "15.2(3)E") is None
    assert cp.at_least("ibns2", "03.06.06E", "16.0.0") is False and cp.at_least("ibns2", "17.9.4a", "16.0.0") is True
    assert cp.at_least("nxos", "7.0(3)I7(9)", "9.2(1)") is False and cp.at_least("nxos", "10.2(5)", "9.3(3)") is True
    assert cp.clean_version("15.2(7)E3; reload") == ""


# ── What each family and release can do ──────────────────────────────────────


def test_classic_releases():
    old = cp.caps("classic", version="12.2(44)SE6")
    assert (old.dialect, old.monitor, old.mab, old.coa, old.audit) == ("dot1x", "server", "pap", None, None)
    assert old.host_modes == ("multi-host", "single-host") and old.message_authenticator == "no"
    assert old.session_command == "show dot1x all summary" and old.violation is False and old.errdisable is False
    assert cp.caps("classic", version="12.2(25)SED").mab is None
    mid = cp.caps("classic", version="12.2(52)SE")
    assert mid.dialect == "authmgr" and mid.monitor == "switch" and mid.coa == "full" and mid.errdisable is True
    assert any("12.2(55)SE" in n for n in mid.notes)
    assert cp.caps("classic", version="15.2(2)E").named_radius is False
    assert cp.caps("classic", version="15.0(2)EX5").named_radius is True
    assert cp.caps("classic", version="15.2(7)E3").tacacs == "named" and cp.caps("classic", version="15.2(4)E").tacacs == "legacy"
    unknown = cp.caps("classic")
    assert unknown.tacacs == "toggle" and unknown.named_radius is True and unknown.warnings
    assert any("train" in w for w in cp.caps("classic", version="15.1(2)SG").warnings)
    lite = cp.caps("classic", version="15.2(7)E3", lan_lite=True)
    assert lite.server_down == ("wait",) and lite.coa is None


def test_iosxe_releases():
    new = cp.caps("ibns2", version="17.9.4a")
    assert new.attr31 and new.tacacs == "named" and not new.warnings
    xe3 = cp.caps("ibns2", version="3.6.6E")
    assert xe3.tacacs == "legacy-xe3" and xe3.attr31 is False and xe3.named_radius is True
    sg = cp.caps("ibns2", version="3.3.0SG")
    assert sg.named_radius is False and any("4500" in w for w in sg.warnings)
    assert cp.caps("ibns2").tacacs == "toggle"


def test_nexus_series():
    fx = cp.caps("nxos", "n9k-fx", "9.3(8)")
    assert fx.monitor == "server" and fx.mab == "pap-wired" and fx.message_authenticator == "no"
    assert fx.host_modes == cp.ALL_HOST_MODES and fx.radius_vlan and fx.coa == "no-bounce" and fx.errdisable
    assert fx.audit == "ports" and fx.tacacs == "nxos"
    old = cp.caps("nxos", "n9k-fx", "7.0(3)I7(9)")
    assert old.mab is None and old.monitor == "none" and old.host_modes == ("multi-host", "single-host")
    assert cp.caps("nxos", "n9k-fxp", "9.3(8)").coa is None
    assert cp.caps("nxos", "n9k", "10.4(1)").mab is None and cp.caps("nxos", "n9k", "10.5(2)").mab == "pap-wired"
    n3k = cp.caps("nxos", "n3k", "9.3(8)")
    assert not n3k.radius_vlan and n3k.coa is None and n3k.mab == "pap-wired" and not n3k.errdisable
    assert any("NX-OS 10" in w for w in cp.caps("nxos", "n3k", "10.2(5)").warnings)
    n5k = cp.caps("nxos", "n5k", "7.3(8)N1(1)")
    assert n5k.radius_vlan and n5k.no_supplicant_vlan
    assert any("7000" in n for n in cp.caps("nxos", "n7k", "8.4(7)").notes)


def test_cisco_business_series():
    assert cp.caps("cbs", "c1300", "4.1.3.36").coa == "full" and cp.caps("cbs", "c1300", "4.1.0.0").coa is None
    sx300 = cp.caps("cbs", "sx300", "1.4.11.5")
    assert sx300.mab == "eap" and sx300.tacacs == "sx-old" and sx300.monitor == "switch"
    c1200 = cp.caps("cbs", "c1200", "4.1.3.36")
    assert c1200.mab is None and c1200.monitor == "none" and not c1200.radius_vlan
    cbs220 = cp.caps("cbs", "cbs220")
    assert cbs220.dialect == "cbs220" and cbs220.monitor == "none" and cbs220.tacacs == "cbs220"
    sg200 = cp.caps("cbs", "sx200")
    assert sg200.dialect == "web" and sg200.audit is None and sg200.tacacs is None
    for s in cp.SERIES["cbs"]:
        c = cp.caps("cbs", s)
        assert c.message_authenticator == "no" and c.session_command is None and "vlan" not in c.server_down


def test_meraki():
    ms, open_ = cp.caps(None, "ms", vendor="meraki"), cp.caps(None, "ms-open", vendor="meraki")
    assert ms.monitor == "server" and open_.monitor == "switch"
    assert ms.mab == "pap-wired" and ms.coa is None and ms.tacacs is None and ms.audit is None and ms.message_authenticator == "no"
    assert cp.caps_for("unifi", {}) is None
    assert cp.describe("meraki", {"series": "ms-open"}).startswith("Meraki MS130")
    assert cp.describe("cisco-switch", {"platform": "nxos", "series": "n9k-fx", "version": "9.3(8)"}) == \
        "Nexus (NX-OS) · Nexus 9300-EX, -FX or -FX2 · 9.3(8)"


# ── Port plans: what each family refuses ──────────────────────────────────────


def test_plan_refusals():
    assert refused({"platform": "nxos", "interfaces": "Ethernet1/1-48"}).field == "series"
    assert refused({"platform": "nxos", "series": "n9k-fx", "interfaces": "Gi1/0/1-24"}).field == "interfaces"
    assert refused({"platform": "ibns2", "interfaces": "Ethernet1/1-48"}).field == "interfaces"
    assert refused({"platform": "nxos", "series": "n9k-fx", "version": "7.0(3)I7(9)", "interfaces": "Ethernet1/1-48",
                    "host_mode": "multi-auth"}).field == "host_mode"
    assert refused({"platform": "cbs", "series": "c1300", "interfaces": "gi1/0/1-24", "server_down": "vlan", "server_down_vlan": 99}).field == "server_down"
    assert refused({"platform": "nxos", "series": "n3k", "interfaces": "Ethernet1/1-48", "host_mode": "multi-host", "no_supplicant": "vlan",
                    "no_supplicant_vlan": 30}).field == "no_supplicant"
    assert refused({"platform": "classic", "version": "12.2(25)SED", "interfaces": "Fa0/1-24", "host_mode": "single-host"}).field == "version"
    assert refused({"platform": "classic", "version": "15.2(4)E", "interfaces": "Gi1/0/1-24", "no_supplicant": "vlan",
                    "no_supplicant_vlan": 30}).field == "no_supplicant"
    # A release from another family (kept from a family change): refused rather than compared as this family's.
    for platform, extra, version in (("classic", {}, "17.9.4a"), ("ibns2", {}, "15.2(7)E3"), ("nxos", {"series": "n9k-fx"}, "17.9.4"),
                                     ("cbs", {"series": "sx350"}, "9.3(8)")):
        ports = {"nxos": "Ethernet1/1-48", "cbs": "gi1/0/1-24"}.get(platform, "Gi1/0/1-24")
        e = refused({"platform": platform, **extra, "version": version, "interfaces": ports, "host_mode": "multi-host"})
        assert e.field == "version" and cp.VERSION_EXAMPLES[platform].split(" ")[0].rstrip(",") in str(e), (platform, str(e))
    for platform, version in (("classic", "12.2(55)SE12"), ("classic", "15.0(2)SG"), ("ibns2", "03.06.08E"), ("ibns2", "16.6.1"),
                              ("nxos", "7.0(3)I7(9)"), ("nxos", "6.0(2)N2(7)"), ("cbs", "3.1.1.7")):
        assert cp.version_fits(platform, version), (platform, version)


def test_plan_normalises_by_family():
    p = wired.validate_profile("cisco-switch", {"platform": "ibns2", "series": "n9k", "lan_lite": True, "interfaces": "Gi1/0/1-24"})
    assert p["series"] == "" and p["lan_lite"] is False
    # No open mode: MAC authentication is how EasyEAP monitors, so it's on whatever was asked.
    assert wired.validate_profile("cisco-switch", {"platform": "nxos", "series": "n9k-fx", "interfaces": "Ethernet1/1-48",
                                                   "host_mode": "multi-host"})["mab"] is True
    assert wired.validate_profile("cisco-switch", {"platform": "cbs", "series": "c1200", "interfaces": "gi1/0/1-24", "mab": True})["mab"] is False
    m = wired.validate_profile("meraki", {"series": "bogus", "interfaces": "Gi1/0/1", "platform": "nxos"})
    assert (m["series"], m["platform"], m["interfaces"], m["mab"]) == ("ms", "ibns2", "", True)


# ── 802.1X configuration per family ──────────────────────────────────────────


def test_nexus_configuration():
    g = guide({"platform": "nxos", "series": "n9k-fx", "version": "9.3(8)", "interfaces": "Ethernet1/1-48", "exclude": "Ethernet1/48",
               "host_mode": "multi-host"})
    cli = g["cli"]
    assert g["monitor_style"] == "server" and g["session_command"] == "show dot1x all summary" and g["mab"] is True
    assert "feature dot1x" in cli and f"radius-server host 10.9.9.9 key 0 {SECRET_PLACEHOLDER}" in cli
    assert "aaa authentication dot1x default group EASYEAP" in cli and "dot1x mac-auth-bypass" in cli
    assert "Ethernet1/48" not in cli.split("! Left alone")[-1].split("\n", 1)[-1]
    assert "authentication open" not in cli and "access-session" not in cli
    assert "dot1x re-authenticate" in g["enforce_cli"]
    assert g["capabilities"]["coa"] == "no-bounce"


def test_cisco_business_configuration():
    sx = guide({"platform": "cbs", "series": "sx350", "version": "3.1.1.7", "interfaces": "gi1/0/1-24", "mab": True})["cli"]
    assert "usage dot1.x" in sx and "authentication open" in sx and "dot1x host-mode multi-sessions" in sx
    assert "interface range gi1/0/1-24" in sx and "dot1x mac-auth radius" in sx and "dot1x authentication 802.1x mac" in sx
    assert "aaa authentication dot1x default radius none" in sx
    c220 = guide({"platform": "cbs", "series": "cbs220", "interfaces": "gi1/0/1-8"})
    assert "usg-type 802.1x" in c220["cli"] and "authentication open" not in c220["cli"] and c220["monitor_style"] == "none"
    web = guide({"platform": "cbs", "series": "sx200", "interfaces": "gi1/0/1-8"})
    assert web["cli"] is None and any("Security → RADIUS" in s for s in web["steps"])
    enforce = guide({"platform": "cbs", "series": "sx350", "interfaces": "gi1/0/1-24", "server_down": "wait"})["enforce_cli"]
    assert " no authentication open" in enforce and "aaa authentication dot1x default radius\n" in enforce + "\n"


def test_meraki_steps():
    g = guide({"series": "ms", "host_mode": "multi-auth"}, vendor="meraki")
    steps = " ".join(g["steps"])
    assert g["cli"] is None and g["coa_port"] == 1700 and g["monitor_style"] == "server"
    assert "RADIUS testing: off" in steps and "RADIUS CoA support: off" in steps and "Hybrid authentication" in steps
    assert "no critical VLAN with Multi-Auth" in steps
    open_ = guide({"series": "ms-open"}, vendor="meraki")
    assert any("Authentication mode: Open" in s for s in open_["steps"])
    assert any("Closed" in s for s in open_["enforce_steps"])
    assert open_["mab_steps"] is None
    on = guide({"series": "ms-open", "mab": True, "last_change": "mab"}, vendor="meraki")
    assert "Access policy type: Hybrid authentication" in on["mab_steps"][0]
    off = guide({"series": "ms-open", "mab": False, "last_change": "mab"}, vendor="meraki")
    assert "Access policy type: 802.1X" in off["mab_steps"][0]


def test_classic_named_server_uses_global_dead_time_and_source():
    g = guide({"platform": "classic", "version": "15.2(7)E3", "interfaces": "Gi1/0/1-24", "source_interface": "Vlan10"})
    assert "radius server EasyEAP" in g["cli"] or "radius server " in g["cli"]
    assert "\nradius-server deadtime 3\n" in g["cli"] and "\nip radius source-interface Vlan10\n" in g["cli"]
    assert "\n deadtime 3" not in g["cli"] and "\n ip radius source-interface" not in g["cli"]
    xe = guide({"platform": "ibns2", "version": "17.9.4", "interfaces": "Gi1/0/1-24", "source_interface": "Vlan10"})
    assert "\n deadtime 3" in xe["cli"] and "\n ip radius source-interface Vlan10" in xe["cli"]


def test_iosxe_converts_to_new_style_before_the_paste():
    xe = guide({"platform": "ibns2", "version": "16.6.1", "interfaces": "Gi1/0/1-24"})
    assert "authentication convert-to new-style" in xe["safe_paste"][1] and xe["safe_paste"][0].startswith("In exec mode: reload in 15")
    classic = guide({"platform": "classic", "version": "15.2(7)E3", "interfaces": "Gi1/0/1-24"})
    assert not any("new-style" in step for step in classic["safe_paste"])


def test_cbs220_waits_while_easyeap_is_unreachable():
    assert cp.caps("cbs", "cbs220").server_down == ("wait",)
    assert refused({"platform": "cbs", "series": "cbs220", "interfaces": "gi1/0/1-24", "host_mode": "multi-host",
                    "server_down": "open"}).field == "server_down"


def test_classic_before_the_authentication_manager():
    g = guide({"platform": "classic", "version": "12.2(44)SE6", "interfaces": "Fa0/1-24", "host_mode": "single-host",
               "server_down": "vlan", "server_down_vlan": 99})
    assert "classic IOS, before the authentication manager" in g["title"]
    assert "authentication open" not in g["cli"] and "authentication port-control" not in g["cli"]
    assert "dot1x port-control auto" in g["cli"]
    enforce = g["enforce_cli"]
    assert "dot1x critical vlan 99" in enforce and "dot1x re-authenticate interface FastEthernet0/1" in enforce


def test_dot1x_summary_sessions():
    out = """Interface     PAE              Client          Status
------------------------------------------------------------------
Ethernet1/1   AUTH        0e:be:ef:0e:be:ef      AUTHORIZED
Ethernet1/2   AUTH                  none         UNAUTHORIZED
Fa0/3         AUTH        0011.2233.4455         UNAUTHORIZED
"""
    rows = wired.parse_sessions(out)
    assert [(r["interface"], r["authorized"]) for r in rows] == [("Ethernet1/1", True), ("Ethernet1/2", False), ("Fa0/3", False)]


# ── RADIUS per switch ────────────────────────────────────────────────────────


def test_agent_needs_and_reports():
    assert cp.agent_needs(cp.caps("ibns2", "", "17.9.4", False)) == set()
    assert cp.agent_needs(cp.caps("classic", "", "15.2(7)E3", False)) == set()
    assert cp.agent_needs(cp.caps("nxos", "n3k", "9.3(8)", False)) == {"pap-wired", "monitor-accept", "send-vlan", "client-message-authenticator"}
    assert cp.agent_needs(cp.caps("cbs", "c1200", "", False)) >= {"send-vlan"}
    assert cp.agent_needs(None) == set()
    src = (ROOT / "services" / "radius" / "agent" / "easyeap_agent.py").read_text()
    for feature in ("pap-wired", "monitor-accept", "send-vlan", "client-message-authenticator", "nxos-roles"):
        assert f'"{feature}"' in src.split("FEATURES = ", 1)[1].split("\n", 1)[0], feature


def test_audit_unavailable_per_case():
    from app.routers.switch_audit import unavailable
    assert unavailable("cisco-switch", {"platform": "ibns2"}) is None
    assert unavailable("cisco-switch", {"platform": "nxos", "series": "n9k-fx"}) is None
    assert "Meraki" in unavailable("meraki", {"series": "ms"})
    assert "SG200" in unavailable("cisco-switch", {"platform": "cbs", "series": "sx200"})
    assert "12.2(50)SE" in unavailable("cisco-switch", {"platform": "classic", "version": "12.2(44)SE6"})


def test_detect_blanks_a_version_it_cant_read():
    d = cp.detect("Cisco Nexus Operating System (NX-OS) Software\n  NXOS: version banana\ncisco Nexus9000 C93180YC-EX chassis\n")
    assert d.platform == "nxos" and d.version == ""


def test_client_flags():
    nexus = SimpleNamespace(vendor="cisco-switch", networks=["wired"], wired_profile={"platform": "nxos", "series": "n9k-fx", "version": "9.3(8)"})
    assert state.client_flags(nexus) == {"monitor_accept": True, "message_authenticator": "no", "send_vlan": True}
    n3k = SimpleNamespace(vendor="cisco-switch", networks=["wired"], wired_profile={"platform": "nxos", "series": "n3k", "version": "9.3(8)"})
    assert state.client_flags(n3k)["send_vlan"] is False
    xe = SimpleNamespace(vendor="cisco-switch", networks=["wired"], wired_profile={"platform": "ibns2"})
    assert state.client_flags(xe) == {"monitor_accept": False, "message_authenticator": "yes", "send_vlan": True}
    wlc = SimpleNamespace(vendor="cisco-9800", networks=["wireless"], wired_profile=None)
    assert state.client_flags(wlc) == {"monitor_accept": False, "message_authenticator": "yes", "send_vlan": True}


# ── Switch audit blocks ──────────────────────────────────────────────────────

MON = {"version": "v2c"}


def test_audit_blocks_per_family():
    classic = service.config_block(MON, "10.9.9.9", ("10.9.9.9", 5514), {"platform": "classic", "version": "15.2(7)E3"})
    assert "access-list 98 permit 10.9.9.9" in classic and "snmp-server community <community> view EASYEAP-RO RO 98" in classic
    assert "logging host 10.9.9.9 transport udp port 5514" in classic
    # Classic IOS has no discriminator; one an earlier block added is removed in the comments, never configured.
    assert not any("discriminator" in line for line in classic.splitlines() if not line.startswith("!"))
    old = service.config_block(MON, "10.9.9.9", ("10.9.9.9", 5514), {"platform": "classic", "version": "15.0(2)SE11"})
    assert "UDP 514 only" in old and not any(line.startswith("logging host") for line in old.splitlines())
    nx = service.config_block(MON, "10.9.9.9", ("10.9.9.9", 5514), {"platform": "nxos", "series": "n9k-fx", "version": "9.3(8)"})
    assert "snmp-server community <community> use-ipv4acl EASYEAP-SNMP" in nx and "group network-operator" in nx
    assert "logging server 10.9.9.9 5 port 5514 use-vrf management" in nx
    n5k = service.config_block(MON, "10.9.9.9", ("10.9.9.9", 5514), {"platform": "nxos", "series": "n5k"})
    assert "UDP 514 only" in n5k
    sb = service.config_block(MON, "10.9.9.9", None, {"platform": "cbs", "series": "sx350"})
    assert "snmp-server community <community> ro 10.9.9.9 view EASYEAP-RO" in sb
    rm = service.removal_block(MON, "abc", None, "10.9.9.9", {"platform": "cbs", "series": "sx350"})
    assert "no snmp-server community abc 10.9.9.9" in rm


def test_audit_v3_algorithms_follow_the_block():
    assert platforms.v3_algorithms({"platform": "ibns2"}) is None
    assert platforms.v3_algorithms({"platform": "nxos"}) == ("sha", "aes128")
    assert platforms.v3_algorithms({"platform": "cbs", "series": "sx300"}) == ("sha", "des")
    assert platforms.v3_algorithms({"platform": "cbs", "series": "c1300"}) == ("sha256", "aes128")
    v3 = service.config_block({"version": "v3", "user": "easyeap"}, "10.9.9.9", None, {"platform": "classic"})
    assert "auth sha <authentication key> priv aes 128" in v3


# ── Syslog from other families ───────────────────────────────────────────────


def test_syslog_nxos_and_letter_severities():
    nx = parse(b"<189>2026 Nov  7 12:00:00 n9k %DOT1X-5-SESSION_TERMINATION: Authentication session terminated on Ethernet1/5")
    assert nx is not None and nx.tag == "DOT1X-5-SESSION_TERMINATION"
    err = parse(b"<187>%ETHPORT-3-IF_DOWN_ERROR_DISABLED: Interface Ethernet1/7 is down (Error disabled. Reason:BPDUGuard)")
    assert err is not None and err.severity == 3
    # Cisco Business writes the severity as a letter.
    letter = parse(b"<188>%DOT1X-W-SECURITY_VIOLATION: Security violation on gi1/0/5")
    assert letter is not None and letter.severity == 4 and letter.tag == "DOT1X-4-SECURITY_VIOLATION"
    stp = parse(b"<190>%STP-W-PORTSTATUS: gi1/0/5: STP status Forwarding")
    assert stp is not None and not kept(stp.facility, stp.mnemonic) and kept("STP", "BLOCK_BPDUGUARD")


# ── Admin logins on NX-OS and Cisco Business ─────────────────────────────────


def _admin(profile: dict, vendor: str = "cisco-switch"):
    c = SimpleNamespace(name="Core", vendor=vendor, wired_profile=profile)
    return c, cisco.ctx_for(c, TENANT, "10.9.9.9")


def test_admin_forms():
    _, ctx = _admin({"platform": "nxos", "series": "n9k-fx", "vrf": "management"})
    assert (ctx.form, ctx.os) == ("nxos", "nxos")
    cfg = cisco.config(ctx)
    assert "feature tacacs+" in cfg and "use-vrf management" in cfg and "tacacs-server host 10.9.9.9 key 0" in cfg
    assert cisco.os_of(SimpleNamespace(vendor="cisco-switch", wired_profile={"platform": "nxos", "series": "n7k"})) == "nxos-n7k"
    assert any("checkpoint" in s for s in cisco.guide(ctx)["steps"])
    _, sx = _admin({"platform": "cbs", "series": "sx350"})
    assert sx.form == "sx" and "tacacs-server host 10.9.9.9" in cisco.config(sx)
    assert _admin({"platform": "cbs", "series": "sx300"})[1].form == "sx-old"
    assert cisco.unsupported(SimpleNamespace(vendor="cisco-switch", wired_profile={"platform": "cbs", "series": "c1200"})) is not None
    assert cisco.unsupported(SimpleNamespace(vendor="meraki", wired_profile={"series": "ms"})) is not None
    assert cisco.form_of(SimpleNamespace(vendor="cisco-switch", wired_profile={"platform": "ibns2", "version": "3.6.6E"})) == "legacy"
    assert cisco.form_of(SimpleNamespace(vendor="cisco-switch", wired_profile={"platform": "classic"}), legacy=True) == "legacy"


@pytest.fixture(scope="module")
def tac():
    path = ROOT / "services" / "radius" / "agent" / "tacacs.py"
    if not path.exists():
        pytest.skip("the RADIUS agent isn't in this checkout")
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location("cp_tacacs", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["cp_tacacs"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_tacacs_roles_per_os(tac):
    assert tac.role_args("ios", 15) == ["priv-lvl=15"]
    assert tac.role_args("nxos", 15) == ['shell:roles="network-admin"']
    assert tac.role_args("nxos", 1) == ['shell:roles="network-operator"']
    assert tac.role_args("nxos-n7k", 15) == ['shell:roles="network-admin vdc-admin"']
