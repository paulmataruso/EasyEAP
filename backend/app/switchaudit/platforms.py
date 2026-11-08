"""The switch audit's SNMP and syslog configuration for Cisco families other than IOS-XE (docs/plans/cisco-platforms.md
§8): classic IOS, Nexus (NX-OS) and Cisco Business. IOS-XE keeps service.config_block's own block.

Each family takes the same inputs as service.config_block (the monitoring settings, EasyEAP's source address, the syslog
destination) plus the switch's capabilities, and returns the lines to paste and the lines that undo them. From Cisco's
configuration guides (research notes ios.md, nxos.md §10–11, smb-meraki.md §1.7–1.8); not verified on hardware.
"""
from __future__ import annotations

from app.radius import cisco_platforms as cp

COMMUNITY_PLACEHOLDER = "<community>"
AUTH_PLACEHOLDER = "<authentication key>"
PRIV_PLACEHOLDER = "<privacy key>"
CLASSIC_ACL = 98   # classic IOS documents a numbered standard ACL on snmp-server community/group
# What Cisco Business switches are polled for (no CISCO-AUTH-FRAMEWORK-MIB or CISCO-ERR-DISABLE-MIB): ports only.
CBS_VIEW = ("1.3.6.1.2.1.1", "1.3.6.1.2.1.2.2.1", "1.3.6.1.2.1.31.1.1.1", "1.3.6.1.2.1.47.1.1.1.1")


def syslog_port_ok(profile: dict, caps: cp.Caps) -> bool:
    """Whether the switch can send syslog to a port other than 514. Classic IOS before 15.2 and Nexus 5000/3548 (and
    NX-OS before 9.3(3)) can't (research snmp-syslog.md, nxos.md §11.1)."""
    platform, series, version = profile.get("platform") or "ibns2", profile.get("series") or "", profile.get("version") or ""
    if platform == "classic":
        return cp.at_least("classic", version, "15.2(1)E") is not False
    if platform == "nxos":
        if series in ("n5k", "n3548"):
            return False
        return series == "n7k" or cp.at_least("nxos", version, "9.3(3)") is not False
    return True


def v3_algorithms(profile: dict | None) -> tuple[str, str] | None:
    """The SNMPv3 authentication and privacy this family's block uses, which the poller must use too; None: the admin
    chooses (IOS-XE). ("sha", "des"): SG300/SF300 firmware 1.4, whose only privacy is DES, which EasyEAP doesn't use."""
    p = profile or {}
    platform = p.get("platform") or "ibns2"
    if platform in ("classic", "nxos"):
        return ("sha", "aes128")
    if platform == "cbs":
        return ("sha", "des") if p.get("series") == "sx300" else ("sha256", "aes128")
    return None


def _no_syslog_port(dest: str, port: int) -> list[str]:
    return ["!", f"! Syslog: this switch sends syslog to UDP 514 only, and EasyEAP listens on {port}. The switch audit works without it",
            f"! (SNMP only). To add it, EasyEAP must listen on 514 (EASYEAP_SYSLOG_PORT=514), then: logging host {dest}"]


# ── Classic IOS ──────────────────────────────────────────────────────────────


def classic_block(mon: dict, src: str, view: list[tuple[str, str]], syslog: tuple[str, int] | None, port_ok: bool) -> list[str]:
    out = ["! EasyEAP switch audit: read-only SNMP for the 802.1X tables, from EasyEAP's address only.",
           f"! {src} is the address the switch sees EasyEAP's requests come from. If access list {CLASSIC_ACL} is already in use",
           "! (show access-lists), pick a free number from 1 to 99 and change it on every line.",
           f"access-list {CLASSIC_ACL} permit {src}", f"access-list {CLASSIC_ACL} deny any", "!"]
    out += [f"snmp-server view EASYEAP-RO {o} included" for o, _ in view]
    if mon.get("version") == "v3":
        out += [f"snmp-server group EASYEAP v3 priv read EASYEAP-RO access {CLASSIC_ACL}",
                f"snmp-server user {mon.get('user') or 'easyeap'} EASYEAP v3 auth sha {AUTH_PLACEHOLDER} priv aes 128 {PRIV_PLACEHOLDER}",
                "! SNMPv3 with AES needs a crypto (k9) image and IOS 12.2(52)SE or later; classic IOS has no SHA-2."]
    else:
        out.append(f"snmp-server community {COMMUNITY_PLACEHOLDER} view EASYEAP-RO RO {CLASSIC_ACL}")
    if syslog:
        dest, port = syslog
        if port_ok or port == 514:
            # No logging discriminator on classic IOS: Cisco notes a memory leak with it on 15.2(7)E; EasyEAP's receiver
            # keeps only the messages it needs.
            out += ["!", "! Syslog: EasyEAP keeps the 802.1X, MAB, err-disable, RADIUS server and configuration messages.",
                    f"logging host {dest}" + ("" if port == 514 else f" transport udp port {port}"),
                    "! Pasted EasyEAP's earlier block (show running-config | include discriminator shows EASYEAP)? Remove it:",
                    f"!   no logging host {dest} transport udp port {port} discriminator EASYEAP",
                    "!   no logging discriminator EASYEAP"]
        else:
            out += _no_syslog_port(dest, port)
    return out


def classic_removal(mon: dict, community: str | None, view: list[tuple[str, str]], syslog: tuple[str, int] | None, port_ok: bool) -> list[str]:
    out = []
    if syslog and (port_ok or syslog[1] == 514):
        dest, port = syslog
        out.append(f"no logging host {dest}" + ("" if port == 514 else f" transport udp port {port}"))
    if mon.get("version") == "v3":
        out += [f"no snmp-server user {mon.get('user') or 'easyeap'} EASYEAP v3", "no snmp-server group EASYEAP v3 priv"]
    else:
        out.append(f"no snmp-server community {community or COMMUNITY_PLACEHOLDER}")
    out += [f"no snmp-server view EASYEAP-RO {o} included" for o, _ in view]
    out.append(f"no access-list {CLASSIC_ACL}")
    return out


# ── NX-OS ────────────────────────────────────────────────────────────────────


def nxos_block(mon: dict, src: str, profile: dict, syslog: tuple[str, int] | None, port_ok: bool) -> list[str]:
    vrf = profile.get("vrf") or "management"
    out = ["! EasyEAP switch audit: read-only SNMP (role network-operator), from EasyEAP's address only.",
           "! NX-OS has no SNMP views: the community or user reads what network-operator can, which is read-only.",
           "ip access-list EASYEAP-SNMP", f"  10 permit udp {src}/{128 if ':' in src else 32} any eq snmp", "!"]
    if mon.get("version") == "v3":
        user = mon.get("user") or "easyeap"
        out += [f"snmp-server user {user} network-operator auth sha {AUTH_PLACEHOLDER} priv aes-128 {PRIV_PLACEHOLDER}",
                f"snmp-server user {user} use-ipv4acl EASYEAP-SNMP",
                f"snmp-server user {user} enforcePriv",
                f"! NX-OS also makes {user} a CLI user (role network-operator) with the authentication key as its password.",
                "! Prefer SNMPv2c on Nexus unless your policy requires v3."]
    else:
        out += [f"snmp-server community {COMMUNITY_PLACEHOLDER} group network-operator",
                f"snmp-server community {COMMUNITY_PLACEHOLDER} use-ipv4acl EASYEAP-SNMP",
                f"! If the switch rejects use-ipv4acl (older NX-OS, Nexus 3000): snmp-server community {COMMUNITY_PLACEHOLDER} use-acl EASYEAP-SNMP"]
    if syslog:
        dest, port = syslog
        if port_ok or port == 514:
            out += ["!", "! Syslog: NX-OS sends everything at notification level (5) and above; EasyEAP keeps the 802.1X, err-disable,",
                    "! RADIUS server and configuration messages.",
                    f"logging server {dest} 5" + ("" if port == 514 else f" port {port}") + f" use-vrf {vrf}"]
        else:
            out += _no_syslog_port(dest, port)
    return out


def nxos_removal(mon: dict, community: str | None, profile: dict, syslog: tuple[str, int] | None, port_ok: bool) -> list[str]:
    out = []
    if syslog and (port_ok or syslog[1] == 514):
        out.append(f"no logging server {syslog[0]}")
    if mon.get("version") == "v3":
        out.append(f"no snmp-server user {mon.get('user') or 'easyeap'}")
    else:
        out.append(f"no snmp-server community {community or COMMUNITY_PLACEHOLDER}")
    out.append("no ip access-list EASYEAP-SNMP")
    return out


# ── Cisco Business ───────────────────────────────────────────────────────────


def cbs_block(mon: dict, src: str, profile: dict, syslog: tuple[str, int] | None) -> list[str]:
    series = profile.get("series") or "sx350"
    out = ["! EasyEAP switch audit: read-only SNMP of the port tables, from EasyEAP's address only.",
           "! Cisco Business switches don't report 802.1X sessions over SNMP: the audit reads ports."]
    if series == "cbs220":
        out += ["snmp-server"]
        out += [f"snmp-server view EASYEAP-RO subtree {o} oid-mask all viewtype included" for o in CBS_VIEW]
        if mon.get("version") == "v3":
            out += ["snmp-server group EASYEAP v3 priv read-view EASYEAP-RO",
                    f"snmp-server user {mon.get('user') or 'easyeap'} EASYEAP auth sha256 {AUTH_PLACEHOLDER} priv {PRIV_PLACEHOLDER}",
                    "! The CBS220 can't limit SNMP to EasyEAP's address: keep its management on a trusted network."]
        else:
            out += [f"snmp-server community {COMMUNITY_PLACEHOLDER} view EASYEAP-RO ro",
                    "! The CBS220 can't limit a community to EasyEAP's address: keep its management on a trusted network."]
    else:
        out += ["snmp-server server"]
        out += [f"snmp-server view EASYEAP-RO {o} included" for o in CBS_VIEW]
        if mon.get("version") == "v3":
            auth = "sha" if series == "sx300" else "sha256"
            priv = "" if series in ("sx300", "sx350", "sx250") else "aes-128 "
            out += ["snmp-server engineID local default",
                    "snmp-server group EASYEAP v3 priv read EASYEAP-RO",
                    f"snmp-server user {mon.get('user') or 'easyeap'} EASYEAP v3 auth {auth} {AUTH_PLACEHOLDER} priv {priv}{PRIV_PLACEHOLDER}",
                    "! If the switch refuses the user line, create the SNMPv3 user in its web interface (Cisco's guide says some "
                    "firmware needs that)."]
        else:
            out.append(f"snmp-server community {COMMUNITY_PLACEHOLDER} ro {src} view EASYEAP-RO")
    if syslog:
        dest, port = syslog
        tail = " severity informational" + ("" if series == "cbs220" else " description EasyEAP")
        out += ["!", "! Syslog: EasyEAP keeps the messages it knows (Cisco documents none for 802.1X on these switches yet).",
                f"logging host {dest} port {port}{tail}"]
    return out


def cbs_removal(mon: dict, community: str | None, profile: dict, syslog: tuple[str, int] | None, src: str) -> list[str]:
    series = profile.get("series") or "sx350"
    out = []
    if syslog:
        out.append(f"no logging host {syslog[0]}")
    if mon.get("version") == "v3":
        out += [f"no snmp-server user {mon.get('user') or 'easyeap'}", "no snmp-server group EASYEAP v3 priv"]
    elif series == "cbs220":
        out.append(f"no snmp-server community {community or COMMUNITY_PLACEHOLDER}")
    else:
        out.append(f"no snmp-server community {community or COMMUNITY_PLACEHOLDER} {src}")
    out.append("no snmp-server view EASYEAP-RO")
    return out
