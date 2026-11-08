"""Wired 802.1X on Cisco Nexus (NX-OS): the configuration EasyEAP generates (docs/plans/cisco-platforms.md §6.3).

NX-OS has no open (monitor) mode before 10.6(3)F, and then only for MAB clients on four models, so EasyEAP monitors
from its side: the ports run 802.1X with MAC authentication bypass, and EasyEAP accepts every MAC request from the
switch until it's enforced (§4). Enforce adds only the switch's fallback actions; the rest is EasyEAP's decision.

The commands are from Cisco's Nexus 9000 7.x/9.2/9.3/10.x, 3000, 3548, 5600 and 7000 security guides (research notes,
plan §12). Not verified on Nexus hardware.
"""
from __future__ import annotations

from app.radius.guides import SECRET_PLACEHOLDER
from app.radius.wired import RANGES_PER_LINE, Ctx, PortRange, access_ranges

SAFE_PASTE = [
    "In exec mode: checkpoint EASYEAP-BEFORE   (a restore point for the running configuration)",
    "configure terminal, paste the configuration, then end",
    "Open a NEW SSH session to the switch and check you can still log in.",
    "If something's wrong: rollback running-config checkpoint EASYEAP-BEFORE",
    "It works: copy running-config startup-config",
]


def _range_text(r: PortRange) -> str:
    return f"{r.kind}{r.prefix}{r.start}" + (f"-{r.end}" if r.end != r.start else "")


def interface_lines(ranges: list[PortRange]) -> list[str]:
    return ["interface " + ", ".join(_range_text(r) for r in ranges[i:i + RANGES_PER_LINE]) for i in range(0, len(ranges), RANGES_PER_LINE)]


def _vrf(c: Ctx) -> str:
    return c.p.vrf or "management"


def preflight(c: Ctx) -> list[dict]:
    vrf = _vrf(c)
    return [
        {"command": "show version", "look_for": ("“Cisco Nexus Operating System (NX-OS) Software”, and the NXOS (or system) version and the "
                                                 "chassis EasyEAP built this for: " + " ".join(x for x in (c.p.version, c.p.series) if x) + ". If they differ, change "
                                                 "them in the switch's settings first.")},
        {"command": "show running-config dot1x", "look_for": "Must print nothing (or only the version line). Otherwise this switch already has 802.1X: stop and merge by hand."},
        {"command": "show running-config aaa", "look_for": "Existing “aaa authentication dot1x” lines or RADIUS groups: stop and merge by hand."},
        {"command": "show interface trunk", "look_for": "Trunk ports are uplinks: put them in “Leave alone” (MAC authentication doesn't run on trunks)."},
        {"command": "show port-channel summary", "look_for": "Port-channel member ports: put them in “Leave alone”."},
        {"command": "show vpc brief", "look_for": "vPC ports and the peer link: put them in “Leave alone” (802.1X isn't supported there)."},
        {"command": "show cdp neighbors", "look_for": "Switches, routers and access points you see here: leave their ports alone."},
        {"command": f"ping {c.server} vrf {vrf}" + (f" source-interface {c.p.source_interface}" if c.p.source_interface else ""),
         "look_for": f"Replies. If not, EasyEAP isn't reachable in VRF {vrf}: set the VRF in the switch's settings (use “default” for in-band)."},
    ]


def _aaa(c: Ctx) -> list[str]:
    p, vrf = c.p, _vrf(c)
    out = ["feature dot1x",
           "!",
           f"radius-server host {c.server} key 0 {SECRET_PLACEHOLDER} auth-port {c.auth} acct-port {c.acct} authentication accounting",
           f"radius-server host {c.server} timeout 5",
           f"radius-server host {c.server} retransmit 2",
           "radius-server deadtime 3",
           "!",
           "aaa group server radius EASYEAP",
           f"  server {c.server}",
           f"  use-vrf {vrf}",
           "  deadtime 3"]
    if p.source_interface:
        out += ["!", f"ip radius source-interface {p.source_interface}"]
    out += ["!",
            "aaa authentication dot1x default group EASYEAP",
            "aaa accounting dot1x default group EASYEAP",
            "dot1x radius-accounting",
            "!"]
    if c.caps.coa:
        out += ["! Change of Authorization (UDP 1700): EasyEAP can re-authenticate or end a device's session (NX-OS can't bounce a port).",
                "aaa server radius dynamic-author",
                f"  client {c.server} vrf {vrf} server-key 0 {SECRET_PLACEHOLDER}",
                "!"]
    return out


def _ports(c: Ctx) -> list[str]:
    p = c.p
    out = ["  switchport", "  switchport mode access"]
    if p.access_vlan:
        out.append(f"  switchport access vlan {p.access_vlan}")
    out += ["  dot1x port-control auto", f"  dot1x host-mode {p.host_mode}"]
    if p.mab:
        out.append("  dot1x mac-auth-bypass")
    out += ["  dot1x re-authentication", "  dot1x timeout tx-period 10", "  dot1x max-reauth-req 2",
            "  spanning-tree port type edge", "  spanning-tree bpduguard enable"]
    return out


def initial(c: Ctx) -> str:
    p = c.p
    head = [f"! EasyEAP: wired 802.1X for {c.switch} (Cisco Nexus, NX-OS)"]
    if c.caps.monitor == "server":
        head += ["! NX-OS has no open (monitor) mode: the ports run 802.1X, and EasyEAP accepts every MAC request from this",
                 "! switch while it's in monitor mode (no VLAN), logging what it would decide. A device that tries 802.1X",
                 "! and fails is refused. Enforce later from EasyEAP (RADIUS → the switch → Enforce)."]
    else:
        head += ["! NX-OS has no open (monitor) mode and this switch has no MAC authentication: from this paste on, a device",
                 "! without an EasyEAP certificate has no access on these ports. List one test port first."]
    head.append("!")
    lines = head + _aaa(c)
    if p.exclude:
        lines.append(f"! Left alone: {p.exclude}")
    for line in interface_lines(access_ranges(p.interfaces, p.exclude)):
        lines += [line, *_ports(c), "!"]
    lines.append("end")
    return "\n".join(lines)


def _actions(c: Ctx, prefix: str) -> tuple[list[str], list[str]]:
    """Enforce-only lines: (global, per port); with prefix "no " the lines that remove them."""
    p = c.p
    glob, port = [], []
    if p.server_down == "open" and "open" in c.caps.server_down:
        # Critical authentication (Nexus 9300-EX/FX/FX2, 10.1(2)+): MAC-authenticated devices only, on their port's VLAN.
        # It needs an idle-time probe: EasyEAP logs those probes as refused requests for the user "test".
        glob += [f"radius-server host {c.server} test idle-time 5", "authentication event server dead action authorize"]
    if p.no_supplicant == "vlan" and c.caps.no_supplicant_vlan:
        port.append(f"  dot1x guest-vlan {p.no_supplicant_vlan}")
    return [prefix + x for x in glob], [x[:2] + prefix + x[2:] for x in port]


def _change(c: Ctx, title: list[str], prefix: str) -> str:
    glob, port = _actions(c, prefix)
    lines = [*title, "!", *glob]
    if port:
        for line in interface_lines(access_ranges(c.p.interfaces, c.p.exclude)):
            lines += [line, *port, "!"]
    lines += ["end", "! Re-authenticate the devices on every 802.1X port:", "dot1x re-authenticate"]
    return "\n".join(lines)


def enforce(c: Ctx) -> str:
    title = [f"! EasyEAP: enforce wired 802.1X on {c.switch} (NX-OS)",
             "! EasyEAP stops accepting MAC requests it would refuse, and sends VLANs: devices not on the MAC allow list lose access."
             if c.caps.monitor == "server" else "! EasyEAP starts sending VLANs to this switch."]
    return _change(c, title, "")


def monitor(c: Ctx) -> str:
    title = [f"! EasyEAP: back to monitor mode on {c.switch} (NX-OS)",
             "! EasyEAP accepts this switch's MAC requests again and stops sending VLANs." if c.caps.monitor == "server"
             else "! EasyEAP stops sending VLANs to this switch. The ports still require 802.1X (NX-OS has no open mode)."]
    return _change(c, title, "no ")
