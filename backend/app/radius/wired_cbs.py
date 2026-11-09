"""Wired 802.1X on Cisco Business and Small Business switches (docs/plans/cisco-platforms.md §6.4).

Three command languages: the "sx" CLI of the Catalyst 1300/1200, CBS350/250 and Sx350/550X/300/250 series; the
CBS220's own CLI; and the SG200's web interface (no CLI). What each series can do is in app/radius/cisco_platforms.py.

Monitor mode: `authentication open` where the series has it (C1300, Sx350/CBS350, Sx300). The C1200, CBS250/Sx250 and
CBS220 have none, and their guest VLAN can't stand in for it (Cisco: a port must not be a static member of the guest
VLAN), so there EasyEAP starts with a test port (plan §4). None of these switches has a critical VLAN: "EasyEAP
unreachable" is the global `aaa authentication dot1x default radius none`.

From Cisco's CLI guides for the C1300/C1300X 4.x, Sx350X 2.5, CBS350/CBS250 3.1, Sx300 1.4 and CBS220 (research notes,
plan §12). Not verified on hardware.
"""
from __future__ import annotations

import re

from app.radius.guides import SECRET_PLACEHOLDER
from app.radius.wired import RANGES_PER_LINE, SX_SHORT, Ctx, PortRange, access_ranges

SAFE_PASTE = [
    "Don't save before you paste: the saved configuration (startup-config) is the way back.",
    "configure terminal, paste the configuration, then end",
    "Open a NEW session to the switch (SSH or the web interface) and check you can still log in.",
    "If something's wrong: reload the switch without saving, and it comes back with the saved configuration.",
    "It works: copy running-config startup-config",
]
HOST_MODES = {"multi-auth": "multi-sessions", "single-host": "single-host", "multi-host": "multi-host"}


def _range_text(r: PortRange) -> str:
    return f"{SX_SHORT.get(r.kind, r.kind)}{r.prefix}{r.start}" + (f"-{r.end}" if r.end != r.start else "")


def interface_lines(ranges: list[PortRange]) -> list[str]:
    return ["interface range " + ",".join(_range_text(r) for r in ranges[i:i + RANGES_PER_LINE]) for i in range(0, len(ranges), RANGES_PER_LINE)]


def source_interface(name: str) -> str:
    """Vlan10 → "vlan 10", Loopback1 → "loopback 1": the form these switches take."""
    mt = re.match(r"^(vlan|loopback)\s*(\d+)$", name.strip(), re.IGNORECASE)
    return f"{mt.group(1).lower()} {mt.group(2)}" if mt else name.strip()


def preflight(c: Ctx) -> list[dict]:
    s = c.p.series
    out = [{"command": "show system", "look_for": "The model in “System Description”: EasyEAP built this for " + (c.p.series or "?") + ". If it's another series, change it first."},
           {"command": "show version", "look_for": "The firmware version" + (f" (EasyEAP assumed {c.p.version})." if c.p.version else ".")},
           {"command": "show running-config | include dot1x|radius|tacacs",
            "look_for": "Only lines for EasyEAP, or nothing. Another RADIUS server or 802.1X settings: stop and merge by hand."},
           {"command": "show interfaces status", "look_for": "The port names (gi1/0/1 …). Uplinks and ports with access points or switches: leave them alone."},
           {"command": f"ping {c.server}", "look_for": "Replies. Without them RADIUS can't reach EasyEAP."}]
    if s == "cbs220":
        out[2]["command"] = "show running-config"
    return out


def _guest(c: Ctx, vlan: int, prefix: str = "") -> list[str]:
    """The guest VLAN (devices without 802.1X once enforced): a VLAN setting on the sx CLI, a global one on the CBS220."""
    if c.caps.dialect == "cbs220":
        return [f"{prefix}dot1x guest-vlan {vlan} enable"]
    return [f"interface vlan {vlan}", f" {prefix}dot1x guest-vlan", " exit"]


def initial(c: Ctx) -> str:
    p, caps = c.p, c.caps
    s = p.series
    ranges = access_ranges(p.interfaces, p.exclude)
    lines = [f"! EasyEAP: wired 802.1X for {c.switch} (Cisco Business), monitor mode"]
    if caps.monitor == "switch":
        lines += ["! Ports stay open (authentication open): devices that fail or don't speak 802.1X keep their access, and",
                  "! EasyEAP logs what it would decide without changing any VLAN. Enforce later from EasyEAP."]
    else:
        lines += ["! This switch has no open (monitor) mode: from this paste on, a device without an EasyEAP certificate has no",
                  "! access on these ports. List one test port first, and leave printers, cameras and phones out."]
    lines.append("!")
    if caps.dialect == "cbs220":
        lines += [f"radius-server host {c.server} auth-port {c.auth} key {SECRET_PLACEHOLDER} timeout 5 retransmit 2 usg-type 802.1x",
                  "dot1x system-auth-control", "!"]
        for line in interface_lines(ranges):
            lines += [line, f" dot1x host-mode {HOST_MODES[p.host_mode]}", " dot1x port-control auto", " exit"]
        lines += ["! Not documented for the CBS220 (unverified): a RADIUS accounting server and the RADIUS source interface.", "end"]
        return "\n".join(lines)
    acct = f" acct-port {c.acct}" if caps.accounting else ""
    lines.append(f"radius-server host {c.server} auth-port {c.auth}{acct} timeout 5 retransmit 2 key {SECRET_PLACEHOLDER} usage dot1.x")
    if p.source_interface and s != "sx300":
        lines.append(f"radius-server host source-interface {source_interface(p.source_interface)}")
    lines.append("! Monitor mode: while EasyEAP is unreachable, ports let devices through (the last method, none).")
    lines.append("aaa authentication dot1x default radius none")
    if caps.accounting:
        lines.append("aaa accounting dot1x start-stop group radius")
    if p.mab and caps.mab == "pap":
        lines += ["! MAC authentication as PAP (Service-Type Call-Check); the user name is the MAC in lower case without separators.",
                  "dot1x mac-auth radius"]
    if caps.coa:
        lines += ["! Change of Authorization (UDP 1700): EasyEAP can end a revoked device's session.",
                  "aaa server radius dynamic-author", f" client {c.server} server-key {SECRET_PLACEHOLDER}", " exit"]
    lines += ["dot1x system-auth-control", "!"]
    if p.exclude:
        lines.append(f"! Left alone: {p.exclude}")
    for line in interface_lines(ranges):
        lines += [line, " switchport mode access"]
        if p.access_vlan:
            lines.append(f" switchport access vlan {p.access_vlan}")
        lines.append(f" dot1x host-mode {HOST_MODES[p.host_mode]}")
        if caps.mab:
            lines.append(" dot1x authentication 802.1x mac" if p.mab else " dot1x authentication 802.1x")
        lines.append(" dot1x reauthentication")
        if caps.monitor == "switch":
            lines.append(" authentication open")
        lines += [" spanning-tree portfast", " dot1x port-control auto", " exit"]
    lines.append("end")
    return "\n".join(lines)


def _restart() -> list[str]:
    return ["! Re-authenticate every port's devices:", "dot1x re-authenticate"]


def _change(c: Ctx, title: list[str], enforce: bool) -> str:
    """Enforce (or, with enforce=False, back to monitor): open mode off, the fallbacks and VLANs on, and the reverse."""
    p, caps = c.p, c.caps
    no = "" if enforce else "no "
    lines = [*title, "!"]
    if caps.dialect != "cbs220":
        if enforce and p.server_down == "wait":
            lines += ["! EasyEAP unreachable: new devices wait (RADIUS only, no fallback).", "aaa authentication dot1x default radius"]
        elif not enforce:
            lines.append("aaa authentication dot1x default radius none")
    if p.no_supplicant == "vlan":
        lines += _guest(c, p.no_supplicant_vlan, no)
    for line in interface_lines(access_ranges(p.interfaces, p.exclude)):
        lines.append(line)
        if caps.monitor == "switch":
            lines.append(" no authentication open" if enforce else " authentication open")
        if caps.radius_vlan:
            word = "radius-attribute" if caps.dialect == "cbs220" else "radius-attributes"
            lines.append(f" dot1x {word} vlan static" if enforce else f" no dot1x {word} vlan")
        if p.no_supplicant == "vlan":
            lines.append(f" {no}dot1x guest-vlan enable")
        lines.append(" exit")
    lines += ["end", *_restart()]
    return "\n".join(lines)


def enforce(c: Ctx) -> str:
    return _change(c, [f"! EasyEAP: enforce wired 802.1X on {c.switch} (Cisco Business)",
                       "! After this, a port lets a device through only once it's accepted."], True)


def monitor(c: Ctx) -> str:
    what = ("! Devices that fail or skip 802.1X keep their access again." if c.caps.monitor == "switch"
            else "! EasyEAP stops sending VLANs. The ports still require 802.1X (this switch has no open mode).")
    return _change(c, [f"! EasyEAP: back to monitor mode on {c.switch} (Cisco Business)", what], False)


def mab(c: Ctx) -> str:
    p = c.p
    ranges = access_ranges(p.interfaces, p.exclude)
    lines = [f"! EasyEAP: MAC authentication {'on' if p.mab else 'off'} for {c.switch} (Cisco Business, monitor mode: ports stay open)", "!"]
    if c.caps.mab == "pap":
        lines.append("dot1x mac-auth radius" if p.mab else "! (dot1x mac-auth radius stays: it only sets how MAC requests are sent)")
    for line in interface_lines(ranges):
        lines += [line, " dot1x authentication 802.1x mac" if p.mab else " dot1x authentication 802.1x", " exit"]
    lines += ["end", *_restart()]
    return "\n".join(lines)


def web_steps(c: Ctx) -> list[str]:
    """SG200/SF200: no CLI, so the web interface (menu names from the 200 series admin guide; not verified on hardware)."""
    return [f"Security → RADIUS: add a server {c.server}, authentication port {c.auth}, accounting port {c.acct}, with the shared "
            "secret, usage type 802.1X.",
            "Security → 802.1X → Properties: Port-based authentication on, authentication method RADIUS.",
            "Security → 802.1X → Port Authentication: set ONE test port's administrative port control to Auto. Leave every other "
            "port on Force Authorized. These switches have no monitor mode: a device without an EasyEAP certificate loses access "
            "on an Auto port.",
            "Plug a test device with an EasyEAP certificate into that port and watch for its first request below.",
            "Then set more ports to Auto. Never the uplink or ports with access points or switches."]
