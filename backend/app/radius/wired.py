"""Wired 802.1X: the switch port plan, its validation, and the switch configuration EasyEAP generates.

docs/plans/wired-8021x.md §5.4–5.5 and §6. The configuration is built for a safe first paste: monitor mode (ports stay
open, EasyEAP sends no VLAN), a preflight that stops on an existing 802.1X configuration, a guard around AAA so the
admin can't lock themselves out, and a `reload in 15` safety net. Enforcing is a separate, smaller change.

Every value that reaches the configuration is validated here, so nothing a user types can inject IOS commands.
Shared secrets never appear: the configuration carries SECRET_PLACEHOLDER, which the console replaces in the browser
with the secret shown once at creation.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app import models as m
from app.radius import cisco_platforms as cp
from app.radius.guides import SECRET_PLACEHOLDER

MAX_PORTS = 2000
RANGES_PER_LINE = 5  # IOS accepts at most five ranges in one `interface range` command

# Port types EasyEAP will configure, with the abbreviations IOS accepts. Ports EasyEAP refuses (management, logical,
# application ports) are in FORBIDDEN, so the error can say why.
PORT_TYPES = {
    "fastethernet": "FastEthernet", "fa": "FastEthernet",
    "gigabitethernet": "GigabitEthernet", "gi": "GigabitEthernet", "gig": "GigabitEthernet",
    "twogigabitethernet": "TwoGigabitEthernet", "tw": "TwoGigabitEthernet",
    "fivegigabitethernet": "FiveGigabitEthernet", "fi": "FiveGigabitEthernet",
    "tengigabitethernet": "TenGigabitEthernet", "te": "TenGigabitEthernet",
    "twentyfivegige": "TwentyFiveGigE", "twe": "TwentyFiveGigE",
    "ethernet": "Ethernet", "eth": "Ethernet",  # NX-OS: Ethernet1/1
}
# Cisco Business switches name ports with these short forms (gi1/0/1, te1/0/1, fa1/1/1; CBS220: gi1).
SX_SHORT = {"FastEthernet": "fa", "GigabitEthernet": "gi", "TenGigabitEthernet": "te"}
FORBIDDEN = {
    "port-channel": "a port channel (an uplink bundle)", "po": "a port channel (an uplink bundle)",
    "vlan": "a VLAN interface, not a switch port", "vl": "a VLAN interface, not a switch port",
    "loopback": "a loopback interface", "lo": "a loopback interface", "tunnel": "a tunnel interface", "tu": "a tunnel interface",
    "appgigabitethernet": "the application hosting port", "ap": "the application hosting port",
    "mgmt": "the management port", "management": "the management port",
    "fortygigabitethernet": "a 40G port, normally an uplink", "fo": "a 40G port, normally an uplink",
    "hundredgige": "a 100G port, normally an uplink", "hu": "a 100G port, normally an uplink",
}
_ITEM = re.compile(r"^(?P<type>[A-Za-z-]+)\s*(?P<num>\d{1,3}(?:/\d{1,3}){0,2})(?:\s*-\s*(?P<end>\d{1,3}))?$")
_IFNAME = re.compile(r"^(?:[A-Za-z][A-Za-z-]{1,30})\d{1,4}(?:/\d{1,3}){0,2}(?:\.\d{1,4})?$")
_VRF = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


class WiredConfigError(ValueError):
    """A port plan EasyEAP won't generate configuration for, with the field it concerns."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field


@dataclass(frozen=True)
class PortRange:
    kind: str     # canonical type, e.g. GigabitEthernet
    prefix: str   # everything before the last number, e.g. "1/0/"
    start: int
    end: int

    def text(self) -> str:
        return f"{self.kind}{self.prefix}{self.start}" + (f" - {self.end}" if self.end != self.start else "")

    def ports(self) -> set[tuple[str, str, int]]:
        return {(self.kind, self.prefix, n) for n in range(self.start, self.end + 1)}


def parse_ports(text: str, field: str = "interfaces") -> list[PortRange]:
    """Parse "Gi1/0/1-24, Gi2/0/1 - 48, Te1/1/3" into validated ranges. Raises WiredConfigError."""
    out: list[PortRange] = []
    for raw in (p.strip() for p in re.split(r"[,\n;]+", text or "")):
        if not raw:
            continue
        mt = _ITEM.match(raw)
        if not mt:
            raise WiredConfigError(field, f"“{raw}” isn't an interface or range. Write it as on the switch, for example GigabitEthernet1/0/1 - 24.")
        t = mt.group("type").lower()
        if t in FORBIDDEN:
            raise WiredConfigError(field, f"“{raw}” is {FORBIDDEN[t]}. Only access ports can use 802.1X.")
        kind = PORT_TYPES.get(t)
        if kind is None:
            raise WiredConfigError(field, f"“{raw}”: EasyEAP doesn't know the interface type “{mt.group('type')}”.")
        num = mt.group("num")
        prefix, _, last = num.rpartition("/")
        prefix = prefix + "/" if prefix else ""
        start = int(last)
        end = int(mt.group("end")) if mt.group("end") else start
        if end < start:
            raise WiredConfigError(field, f"“{raw}”: the range ends before it starts.")
        if kind == "GigabitEthernet" and prefix == "0/" and start == 0:
            raise WiredConfigError(field, "GigabitEthernet0/0 is the management port. Leave it out.")
        out.append(PortRange(kind, prefix, start, end))
    total = sum(r.end - r.start + 1 for r in out)
    if total > MAX_PORTS:
        raise WiredConfigError(field, f"That's {total} ports; EasyEAP configures at most {MAX_PORTS} per switch.")
    return out


def ranges_text(ranges: list[PortRange]) -> str:
    return ", ".join(r.text() for r in ranges)


def access_ranges(interfaces: str, exclude: str = "") -> list[PortRange]:
    """The ports EasyEAP configures: the access ports minus the ports to leave alone, as contiguous ranges in the order
    they were listed. "Gi1/0/1-48" leaving "Gi1/0/48" alone is "GigabitEthernet1/0/1 - 47"."""
    skip = set().union(*(r.ports() for r in parse_ports(exclude, "exclude"))) if exclude else set()
    groups: dict[tuple[str, str], set[int]] = {}
    for r in parse_ports(interfaces, "interfaces"):
        groups.setdefault((r.kind, r.prefix), set()).update(n for n in range(r.start, r.end + 1) if (r.kind, r.prefix, n) not in skip)
    out: list[PortRange] = []
    for (kind, prefix), nums in groups.items():
        run: list[int] = []
        for n in sorted(nums):
            if run and n != run[-1] + 1:
                out.append(PortRange(kind, prefix, run[0], run[-1]))
                run = []
            run.append(n)
        if run:
            out.append(PortRange(kind, prefix, run[0], run[-1]))
    return out


_PORTNAME = re.compile(r"^(?P<type>[A-Za-z][A-Za-z-]*?)\s*(?P<num>\d{1,4}(?:/\d{1,4}){0,3})$")


def canonical_port(name: str | None) -> str:
    """One spelling per port, shared by the port plan, RADIUS's NAS-Port-Id and SNMP's ifName: `Gi1/0/5`,
    `gi1/0/5` and `GigabitEthernet1/0/5` are all `GigabitEthernet1/0/5`. Other interfaces come back as given."""
    raw = (name or "").strip()
    mt = _PORTNAME.match(raw)
    kind = PORT_TYPES.get(mt.group("type").lower()) if mt else None
    return f"{kind}{mt.group('num')}" if mt and kind else raw


def planned_ports(profile: dict | None) -> set[str]:
    """The canonical names of the ports a switch's plan configures (access ports minus those left alone)."""
    p = profile or {}
    if not p.get("interfaces"):
        return set()
    try:
        ranges = access_ranges(p["interfaces"], p.get("exclude") or "")
    except WiredConfigError:
        return set()
    return {f"{kind}{prefix}{n}" for r in ranges for kind, prefix, n in r.ports()}


def interface_range_lines(ranges: list[PortRange]) -> list[str]:
    """`interface range` commands of at most five ranges each."""
    return ["interface range " + ", ".join(r.text() for r in ranges[i:i + RANGES_PER_LINE]) for i in range(0, len(ranges), RANGES_PER_LINE)]


class WiredProfile(BaseModel):
    """The port plan for one switch (radius_clients.wired_profile). No secrets."""

    # Cisco: the configuration language (docs/plans/cisco-platforms.md §2). IOS-XE IBNS 2.0, classic IOS, NX-OS or
    # Cisco Business; with the series and release where features differ (empty: unknown).
    platform: Literal["ibns2", "classic", "nxos", "cbs"] = "ibns2"
    series: str = Field(default="", max_length=16)
    version: str = Field(default="", max_length=cp.VERSION_MAX)
    lan_lite: bool = False
    mode: Literal["monitor", "enforce"] = "monitor"
    interfaces: str = Field(default="", max_length=2000)  # access ports EasyEAP configures
    exclude: str = Field(default="", max_length=2000)     # ports to leave alone: uplinks, APs, printers, phones
    has_aaa: bool = False                                 # the switch already runs `aaa new-model`
    host_mode: Literal["multi-auth", "single-host", "multi-host"] = "multi-auth"
    no_supplicant: Literal["block", "vlan"] = "block"     # devices without 802.1X once enforced
    no_supplicant_vlan: int | None = Field(default=None, ge=1, le=4094)
    server_down: Literal["wait", "open", "vlan"] = "wait"  # new devices while EasyEAP is unreachable
    server_down_vlan: int | None = Field(default=None, ge=1, le=4094)
    access_vlan: int | None = Field(default=None, ge=1, le=4094)  # None: keep each port's VLAN
    source_interface: str = Field(default="", max_length=40)
    vrf: str = Field(default="", max_length=32)
    fallback_vlan: int | None = Field(default=None, ge=1, le=4094)  # UniFi: where rejected or 802.1X-less devices go
    # MAC authentication (docs/plans/mac-auth.md): devices without 802.1X are checked against the MAC allow list.
    # Changed only in monitor mode, through its own change (POST …/mab), never with a port plan edit.
    mab: bool = False
    mode_set_at: str | None = None
    mode_set_by: str | None = None
    # IBNS 2.0: the control policy EasyEAP's latest change attaches to the ports, the one it replaced, and which change
    # that was. Policy names carry a hash of their content (§6.1 of the MAC plan), so a change is always "define the new
    # policy, swap it in, remove the old one" and never an edit of an attached policy, which IOS would merge.
    policy: str | None = Field(default=None, max_length=64)
    policy_prev: str | None = Field(default=None, max_length=64)
    last_change: Literal["created", "mab", "enforce", "monitor"] | None = None

    @field_validator("version")
    @classmethod
    def _version(cls, v: str) -> str:
        v = v.strip()
        if v and not cp.clean_version(v):
            raise ValueError("Enter the version as the switch shows it, for example 15.2(7)E3, 17.9.4a or 9.3(8).")
        return v

    @field_validator("source_interface")
    @classmethod
    def _source(cls, v: str) -> str:
        v = v.strip()
        if v and not _IFNAME.match(v):
            raise ValueError("Enter an interface name such as Vlan10 or Loopback0.")
        return v

    @field_validator("vrf")
    @classmethod
    def _vrf(cls, v: str) -> str:
        v = v.strip()
        if v and not _VRF.match(v):
            raise ValueError("A VRF name has letters, digits, dot, dash and underscore only.")
        return v

    @model_validator(mode="after")
    def _choices(self) -> WiredProfile:
        if self.no_supplicant == "vlan" and self.no_supplicant_vlan is None:
            raise ValueError("Choose the VLAN for devices without 802.1X.")
        if self.server_down == "vlan" and self.server_down_vlan is None:
            raise ValueError("Choose the VLAN for new devices while EasyEAP is unreachable.")
        return self


HOST_MODE_WORDS = {"multi-auth": "each device authenticates (multi-auth)", "single-host": "one device per port (single-host)",
                   "multi-host": "the first device opens the port (multi-host)"}
PORT_KINDS = {"nxos": {"Ethernet"}, "cbs": set(SX_SHORT)}


def _check_ports(platform: str, ranges: list[PortRange], field: str) -> None:
    allowed = PORT_KINDS.get(platform)
    for r in ranges:
        if allowed is not None and r.kind not in allowed:
            want = "Ethernet1/1 - 48" if platform == "nxos" else "gi1/0/1 - 24"
            raise WiredConfigError(field, f"“{r.text()}” isn't a port name this switch uses. Write them as it does, for example {want}.")
        if allowed is None and r.kind == "Ethernet":
            raise WiredConfigError(field, f"“{r.text()}”: Catalyst switches don't name access ports Ethernet. Write them as the switch does, for example GigabitEthernet1/0/1 - 24.")


def check_capabilities(vendor: str, p: WiredProfile) -> None:
    """Refuse plan choices the switch can't carry out, saying why. Rules: app/radius/cisco_platforms.py."""
    c = cp.caps(p.platform, p.series, p.version, p.lan_lite, vendor)
    if p.host_mode not in c.host_modes:
        raise WiredConfigError("host_mode", "This switch can't do that host mode. Choose: " + ", ".join(HOST_MODE_WORDS[h] for h in c.host_modes) + ".")
    if p.server_down not in c.server_down:
        choices = {"wait": "wait", "open": "allow on the port's VLAN", "vlan": "allow on a VLAN"}
        raise WiredConfigError("server_down", "While EasyEAP is unreachable this switch can only: " + " or ".join(choices[x] for x in c.server_down) + ".")
    if p.no_supplicant == "vlan" and not c.no_supplicant_vlan:
        raise WiredConfigError("no_supplicant", "This switch has no VLAN for devices without 802.1X: they're blocked once enforced"
                               + (", unless they're on the MAC allow list." if c.mab else "."))
    if (p.platform == "classic" and c.dialect == "authmgr" and p.no_supplicant == "vlan" and p.host_mode == "multi-auth"
            and cp.at_least("classic", p.version, "15.2(7)E") is False):
        raise WiredConfigError("no_supplicant", f"IOS {p.version} has no VLAN for devices without 802.1X on multi-auth ports (Cisco documents "
                               "it from 15.2(7)E). Choose single-host or multi-host, or block them.")
    if p.platform == "classic" and c.dialect == "dot1x" and c.mab is None:
        raise WiredConfigError("version", f"IOS {p.version} is older than 12.2(25)SEE, which EasyEAP needs (MAC authentication bypass, "
                               "dot1x pae). Upgrade the switch.")


def validate_profile(vendor: str, data: dict) -> dict:
    """Validate and normalise a port plan for a switch of this vendor. Raises WiredConfigError or pydantic's error."""
    p = WiredProfile.model_validate(data)
    if vendor not in ("cisco-switch", "unifi", "meraki"):
        p.mab = False  # MAC authentication is generated for Cisco and UniFi switches only
    if vendor == "meraki":
        p.platform, p.lan_lite, p.version = "ibns2", False, ""
        p.series = p.series if p.series in cp.SERIES["meraki"] else "ms"
        p.interfaces = p.exclude = ""
    if vendor == "cisco-switch":
        if p.version and not cp.version_fits(p.platform, p.version):
            # A release from another family (left over from a family change, or pasted for the wrong switch) would be
            # read as unknown, or worse, compared as if it were this family's.
            raise WiredConfigError("version", f"“{p.version}” isn't how {cp.PLATFORM_LABELS[p.platform]} numbers its releases "
                                   f"(for example {cp.VERSION_EXAMPLES[p.platform]}). Paste show version again, or clear it.")
        if p.platform in ("nxos", "cbs") and p.series not in cp.SERIES[p.platform]:
            raise WiredConfigError("series", "Choose the switch's model family.")
        if p.platform not in ("nxos", "cbs"):
            p.series = ""
        if p.platform != "classic":
            p.lan_lite = False
        ranges = parse_ports(p.interfaces, "interfaces")
        if not ranges:
            raise WiredConfigError("interfaces", "List the access ports to configure, for example GigabitEthernet1/0/1 - 24.")
        exclude = parse_ports(p.exclude, "exclude")
        _check_ports(p.platform, ranges, "interfaces")
        _check_ports(p.platform, exclude, "exclude")
        # Ports to leave alone are skipped even inside the access-port ranges ("Gi1/0/1-48" leaving the uplink 48 alone).
        if not access_ranges(p.interfaces, p.exclude):
            raise WiredConfigError("exclude", "Every access port is also in “Ports to leave alone”, so there's nothing to configure.")
        p.interfaces, p.exclude = ranges_text(ranges), ranges_text(exclude)
    if vendor in ("cisco-switch", "meraki"):
        check_capabilities(vendor, p)
        c = cp.caps(p.platform, p.series, p.version, p.lan_lite, vendor)
        if c.mab is None:
            p.mab = False
        elif c.monitor == "server":
            p.mab = True  # how devices without 802.1X keep working in monitor mode (§4)
    return p.model_dump()


# ── Cisco ────────────────────────────────────────────────────────────────────


@dataclass
class Ctx:
    name: str        # RADIUS server name on the switch
    server: str      # EasyEAP's RADIUS address
    auth: int
    acct: int
    p: WiredProfile
    switch: str
    admin: bool = False  # admin logins over TACACS+ are on (app/admin/cisco.py owns the login and exec lists)
    caps: cp.Caps | None = None

    def __post_init__(self) -> None:
        if self.caps is None:
            self.caps = cp.caps(self.p.platform, self.p.series, self.p.version, self.p.lan_lite)


def _ctx(client: m.RadiusClient | None, profile: dict, settings: m.RadiusSettings, radius_ip: str, tenant: m.Tenant,
         vendor: str = "cisco-switch") -> Ctx:
    auth, acct = (settings.auth_port, settings.acct_port) if settings.dedicated_ports else (1812, 1813)
    p = WiredProfile.model_validate(profile)
    return Ctx(name=f"EASYEAP-{tenant.slug.upper()}"[:31], server=radius_ip or "<easyeap-radius-ip>", auth=auth, acct=acct,
               p=p, switch=(client.name if client else "this switch"), admin=bool(getattr(client, "admin_enabled", False)),
               caps=cp.caps(p.platform, p.series, p.version, p.lan_lite, vendor))


def preflight(c: Ctx, vendor: str) -> list[dict]:
    """Commands to run before pasting anything, and what each answer means (IOS and IOS-XE)."""
    if vendor != "cisco-switch":
        return []
    vrf = f" vrf {c.p.vrf}" if c.p.vrf else ""
    src = f" source {c.p.source_interface}" if c.p.source_interface else ""
    which = ("IOS-XE " + c.p.version) if c.p.platform == "ibns2" and c.p.version else ("IOS " + c.p.version) if c.p.version else ""
    existing = ("show running-config | include dot1x|access-session|authentication port-control|policy-map type control"
                if c.caps.dialect != "dot1x" else "show running-config | include dot1x")
    return [
        {"command": "show version", "look_for": (f"The version EasyEAP built this for: {which}. If it's different, change it in the switch's settings first: "
                                                 "commands differ between releases." if which else
                                                 "Paste it into EasyEAP's switch settings (“Detect from show version”): commands differ between releases, "
                                                 "and EasyEAP otherwise assumes a recent one.")},
        {"command": "show running-config | include ^aaa new-model", "look_for": "“aaa new-model”: AAA is on, so tick “Already uses AAA”. "
                    "Nothing (or “no aaa new-model”, which the ^ should already hide): AAA is off, leave it unticked."},
        {"command": existing,
         "look_for": "Must print nothing. If it prints anything, this switch already has 802.1X: stop here and merge by hand (docs/controllers/cisco-catalyst-switch.md)."},
        {"command": "show interfaces trunk", "look_for": "Trunk ports are uplinks or AP ports. Put them in “Leave alone”."},
        {"command": "show monitor session all",
         "look_for": "Destination Ports: a port listed there is a SPAN destination. The switch doesn't run 802.1X on it (and it doesn't "
                     "forward traffic) until the monitor session is removed: leave it out of the plan, or remove the session first "
                     "(no monitor session <number>). “No SPAN configuration”: nothing to do."},
        {"command": "show cdp neighbors", "look_for": "Switches, routers, access points and phones you see here: put their ports in “Leave alone”. (Or show lldp neighbors.)"},
        {"command": "show users", "look_for": "Your own session. If you're on a switch port (not the management network), find it with show mac address-table address <your-mac> and leave it alone."},
        {"command": f"ping{vrf} {c.server}{src}", "look_for": "Replies. Without them RADIUS can't reach EasyEAP; check routing, the source interface and the VRF first."},
    ]


def _aaa_block(c: Ctx, accounting: str | None) -> list[str]:
    p = c.p
    out = []
    if c.admin:
        # Regenerating this configuration must never put `login default local` back over the TACACS+ lists.
        out += ["! Admin logins come from EasyEAP device administration: its login and exec lists are left as they are.",
                "aaa new-model",
                "!"]
    elif not p.has_aaa:
        out += ["! This switch doesn't use AAA yet. aaa new-model changes how logins work, so keep logging in with the",
                "! switch's local users (make sure one exists: show running-config | include ^username).",
                "aaa new-model",
                "aaa authentication login default local",
                "aaa authorization exec default local",
                "!"]
    else:
        # Every aaa and radius server command below needs it; entering it again on a switch that has it changes nothing.
        out += ["! The switch already uses AAA: its login and exec lists are left exactly as they are.",
                "aaa new-model",
                "!"]
    if c.caps.named_radius:
        out += [f"radius server {c.name}",
                f" address ipv4 {c.server} auth-port {c.auth} acct-port {c.acct}",
                f" key 0 {SECRET_PLACEHOLDER}",
                " timeout 5",
                " retransmit 2",
                "!",
                "aaa group server radius EASYEAP",
                f" server name {c.name}"]
        if c.p.platform == "classic":
            # Classic IOS: Cisco's Catalyst access-switch guides give the dead time and the source interface only in
            # their global form (research ios.md), so these are the ones a 15.x image is sure to take.
            if p.vrf:
                out.append(f" ip vrf forwarding {p.vrf}")
            out += ["!", "radius-server deadtime 3"]
            if p.source_interface:
                out.append(f"ip radius source-interface {p.source_interface}")
            if p.vrf:
                out.append("! The VRF line needs an IP Services image on classic Catalyst switches.")
        else:
            out.append(" deadtime 3")
            if p.source_interface:
                out.append(f" ip radius source-interface {p.source_interface}")
            if p.vrf:
                out.append(f" ip vrf forwarding {p.vrf}")
        out.append("!")
    else:
        # Classic IOS (and IOS-XE before 3.6E): the host form every release has. The key goes last; the group repeats
        # the ports, or it refers to another entry for the same address (Cisco's 12.2SE–15.2(7)E guides).
        out += [f"radius-server host {c.server} auth-port {c.auth} acct-port {c.acct} timeout 5 retransmit 2 key {SECRET_PLACEHOLDER}",
                "!",
                "aaa group server radius EASYEAP",
                f" server {c.server} auth-port {c.auth} acct-port {c.acct}"]
        if p.vrf:
            out.append(f" ip vrf forwarding {p.vrf}")
        out += ["!", "radius-server deadtime 3"]
        if p.source_interface:
            out.append(f"ip radius source-interface {p.source_interface}")
        if p.vrf:
            out.append("! The VRF line needs an IP Services image on classic Catalyst switches.")
        out.append("!")
    out += ["aaa authentication dot1x default group EASYEAP",
            "aaa authorization network default group EASYEAP"]
    if accounting:
        out.append(f"aaa accounting {accounting} default start-stop group EASYEAP")
    out.append("!")
    if c.caps.coa:
        out += ["! Change of Authorization: lets EasyEAP end a revoked device's session (UDP 1700).",
                "aaa server radius dynamic-author",
                f" client {c.server}" + (f" vrf {p.vrf}" if p.vrf else "") + f" server-key 0 {SECRET_PLACEHOLDER}",
                " auth-type any",
                "!"]
    if c.caps.dead_criteria:
        out += ["! A server that doesn't answer 3 tries within 5 s is marked dead for 3 minutes (deadtime above).",
                "radius-server dead-criteria time 5 tries 3"]
    if c.caps.attr31:
        out.append("radius-server attribute 31 mac format ietf upper-case")
    out += ["radius-server vsa send authentication",
            "radius-server vsa send accounting",
            "!",
            "dot1x system-auth-control",
            "!"]
    return out


def _port_common(p: WiredProfile) -> list[str]:
    out = [" switchport mode access"]
    if p.access_vlan:
        out.append(f" switchport access vlan {p.access_vlan}")
    return out


def _ibns2_failure_classes(p: WiredProfile, enforce: bool, open_tpl: str) -> list[str]:
    """`event authentication-failure` entries. Connected devices always keep working while EasyEAP is unreachable.
    With MAC authentication, a device that doesn't answer 802.1X gets MAB; one that answers and fails never does."""
    out = [" event authentication-failure match-first",
           "  5 class AAA_SVR_DOWN_AUTHD_HOST do-until-failure",
           "   10 pause reauthentication",
           "   20 authorize"]
    if enforce and p.server_down != "wait":
        tpl = "EASYEAP_CRITICAL" if p.server_down == "vlan" else open_tpl
        out += ["  10 class AAA_SVR_DOWN_UNAUTHD_HOST do-until-failure",
                f"   10 activate service-template {tpl}",
                "   20 authorize",
                "   30 pause reauthentication"]
    if p.mab:
        out += ["  20 class DOT1X_NO_RESP do-until-failure",
                "   10 terminate dot1x",
                "   20 authenticate using mab priority 20",
                "  30 class MAB_FAILED do-until-failure",
                "   10 terminate mab"]
        # Not on the allow list: the unknown-device VLAN, or nothing until the next try.
        out += (["   20 activate service-template EASYEAP_NO_8021X", "   30 authorize"] if enforce and p.no_supplicant == "vlan"
                else ["   20 authentication-restart 300"])
        out += ["  40 class always do-until-failure",
                "   10 terminate dot1x",
                "   20 terminate mab",
                "   30 authentication-restart 300"]
        return out
    if enforce and p.no_supplicant == "vlan":
        out += ["  20 class DOT1X_NO_RESP do-until-failure",
                "   10 terminate dot1x",
                "   20 activate service-template EASYEAP_NO_8021X",
                "   30 authorize"]
    out += ["  40 class always do-until-failure",
            "   10 terminate dot1x",
            "   20 authentication-restart 300"]
    return out


# Before EASYEAP_CRITICAL_OPEN, "allow on the port's VLAN" activated this template. A switch enforced with it keeps
# its policy (and name) until its next change, so EasyEAP never redefines an attached policy under a new name.
LEGACY_OPEN = "DEFAULT_CRITICAL_DATA_TEMPLATE"


def _ibns2_body(p: WiredProfile, enforce: bool, open_tpl: str = "") -> list[str]:
    """The policy's content, without its name."""
    open_tpl = open_tpl or CRITICAL_OPEN
    agent_found = (["   10 terminate mab", "   20 authenticate using dot1x priority 10"] if p.mab
                   else ["   10 authenticate using dot1x priority 10"])
    return [" event session-started match-all",
            "  10 class always do-until-failure",
            "   10 authenticate using dot1x priority 10",
            *_ibns2_failure_classes(p, enforce, open_tpl),
            " event agent-found match-all",
            "  10 class always do-until-failure",
            *agent_found,
            " event aaa-available match-all",
            "  10 class IN_CRITICAL_AUTH do-until-failure",
            "   10 clear-session",
            "  20 class NOT_IN_CRITICAL_AUTH do-until-failure",
            "   10 resume reauthentication",
            " event inactivity-timeout match-all",
            "  10 class always do-until-failure",
            "   10 clear-session",
            " event violation match-all",
            "  10 class always do-until-failure",
            "   10 restrict"]


def _named(prefix: str, body: list[str]) -> str:
    digest = hashlib.sha256("\n".join(body).encode()).hexdigest()[:8].upper()
    return f"{prefix}_{digest}"


def monitor_policy(p: WiredProfile) -> str:
    """Name of the monitor-mode control policy for this plan: EASYEAP_MONITOR_<hash of its content>."""
    return _named("EASYEAP_MONITOR", _ibns2_body(p, enforce=False))


def _closed_tpl(p: WiredProfile) -> str:
    """The open-critical template the closed policy uses: the legacy one when the attached policy was built with it."""
    if p.server_down == "open" and p.policy and p.policy == _named("EASYEAP_CLOSED", _ibns2_body(p, True, LEGACY_OPEN)):
        return LEGACY_OPEN
    return CRITICAL_OPEN


def closed_policy(p: WiredProfile) -> str:
    return _named("EASYEAP_CLOSED", _ibns2_body(p, True, _closed_tpl(p)))


def _ibns2_policy(p: WiredProfile, enforce: bool) -> list[str]:
    name = closed_policy(p) if enforce else monitor_policy(p)
    return [f"policy-map type control subscriber {name}", *_ibns2_body(p, enforce, _closed_tpl(p) if enforce else ""), "!"]


# "EasyEAP unreachable, allow on the port's VLAN": a template of EasyEAP's own (Cisco documents no built-in templates), defined
# before the classes that match it.
CRITICAL_OPEN = "EASYEAP_CRITICAL_OPEN"
CRITICAL_OPEN_TEMPLATE = [f"service-template {CRITICAL_OPEN}", " description EasyEAP unreachable: authorized on the port's VLAN", "!"]

IBNS2_CLASSES = [
    *CRITICAL_OPEN_TEMPLATE,
    "class-map type control subscriber match-all AAA_SVR_DOWN_AUTHD_HOST",
    " match result-type aaa-timeout",
    " match authorization-status authorized",
    "!",
    "class-map type control subscriber match-all AAA_SVR_DOWN_UNAUTHD_HOST",
    " match result-type aaa-timeout",
    " match authorization-status unauthorized",
    "!",
    "class-map type control subscriber match-all DOT1X_NO_RESP",
    " match method dot1x",
    " match result-type method dot1x agent-not-found",
    "!",
    "class-map type control subscriber match-any IN_CRITICAL_AUTH",
    f" match activated-service-template {CRITICAL_OPEN}",
    "!",
    "class-map type control subscriber match-none NOT_IN_CRITICAL_AUTH",
    f" match activated-service-template {CRITICAL_OPEN}",
    "!",
]


# Defined only once MAC authentication is on (re-pasting a class-map with the same match lines changes nothing).
MAB_CLASSES = [
    "class-map type control subscriber match-all MAB_FAILED",
    " match method mab",
    " match result-type method mab authoritative",
    "!",
]


def _classes(p: WiredProfile) -> list[str]:
    return IBNS2_CLASSES + (MAB_CLASSES if p.mab else [])


def _service_templates(p: WiredProfile) -> list[str]:
    # A switch first configured before EASYEAP_CRITICAL_OPEN existed gets it (and its class matches) now; re-entering
    # an existing template or match line changes nothing.
    out = [*CRITICAL_OPEN_TEMPLATE,
           "class-map type control subscriber match-any IN_CRITICAL_AUTH", f" match activated-service-template {CRITICAL_OPEN}", "!",
           "class-map type control subscriber match-none NOT_IN_CRITICAL_AUTH", f" match activated-service-template {CRITICAL_OPEN}", "!"]
    if p.server_down == "vlan" and p.server_down_vlan:
        # The template exists only from here on, so the critical-session classes learn it now.
        out += ["service-template EASYEAP_CRITICAL", f" vlan {p.server_down_vlan}", "!",
                "class-map type control subscriber match-any IN_CRITICAL_AUTH", " match activated-service-template EASYEAP_CRITICAL", "!",
                "class-map type control subscriber match-none NOT_IN_CRITICAL_AUTH", " match activated-service-template EASYEAP_CRITICAL", "!"]
    if p.no_supplicant == "vlan" and p.no_supplicant_vlan:
        out += ["service-template EASYEAP_NO_8021X", f" vlan {p.no_supplicant_vlan}", "!"]
    return out


SAFE_PASTE = [
    "In exec mode: reload in 15   (if you lose access, the switch reverts to its saved configuration in 15 minutes)",
    "configure terminal, paste the configuration, then end",
    "Open a NEW SSH session to the switch. If you can log in: reload cancel",
    "write memory",
]
# IOS-XE asks once, with a yes/no prompt, before it takes its first control policy (the switch moves to the new-style
# configuration for good); inside a paste, the prompt would take the next pasted line as its answer.
IBNS2_SAFE_PASTE = [SAFE_PASTE[0],
                    "In exec mode: authentication convert-to new-style, and answer yes   (IOS-XE asks this once, before the "
                    "first control policy; answered now, it can't take a line of the paste as its answer. Releases without "
                    "the command: authentication display new-style. If the switch doesn't offer either, it already uses the "
                    "new style: carry on.)",
                    *SAFE_PASTE[1:]]


def _ibns2_ports(p: WiredProfile) -> list[str]:
    out = [" access-session host-mode " + p.host_mode,
           " access-session port-control auto",
           " authentication periodic",
           " authentication timer reauthenticate server",
           " dot1x pae authenticator",
           " dot1x timeout tx-period 10"]
    if p.mab:
        out += MAB_PORT_IBNS2
    return [*out, " spanning-tree portfast", " spanning-tree bpduguard enable"]


# MAC authentication on a port: MAB after 802.1X gets no answer (two EAP requests 10 s apart, about 30 s after link-up).
MAB_PORT_IBNS2 = [" mab", " dot1x max-reauth-req 2"]
MAB_PORT_CLASSIC = [" authentication order dot1x mab", " authentication priority dot1x mab", " mab", " dot1x max-reauth-req 2",
                    " authentication timer restart 300"]
MAB_PORT_IBNS2_OFF = [" no mab", " no dot1x max-reauth-req"]
MAB_PORT_CLASSIC_OFF = [" no authentication order", " no authentication priority", " no mab", " no dot1x max-reauth-req",
                        " no authentication timer restart"]


def _classic_ports(c: Ctx) -> list[str]:
    """Classic IOS ports in monitor mode: the authentication manager (12.2(50)SE+), or the dot1x commands before it."""
    p = c.p
    if c.caps.dialect == "dot1x":
        # No open mode before 12.2(50)SE: EasyEAP accepts this switch's MAC requests until it's enforced (server-side
        # monitor), so MAC authentication bypass is always on. No multi-auth: multi-host or single-host.
        return [" dot1x pae authenticator",
                " dot1x port-control auto",
                " dot1x host-mode " + p.host_mode,
                " dot1x reauthentication",
                " dot1x timeout reauth-period server",
                " dot1x timeout tx-period 10",
                " dot1x max-reauth-req 2",
                " dot1x mac-auth-bypass",
                " spanning-tree portfast",
                " spanning-tree bpduguard enable"]
    return [" authentication host-mode " + p.host_mode,
            " authentication open",
            " authentication port-control auto",
            " authentication periodic",
            " authentication timer reauthenticate server",
            *([" authentication violation restrict"] if c.caps.violation else []),
            " dot1x pae authenticator",
            " dot1x timeout tx-period 10",
            *(MAB_PORT_CLASSIC if p.mab else []),
            " spanning-tree portfast",
            " spanning-tree bpduguard enable"]


def _reauth_ports(c: Ctx) -> list[str]:
    """`dot1x re-authenticate interface` for each port: the restart Cisco documents on every classic release."""
    return [f"dot1x re-authenticate interface {r.kind}{r.prefix}{n}" for r in access_ranges(c.p.interfaces, c.p.exclude)
            for n in range(r.start, r.end + 1)]


def _restart_classic(c: Ctx, comment: bool = True) -> list[str]:
    if c.caps.dialect == "dot1x":
        return [*(["! Re-authenticate every port's devices:"] if comment else []), *_reauth_ports(c)]
    if not comment:
        return ["clear authentication sessions"]
    return ["! Restart the sessions so devices are re-authenticated and get their VLANs:", "clear authentication sessions",
            "! If the switch doesn't know that command: dot1x re-authenticate interface <port>, for each port"]


def cisco_initial(c: Ctx) -> str:
    """The first paste: AAA, RADIUS and the ports in monitor mode (open, no fallback actions, no VLAN from EasyEAP)."""
    p = c.p
    ranges = access_ranges(p.interfaces, p.exclude)
    head = [f"! EasyEAP: wired 802.1X for {c.switch}, monitor mode",
            "! Ports stay open: devices that fail or don't speak 802.1X keep their access, and EasyEAP logs what it",
            "! would decide without changing any VLAN. Enforce later from EasyEAP (RADIUS → the switch → Enforce).",
            "!"]
    if p.mab:
        head[-1:] = ["! MAC authentication: devices that don't answer 802.1X are checked against EasyEAP's MAC allow list.", "!"]
    if p.platform == "ibns2":
        # aaa accounting identity needs the CLI in policy (new-style) mode, which the first control class or policy
        # turns on for good: so it comes after them.
        body = [*_aaa_block(c, None), *_classes(p), *_ibns2_policy(p, enforce=False),
                "aaa accounting identity default start-stop group EASYEAP", "!"]
        ports = [*_ibns2_ports(p), f" service-policy type control subscriber {monitor_policy(p)}"]
    else:
        body = _aaa_block(c, "dot1x")
        ports = _classic_ports(c)
    if c.caps.monitor == "server":
        head[1:3] = ["! This release has no open mode: the ports run 802.1X, and EasyEAP accepts every MAC request from",
                     "! this switch while it's in monitor mode (no VLAN), logging what it would decide. A device that",
                     "! tries 802.1X and fails is refused. Enforce later from EasyEAP (RADIUS → the switch → Enforce)."]
    lines = head + body
    if p.exclude:
        lines.append(f"! Left alone: {p.exclude}")
    for line in interface_range_lines(ranges):
        lines += [line, *_port_common(p), *ports, "!"]
    lines.append("end")
    return "\n".join(lines)


def attached_policy(p: WiredProfile) -> str:
    """The control policy on the ports after EasyEAP's latest change (IBNS 2.0)."""
    return p.policy or (closed_policy(p) if p.mode == "enforce" else monitor_policy(p))


def _swap(ranges: list[PortRange], old: str, new: str, extra: list[str]) -> list[str]:
    """Attach `new` in place of `old` on every port range, then remove `old`. Never an edit of an attached policy."""
    out = []
    for line in interface_range_lines(ranges):
        out += [line]
        if old != new:
            out.append(f" no service-policy type control subscriber {old}")
        out += [f" service-policy type control subscriber {new}", *extra, "!"]
    if old != new:
        out.append(f"no policy-map type control subscriber {old}")
    return out


def cisco_enforce(c: Ctx) -> str:
    """Monitor → enforce: ports closed, fallback actions on, and existing sessions restarted so they get VLANs."""
    p = c.p
    ranges = access_ranges(p.interfaces, p.exclude)
    lines = [f"! EasyEAP: enforce wired 802.1X on {c.switch}",
             "! After this, a port lets traffic through only once its device is accepted.", "!"]
    if p.server_down != "wait" and c.caps.critical_eapol:
        lines += ["! EasyEAP unreachable: authorize new devices (critical access) and let them retry once it's back.",
                  "dot1x critical eapol", "!"]
    if p.platform == "ibns2":
        old = attached_policy(p) if p.mode == "monitor" else (p.policy_prev if p.last_change == "enforce" and p.policy_prev else monitor_policy(p))
        lines += (MAB_CLASSES if p.mab else []) + _service_templates(p) + _ibns2_policy(p, enforce=True)
        lines += _swap(ranges, old, closed_policy(p), [" access-session closed"])
        lines += ["end", "! Restart the sessions so devices are re-authenticated and get their VLANs:", "clear access-session"]
    else:
        for line in interface_range_lines(ranges):
            lines += [line, *([] if c.caps.dialect == "dot1x" else [" no authentication open"]), *_classic_actions(c, ""), "!"]
        if c.caps.monitor == "server":
            lines.insert(2, "! EasyEAP also stops accepting MAC requests it would refuse: devices not on the MAC allow list lose access.")
        lines += ["end", *_restart_classic(c)]
    return "\n".join(lines)


def _classic_actions(c: Ctx, prefix: str) -> list[str]:
    """Classic fallback actions added by Enforce; with prefix "no " the exact commands that remove them."""
    p = c.p
    out = []
    # Before 12.2(55)SE (and before the authentication manager) critical access is the dot1x critical commands: the
    # 12.2(50)SE guide still uses them, and `server dead action authorize vlan` is documented from 12.2(55)SE.
    old_critical = c.caps.dialect == "dot1x" or cp.at_least("classic", p.version, "12.2(55)SE") is False
    if old_critical and p.server_down != "wait":
        out.append(" dot1x critical")
        if p.server_down == "vlan":
            out.append(f" dot1x critical vlan {p.server_down_vlan}")
        out.append(" dot1x critical recovery action reinitialize")
    if c.caps.dialect == "dot1x":
        if p.no_supplicant == "vlan":
            out.insert(0, f" dot1x guest-vlan {p.no_supplicant_vlan}")
        return [" " + prefix + x.lstrip() for x in out]
    # Multi-auth ports: Cisco's guides (12.2(52)SE on) give `reinitialize vlan` for critical access. Only when the
    # release is known: switches configured before EasyEAP knew it keep the form they were given.
    reinit = p.host_mode == "multi-auth" and cp.at_least("classic", p.version, "12.2(52)SE") is True
    if old_critical:
        pass
    elif p.server_down == "open":
        out.append(f" authentication event server dead action reinitialize vlan {p.access_vlan}" if reinit and p.access_vlan
                   else " authentication event server dead action authorize")
    elif p.server_down == "vlan":
        out.append(f" authentication event server dead action {'reinitialize' if reinit else 'authorize'} vlan {p.server_down_vlan}")
    if p.server_down != "wait" and not old_critical:
        out.append(" authentication event server alive action reinitialize")
    if p.no_supplicant == "vlan":
        # With MAC authentication, also where devices that aren't on the allow list go.
        out.append(f" authentication event no-response action authorize vlan {p.no_supplicant_vlan}")
    return [" " + prefix + x.lstrip() for x in out]


def cisco_monitor(c: Ctx) -> str:
    """Enforce → monitor: ports open again and the fallback actions off."""
    p = c.p
    ranges = access_ranges(p.interfaces, p.exclude)
    lines = [f"! EasyEAP: back to monitor mode on {c.switch}", "! Ports open again; EasyEAP stops sending VLANs to this switch.", "!"]
    if p.platform == "ibns2":
        old = attached_policy(p) if p.mode == "enforce" else (p.policy_prev if p.last_change == "monitor" and p.policy_prev else closed_policy(p))
        lines += _classes(p) + _ibns2_policy(p, enforce=False)
        lines += _swap(ranges, old, monitor_policy(p), [" no access-session closed"])
        lines += ["end", "clear access-session"]
    else:
        for line in interface_range_lines(ranges):
            lines += [line, *([] if c.caps.dialect == "dot1x" else [" authentication open"]), *_classic_actions(c, "no "), "!"]
        if c.caps.monitor == "server":
            lines.insert(2, "! EasyEAP accepts this switch's MAC requests again while it's in monitor mode.")
        lines += ["end", *_restart_classic(c, comment=False)]
    return "\n".join(lines)


def cisco_mab(c: Ctx) -> str:
    """Turn MAC authentication on or off (to what the plan says now), in monitor mode: ports stay open throughout."""
    p = c.p
    ranges = access_ranges(p.interfaces, p.exclude)
    word = "on" if p.mab else "off"
    lines = [f"! EasyEAP: MAC authentication {word} for {c.switch} (monitor mode: ports stay open)",
             "! Devices that don't answer 802.1X are checked against EasyEAP's MAC allow list; EasyEAP logs each decision." if p.mab
             else "! Devices that don't answer 802.1X are no longer checked by MAC address.", "!"]
    if p.platform == "ibns2":
        flipped = p.model_copy(update={"mab": not p.mab})
        old = p.policy_prev if p.last_change == "mab" and p.policy_prev else monitor_policy(flipped)
        lines += _classes(p) + _ibns2_policy(p, enforce=False)
        lines += _swap(ranges, old, monitor_policy(p), MAB_PORT_IBNS2 if p.mab else MAB_PORT_IBNS2_OFF)
        lines += ["end", "clear access-session"]
    else:
        on, off = ([" dot1x mac-auth-bypass"], [" no dot1x mac-auth-bypass"]) if c.caps.dialect == "dot1x" else (MAB_PORT_CLASSIC, MAB_PORT_CLASSIC_OFF)
        for line in interface_range_lines(ranges):
            lines += [line, *(on if p.mab else off), "!"]
        lines += ["end", *_restart_classic(c, comment=False)]
    return "\n".join(lines)


def session_command(profile: dict, vendor: str = "cisco-switch") -> str | None:
    c = cp.caps_for(vendor, profile)
    return c.session_command if c else None


# ── Guides ───────────────────────────────────────────────────────────────────


def _checks(c: Ctx, vlans: list[m.Vlan], vendor: str = "cisco-switch") -> list[str]:
    assigned = sorted({v.wired_vlan_id if v.wired_mode == "vlan" else v.vlan_id for v in vlans if v.wired_mode != "port"})
    out = ["Monitor mode first. Watch the Authentication log (Network: Wired) for a few days: every device that should be on the "
           "network must show as accepted before you enforce."]
    exists = {"cisco-switch": "switch (show vlan brief)", "unifi": "switch as a network (UniFi Network → Settings → Networks)"}.get(vendor, "switch")
    if assigned:
        out.append("Once enforced, EasyEAP assigns VLAN " + ", ".join(map(str, assigned)) + f" on switch ports. Each must exist on this {exists}, "
                   "or the device fails authorization. Change a VLAN's “On switch ports” in Access policy if not.")
    else:
        out.append("EasyEAP assigns no VLAN on switch ports: each device stays on its port's VLAN.")
    if c.p.mab:
        out.append("Devices without 802.1X (printers, cameras, phones) are checked against the MAC allow list. In monitor mode, the ones "
                   "that aren't on it appear under MAC allow list → Seen, not allowed; allow them there before you enforce.")
        out.append("A MAC address is easy to copy, so MAC-authenticated devices should get a VLAN that reaches only what they need.")
    else:
        out.append("Printers, cameras, phones and other devices without 802.1X: turn on MAC authentication for this switch, or leave "
                   "their ports out.")
    return out


def _vlan_checks(c: Ctx) -> list[str]:
    """The VLANs the plan names that must exist on the switch (a missing one fails devices, or the paste)."""
    p, out = c.p, []
    if p.server_down == "vlan" and p.server_down_vlan:
        out.append(f"VLAN {p.server_down_vlan} (new devices while EasyEAP is unreachable) must exist on the switch.")
    if p.no_supplicant == "vlan" and p.no_supplicant_vlan:
        out.append(f"VLAN {p.no_supplicant_vlan} (devices without 802.1X, once enforced) must exist on the switch.")
    return out


def guide(vendor: str, *, client: m.RadiusClient | None, profile: dict, settings: m.RadiusSettings, radius_ip: str,
          vlans: list[m.Vlan], tenant: m.Tenant) -> dict:
    """The wired guide for a switch: preflight, configuration, steps and checks. Also the enforce/monitor changes."""
    c = _ctx(client, profile, settings, radius_ip, tenant, vendor)
    base = {"vendor": vendor, "kind": "wired", "mode": c.p.mode, "coa_port": 1700 if vendor in ("cisco-switch", "meraki") else 3799,
            "radius_address": radius_ip or None}
    if vendor in ("cisco-switch", "meraki"):
        caps = c.caps
        base |= {"capabilities": caps.out(), "notes": caps.notes, "warnings": caps.warnings, "monitor_style": caps.monitor,
                 "mab": c.p.mab, "session_command": caps.session_command}
        checks = _checks(c, vlans, vendor) + _vlan_checks(c)
        mab_latest = c.p.mode == "monitor" and c.p.last_change == "mab"
        paste_steps = ["Run the preflight commands and check each answer.", "Paste the configuration with the safe-paste steps.",
                       "Plug a test device with an EasyEAP certificate into one of the ports and watch for its first request below."]
        if vendor == "meraki":
            from app.radius import wired_meraki as mk
            return {**base, "title": "Cisco Meraki MS switches" + (" (MS130/MS150, open mode)" if caps.monitor == "switch" else ""),
                    "preflight": [], "cli": None, "safe_paste": [], "steps": mk.steps(c), "enforce_steps": mk.enforce_steps(c),
                    "monitor_steps": mk.monitor_steps(c), "checks": checks, "mab_steps": mk.mab_steps(c)}
        if caps.dialect == "nxos":
            from app.radius import wired_nxos as nx
            return {**base, "title": "Cisco Nexus switch (NX-OS" + (f" {c.p.version})" if c.p.version else ")"),
                    "preflight": nx.preflight(c), "cli": nx.initial(c), "safe_paste": nx.SAFE_PASTE, "enforce_cli": nx.enforce(c),
                    "monitor_cli": nx.monitor(c), "mab_cli": None, "steps": paste_steps, "checks": checks}
        if caps.dialect in ("sx", "cbs220", "web"):
            from app.radius import wired_cbs as sb
            title = "Cisco Business switch (" + cp.SERIES_LABELS.get(c.p.series, c.p.series) + ")"
            if caps.dialect == "web":
                return {**base, "title": title, "preflight": [], "cli": None, "safe_paste": [], "steps": sb.web_steps(c),
                        "enforce_steps": [], "monitor_steps": [], "checks": checks, "mab_steps": None}
            return {**base, "title": title, "preflight": sb.preflight(c), "cli": sb.initial(c), "safe_paste": sb.SAFE_PASTE,
                    "enforce_cli": sb.enforce(c), "monitor_cli": sb.monitor(c),
                    "mab_cli": sb.mab(c) if mab_latest and caps.mab else None, "steps": paste_steps, "checks": checks}
        style = ("IOS-XE (IBNS 2.0)" if c.p.platform == "ibns2" else
                 "classic IOS, before the authentication manager" if caps.dialect == "dot1x" else "classic IOS / IOS-XE")
        return {**base, "title": f"Cisco Catalyst switch, {style}", "preflight": preflight(c, vendor), "cli": cisco_initial(c),
                "safe_paste": IBNS2_SAFE_PASTE if c.p.platform == "ibns2" else SAFE_PASTE, "enforce_cli": cisco_enforce(c),
                "monitor_cli": cisco_monitor(c),
                # The MAC authentication change, while it's the latest change in monitor mode.
                "mab_cli": cisco_mab(c) if mab_latest and caps.monitor != "server" else None,
                "steps": paste_steps, "checks": checks}
    if vendor == "unifi":
        fb = c.p.fallback_vlan
        steps = [
            "UniFi Network → Settings → Profiles → RADIUS: open the EasyEAP profile used for Wi-Fi (or create one with "
            f"authentication server {c.server}:{c.auth}, accounting {c.server}:{c.acct} and the shared secret).",
            "In the profile, turn on “RADIUS Assigned VLAN for Wired Network”.",
            "Settings → Networks → Global Switch Settings (Ports Manager in older versions) → 802.1X Control: on, RADIUS profile = the "
            "EasyEAP profile, Fallback VLAN = "
            + (f"{fb}." if fb else "the VLAN your ports use today, so rejected devices keep working while you test (UniFi's monitor mode)."),
            "Devices → the switch → Port Manager: set ONE test port's 802.1X Control to Auto. Leave every other port on Force Authorized.",
            "Plug a test device with an EasyEAP certificate into that port and watch for its first request below.",
            "Then set more ports to Auto. Never the uplink or ports with access points.",
        ]
        if c.p.mab:
            steps += ["MAC authentication: for ports with printers, cameras or other devices without 802.1X, set 802.1X Control to "
                      "MAC-Based (“MAC Address” in some versions). UniFi then sends the device's MAC address, and EasyEAP checks it "
                      "against the MAC allow list. Keep Auto on ports for 802.1X devices."]
        enforce = ["Settings → Networks → Global Switch Settings → 802.1X Control: set the Fallback VLAN to a restricted network "
                   "(internet only, or nothing), because rejected devices also land there.",
                   "Turn ports off and on, or reconnect devices, so they re-authenticate."]
        monitor = ["Set the Fallback VLAN back to the VLAN the ports used before, so rejected devices keep working."]
        checks = [*_checks(c, vlans, vendor),
                  "Not verified on UniFi hardware by EasyEAP: Change of Authorization, re-authentication timing, and the port type UniFi "
                  "reports. Leave CoA off for UniFi and check the first requests' Network column says Wired."]
        if c.p.mab:
            checks.append("Not verified on UniFi hardware by EasyEAP: the attributes of MAC-Based requests. The switch panel shows "
                          "whether MAC requests arrive and how EasyEAP answered them.")
        return {**base, "title": "UniFi switches", "preflight": [], "cli": None, "safe_paste": [], "steps": steps,
                "enforce_steps": enforce, "monitor_steps": monitor, "checks": checks, "session_command": None, "mab": c.p.mab,
                "mab_steps": (["Set 802.1X Control to MAC-Based on the ports with devices that can't do 802.1X."] if c.p.mab else
                              ["Set ports on MAC-Based back to Auto or Force Authorized: EasyEAP now refuses MAC requests from this switch."])
                if c.p.last_change == "mab" else None}
    steps = [f"Add a RADIUS server {c.server}, authentication port {c.auth}, accounting port {c.acct}, with the shared secret.",
             "Make sure 802.1X requests carry Message-Authenticator (EAP requests always do).",
             "Turn on 802.1X (EAP) on one test port first, in a monitor or open mode if the switch has one.",
             "If you want EasyEAP's VLANs, enable dynamic VLAN assignment (Tunnel-Type 13, Tunnel-Medium-Type 6, Tunnel-Private-Group-ID).",
             "If the switch reports NAS-Port-Type = Ethernet (15), EasyEAP recognises wired requests; otherwise register it for Wired only."]
    return {**base, "title": "Other switch", "preflight": [], "cli": None, "safe_paste": [], "steps": steps, "checks": _checks(c, vlans, vendor),
            "session_command": None}


# ── Readiness: what enforcing would cut off ──────────────────────────────────

_SESSION_LINE = re.compile(r"^(?P<intf>(?:[A-Za-z]{2,}[A-Za-z-]*)\d+(?:/\d+){0,3})\s+(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|\(unknown\)|N/A)\s+"
                           r"(?P<method>\S+)\s+(?P<domain>\S+)\s+(?P<status>.+?)\s*(?P<sid>[0-9A-Fa-f]{16,32})?\s*$")


# `show dot1x all summary`: classic IOS before the authentication manager, and NX-OS ("Interface PAE Client Status").
_DOT1X_LINE = re.compile(r"^(?P<intf>(?:[A-Za-z]{2,}[A-Za-z-]*)\d+(?:/\d+){0,3})\s+(?P<pae>AUTH|SUPP|NONE)\s+"
                         r"(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}|none|N/A)\s+"
                         r"(?P<status>[A-Za-z_-]+)\s*$", re.IGNORECASE)


def parse_sessions(text: str) -> list[dict]:
    """Rows of `show access-session` (IBNS 2.0), `show authentication sessions` (classic) or `show dot1x all summary`
    (older classic IOS, NX-OS), with whether each is authorized. Anything else in the paste (headers, prompts, legends)
    is ignored."""
    rows = []
    for line in (text or "").splitlines()[:5000]:
        d = _DOT1X_LINE.match(line.strip())
        if d:
            status = d.group("status")
            rows.append({"interface": d.group("intf"), "mac": d.group("mac"), "method": "dot1x", "domain": "-",
                         "status": status[:40], "authorized": status.upper() == "AUTHORIZED"})
            continue
        mt = _SESSION_LINE.match(line.strip())
        if not mt:
            continue
        status = mt.group("status").strip()
        s = status.lower()
        authorized = ("auth" in s and "unauth" not in s and "fail" not in s) or "success" in s
        rows.append({"interface": mt.group("intf"), "mac": mt.group("mac"), "method": mt.group("method"), "domain": mt.group("domain"),
                     "status": status[:40], "authorized": authorized})
    return rows
