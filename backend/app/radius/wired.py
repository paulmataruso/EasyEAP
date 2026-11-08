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
}
FORBIDDEN = {
    "port-channel": "a port channel (an uplink bundle)", "po": "a port channel (an uplink bundle)",
    "vlan": "a VLAN interface, not a switch port", "vl": "a VLAN interface, not a switch port",
    "loopback": "a loopback interface", "lo": "a loopback interface", "tunnel": "a tunnel interface", "tu": "a tunnel interface",
    "appgigabitethernet": "the application hosting port", "ap": "the application hosting port",
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

    platform: Literal["ibns2", "classic"] = "ibns2"   # Cisco only: IOS-XE IBNS 2.0, or classic IOS / IOS-XE
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


def validate_profile(vendor: str, data: dict) -> dict:
    """Validate and normalise a port plan for a switch of this vendor. Raises WiredConfigError or pydantic's error."""
    p = WiredProfile.model_validate(data)
    if vendor not in ("cisco-switch", "unifi"):
        p.mab = False  # MAC authentication is generated for Cisco Catalyst and UniFi switches only
    if vendor == "cisco-switch":
        ranges = parse_ports(p.interfaces, "interfaces")
        if not ranges:
            raise WiredConfigError("interfaces", "List the access ports to configure, for example GigabitEthernet1/0/1 - 24.")
        exclude = parse_ports(p.exclude, "exclude")
        # Ports to leave alone are skipped even inside the access-port ranges ("Gi1/0/1-48" leaving the uplink 48 alone).
        if not access_ranges(p.interfaces, p.exclude):
            raise WiredConfigError("exclude", "Every access port is also in “Ports to leave alone”, so there's nothing to configure.")
        p.interfaces, p.exclude = ranges_text(ranges), ranges_text(exclude)
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


def _ctx(client: m.RadiusClient | None, profile: dict, settings: m.RadiusSettings, radius_ip: str, tenant: m.Tenant) -> Ctx:
    auth, acct = (settings.auth_port, settings.acct_port) if settings.dedicated_ports else (1812, 1813)
    return Ctx(name=f"EASYEAP-{tenant.slug.upper()}"[:31], server=radius_ip or "<easyeap-radius-ip>", auth=auth, acct=acct,
               p=WiredProfile.model_validate(profile), switch=(client.name if client else "this switch"),
               admin=bool(getattr(client, "admin_enabled", False)))


def preflight(c: Ctx, vendor: str) -> list[dict]:
    """Commands to run before pasting anything, and what each answer means."""
    if vendor != "cisco-switch":
        return []
    vrf = f" vrf {c.p.vrf}" if c.p.vrf else ""
    src = f" source {c.p.source_interface}" if c.p.source_interface else ""
    return [
        {"command": "show version | include IOS", "look_for": "“IOS XE Software, Version 16.”, 17. or 26., or IOS-XE 3.x (“Version 03.0…E” on a "
                    "3650/3850/4500E): use “IOS-XE (IBNS 2.0)”. Classic IOS 12.2 or 15.x (2960, 2960-X, 3560, 3750): use “Classic”."},
        {"command": "show running-config | include ^aaa new-model", "look_for": "“aaa new-model”: AAA is on, so tick “Already uses AAA”. "
                    "Nothing (or “no aaa new-model”, which the ^ should already hide): AAA is off, leave it unticked."},
        {"command": "show running-config | include dot1x|access-session|authentication port-control|policy-map type control",
         "look_for": "Must print nothing. If it prints anything, this switch already has 802.1X: stop here and merge by hand (docs/controllers/cisco-catalyst-switch.md)."},
        {"command": "show interfaces trunk", "look_for": "Trunk ports are uplinks or AP ports. Put them in “Leave alone”."},
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
    out += [f"radius server {c.name}",
            f" address ipv4 {c.server} auth-port {c.auth} acct-port {c.acct}",
            f" key 0 {SECRET_PLACEHOLDER}",
            " timeout 5",
            " retransmit 2",
            "!",
            "aaa group server radius EASYEAP",
            f" server name {c.name}",
            " deadtime 3"]
    if p.source_interface:
        out.append(f" ip radius source-interface {p.source_interface}")
    if p.vrf:
        out.append(f" ip vrf forwarding {p.vrf}")
    out += ["!",
            "aaa authentication dot1x default group EASYEAP",
            "aaa authorization network default group EASYEAP"]
    if accounting:
        out.append(f"aaa accounting {accounting} default start-stop group EASYEAP")
    out += ["!",
            "! Change of Authorization: lets EasyEAP end a revoked device's session (UDP 1700).",
            "aaa server radius dynamic-author",
            f" client {c.server}" + (f" vrf {p.vrf}" if p.vrf else "") + f" server-key 0 {SECRET_PLACEHOLDER}",
            " auth-type any",
            "!",
            "! A server that doesn't answer 3 tries within 5 s is marked dead for 3 minutes (deadtime above).",
            "radius-server dead-criteria time 5 tries 3",
            "radius-server attribute 31 mac format ietf upper-case",
            "radius-server vsa send authentication",
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


def _ibns2_failure_classes(p: WiredProfile, enforce: bool) -> list[str]:
    """`event authentication-failure` entries. Connected devices always keep working while EasyEAP is unreachable.
    With MAC authentication, a device that doesn't answer 802.1X gets MAB; one that answers and fails never does."""
    out = [" event authentication-failure match-first",
           "  5 class AAA_SVR_DOWN_AUTHD_HOST do-until-failure",
           "   10 pause reauthentication",
           "   20 authorize"]
    if enforce and p.server_down != "wait":
        tpl = "EASYEAP_CRITICAL" if p.server_down == "vlan" else "DEFAULT_CRITICAL_DATA_TEMPLATE"
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


def _ibns2_body(p: WiredProfile, enforce: bool) -> list[str]:
    """The policy's content, without its name."""
    agent_found = (["   10 terminate mab", "   20 authenticate using dot1x priority 10"] if p.mab
                   else ["   10 authenticate using dot1x priority 10"])
    return [" event session-started match-all",
            "  10 class always do-until-failure",
            "   10 authenticate using dot1x priority 10",
            *_ibns2_failure_classes(p, enforce),
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


def closed_policy(p: WiredProfile) -> str:
    return _named("EASYEAP_CLOSED", _ibns2_body(p, enforce=True))


def _ibns2_policy(p: WiredProfile, enforce: bool) -> list[str]:
    name = closed_policy(p) if enforce else monitor_policy(p)
    return [f"policy-map type control subscriber {name}", *_ibns2_body(p, enforce), "!"]


IBNS2_CLASSES = [
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
    " match activated-service-template DEFAULT_CRITICAL_DATA_TEMPLATE",
    "!",
    "class-map type control subscriber match-none NOT_IN_CRITICAL_AUTH",
    " match activated-service-template DEFAULT_CRITICAL_DATA_TEMPLATE",
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
    out = []
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
        ports = [" authentication host-mode " + p.host_mode,
                 " authentication open",
                 " authentication port-control auto",
                 " authentication periodic",
                 " authentication timer reauthenticate server",
                 " authentication violation restrict",
                 " dot1x pae authenticator",
                 " dot1x timeout tx-period 10",
                 *(MAB_PORT_CLASSIC if p.mab else []),
                 " spanning-tree portfast",
                 " spanning-tree bpduguard enable"]
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
    if p.server_down != "wait":
        lines += ["! EasyEAP unreachable: authorize new devices (critical access) and let them retry once it's back.",
                  "dot1x critical eapol", "!"]
    if p.platform == "ibns2":
        old = attached_policy(p) if p.mode == "monitor" else (p.policy_prev if p.last_change == "enforce" and p.policy_prev else monitor_policy(p))
        lines += (MAB_CLASSES if p.mab else []) + _service_templates(p) + _ibns2_policy(p, enforce=True)
        lines += _swap(ranges, old, closed_policy(p), [" access-session closed"])
        lines += ["end", "! Restart the sessions so devices are re-authenticated and get their VLANs:", "clear access-session"]
    else:
        for line in interface_range_lines(ranges):
            lines += [line, " no authentication open", *_classic_actions(p, ""), "!"]
        lines += ["end", "! Restart the sessions so devices are re-authenticated and get their VLANs:", "clear authentication sessions"]
    return "\n".join(lines)


def _classic_actions(p: WiredProfile, prefix: str) -> list[str]:
    """Classic fallback actions added by Enforce; with prefix "no " the exact commands that remove them."""
    out = []
    if p.server_down == "open":
        out.append(" authentication event server dead action authorize")
    elif p.server_down == "vlan":
        out.append(f" authentication event server dead action authorize vlan {p.server_down_vlan}")
    if p.server_down != "wait":
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
            lines += [line, " authentication open", *_classic_actions(p, "no "), "!"]
        lines += ["end", "clear authentication sessions"]
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
        for line in interface_range_lines(ranges):
            lines += [line, *(MAB_PORT_CLASSIC if p.mab else MAB_PORT_CLASSIC_OFF), "!"]
        lines += ["end", "clear authentication sessions"]
    return "\n".join(lines)


def session_command(profile: dict) -> str:
    return "show access-session" if (profile or {}).get("platform", "ibns2") == "ibns2" else "show authentication sessions"


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


def guide(vendor: str, *, client: m.RadiusClient | None, profile: dict, settings: m.RadiusSettings, radius_ip: str,
          vlans: list[m.Vlan], tenant: m.Tenant) -> dict:
    """The wired guide for a switch: preflight, configuration, steps and checks. Also the enforce/monitor changes."""
    c = _ctx(client, profile, settings, radius_ip, tenant)
    base = {"vendor": vendor, "kind": "wired", "mode": c.p.mode, "coa_port": 1700 if vendor == "cisco-switch" else 3799,
            "radius_address": radius_ip or None}
    if vendor == "cisco-switch":
        style = "IOS-XE (IBNS 2.0)" if c.p.platform == "ibns2" else "classic IOS / IOS-XE"
        return {**base, "title": f"Cisco Catalyst switch, {style}", "preflight": preflight(c, vendor), "cli": cisco_initial(c),
                "safe_paste": SAFE_PASTE, "enforce_cli": cisco_enforce(c), "monitor_cli": cisco_monitor(c),
                # The MAC authentication change, while it's the latest change in monitor mode.
                "mab_cli": cisco_mab(c) if c.p.mode == "monitor" and c.p.last_change == "mab" else None,
                "mab": c.p.mab, "session_command": session_command(profile),
                "steps": ["Run the preflight commands and check each answer.", "Paste the configuration with the safe-paste steps.",
                          "Plug a test device with an EasyEAP certificate into one of the ports and watch for its first request below."],
                "checks": _checks(c, vlans, vendor)}
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


def parse_sessions(text: str) -> list[dict]:
    """Rows of `show access-session` (IBNS 2.0) or `show authentication sessions` (classic), with whether each is
    authorized. Anything else in the paste (headers, prompts, legends) is ignored."""
    rows = []
    for line in (text or "").splitlines()[:5000]:
        mt = _SESSION_LINE.match(line.strip())
        if not mt:
            continue
        status = mt.group("status").strip()
        s = status.lower()
        authorized = ("auth" in s and "unauth" not in s and "fail" not in s) or "success" in s
        rows.append({"interface": mt.group("intf"), "mac": mt.group("mac"), "method": mt.group("method"), "domain": mt.group("domain"),
                     "status": status[:40], "authorized": authorized})
    return rows
