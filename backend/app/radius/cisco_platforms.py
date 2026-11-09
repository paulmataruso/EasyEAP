"""Cisco switch families: telling them apart from `show version`, and what each can do (docs/plans/cisco-platforms.md).

One table of capabilities (`caps`) is read by every configuration generator, the port-plan validation, the RADIUS
state and the console, so a rule about a release or a model lives in one place. The rules come from Cisco's
configuration guides, command references and release notes; the research notes behind each are listed in the plan
(§12). Nothing here was run on Cisco hardware.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

Platform = Literal["ibns2", "classic", "nxos", "cbs"]
PLATFORMS: tuple[str, ...] = ("ibns2", "classic", "nxos", "cbs")
SERIES: dict[str, tuple[str, ...]] = {
    "ibns2": ("",),
    "classic": ("",),
    "nxos": ("n9k-fx", "n9k-fxp", "n9k", "n3k", "n3548", "n5k", "n7k"),
    "cbs": ("c1300", "sx350", "sx300", "c1200", "sx250", "cbs220", "sx200"),
    "meraki": ("ms", "ms-open"),
}
SERIES_LABELS = {
    "n9k-fx": "Nexus 9300-EX, -FX or -FX2",
    "n9k-fxp": "Nexus 9348GC-FXP",
    "n9k": "Other Nexus 9000 (9300-FX3, -GX, 9500 with EX/FX line cards)",
    "n3k": "Nexus 3000, 3100, 3200 (not 3548 or 3600)",
    "n3548": "Nexus 3548",
    "n5k": "Nexus 5500, 5600 or 6000",
    "n7k": "Nexus 7000 or 7700",
    "c1300": "Catalyst 1300",
    "sx350": "CBS350, Sx350, SG350X, Sx550X",
    "sx300": "SG300, SF300, SG500 (firmware 1.4)",
    "c1200": "Catalyst 1200",
    "sx250": "CBS250, SG250, SF250",
    "cbs220": "CBS220",
    "sx200": "SG200, SF200",
    "ms": "Meraki MS (any model)",
    "ms-open": "Meraki MS130 or MS150 on MS 18 or later",
}

VERSION_MAX = 40
_VERSION_OK = re.compile(r"^[0-9][0-9A-Za-z.()\-]{0,38}$")


# ── Versions ─────────────────────────────────────────────────────────────────

_CLASSIC = re.compile(r"^(\d+)\.(\d+)\((\d+)([a-z]?)\)([A-Z]+)(\d*)([a-z]?)$")
# The trains Catalyst access switches run (12.2(xx)SE…, 12.2(xx)EX/EY/EZ/EA, 15.x E/EX/SE). Others (SX, SY, SG, T, M…)
# number their releases differently, so EasyEAP treats them as unknown rather than compare them.
_ACCESS_TRAIN = re.compile(r"^(?:SE[A-H]?|E[A-Z]?)$")
_XE = re.compile(r"^0?(\d+)\.(\d+)\.(\d+)([a-z]?)\.?(?:[A-Z]{1,3})?$")
_NXOS = re.compile(r"^(\d+)\.(\d+)\((\d+)([a-z]?)\)(.*)$")
_DOTTED = re.compile(r"^\d+(?:\.\d+){1,4}$")


def clean_version(v: str | None) -> str:
    """The version as typed, trimmed; empty when it isn't a version (it's shown back, never put in configuration)."""
    s = (v or "").strip()
    return s if _VERSION_OK.match(s) else ""


_SHAPE = {"classic": _CLASSIC, "ibns2": _XE, "nxos": _NXOS, "cbs": _DOTTED}
VERSION_EXAMPLES = {"classic": "15.2(7)E3 or 12.2(55)SE12", "ibns2": "17.9.4a, 16.6.1 or 03.06.08E", "nxos": "9.3(8) or 7.0(3)I7(9)",
                    "cbs": "3.1.1.7 or 4.1.3.36"}


def version_fits(platform: str, version: str | None) -> bool:
    """Whether `version` is written the way this platform numbers releases (an IOS-XE release on a classic plan isn't)."""
    v = clean_version(version)
    rx = _SHAPE.get(platform)
    return bool(v) and (rx is None or bool(rx.match(v)))


def version_key(platform: str, version: str | None) -> tuple | None:
    """A comparable key for a release, or None when it can't be read."""
    v = clean_version(version)
    if not v:
        return None
    if platform == "classic":
        mt = _CLASSIC.match(v)
        # 12.2(25)SEE4 → (12, 2, 25, "", "SEE", 4): trains of one release compare as strings (SE < SEA < … < SEE).
        if not mt or not _ACCESS_TRAIN.match(mt[5]):
            return None
        return (int(mt[1]), int(mt[2]), int(mt[3]), mt[4], mt[5], int(mt[6] or 0))
    if platform == "ibns2":
        mt = _XE.match(v)
        return (int(mt[1]), int(mt[2]), int(mt[3]), mt[4]) if mt else None
    if platform == "nxos":
        mt = _NXOS.match(v)
        return (int(mt[1]), int(mt[2]), int(mt[3]), mt[4]) if mt else None
    if platform in ("cbs", "meraki"):
        return tuple(int(x) for x in v.split(".")) if _DOTTED.match(v) else None
    return None


def at_least(platform: str, version: str | None, gate: str) -> bool | None:
    """Whether `version` is `gate` or later; None when the version is unknown or unreadable."""
    k, g = version_key(platform, version), version_key(platform, gate)
    if k is None or g is None:
        return None
    if platform == "classic":
        if k[:4] != g[:4]:
            return k[:4] > g[:4]
        if k[4] != g[4]:
            if k[4].startswith("SE") and g[4].startswith("SE"):
                return k[4] > g[4]   # rebuilds of one release: SE < SEA < … < SEE
            return True              # parallel trains of one release (12.2(46)EX next to 12.2(46)SE): the same features
        return k[5] >= g[5]
    return k >= g


# ── Detection from `show version` ────────────────────────────────────────────

_NX = re.compile(r"Cisco Nexus Operating System \(NX-OS\) Software", re.IGNORECASE)
_NX_VER = re.compile(r"(?im)^\s*(?:NXOS|system):\s+version\s+(\S+)")
_NX_CHASSIS = re.compile(r"(?im)^\s*cisco\s+(Nexus\s?\d+\S*(?:\s+(?!chassis\b)\S+)?)\s+(?:chassis|\()")
_XE_LINE = re.compile(r"(?im)^\s*Cisco IOS XE Software,\s*Version\s+(\d{2})\.(\d{2})\.(\d{2}[a-z]?)\b")
_BANNER = re.compile(r"Cisco IOS Software(?:\s*\[[^\]]+\])?,\s+(?P<xe3>IOS-XE Software,\s+)?(?P<desc>[^(]*?)\s*\((?P<image>[A-Za-z0-9_\-]+)\),"
                     r"\s*(?:Experimental\s+)?Version\s+(?:(?:Denali|Everest|Fuji|Gibraltar)\s+)?(?P<ver>[^\s,]+)")
_OLD_BANNER = re.compile(r"IOS \(tm\)\s+(?P<desc>[^(]*?)\s*\((?P<image>[A-Za-z0-9_\-]+)\),\s*Version\s+(?P<ver>[^\s,]+)")
_V3 = re.compile(r"^0?3\.\d{1,2}\.\d{1,2}[a-z]?\.?(?:E|SE|SG|XO|S)$")
_CLS = re.compile(r"^1[25]\.\d+\(\d+[a-z]?\)[A-Z]+\d*[a-z]?$")
_MODEL = re.compile(r"(?im)^\s*Model\s+number\s*:\s*(\S+)")
_PROC = re.compile(r"(?im)^cisco\s+(\S+)\s+\([^)]+\)\s+processor")
_SB_MODEL = re.compile(r"\b((?:C1300X?|C1200|CBS350|CBS250|CBS220|SG350XG|SG350X|SF350|SG350|SG550XG|SG550X|SF550X|SG300|SF300|SG500XG|SG500X|SG500|"
                       r"SG250X?|SF250|SG200|SF200)-[0-9A-Z][0-9A-Z-]*)", re.IGNORECASE)
_SB_VER = re.compile(r"(?im)(?:Active-image.*?\n\s*Version|SW version|Software Version|^\s*Version)\s*:?\s*(\d+\.\d+\.\d+\.\d+)")


@dataclass
class Detected:
    platform: str | None = None    # None: not recognised, the admin chooses
    series: str = ""
    version: str = ""
    lan_lite: bool = False
    model: str = ""
    family: str = ""               # what it is, in words
    evidence: str = ""             # the line it was recognised by
    unsupported: str = ""          # why EasyEAP can't configure 802.1X on it (no 802.1X at all)

    def out(self) -> dict:
        return {"platform": self.platform, "series": self.series, "version": self.version, "lan_lite": self.lan_lite,
                "model": self.model, "family": self.family, "evidence": self.evidence[:200], "unsupported": self.unsupported}


def _first_line(text: str, rx: re.Pattern) -> str:
    mt = rx.search(text)
    if not mt:
        return ""
    start = text.rfind("\n", 0, mt.start()) + 1
    end = text.find("\n", mt.end())
    return text[start:end if end >= 0 else len(text)].strip()


def _nxos_series(chassis: str, version: str) -> str:
    c = chassis.upper().replace(" ", "")
    if re.search(r"C93\d+[A-Z]*-(?:EX|FX2|FX)(?![0-9A-Z])", c):
        return "n9k-fx"   # 9300-EX/-FX/-FX2 (not FX3, FXP or GX)
    if "C9348GC-FXP" in c:
        return "n9k-fxp"
    if "3548" in c or "3524" in c:
        return "n3548"
    if re.search(r"NEXUS36\d|C36\d{3}", c):
        return "n3600"    # no 802.1X: refused by detect()
    if re.search(r"NEXUS3\d|C3\d{3}", c):
        return "n3k"
    if re.search(r"NEXUS7\d|C7\d{3}", c):
        return "n7k"
    if re.search(r"NEXUS[56]\d|C[56]\d{3}", c):
        return "n5k"
    if re.search(r"NEXUS[39]\d|C[39]\d{3}", c):
        return "n9k"
    if re.search(r"\)N\d", version):
        return "n5k"
    if re.search(r"\)D\d", version):
        return "n7k"
    return ""


def detect(text: str) -> Detected:
    """What `show version` (or Cisco Business `show version` / `show system`) says the switch is. Pure; the text
    isn't kept. A version it can't read for that platform is left empty rather than guessed."""
    d = _detect(text)
    if d.version and not version_fits(d.platform, d.version):
        d.version = ""
    return d


def _detect(text: str) -> Detected:
    t = (text or "")[:20000].replace("\r", "").replace("®", "")
    # Rejoin lines a terminal wrapped inside the banner ("Software,\n Catalyst …").
    flat = re.sub(r",\s*\n\s*", ", ", t)
    d = Detected()
    if _NX.search(t):
        mv = _NX_VER.search(t)
        mc = _NX_CHASSIS.search(t)
        d.platform, d.version = "nxos", (mv.group(1) if mv else "")
        d.model = mc.group(1).strip() if mc else ""
        d.series = _nxos_series(d.model, d.version)
        d.family, d.evidence = "Cisco Nexus (NX-OS)", _first_line(t, _NX_VER) or _first_line(t, _NX)
        if d.series == "n3600":
            d.series, d.unsupported = "", "The Nexus 3600 has no 802.1X (Cisco documents none on any release)."
        return d
    mx = _XE_LINE.search(t)
    mb = _BANNER.search(flat) or _OLD_BANNER.search(flat)
    model = (_MODEL.search(t) or _PROC.search(t))
    d.model = model.group(1) if model else ""
    if mx:
        d.platform, d.version = "ibns2", f"{int(mx.group(1))}.{int(mx.group(2))}.{mx.group(3).lstrip('0') or '0'}"
        d.family, d.evidence = f"Cisco IOS-XE {int(mx.group(1))}", _first_line(t, _XE_LINE)
        return d
    if mb:
        ver = mb.group("ver")
        if mb.groupdict().get("xe3") or _V3.match(ver):
            d.platform, d.version, d.family = "ibns2", ver, "Cisco IOS-XE 3.x"
        elif re.match(r"^1[67]\.\d", ver):
            d.platform, d.version, d.family = "ibns2", ver, "Cisco IOS-XE 16"
        elif _CLS.match(ver):
            d.platform, d.version, d.family = "classic", ver, "Cisco IOS (classic)"
            d.lan_lite = "LANLITE" in mb.group("image").upper()
        if d.platform:
            d.evidence = _first_line(flat, _BANNER if _BANNER.search(flat) else _OLD_BANNER)
            return d
    ms = _SB_MODEL.search(t)
    if ms:
        m = ms.group(1).upper()
        d.platform, d.model = "cbs", m
        d.series = ("c1300" if m.startswith("C1300") else "c1200" if m.startswith("C1200") else "cbs220" if m.startswith("CBS220")
                    else "sx250" if m.startswith(("CBS250", "SG250", "SF250")) else "sx200" if m.startswith(("SG200", "SF200"))
                    else "sx300" if m.startswith(("SG300", "SF300", "SG500")) else "sx350")
        mv = _SB_VER.search(t)
        d.version = mv.group(1) if mv else ""
        d.family, d.evidence = "Cisco Business", _first_line(t, _SB_MODEL)
        return d
    if re.search(r"(?im)^\s*Active-image\s*:", t):
        # Cisco Business `show version` alone: the series needs `show system`.
        mv = _SB_VER.search(t)
        d.platform, d.version, d.family = "cbs", (mv.group(1) if mv else ""), "Cisco Business"
        d.evidence = _first_line(t, re.compile(r"(?im)^\s*Active-image\s*:"))
    return d


# ── Capabilities ─────────────────────────────────────────────────────────────


@dataclass
class Caps:
    dialect: str                         # ibns2 | authmgr | dot1x | nxos | sx | cbs220 | web | meraki
    monitor: str                         # switch (open mode) | server (EasyEAP-side, §4) | none (start with a test port)
    mab: str | None                      # pap | pap-wired | eap | None
    host_modes: tuple[str, ...]
    radius_vlan: bool
    no_supplicant_vlan: bool             # a VLAN for devices without 802.1X
    server_down: tuple[str, ...]         # wait | open | vlan
    coa: str | None                      # full | no-bounce | None
    accounting: bool
    tacacs: str | None                   # named | legacy | legacy-xe3 | toggle | nxos | sx | sx-old | cbs220 | None
    audit: str | None                    # caf | ports | None
    session_command: str | None
    named_radius: bool = True
    attr31: bool = False
    dead_criteria: bool = True
    critical_eapol: bool = True
    violation: bool = True
    # FreeRADIUS require_message_authenticator for this switch: "yes" (IOS/IOS-XE with an open mode, today's rule) or
    # "no" where MAC requests are sent without it (Cisco Business, research §1.2) or where a dropped MAC request would
    # cut off devices in monitor mode (server-side monitor). "no" comes with limit_proxy_state (BlastRADIUS).
    message_authenticator: str = "yes"
    errdisable: bool = True              # err-disabled ports over SNMP (CISCO-ERR-DISABLE-MIB)
    notes: list[str] = field(default_factory=list)       # what this switch can't do, in plain words
    warnings: list[str] = field(default_factory=list)    # assumptions made because the version is unknown

    def out(self) -> dict:
        return {k: (list(v) if isinstance(v, tuple) else v) for k, v in self.__dict__.items()}


ALL_HOST_MODES = ("multi-auth", "single-host", "multi-host")


def _classic(version: str, lan_lite: bool) -> Caps:
    v = clean_version(version)
    known = version_key("classic", v) is not None
    authmgr = at_least("classic", v, "12.2(50)SE")
    c = Caps(dialect="authmgr" if authmgr in (True, None) else "dot1x", monitor="switch", mab="pap", host_modes=ALL_HOST_MODES,
             radius_vlan=True, no_supplicant_vlan=True, server_down=("wait", "open", "vlan"), coa="full", accounting=True,
             tacacs="toggle", audit="caf", session_command="show authentication sessions", attr31=False)
    # The named `radius server` from 15.2(3)E (2960-X: 15.0(2)EX). Unknown release: the named form EasyEAP has always
    # given classic switches, so a switch configured before keeps the server it has.
    c.named_radius = at_least("classic", v, "15.2(3)E") is not False or bool(re.match(r"^15\.0\(\d+\)EX", v))
    c.dead_criteria = at_least("classic", v, "12.2(55)SE") is not False
    if not v:
        c.warnings.append("Version unknown: EasyEAP assumes IOS 15.2(3)E or later (the authentication manager, CoA, VLANs on "
                          "multi-auth ports, the named RADIUS server).")
    elif not known:
        c.warnings.append(f"EasyEAP doesn't know the IOS train of {v} (Catalyst access switches run SE or E releases): it assumes "
                          "15.2(3)E or later. Check each command as you paste it.")
    if c.dialect == "dot1x":
        c.monitor, c.host_modes, c.coa, c.audit = "server", ("multi-host", "single-host"), None, None
        c.session_command, c.message_authenticator = "show dot1x all summary", "no"
        c.server_down = ("wait", "vlan")
        c.notes += ["Before IOS 12.2(50)SE there's no authentication manager: no open (monitor) mode, no multi-auth, no CoA. "
                    "EasyEAP monitors from its side: it accepts MAC requests from this switch until you enforce.",
                    "A device that tries 802.1X and fails is blocked even in monitor mode on this release."]
        if at_least("classic", v, "12.2(25)SEE") is False:
            c.mab = None
            c.notes.append("Before 12.2(25)SEE there's no MAC authentication bypass: upgrade the switch.")
        if at_least("classic", v, "12.2(46)SE1") is False:
            c.violation = False
    if c.dialect == "authmgr" and at_least("classic", v, "12.2(52)SE") is False:
        c.coa = None
        c.notes.append("CoA (EasyEAP ending a revoked device's session) needs IOS 12.2(52)SE or later.")
    if c.dialect == "authmgr" and at_least("classic", v, "12.2(55)SE") is False:
        c.notes.append("Before 12.2(55)SE the switch doesn't apply RADIUS VLANs on multi-auth ports: use single-host or multi-host "
                       "if EasyEAP assigns VLANs. Critical access uses the older dot1x critical commands.")
    if at_least("classic", v, "15.2(7)E") is not True and c.dialect == "authmgr":
        # Guest VLAN on multi-auth: documented only from 15.2(7)E. Unknown: a check line, not a refusal.
        c.notes.append("Cisco documents the VLAN for devices without 802.1X on multi-auth ports only from 15.2(7)E; on earlier "
                       "releases use it with single-host or multi-host ports.")
    if at_least("classic", v, "15.2(7)E3") is True:
        c.tacacs = "named"
    elif at_least("classic", v, "15.2(7)E3") is False:
        c.tacacs = "legacy"
    if at_least("classic", v, "12.2(52)SE") is False:
        c.errdisable = False  # CISCO-ERR-DISABLE-MIB is missing on early 12.2SE images (research snmp-syslog.md)
    if lan_lite:
        c.coa, c.violation, c.critical_eapol = None, False, False
        c.server_down = ("wait",)
        c.notes.append("LAN Lite image: no critical authentication (EasyEAP unreachable means new devices wait), no CoA, no violation modes.")
    return c


def _ibns2(version: str) -> Caps:
    v = clean_version(version)
    c = Caps(dialect="ibns2", monitor="switch", mab="pap", host_modes=ALL_HOST_MODES, radius_vlan=True, no_supplicant_vlan=True,
             server_down=("wait", "open", "vlan"), coa="full", accounting=True, tacacs="named", audit="caf", session_command="show access-session",
             named_radius=True, attr31=True)
    xe3 = at_least("ibns2", v, "16.0.0") is False
    if xe3:
        c.attr31 = False
        c.tacacs = "legacy-xe3"
        if at_least("ibns2", v, "3.6.0") is False:
            c.named_radius = False
        if re.search(r"(SG|XO)$", v, re.IGNORECASE):
            c.warnings.append("IOS-XE 3.x on a Catalyst 4500 (SG/XO): Cisco documents IBNS 2.0 there only on Supervisor 8-E and later, "
                              "and EasyEAP hasn't verified it. Check each command as you paste it.")
    if not v:
        c.tacacs = "toggle"  # the admin's "older IOS" choice decides, as before EasyEAP knew releases
        c.warnings.append("Version unknown: EasyEAP assumes IOS-XE 16 or later.")
    return c


def _nxos(series: str, version: str) -> Caps:
    v = clean_version(version)
    s = series
    c = Caps(dialect="nxos", monitor="server", mab="pap-wired", host_modes=("multi-host", "single-host"), radius_vlan=False,
             no_supplicant_vlan=False, server_down=("wait",), coa=None, accounting=True, tacacs="nxos", audit="ports",
             session_command="show dot1x all summary", named_radius=False, dead_criteria=False, critical_eapol=False, violation=False,
             message_authenticator="no", errdisable=s in ("n9k-fx", "n9k-fxp", "n9k"))
    n92 = at_least("nxos", v, "9.2(1)")
    if s in ("n9k-fx", "n9k-fxp", "n9k"):
        if n92 is not False:
            c.host_modes = ALL_HOST_MODES
        if s == "n9k-fx":
            c.radius_vlan = n92 is not False
            c.notes.append("A RADIUS VLAN applies to the first device on a multi-auth port only; later devices must get the same VLAN.")
        elif s == "n9k" and at_least("nxos", v, "10.5(2)") is not True:
            c.mab = None  # MAB on 9300-FX3/GX… from 10.5(2)F
        if n92 is False:
            c.mab = None  # 7.0(3)I7: 802.1X only
        if s != "n9k-fxp" and at_least("nxos", v, "9.2(3)") is not False:
            c.coa = "no-bounce"
        if s == "n9k-fx" and at_least("nxos", v, "10.1(2)") is True:
            c.server_down = ("wait", "open")
    elif s == "n3k":
        # Nexus 3000 on 9.x: MAB, no VLANs from RADIUS, no critical VLAN; CoA "for VXLAN EVPN" only; 7.x: no MAB.
        if n92 is False:
            c.mab = None
        k = version_key("nxos", v)
        if k is None or k[0] >= 10:
            c.warnings.append("Cisco publishes no 802.1X guide for the Nexus 3000 on NX-OS 10: EasyEAP assumes what 9.3 does.")
    elif s == "n3548":
        c.host_modes, c.radius_vlan = ALL_HOST_MODES, True
    elif s == "n5k":
        c.radius_vlan, c.no_supplicant_vlan = True, True
    elif s == "n7k":
        c.notes.append("Nexus 7000 doesn't apply VLANs from RADIUS: devices stay on their port's VLAN.")
    if not c.radius_vlan and s != "n7k":
        c.notes.append("This Nexus doesn't apply VLANs from RADIUS: devices stay on their port's VLAN.")
    if c.mab is None:
        c.monitor = "none"
        c.notes.append("No MAC authentication on this Nexus and release, and NX-OS has no open mode: there's no monitor phase. "
                       "Devices without 802.1X lose access on 802.1X ports: start with one test port.")
    else:
        c.notes.append("NX-OS has no open (monitor) mode. EasyEAP monitors from its side: it accepts MAC requests from this switch "
                       "until you enforce. A device that tries 802.1X and fails is blocked even in monitor mode.")
    if c.coa is None:
        c.notes.append("No CoA on this Nexus and release (Nexus 9000 from 9.2(3) only, not the 9348GC-FXP): a revoked device keeps "
                       "its session until it reconnects.")
    elif c.coa == "no-bounce":
        c.notes.append("NX-OS CoA can re-authenticate or disconnect a device but not bounce its port.")
    c.notes.append("NX-OS has no CISCO-AUTH-FRAMEWORK-MIB: the switch audit reads ports" + (" and err-disabled state" if c.errdisable else "")
                   + ", not 802.1X sessions.")
    if not v:
        c.warnings.append("Version unknown: EasyEAP assumes NX-OS 9.3 or later.")
    return c


def _cbs(series: str, version: str) -> Caps:
    s = series or "sx350"
    v = clean_version(version)
    c = Caps(dialect="sx", monitor="switch", mab="pap", host_modes=("multi-auth", "multi-host", "single-host"), radius_vlan=True,
             no_supplicant_vlan=True, server_down=("wait", "open"), coa=None, accounting=True, tacacs="sx", audit="ports",
             session_command=None, named_radius=False, dead_criteria=False, critical_eapol=False, violation=False,
             message_authenticator="no", errdisable=False)
    c.notes.append("Cisco Business switches have no critical VLAN: while EasyEAP is unreachable new devices either wait or are "
                   "allowed on their port's VLAN (one setting for the whole switch).")
    if s == "c1300":
        if at_least("cbs", v, "4.1.3.36") is not False:
            c.coa = "full"
        else:
            c.notes.append("CoA needs Catalyst 1300 firmware 4.1.3.36 or later.")
    elif s == "sx300":
        c.mab, c.tacacs = "eap", "sx-old"
        c.notes.append("Firmware 1.4 sends MAC authentication as EAP-MD5; EasyEAP answers it.")
    elif s in ("c1200", "sx250"):
        c.mab, c.radius_vlan, c.accounting, c.tacacs, c.monitor = None, False, False, None, "none"
        c.notes += ["No MAC authentication, VLANs from RADIUS or accounting on this series.",
                    "No open (monitor) mode: a device without an EasyEAP certificate loses access on an 802.1X port. Start with "
                    "one test port, and leave ports with printers, cameras and phones out of the plan."]
    elif s == "cbs220":
        c.dialect, c.mab, c.accounting, c.tacacs, c.monitor = "cbs220", None, False, "cbs220", "none"
        c.server_down = ("wait",)  # its guide has no "radius none" fallback for 802.1X
        c.notes += ["CBS220: no MAC authentication or accounting; while EasyEAP is unreachable, new devices wait.",
                    "No open (monitor) mode: a device without an EasyEAP certificate loses access on an 802.1X port. Start with "
                    "one test port, and leave ports with printers, cameras and phones out of the plan."]
    elif s == "sx200":
        c.dialect, c.mab, c.radius_vlan, c.accounting, c.tacacs, c.audit = "web", None, False, False, None, None
        c.monitor = "none"
        c.notes.append("SG200/SF200 have no command line: EasyEAP gives web interface steps. No monitor mode: start with one test port.")
    if c.coa is None and s != "c1300":
        c.notes.append("No CoA on this series: a revoked device keeps its session until it reconnects.")
    if c.audit == "ports":
        c.notes.append("The switch audit reads ports only (Cisco Business switches have no CISCO-AUTH-FRAMEWORK-MIB).")
    return c


def _meraki(series: str) -> Caps:
    c = Caps(dialect="meraki", monitor="switch" if series == "ms-open" else "server", mab="pap-wired", host_modes=ALL_HOST_MODES,
             radius_vlan=True, no_supplicant_vlan=True, server_down=("wait", "open", "vlan"), coa=None, accounting=True, tacacs=None,
             audit=None, session_command=None, named_radius=False, dead_criteria=False, critical_eapol=False, violation=False,
             message_authenticator="no", errdisable=False)
    if series != "ms-open":
        c.notes.append("Meraki MS has open (monitor) mode only on MS130/MS150 with MS 18. On other models EasyEAP monitors from its "
                       "side: with Hybrid authentication, devices that fail or skip 802.1X fall back to MAC authentication, which "
                       "EasyEAP accepts until you enforce.")
    c.notes += ["Leave RADIUS CoA off: Meraki needs a session ID in each Access-Accept that EasyEAP doesn't send yet.",
                "Meraki classic MS: no critical VLAN on Multi-Auth ports.",
                "No TACACS+ and no 802.1X data over SNMP on Meraki MS: no device admin or switch audit."]
    return c


def caps(platform: str | None, series: str = "", version: str = "", lan_lite: bool = False, vendor: str = "cisco-switch") -> Caps:
    """What this switch can do. Unknown platform: IOS-XE (today's default)."""
    if vendor == "meraki":
        return _meraki(series)
    if platform == "classic":
        return _classic(version, lan_lite)
    if platform == "nxos":
        return _nxos(series, version)
    if platform == "cbs":
        return _cbs(series, version)
    return _ibns2(version)


PLATFORM_LABELS = {"ibns2": "IOS-XE (IBNS 2.0)", "classic": "Classic IOS", "nxos": "Nexus (NX-OS)", "cbs": "Cisco Business"}


def describe(vendor: str, profile: dict | None) -> str | None:
    """The switch in words for the console, e.g. "Nexus (NX-OS) · Nexus 9300-EX, -FX or -FX2 · 9.3(8)"."""
    p = profile or {}
    if vendor == "meraki":
        return SERIES_LABELS.get(p.get("series") or "ms", "Meraki MS")
    if vendor != "cisco-switch":
        return None
    parts = [PLATFORM_LABELS.get(p.get("platform") or "ibns2", "IOS-XE (IBNS 2.0)")]
    if p.get("series"):
        parts.append(SERIES_LABELS.get(p["series"], p["series"]))
    parts.append(p.get("version") or "release not given")
    if p.get("lan_lite"):
        parts.append("LAN Lite")
    return " · ".join(parts)


def agent_needs(c: Caps | None) -> set[str]:
    """The RADIUS agent features a switch relies on (services/radius/agent/easyeap_agent.py FEATURES). An agent without
    them would answer it as an IOS-XE switch: MAC requests from a Nexus or Meraki refused, no monitor accepts, VLANs to a
    switch that fails the port on one, Message-Authenticator required."""
    if c is None:
        return set()
    need = set()
    if c.mab == "pap-wired":
        need.add("pap-wired")
    if c.monitor == "server":
        need.add("monitor-accept")
    if not c.radius_vlan:
        need.add("send-vlan")
    if c.message_authenticator == "no":
        need.add("client-message-authenticator")
    return need


def caps_for(vendor: str, profile: dict | None) -> Caps | None:
    """The capabilities of a registered switch, or None for vendors without a Cisco platform (UniFi, other)."""
    p = profile or {}
    if vendor not in ("cisco-switch", "meraki"):
        return None
    return caps(p.get("platform") or "ibns2", p.get("series") or "", p.get("version") or "", bool(p.get("lan_lite")), vendor)
