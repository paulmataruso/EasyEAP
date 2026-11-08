"""Syslog from switches and controllers (docs/plans/syslog-full.md): "the device says".

Runs as its own container (`entrypoint.sh syslog`, `python -m app.switchaudit.syslog`) so a port conflict or a flood
never touches SNMP polling or RADIUS. Every message from a known device is kept (coalesced per identical text per
minute), parsed where EasyEAP knows the format, and marked notable when EasyEAP decodes it (802.1X/MAB sessions,
err-disable, RADIUS servers, configuration changes, wireless clients). Syslog isn't authenticated, so nothing here
opens or resolves a finding: messages are shown as what the device says, and a few move a switch's next poll earlier.

Attribution (§9): every RADIUS client's address, in every tenant, is a claim, and so is the SNMP address of a switch
that answered a poll recently with its tenant's credentials. A datagram goes to the longest matching claim; it's
dropped when two devices tie there or any matching claim is another tenant's (ambiguous), and when the device hasn't
syslog on (disabled). A per-device token bucket, caps on open coalescing entries (per device, per tenant, overall) and
a daily byte quota per tenant (notable messages get the last 20 %) bound what one sender can cost.

Two threads: the socket thread parses and coalesces under a lock; the writer thread stores new rows every second and
count updates every few seconds, one batch per tenant in the tenant's own session (row-level security checks every
row). The writer is the only process that writes switch_syslog: that keeps commit order = seq order, which the live
view's cursor relies on.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import signal
import socket
import sys
import threading
import time
import uuid
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta

from app.radius.wired import PORT_TYPES, canonical_port

log = logging.getLogger("easyeap.syslog")

LISTEN_PORT = 5514            # inside the container; published as EASYEAP_SYSLOG_BIND:EASYEAP_SYSLOG_PORT (and :514)
MAX_DATAGRAM = 2048           # longer messages are cut: device messages are a few hundred bytes
MAX_TEXT = 500
RATE, BURST = 100.0, 200.0    # new rows a second per device
RAW_RATE, RAW_BURST = 1000.0, 2000.0   # datagrams a second per device, before parsing
TENANT_BYTES_PER_DAY = 50 * 1024 * 1024
NOTABLE_SHARE = 0.8           # past this share of the day's bytes, only notable messages are stored
MAX_ENTRIES = 50_000          # open coalescing entries overall
MAX_ENTRIES_PER_TENANT = 20_000
MAX_ENTRIES_PER_DEVICE = 2_000
FLUSH_SECONDS = 1.0           # new rows reach the live view within about a second
COUNT_SECONDS = 5.0           # a repeat's count is written at most this often (and when its minute ends)
STATS_SECONDS = 10.0
RELOAD_SECONDS = 30
HEARTBEAT_SECONDS = 30
PRUNE_SECONDS = 3600
PRUNE_BATCH = 10_000
KEEP_DAYS, KEEP_DAYS_OTHER = 14, 3
MAX_WRITE_FAILURES = 5
MAX_UNKNOWN = 1000            # distinct unknown source addresses remembered
SAMPLE_CHARS = 160
TAG_WITHIN = 160              # a Cisco tag must start this close to the start of the message
NO_CISCO_TAGS = {"unifi"}     # these devices never send Cisco-format messages: a "%…-4-…:" inside one is just text
# A message moves the next poll earlier, never sooner than this after the last poll (a spoofed message can't add load).
HINT_MIN_GAP, HINT_DELAY = timedelta(seconds=30), timedelta(seconds=10)

# The switch audit's evidence (the old keep list): facility → mnemonics (a trailing "_" matches every mnemonic with that
# prefix). Notable, and the source of the "poll sooner" hints.
KEEP: dict[str, set[str]] = {
    "SESSION_MGR": {"FAIL", "SECURITY_VIOLATION"},
    "AUTHMGR": {"FAIL", "SECURITY_VIOLATION"},
    "DOT1X": {"FAIL", "SESSION_TERMINATION", "SECURITY_VIOLATION"},   # NX-OS: no FAIL; termination and violation
    "MAB": {"FAIL"},
    "DOT1X_SWITCH": {"ERR_"},
    "PM": {"ERR_DISABLE", "ERR_RECOVER"},
    "RADIUS": {"RADIUS_DEAD", "RADIUS_ALIVE", "ALLDEADSERVER"},
    "RADIUS_AUDIT_MESSAGE": {"RADIUS_DEAD", "RADIUS_ALIVE"},   # IOS-XE 17
    "SYS": {"CONFIG_I"},
    # NX-OS (docs/plans/cisco-platforms.md §8; research nxos.md §11.3)
    "ETHPORT": {"IF_DOWN_ERROR_DISABLED", "IF_ERRDIS_RECOVERY"},
    "STP": {"BLOCK_BPDUGUARD"},
    "VSHD": {"VSHD_SYSLOG_CONFIG_I"},
}
# What EasyEAP decodes into sessions and clients (service.syslog_sessions): notable too.
DECODED: dict[str, set[str]] = {
    "SESSION_MGR": {"START", "SUCCESS", "FAIL", "VLANASSIGN", "MACMOVE", "MACREPLACE", "SECURITY_VIOLATION"},
    "AUTHMGR": {"START", "SUCCESS", "FAIL", "VLANASSIGN", "MACMOVE", "MACREPLACE", "SECURITY_VIOLATION"},
    "DOT1X": {"SUCCESS", "FAIL", "SESSION_CREATION", "SESSION_TERMINATION", "ABORT_AUTH", "SECURITY_VIOLATION"},
    "MAB": {"SUCCESS", "FAIL"},
    "EPM": {"POLICY_REQ", "IPEVENT", "POLICY_APP_SUCCESS", "POLICY_APP_FAILURE"},
    "CLIENT_ORCH_LOG": {"CLIENT_ADDED_TO_RUN_STATE", "CLIENT_MOVED_TO_RUN_STATE", "CLIENT_MOVED_TO_DELETE_STATE"},
    "CLIENT_EXCLUSION_SERVER": {"ADD_TO_EXCLUSIONLIST_REASON_DYNAMIC", "ADD_TO_EXCLUSIONLIST_REASON"},
    "APF": {"AUTHENTICATION_TRAP", "ASSOC_TRAP", "DISASSOC_TRAP", "DEAUTH_TRAP", "AUTHFAIL_TRAP", "EXCLUDED_TRAP"},
    "AAA": {"RADIUS_RESPONSE_FAILED"},
    "UNIFI": {"WiFi Client Connected", "WiFi Client Disconnected", "WiFi Client Roamed"},
}
HINT_ON = {"ERR_DISABLE", "ERR_RECOVER", "SECURITY_VIOLATION", "CONFIG_I", "FAIL",   # the SNMP evidence should follow soon
           "IF_DOWN_ERROR_DISABLED", "IF_ERRDIS_RECOVERY", "VSHD_SYSLOG_CONFIG_I"}
PRIORITY = {("RADIUS", "RADIUS_DEAD"), ("RADIUS", "RADIUS_ALIVE"), ("RADIUS", "ALLDEADSERVER"),   # stored past the quota
            ("RADIUS_AUDIT_MESSAGE", "RADIUS_DEAD"), ("RADIUS_AUDIT_MESSAGE", "RADIUS_ALIVE"), ("PM", "ERR_DISABLE"),
            ("ETHPORT", "IF_DOWN_ERROR_DISABLED"), ("AAA", "RADIUS_RESPONSE_FAILED")}
RADIUS_FACILITIES = {"RADIUS", "RADIUS_AUDIT_MESSAGE"}
# hostapd (UniFi access points): the client lines worth keeping 14 days.
_HOSTAPD_NOTABLE = re.compile(r"IEEE 802\.1X: (?:authenticated|authentication failed)|IEEE 802\.11: (?:associated|disassociated|deauthenticated)"
                              r"|No response from Authentication server")

_PRI = re.compile(rb"^\s*<(\d{1,3})>")
# %FACILITY[-SUBFACILITY]-SEVERITY-MNEMONIC: (some platforms add a sub-facility, %PM-SP-4-ERR_DISABLE). Cisco Business
# writes the severity as a letter (%LINK-W-Down, %SEC-I-PORTAUTHORIZED) and mnemonics in mixed case; AireOS may write
# "#" for "%" (CSCul11353).
_TAG = re.compile(rb"[%#]([A-Z][A-Z0-9_]{0,31})(?:-[A-Z][A-Z0-9_]{0,15})?-([0-7]|[AFCEWNID])-([A-Z][A-Za-z0-9_]{0,47}):[ \t]?")
_WORD = re.compile(rb"[A-Za-z0-9_]")   # a tag right after one of these is inside a word: text, not a tag
LETTER_SEVERITY = {"F": 0, "A": 1, "C": 2, "E": 3, "W": 4, "N": 5, "I": 6, "D": 7}
_ORIGIN = re.compile(r"^(?:(?:Switch|Chassis) ?\d+ )?R\d+/\d+: \w+: ")  # IOS-XE's "Switch 1 R0/0: sessmgrd: ", the 9800's "R0/0: wncd: "
_AIREOS_SRC = re.compile(r"^(?:\[[A-Z]{1,4}\])?[\w.-]{1,40}\.c:\d{1,6}:? ")   # AireOS: "[PA]radius_db.c:658 "
_TS3164 = re.compile(r"^[A-Z][a-z]{2} \d{1,2}(?: \d{4})? \d\d:\d\d:\d\d(?:\.\d{1,6})?(?: [A-Z]{2,5})?:? ")   # after _clean: one space
_DEVTAG = re.compile(r"^[^\s:]*,[^\s:]*: ")   # UniFi's "<ap mac>,<model>-<firmware>: "
_PROG = re.compile(r"^([A-Za-z][\w.-]{0,31})(?:\[\d{1,10}\])?: ")
_PORT = re.compile(r"\b([A-Za-z][A-Za-z-]{0,24}?) ?(\d{1,4}(?:/\d{1,4}){1,3})\b")   # bounded: no backtracking on "a-a-a-…"
PORT_WITHIN = 400   # an interface is named early in a message; reading further only costs time
_CLIENT_MAC = re.compile(r"\(([0-9a-fA-F]{4})\.([0-9a-fA-F]{4})\.([0-9a-fA-F]{4})\)")
_DOTTED_MAC = re.compile(r"\b([0-9a-fA-F]{4})\.([0-9a-fA-F]{4})\.([0-9a-fA-F]{4})\b")
_COLON_MAC = re.compile(r"\b((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})\b")
_SESSION = re.compile(r"AuditSessionID:? ?([0-9A-Fa-f]{8,64})")
_SERVER = re.compile(r"(?i)RADIUS server ([0-9A-Fa-f.:]+?)(?::(\d+)(?:,\d+)?)?(?: is|\s|$)")
_CONFIG_BY = re.compile(r"Configured from (.{1,80})$")
_CAUSE = re.compile(r"^(\S{1,40}) error detected")
_NX_CAUSE = re.compile(r"Reason: ?([^)]{1,40})\)")  # NX-OS: "is down (Error disabled. Reason:BPDUGuard)"
_AP_NAME = re.compile(r"AP Name: ?([^,\s]{1,64})")
_LOGGED_CMD = re.compile(r"(?i)(logged command: ?)(.*)$")
_REDACT = [
    (re.compile(r"(?i)\[user: [^\]]*\]"), "[user: <redacted>]"),
    # A keyword, then any type digits, encodings and algorithms (secret 5 …, key 7 …, psk set-key ascii 0 …,
    # authentication-key 1 md5 …), then the value.
    (re.compile(r"(?i)\b(\w*pass(?:word|phrase|wd)|secret|key-string|key|community|wpa-psk|psk|set-key|user ?name|user)(\s*[:=]\s*|\s+)"
                r"(?:(?:set-key|ascii|hex|md5|sha\w*|aes\w*|3?des\w*|\d)\s+){0,4}([^\s,;\]|]+)"), r"\1\2<redacted>"),
    (re.compile(r"(?i)\b(ascii|hex)\s+(?!<redacted>)([^\s,;\]|]+)"), r"\1 <redacted>"),   # AireOS: "… 1812 ascii <secret>"
    (re.compile(r"(?i)\b(version\s+(?:1|2c))\s+([^\s,;\]|]+)"), r"\1 <redacted>"),        # snmp-server host … version 2c <community>
    (re.compile(r"(?i)\b(snmp-server host\s+\S+(?:\s+(?:informs|traps))?)\s+(?!version\b|vrf\b|<redacted>)([^\s,;\]|]+)"), r"\1 <redacted>"),
    (re.compile(r"(?i)\b((?:mgmtuser|netuser)\s+add\s+\S+)\s+(\S+)"), r"\1 <redacted>"),   # AireOS local users
    (re.compile(r"(?i)\b(auth|priv)\s+(md5|sha[\w-]*(?:\s+\d{3})?|aes(?:-\d{3})?(?:\s+\d{3})?|3?des\S*)\s+(\S+)"), r"\1 \2 <redacted>"),
    (re.compile(r"(?i)\b([sd]user)=(.*?)(?=\s+\w+=|$)"), r"\1=<redacted>"),   # CEF
    (re.compile(r"(?i)(\bidentity\b[^'\"]{0,40})(['\"])[^'\"]*\2"), r"\1\2<redacted>\2"),   # hostapd
]
_CEF_FIELD = re.compile(r"(\w+)=((?:[^\\]|\\.)*?)(?=\s+\w+=|$)")


@dataclass(frozen=True)
class Message:
    facility: str
    severity: int
    mnemonic: str
    text: str
    port: str = ""
    mac: str = ""
    session_id: str = ""
    subject: str = ""  # what else tells two messages apart: a RADIUS server, who configured, an err-disable cause, an AP

    @property
    def tag(self) -> str:
        if self.mnemonic:
            return f"{self.facility}-{self.severity}-{self.mnemonic}"
        return self.facility or "syslog"


def kept(facility: str, mnemonic: str) -> bool:
    """In the switch audit's evidence (the old keep list)."""
    allowed = KEEP.get(facility)
    if not allowed:
        return False
    return mnemonic in allowed or any(a.endswith("_") and mnemonic.startswith(a) for a in allowed)


def notable(msg: Message) -> bool:
    """EasyEAP uses it (evidence, sessions, wireless clients): kept 14 days, and stored past 80 % of the quota."""
    if kept(msg.facility, msg.mnemonic) or msg.mnemonic in DECODED.get(msg.facility, ()):
        return True
    return msg.facility == "hostapd" and bool(_HOSTAPD_NOTABLE.search(msg.text))


def redact(text: str) -> str:
    m = _LOGGED_CMD.search(text)
    if m:  # a logged configuration command keeps its first two words only: the rest may be a key or a community
        words = m.group(2).split()
        text = text[:m.start(2)] + " ".join(words[:2]) + (" …" if len(words) > 2 else "")
    for rx, repl in _REDACT:
        text = rx.sub(repl, text)
    return text


def _clean(raw: bytes) -> str:
    s = raw.decode("utf-8", "replace")
    return " ".join("".join(ch if ch >= " " and ch != "\x7f" else " " for ch in s).split())


def port_of(text: str) -> str:
    for kind, num in _PORT.findall(text[:PORT_WITHIN]):
        if kind.lower() in PORT_TYPES:
            return canonical_port(f"{kind}{num}")
    return ""


def mac_of(text: str) -> str:
    """The client's MAC: Cisco writes it in parentheses, dotted; otherwise the first MAC in any notation."""
    m = _CLIENT_MAC.search(text) or _DOTTED_MAC.search(text)
    if m:
        return "".join(m.groups()).upper()
    m = _COLON_MAC.search(text)
    return re.sub(r"[:-]", "", m.group(1)).upper() if m else ""


def server_of(text: str) -> str:
    m = _SERVER.search(text)
    return m.group(1).rstrip(".") if m else ""


def _subject(facility: str, mnemonic: str, body: str) -> str:
    if facility in RADIUS_FACILITIES or (facility, mnemonic) == ("AAA", "RADIUS_RESPONSE_FAILED"):
        return server_of(body) or ("all" if mnemonic == "ALLDEADSERVER" else "")
    if mnemonic.endswith("CONFIG_I"):
        m = _CONFIG_BY.search(body)
        return m.group(1)[:64] if m else ""
    if mnemonic in ("ERR_DISABLE", "ERR_RECOVER", "IF_DOWN_ERROR_DISABLED"):
        m = _CAUSE.search(body) or _NX_CAUSE.search(body)
        return m.group(1)[:64] if m else ""
    if facility == "CLIENT_EXCLUSION_SERVER":
        m = _AP_NAME.search(body)
        return m.group(1) if m else ""
    return ""


def _cisco_tag(data: bytes, start: int) -> re.Match[bytes] | None:
    """The first %FAC-SEV-MNEMONIC: tag starting within TAG_WITHIN bytes of `start`, not inside a word."""
    for m in _TAG.finditer(data, start, min(len(data), start + TAG_WITHIN + 120)):
        if m.start() - start > TAG_WITHIN:
            return None
        if m.start() == start or not _WORD.match(data, m.start() - 1):
            return m
    return None


def parse(data: bytes, vendor: str = "cisco-switch") -> Message | None:
    """One syslog datagram as a Message: Cisco's %FACILITY-SEVERITY-MNEMONIC wherever the priority, counter, origin,
    sequence number and timestamp put it; otherwise RFC 3164 (the program as the facility, the host as the subject) or
    CEF (UniFi). None for a datagram with nothing printable."""
    data = data[:MAX_DATAGRAM]
    pm = _PRI.match(data)
    pri = int(pm.group(1)) if pm else -1
    start = pm.end() if pm else 0
    m = None if vendor in NO_CISCO_TAGS else _cisco_tag(data, start)
    if m is not None:
        sev = m.group(2).decode()
        facility, severity, mnemonic = m.group(1).decode(), int(sev) if sev.isdigit() else LETTER_SEVERITY[sev], m.group(3).decode()
        body = _AIREOS_SRC.sub("", _ORIGIN.sub("", _clean(data[m.end():])))
        sid = _SESSION.search(body)
        return Message(facility, severity, mnemonic, redact(body)[:MAX_TEXT], port_of(body), mac_of(body),
                       sid.group(1).upper() if sid else "", redact(_subject(facility, mnemonic, body))[:64])
    line = _clean(data[start:])
    if not line:
        return None
    severity = pri & 7 if 0 <= pri <= 191 else 6
    i = line.find("CEF:")
    if i >= 0:
        return _cef(line[i:], severity)
    host, rest = "", line
    ts = _TS3164.match(line)
    if ts:
        host, _, rest = line[ts.end():].partition(" ")
    if (d := _DEVTAG.match(rest)) is not None:
        rest = rest[d.end():]
    prog = ""
    if (p := _PROG.match(rest)) is not None:
        prog, rest = p.group(1), rest[p.end():]
    return Message(prog[:32], severity, "", redact(rest)[:MAX_TEXT], "", mac_of(rest), "", redact(host)[:64])


def _cef(cef: str, severity: int) -> Message:
    """CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension (UniFi's SIEM integration)."""
    parts, cur, esc = [], [], False
    for ch in cef:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            cur.append(ch)
            esc = True
        elif ch == "|" and len(parts) < 7:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    fields = {k: v.replace("\\=", "=").replace("\\\\", "\\").strip() for k, v in _CEF_FIELD.findall(parts[7] if len(parts) > 7 else "")}
    vendor = parts[1] if len(parts) > 1 else ""
    name = (parts[5] if len(parts) > 5 else "").strip()[:48]
    mac = re.sub(r"[^0-9A-Fa-f]", "", fields.get("UNIFIclientMac", "")).upper()
    ap = fields.get("UNIFIlastConnectedToDeviceName") or fields.get("UNIFIconnectedToDeviceName") or fields.get("UNIFIdeviceName") or ""
    text = fields.get("msg") or (parts[7] if len(parts) > 7 else cef)
    return Message("UNIFI" if vendor == "Ubiquiti" else "CEF", severity, name, redact(text)[:MAX_TEXT], "",
                   mac if len(mac) == 12 else "", "", redact(ap)[:64])


def normalize_ip(addr: str) -> str:
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return addr
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return str(ip.ipv4_mapped)
    return str(ip)


# ── Attribution ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Device:
    client_id: uuid.UUID
    tenant_id: uuid.UUID
    vendor: str = "cisco-switch"


_MAPPED = ipaddress.ip_network("::ffff:0:0/96")
_REFUSED_V6 = (ipaddress.ip_network("::/96"), ipaddress.ip_network("64:ff9b::/96"))   # IPv4-compatible, NAT64


def claim_network(address: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """An address or range as a claim: IPv4-mapped IPv6 becomes the IPv4 range it means (sources are normalised the
    same way); IPv4-compatible and NAT64 ranges, and anything wider than 65,536 addresses, aren't claims."""
    try:
        net = ipaddress.ip_network(address.strip().split("%")[0], strict=False)
    except ValueError:
        return None
    if net.num_addresses > 65_536:
        return None
    if isinstance(net, ipaddress.IPv6Network):  # at most a /112 here, so it's inside these or apart from them
        if net.subnet_of(_MAPPED):
            return ipaddress.ip_network((int(net.network_address) & 0xFFFFFFFF, net.prefixlen - 96))
        if any(net.overlaps(r) for r in _REFUSED_V6):
            return None
    return net


class Claims:
    """Source address → device. Built from (address or range, device, may attribute) for every RADIUS client and every
    verified switch SNMP address; one dict per prefix length in use, looked up longest first."""

    def __init__(self, claims: Iterable[tuple] = ()) -> None:
        """Each claim: (address or range, device, may attribute[, proven]). Proven: the tenant's SNMP credentials got an
        answer from that address, so the tenant controls the device there."""
        self.tables: dict[tuple[int, int], dict[int, list[tuple[Device, bool, bool]]]] = {}
        self.enabled: set[Device] = set()
        for addr, dev, on, *rest in claims:
            net = claim_network(addr) if addr else None
            if net is None:
                continue
            proven = bool(rest and rest[0])
            self.tables.setdefault((net.version, net.prefixlen), {}).setdefault(int(net.network_address), []).append((dev, on, proven))
            if on:
                self.enabled.add(dev)
        self.lengths = {v: sorted((p for ver, p in self.tables if ver == v), reverse=True) for v in (4, 6)}

    def lookup(self, ip: str) -> tuple[Device | None, str]:
        """(device, "ok"), or (None, "unknown" | "ambiguous" | "disabled")."""
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None, "unknown"
        bits, n = a.max_prefixlen, int(a)
        matches: list[tuple[int, Device, bool]] = []
        proven: set[uuid.UUID] = set()
        for plen in self.lengths.get(a.version, ()):
            key = (n >> (bits - plen)) << (bits - plen) if plen else 0
            for dev, on, pr in self.tables[(a.version, plen)].get(key, ()):
                matches.append((plen, dev, on))
                if pr and on:
                    proven.add(dev.tenant_id)
        if not matches:
            return None, "unknown"
        if len({d.tenant_id for _, d, _ in matches}) > 1:
            # Two tenants claim it. A tenant whose SNMP credentials the device there answers controls it (it sees the
            # switch over SNMP anyway); otherwise their messages can't be told apart.
            if len(proven) != 1:
                return None, "ambiguous"
            owner = next(iter(proven))
            matches = [x for x in matches if x[1].tenant_id == owner]
        best = matches[0][0]
        top = {d.client_id for p, d, _ in matches if p == best}
        if len(top) > 1:
            return None, "ambiguous"
        dev = next(d for p, d, _ in matches if p == best)
        if not any(on for _, d, on in matches if d.client_id == dev.client_id):
            return None, "disabled"
        return dev, "ok"


# ── Bounding what a sender can cost ──────────────────────────────────────────


@dataclass
class Bucket:
    rate: float = RATE
    burst: float = BURST
    tokens: float = BURST
    at: float | None = None  # the clock starts at the first message

    def take(self, now: float) -> bool:
        if self.at is not None:
            self.tokens = min(self.burst, self.tokens + max(0.0, now - self.at) * self.rate)
        self.at = now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True


@dataclass
class Entry:
    id: uuid.UUID
    device: Device
    msg: Message
    source: str
    notable: bool
    first_at: datetime
    last_at: datetime
    count: int = 1
    dirty: bool = True
    written: bool = False   # inserted once: later writes only move the count, and can wait COUNT_SECONDS
    wrote_at: float = 0.0
    minute: int = 0
    failures: int = 0


@dataclass
class Stats:
    """Per device, since the last write to syslog_stats."""
    received: int = 0
    kept: int = 0
    quota: int = 0
    bytes: int = 0
    last_at: datetime | None = None
    last_tag: str = ""


@dataclass
class Batch:
    at: datetime
    entries: list[Entry]
    stats: dict[Device, Stats]
    hints: dict[Device, datetime]
    failed: list[Entry] = field(default_factory=list)  # store() appends the entries it couldn't write


class Coalescer:
    """One entry per (device, message, text) per minute, counted; quotas per device, tenant and overall. Not
    thread-safe: the Receiver holds its lock around every call."""

    def __init__(self, max_entries: int = MAX_ENTRIES, per_tenant: int = MAX_ENTRIES_PER_TENANT, per_device: int = MAX_ENTRIES_PER_DEVICE,
                 tenant_bytes: int = TENANT_BYTES_PER_DAY) -> None:
        self.entries: dict[tuple, Entry] = {}
        self.per_device: Counter[uuid.UUID] = Counter()
        self.per_tenant: Counter[uuid.UUID] = Counter()
        self.buckets: dict[uuid.UUID, Bucket] = {}
        self.max_entries, self.max_per_tenant, self.max_per_device, self.tenant_bytes = max_entries, per_tenant, per_device, tenant_bytes
        self.used: dict[uuid.UUID, int] = {}
        self.day: date | None = None
        self.stats: dict[Device, Stats] = {}
        self.hints: dict[Device, datetime] = {}

    def set_usage(self, day: date, used: dict[uuid.UUID, int]) -> None:
        """Today's stored bytes per tenant (from syslog_stats), so a restart doesn't reset the quota."""
        self.day, self.used = day, dict(used)

    def add(self, dev: Device, msg: Message | None, now: datetime, source: str = "", mono: float | None = None) -> str:
        """Count one datagram from a known device. Returns what happened: kept | quota | empty."""
        st = self.stats.setdefault(dev, Stats())
        st.received += 1
        if msg is None:
            return "empty"
        if self.day != now.date():
            self.day, self.used = now.date(), {}
        minute = int(now.timestamp() // 60)
        key = (dev.client_id, msg.facility, msg.mnemonic, msg.port, msg.mac, msg.subject, msg.text, minute)
        e = self.entries.get(key)
        if e is not None:  # a repeat costs a counter, nothing more
            e.count, e.last_at, e.dirty = e.count + 1, now, True
        else:
            if not self.buckets.setdefault(dev.client_id, Bucket()).take(time.monotonic() if mono is None else mono):
                st.quota += 1
                return "quota"
            note = notable(msg)
            size = len(msg.text) + 200
            if (msg.facility, msg.mnemonic) not in PRIORITY:
                limit = self.tenant_bytes if note else self.tenant_bytes * NOTABLE_SHARE
                if self.used.get(dev.tenant_id, 0) + size > limit:
                    st.quota += 1
                    return "quota"
            if len(self.entries) >= self.max_entries or self.per_tenant[dev.tenant_id] >= self.max_per_tenant \
                    or self.per_device[dev.client_id] >= self.max_per_device:
                st.quota += 1
                return "quota"
            self.used[dev.tenant_id] = self.used.get(dev.tenant_id, 0) + size
            st.bytes += size
            self.entries[key] = Entry(uuid.uuid4(), dev, msg, source, note, now, now, minute=minute)
            self.per_device[dev.client_id] += 1
            self.per_tenant[dev.tenant_id] += 1
        st.kept += 1
        st.last_at, st.last_tag = now, msg.tag[:100]
        if dev.vendor == "cisco-switch" and msg.mnemonic in HINT_ON and kept(msg.facility, msg.mnemonic):
            self.hints[dev] = now
        return "kept"

    def take(self, now: datetime, mono: float) -> list[Entry]:
        """The entries to write, marked clean: every new one, and repeats whose count was last written COUNT_SECONDS
        ago or whose minute ended. Entries of minutes that ended are forgotten at the flush after the one that wrote
        them, so a failed write (marked dirty again) loses nothing."""
        current = int(now.timestamp() // 60)
        for key in [k for k, e in self.entries.items() if not e.dirty and e.minute < current]:
            self.forget(key)
        out = [e for e in self.entries.values()
               if e.dirty and (not e.written or e.minute < current or mono - e.wrote_at >= COUNT_SECONDS)]
        for e in out:
            e.dirty, e.written, e.wrote_at = False, True, mono
        return out

    def forget(self, key: tuple) -> None:
        e = self.entries.pop(key, None)
        if e is not None:
            for counter, k in ((self.per_device, e.device.client_id), (self.per_tenant, e.device.tenant_id)):
                counter[k] -= 1
                if counter[k] <= 0:
                    del counter[k]

    def failed(self, e: Entry) -> None:
        """A write of `e` failed: retried at the next flush, a few times."""
        e.failures += 1
        if e.failures < MAX_WRITE_FAILURES:
            e.dirty, e.written = True, False
        else:
            self.forget(next((k for k, x in self.entries.items() if x is e), ()))

    def take_stats(self) -> dict[Device, Stats]:
        out, self.stats = self.stats, {}
        return out

    def take_hints(self) -> dict[Device, datetime]:
        out, self.hints = self.hints, {}
        return out

    def reset(self) -> None:
        """After a restore: nothing in memory belongs to the database that's there now."""
        self.entries.clear()
        self.per_device.clear()
        self.per_tenant.clear()
        self.buckets.clear()
        self.used, self.day = {}, None
        self.stats.clear()
        self.hints.clear()


# ── The receiver ─────────────────────────────────────────────────────────────


def own_gateways(route: str = "/proc/net/route", route6: str = "/proc/net/ipv6_route") -> set[str]:
    """The container's default gateways. A datagram "from" one was rewritten on its way in (Docker's userland proxy,
    rootless Docker): it isn't the device's address, and must never be attributed to whoever claims that address."""
    out: set[str] = set()
    try:
        with open(route) as f:
            for line in f.readlines()[1:]:
                p = line.split()
                if len(p) > 2 and p[1] == "00000000" and p[2] != "00000000":
                    out.add(str(ipaddress.IPv4Address(int(p[2], 16).to_bytes(4, "little"))))
    except (OSError, ValueError):
        pass
    try:
        with open(route6) as f:
            for line in f:
                p = line.split()
                if len(p) > 4 and p[1] == "00" and int(p[4], 16):
                    gw = ipaddress.IPv6Address(int(p[4], 16))
                    if not gw.is_link_local:   # fe80:: is per interface, and a datagram from it can't come from outside
                        out.add(str(gw))
    except (OSError, ValueError):
        pass
    return out


def kernel_drops(port: int) -> int | None:
    """Datagrams the kernel dropped for our socket (its receive buffer was full): /proc/net/udp{,6}, last column."""
    total, found = 0, False
    want = f":{port:04X}"
    for path in ("/proc/net/udp", "/proc/net/udp6"):
        try:
            with open(path) as f:
                next(f, None)
                for line in f:
                    cols = line.split()
                    if len(cols) > 12 and cols[1].endswith(want):
                        total += int(cols[-1])
                        found = True
        except (OSError, ValueError):
            continue
    return total if found else None


class Receiver:
    """Receives, attributes, parses and coalesces (socket thread); stores every FLUSH_SECONDS (writer thread). `load`
    returns the claims, `store` writes a Batch, `usage` today's stored bytes per tenant; `paused` is true while a
    restore replaces the database."""

    def __init__(self, load: Callable[[], Claims], store: Callable[[Batch], None], paused: Callable[[], object] = lambda: None,
                 usage: Callable[[], dict[uuid.UUID, int]] | None = None, port: int = LISTEN_PORT) -> None:
        self.load, self.store, self.paused, self.usage, self.port = load, store, paused, usage, port
        self.claims = Claims()
        self.coalescer = Coalescer()
        self.lock = threading.Lock()
        self.unknown: Counter[str] = Counter()   # datagrams from addresses no enabled device has
        self.unknown_why: dict[str, str] = {}
        self.unknown_sample: dict[str, str] = {}
        self.dropped: Counter[str] = Counter()   # unknown | ambiguous | disabled
        self.received = 0
        self.raw: dict[uuid.UUID, Bucket] = {}   # per device, before parsing: what a flood can cost in CPU
        self.rewritten = own_gateways()          # Docker's own gateways: a source rewritten on the way in
        self._usage_loaded = False
        self._paused = False
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self.threads: list[threading.Thread] = []

    def bind(self) -> socket.socket:
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            s.bind(("::", self.port))
        except OSError:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("0.0.0.0", self.port))  # noqa: S104 — the published port decides who can reach it
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        s.settimeout(0.5)
        return s

    def start(self) -> None:
        self._sock = self.bind()
        self.threads = [threading.Thread(target=self.run, name="syslog", daemon=True),
                        threading.Thread(target=self.write_loop, name="syslog-writer", daemon=True)]
        for t in self.threads:
            t.start()

    def alive(self) -> bool:
        """Both threads are running (a thread that died is a receiver that silently stopped)."""
        return bool(self.threads) and all(t.is_alive() for t in self.threads)

    def stop(self) -> None:
        self._stop.set()
        for t in self.threads:
            t.join(5)
        if self._sock:
            self._sock.close()
        if any(t.is_alive() for t in self.threads if t.name == "syslog-writer"):
            log.warning("Syslog: the writer is still storing; the last messages are dropped")
            return   # one writer only: a second transaction could commit a later seq first and a live viewer skip one
        try:
            self.flush(stats=True)
        except Exception as exc:  # noqa: BLE001 — the database may be gone already
            log.warning("Syslog: couldn't store the last messages: %s", exc)

    def handle(self, data: bytes, addr: str, now: datetime | None = None) -> str:
        self.received += 1
        ip = normalize_ip(addr)
        dev, why = (None, "rewritten") if ip in self.rewritten else self.claims.lookup(ip)
        if dev is None:
            self.dropped[why] += 1
            if ip in self.unknown or len(self.unknown) < MAX_UNKNOWN:
                n = self.unknown[ip] = self.unknown[ip] + 1
                self.unknown_why[ip] = why
                if n == 1 or n % 50 == 0:  # not every datagram: a flood shouldn't cost a redaction each
                    self.unknown_sample[ip] = redact(_clean(data[:MAX_DATAGRAM]))[:SAMPLE_CHARS]
            return why
        if not self.raw.setdefault(dev.client_id, Bucket(RAW_RATE, RAW_BURST, RAW_BURST)).take(time.monotonic()):
            with self.lock:
                self.coalescer.stats.setdefault(dev, Stats()).quota += 1
            return "quota"
        msg = parse(data, dev.vendor)
        with self.lock:
            return self.coalescer.add(dev, msg, now or datetime.now(UTC), ip)

    def _reload(self) -> None:
        try:
            # Today's usage first, once: until it's in, no claims, so nothing is stored against a zero quota.
            if self.usage is not None and not self._usage_loaded:
                used = self.usage()
                with self.lock:
                    self.coalescer.set_usage(datetime.now(UTC).date(), used)
                self._usage_loaded = True
            self.claims = self.load()
        except Exception as exc:  # noqa: BLE001 — the database may be restarting: keep the last claims
            log.warning("Syslog: couldn't load the device addresses: %s", exc)

    def run(self) -> None:
        """The socket thread: nothing here waits on the database."""
        assert self._sock is not None  # noqa: S101
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(MAX_DATAGRAM + 512)
            except TimeoutError:
                continue
            except OSError as exc:
                if self._stop.is_set():
                    return
                log.warning("Syslog socket error: %s", exc)
                continue
            if not self._paused:
                try:
                    self.handle(data, addr[0])
                except Exception:   # one bad datagram mustn't stop the receiver
                    log.exception("Syslog: couldn't handle a datagram from %s", addr[0])

    def write_loop(self) -> None:
        last_load = last_stats = 0.0
        was_paused = False
        while not self._stop.wait(FLUSH_SECONDS):
            self._paused = paused = bool(self.paused())
            if paused:
                was_paused = True
                continue
            if was_paused:
                with self.lock:
                    self.coalescer.reset()  # a restore replaced the database: start over, with fresh claims and usage
                was_paused, last_load, self._usage_loaded = False, 0.0, False
            mono = time.monotonic()
            if mono - last_load > RELOAD_SECONDS:
                self._reload()
                last_load = mono
            stats = mono - last_stats >= STATS_SECONDS
            try:
                self.flush(stats)
            except Exception as exc:  # noqa: BLE001 — what failed is retried at the next flush
                log.warning("Syslog: couldn't store messages: %s", exc)
            if stats:
                last_stats = mono

    def flush(self, stats: bool = False) -> None:
        now, mono = datetime.now(UTC), time.monotonic()
        with self.lock:
            batch = Batch(now, self.coalescer.take(now, mono), self.coalescer.take_stats() if stats else {}, self.coalescer.take_hints())
        if not (batch.entries or batch.stats or batch.hints):
            return
        try:
            self.store(batch)
        except Exception:
            batch.failed = list(batch.entries)
            raise
        finally:
            if batch.failed:
                with self.lock:
                    for e in batch.failed:
                        self.coalescer.failed(e)

    def health(self) -> dict:
        port = self._sock.getsockname()[1] if self._sock else self.port
        return {"received": self.received, "sources": len(self.claims.enabled), "unknown_source": self.dropped["unknown"],
                "ambiguous": self.dropped["ambiguous"], "disabled": self.dropped["disabled"], "rewritten": self.dropped["rewritten"],
                "unknown_top": [{"address": a, "count": n, "why": self.unknown_why.get(a, "unknown"), "sample": self.unknown_sample.get(a, "")}
                                for a, n in self.unknown.most_common(5)],
                "open_entries": len(self.coalescer.entries), "kernel_drops": kernel_drops(port)}


# ── The database side ────────────────────────────────────────────────────────


def load_claims() -> Claims:
    """Every RADIUS client's address (and its extra syslog addresses), in every tenant, and the SNMP address of every
    monitored Cisco switch. A claim may attribute when its tenant is active and the device has syslog on, or (an SNMP
    address) the switch answered a poll there within three intervals with its tenant's credentials."""
    from sqlalchemy import select

    from app import models as m
    from app.db import platform_session
    now = datetime.now(UTC)
    out: list[tuple[str, Device, bool]] = []
    with platform_session() as s:
        rows = s.execute(select(m.RadiusClient, m.SwitchState.last_ok_at, m.Tenant.status)
                         .join(m.Tenant, m.Tenant.id == m.RadiusClient.tenant_id)
                         .outerjoin(m.SwitchState, m.SwitchState.client_id == m.RadiusClient.id)).all()
        for c, last_ok, status in rows:
            live = status in ("active", "setup")
            dev = Device(c.id, c.tenant_id, c.vendor)
            sl = c.syslog or {}
            on = live and bool(sl.get("enabled"))
            out.append((c.address, dev, on))
            if on:   # extra addresses only claim while syslog is on (a switched-off claim mustn't block another tenant)
                out += [(a, dev, on) for a in (sl.get("addresses") or [])[:8] if isinstance(a, str)]
            mon = c.monitoring or {}
            if c.vendor == "cisco-switch" and mon.get("enabled") and mon.get("host"):
                interval = timedelta(minutes=int(mon.get("interval_minutes") or 15))
                verified = bool(last_ok and now - last_ok <= interval * 3)
                out.append((mon["host"], dev, live and verified, verified))
    return Claims(out)


def load_usage() -> dict[uuid.UUID, int]:
    from sqlalchemy import func, select

    from app import models as m
    from app.db import platform_session
    with platform_session() as s:
        return {t: int(n or 0) for t, n in s.execute(select(m.SyslogStats.tenant_id, func.sum(m.SyslogStats.bytes))
                                                     .where(m.SyslogStats.day == datetime.now(UTC).date()).group_by(m.SyslogStats.tenant_id))}


def _rows(entries: list[Entry]):
    from sqlalchemy.dialects.postgresql import insert

    from app import models as m
    stmt = insert(m.SwitchSyslog).values([{
        "id": e.id, "tenant_id": e.device.tenant_id, "client_id": e.device.client_id, "first_at": e.first_at, "last_at": e.last_at,
        "count": e.count, "severity": e.msg.severity, "facility": e.msg.facility[:32], "mnemonic": e.msg.mnemonic[:48],
        "port": e.msg.port[:64], "mac": e.msg.mac[:12], "session_id": e.msg.session_id[:64], "subject": e.msg.subject[:64],
        "text": e.msg.text[:MAX_TEXT], "notable": e.notable, "source": e.source[:64]} for e in entries])
    # The trigger gives the row a new seq on the update too: the live view sees the new count.
    return stmt.on_conflict_do_update(index_elements=["id"], set_={"count": stmt.excluded.count, "last_at": stmt.excluded.last_at})


def store(batch: Batch) -> None:
    """Write the batch, one tenant at a time in the tenant's own session (row-level security checks each row): the
    messages in one statement (row by row when that fails, so one removed device doesn't hold up the others), the
    per-device counters and the poll hints. What can't be written goes to batch.failed."""
    from sqlalchemy import case, func, or_, update
    from sqlalchemy.dialects.postgresql import insert
    from sqlalchemy.exc import SQLAlchemyError

    from app import models as m
    from app.db import new_session, set_tenant
    tenants = {e.device.tenant_id for e in batch.entries} | {d.tenant_id for d in batch.stats} | {d.tenant_id for d in batch.hints}
    for tid in tenants:
        mine = [e for e in batch.entries if e.device.tenant_id == tid]
        failed: list[Entry] = []
        s = new_session()
        try:
            set_tenant(s, tid)
            if mine:
                try:
                    with s.begin_nested():
                        s.execute(_rows(mine))
                except SQLAlchemyError:
                    for e in mine:
                        try:
                            with s.begin_nested():
                                s.execute(_rows([e]))
                        except SQLAlchemyError:
                            failed.append(e)
            for dev, st in ((d, st) for d, st in batch.stats.items() if d.tenant_id == tid):
                stmt = insert(m.SyslogStats).values(client_id=dev.client_id, tenant_id=tid, day=batch.at.date(), received=st.received,
                                                    kept=st.kept, quota=st.quota, bytes=st.bytes, last_at=st.last_at, last_tag=st.last_tag)
                same = m.SyslogStats.day == stmt.excluded.day
                stmt = stmt.on_conflict_do_update(index_elements=["client_id"], set_={
                    "day": stmt.excluded.day,
                    **{k: case((same, getattr(m.SyslogStats, k) + getattr(stmt.excluded, k)), else_=getattr(stmt.excluded, k))
                       for k in ("received", "kept", "quota", "bytes")},
                    "last_at": func.coalesce(stmt.excluded.last_at, m.SyslogStats.last_at),
                    "last_tag": case((stmt.excluded.last_at.is_(None), m.SyslogStats.last_tag), else_=stmt.excluded.last_tag)})
                try:
                    with s.begin_nested():
                        s.execute(stmt)
                except SQLAlchemyError:
                    pass  # the device was just removed
            for dev, at in ((d, at) for d, at in batch.hints.items() if d.tenant_id == tid):
                # One statement, so it's computed from the row as it is when written: a poll the collector finishes
                # meanwhile moves polled_at, and the hint follows it.
                hint = func.greatest(m.SwitchState.polled_at + HINT_MIN_GAP, at + HINT_DELAY)
                s.execute(update(m.SwitchState)
                          .where(m.SwitchState.client_id == dev.client_id, m.SwitchState.polled_at.is_not(None),
                                 or_(m.SwitchState.next_poll_at.is_(None), hint < m.SwitchState.next_poll_at))
                          .values(next_poll_at=hint).execution_options(synchronize_session=False))
            s.commit()
            batch.failed += failed
        except Exception:
            s.rollback()
            batch.failed += mine
            log.warning("Syslog: couldn't store tenant %s's messages", tid, exc_info=True)
        finally:
            s.close()


def heartbeat(health: dict) -> None:
    from app import models as m
    from app.db import platform_session
    with platform_session() as s:
        hb = s.get(m.PlatformSetting, "syslog_heartbeat") or m.PlatformSetting(key="syslog_heartbeat", value={})
        hb.value = {"at": datetime.now(UTC).isoformat(), **health}
        s.add(hb)


def prune(s) -> int:
    """Platform-scoped: forget notable messages after KEEP_DAYS and the rest after KEEP_DAYS_OTHER, in batches."""
    from sqlalchemy import and_, delete, or_, select

    from app import models as m
    now = datetime.now(UTC)
    old = or_(m.SwitchSyslog.last_at < now - timedelta(days=KEEP_DAYS),
              and_(m.SwitchSyslog.notable.is_(False), m.SwitchSyslog.last_at < now - timedelta(days=KEEP_DAYS_OTHER)))
    total = 0
    while True:
        ids = select(m.SwitchSyslog.id).where(old).limit(PRUNE_BATCH).scalar_subquery()
        n = s.execute(delete(m.SwitchSyslog).where(m.SwitchSyslog.id.in_(ids)).execution_options(synchronize_session=False)).rowcount or 0
        s.commit()
        total += n
        if n < PRUNE_BATCH:
            return total


def main() -> None:
    from app.backup.engine import maintenance
    from app.db import platform_session
    from app.logs.dbhandler import install as install_db_logging
    from app.security.redact import configure_logging
    configure_logging()
    install_db_logging("switch-syslog")
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    r = Receiver(load_claims, store, maintenance, load_usage)
    r.start()
    log.info("EasyEAP syslog receiver started on UDP %s", r.port)
    last_beat = last_prune = 0.0
    while not stop.wait(5):
        if not r.alive():
            log.error("Syslog receiver: a thread stopped; exiting so the container restarts")
            r.stop()
            sys.exit(1)
        if maintenance():
            continue
        try:
            if time.monotonic() - last_beat > HEARTBEAT_SECONDS:
                heartbeat(r.health())
                last_beat = time.monotonic()
            if time.monotonic() - last_prune > PRUNE_SECONDS:
                with platform_session() as s:
                    prune(s)
                last_prune = time.monotonic()
        except Exception as exc:  # noqa: BLE001 — the database may be restarting
            log.warning("Syslog receiver: %s", exc)
    r.stop()
    log.info("EasyEAP syslog receiver stopped")


if __name__ == "__main__":
    main()
