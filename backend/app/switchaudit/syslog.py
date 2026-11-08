"""Syslog from monitored switches (docs/plans/switch-audit.md §0a): "the switch says".

Runs as its own container (`entrypoint.sh syslog`, `python -m app.switchaudit.syslog`) so a port conflict or a flood
never touches SNMP polling. It keeps the 802.1X, MAB, err-disable, RADIUS-server and configuration messages of
monitored switches and stores them coalesced per minute. Syslog isn't authenticated, so nothing here opens or resolves
a finding: messages are shown next to the SNMP evidence, and a few of them move the switch's next poll earlier.

A datagram is attributed to a switch only when it comes from that switch's SNMP management address and the switch
answered a poll there recently with its tenant's credentials; an address two switches claim is ignored. Per source a
token bucket, per switch and overall a cap on open coalescing entries, and per tenant a daily byte quota bound what
one sender can cost. Rows are written in the tenant's own session, so row-level security checks every insert.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import signal
import socket
import threading
import time
import uuid
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from app.radius.wired import PORT_TYPES, canonical_port

log = logging.getLogger("easyeap.syslog")

LISTEN_PORT = 5514            # inside the container; published as EASYEAP_SYSLOG_BIND:EASYEAP_SYSLOG_PORT
MAX_DATAGRAM = 2048           # longer messages are cut: switch messages are a few hundred bytes
MAX_TEXT = 500
RATE, BURST = 100.0, 200.0    # new messages a second per source
TENANT_BYTES_PER_DAY = 50 * 1024 * 1024
MAX_ENTRIES = 20_000          # open coalescing entries overall
MAX_ENTRIES_PER_SWITCH = 2_000
FLUSH_SECONDS = 2
RELOAD_SECONDS = 30
HEARTBEAT_SECONDS = 30
PRUNE_SECONDS = 24 * 3600
KEEP_DAYS = 14
MAX_WRITE_FAILURES = 5
# A message moves the next poll earlier, never sooner than this after the last poll (a spoofed message can't add load).
HINT_MIN_GAP, HINT_DELAY = timedelta(seconds=30), timedelta(seconds=10)

# What is kept: facility → mnemonics (a trailing "_" keeps every mnemonic with that prefix). Severity doesn't matter.
# The SESSION_MGR form of SECURITY_VIOLATION is kept in case IOS-XE logs it under that facility (unverified).
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
HINT_ON = {"ERR_DISABLE", "ERR_RECOVER", "SECURITY_VIOLATION", "CONFIG_I", "FAIL",   # the SNMP evidence should follow soon
           "IF_DOWN_ERROR_DISABLED", "IF_ERRDIS_RECOVERY", "VSHD_SYSLOG_CONFIG_I"}
PRIORITY = {"RADIUS_DEAD", "RADIUS_ALIVE", "ALLDEADSERVER", "ERR_DISABLE",     # kept even past the tenant's byte quota
            "IF_DOWN_ERROR_DISABLED"}
RADIUS_FACILITIES = {"RADIUS", "RADIUS_AUDIT_MESSAGE"}

# %FACILITY[-SUBFACILITY]-SEVERITY-MNEMONIC: (some platforms add a sub-facility, %PM-SP-4-ERR_DISABLE). Cisco Business
# writes the severity as a letter (%LINK-W-Down, %SEC-I-PORTAUTHORIZED) and mnemonics in mixed case.
_TAG = re.compile(rb"%([A-Z][A-Z0-9_]{0,31})(?:-[A-Z][A-Z0-9_]{0,15})?-([0-7]|[AFCEWNID])-([A-Z][A-Za-z0-9_]{0,47}):[ \t]?")
LETTER_SEVERITY = {"F": 0, "A": 1, "C": 2, "E": 3, "W": 4, "N": 5, "I": 6, "D": 7}
_ORIGIN = re.compile(r"^(?:(?:Switch|Chassis) ?\d+ )?R\d+/\d+: \w+: ")  # IOS-XE's "Switch 1 R0/0: sessmgrd: "
_PORT = re.compile(r"\b([A-Za-z][A-Za-z-]*?) ?(\d{1,4}(?:/\d{1,4}){1,3})\b")
_CLIENT_MAC = re.compile(r"\(([0-9a-fA-F]{4})\.([0-9a-fA-F]{4})\.([0-9a-fA-F]{4})\)")
_DOTTED_MAC = re.compile(r"\b([0-9a-fA-F]{4})\.([0-9a-fA-F]{4})\.([0-9a-fA-F]{4})\b")
_COLON_MAC = re.compile(r"\b((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})\b")
_SESSION = re.compile(r"AuditSessionID:? ?([0-9A-Fa-f]{8,64})")
_SERVER = re.compile(r"(?i)RADIUS server ([0-9A-Fa-f.:]+?)(?::(\d+)(?:,\d+)?)?(?: is|\s|$)")
_CONFIG_BY = re.compile(r"Configured from (.{1,80})$")
_CAUSE = re.compile(r"^(\S{1,40}) error detected")
_NX_CAUSE = re.compile(r"Reason: ?([^)]{1,40})\)")  # NX-OS: "is down (Error disabled. Reason:BPDUGuard)"
_REDACT = [
    (re.compile(r"(?i)\[user: [^\]]*\]"), "[user: <redacted>]"),
    (re.compile(r"(?i)\b(password|passwd|secret|key|community|user|username)(\s*[:=]\s*|\s+)([^\s,;\]]+)"), r"\1\2<redacted>"),
]


@dataclass(frozen=True)
class Message:
    facility: str
    severity: int
    mnemonic: str
    text: str
    port: str = ""
    mac: str = ""
    session_id: str = ""
    subject: str = ""  # what else tells two messages apart: a RADIUS server, who configured, an err-disable cause

    @property
    def tag(self) -> str:
        return f"{self.facility}-{self.severity}-{self.mnemonic}"


def kept(facility: str, mnemonic: str) -> bool:
    allowed = KEEP.get(facility)
    if not allowed:
        return False
    return mnemonic in allowed or any(a.endswith("_") and mnemonic.startswith(a) for a in allowed)


def redact(text: str) -> str:
    for rx, repl in _REDACT:
        text = rx.sub(repl, text)
    return text


def _clean(raw: bytes) -> str:
    s = raw.decode("utf-8", "replace")
    return " ".join("".join(ch if ch >= " " and ch != "\x7f" else " " for ch in s).split())


def port_of(text: str) -> str:
    for kind, num in _PORT.findall(text):
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
    if facility in RADIUS_FACILITIES:
        return server_of(body) or ("all" if mnemonic == "ALLDEADSERVER" else "")
    if mnemonic.endswith("CONFIG_I"):
        m = _CONFIG_BY.search(body)
        return m.group(1)[:64] if m else ""
    if mnemonic in ("ERR_DISABLE", "ERR_RECOVER", "IF_DOWN_ERROR_DISABLED"):
        m = _CAUSE.search(body) or _NX_CAUSE.search(body)
        return m.group(1)[:64] if m else ""
    return ""


def parse(data: bytes) -> Message | None:
    """The Cisco message in a syslog datagram, wherever the priority, counter, origin, sequence number and timestamp put
    the %FACILITY-SEVERITY-MNEMONIC tag; None when there's no tag."""
    data = data[:MAX_DATAGRAM]
    m = _TAG.search(data)
    if m is None:
        return None
    sev = m.group(2).decode()
    facility, severity, mnemonic = m.group(1).decode(), int(sev) if sev.isdigit() else LETTER_SEVERITY[sev], m.group(3).decode()
    body = _ORIGIN.sub("", _clean(data[m.end():]))
    text = redact(body)[:MAX_TEXT]
    sid = _SESSION.search(body)
    return Message(facility, severity, mnemonic, text, port_of(body), mac_of(body), sid.group(1).upper() if sid else "",
                   redact(_subject(facility, mnemonic, body)))


def normalize_ip(addr: str) -> str:
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return addr
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return str(ip.ipv4_mapped)
    return str(ip)


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


@dataclass(frozen=True)
class Switch:
    client_id: uuid.UUID
    tenant_id: uuid.UUID


@dataclass
class Entry:
    id: uuid.UUID
    switch: Switch
    msg: Message
    first_at: datetime
    last_at: datetime
    count: int = 1
    dirty: bool = True
    minute: int = 0
    failures: int = 0


@dataclass
class Stats:
    """Per switch, since the last write to switch_states.syslog."""
    received: int = 0
    kept: int = 0
    filtered: int = 0
    quota: int = 0
    last_at: datetime | None = None
    last_tag: str = ""


class Coalescer:
    """One entry per (switch, message, port, MAC, subject) per minute, counted; quotas per source, switch and tenant."""

    def __init__(self, max_entries: int = MAX_ENTRIES, per_switch: int = MAX_ENTRIES_PER_SWITCH,
                 tenant_bytes: int = TENANT_BYTES_PER_DAY) -> None:
        self.entries: dict[tuple, Entry] = {}
        self.per_switch: Counter[Switch] = Counter()
        self.buckets: dict[str, Bucket] = {}
        self.max_entries, self.max_per_switch, self.tenant_bytes = max_entries, per_switch, tenant_bytes
        self.used: dict[uuid.UUID, int] = {}
        self.day: date | None = None
        self.stats: dict[Switch, Stats] = {}
        self.hints: dict[Switch, datetime] = {}

    def set_usage(self, day: date, used: dict[uuid.UUID, int]) -> None:
        """Today's stored bytes per tenant (from the database), so a restart doesn't reset the quota."""
        self.day, self.used = day, dict(used)

    def add(self, source: str, sw: Switch, msg: Message | None, now: datetime, mono: float | None = None) -> str:
        """Count one datagram from a known switch. Returns what happened: kept | filtered | quota."""
        st = self.stats.setdefault(sw, Stats())
        st.received += 1
        if msg is None or not kept(msg.facility, msg.mnemonic):
            st.filtered += 1
            return "filtered"
        if self.day != now.date():
            self.day, self.used = now.date(), {}
        minute = int(now.timestamp() // 60)
        key = (sw.client_id, msg.facility, msg.mnemonic, msg.port, msg.mac, msg.subject, minute)
        e = self.entries.get(key)
        if e is not None:  # a repeat costs a counter, nothing more
            e.count, e.last_at, e.dirty = e.count + 1, now, True
        else:
            if not self.buckets.setdefault(source, Bucket()).take(time.monotonic() if mono is None else mono):
                st.quota += 1
                return "quota"
            size = len(msg.text) + 200
            over_bytes = self.used.get(sw.tenant_id, 0) + size > self.tenant_bytes and msg.mnemonic not in PRIORITY
            if over_bytes or len(self.entries) >= self.max_entries or self.per_switch[sw] >= self.max_per_switch:
                st.quota += 1
                return "quota"
            self.used[sw.tenant_id] = self.used.get(sw.tenant_id, 0) + size
            self.entries[key] = Entry(uuid.uuid4(), sw, msg, now, now, minute=minute)
            self.per_switch[sw] += 1
        st.kept += 1
        st.last_at, st.last_tag = now, msg.tag
        if msg.mnemonic in HINT_ON:
            self.hints[sw] = now
        return "kept"

    def take_dirty(self, now: datetime) -> list[Entry]:
        """The entries to write, marked clean. Entries of minutes that ended are forgotten at the flush after the one
        that wrote them, so a failed write (marked dirty again) loses nothing."""
        current = int(now.timestamp() // 60)
        for key in [k for k, e in self.entries.items() if not e.dirty and e.minute < current]:
            self.forget(key)
        out = [e for e in self.entries.values() if e.dirty]
        for e in out:
            e.dirty = False
        return out

    def forget(self, key: tuple) -> None:
        e = self.entries.pop(key, None)
        if e is not None:
            self.per_switch[e.switch] -= 1
            if self.per_switch[e.switch] <= 0:
                del self.per_switch[e.switch]

    def failed(self, e: Entry) -> None:
        """A write of `e` failed: retried at the next flush, a few times."""
        e.failures += 1
        if e.failures < MAX_WRITE_FAILURES:
            e.dirty = True
        else:
            self.forget(next((k for k, x in self.entries.items() if x is e), ()))

    def take_stats(self) -> dict[Switch, Stats]:
        out, self.stats = self.stats, {}
        return out

    def take_hints(self) -> dict[Switch, datetime]:
        out, self.hints = self.hints, {}
        return out

    def reset(self) -> None:
        """After a restore: nothing in memory belongs to the database that's there now."""
        self.entries.clear()
        self.per_switch.clear()
        self.buckets.clear()
        self.used, self.day = {}, None
        self.stats.clear()
        self.hints.clear()


# ── The receiver ─────────────────────────────────────────────────────────────


class Receiver:
    """Receives, filters and coalesces; `store` writes what's due every FLUSH_SECONDS, in the same thread. `load`
    returns the source-address → switch map, `usage` today's stored bytes per tenant; `paused` is true while a
    restore replaces the database."""

    def __init__(self, load: Callable[[], dict[str, Switch]], store: Callable[[Coalescer, datetime], None],
                 paused: Callable[[], object] = lambda: None, usage: Callable[[], dict[uuid.UUID, int]] | None = None,
                 port: int = LISTEN_PORT) -> None:
        self.load, self.store, self.paused, self.usage, self.port = load, store, paused, usage, port
        self.sources: dict[str, Switch] = {}
        self.coalescer = Coalescer()
        self.unknown: Counter[str] = Counter()  # datagrams from addresses that aren't a monitored switch
        self.received = 0
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self.thread: threading.Thread | None = None

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
        self.thread = threading.Thread(target=self.run, name="syslog", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self.thread:
            self.thread.join(5)
        if self._sock:
            self._sock.close()

    def handle(self, data: bytes, addr: str, now: datetime | None = None) -> str:
        self.received += 1
        ip = normalize_ip(addr)
        sw = self.sources.get(ip)
        if sw is None:
            if ip in self.unknown or len(self.unknown) < 1000:
                self.unknown[ip] += 1
            return "unknown"
        return self.coalescer.add(ip, sw, parse(data), now or datetime.now(UTC))

    def _reload(self) -> None:
        try:
            self.sources = self.load()
            if self.usage is not None and self.coalescer.day != datetime.now(UTC).date():
                self.coalescer.set_usage(datetime.now(UTC).date(), self.usage())
        except Exception as exc:  # noqa: BLE001 — the database may be restarting: keep the last map
            log.warning("Syslog: couldn't load the switch addresses: %s", exc)

    def run(self) -> None:
        assert self._sock is not None  # noqa: S101
        last_flush = last_load = last_check = 0.0
        paused = was_paused = False
        while not self._stop.is_set():
            now = time.monotonic()
            if now - last_check > 1:  # not per datagram: a flood shouldn't cost a file check each
                paused, last_check = bool(self.paused()), now
                if was_paused and not paused:
                    self.coalescer.reset()  # a restore replaced the database: start over, with a fresh map
                    last_load = 0.0
                was_paused = paused
            if not paused and now - last_load > RELOAD_SECONDS:
                self._reload()
                last_load = now
            try:
                data, addr = self._sock.recvfrom(MAX_DATAGRAM + 512)
            except TimeoutError:
                data = None
            except OSError as exc:
                log.warning("Syslog socket error: %s", exc)
                data = None
            if data is not None and not paused:
                self.handle(data, addr[0])
            if not paused and time.monotonic() - last_flush > FLUSH_SECONDS:
                last_flush = time.monotonic()
                try:
                    self.store(self.coalescer, datetime.now(UTC))
                except Exception as exc:  # noqa: BLE001 — what failed is retried at the next flush
                    log.warning("Syslog: couldn't store messages: %s", exc)

    def health(self) -> dict:
        return {"received": self.received, "sources": len(self.sources), "unknown_source": sum(self.unknown.values()),
                "unknown_top": [{"address": a, "count": n} for a, n in self.unknown.most_common(5)],
                "open_entries": len(self.coalescer.entries)}


# ── The database side ────────────────────────────────────────────────────────


def load_sources() -> dict[str, Switch]:
    """Source address → switch: the SNMP management address of every Cisco switch with monitoring on whose latest
    successful poll there was within three intervals (the switch answered the tenant's own credentials at that
    address). An address that more than one switch claims, in any tenant, is left out."""
    from sqlalchemy import select

    from app import models as m
    from app.db import platform_session
    now = datetime.now(UTC)
    out = []
    with platform_session() as s:
        rows = s.execute(select(m.RadiusClient, m.SwitchState)
                         .join(m.Tenant, m.Tenant.id == m.RadiusClient.tenant_id)
                         .outerjoin(m.SwitchState, m.SwitchState.client_id == m.RadiusClient.id)
                         .where(m.RadiusClient.vendor == "cisco-switch", m.RadiusClient.monitoring["enabled"].as_boolean().is_(True),
                                m.Tenant.status.in_(("active", "setup")))).all()
        for c, st in rows:
            mon = c.monitoring or {}
            interval = timedelta(minutes=int(mon.get("interval_minutes") or 15))
            verified = bool(st is not None and st.last_ok_at and now - st.last_ok_at <= interval * 3)
            out.append((Switch(c.id, c.tenant_id), {mon.get("host") or ""}, verified))
    return source_map(out)


def source_map(switches: Iterable[tuple[Switch, set[str], bool]]) -> dict[str, Switch]:
    """(switch, its addresses, verified) → address → switch. Every claim counts towards ambiguity, verified or not;
    only verified switches are mapped."""
    claims: dict[str, set[Switch]] = {}
    verified: set[Switch] = set()
    for sw, addrs, ok in switches:
        if ok:
            verified.add(sw)
        for a in addrs:
            if a:
                claims.setdefault(normalize_ip(a), set()).add(sw)
    return {a: next(iter(sws)) for a, sws in claims.items() if len(sws) == 1 and next(iter(sws)) in verified}


def load_usage() -> dict[uuid.UUID, int]:
    from sqlalchemy import func, select

    from app import models as m
    from app.db import platform_session
    day = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    with platform_session() as s:
        return {t: int(n or 0) for t, n in s.execute(select(m.SwitchSyslog.tenant_id, func.sum(func.length(m.SwitchSyslog.text) + 200))
                                                     .where(m.SwitchSyslog.first_at >= day).group_by(m.SwitchSyslog.tenant_id))}


def store(co: Coalescer, now: datetime) -> None:
    """Write the coalesced messages, the per-switch counters and the poll hints, one tenant at a time in the tenant's
    own session (row-level security checks each row). A row that can't be written (its switch was just removed) is
    retried a few times and then dropped, without holding up the others."""
    from sqlalchemy import func, or_, update
    from sqlalchemy.dialects.postgresql import insert
    from sqlalchemy.exc import SQLAlchemyError

    from app import models as m
    from app.db import new_session, set_tenant
    entries, stats, hints = co.take_dirty(now), co.take_stats(), co.take_hints()
    tenants = {e.switch.tenant_id for e in entries} | {sw.tenant_id for sw in stats} | {sw.tenant_id for sw in hints}
    for tid in tenants:
        mine = [e for e in entries if e.switch.tenant_id == tid]
        s = new_session()
        try:
            set_tenant(s, tid)
            for e in mine:
                stmt = insert(m.SwitchSyslog).values(
                    id=e.id, tenant_id=tid, client_id=e.switch.client_id, first_at=e.first_at, last_at=e.last_at, count=e.count,
                    severity=e.msg.severity, facility=e.msg.facility, mnemonic=e.msg.mnemonic, port=e.msg.port, mac=e.msg.mac,
                    session_id=e.msg.session_id, subject=e.msg.subject, text=e.msg.text)
                try:
                    with s.begin_nested():
                        s.execute(stmt.on_conflict_do_update(index_elements=["id"], set_={"count": e.count, "last_at": e.last_at}))
                except SQLAlchemyError:
                    co.failed(e)
            for sw, st in ((sw, st) for sw, st in stats.items() if sw.tenant_id == tid):
                state = s.get(m.SwitchState, sw.client_id)
                if state is None:
                    continue
                cur = dict(state.syslog or {})
                day = now.date().isoformat()
                if cur.get("day") != day:
                    cur = {"day": day, "received": 0, "kept": 0, "filtered": 0, "quota": 0}
                for k in ("received", "kept", "filtered", "quota"):
                    cur[k] = int(cur.get(k) or 0) + getattr(st, k)
                if st.last_at:
                    cur["last_at"], cur["last_tag"] = st.last_at.isoformat(), st.last_tag
                state.syslog = cur
            for sw, at in ((sw, at) for sw, at in hints.items() if sw.tenant_id == tid):
                # One statement, so it's computed from the row as it is when written: a poll the collector finishes
                # meanwhile moves polled_at, and the hint follows it.
                hint = func.greatest(m.SwitchState.polled_at + HINT_MIN_GAP, at + HINT_DELAY)
                s.execute(update(m.SwitchState)
                          .where(m.SwitchState.client_id == sw.client_id, m.SwitchState.polled_at.is_not(None),
                                 or_(m.SwitchState.next_poll_at.is_(None), hint < m.SwitchState.next_poll_at))
                          .values(next_poll_at=hint).execution_options(synchronize_session=False))
            s.commit()
        except Exception:
            s.rollback()
            for e in mine:
                if not e.dirty:  # not already marked by a failed row above
                    co.failed(e)
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
    """Platform-scoped: forget messages older than KEEP_DAYS."""
    from sqlalchemy import delete

    from app import models as m
    cutoff = datetime.now(UTC) - timedelta(days=KEEP_DAYS)
    return s.execute(delete(m.SwitchSyslog).where(m.SwitchSyslog.last_at < cutoff)).rowcount or 0


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
    r = Receiver(load_sources, store, maintenance, load_usage)
    r.start()
    log.info("EasyEAP syslog receiver started on UDP %s", r.port)
    last_beat = last_prune = 0.0
    while not stop.wait(5):
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
