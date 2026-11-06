"""Remote syslog: forward the audit trail, authentication events and the system log to up to four destinations.

* Transports: UDP (RFC 5426, best effort), TCP (RFC 6587) and TLS (RFC 5425). TLS verifies the server certificate and
  name against the system CAs, or against a pasted CA bundle instead.
* Formats: RFC 5424 or RFC 3164 headers, with a text (key="value") or JSON body. TCP and TLS frame each message with
  octet counting (RFC 6587 3.4.1) by default, or with a trailing newline.
* Delivery: the worker's forwarder reads each category past a per-destination cursor (row ids are monotonic), sends a
  batch, and advances the cursor only after the batch was written to the connection: at least once over TCP and TLS.
  A new destination starts at the newest rows; it does not replay history.
* Nothing here is secret: audit rows are already free of secrets, and system log messages were redacted when written.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import select
import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import text

from app.config import get_settings

log = logging.getLogger("easyeap.syslog")

CATEGORIES = ("audit", "auth", "system")
MAX_DESTINATIONS = 4
BATCH = 500
UDP_MAX = 8192
CONFIG_KEY, STATE_KEY = "syslog", "syslog_state"
FACILITIES = {"user": 1, "daemon": 3, "auth": 4, "authpriv": 10, **{f"local{i}": 16 + i for i in range(8)}}
SEVERITY = {"emergency": 0, "alert": 1, "critical": 2, "error": 3, "warning": 4, "notice": 5, "info": 6, "debug": 7}
LEVEL_ORDER = ("debug", "info", "warning", "error", "critical")
_HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


class Destination(BaseModel):
    """One remote syslog receiver (stored in platform_settings['syslog'])."""
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12], pattern=r"^[a-f0-9]{6,32}$")
    name: str = Field(min_length=1, max_length=60)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    transport: Literal["udp", "tcp", "tls"] = "tls"
    format: Literal["rfc5424", "rfc3164"] = "rfc5424"
    body: Literal["text", "json"] = "text"
    framing: Literal["octet", "newline"] = "octet"
    facility: str = "local0"
    categories: list[Literal["audit", "auth", "system"]] = Field(default_factory=lambda: list(CATEGORIES), min_length=1)
    system_level: Literal["info", "warning", "error"] = "info"
    ca_pem: str | None = Field(default=None, max_length=65536)
    enabled: bool = True
    start_after: dict[str, int] = Field(default_factory=dict)
    created_at: str | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        return v.strip()

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        v = v.strip().strip("[]")
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            pass
        if not _HOST.match(v):
            raise ValueError("Enter a host name or IP address, without a scheme or port.")
        return v.lower()

    @field_validator("facility")
    @classmethod
    def _facility(cls, v: str) -> str:
        if v not in FACILITIES:
            raise ValueError(f"Facility must be one of {', '.join(FACILITIES)}.")
        return v

    @field_validator("categories")
    @classmethod
    def _cats(cls, v: list[str]) -> list[str]:
        return [c for c in CATEGORIES if c in v]

    @field_validator("ca_pem")
    @classmethod
    def _ca(cls, v: str | None) -> str | None:
        v = (v or "").strip()
        if not v:
            return None
        from cryptography import x509
        try:
            certs = x509.load_pem_x509_certificates(v.encode())
        except ValueError as exc:
            raise ValueError("The CA bundle must be one or more PEM certificates (-----BEGIN CERTIFICATE-----).") from exc
        if not certs:
            raise ValueError("The CA bundle has no certificates.")
        return v + "\n"

    @model_validator(mode="after")
    def _transport(self) -> Destination:
        if self.transport != "tls":
            self.ca_pem = None
        return self


# ── Messages ─────────────────────────────────────────────────────────────────

@dataclass
class Message:
    category: str
    id: int
    at: datetime
    severity: int
    fields: dict[str, Any] = field(default_factory=dict)


def _quote(v: Any) -> str:
    if v is None:
        return "-"
    if isinstance(v, (dict, list)):
        v = json.dumps(v, separators=(",", ":"), sort_keys=True, default=str)
    s = str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n")
    return f'"{s}"' if (not s or any(c in s for c in ' ="\\')) else s


def text_body(msg: Message) -> str:
    parts = [f"{msg.category}", f"seq={msg.id}"]
    parts += [f"{k}={_quote(v)}" for k, v in msg.fields.items() if v not in (None, "", {}, [])]
    return " ".join(parts)


def json_body(msg: Message) -> str:
    return json.dumps({"category": msg.category, "seq": msg.id, "at": _iso(msg.at), **{k: v for k, v in msg.fields.items() if v is not None}},
                      separators=(",", ":"), default=str, ensure_ascii=False)


def _iso(at: datetime) -> str:
    return at.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _ascii_token(v: str, limit: int) -> str:
    out = "".join(c for c in v if 33 <= ord(c) <= 126)[:limit]
    return out or "-"


def render(dest: Destination, msg: Message, hostname: str, app_name: str = "easyeap") -> bytes:
    """One syslog message, without transport framing."""
    pri = FACILITIES[dest.facility] * 8 + msg.severity
    body = json_body(msg) if dest.body == "json" else text_body(msg)
    host = _ascii_token(hostname, 255)
    if dest.format == "rfc5424":
        line = f"<{pri}>1 {_iso(msg.at)} {host} {_ascii_token(app_name, 48)} - {_ascii_token(msg.category, 32)} - {body}"
    else:
        at = msg.at.astimezone(UTC)
        line = f"<{pri}>{at:%b} {at.day:>2} {at:%H:%M:%S} {host} {_ascii_token(app_name, 24)}-{msg.category}: {body}"
    return line.encode("utf-8", "replace")


def frame(dest: Destination, data: bytes) -> bytes:
    if dest.framing == "newline":
        return data.replace(b"\n", b" ") + b"\n"
    return str(len(data)).encode() + b" " + data


def hostname() -> str:
    return urlparse(get_settings().public_url).hostname or socket.gethostname()


# ── Rows → messages ──────────────────────────────────────────────────────────

def fetch(conn: Any, category: str, after: int, *, limit: int = BATCH, system_level: str = "info") -> tuple[list[Message], int]:
    """Rows of one category with id > after, oldest first, and the id the cursor can move to (past rows that were
    scanned but filtered out). `conn` is a SQLAlchemy connection with platform scope."""
    if category == "audit":
        rows = conn.execute(text(
            "SELECT a.id, a.at, a.action, a.actor_type, a.actor_label, a.target_type, a.target_label, a.ip, a.detail, a.hash, t.name AS tenant "
            "FROM audit_events a LEFT JOIN tenants t ON t.id = a.tenant_id WHERE a.id > :after ORDER BY a.id LIMIT :n"),
            {"after": after, "n": limit}).mappings()
        msgs = [Message("audit", r["id"], r["at"], SEVERITY["warning"] if _audit_alarm(r["action"]) else SEVERITY["notice"], {
            "tenant": r["tenant"], "actor": r["actor_label"], "actor_type": r["actor_type"], "action": r["action"],
            "target": f"{r['target_type']}:{r['target_label']}" if r["target_type"] else r["target_label"] or None,
            "ip": r["ip"], "detail": r["detail"] or None, "hash": r["hash"]}) for r in rows]
        return msgs, msgs[-1].id if msgs else after
    if category == "auth":
        rows = conn.execute(text(
            "SELECT e.id, e.at, e.result, e.reason_code, e.username, e.calling_station_id, e.called_station_id, e.nas_ip, e.ssid, "
            "e.vlan_id, e.cert_serial, t.name AS tenant FROM auth_events e LEFT JOIN tenants t ON t.id = e.tenant_id "
            "WHERE e.id > :after ORDER BY e.id LIMIT :n"), {"after": after, "n": limit}).mappings()
        msgs = [Message("auth", r["id"], r["at"], SEVERITY["info"] if r["result"] == "accept" else SEVERITY["warning"], {
            "tenant": r["tenant"], "result": r["result"], "reason": r["reason_code"], "user": r["username"],
            "mac": r["calling_station_id"], "nas": r["nas_ip"], "called": r["called_station_id"], "ssid": r["ssid"],
            "vlan": r["vlan_id"], "serial": r["cert_serial"]}) for r in rows]
        return msgs, msgs[-1].id if msgs else after
    if category == "system":
        levels = set(LEVEL_ORDER[LEVEL_ORDER.index(system_level):])
        rows = list(conn.execute(text("SELECT id, at, level, source, logger, message FROM system_logs WHERE id > :after ORDER BY id LIMIT :n"),
                                 {"after": after, "n": limit}).mappings())
        msgs = [Message("system", r["id"], r["at"], SEVERITY.get(r["level"], SEVERITY["info"]), {
            "level": r["level"], "source": r["source"], "logger": r["logger"], "message": r["message"]}) for r in rows if r["level"] in levels]
        return msgs, rows[-1]["id"] if rows else after
    raise ValueError(category)


def _audit_alarm(action: str) -> bool:
    return action.endswith(("_failed", ".failed", "_denied", ".locked")) or action in {"auth.login_failed", "auth.reauth_failed", "system.restore_started"}


def newest_ids(conn: Any) -> dict[str, int]:
    r = conn.execute(text("SELECT (SELECT coalesce(max(id), 0) FROM audit_events), (SELECT coalesce(max(id), 0) FROM auth_events), "
                          "(SELECT coalesce(max(id), 0) FROM system_logs)")).one()
    return {"audit": int(r[0]), "auth": int(r[1]), "system": int(r[2])}


# ── Transport ────────────────────────────────────────────────────────────────

class Sender:
    """One connection to a destination. Reconnects when the peer has gone away."""

    def __init__(self, dest: Destination, timeout: float = 10):
        self.dest, self.timeout = dest, timeout
        self.sock: socket.socket | None = None

    def _connect(self) -> socket.socket:
        d = self.dest
        if d.transport == "udp":
            last: OSError | None = None
            for family, kind, proto, _, addr in socket.getaddrinfo(d.host, d.port, type=socket.SOCK_DGRAM):
                try:
                    s = socket.socket(family, kind, proto)
                    s.settimeout(self.timeout)
                    s.connect(addr)
                    return s
                except OSError as exc:
                    last = exc
            raise last or OSError(f"Can't resolve {d.host}")
        raw = socket.create_connection((d.host, d.port), timeout=self.timeout)
        if d.transport == "tcp":
            return raw
        ctx = ssl.create_default_context(cadata=d.ca_pem) if d.ca_pem else ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if d.ca_pem:
            # Private syslog CAs often omit extensions that strict RFC 5280 checking demands (Authority Key Identifier).
            # The chain, validity and host name are still verified against the pasted CA.
            ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
        try:
            return ctx.wrap_socket(raw, server_hostname=d.host)
        except BaseException:
            raw.close()
            raise

    def _alive(self) -> bool:
        """A syslog receiver never sends: a readable socket means it closed the connection (or sent close_notify)."""
        if self.sock is None:
            return False
        if self.dest.transport == "udp":
            return True
        try:
            readable, _, _ = select.select([self.sock], [], [], 0)
        except (OSError, ValueError):
            return False
        return not readable

    def send(self, messages: list[bytes]) -> None:
        if not self._alive():
            self.close()
            self.sock = self._connect()
        assert self.sock is not None  # noqa: S101 — set just above
        if self.dest.transport == "udp":
            for m in messages:
                self.sock.send(m[:UDP_MAX])
        else:
            self.sock.sendall(b"".join(frame(self.dest, m) for m in messages))

    def close(self) -> None:
        if self.sock is not None:
            try:
                if isinstance(self.sock, ssl.SSLSocket):
                    # Say goodbye (close_notify) so the receiver doesn't log a reset connection.
                    self.sock.settimeout(1)
                    self.sock.unwrap().close()
                else:
                    self.sock.close()
            except (OSError, ValueError):
                try:
                    self.sock.close()
                except OSError:
                    pass
        self.sock = None


def describe_error(exc: BaseException) -> str:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return f"The server's certificate isn't trusted: {exc.verify_message or exc.reason}. Paste its CA certificate, or check the host name."
    if isinstance(exc, ssl.SSLError):
        return f"TLS handshake failed ({exc.reason or exc}). Check that the port expects TLS."
    if isinstance(exc, socket.gaierror):
        return "The host name doesn't resolve."
    if isinstance(exc, ConnectionRefusedError):
        return "Connection refused: nothing is listening on that port."
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "Timed out connecting or sending."
    if isinstance(exc, OSError) and exc.strerror:
        return exc.strerror
    return str(exc) or type(exc).__name__


def send_test(dest: Destination, actor: str) -> None:
    """Send one message straight away (the console's "Send test message"). Raises on failure."""
    msg = Message("system", 0, datetime.now(UTC), SEVERITY["notice"], {
        "level": "info", "source": "api", "logger": "easyeap.syslog",
        "message": f"Test message from EasyEAP, sent by {actor} to destination \"{dest.name}\"."})
    sender = Sender(dest, timeout=8)
    try:
        sender.send([render(dest, msg, hostname())])
    finally:
        sender.close()


# ── Configuration and state ─────────────────────────────────────────────────

def load_destinations(s: Any) -> list[Destination]:
    from app import models as m
    row = s.get(m.PlatformSetting, CONFIG_KEY)
    out = []
    for d in (row.value if row else {}).get("destinations", []):
        try:
            out.append(Destination.model_validate(d))
        except ValueError:
            log.warning("Ignoring an invalid syslog destination in the settings")
    return out


def save_destinations(s: Any, dests: list[Destination]) -> None:
    from app import models as m
    row = s.get(m.PlatformSetting, CONFIG_KEY) or m.PlatformSetting(key=CONFIG_KEY, value={})
    row.value = {"destinations": [d.model_dump() for d in dests]}
    s.add(row)


def load_state(s: Any) -> dict[str, Any]:
    from app import models as m
    row = s.get(m.PlatformSetting, STATE_KEY)
    return dict(row.value) if row and row.value else {}


# ── Forwarder (runs in the worker) ───────────────────────────────────────────

class Forwarder(threading.Thread):
    def __init__(self, interval: float = 2.0):
        super().__init__(name="syslog-forwarder", daemon=True)
        self.interval = interval
        self.stop_event = threading.Event()
        self.senders: dict[str, tuple[str, Sender]] = {}
        self.retry_at: dict[str, float] = {}
        self.failures: dict[str, int] = {}
        self._last_backlog = 0.0

    def run(self) -> None:
        from app.backup.engine import maintenance
        log.info("Syslog forwarder started")
        while not self.stop_event.is_set():
            busy = False
            try:
                if maintenance():
                    self._close_all()
                    self.stop_event.wait(3)
                    continue
                busy = self.cycle()
            except Exception as exc:  # noqa: BLE001 — keep forwarding; the database may be restarting
                log.warning("Syslog forwarder error: %s", exc)
                self.stop_event.wait(5)
            self.stop_event.wait(0.2 if busy else self.interval)
        self._close_all()

    def _close_all(self) -> None:
        for _, sender in self.senders.values():
            sender.close()
        self.senders.clear()

    def _sender(self, d: Destination) -> Sender:
        key = d.model_dump_json(include={"host", "port", "transport", "framing", "ca_pem"})
        cur = self.senders.get(d.id)
        if cur is None or cur[0] != key:
            if cur:
                cur[1].close()
            cur = (key, Sender(d))
            self.senders[d.id] = cur
        return cur[1]

    def cycle(self) -> bool:
        """Send at most one batch per category per destination. Returns True when there is more to send."""
        from app import models as m
        from app.db import platform_session
        busy = False
        with platform_session() as s:
            dests = load_destinations(s)
            row = s.get(m.PlatformSetting, STATE_KEY) or m.PlatformSetting(key=STATE_KEY, value={})
            state: dict[str, Any] = dict(row.value or {})
            before = json.dumps(state, sort_keys=True, default=str)
            live = {d.id for d in dests}
            for gone in set(self.senders) - live:
                self.senders.pop(gone)[1].close()
            state = {k: v for k, v in state.items() if k in live}
            conn = s.connection()
            host = hostname()
            now_mono = time.monotonic()
            backlog_due = now_mono - self._last_backlog > 15
            newest = newest_ids(conn) if backlog_due else None
            for d in dests:
                st = dict(state.get(d.id) or {})
                saved = st.get("cursors") or {}
                # start_after moves forward when a category is added to an existing destination.
                cursors = {c: max(int(d.start_after.get(c, 0)), int(saved.get(c, 0))) for c in {*d.start_after, *saved}}
                if not d.enabled:
                    state[d.id] = {**st, "cursors": cursors}
                    continue
                if self.retry_at.get(d.id, 0) > now_mono:
                    state[d.id] = {**st, "cursors": cursors}
                    continue
                failed = False
                for cat in d.categories:
                    prev = int(cursors.get(cat, 0))
                    msgs, last = fetch(conn, cat, prev, system_level=d.system_level)
                    more = last - prev >= BATCH  # a full page was scanned: there is probably more right now
                    if not msgs:
                        cursors[cat] = last
                        busy = busy or more
                        continue
                    try:
                        self._sender(d).send([render(d, msg, host) for msg in msgs])
                    except (OSError, ssl.SSLError, ValueError) as exc:
                        failed = True
                        n = self.failures.get(d.id, 0) + 1
                        self.failures[d.id] = n
                        self.retry_at[d.id] = now_mono + min(60, 2 ** min(n, 6))
                        self._sender(d).close()
                        err = describe_error(exc)
                        if st.get("error") != err:
                            log.warning("Syslog destination %s (%s:%s) is failing: %s", d.name, d.host, d.port, err)
                        st.update(error=err, error_at=datetime.now(UTC).isoformat())
                        break
                    cursors[cat] = last
                    st["sent"] = int(st.get("sent") or 0) + len(msgs)
                    st["last_sent_at"] = datetime.now(UTC).isoformat()
                    busy = busy or more
                if not failed and st.get("error"):
                    log.info("Syslog destination %s (%s:%s) is delivering again", d.name, d.host, d.port)
                    st.pop("error", None)
                    st["recovered_at"] = datetime.now(UTC).isoformat()
                if not failed:
                    self.failures.pop(d.id, None)
                    self.retry_at.pop(d.id, None)
                st["cursors"] = cursors
                if newest is not None:
                    st["backlog"] = sum(max(0, newest[c] - int(cursors.get(c, 0))) for c in d.categories)
                state[d.id] = st
            if backlog_due:
                self._last_backlog = now_mono
            if json.dumps(state, sort_keys=True, default=str) != before:
                row.value = state
                s.add(row)
        return busy
