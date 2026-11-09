"""A small SNMP manager: GET and GETBULK walks over SNMPv2c and SNMPv3 (USM, authPriv).

EasyEAP only reads a handful of tables from a switch, so this implements exactly that (docs/plans/switch-audit.md §0):

* BER for the types SNMP uses (RFC 3416), the v2c message (RFC 1901) and the v3 message (RFC 3412);
* USM (RFC 3414): engine discovery, the time window, key localization; HMAC-SHA-1-96 (RFC 3414) and
  HMAC-SHA-256-192 (RFC 7860) authentication; AES-128 and AES-256 in CFB mode (RFC 3826). AES-256 is only offered with
  SHA-256 authentication, whose 32-byte localized key is long enough, so no key extension (vendors disagree on which)
  is ever needed;
* one UDP socket per session, connected to the switch so the kernel drops datagrams from anyone else, with a timeout
  and retries per request and a deadline for the whole session.

Everything a switch sends is untrusted: lengths are checked against the buffer, nesting is bounded, a v3 response must
carry a valid HMAC before anything in it is believed, and a walk stops when the agent's OIDs stop increasing.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import socket
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

try:  # cryptography 47+ keeps CFB (still what SNMP's AES uses, RFC 3826) under "decrepit"
    from cryptography.hazmat.decrepit.ciphers.modes import CFB
except ImportError:  # pragma: no cover — older cryptography
    from cryptography.hazmat.primitives.ciphers.modes import CFB

OID = tuple[int, ...]

# ── Errors ───────────────────────────────────────────────────────────────────


class SnmpError(Exception):
    """kind: timeout | auth | protocol | config | too_big"""

    kind = "protocol"

    def __init__(self, message: str, kind: str | None = None) -> None:
        super().__init__(message)
        if kind:
            self.kind = kind


class SnmpTimeout(SnmpError):
    kind = "timeout"


class SnmpAuthError(SnmpError):
    kind = "auth"


# ── BER ──────────────────────────────────────────────────────────────────────

INTEGER, OCTET_STRING, NULL, OBJECT_ID, SEQUENCE = 0x02, 0x04, 0x05, 0x06, 0x30
IP_ADDRESS, COUNTER32, GAUGE32, TIMETICKS, OPAQUE, COUNTER64 = 0x40, 0x41, 0x42, 0x43, 0x44, 0x46
NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW = 0x80, 0x81, 0x82
GET, GETNEXT, RESPONSE, GETBULK, REPORT = 0xA0, 0xA1, 0xA2, 0xA5, 0xA8
MAX_DEPTH = 8
MAX_INT32 = 2_147_483_647
TIME_WINDOW = 150  # seconds (RFC 3414 §2.2.3)


class _Exception:
    """noSuchObject, noSuchInstance, endOfMibView: varbind values that say there is no value."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return self.name

    def __bool__(self) -> bool:
        return False


NoSuchObject, NoSuchInstance, EndOfMibView = _Exception("noSuchObject"), _Exception("noSuchInstance"), _Exception("endOfMibView")
_EXCEPTIONS = {NO_SUCH_OBJECT: NoSuchObject, NO_SUCH_INSTANCE: NoSuchInstance, END_OF_MIB_VIEW: EndOfMibView}


def is_missing(value: object) -> bool:
    return isinstance(value, _Exception)


def oid(text: str | OID) -> OID:
    if isinstance(text, tuple):
        return text
    return tuple(int(x) for x in text.strip(".").split("."))


def oid_text(o: OID) -> str:
    return ".".join(str(x) for x in o)


def _length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _length(len(body)) + body


def enc_int(v: int, tag: int = INTEGER) -> bytes:
    if tag == INTEGER:
        body = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True)
    else:  # unsigned application types: a leading zero keeps the top bit clear
        body = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
        if body[0] & 0x80:
            body = b"\x00" + body
    return tlv(tag, body)


def _base128(n: int) -> bytes:
    chunk = [n & 0x7F]
    n >>= 7
    while n:
        chunk.append(0x80 | (n & 0x7F))
        n >>= 7
    return bytes(reversed(chunk))


def enc_oid(o: OID) -> bytes:
    if len(o) < 2 or o[0] > 2 or (o[0] < 2 and o[1] > 39) or any(a < 0 for a in o):
        raise SnmpError(f"Invalid OID {oid_text(o)}", "config")
    return tlv(OBJECT_ID, _base128(o[0] * 40 + o[1]) + b"".join(_base128(a) for a in o[2:]))


def seq(*items: bytes, tag: int = SEQUENCE) -> bytes:
    return tlv(tag, b"".join(items))


@dataclass
class Node:
    tag: int
    start: int   # offset of the value in the buffer
    end: int
    buf: bytes

    @property
    def value(self) -> bytes:
        return self.buf[self.start:self.end]


def read(buf: bytes, pos: int = 0, end: int | None = None) -> tuple[Node, int]:
    """One TLV at `pos`; returns it and the position after it. Definite lengths only (SNMP forbids the others)."""
    end = len(buf) if end is None else end
    if pos + 2 > end:
        raise SnmpError("Truncated message")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise SnmpError("Unsupported multi-byte tag")
    n = buf[pos + 1]
    pos += 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or pos + k > end:
            raise SnmpError("Bad length")
        n = int.from_bytes(buf[pos:pos + k], "big")
        pos += k
    if pos + n > end:
        raise SnmpError("Truncated message")
    return Node(tag, pos, pos + n, buf), pos + n


def children(node: Node) -> list[Node]:
    out, pos = [], node.start
    while pos < node.end:
        child, pos = read(node.buf, pos, node.end)
        out.append(child)
        if len(out) > 10_000:
            raise SnmpError("Too many elements")
    return out


def dec_int(node: Node, signed: bool = True) -> int:
    v = node.value
    if not v or len(v) > 9:
        raise SnmpError("Bad integer")
    return int.from_bytes(v, "big", signed=signed)


def dec_oid(node: Node) -> OID:
    v = node.value
    if not v or len(v) > 512:
        raise SnmpError("Bad OID")
    subs, cur, count = [], 0, 0
    for b in v:
        cur = (cur << 7) | (b & 0x7F)
        count += 1
        if count > 5:
            raise SnmpError("Bad OID arc")
        if not b & 0x80:
            subs.append(cur)
            cur, count = 0, 0
    if count:
        raise SnmpError("Bad OID")
    first = min(subs[0] // 40, 2)
    return (first, subs[0] - 40 * first, *subs[1:])


def dec_value(node: Node) -> object:
    t = node.tag
    if t == INTEGER:
        return dec_int(node)
    if t in (OCTET_STRING, OPAQUE):
        return node.value
    if t == NULL:
        return None
    if t == OBJECT_ID:
        return dec_oid(node)
    if t == IP_ADDRESS:
        v = node.value
        return ".".join(str(b) for b in v) if len(v) == 4 else v.hex()
    if t in (COUNTER32, GAUGE32, TIMETICKS, COUNTER64):
        return dec_int(node, signed=False) if node.value else 0
    if t in _EXCEPTIONS:
        return _EXCEPTIONS[t]
    raise SnmpError(f"Unsupported value type 0x{t:02x}")


def _expect(node: Node, tag: int, what: str) -> Node:
    if node.tag != tag:
        raise SnmpError(f"Malformed {what}")
    return node


# ── PDUs ─────────────────────────────────────────────────────────────────────


@dataclass
class Pdu:
    kind: int
    request_id: int
    error_status: int
    error_index: int
    varbinds: list[tuple[OID, object]]


def enc_pdu(kind: int, request_id: int, oids: Sequence[OID], a: int = 0, b: int = 0) -> bytes:
    vbs = seq(*(seq(enc_oid(o), tlv(NULL, b"")) for o in oids))
    return seq(enc_int(request_id), enc_int(a), enc_int(b), vbs, tag=kind)


def dec_pdu(node: Node) -> Pdu:
    if node.tag not in (RESPONSE, REPORT, GET, GETNEXT, GETBULK):
        raise SnmpError(f"Unexpected PDU type 0x{node.tag:02x}")
    parts = children(node)
    if len(parts) != 4:
        raise SnmpError("Malformed PDU")
    vbs = []
    for vb in children(_expect(parts[3], SEQUENCE, "varbind list")):
        pair = children(_expect(vb, SEQUENCE, "varbind"))
        if len(pair) != 2:
            raise SnmpError("Malformed varbind")
        vbs.append((dec_oid(_expect(pair[0], OBJECT_ID, "varbind name")), dec_value(pair[1])))
    return Pdu(node.tag, dec_int(parts[0]), dec_int(parts[1]), dec_int(parts[2]), vbs)


ERROR_STATUS = {1: "tooBig", 2: "noSuchName", 3: "badValue", 4: "readOnly", 5: "genErr", 6: "noAccess", 16: "authorizationError"}

# ── USM (RFC 3414, RFC 7860, RFC 3826) ───────────────────────────────────────

AUTH = {"sha": ("sha1", 12), "sha256": ("sha256", 24)}
PRIV = {"aes128": 16, "aes256": 32}
USM_STATS = "1.3.6.1.6.3.15.1.1"
REPORTS = {
    oid(USM_STATS + ".1.0"): ("unsupportedSecLevels", "The switch doesn't accept authPriv for this user.", "auth"),
    oid(USM_STATS + ".2.0"): ("notInTimeWindows", "The switch's clock window moved.", "protocol"),
    oid(USM_STATS + ".3.0"): ("unknownUserNames", "The switch doesn't know this SNMPv3 user.", "auth"),
    oid(USM_STATS + ".4.0"): ("unknownEngineIDs", "The switch's engine ID changed during the request.", "protocol"),
    oid(USM_STATS + ".5.0"): ("wrongDigests", "The switch rejected the authentication key (wrong key, or a different authentication algorithm).", "auth"),
    oid(USM_STATS + ".6.0"): ("decryptionErrors", "The switch couldn't decrypt the request (wrong privacy key, or a different privacy algorithm).", "auth"),
}


def password_to_key(password: bytes, hash_name: str) -> bytes:
    """RFC 3414 A.2: hash one megabyte of the password repeated."""
    if not password:
        raise SnmpError("Empty key", "config")
    data = (password * (1_048_576 // len(password) + 1))[:1_048_576]
    return hashlib.new(hash_name, data).digest()


def localize(ku: bytes, engine_id: bytes, hash_name: str) -> bytes:
    return hashlib.new(hash_name, ku + engine_id + ku).digest()


@dataclass(frozen=True)
class V2c:
    community: str = field(repr=False)


@dataclass(frozen=True)
class V3:
    user: str
    auth_key: str = field(repr=False)
    priv_key: str = field(repr=False)
    auth: str = "sha256"
    priv: str = "aes128"

    def check(self) -> None:
        if self.auth not in AUTH or self.priv not in PRIV:
            raise SnmpError("Unsupported SNMPv3 protocols", "config")
        if self.priv == "aes256" and self.auth != "sha256":
            raise SnmpError("AES-256 needs SHA-256 authentication", "config")
        if len(self.auth_key) < 8 or len(self.priv_key) < 8:
            raise SnmpError("SNMPv3 keys are at least 8 characters", "config")


@dataclass
class _Engine:
    engine_id: bytes = b""
    boots: int = 0
    time: int = 0
    at: float = 0.0
    auth_key: bytes = b""
    priv_key: bytes = b""

    def now(self) -> int:
        return min(2_147_483_647, self.time + int(time.monotonic() - self.at))


# ── Session ──────────────────────────────────────────────────────────────────


@dataclass
class Session:
    """One switch. `deadline` (monotonic seconds) bounds everything this session does."""

    host: str
    creds: V2c | V3 = field(repr=False)
    port: int = 161
    timeout: float = 3.0
    retries: int = 2
    max_repetitions: int = 20
    deadline: float | None = None
    requests: int = 0
    _sock: socket.socket | None = field(default=None, repr=False)
    _engine: _Engine = field(default_factory=_Engine, repr=False)
    _ku: tuple[bytes, bytes] | None = field(default=None, repr=False)
    _verified: bool = field(default=False, repr=False)  # an authenticated v3 response has arrived
    _id: int = field(default_factory=lambda: secrets.randbelow(1 << 30) + 1, repr=False)
    _salt: int = field(default_factory=lambda: int.from_bytes(os.urandom(8), "big"), repr=False)

    def __post_init__(self) -> None:
        if isinstance(self.creds, V3):
            self.creds.check()

    def __enter__(self) -> Session:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    @property
    def engine_id(self) -> bytes:
        return self._engine.engine_id

    # ── transport ────────────────────────────────────────────────────────────

    def _socket(self) -> socket.socket:
        if self._sock is None:
            try:
                infos = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_DGRAM)
            except OSError as exc:
                raise SnmpError(f"Can't resolve {self.host}: {exc}", "config") from exc
            family, kind, proto, _, addr = infos[0]
            s = socket.socket(family, kind, proto)
            try:
                s.connect(addr)  # the kernel then drops datagrams from any other address
            except OSError as exc:
                s.close()
                raise SnmpError(f"Can't reach {self.host}: {exc}", "timeout") from exc
            self._sock = s
        return self._sock

    def _next_id(self) -> int:
        """A fresh random msgID or request-id, independent of the others: a response captured earlier can't be replayed
        into a later request by predicting its ids."""
        self._id = secrets.randbelow(2_147_483_646) + 1
        return self._id

    def _exchange(self, build, accept) -> object:
        """Send build() and wait for a datagram accept() returns something for (None = not ours), with retries."""
        sock = self._socket()
        last: Exception | None = None
        for _ in range(self.retries + 1):
            remaining = None if self.deadline is None else self.deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise SnmpTimeout("The poll ran out of time.")
            wait = self.timeout if remaining is None else min(self.timeout, remaining)
            try:
                sock.send(build())
            except OSError as exc:  # e.g. ICMP unreachable from an earlier send
                last = exc
                time.sleep(min(wait, 0.5))
                continue
            self.requests += 1
            until = time.monotonic() + wait
            while (left := until - time.monotonic()) > 0:
                sock.settimeout(left)
                try:
                    data = sock.recv(65535)
                except TimeoutError:
                    break
                except OSError as exc:  # ICMP port unreachable: nothing listens on that port
                    last = exc
                    break
                try:
                    got = accept(data)
                except SnmpAuthError:
                    raise
                except SnmpError as exc:
                    last = exc
                    continue
                if got is not None:
                    return got
        if isinstance(last, SnmpError) and not isinstance(last, SnmpTimeout):
            raise last
        raise SnmpTimeout(f"No answer from {self.host} port {self.port}.")

    # ── v2c ──────────────────────────────────────────────────────────────────

    def _v2c(self, kind: int, oids: Sequence[OID], a: int, b: int) -> Pdu:
        assert isinstance(self.creds, V2c)  # noqa: S101 — narrowing for the type checker
        rid = self._next_id()
        msg = seq(enc_int(1), tlv(OCTET_STRING, self.creds.community.encode()), enc_pdu(kind, rid, oids, a, b))

        def accept(data: bytes) -> Pdu | None:
            top, _ = read(data)
            parts = children(_expect(top, SEQUENCE, "message"))
            if len(parts) != 3 or dec_int(parts[0]) != 1:
                return None
            pdu = dec_pdu(parts[2])
            return pdu if pdu.kind == RESPONSE and pdu.request_id == rid else None

        return self._exchange(lambda: msg, accept)

    # ── v3 ───────────────────────────────────────────────────────────────────

    def _keys(self) -> None:
        c = self.creds
        assert isinstance(c, V3)  # noqa: S101
        h = AUTH[c.auth][0]
        if self._ku is None:
            self._ku = (password_to_key(c.auth_key.encode(), h), password_to_key(c.priv_key.encode(), h))
        e = self._engine
        e.auth_key = localize(self._ku[0], e.engine_id, h)
        e.priv_key = localize(self._ku[1], e.engine_id, h)[:PRIV[c.priv]]

    def _discover(self) -> None:
        """Learn the engine ID, boots and time from the Report an unauthenticated empty request draws (RFC 3414 §4)."""
        mid, rid = self._next_id(), self._next_id()
        sec = seq(tlv(OCTET_STRING, b""), enc_int(0), enc_int(0), tlv(OCTET_STRING, b""), tlv(OCTET_STRING, b""), tlv(OCTET_STRING, b""))
        scoped = seq(tlv(OCTET_STRING, b""), tlv(OCTET_STRING, b""), enc_pdu(GET, rid, []))
        msg = seq(enc_int(3), seq(enc_int(mid), enc_int(65507), tlv(OCTET_STRING, b"\x04"), enc_int(3)), tlv(OCTET_STRING, sec), scoped)

        def accept(data: bytes) -> bool | None:
            m = self._parse_v3(data)
            if m is None or m["msg_id"] != mid:
                return None
            if not m["engine_id"] or len(m["engine_id"]) > 32:
                raise SnmpError("The switch sent an invalid engine ID.")
            e = self._engine
            e.engine_id, e.boots, e.time, e.at = m["engine_id"], m["boots"], m["time"], time.monotonic()
            return True

        self._exchange(lambda: msg, accept)
        self._keys()

    def _parse_v3(self, data: bytes) -> dict | None:
        top, _ = read(data)
        parts = children(_expect(top, SEQUENCE, "message"))
        if len(parts) != 4 or dec_int(parts[0]) != 3:
            return None
        g = children(_expect(parts[1], SEQUENCE, "header"))
        if len(g) != 4:
            raise SnmpError("Malformed header")
        flags = _expect(g[2], OCTET_STRING, "flags").value
        if len(flags) != 1 or dec_int(g[3]) != 3:
            raise SnmpError("Not a USM message")
        sec_outer = _expect(parts[2], OCTET_STRING, "security parameters")
        sec_top, _ = read(data, sec_outer.start, sec_outer.end)
        sp = children(_expect(sec_top, SEQUENCE, "security parameters"))
        if len(sp) != 6:
            raise SnmpError("Malformed security parameters")
        boots, at = dec_int(sp[1]), dec_int(sp[2])
        if not (0 <= boots <= MAX_INT32 and 0 <= at <= MAX_INT32):
            raise SnmpError("The switch sent an invalid engine boots or time.")
        return {"msg_id": dec_int(g[0]), "flags": flags[0], "engine_id": sp[0].value, "boots": boots, "time": at,
                "user": sp[3].value, "auth": sp[4], "salt": sp[5].value, "data": parts[3]}

    def _v3(self, kind: int, oids: Sequence[OID], a: int, b: int, retried: bool = False) -> Pdu:
        c = self.creds
        assert isinstance(c, V3)  # noqa: S101
        if not self._engine.engine_id:
            self._discover()
        e = self._engine
        h, mac_len = AUTH[c.auth]
        mid, rid = self._next_id(), self._next_id()
        self._salt = (self._salt + 1) % (1 << 64)
        salt = self._salt.to_bytes(8, "big")
        boots, now = e.boots, e.now()
        scoped = seq(tlv(OCTET_STRING, e.engine_id), tlv(OCTET_STRING, b""), enc_pdu(kind, rid, oids, a, b))
        iv = boots.to_bytes(4, "big") + now.to_bytes(4, "big") + salt
        enc = Cipher(algorithms.AES(e.priv_key), CFB(iv)).encryptor()
        encrypted = enc.update(scoped) + enc.finalize()
        marker = os.urandom(mac_len)
        sec = seq(tlv(OCTET_STRING, e.engine_id), enc_int(boots), enc_int(now), tlv(OCTET_STRING, c.user.encode()),
                  tlv(OCTET_STRING, marker), tlv(OCTET_STRING, salt))
        msg = seq(enc_int(3), seq(enc_int(mid), enc_int(65507), tlv(OCTET_STRING, b"\x07"), enc_int(3)),
                  tlv(OCTET_STRING, sec), tlv(OCTET_STRING, encrypted))
        at = msg.index(marker)
        blank = msg[:at] + b"\x00" * mac_len + msg[at + mac_len:]
        digest = hmac.new(e.auth_key, blank, h).digest()[:mac_len]
        msg = msg[:at] + digest + msg[at + mac_len:]

        def accept(data: bytes) -> Pdu | tuple | None:
            m = self._parse_v3(data)
            if m is None or m["msg_id"] != mid:
                return None
            if not m["flags"] & 0x01:
                # Unauthenticated: only a Report can be, and it says why the switch refused the request.
                if m["flags"] & 0x02:
                    raise SnmpError("Encrypted response without authentication")
                pdu = dec_pdu(_scoped_pdu(m["data"]))
                if pdu.kind != REPORT:
                    raise SnmpError("Unauthenticated response")
                return ("report", pdu)
            if m["engine_id"] != e.engine_id:
                raise SnmpError("Response from a different SNMP engine")
            node: Node = m["auth"]
            if node.end - node.start != mac_len:
                raise SnmpAuthError("The switch's response has the wrong authentication length (a different authentication algorithm?).")
            got = data[node.start:node.end]
            check = hmac.new(e.auth_key, data[:node.start] + b"\x00" * mac_len + data[node.end:], h).digest()[:mac_len]
            if not hmac.compare_digest(got, check):
                raise SnmpAuthError("The switch's response failed authentication: the authentication key or algorithm differs.")
            # RFC 3414 §3.2 step 7: resynchronize with a newer boots/time, then drop anything outside the time window
            # (an authentic message replayed from earlier).
            if m["boots"] > e.boots or (m["boots"] == e.boots and m["time"] > e.now()):
                e.boots, e.time, e.at = m["boots"], m["time"], time.monotonic()
            if m["boots"] == MAX_INT32 or m["boots"] < e.boots or (m["boots"] == e.boots and m["time"] < e.now() - TIME_WINDOW):
                return None
            self._verified = True
            if m["flags"] & 0x02:
                if len(m["salt"]) != 8:
                    raise SnmpError("Bad privacy parameters")
                riv = m["boots"].to_bytes(4, "big") + m["time"].to_bytes(4, "big") + m["salt"]
                ct = _expect(m["data"], OCTET_STRING, "encrypted PDU").value
                dec = Cipher(algorithms.AES(e.priv_key), CFB(riv)).decryptor()
                plain = dec.update(ct) + dec.finalize()
                try:
                    top, _ = read(plain)
                except SnmpError as exc:
                    raise SnmpAuthError("The switch's response didn't decrypt: the privacy key or algorithm differs.") from exc
                pdu = dec_pdu(_scoped_pdu(top))
            else:
                pdu = dec_pdu(_scoped_pdu(m["data"]))
                if pdu.kind != REPORT:  # a response to an authPriv request must be encrypted too
                    raise SnmpError("The switch answered without encryption.")
            if pdu.kind == REPORT:
                return ("report", pdu)
            return pdu if pdu.kind == RESPONSE and pdu.request_id == rid else None

        try:
            got = self._exchange(lambda: msg, accept)
        except SnmpTimeout as exc:
            if not self._verified:
                # The engine answered discovery, so it's there; a switch silently drops what it can't decrypt.
                raise SnmpAuthError("The switch answered but ignored EasyEAP's request: the privacy key or algorithm "
                                    "probably differs (or the user isn't allowed this view).") from exc
            raise
        if isinstance(got, tuple):
            pdu = got[1]
            name, text, err_kind = REPORTS.get(pdu.varbinds[0][0] if pdu.varbinds else (), ("report", "The switch refused the request.", "protocol"))
            if name in ("notInTimeWindows", "unknownEngineIDs") and not retried:
                if name == "unknownEngineIDs":
                    self._engine = _Engine()
                return self._v3(kind, oids, a, b, retried=True)
            raise SnmpError(text, err_kind) if err_kind != "auth" else SnmpAuthError(text)
        return got

    # ── requests ─────────────────────────────────────────────────────────────

    def request(self, kind: int, oids: Sequence[OID], a: int = 0, b: int = 0) -> Pdu:
        pdu = self._v3(kind, oids, a, b) if isinstance(self.creds, V3) else self._v2c(kind, oids, a, b)
        if pdu.error_status:
            name = ERROR_STATUS.get(pdu.error_status, str(pdu.error_status))
            raise SnmpError(f"The switch answered {name}.", "too_big" if pdu.error_status == 1 else "protocol")
        return pdu

    def get(self, oids: Iterable[str | OID]) -> dict[OID, object]:
        wanted = [oid(o) for o in oids]
        pdu = self.request(GET, wanted)
        return dict(pdu.varbinds)

    def walk(self, base: str | OID, max_rows: int = 20_000, truncate: bool = False) -> list[tuple[OID, object]]:
        """Every (OID, value) under `base`, by GETBULK. Past `max_rows`: raises SnmpError(kind=too_big), or with
        `truncate` returns max_rows + 1 rows (the caller tells it was cut short by the extra row)."""
        root = oid(base)
        cur, out = root, []
        reps = self.max_repetitions
        while True:
            try:
                pdu = self.request(GETBULK, [cur], 0, reps)
            except SnmpError as exc:
                if exc.kind == "too_big" and reps > 1:
                    reps = max(1, reps // 2)
                    continue
                raise
            if not pdu.varbinds:
                return out
            for o, v in pdu.varbinds:
                if v is EndOfMibView or o[:len(root)] != root or len(o) == len(root):
                    return out
                if o <= cur:
                    raise SnmpError("The switch returned OIDs out of order.")
                if not is_missing(v):
                    out.append((o, v))
                cur = o
                if len(out) > max_rows:
                    if truncate:
                        return out
                    raise SnmpError(f"More than {max_rows} rows under {oid_text(root)}.", "too_big")

    def first(self, base: str | OID) -> tuple[OID, object] | None:
        """The first row under `base` (GETNEXT), or None: the capability probe."""
        root = oid(base)
        pdu = self.request(GETNEXT, [root])
        for o, v in pdu.varbinds:
            if v is not EndOfMibView and not is_missing(v) and o[:len(root)] == root and len(o) > len(root):
                return o, v
        return None


def _scoped_pdu(node: Node) -> Node:
    parts = children(_expect(node, SEQUENCE, "scoped PDU"))
    if len(parts) != 3:
        raise SnmpError("Malformed scoped PDU")
    return parts[2]


def text(value: object, limit: int = 255) -> str:
    """An OCTET STRING as printable text (SnmpAdminString is UTF-8); control characters dropped."""
    if isinstance(value, bytes):
        s = value.decode("utf-8", "replace")
    elif value is None or is_missing(value):
        return ""
    else:
        s = str(value)
    return "".join(ch for ch in s if ch >= " " and ch != "\x7f")[:limit].strip()


def mac(value: object) -> str:
    """A MacAddress (6 octets) as 12 uppercase hex digits, or ""."""
    return value.hex().upper() if isinstance(value, bytes) and len(value) == 6 else ""
