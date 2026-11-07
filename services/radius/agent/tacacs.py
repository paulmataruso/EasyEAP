"""EasyEAP TACACS+ service (RFC 8907): administrator logins to switches and controllers with AD or local accounts.

docs/plans/device-admin.md §2 and §4. Started and supervised by the radius-agent once a device has admin logins on.
It decides every login from the agent's local copy of the tenant's admin data (admin.json, 0600), so logins keep
working while the EasyEAP API is down, and writes what happened to the agent's spool (admin-*.jsonl).

* Only registered, admin-enabled device addresses are answered; anything else is dropped (TCP: not spoofable).
* FAIL is final on IOS, ERROR makes it try the next method (the device's own accounts): FAIL only for a real denial;
  ERROR when EasyEAP can't decide (domain controllers down, admin data expired, an internal error, a key that doesn't
  decrypt the packet) and for local-only (break-glass) usernames.
* AD logins bind as the user over LDAPS or StartTLS with a verified certificate, then read the bound connection's
  tokenGroups from the RootDSE; no service account is involved.
* Throttles keyed by the resolved account; every failure answered after the same minimum delay.

Standard library only, plus ldap3 (python3-ldap3) for AD logins.
"""
from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import signal
import ssl
import struct
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from tacmask import mask_command

STATE = Path(os.environ.get("EASYEAP_RADIUS_STATE", "/var/lib/easyeap-radius"))
ADMIN_FILE = STATE / "admin.json"
SPOOL = STATE / "spool"
PORT = int(os.environ.get("EASYEAP_TACACS_PORT", "4949"))
FAIL_DELAY = float(os.environ.get("EASYEAP_TACACS_FAIL_DELAY", "1.0"))
TOKEN_FILE = os.environ.get("EASYEAP_AGENT_TOKEN_FILE", "/run/secrets/agent_token")

MAX_BODY = 64 * 1024
PER_SOURCE = 20
TOTAL = 300
IDLE_TIMEOUT = 120.0
SESSION_TIMEOUT = 60.0
LDAP_BUDGET = 3.0
WORKERS, LDAP_WORKERS, PER_TENANT = 4, 16, 2

log = logging.getLogger("tacacs")
ENAB_USER = re.compile(r"^\$enab\d{1,2}\$$")

# ── Protocol constants (RFC 8907 §4–§7) ─────────────────────────────────────

MAJOR = 0xC
AUTHEN, AUTHOR, ACCT = 1, 2, 3
FLAG_UNENCRYPTED, FLAG_SINGLE_CONNECT = 0x01, 0x04
# authentication
LOGIN = 1
ASCII, PAP, CHAP, ARAP, MSCHAP, MSCHAPV2 = 1, 2, 3, 4, 5, 6
SVC_NONE, SVC_LOGIN, SVC_ENABLE = 0, 1, 2
ST_PASS, ST_FAIL, ST_GETDATA, ST_GETUSER, ST_GETPASS, ST_RESTART, ST_ERROR = 1, 2, 3, 4, 5, 6, 7
REPLY_NOECHO = 0x01
CONTINUE_ABORT = 0x01
# authorization
AUTHOR_PASS_ADD, AUTHOR_PASS_REPL, AUTHOR_FAIL, AUTHOR_ERROR = 0x01, 0x02, 0x10, 0x11
# accounting
ACCT_START, ACCT_STOP, ACCT_WATCHDOG = 0x02, 0x04, 0x08
ACCT_SUCCESS, ACCT_ERROR = 0x01, 0x02


class BadPacket(ValueError):
    """The body's lengths don't add up: wrong key, or a malformed packet."""


@dataclass
class Header:
    version: int
    type: int
    seq: int
    flags: int
    session_id: int
    length: int

    @classmethod
    def parse(cls, b: bytes) -> Header:
        v, t, seq, fl, sid, ln = struct.unpack("!BBBBII", b)
        return cls(v, t, seq, fl, sid, ln)

    def pack(self) -> bytes:
        return struct.pack("!BBBBII", self.version, self.type, self.seq, self.flags, self.session_id, self.length)


def pad(session_id: int, key: bytes, version: int, seq: int, length: int) -> bytes:
    """The MD5 pseudo-pad (RFC 8907 §4.5): MD5(session_id, key, version, seq_no[, previous hash]) repeated."""
    base = struct.pack("!I", session_id) + key + bytes([version, seq])
    out, prev = b"", b""
    while len(out) < length:
        prev = hashlib.md5(base + prev).digest()  # noqa: S324 — the protocol's obfuscation, not a security hash
        out += prev
    return out[:length]


def crypt(h: Header, key: bytes, body: bytes) -> bytes:
    """Obfuscate or de-obfuscate (XOR is its own inverse)."""
    if not key:
        return body
    p = pad(h.session_id, key, h.version, h.seq, len(body))
    return bytes(a ^ b for a, b in zip(body, p, strict=True))


def packet(h: Header, key: bytes, body: bytes) -> bytes:
    h.length = len(body)
    return h.pack() + crypt(h, key, body)


def _fields(b: bytes, start: int, lengths: list[int]) -> list[bytes]:
    if start + sum(lengths) != len(b):
        raise BadPacket("lengths")
    out, pos = [], start
    for n in lengths:
        out.append(b[pos:pos + n])
        pos += n
    return out


@dataclass
class AuthenStart:
    action: int
    priv_lvl: int
    authen_type: int
    service: int
    user: str
    port: str
    rem_addr: str
    data: bytes


def parse_authen_start(b: bytes) -> AuthenStart:
    if len(b) < 8:
        raise BadPacket("short")
    action, priv, atype, svc, ul, pl, rl, dl = struct.unpack("!BBBBBBBB", b[:8])
    if action not in (1, 2, 4) or not 1 <= atype <= 6 or svc > 9 or priv > 15:
        raise BadPacket("values")
    user, port, rem, data = _fields(b, 8, [ul, pl, rl, dl])
    return AuthenStart(action, priv, atype, svc, user.decode("utf-8", "replace"), port.decode("utf-8", "replace"),
                       rem.decode("utf-8", "replace"), data)


def parse_authen_continue(b: bytes) -> tuple[str, bytes, int]:
    if len(b) < 5:
        raise BadPacket("short")
    ul, dl, flags = struct.unpack("!HHB", b[:5])
    msg, data = _fields(b, 5, [ul, dl])
    return msg.decode("utf-8", "replace"), data, flags


def authen_reply(status: int, msg: str = "", data: bytes = b"", flags: int = 0) -> bytes:
    m = msg.encode()
    return struct.pack("!BBHH", status, flags, len(m), len(data)) + m + data


@dataclass
class ArgsRequest:
    authen_method: int
    priv_lvl: int
    authen_type: int
    service: int
    user: str
    port: str
    rem_addr: str
    args: list[str]
    flags: int = 0  # accounting only


def _parse_args_request(b: bytes, acct: bool) -> ArgsRequest:
    off = 1 if acct else 0
    if len(b) < 8 + off:
        raise BadPacket("short")
    flags = b[0] if acct else 0
    method, priv, atype, svc, ul, pl, rl, n = struct.unpack("!BBBBBBBB", b[off:off + 8])
    if priv > 15:
        raise BadPacket("values")
    if len(b) < 8 + off + n:
        raise BadPacket("short")
    arglens = list(b[8 + off:8 + off + n])
    parts = _fields(b, 8 + off + n, [ul, pl, rl, *arglens])
    dec = [p.decode("utf-8", "replace") for p in parts]
    return ArgsRequest(method, priv, atype, svc, dec[0], dec[1], dec[2], dec[3:], flags)


def parse_author_request(b: bytes) -> ArgsRequest:
    return _parse_args_request(b, acct=False)


def parse_acct_request(b: bytes) -> ArgsRequest:
    return _parse_args_request(b, acct=True)


def author_reply(status: int, args: list[str] | None = None, msg: str = "") -> bytes:
    a = [x.encode() for x in (args or [])]
    m = msg.encode()
    return struct.pack("!BBHH", status, len(a), len(m), 0) + bytes(len(x) for x in a) + m + b"".join(a)


def acct_reply(status: int, msg: str = "") -> bytes:
    m = msg.encode()
    return struct.pack("!HHB", len(m), 0, status) + m


def args_dict(args: list[str]) -> dict[str, str]:
    """`name=value` (mandatory) and `name*value` (optional) pairs; repeated names (cmd-arg) joined by spaces."""
    out: dict[str, str] = {}
    for a in args:
        i = min((x for x in (a.find("="), a.find("*")) if x >= 0), default=-1)
        if i <= 0:
            continue
        k, v = a[:i], a[i + 1:]
        out[k] = f"{out[k]} {v}" if k in out and k == "cmd-arg" else v
    return out


# ── TOTP and passwords (mirrors backend/app/admin/passwords.py) ──────────────


def scrypt_verify(stored: str | None, password: str) -> bool:
    try:
        alg, log_n, r, p, salt, want = (stored or "").split("$")
        if alg != "scrypt" or not (10 <= int(log_n) <= 20):
            return False
        dk = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=2 ** int(log_n), r=int(r), p=int(p),
                            maxmem=64 * 1024 * 1024, dklen=32)
        return hmac.compare_digest(dk, base64.b64decode(want))
    except (ValueError, TypeError):
        return False


def _dummy_hash() -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(b"easyeap-timing", salt=salt, n=2 ** 15, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)
    return f"scrypt$15$8$1${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def totp_counter(secret: str, code: str, now: float, after: int = -1) -> int | None:
    """The time step (RFC 6238, 30 s, SHA-1, 6 digits) whose code matches, within one step either way, and later than
    `after` (a code is used once). None when nothing matches."""
    if len(code) != 6 or not code.isdigit():
        return None
    try:
        key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    except (ValueError, TypeError):
        return None
    base = int(now // 30)
    for ctr in (base - 1, base, base + 1):
        if ctr <= after:
            continue
        h = hmac.new(key, struct.pack(">Q", ctr), hashlib.sha1).digest()
        o = h[-1] & 0x0F
        v = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000
        if hmac.compare_digest(f"{v:06d}", code):
            return ctr
    return None


def sid_text(value: bytes) -> str | None:
    try:
        b = bytes(value)
        rev, count = b[0], b[1]
        auth = int.from_bytes(b[2:8], "big")
        subs = [int.from_bytes(b[8 + 4 * i: 12 + 4 * i], "little") for i in range(count)]
        return "S-" + "-".join([str(rev), str(auth), *map(str, subs)])
    except (IndexError, TypeError, ValueError):
        return None


# ── Admin data (from the agent) ──────────────────────────────────────────────


@dataclass
class Device:
    tenant: str
    id: str
    name: str
    site: str
    keys: list[bytes]
    prev_until: int | None


@dataclass
class Tenant:
    id: str
    valid_until: int
    users: dict[str, dict]
    by_sam: dict[str, dict]
    by_upn: dict[str, dict]
    by_id: dict[str, dict]
    maps: list[dict]
    local_only: set[str]
    directory: dict | None
    cache_hours: int


class Store:
    """admin.json, reloaded when the agent rewrites it."""

    def __init__(self, path: Path = ADMIN_FILE) -> None:
        self.path = path
        self.stamp: tuple[int, int] | None = None
        self.tenants: dict[str, Tenant] = {}
        self.nets: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, Device]] = []

    def refresh(self) -> None:
        try:
            st = self.path.stat()
        except OSError:
            self.tenants, self.nets, self.stamp = {}, [], None
            return
        stamp = (st.st_mtime_ns, st.st_size)
        if stamp == self.stamp:
            return
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError) as exc:
            log.error("Can't read %s: %s", self.path, exc)
            return
        self.load(data)
        self.stamp = stamp

    def load(self, data: dict) -> None:
        tenants, nets = {}, []
        for tid, entry in (data.get("tenants") or {}).items():
            part = entry.get("admin") or {}
            users = {u["username"]: u for u in part.get("users") or [] if u.get("username")}
            cands = part.get("candidates") or []
            tenants[tid] = Tenant(
                id=tid, valid_until=int(entry.get("valid_until") or 0), users=users,
                by_sam={c["username"]: c for c in cands if c.get("username")}, by_upn={c["upn"]: c for c in cands if c.get("upn")},
                by_id={c["id"]: c for c in cands}, maps=part.get("maps") or [], local_only=set(part.get("local_only") or []),
                directory=part.get("directory"), cache_hours=int(part.get("role_cache_hours") or 12))
            for c in part.get("clients") or []:
                try:
                    net = ipaddress.ip_network(c["address"], strict=False)
                except (KeyError, ValueError):
                    continue
                nets.append((net, Device(tenant=tid, id=c["id"], name=c.get("name") or "", site=(c.get("site") or "").lower(),
                                         keys=[k.encode() for k in c.get("keys") or [] if k], prev_until=c.get("prev_until"))))
        nets.sort(key=lambda x: x[0].prefixlen, reverse=True)
        self.tenants, self.nets = tenants, nets

    def device_for(self, ip: str) -> Device | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        for net, dev in self.nets:
            if addr.version == net.version and addr in net:
                return dev
        return None

    def keys_for(self, dev: Device, now: float) -> list[bytes]:
        if len(dev.keys) > 1 and not (dev.prev_until and now < dev.prev_until):
            return dev.keys[:1]
        return dev.keys


# ── Decisions ────────────────────────────────────────────────────────────────


@dataclass
class Outcome:
    status: str                  # pass | fail | error
    reason: str | None = None
    user_id: str | None = None
    source: str | None = None    # local | directory
    username: str | None = None  # what the log shows: the account's name, or a keyed hash for unknown names
    priv: int | None = None
    message: str | None = None
    sids: list[str] | None = None  # a directory login: the groups the domain controller gave (for authorization)


@dataclass
class PendingBind:
    """A directory login waiting for its bind: Decider.begin's answer when a domain controller has to be asked. Decider.
    reserve gives it a place under the account's bind cap (token), which Decider.bind or release gives back."""
    tenant: Tenant
    dev: Device
    account: dict
    password: str = field(repr=False)
    key: tuple = ()
    digest: str = field(default="", repr=False)
    token: object = None
    enable_priv: int | None = None
    now: float = 0.0


@dataclass
class Throttle:
    """Per node, in memory. Keys are resolved accounts, so a typed name can't lock someone else out."""
    lock: threading.Lock = field(default_factory=threading.Lock)
    source_fails: dict[tuple, list[float]] = field(default_factory=dict)   # (tenant, account, rem_addr) → failure times
    ad_fails: dict[tuple, list[float]] = field(default_factory=dict)       # (tenant, account) → AD binds failed on the password
    ad_inflight: dict[tuple, set[object]] = field(default_factory=dict)    # (tenant, account) → binds not finished yet
    wrong: dict[tuple, dict[str, float]] = field(default_factory=dict)     # (tenant, account) → keyed hash of a wrong password
    local_fails: dict[tuple, list[float]] = field(default_factory=dict)    # (tenant, user id) → failures
    locked_at: dict[tuple, float] = field(default_factory=dict)
    totp_used: dict[tuple, int] = field(default_factory=dict)              # (tenant, user id, login|enable) → last step
    # (tenant, account, device) → (group SIDs from the login, until): who logged in to which device through EasyEAP
    logins: dict[tuple, tuple[list[str], float]] = field(default_factory=dict)

    def backoff_until(self, key: tuple, now: float) -> float:
        with self.lock:
            fails = [t for t in self.source_fails.get(key, []) if now - t < 900]
            self.source_fails[key] = fails
            if len(fails) < 3:
                return 0.0
            return fails[-1] + min(60.0, 2.0 ** (len(fails) - 3))

    def failed(self, key: tuple, now: float) -> None:
        with self.lock:
            self.source_fails.setdefault(key, []).append(now)

    def succeeded(self, key: tuple) -> None:
        with self.lock:
            self.source_fails.pop(key, None)


def ad_bind_cap(threshold: int | None) -> int:
    """Failed AD binds per account per lockout observation window, per node: below the domain's lockout threshold, so
    EasyEAP alone can't lock an account out (§4.3). A threshold not read yet (no sync, or the sync couldn't read it): 1.
    No lockout (0): 5."""
    if threshold is None:
        return 1
    if threshold <= 0:
        return 5
    return max(1, (threshold - 1) // 2)


BUSY = object()  # Decider.reserve: the cap is taken by binds still in flight; ask again in a moment

# authen_method in authorization requests (RFC 8907 §6.1): how the device authenticated the session.
METH_NOT_SET, METH_TACACSPLUS = 0x00, 0x06


class Decider:
    def __init__(self, store: Store, secret: bytes, ldap_login=None) -> None:
        self.store = store
        self.secret = secret
        self.t = Throttle()
        self.dummy = _dummy_hash()
        self.ldap_login = ldap_login or ad_login

    # names

    def hashed(self, name: str) -> str:
        return "unknown:" + hmac.new(self.secret, name.encode(), hashlib.sha256).hexdigest()[:12]

    @staticmethod
    def canonical(typed: str) -> str:
        name = typed.strip().lower()
        if "\\" in name:
            name = name.split("\\", 1)[1]
        return name

    def resolve(self, t: Tenant, typed: str) -> tuple[str, dict] | None:
        """("local", user) or ("directory", candidate) for a typed name: user, DOMAIN\\user or user@upn. Local first."""
        name = self.canonical(typed)
        if not name:
            return None
        if name in t.users:
            return "local", t.users[name]
        if name in t.by_upn:
            return "directory", t.by_upn[name]
        if "@" in name:
            left, _, right = name.partition("@")
            dom = (t.directory or {}).get("domain") or ""
            if dom and right == dom and left in t.by_sam:
                return "directory", t.by_sam[left]
            return None
        if name in t.by_sam:
            return "directory", t.by_sam[name]
        return None

    def shown(self, t: Tenant | None, typed: str) -> str | None:
        """The name the log shows for a typed name: the account's, else a keyed hash, so a password typed at the
        username prompt isn't kept."""
        if not typed.strip():
            return None
        hit = self.resolve(t, typed) if t is not None else None
        return hit[1]["username"] if hit else self.hashed(self.canonical(typed))

    def local_only(self, t: Tenant, typed: str) -> bool:
        return self.canonical(typed) in t.local_only or typed.strip().lower() in t.local_only

    @staticmethod
    def site_ok(sites: list[str], dev: Device) -> bool:
        return not sites or dev.site in sites

    def _role_from_maps(self, t: Tenant, sids: set[str], dev: Device) -> dict | None:
        return next((mp for mp in t.maps if mp.get("sid") in sids and self.site_ok(mp.get("sites") or [], dev)), None)

    # login

    def login(self, dev: Device, typed: str, password: str, rem_addr: str, *, enable_priv: int | None = None,
              now: float | None = None) -> Outcome:
        """One authentication, start to finish in this thread. The server runs the halves itself: begin in the hash pool,
        the bind in the LDAP pool under the tenant's limit, complete on the event loop."""
        o = self.begin(dev, typed, password, rem_addr, enable_priv=enable_priv, now=now)
        if not isinstance(o, PendingBind):
            return o
        r = self.reserve(o)
        if r is BUSY:
            return self.abandoned(o, "admin_directory_busy", "Other logins for this account were still waiting for the domain controllers.")
        return r if isinstance(r, Outcome) else self.complete(o, self.bind(o))

    def begin(self, dev: Device, typed: str, password: str, rem_addr: str, *, enable_priv: int | None = None,
              now: float | None = None) -> Outcome | PendingBind:
        """Everything up to the AD bind: the answer, or a PendingBind for a directory account.
        enable_priv: an enable request for that privilege level (the role must reach it)."""
        now = now or time.time()
        t = self.store.tenants.get(dev.tenant)
        if t is None or t.valid_until < now:
            return Outcome("error", "admin_data_expired", username=self.shown(t, typed),
                           message="EasyEAP's admin data on this RADIUS node is out of date; the device uses its own accounts.")
        if self.local_only(t, typed):
            return Outcome("error", "admin_local_only", username=typed.strip()[:64], message="Local-only username: the device's own account is used.")
        if ENAB_USER.match(typed.strip()):
            # IOS's stand-in name for enable without a logged-in user (a line password): the device's enable secret decides.
            return Outcome("error", "admin_enable_no_user", username=typed.strip()[:16])
        hit = self.resolve(t, typed)
        if hit is None:
            scrypt_verify(self.dummy, password)  # same work as for a real account
            return Outcome("fail", "admin_unknown_user", username=self.hashed(self.canonical(typed)))
        source, acct = hit
        key = (t.id, acct["id"], rem_addr or "")
        name = acct["username"]
        if self.t.backoff_until(key, now) > now:
            return Outcome("fail", "admin_throttled", acct["id"], source, name, message="Too many failed logins from this address; wait a minute.")
        if not password:
            self.t.failed(key, now)
            return Outcome("fail", "admin_bad_password", acct["id"], source, name)
        if source == "local":
            return self._settle(t, dev, acct, source, key, self._local(t, dev, acct, password, now, enable=enable_priv is not None),
                                enable_priv, now)
        d = t.directory
        if not d or d.get("usable") is False:
            return self._settle(t, dev, acct, source, key, Outcome(
                "error", "admin_directory_unusable",
                message="The directory can't be used for admin logins (it needs LDAPS or StartTLS with certificate verification)."), enable_priv, now)
        digest = hmac.new(self.secret, f"{acct['id']}\0{password}".encode(), hashlib.sha256).hexdigest()
        return PendingBind(t, dev, acct, password, key=key, digest=digest, enable_priv=enable_priv, now=now)

    def _settle(self, t: Tenant, dev: Device, acct: dict, source: str, key: tuple, out: Outcome, enable_priv: int | None,
                now: float) -> Outcome:
        out.user_id, out.source, out.username = acct["id"], source, acct["username"]
        if out.status == "pass" and enable_priv is not None and enable_priv > (out.priv or 0):
            return Outcome("fail", "admin_priv_too_high", acct["id"], source, acct["username"], out.priv,
                           message=f"The role's privilege level is {out.priv}; enable asked for {enable_priv}.")
        if out.status == "fail" and out.reason in ("admin_bad_password", "admin_bad_code", "admin_lockout"):
            self.t.failed(key, now)
        elif out.status == "pass":
            self.t.succeeded(key)
            with self.t.lock:
                self.t.logins[(t.id, acct["id"], dev.id)] = (list(out.sids or []), now + t.cache_hours * 3600)
        return out

    def _local(self, t: Tenant, dev: Device, u: dict, password: str, now: float, *, enable: bool = False) -> Outcome:
        lk = (t.id, u["id"])
        with self.t.lock:
            locked = self.t.locked_at.get(lk)
            if locked and (now - locked >= 900 or (u.get("unlocked_at") or 0) >= locked):
                self.t.locked_at.pop(lk, None)
                self.t.local_fails.pop(lk, None)
                locked = None
        if locked:
            return Outcome("fail", "admin_locked", message="Locked for 15 minutes after 10 failed logins (Device administration → Accounts → Unlock).")
        code = None
        if u.get("totp"):
            # With an authenticator, the password field ends with the 6-digit code.
            password, code = password[:-6], password[-6:]
        pw_ok = scrypt_verify(u.get("hash") or self.dummy, password) and bool(u.get("hash"))
        # A code works once for logins and once for enable (typed again straight after a login, often in the same 30 s).
        rk = (t.id, u["id"], "enable" if enable else "login")
        with self.t.lock:
            ctr = None
            if pw_ok and code is not None:
                ctr = totp_counter(u["totp"], code, now, self.t.totp_used.get(rk, -1))
                if ctr is not None:
                    self.t.totp_used[rk] = ctr  # checked and used under one lock: two logins can't both use it
            ok = pw_ok and (code is None or ctr is not None)
            if ok:
                self.t.local_fails.pop(lk, None)
            else:
                fails = [x for x in self.t.local_fails.get(lk, []) if now - x < 900 and x > (u.get("unlocked_at") or 0)] + [now]
                self.t.local_fails[lk] = fails
                if len(fails) >= 10:
                    self.t.locked_at[lk] = now
                    return Outcome("fail", "admin_lockout", message="10 failed logins in 15 minutes: locked for 15 minutes.")
        if not ok:
            return Outcome("fail", "admin_bad_password" if not pw_ok else "admin_bad_code")
        if not u.get("enabled", True):
            return Outcome("fail", "admin_disabled")
        if u.get("expires_at") and u["expires_at"] <= now:
            return Outcome("fail", "admin_expired")
        if not self.site_ok(u.get("sites") or [], dev):
            return Outcome("fail", "admin_wrong_site", message=f"This account isn't allowed on devices at site “{dev.site or '(none)'}”.")
        return Outcome("pass", priv=int(u.get("priv") or 0))

    def reserve(self, p: PendingBind) -> Outcome | object | None:
        """Checks the account's bind cap and takes a place under it in one step, so concurrent logins can't all pass the
        check and then all fail on the password. None: reserved, go and bind. An Outcome: the answer (the same wrong
        password again, or too many failed binds). BUSY: the cap is taken by binds still in flight (their passwords may
        be right); ask again in a moment."""
        d = p.tenant.directory or {}
        ak = (p.tenant.id, p.account["id"])
        cap = ad_bind_cap(d.get("lockout_threshold"))
        window = max(1800, int(d.get("lockout_window") or 0))
        with self.t.lock:
            wrong = {h: x for h, x in self.t.wrong.get(ak, {}).items() if p.now - x < 600}
            self.t.wrong[ak] = wrong
            fails = [x for x in self.t.ad_fails.get(ak, []) if p.now - x < window]
            self.t.ad_fails[ak] = fails
            inflight = self.t.ad_inflight.setdefault(ak, set())
            if p.digest in wrong:
                # The same wrong password again (a script, a saved password): refused without another bind, so it can't
                # count towards the domain's lockout.
                out = Outcome("fail", "admin_bad_password", message="The same wrong password as a moment ago.")
            elif len(fails) >= cap:
                out = Outcome("fail", "admin_throttled", message="Too many failed AD logins for this account; wait before trying again.")
            elif len(fails) + len(inflight) >= cap:
                return BUSY
            else:
                p.token = object()
                inflight.add(p.token)
                return None
        return self._settle(p.tenant, p.dev, p.account, "directory", p.key, out, p.enable_priv, p.now)

    def release(self, p: PendingBind) -> None:
        """Gives back a place under the cap (the bind ended, or never ran)."""
        ak = (p.tenant.id, p.account["id"])
        with self.t.lock:
            inflight = self.t.ad_inflight.get(ak)
            if inflight is not None:
                inflight.discard(p.token)
                if not inflight:
                    del self.t.ad_inflight[ak]

    def bind(self, p: PendingBind) -> tuple[str, str | None, list[str], str | None]:
        """The AD bind (blocking; the LDAP pool). Records a failure on the password however the asyncio side fares, so a
        login that timed out there still counts."""
        try:
            res = self.ldap_login(p.tenant.directory or {}, p.account, p.password)
        except Exception:  # noqa: BLE001
            log.exception("AD login failed")
            res = ("error", "admin_internal_error", [], None)
        if res[0] == "fail" and res[1] == "admin_bad_password":
            with self.t.lock:
                ak = (p.tenant.id, p.account["id"])
                self.t.ad_fails.setdefault(ak, []).append(p.now)
                self.t.wrong.setdefault(ak, {})[p.digest] = p.now
        self.release(p)
        return res

    def complete(self, p: PendingBind, res: tuple[str, str | None, list[str], str | None]) -> Outcome:
        status, reason, sids, msg = res
        if status in ("fail", "error"):
            out = Outcome(status, reason, message=msg)
        else:
            mp = self._role_from_maps(p.tenant, set(sids), p.dev)
            out = (Outcome("fail", "admin_not_permitted", message="Not in a directory group that may log in to this device.") if mp is None
                   else Outcome("pass", priv=int(mp.get("priv") or 0), message=f"Role {mp.get('role')} from group {mp.get('group')}.", sids=list(sids)))
        return self._settle(p.tenant, p.dev, p.account, "directory", p.key, out, p.enable_priv, p.now)

    @staticmethod
    def abandoned(p: PendingBind, reason: str, message: str) -> Outcome:
        """ERROR for a directory login the server gave up waiting for (the device uses its own accounts)."""
        return Outcome("error", reason, p.account["id"], "directory", p.account["username"], message=message)

    # authorization

    def authorize(self, dev: Device, typed: str, authen_method: int = METH_TACACSPLUS, now: float | None = None) -> Outcome:
        """The privilege level for an exec session (or a command), only for a session EasyEAP authenticated: the device
        says it authenticated it over TACACS+ and this node saw that account log in to this device. The role is worked
        out again from the current data, so disabling an account or removing a group mapping applies at once. Any other
        session gets ERROR: the device's own method list (its local accounts) decides, not EasyEAP."""
        now = now or time.time()
        t = self.store.tenants.get(dev.tenant)
        if t is None or t.valid_until < now:
            return Outcome("error", "admin_data_expired", username=self.shown(t, typed))
        if self.local_only(t, typed):
            return Outcome("error", "admin_local_only", username=typed.strip()[:64])
        hit = self.resolve(t, typed)
        if hit is None:
            return Outcome("error", "admin_not_easyeap_login", username=self.shown(t, typed))
        source, acct = hit
        base = Outcome("pass", user_id=acct["id"], source=source, username=acct["username"])
        with self.t.lock:
            seen = self.t.logins.get((t.id, acct["id"], dev.id))
        if authen_method not in (METH_NOT_SET, METH_TACACSPLUS) or not seen or seen[1] <= now:
            base.status, base.reason = "error", "admin_not_easyeap_login"
            return base
        if source == "local":
            if not acct.get("enabled", True):
                base.status, base.reason = "fail", "admin_disabled"
            elif acct.get("expires_at") and acct["expires_at"] <= now:
                base.status, base.reason = "fail", "admin_expired"
            elif not self.site_ok(acct.get("sites") or [], dev):
                base.status, base.reason = "fail", "admin_wrong_site"
            else:
                base.priv = int(acct.get("priv") or 0)
            return base
        mp = self._role_from_maps(t, set(seen[0]), dev)
        if mp is None:
            base.status, base.reason = "fail", "admin_not_permitted"
        else:
            base.priv = int(mp.get("priv") or 0)
        return base


# ── Active Directory ─────────────────────────────────────────────────────────

_AD_CODES = {"52e": "admin_bad_password", "525": "admin_bad_password", "775": "admin_ad_locked", "533": "admin_disabled",
             "701": "admin_expired", "532": "admin_password_expired", "773": "admin_password_expired", "530": "admin_wrong_site",
             "531": "admin_wrong_site"}


def ad_login(d: dict, c: dict, password: str) -> tuple[str, str | None, list[str], str | None]:
    """Bind as the user and read the bound connection's group SIDs. (status, reason, sids, message): status pass,
    fail (a denial: wrong password, disabled, …) or error (EasyEAP couldn't ask a domain controller)."""
    if not password:
        return "fail", "admin_bad_password", [], None  # an empty password is an anonymous bind, never a login
    try:
        from ldap3 import BASE, FIRST, NONE, Connection, Server, ServerPool, Tls
        from ldap3.core.exceptions import LDAPException
    except ImportError:
        return "error", "admin_directory_unusable", [], "ldap3 isn't installed on this RADIUS node."
    if d.get("transport") not in ("ldaps", "starttls") or not d.get("verify"):
        return "error", "admin_directory_unusable", [], "AD logins need LDAPS or StartTLS with certificate verification."
    kw = {"validate": ssl.CERT_REQUIRED, "version": ssl.PROTOCOL_TLS_CLIENT}
    if d.get("ca_pem"):
        kw["ca_certs_data"] = d["ca_pem"]
    tls = Tls(**kw)
    servers = [Server(h.strip(), port=int(d.get("port") or 636), use_ssl=d["transport"] == "ldaps", tls=tls, get_info=NONE,
                      connect_timeout=2) for h in d.get("hosts") or [] if h.strip()]
    if not servers:
        return "error", "admin_directory_unusable", [], "No domain controller configured."
    user = c.get("upn") or f"{c['username']}@{d.get('domain') or ''}"
    conn = Connection(ServerPool(servers, FIRST, active=1, exhaust=True), user=user, password=password, auto_bind=False,
                      receive_timeout=int(LDAP_BUDGET), raise_exceptions=False, read_only=True)
    try:
        conn.open()
        if conn.closed:
            return "error", "admin_directory_down", [], str(conn.last_error)[:200]
        if d["transport"] == "starttls" and not conn.start_tls():
            return "error", "admin_directory_down", [], "StartTLS failed"
        if not conn.bind():
            res = conn.result or {}
            text = f"{res.get('description', '')} {res.get('message', '')}"
            if res.get("result") == 49:
                code = next((k for k in _AD_CODES if f"data {k}" in text), "52e")
                return "fail", _AD_CODES[code], [], None
            return "error", "admin_directory_down", [], text.strip()[:200]
        who = conn.extend.standard.who_am_i() or ""
        bound = who.split(":", 1)[-1].split("\\")[-1].lower() if who else ""
        if bound and bound not in (c["username"], (c.get("upn") or "").lower()):
            return "fail", "admin_not_permitted", [], f"The directory bound {who}, not {c['username']}."
        conn.search("", "(objectClass=*)", search_scope=BASE, attributes=["tokenGroups"])
        sids: list[str] = []
        for e in conn.response or []:
            if e.get("type") == "searchResEntry":
                sids = [s for s in (sid_text(v) for v in (e.get("raw_attributes") or {}).get("tokenGroups", [])) if s]
        if not sids:
            # Without the token the groups can't be checked live: fall back to the groups from the last sync.
            sids = list(c.get("sids") or [])
        return "pass", None, sids, None
    except LDAPException as exc:
        return "error", "admin_directory_down", [], str(exc)[:200]
    except (OSError, ssl.SSLError) as exc:
        return "error", "admin_directory_down", [], f"{type(exc).__name__}: {exc}"[:200]
    finally:
        try:
            conn.unbind()
        except Exception:  # noqa: BLE001, S110
            pass


# ── Events ───────────────────────────────────────────────────────────────────


class Spool:
    def __init__(self, directory: Path = SPOOL) -> None:
        self.dir = directory
        self.hour, self.fh = "", None

    def write(self, rec: dict) -> None:
        hour = time.strftime("%Y%m%d%H", time.gmtime())
        try:
            if hour != self.hour or self.fh is None:
                if self.fh:
                    self.fh.close()
                self.dir.mkdir(parents=True, exist_ok=True)
                self.fh = (self.dir / f"admin-{hour}.jsonl").open("a")
                self.hour = hour
            self.fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
            self.fh.flush()
        except OSError as exc:
            log.error("Can't write the admin log spool: %s", exc)


# ── Server ───────────────────────────────────────────────────────────────────


@dataclass
class Session:
    key: bytes
    version: int
    seq: int
    started: float
    start: AuthenStart | None = None
    user: str = ""
    getuser_tries: int = 0


class Server:
    def __init__(self, store: Store, decider: Decider, spool: Spool) -> None:
        self.store, self.decider, self.spool = store, decider, spool
        # Password hashing and the decision itself; AD binds apart, so slow domain controllers can't hold the threads
        # local logins need. Each tenant has at most PER_TENANT binds in flight (an asyncio limit: waiting holds no thread).
        self.hash_pool = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="tacacs-hash")
        self.ldap_pool = ThreadPoolExecutor(max_workers=LDAP_WORKERS, thread_name_prefix="tacacs-ldap")
        self.tenant_binds: dict[str, asyncio.Semaphore] = {}
        self.per_source: dict[str, int] = {}
        self.total = 0
        self.noted: dict[str, float] = {}

    def _note_once(self, key: str, msg: str, *args) -> None:
        now = time.time()
        if now - self.noted.get(key, 0) > 300:
            self.noted[key] = now
            log.warning(msg, *args)

    def event(self, dev: Device, ip: str, kind: str, result: str, o: Outcome | None = None, **kw) -> None:
        rec = {"uid": uuid.uuid4().hex, "ts": time.time(), "tenant": dev.tenant, "client_id": dev.id, "nas_ip": ip,
               "kind": kind, "result": result}
        if o is not None:
            rec.update({"username": o.username, "user_id": o.user_id, "source": o.source, "reason": o.reason, "priv_lvl": o.priv,
                        "message": o.message})
        rec.update({k: v for k, v in kw.items() if v not in (None, "")})
        if rec.get("command"):
            rec["command"] = mask_command(rec["command"])
        self.spool.write(rec)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("", 0)
        ip = str(peer[0]).removeprefix("::ffff:")
        self.store.refresh()
        dev = self.store.device_for(ip)
        if dev is None:
            self._note_once(f"unknown:{ip}", "TACACS+ connection from %s, which isn't a device with admin logins on: dropped", ip)
            writer.close()
            return
        if self.per_source.get(ip, 0) >= PER_SOURCE or self.total >= TOTAL:
            self._note_once(f"limit:{ip}", "Too many TACACS+ connections (from %s): refused", ip)
            writer.close()
            return
        self.per_source[ip] = self.per_source.get(ip, 0) + 1
        self.total += 1
        try:
            await self.serve(reader, writer, dev, ip)
        except (asyncio.IncompleteReadError, ConnectionError, TimeoutError):
            pass
        except Exception:  # noqa: BLE001
            log.exception("TACACS+ connection from %s failed", ip)
        finally:
            self.per_source[ip] -= 1
            if not self.per_source[ip]:
                del self.per_source[ip]
            self.total -= 1
            try:
                writer.close()
            except Exception:  # noqa: BLE001, S110
                pass

    async def serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, dev: Device, ip: str) -> None:
        sessions: dict[int, Session] = {}
        while True:
            raw = await asyncio.wait_for(reader.readexactly(12), IDLE_TIMEOUT)
            h = Header.parse(raw)
            if h.version >> 4 != MAJOR or h.type not in (AUTHEN, AUTHOR, ACCT) or h.length > MAX_BODY:
                return  # framing we can't trust: close (RFC 8907 §4.1)
            body = await asyncio.wait_for(reader.readexactly(h.length), IDLE_TIMEOUT)
            if h.flags & FLAG_UNENCRYPTED:
                self._note_once(f"plain:{ip}", "TACACS+ packet without obfuscation from %s (%s): dropped. Set a key on the device.", dev.name, ip)
                return
            s = sessions.get(h.session_id)
            if s is None:
                if h.seq != 1:
                    return
            elif h.seq != s.seq + 2 or h.seq >= 255:
                return
            reply, done = await self.dispatch(h, body, s, sessions, dev, ip)
            if reply is None:
                return
            key, rbody = reply
            out = Header(h.version, h.type, h.seq + 1, 0, h.session_id, 0)  # single-connection is never echoed: declined
            writer.write(packet(out, key, rbody))
            await writer.drain()
            if done:
                sessions.pop(h.session_id, None)
                return  # one session per connection

    def _decrypt(self, h: Header, body: bytes, dev: Device, parse):
        """Try the device's key, then the previous one during a rotation; the one that yields a well-formed body wins."""
        keys = self.store.keys_for(dev, time.time())
        for key in keys:
            try:
                return key, parse(crypt(h, key, body))
            except BadPacket:
                continue
        return (keys[0] if keys else b""), None

    async def dispatch(self, h: Header, body: bytes, s: Session | None, sessions: dict[int, Session], dev: Device, ip: str):
        if h.type == AUTHEN:
            return await self.authen(h, body, s, sessions, dev, ip)
        parse = parse_author_request if h.type == AUTHOR else parse_acct_request
        key, req = self._decrypt(h, body, dev, parse)
        if req is None:
            self._note_once(f"key:{dev.id}", "TACACS+ packet from %s (%s) doesn't decrypt with its key: answered ERROR. Check the key on the device.",
                            dev.name, ip)
            self.event(dev, ip, "authz" if h.type == AUTHOR else "session", "error", reason="admin_bad_key")
            return (key, author_reply(AUTHOR_ERROR) if h.type == AUTHOR else acct_reply(ACCT_ERROR)), True
        if h.type == AUTHOR:
            return (key, await self.author(req, dev, ip)), True
        return (key, self.acct(req, dev, ip)), True

    async def authen(self, h: Header, body: bytes, s: Session | None, sessions: dict[int, Session], dev: Device, ip: str):
        if s is None:
            key, start = self._decrypt(h, body, dev, parse_authen_start)
            if start is None:
                self._note_once(f"key:{dev.id}", "TACACS+ login from %s (%s) doesn't decrypt with its key: answered ERROR. Check the key on the device.",
                                dev.name, ip)
                self.event(dev, ip, "login", "error", reason="admin_bad_key")
                return (key, authen_reply(ST_ERROR)), True
            s = Session(key=key, version=h.version, seq=h.seq, started=time.time(), start=start, user=start.user)
            sessions[h.session_id] = s
            kind = "enable" if start.service == SVC_ENABLE else "login"
            if start.action != LOGIN:
                return (key, authen_reply(ST_FAIL, "EasyEAP supports logins only.")), True
            if start.authen_type not in (ASCII, PAP):
                self.event(dev, ip, kind, "fail", Outcome("fail", "admin_unsupported_method", username=None), rem_addr=start.rem_addr, port=start.port)
                return (key, authen_reply(ST_FAIL, "Set the device to ASCII or PAP logins for EasyEAP.")), True
            if start.service not in (SVC_NONE, SVC_LOGIN, SVC_ENABLE):
                return (key, authen_reply(ST_FAIL)), True
            # Minor version 1 for PAP, 0 for ASCII (RFC 8907 §5.4.1, §3.2).
            if (h.version & 0x0F) != (1 if start.authen_type == PAP else 0):
                return (key, authen_reply(ST_ERROR)), True
            if start.authen_type == PAP:
                return (key, await self.finish(s, dev, ip, start.user, start.data.decode("utf-8", "replace"))), True
            if not start.user:
                s.getuser_tries = 1
                return (key, authen_reply(ST_GETUSER, "Username: ")), False
            return (key, authen_reply(ST_GETPASS, "Password: ", flags=REPLY_NOECHO)), False
        s.seq = h.seq
        try:
            msg, _data, flags = parse_authen_continue(crypt(h, s.key, body))
        except BadPacket:
            return (s.key, authen_reply(ST_ERROR)), True
        if flags & CONTINUE_ABORT:
            return None, True  # the user gave up: no reply, not counted as a failure
        if time.time() - s.started > SESSION_TIMEOUT:
            return (s.key, authen_reply(ST_ERROR, "Login timed out.")), True
        if not s.user:
            s.user = msg.strip()
            if not s.user:
                s.getuser_tries += 1
                if s.getuser_tries > 3:
                    return (s.key, authen_reply(ST_FAIL)), True
                return (s.key, authen_reply(ST_GETUSER, "Username: ")), False
            return (s.key, authen_reply(ST_GETPASS, "Password: ", flags=REPLY_NOECHO)), False
        return (s.key, await self.finish(s, dev, ip, s.user, msg)), True

    async def finish(self, s: Session, dev: Device, ip: str, user: str, password: str) -> bytes:
        start = s.start
        if start is None:
            return authen_reply(ST_ERROR)
        enable = start.service == SVC_ENABLE
        t0 = time.monotonic()
        deadline = t0 + LDAP_BUDGET + 2
        loop = asyncio.get_running_loop()
        try:
            fut = loop.run_in_executor(self.hash_pool, functools.partial(
                self.decider.begin, dev, user, password, start.rem_addr, enable_priv=start.priv_lvl if enable else None))
            try:
                o = await asyncio.wait_for(fut, deadline - time.monotonic())
            except TimeoutError:
                o = Outcome("error", "admin_busy", username=self.decider.shown(self.store.tenants.get(dev.tenant), user),
                            message="EasyEAP couldn't decide in time; the device uses its own accounts.")
            if isinstance(o, PendingBind):
                o = await self.directory_login(o, deadline)
        except Exception:  # noqa: BLE001
            log.exception("TACACS+ login decision failed")
            o = Outcome("error", "admin_internal_error", username=self.decider.shown(self.store.tenants.get(dev.tenant), user))
        if o.status == "fail":
            await asyncio.sleep(max(0.0, t0 + FAIL_DELAY - time.monotonic()))
        self.event(dev, ip, "enable" if enable else "login", o.status, o, rem_addr=start.rem_addr, port=start.port)
        return authen_reply({"pass": ST_PASS, "fail": ST_FAIL}.get(o.status, ST_ERROR))

    async def directory_login(self, p: PendingBind, deadline: float) -> Outcome:
        """The AD bind in the LDAP pool, at most PER_TENANT at once per tenant, within the login's deadline."""
        loop = asyncio.get_running_loop()
        while (r := self.decider.reserve(p)) is BUSY:
            if time.monotonic() + 0.05 >= deadline:
                return self.decider.abandoned(p, "admin_directory_busy", "Other logins for this account were still waiting for the domain controllers.")
            await asyncio.sleep(0.05)
        if isinstance(r, Outcome):
            return r
        sem = self.tenant_binds.setdefault(p.tenant.id, asyncio.Semaphore(PER_TENANT))
        try:
            await asyncio.wait_for(sem.acquire(), max(0.0, deadline - time.monotonic()))
        except TimeoutError:
            self.decider.release(p)
            return self.decider.abandoned(p, "admin_directory_busy", "Other admin logins for this tenant were waiting for the domain controllers.")
        try:
            fut = loop.run_in_executor(self.ldap_pool, self.decider.bind, p)
        except Exception:
            sem.release()
            self.decider.release(p)
            raise
        fut.add_done_callback(lambda _f: sem.release())  # when the bind ends, even after the device was answered
        try:
            res = await asyncio.wait_for(asyncio.shield(fut), max(0.0, deadline - time.monotonic()))
        except TimeoutError:
            return self.decider.abandoned(p, "admin_directory_timeout", "The domain controllers didn't answer in time.")
        return self.decider.complete(p, res)

    async def author(self, req: ArgsRequest, dev: Device, ip: str) -> bytes:
        a = args_dict(req.args)
        service = a.get("service", "")
        o = self.decider.authorize(dev, req.user, req.authen_method)
        if service != "shell":
            self.event(dev, ip, "authz", "fail", o, reason="admin_service_not_supported", rem_addr=req.rem_addr, port=req.port,
                       message=f"service={service}")
            return author_reply(AUTHOR_FAIL)
        cmd = a.get("cmd", "")
        if cmd:
            # Command authorization isn't in EasyEAP's configuration; configured by hand, level 15 may run anything.
            command = f"{cmd} {a.get('cmd-arg', '')}".strip()
            if o.status == "pass" and (o.priv or 0) < 15:
                o.status, o.reason = "fail", "admin_command_denied"
            self.event(dev, ip, "authz", o.status, o, rem_addr=req.rem_addr, port=req.port, command=command)
            return author_reply({"pass": AUTHOR_PASS_ADD, "fail": AUTHOR_FAIL}.get(o.status, AUTHOR_ERROR))
        self.event(dev, ip, "authz", o.status, o, rem_addr=req.rem_addr, port=req.port)
        if o.status == "pass":
            return author_reply(AUTHOR_PASS_ADD, [f"priv-lvl={o.priv}"])
        return author_reply(AUTHOR_FAIL if o.status == "fail" else AUTHOR_ERROR)

    def acct(self, req: ArgsRequest, dev: Device, ip: str) -> bytes:
        flags = req.flags & (ACCT_START | ACCT_STOP | ACCT_WATCHDOG)
        if flags not in (ACCT_START, ACCT_STOP, ACCT_WATCHDOG, ACCT_WATCHDOG | ACCT_START):
            return acct_reply(ACCT_ERROR)
        a = args_dict(req.args)
        result = "start" if flags == ACCT_START else "stop" if flags == ACCT_STOP else "update"
        t = self.store.tenants.get(dev.tenant)
        hit = self.decider.resolve(t, req.user) if t else None
        o = Outcome("pass", username=hit[1]["username"] if hit else (req.user.strip()[:64] if t and self.decider.local_only(t, req.user)
                                                                       else self.decider.hashed(self.decider.canonical(req.user)) if req.user else None),
                    user_id=hit[1]["id"] if hit else None, source=hit[0] if hit else None)
        try:
            o.priv = int(a.get("priv-lvl", req.priv_lvl))
        except ValueError:
            o.priv = req.priv_lvl
        command = a.get("cmd")
        self.event(dev, ip, "command" if command else "session", result, o, rem_addr=req.rem_addr, port=req.port, task_id=a.get("task_id"),
                   command=command)
        return acct_reply(ACCT_SUCCESS)


def agent_secret() -> bytes:
    """Keys the hash of unknown usernames in the log: the agent token, shared by every node, so hashes match."""
    try:
        return (os.environ.get("EASYEAP_AGENT_TOKEN") or Path(TOKEN_FILE).read_text().strip()).encode()
    except OSError:
        return b"easyeap-tacacs"


async def run(port: int = PORT) -> None:
    store = Store()
    store.refresh()
    server = Server(store, Decider(store, agent_secret()), Spool())
    srv = await asyncio.start_server(server.handle, host="0.0.0.0", port=port, limit=MAX_BODY + 64)  # noqa: S104 — published only when EASYEAP_TACACS_BIND is set
    log.info("TACACS+ listening on TCP %d", port)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    async with srv:
        await stop.wait()
    server.hash_pool.shutdown(wait=False, cancel_futures=True)
    server.ldap_pool.shutdown(wait=False, cancel_futures=True)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s tacacs %(levelname)s %(message)s", stream=sys.stdout)
    os.umask(0o077)
    asyncio.run(run())


if __name__ == "__main__":
    main()
