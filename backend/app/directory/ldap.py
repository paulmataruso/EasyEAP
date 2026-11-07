"""Active Directory over LDAPS / StartTLS with a read-only service account (ldap3).

* Users are keyed by objectGUID, so renames keep their certificates and history.
* Transitive group membership comes from `tokenGroups` (base-scope read per user). Unlike `memberOf` it includes
  nested groups and the primary group (usually *Domain Users*).
* Account state: userAccountControl (disabled), msDS-User-Account-Control-Computed (locked out), accountExpires.
* A full sync that would mark more than half of the known directory users deleted stops for safety instead.
"""
from __future__ import annotations

import ssl
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from ldap3 import BASE, FIRST, NONE, SUBTREE, Connection, Server, ServerPool, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from app.config import get_settings

USER_ATTRS = ["objectGUID", "objectSid", "sAMAccountName", "userPrincipalName", "mail", "displayName", "department",
              "title", "userAccountControl", "msDS-User-Account-Control-Computed", "accountExpires", "primaryGroupID",
              "distinguishedName"]
GROUP_ATTRS = ["objectGUID", "objectSid", "cn", "sAMAccountName", "distinguishedName"]
UF_ACCOUNTDISABLE = 0x2
UF_LOCKOUT = 0x10
NEVER = (0, 0x7FFFFFFFFFFFFFFF)


class DirectoryError(RuntimeError):
    def __init__(self, message: str, hint: str = "", detail: str = ""):
        super().__init__(message)
        self.hint = hint
        self.detail = detail[:500]


@dataclass
class DirectoryParams:
    hosts: list[str]
    port: int
    transport: str  # ldaps | starttls | plain
    verify_certificate: bool
    ca_bundle_pem: str | None
    base_dn: str
    user_search_base: str
    group_search_base: str
    user_filter: str
    group_filter: str
    bind_dn: str
    bind_password: str = field(repr=False)


@dataclass
class DirUser:
    object_guid: str
    sid: str | None
    username: str
    upn: str | None
    email: str | None
    display_name: str
    department: str | None
    title: str | None
    account_state: str
    group_sids: list[str] = field(default_factory=list)


@dataclass
class DirGroup:
    object_guid: str
    sid: str | None
    dn: str
    name: str


def _tls(p: DirectoryParams) -> Tls:
    if not p.verify_certificate:
        return Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS_CLIENT)
    kwargs: dict[str, Any] = {"validate": ssl.CERT_REQUIRED, "version": ssl.PROTOCOL_TLS_CLIENT}
    if p.ca_bundle_pem:
        kwargs["ca_certs_data"] = p.ca_bundle_pem
    return Tls(**kwargs)


def connect(p: DirectoryParams, timeout: int = 8, *, anonymous: bool = False) -> Connection:
    """Open, secure (StartTLS) and bind. anonymous=True binds without credentials: only for reading the RootDSE."""
    if p.transport == "plain" and not get_settings().lab_mode:
        raise DirectoryError("Plain LDAP is disabled.", "Use LDAPS (636) or StartTLS so the service-account password is encrypted in transit.")
    tls = None if p.transport == "plain" else _tls(p)
    servers = [Server(h.strip(), port=p.port, use_ssl=p.transport == "ldaps", tls=tls, get_info=NONE, connect_timeout=timeout)
               for h in p.hosts if h.strip()]
    if not servers:
        raise DirectoryError("No domain controller configured.", "Enter at least one domain controller hostname.")
    pool = ServerPool(servers, FIRST, active=1, exhaust=True)
    conn = Connection(pool, user=None if anonymous else p.bind_dn, password=None if anonymous else p.bind_password, auto_bind=False,
                      receive_timeout=timeout * 2,
                      raise_exceptions=False, read_only=True)
    try:
        conn.open()  # raises on socket/TLS failure
        if conn.closed:
            raise DirectoryError("Could not reach a domain controller.", _hint_for(str(conn.last_error)), str(conn.last_error))
        if p.transport == "starttls" and not conn.start_tls():
            raise DirectoryError("StartTLS failed.", "Check the domain controller's certificate and the uploaded CA bundle.", str(conn.result))
        if not conn.bind():
            res = conn.result or {}
            text = f"{res.get('description', '')} {res.get('message', '')}".strip()
            if anonymous:
                raise DirectoryError("The domain controller refused an anonymous connection.", "Enter the service account and try again.", text)
            raise DirectoryError("The service account could not sign in.", _hint_for(text), text)
    except LDAPException as exc:
        raise DirectoryError("Could not connect to the directory.", _hint_for(str(exc)), str(exc)) from exc
    return conn


def _hint_for(message: str) -> str:
    msg = message.lower()
    if "certificate verify failed" in msg or ("certificate" in msg and "verify" in msg):
        return "The domain controller's certificate is not trusted. Paste your AD root CA (PEM) under Certificate trust."
    if "doesn't match" in msg or "does not match" in msg or ("hostname" in msg and "match" in msg):
        return "The certificate does not match the hostname. Use the DC's fully qualified name as it appears in its certificate."
    if "invalidcredentials" in msg or "invalid credentials" in msg or "52e" in msg:
        return "Check the service account's bind DN (or user@domain) and password."
    if "533" in msg:
        return "The service account is disabled in Active Directory."
    if "775" in msg:
        return "The service account is locked out."
    if "strongerauthrequired" in msg or "stronger" in msg:
        return "The domain controller requires signing or TLS. Use LDAPS or StartTLS."
    if "timed out" in msg or "timeout" in msg or "unreachable" in msg or "refused" in msg or "socket" in msg or "no active server" in msg:
        return "EasyEAP could not open a connection. Check DNS, routing and that TCP 636 (or 389 for StartTLS) is allowed."
    return "See the technical details for the exact error."


def _guid(value: Any) -> str:
    if isinstance(value, bytes):
        return str(uuid.UUID(bytes_le=value))
    return str(value).strip("{}").lower()


def _sid(value: Any) -> str | None:
    if value is None or value == []:
        return None
    if isinstance(value, str):
        return value
    b = bytes(value)
    rev, count = b[0], b[1]
    auth = int.from_bytes(b[2:8], "big")
    subs = [int.from_bytes(b[8 + 4 * i: 12 + 4 * i], "little") for i in range(count)]
    return "S-" + "-".join([str(rev), str(auth), *map(str, subs)])


def _first(entry: dict, key: str) -> Any:
    v = entry.get(key)
    if isinstance(v, list):
        return v[0] if v else None
    return v


def _filetime(v: Any) -> datetime | None:
    if isinstance(v, datetime):
        return v if v.year > 1601 and v.year < 9000 else None
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    if n in NEVER:
        return None
    return datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=n / 10)


def _account_state(attrs: dict) -> str:
    uac = int(_first(attrs, "userAccountControl") or 0)
    computed = int(_first(attrs, "msDS-User-Account-Control-Computed") or 0)
    if uac & UF_ACCOUNTDISABLE:
        return "disabled"
    if computed & UF_LOCKOUT:
        return "locked"
    expires = _filetime(_first(attrs, "accountExpires"))
    if expires and expires <= datetime.now(UTC):
        return "disabled"
    return "enabled"


def _to_user(attrs: dict) -> DirUser:
    sam = _first(attrs, "sAMAccountName") or ""
    return DirUser(
        object_guid=_guid(_first(attrs, "objectGUID")), sid=_sid(_first(attrs, "objectSid")), username=str(sam),
        upn=_first(attrs, "userPrincipalName"), email=_first(attrs, "mail"),
        display_name=_first(attrs, "displayName") or str(sam), department=_first(attrs, "department"),
        title=_first(attrs, "title"), account_state=_account_state(attrs),
    )


def _paged(conn: Connection, base: str, flt: str, attrs: list[str]):
    yield from conn.extend.standard.paged_search(base, flt, search_scope=SUBTREE, attributes=attrs, paged_size=500, generator=True)


def fetch_groups(conn: Connection, p: DirectoryParams) -> list[DirGroup]:
    out = []
    for e in _paged(conn, p.group_search_base or p.base_dn, p.group_filter, GROUP_ATTRS):
        if e.get("type") != "searchResEntry":
            continue
        a = e["attributes"]
        raw = e["raw_attributes"]
        out.append(DirGroup(object_guid=_guid(raw["objectGUID"][0]), sid=_sid(raw.get("objectSid", [None])[0]),
                            dn=e["dn"], name=str(_first(a, "cn") or _first(a, "sAMAccountName") or e["dn"])))
    return out


def token_group_sids(conn: Connection, dn: str) -> list[str]:
    conn.search(dn, "(objectClass=*)", search_scope=BASE, attributes=["tokenGroups"])
    if not conn.entries and not conn.response:
        return []
    for e in conn.response or []:
        if e.get("type") == "searchResEntry":
            return [s for s in (_sid(v) for v in e["raw_attributes"].get("tokenGroups", [])) if s]
    return []


def _domain_root(conn: Connection, base_dn: str) -> str:
    """The domain's own entry, where the default password policy lives: RootDSE defaultNamingContext, else the DC=
    components of the base DN (a sync base can be an OU)."""
    try:
        conn.search("", "(objectClass=*)", search_scope=BASE, attributes=["defaultNamingContext"])
        for e in conn.response or []:
            if e.get("type") == "searchResEntry":
                v = (e.get("attributes") or {}).get("defaultNamingContext")
                v = v[0] if isinstance(v, list) and v else v
                if v:
                    return str(v)
    except (LDAPException, TypeError, ValueError):
        pass
    return ",".join(p.strip() for p in base_dn.split(",") if p.strip().upper().startswith("DC="))


def _seconds(v) -> int | None:
    """lockOutObservationWindow: a negative count of 100-ns intervals (ldap3 may already give a timedelta)."""
    if v in (None, "", []):
        return None
    if isinstance(v, list):
        v = v[0] if v else None
    if hasattr(v, "total_seconds"):
        return int(abs(v.total_seconds()))
    try:
        return int(abs(int(v)) // 10_000_000)
    except (TypeError, ValueError):
        return None


def lockout_policy(conn: Connection, base_dn: str) -> tuple[int | None, int | None]:
    """The domain's (lockoutThreshold, lockOutObservationWindow in seconds); threshold 0 = accounts never lock, None =
    it couldn't be read. Fine-grained password policies (PSOs) aren't readable with a read-only account and aren't
    considered."""
    root = _domain_root(conn, base_dn)
    if not root:
        return None, None
    try:
        conn.search(root, "(objectClass=*)", search_scope=BASE, attributes=["lockoutThreshold", "lockOutObservationWindow"])
        for e in conn.response or []:
            if e.get("type") == "searchResEntry":
                attrs = e.get("attributes") or {}
                v = attrs.get("lockoutThreshold")
                v = v[0] if isinstance(v, list) and v else v
                threshold = int(v) if v not in (None, "", []) else None
                raw = (e.get("raw_attributes") or {}).get("lockOutObservationWindow")
                window = _seconds(raw[0].decode() if isinstance(raw, list) and raw and isinstance(raw[0], bytes) else attrs.get("lockOutObservationWindow"))
                return threshold, window
    except (LDAPException, TypeError, ValueError):
        return None, None
    return None, None


def fetch_users(conn: Connection, p: DirectoryParams, with_groups: bool = True) -> list[DirUser]:
    users = []
    for e in _paged(conn, p.user_search_base or p.base_dn, p.user_filter, USER_ATTRS):
        if e.get("type") != "searchResEntry":
            continue
        attrs = dict(e["attributes"])
        attrs["objectGUID"] = e["raw_attributes"]["objectGUID"][0]
        attrs["objectSid"] = (e["raw_attributes"].get("objectSid") or [None])[0]
        u = _to_user(attrs)
        if with_groups:
            u.group_sids = token_group_sids(conn, e["dn"])
        users.append(u)
    return users


def search_live(conn: Connection, p: DirectoryParams, query: str, limit: int = 25) -> list[DirUser]:
    q = escape_filter_chars(query.strip())
    flt = f"(&{p.user_filter}(|(sAMAccountName={q}*)(displayName=*{q}*)(mail={q}*)(userPrincipalName={q}*)))"
    conn.search(p.user_search_base or p.base_dn, flt, search_scope=SUBTREE, attributes=USER_ATTRS, size_limit=limit)
    out = []
    for e in conn.response or []:
        if e.get("type") != "searchResEntry":
            continue
        attrs = dict(e["attributes"])
        attrs["objectGUID"] = e["raw_attributes"]["objectGUID"][0]
        attrs["objectSid"] = (e["raw_attributes"].get("objectSid") or [None])[0]
        out.append(_to_user(attrs))
    return out


def read_root_dse(conn: Connection) -> dict[str, Any]:
    conn.search("", "(objectClass=*)", search_scope=BASE, attributes=["defaultNamingContext", "dnsHostName"])
    for e in conn.response or []:
        if e.get("type") == "searchResEntry":
            return dict(e.get("attributes") or {})
    return {}


def dn_to_domain(dn: str) -> str:
    """DC=corp,DC=example,DC=com -> corp.example.com"""
    return ".".join(rdn.split("=", 1)[1].strip() for rdn in dn.split(",") if rdn.strip().lower().startswith("dc=")).lower()


def within(dn: str, base: str) -> bool:
    """True when dn is base or sits below it (RDN-wise, ignoring case and spacing)."""
    def norm(x: str) -> list[str]:
        return [r.strip().lower().replace(" ", "") for r in x.split(",") if r.strip()]
    d, b = norm(dn), norm(base)
    return bool(b) and len(d) >= len(b) and d[-len(b):] == b


def discover(p: DirectoryParams) -> dict[str, Any]:
    """Read the directory's base DN and DNS domain from its RootDSE.

    Active Directory publishes the RootDSE to anonymous clients, so this needs only the domain controller and the
    TLS settings, and sends no password. If a hardened directory refuses that and a service account was entered,
    it signs in and reads it again.
    """
    def read(anonymous: bool) -> dict[str, Any]:
        conn = connect(p, anonymous=anonymous)
        try:
            return read_root_dse(conn)
        finally:
            conn.unbind()

    try:
        try:
            dse, signed_in = read(anonymous=True), False
        except DirectoryError:
            if not (p.bind_dn and p.bind_password):
                raise
            dse = {}
        if not _first(dse, "defaultNamingContext") and p.bind_dn and p.bind_password:
            dse, signed_in = read(anonymous=False), True
    except DirectoryError as exc:
        return {"ok": False, "message": str(exc), "hint": exc.hint, "detail": exc.detail}
    base = _first(dse, "defaultNamingContext")
    if not base:
        return {"ok": False, "message": "The domain controller didn’t report a base DN.",
                "hint": "Enter the service account below and detect again, or type the base DN.", "detail": ""}
    return {"ok": True, "base_dn": str(base), "domain": dn_to_domain(str(base)), "dc_hostname": str(_first(dse, "dnsHostName") or p.hosts[0]),
            "signed_in": signed_in}


def test(p: DirectoryParams) -> dict[str, Any]:
    """Connection test with one step per stage, for the setup wizard and Directory settings."""
    steps: list[dict[str, Any]] = []
    try:
        conn = connect(p)
    except DirectoryError as exc:
        steps.append({"step": "connect", "ok": False, "message": str(exc), "hint": exc.hint, "detail": exc.detail})
        return {"ok": False, "steps": steps}
    steps.append({"step": "connect", "ok": True, "message": f"Connected over {p.transport.upper()} and signed in as the service account"})
    try:
        directory_base = _first(read_root_dse(conn), "defaultNamingContext")
        discovered = {"base_dn": str(directory_base), "domain": dn_to_domain(str(directory_base))} if directory_base else None
        conn.search(p.user_search_base or p.base_dn, p.user_filter, search_scope=SUBTREE, attributes=["sAMAccountName"], size_limit=5)
        n_users = len([e for e in conn.response or [] if e.get("type") == "searchResEntry"])
        conn.search(p.group_search_base or p.base_dn, p.group_filter, search_scope=SUBTREE, attributes=["cn"], size_limit=5)
        n_groups = len([e for e in conn.response or [] if e.get("type") == "searchResEntry"])
        ok = n_users > 0
        outside = bool(discovered) and not within(p.base_dn, discovered["base_dn"])
        steps.append({"step": "search", "ok": ok, "message": f"Found users ({n_users}+ sample) and groups ({n_groups}+ sample)" if ok else "The user search returned no users",
                      "hint": "" if ok else (f"This directory's base DN is {discovered['base_dn']}." if outside else "Check the base DN and user search base.")})
        return {"ok": ok, "steps": steps, "discovered": discovered, "base_dn_outside": outside}
    finally:
        conn.unbind()
