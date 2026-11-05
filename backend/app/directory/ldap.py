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

from ldap3 import BASE, NONE, SUBTREE, Connection, Server, ServerPool, Tls, FIRST
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
    def __init__(self, message: str, hint: str = ""):
        super().__init__(message)
        self.hint = hint


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


def connect(p: DirectoryParams, timeout: int = 8) -> Connection:
    if p.transport == "plain" and not get_settings().lab_mode:
        raise DirectoryError("Plain LDAP is disabled.", "Use LDAPS (636) or StartTLS so the service-account password is encrypted in transit.")
    tls = None if p.transport == "plain" else _tls(p)
    servers = [Server(h.strip(), port=p.port, use_ssl=p.transport == "ldaps", tls=tls, get_info=NONE, connect_timeout=timeout)
               for h in p.hosts if h.strip()]
    if not servers:
        raise DirectoryError("No domain controller configured.", "Enter at least one domain controller hostname.")
    pool = ServerPool(servers, FIRST, active=1, exhaust=True)
    conn = Connection(pool, user=p.bind_dn, password=p.bind_password, auto_bind=False, receive_timeout=timeout * 2,
                      raise_exceptions=False, read_only=True)
    try:
        if not conn.open():
            raise DirectoryError("Could not reach a domain controller.", _hint_for(str(conn.result)))
        if p.transport == "starttls" and not conn.start_tls():
            raise DirectoryError("StartTLS failed.", "Check the domain controller's certificate and the uploaded CA bundle.")
        if not conn.bind():
            desc = (conn.result or {}).get("description", "")
            raise DirectoryError("The service account could not sign in.", _hint_for(desc + " " + str((conn.result or {}).get("message", ""))))
    except LDAPException as exc:
        raise DirectoryError("Could not connect to the directory.", _hint_for(str(exc))) from exc
    return conn


def _hint_for(message: str) -> str:
    msg = message.lower()
    if "certificate verify failed" in msg or "certificate" in msg and "verify" in msg:
        return "The domain controller's certificate is not trusted. Upload your AD root CA (PEM) in Advanced settings."
    if "hostname" in msg and "match" in msg:
        return "The certificate does not match the hostname. Use the DC's fully qualified name as it appears in its certificate."
    if "invalidcredentials" in msg or "invalid credentials" in msg or "52e" in msg:
        return "Check the service account's bind DN (or user@domain) and password."
    if "533" in msg:
        return "The service account is disabled in Active Directory."
    if "775" in msg:
        return "The service account is locked out."
    if "strongerauthrequired" in msg or "stronger" in msg:
        return "The domain controller requires signing or TLS. Use LDAPS or StartTLS."
    if "timed out" in msg or "timeout" in msg or "unreachable" in msg or "refused" in msg or "socket" in msg:
        return "EasyEAP could not open a connection. Check DNS, routing and that TCP 636 (or 389 for StartTLS) is allowed."
    return "See technical details below."


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


def test(p: DirectoryParams) -> dict[str, Any]:
    """Connection test with one step per stage, for the setup wizard and Directory settings."""
    steps: list[dict[str, Any]] = []
    try:
        conn = connect(p)
    except DirectoryError as exc:
        steps.append({"step": "connect", "ok": False, "message": str(exc), "hint": exc.hint})
        return {"ok": False, "steps": steps}
    steps.append({"step": "connect", "ok": True, "message": f"Connected over {p.transport.upper()} and signed in as the service account"})
    try:
        conn.search(p.user_search_base or p.base_dn, p.user_filter, search_scope=SUBTREE, attributes=["sAMAccountName"], size_limit=5)
        n_users = len([e for e in conn.response or [] if e.get("type") == "searchResEntry"])
        conn.search(p.group_search_base or p.base_dn, p.group_filter, search_scope=SUBTREE, attributes=["cn"], size_limit=5)
        n_groups = len([e for e in conn.response or [] if e.get("type") == "searchResEntry"])
        ok = n_users > 0
        steps.append({"step": "search", "ok": ok, "message": f"Found users ({n_users}+ sample) and groups ({n_groups}+ sample)" if ok else "The user search returned no users",
                      "hint": "" if ok else "Check the base DN and user search base."})
        return {"ok": ok, "steps": steps}
    finally:
        conn.unbind()
