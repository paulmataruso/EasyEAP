"""The Kerberos service account for Group Policy autoenrollment, made from the console (docs/autoenrollment.md §1).

An administrator types a domain account that may create users once; EasyEAP binds with it over LDAPS or StartTLS
(never plain LDAP), checks that HTTP/<console host> (and HOST/, its alias) isn't another account's SPN anywhere in the
forest, creates (or resets the one EasyEAP made) the user `easyeap-cep` with a random password, AES only and not
delegable, registers the SPN on it, and derives its keys from that password with the salt the domain controller itself
reports (MIT `ktutil addent -f`), so neither Windows' nor Samba's salting rule is assumed. The administrator's
credentials and the account's password are kept only in memory for the request: nothing is stored or logged but the
keytab, encrypted like an uploaded one.

Order matters for a reset: the keys are derived before the password changes (the salt doesn't change with it), so a
domain controller EasyEAP can't reach over Kerberos stops the run before anything in AD changes, and once the password
has changed EasyEAP always has the keys that match it.
"""
from __future__ import annotations

import os
import re
import secrets
import shutil
import socket
import ssl
import string
import struct
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from ldap3 import BASE, FIRST, MODIFY_ADD, MODIFY_REPLACE, NONE, SUBTREE, Connection, Server, ServerPool, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars

from app.directory.ldap import DirectoryParams, _guid, _hint_for, _sid

DESCRIPTION = "EasyEAP certificate enrollment (Kerberos service for Group Policy autoenrollment). Not for signing in."
MARK = "EasyEAP certificate enrollment"  # an existing account is EasyEAP's own only if its description starts with this
UF_ACCOUNTDISABLE, UF_PASSWD_NOTREQD, UF_NORMAL_ACCOUNT, UF_DONT_EXPIRE_PASSWD, UF_NOT_DELEGATED = 0x2, 0x20, 0x200, 0x10000, 0x100000
# The userAccountControl bits an account EasyEAP may take over can have: what EasyEAP and its scripts set, and the
# defaults of a half-made one. Anything else (smart card required, trusted for delegation, a computer…) isn't ours.
TAKEOVER_UAC = UF_ACCOUNTDISABLE | UF_PASSWD_NOTREQD | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD | UF_NOT_DELEGATED
AES_ONLY = 0x18  # msDS-SupportedEncryptionTypes: AES128 and AES256 (RFC 3962), no RC4 or DES
ENCTYPES = ("aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96")
KTUTIL = "ktutil"
TIMEOUT = 20


class AccountError(Exception):
    """A step that failed, said for the console: `step` is directory | permission | spn | account | kerberos."""

    def __init__(self, step: str, message: str, detail: str = ""):
        super().__init__(message)
        self.step, self.detail = step, detail[:300]


@dataclass
class Made:
    dn: str
    guid: str
    kvno: int
    created: bool
    keytab: bytes = field(repr=False)
    gc_checked: bool = True


# ── The administrator's connection ───────────────────────────────────────────


def admin_user(name: str, realm: str) -> str:
    """What the administrator typed, as LDAP simple bind takes it: a UPN, DOMAIN\\name, or a DN as typed; a bare name
    becomes name@domain."""
    name = name.strip()
    if not name or len(name) > 256 or any(c in name for c in "\r\n\x00"):
        raise AccountError("directory", "Enter the administrator's user name, for example Administrator@corp.example.")
    if "@" in name or "\\" in name or "=" in name:
        return name
    return f"{name}@{realm.lower()}"


def _tls(p: DirectoryParams) -> Tls:
    if not p.verify_certificate:
        return Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS_CLIENT)
    return Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLS_CLIENT, **({"ca_certs_data": p.ca_bundle_pem} if p.ca_bundle_pem else {}))


def connect(p: DirectoryParams, user: str, password: str, *, port: int | None = None, ssl_only: bool = False,
            timeout: int = 8) -> Connection:
    """Bind as the administrator over LDAPS or StartTLS. A password is set on this connection, so plain LDAP is
    refused even in the lab."""
    if p.transport == "plain":
        raise AccountError("directory", "The directory connection uses plain LDAP. Switch it to LDAPS or StartTLS first: "
                                        "Active Directory sets passwords only over an encrypted connection.")
    use_ssl = ssl_only or p.transport == "ldaps"
    servers = [Server(h.strip().split(":", 1)[0], port=port or p.port, use_ssl=use_ssl, tls=_tls(p), get_info=NONE, connect_timeout=timeout)
               for h in p.hosts if h.strip()]
    if not servers:
        raise AccountError("directory", "No domain controller is configured under Directory.")
    conn = Connection(ServerPool(servers, FIRST, active=1, exhaust=True), user=user, password=password, auto_bind=False,
                      receive_timeout=timeout * 2, raise_exceptions=False, read_only=False)
    try:
        conn.open()
        if conn.closed:
            raise AccountError("directory", "EasyEAP couldn't reach a domain controller.", _hint_for(str(conn.last_error)))
        if not use_ssl and not conn.start_tls():
            raise AccountError("directory", "StartTLS failed.", str(conn.result))
        if not conn.bind():
            res = conn.result or {}
            text = f"{res.get('description', '')} {res.get('message', '')}".strip()
            raise AccountError("permission", "The administrator account couldn't sign in. " + _hint_for(text).replace("service account's", "account's"), text)
    except LDAPException as exc:
        raise AccountError("directory", "EasyEAP couldn't connect to the directory.", str(exc)) from exc
    return conn


def _one(conn: Connection, base: str, flt: str, attrs: list[str], scope=SUBTREE, controls=None) -> list[dict]:
    """Search results as dicts (with the raw values under "_raw"). A search that fails raises: an empty answer must
    mean nothing matched, not that the directory didn't answer."""
    try:
        conn.search(base, flt, search_scope=scope, attributes=attrs, size_limit=50, controls=controls)
    except LDAPException as exc:
        raise AccountError("directory", "A directory search failed.", str(exc)) from exc
    res = conn.result or {}
    if res.get("result") == 32:  # noSuchObject: the base isn't there
        return []
    if res.get("result") not in (0, None):
        text = f"{res.get('description', '')} {res.get('message', '')}".strip()
        raise AccountError("directory", f"A directory search failed: {text or res.get('result')}.", text)
    return [{"dn": e.get("dn"), **(e.get("attributes") or {}), "_raw": e.get("raw_attributes") or {}}
            for e in conn.response or [] if e.get("type") == "searchResEntry"]


def _raw1(row: dict, name: str):
    v = (row.get("_raw") or {}).get(name)
    return v[0] if isinstance(v, list) and v else (v if v not in ([], None) else None)


def _first(v):
    return v[0] if isinstance(v, list) and v else v


def domain_info(conn: Connection) -> dict:
    """The domain's naming context, its DNS name as a realm, the default container for users and the forest's root."""
    root = _one(conn, "", "(objectClass=*)", ["defaultNamingContext", "rootDomainNamingContext"], scope=BASE)
    if not root or not root[0].get("defaultNamingContext"):
        raise AccountError("directory", "The domain controller didn't say which domain it serves.")
    base = _first(root[0]["defaultNamingContext"])
    realm = ".".join(part.split("=", 1)[1] for part in base.split(",") if part.strip().upper().startswith("DC=")).upper()
    users = f"CN=Users,{base}"
    wk = _one(conn, base, "(objectClass=*)", ["wellKnownObjects", "objectSid"], scope=BASE)
    for value in (wk[0].get("wellKnownObjects") or []) if wk else []:
        # B:32:A9D1CA15768811D1ADED00C04FD8D5CD:CN=Users,DC=… (the users container's well-known GUID)
        if isinstance(value, str) and value.upper().startswith("B:32:A9D1CA15768811D1ADED00C04FD8D5CD:"):
            users = value.split(":", 3)[3]
    sid = _sid(_raw1(wk[0], "objectSid")) if wk else None
    return {"base": base, "realm": realm, "users": users, "forest": _first(root[0].get("rootDomainNamingContext")) or base, "sid": sid}


def admin_sids(conn: Connection, info: dict) -> set[str]:
    """Owners an account EasyEAP takes over may have: Domain Admins, Enterprise Admins (of a single-domain forest),
    Administrators, SYSTEM, and the administrator signed in now (who owns what they create without Domain Admins)."""
    out = {"S-1-5-32-544", "S-1-5-18"}
    if info.get("sid"):
        out |= {f"{info['sid']}-512", f"{info['sid']}-519"}
    try:
        who = str(conn.extend.standard.who_am_i() or "")  # u:CORP\admin
    except LDAPException:
        who = ""
    name = who.split("\\", 1)[-1] if who.startswith("u:") else ""
    if name:
        me = _one(conn, info["base"], f"(sAMAccountName={escape_filter_chars(name)})", ["objectSid"])
        if me and _raw1(me[0], "objectSid"):
            out.add(_sid(_raw1(me[0], "objectSid")))
    return out


def _owner(sd: bytes | None) -> str | None:
    """The owner SID of a self-relative security descriptor (MS-DTYP 2.4.6)."""
    if not sd or len(sd) < 20:
        return None
    (off,) = struct.unpack_from("<I", sd, 4)
    return _sid(sd[off:]) if off and off + 8 <= len(sd) else None


# ── The SPN and the account ──────────────────────────────────────────────────


def spn_owners(p: DirectoryParams, user: str, password: str, conn: Connection, info: dict, host: str) -> tuple[list[dict], bool]:
    """Accounts that hold HTTP/<host>, or HOST/<host>, which Active Directory's default sPNMappings make cover HTTP/<host>
    (a domain-joined computer of that name): in the whole forest through the global catalog (3269, TLS) when it
    answers, otherwise in this domain. Returns (owners, whether the whole forest was searched)."""
    h = escape_filter_chars(host)
    flt = f"(|(servicePrincipalName=HTTP/{h})(servicePrincipalName=HOST/{h}))"
    attrs = ["sAMAccountName", "objectGUID", "description", "servicePrincipalName", "objectClass"]

    def rows(c: Connection, base: str) -> list[dict]:
        return [{**r, "guid": _guid(_raw1(r, "objectGUID")) if _raw1(r, "objectGUID") else ""} for r in _one(c, base, flt, attrs)]
    try:
        gc = connect(p, user, password, port=3269, ssl_only=True, timeout=5)
    except AccountError:
        return rows(conn, info["base"]), False
    try:
        return rows(gc, ""), True
    except AccountError:  # the global catalog answered the bind but not the search
        return rows(conn, info["base"]), False
    finally:
        gc.unbind()


def new_password() -> str:
    """40 random characters with every class Active Directory's complexity rule counts."""
    alphabet = string.ascii_letters + string.digits + "-_.~!"
    body = "".join(secrets.choice(alphabet) for _ in range(36))
    return body + secrets.choice(string.ascii_uppercase) + secrets.choice(string.ascii_lowercase) + secrets.choice(string.digits) + "!"


def _pw(password: str) -> bytes:
    return f'"{password}"'.encode("utf-16-le")


def _ok(conn: Connection, what: str) -> None:
    res = conn.result or {}
    if res.get("result") == 0:
        return
    text = f"{res.get('description', '')} {res.get('message', '')}".strip()
    if "000021C7" in text or "would cause a conflict" in text:  # ERROR_DS_SPN_VALUE_NOT_UNIQUE_IN_FOREST; Samba's wording
        raise AccountError("spn", "Active Directory says another account already uses that service name (a duplicate SPN, or "
                                  "HOST/ on a computer of that name).", text)
    if res.get("result") in (50, 32) or "insufficientAccessRights" in text or "INSUFF_ACCESS_RIGHTS" in text:
        raise AccountError("permission", f"The administrator account may not {what}. Use a Domain Admin, or an account with "
                                         "the right to create users in that container.", text)
    if res.get("result") == 19 or "constraintViolation" in text or "unwillingToPerform" in text:
        raise AccountError("account", f"Active Directory refused to {what}: {text or 'constraint violation'}.", text)
    raise AccountError("account", f"Active Directory couldn't {what}: {text or res}.", text)


def find_account(conn: Connection, info: dict, account: str) -> dict | None:
    """The user `account` in the domain, with what deciding whether EasyEAP may take it over needs."""
    found = _one(conn, info["base"], f"(&(objectClass=user)(sAMAccountName={escape_filter_chars(account)}))",
                 ["objectGUID", "description", "servicePrincipalName", "userAccountControl", "adminCount", "objectClass",
                  "nTSecurityDescriptor"], controls=security_descriptor_control(sdflags=0x01))
    if not found:
        return None
    a = found[0]
    return {"dn": a["dn"], "guid": _guid(_raw1(a, "objectGUID")) if _raw1(a, "objectGUID") else "",
            "description": str(_first(a.get("description")) or ""), "spns": [str(v) for v in (a.get("servicePrincipalName") or [])],
            "uac": int(_first(a.get("userAccountControl")) or 0), "admin_count": int(_first(a.get("adminCount")) or 0),
            "classes": [str(c).lower() for c in (a.get("objectClass") or [])], "owner": _owner(_raw1(a, "nTSecurityDescriptor"))}


def check_takeover(a: dict, *, account: str, spn: str, known_guid: str | None, owners: set[str]) -> None:
    """Refuse to reset an account EasyEAP didn't make: the one whose objectGUID EasyEAP keeps, or one its scripts made
    (the description) that only administrators control, has no other service names and nothing unusual set. Anyone
    who owns the object could otherwise set its key themselves and forge tickets to EasyEAP."""
    if a["admin_count"] == 1:
        raise AccountError("account", f"{account} is (or was) in a protected group such as Domain Admins (adminCount 1). EasyEAP won't "
                                      "use it: remove it, or choose another account name in Settings.")
    if "computer" in a["classes"]:
        raise AccountError("account", f"{account} is a computer account. Choose another account name in Settings.")
    if known_guid and a["guid"] == known_guid.strip("{}").lower():
        return
    if not a["description"].startswith(MARK):
        raise AccountError("account", f"An account named {account} already exists and EasyEAP didn't make it. Rename or remove it, "
                                      "or choose another account name in Settings.")
    if a["owner"] not in owners:
        raise AccountError("account", f"{account} exists, but it's owned by {a['owner'] or 'an unknown owner'}, not by Domain Admins or "
                                      "you: whoever owns it could set its key and forge tickets to EasyEAP. Remove it and try again "
                                      "(EasyEAP creates it afresh), or choose another account name in Settings.")
    other = [v for v in a["spns"] if v.lower() != spn.lower()]
    if other:
        raise AccountError("account", f"{account} exists and also serves {', '.join(other[:3])}: it isn't only EasyEAP's. Choose another "
                                      "account name in Settings.")
    if a["uac"] & ~TAKEOVER_UAC:
        raise AccountError("account", f"{account} exists with settings EasyEAP doesn't make (userAccountControl {a['uac']:#x}). Remove it "
                                      "and try again, or choose another account name in Settings.")


def create_account(conn: Connection, info: dict, *, account: str, spn: str, container: str | None) -> tuple[str, str]:
    """Add the account disabled and without a password (Windows doesn't take unicodePwd in the add of a user, KB
    269190; an explicit userAccountControl keeps PASSWD_NOTREQD off). Returns (dn, objectGUID)."""
    where = container or info["users"]
    dn = f"CN={account},{where}"
    _call(conn, f"create {account} in {where}", lambda: conn.add(dn, ["top", "person", "organizationalPerson", "user"], {
        "sAMAccountName": account,
        # The UPN's name is the sAMAccountName exactly, so Windows' salt (realm + sAMAccountName) and Samba's (from
        # the UPN) agree; the keys are derived with the salt the KDC reports anyway.
        "userPrincipalName": f"{account}@{info['realm'].lower()}",
        "description": DESCRIPTION,
        "userAccountControl": str(UF_NORMAL_ACCOUNT | UF_ACCOUNTDISABLE),
        "msDS-SupportedEncryptionTypes": str(AES_ONLY),
        "servicePrincipalName": [spn],
    }))
    got = _one(conn, dn, "(objectClass=user)", ["objectGUID"], scope=BASE)
    return dn, (_guid(_raw1(got[0], "objectGUID")) if got and _raw1(got[0], "objectGUID") else "")


def set_password(conn: Connection, dn: str, password: str, account: str) -> None:
    _call(conn, f"set the password of {account}", lambda: conn.modify(dn, {"unicodePwd": [(MODIFY_REPLACE, [_pw(password)])]}))


def finish_account(conn: Connection, dn: str, *, account: str, spn: str, spns: list[str], created: bool) -> None:
    """Enabled, password never expires, not delegable, AES only, and the SPN."""
    changes = {"userAccountControl": [(MODIFY_REPLACE, [str(UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD | UF_NOT_DELEGATED)])],
               "msDS-SupportedEncryptionTypes": [(MODIFY_REPLACE, [str(AES_ONLY)])]}
    if spn.lower() not in [v.lower() for v in spns]:
        changes["servicePrincipalName"] = [(MODIFY_ADD, [spn])]
    _call(conn, f"enable {account}" if created else f"update {account}", lambda: conn.modify(dn, changes))


def _call(conn: Connection, what: str, op) -> None:
    try:
        op()
    except LDAPException as exc:
        raise AccountError("directory", f"The directory connection failed while trying to {what}.", str(exc)) from exc
    _ok(conn, what)


def key_version(conn: Connection, dn: str) -> int:
    got = _one(conn, dn, "(objectClass=*)", ["msDS-KeyVersionNumber"], scope=BASE)
    kvno = _first(got[0].get("msDS-KeyVersionNumber")) if got else None
    try:
        return int(kvno)
    except (TypeError, ValueError):
        raise AccountError("account", "Active Directory didn't report the account's key version (msDS-KeyVersionNumber).") from None


# ── The keytab ───────────────────────────────────────────────────────────────

_REALM = re.compile(r"^[A-Z0-9](?:[A-Z0-9.-]{0,250}[A-Z0-9])?$")
_KDC = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_ETYPE = {"aes256-cts-hmac-sha1-96": 18, "aes128-cts-hmac-sha1-96": 17}


def read_keys(data: bytes) -> list[tuple[int, int, bytes]]:
    """(kvno, enctype, key) of each entry in an MIT keytab (format 0x0502)."""
    if data[:2] != b"\x05\x02":
        raise ValueError("not a version 2 keytab")
    pos, out = 2, []
    while pos + 4 <= len(data):
        (size,) = struct.unpack_from(">i", data, pos)
        pos += 4
        if size <= 0:
            if size == 0:
                break
            pos += -size
            continue
        e, i = data[pos:pos + size], 0
        pos += size
        (ncomp,) = struct.unpack_from(">H", e, i)
        i += 2
        for _ in range(ncomp + 1):  # the realm, then the components
            (n,) = struct.unpack_from(">H", e, i)
            i += 2 + n
        i += 8  # name type, timestamp
        kvno = e[i]
        i += 1
        etype, n = struct.unpack_from(">HH", e, i)
        i += 4
        key = e[i:i + n]
        i += n
        if len(e) - i >= 4:
            (kvno32,) = struct.unpack_from(">I", e, i)
            kvno = kvno32 or kvno
        out.append((kvno, etype, key))
    return out


def write_keytab(realm: str, components: list[str], keys: list[tuple[int, int, bytes]], *, name_type: int = 1) -> bytes:
    """An MIT keytab (0x0502) with one principal's keys."""
    def counted(b: bytes) -> bytes:
        return struct.pack(">H", len(b)) + b

    now = int(time.time())
    out = b"\x05\x02"
    for kvno, etype, key in keys:
        body = struct.pack(">H", len(components)) + counted(realm.encode()) + b"".join(counted(c.encode()) for c in components)
        body += struct.pack(">IIB", name_type, now, kvno & 0xFF) + struct.pack(">H", etype) + counted(key) + struct.pack(">I", kvno)
        out += struct.pack(">i", len(body)) + body
    return out


def kerberos_ready(realm: str, kdcs: list[str], timeout: float = 3) -> list[str]:
    """Before anything in AD changes: ktutil is there and a domain controller answers on 88/tcp. Returns the usable
    KDC names, the ones that answered first."""
    kdcs = [k for k in kdcs if _KDC.match(k)][:4]
    if not _REALM.match(realm) or not kdcs:
        raise AccountError("kerberos", "The directory's domain or server names can't be used for Kerberos (use DNS names or IPv4 addresses).")
    if shutil.which(KTUTIL) is None:
        raise AccountError("kerberos", "This EasyEAP image has no ktutil (MIT Kerberos): update it.")
    up = []
    for k in kdcs:
        try:
            with socket.create_connection((k, 88), timeout=timeout):
                up.append(k)
        except OSError:
            continue
    if not up:
        raise AccountError("kerberos", f"No domain controller answers Kerberos (88/tcp) from EasyEAP ({', '.join(kdcs)}). EasyEAP needs it to "
                                       "derive the account's keys and test them; nothing in Active Directory was changed.")
    return up + [k for k in kdcs if k not in up]


def derive_keys(*, realm: str, kdcs: list[str], account: str, password: str, retries: int = 4) -> list[tuple[int, bytes]]:
    """(enctype, key) for the account's AES keys from `password`, with the salt the KDC reports for it (`ktutil addent
    -f`, an AS request; the account must exist). The key version is only a label in a keytab: the caller sets it."""
    kt = derive_keytab(realm=realm, kdcs=kdcs, account=account, password=password, kvno=1, host="-", retries=retries)
    return [(etype, key) for _, etype, key in read_keys(kt)]


def keytab_for(realm: str, host: str, keys: list[tuple[int, bytes]], kvno: int) -> bytes:
    """The keys as HTTP/<host>@<realm> at `kvno`: tickets for that SPN are encrypted with the account's keys."""
    return write_keytab(realm, ["HTTP", host], [(kvno, etype, key) for etype, key in keys])


def derive_keytab(*, realm: str, kdcs: list[str], account: str, password: str, kvno: int, host: str, retries: int = 4) -> bytes:
    """The account's AES keys from its password, with the salt the KDC reports for it (`ktutil addent -f`), written
    as the keys of HTTP/<host>@<realm>: tickets for that SPN are encrypted with the account's keys."""
    kdcs = [k for k in kdcs if _KDC.match(k)][:4]
    if not _REALM.match(realm) or not kdcs:
        raise AccountError("kerberos", "The directory's domain or server names can't be used for Kerberos (use DNS names or IPv4 addresses).")
    if shutil.which(KTUTIL) is None:
        raise AccountError("kerberos", "This EasyEAP image has no ktutil (MIT Kerberos): update it.")
    shm = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else None  # noqa: S108
    with tempfile.TemporaryDirectory(prefix="easyeap-sa-", dir=shm) as d:
        conf, kt = Path(d) / "krb5.conf", Path(d) / f"{uuid.uuid4().hex}.keytab"
        kdc_lines = "\n".join(f"        kdc = {k}" for k in kdcs)
        conf.write_text(f"""[libdefaults]
    default_realm = {realm}
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    udp_preference_limit = 0
[realms]
    {realm} = {{
{kdc_lines}
    }}
""")
        principal = f"{account}@{realm}"
        script = "".join(f"addent -password -p {principal} -k {kvno} -e {e} -f\n{password}\n" for e in ENCTYPES) + f"wkt {kt}\nquit\n"
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "KRB5_CONFIG": str(conf), "HOME": d, "KRB5CCNAME": "MEMORY:easyeap-sa"}
        last = ""
        for attempt in range(retries):  # a new account may take a moment to reach the KDC that answers
            try:
                p = subprocess.run([KTUTIL], input=script, capture_output=True, text=True, timeout=TIMEOUT, env=env, cwd=d)  # noqa: S603
            except subprocess.TimeoutExpired:
                raise AccountError("kerberos", "The domain controller didn't answer Kerberos (88/tcp) in time.") from None
            last = (p.stderr or p.stdout or "").replace(password, "<password>")
            if kt.exists() and kt.stat().st_size > 2:
                keys = [k for k in read_keys(kt.read_bytes()) if k[1] in _ETYPE.values()]
                if len(keys) == len(ENCTYPES):
                    return write_keytab(realm, ["HTTP", host], keys)
            kt.unlink(missing_ok=True)
            time.sleep(1 + attempt)
    hint = ("The domain controller doesn't know the account yet, or Kerberos (88/tcp) from EasyEAP to it is blocked."
            if "not found" in last.lower() or "cannot contact" in last.lower() or "unable to reach" in last.lower() else "")
    raise AccountError("kerberos", ("EasyEAP couldn't get the account's salt from the domain controller. " + hint).strip(),
                       re.sub(r"\s+", " ", last)[:300])
