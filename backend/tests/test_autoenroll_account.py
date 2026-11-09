"""app/autoenroll/account.py and POST /autoenroll/service-account: the Kerberos service account made from the console
with an administrator's credentials (docs/autoenrollment.md §1). No directory here: a fake LDAP connection and a fake
ktutil; the real ktutil, when the image has it, for the keytab it writes."""
from __future__ import annotations

import os
import shutil
import stat
import string
import struct
import subprocess
import sys
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.autoenroll import account, kerberos

INFO = {"base": "DC=corp,DC=example", "realm": "CORP.EXAMPLE", "users": "CN=Users,DC=corp,DC=example", "forest": "DC=corp,DC=example"}
SPN = "HTTP/easyeap.corp.example"


class FakeConn:
    """Enough of ldap3.Connection: searches answer from `entries` (by base and a substring of the filter); an attrs dict
    may carry "_raw" (the raw attribute values)."""

    def __init__(self, entries=None, results=None, search_result=None):
        self.entries = entries or {}
        self.results = list(results or [])
        self.search_result = search_result or {"result": 0}
        self.calls: list[tuple] = []
        self.result: dict = {"result": 0}
        self.response: list = []

    def search(self, base, flt, search_scope=None, attributes=None, size_limit=None, controls=None):
        self.calls.append(("search", base, flt, controls))
        self.result = self.search_result
        self.response = [{"type": "searchResEntry", "dn": dn, "attributes": {k: v for k, v in attrs.items() if k != "_raw"},
                          "raw_attributes": attrs.get("_raw", {})}
                         for (b, needle), rows in self.entries.items() if b == base and needle in flt for dn, attrs in rows]
        return bool(self.response)

    def _done(self):
        self.result = self.results.pop(0) if self.results else {"result": 0}
        return self.result["result"] == 0

    def modify(self, dn, changes):
        self.calls.append(("modify", dn, changes))
        return self._done()

    def add(self, dn, classes, attrs):
        self.calls.append(("add", dn, classes, attrs))
        return self._done()


DOMAIN_SID = "S-1-5-21-1-2-3"
GUID = "6f9619ff-8b86-d011-b42d-00c04fc964ff"


def sid_bytes(sid: str) -> bytes:
    parts = sid.split("-")
    subs = [int(x) for x in parts[3:]]
    return bytes([int(parts[1]), len(subs)]) + int(parts[2]).to_bytes(6, "big") + b"".join(x.to_bytes(4, "little") for x in subs)


def sd_owned_by(sid: str) -> bytes:
    """A self-relative security descriptor with only an owner."""
    return struct.pack("<BBHIIII", 1, 0, 0x8000, 20, 0, 0, 0) + sid_bytes(sid)


def acct(**over) -> dict:
    """find_account's answer for an account EasyEAP's script made, owned by Domain Admins."""
    return {"dn": "CN=easyeap-cep,CN=Users,DC=corp,DC=example", "guid": GUID, "description": account.DESCRIPTION, "spns": [SPN],
            "uac": 0x200 | 0x10000 | 0x100000, "admin_count": 0, "classes": ["top", "person", "organizationalPerson", "user"],
            "owner": f"{DOMAIN_SID}-512", **over}


OWNERS = {f"{DOMAIN_SID}-512", "S-1-5-32-544"}


# ── Small pieces ─────────────────────────────────────────────────────────────


def test_admin_user():
    assert account.admin_user(" Administrator ", "CORP.EXAMPLE") == "Administrator@corp.example"
    assert account.admin_user("admin@corp.example", "CORP.EXAMPLE") == "admin@corp.example"
    assert account.admin_user("CORP\\admin", "CORP.EXAMPLE") == "CORP\\admin"
    assert account.admin_user("CN=Admin,CN=Users,DC=corp,DC=example", "CORP.EXAMPLE").startswith("CN=Admin")
    for bad in ("", "   ", "a\r\nb", "x" * 300):
        with pytest.raises(account.AccountError) as e:
            account.admin_user(bad, "CORP.EXAMPLE")
        assert e.value.step == "directory"


def test_new_password_meets_complexity():
    seen = set()
    for _ in range(50):
        pw = account.new_password()
        assert len(pw) == 40 and pw not in seen
        seen.add(pw)
        assert any(c in string.ascii_uppercase for c in pw) and any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.digits for c in pw) and any(not c.isalnum() for c in pw)
        assert '"' not in pw and "\n" not in pw  # unicodePwd quotes it; ktutil reads it as one line


def test_password_value_is_quoted_utf16():
    assert account._pw("Pa1!") == '"Pa1!"'.encode("utf-16-le")


def test_plain_ldap_is_refused():
    p = SimpleNamespace(transport="plain", hosts=["dc1"], port=389)
    with pytest.raises(account.AccountError) as e:
        account.connect(p, "admin@corp.example", "pw")
    assert e.value.step == "directory" and "LDAPS" in str(e.value)


@pytest.mark.parametrize(("result", "step"), [
    ({"result": 50, "description": "insufficientAccessRights", "message": ""}, "permission"),
    ({"result": 32, "description": "noSuchObject", "message": ""}, "permission"),
    ({"result": 19, "description": "constraintViolation", "message": "0000052D: password policy"}, "account"),
    ({"result": 53, "description": "unwillingToPerform", "message": "0000001F: SvcErr"}, "account"),
    ({"result": 80, "description": "other", "message": ""}, "account"),
])
def test_ok_maps_ldap_results(result, step):
    conn = FakeConn()
    conn.result = result
    with pytest.raises(account.AccountError) as e:
        account._ok(conn, "create easyeap-cep")
    assert e.value.step == step and e.value.detail


def test_domain_info_reads_the_users_container():
    conn = FakeConn({
        ("", "objectClass"): [("", {"defaultNamingContext": "DC=corp,DC=example", "rootDomainNamingContext": "DC=example"})],
        ("DC=corp,DC=example", "objectClass"): [("DC=corp,DC=example", {"wellKnownObjects": [
            "B:32:AA312825768811D1ADED00C04FD8D5CD:CN=Computers,DC=corp,DC=example",
            "B:32:A9D1CA15768811D1ADED00C04FD8D5CD:OU=People,DC=corp,DC=example"], "_raw": {"objectSid": [sid_bytes(DOMAIN_SID)]}})],
    })
    info = account.domain_info(conn)
    assert info == {"base": "DC=corp,DC=example", "realm": "CORP.EXAMPLE", "users": "OU=People,DC=corp,DC=example", "forest": "DC=example",
                    "sid": DOMAIN_SID}


def test_domain_info_without_a_naming_context():
    with pytest.raises(account.AccountError):
        account.domain_info(FakeConn({("", "objectClass"): [("", {})]}))


def test_a_failed_search_is_an_error_not_an_empty_answer():
    conn = FakeConn(search_result={"result": 1, "description": "operationsError", "message": "000004DC: LdapErr"})
    with pytest.raises(account.AccountError) as e:
        account._one(conn, "DC=corp,DC=example", "(x=y)", ["x"])
    assert e.value.step == "directory"
    assert account._one(FakeConn(search_result={"result": 32}), "CN=gone,DC=corp,DC=example", "(x=y)", ["x"]) == []


# ── The account ──────────────────────────────────────────────────────────────


def test_find_account_reads_owner_guid_and_flags():
    raw = {"objectGUID": [uuid.UUID(GUID).bytes_le], "nTSecurityDescriptor": [sd_owned_by(f"{DOMAIN_SID}-512")]}
    conn = FakeConn({("DC=corp,DC=example", "sAMAccountName=easyeap-cep"): [("CN=easyeap-cep,CN=Users,DC=corp,DC=example", {
        "description": [account.DESCRIPTION], "servicePrincipalName": [SPN], "userAccountControl": 66048, "objectClass": ["user"], "_raw": raw})]})
    a = account.find_account(conn, INFO, "easyeap-cep")
    assert a["guid"] == GUID and a["owner"] == f"{DOMAIN_SID}-512" and a["uac"] == 66048 and a["spns"] == [SPN]
    assert conn.calls[0][3] is not None  # asked for the owner (SD flags control)
    other = FakeConn()
    assert account.find_account(other, INFO, "a*b") is None and "sAMAccountName=a\\2ab" in other.calls[0][2]  # escaped


def test_takeover_of_the_account_easyeap_made():
    account.check_takeover(acct(), account="easyeap-cep", spn=SPN, known_guid=None, owners=OWNERS)  # the script's, admin-owned
    # The GUID EasyEAP keeps is enough, whoever owns it now.
    account.check_takeover(acct(owner="S-1-5-21-9-9-9-1105", description=""), account="easyeap-cep", spn=SPN, known_guid="{" + GUID.upper() + "}",
                           owners=OWNERS)
    account.check_takeover(acct(uac=0x202), account="easyeap-cep", spn=SPN, known_guid=None, owners=OWNERS)  # a half-made one


@pytest.mark.parametrize(("over", "says"), [
    ({"description": "Payroll service"}, "didn't make it"),
    ({"owner": "S-1-5-21-1-2-3-1105"}, "owned by S-1-5-21-1-2-3-1105"),       # a helpdesk user made it with the marker
    ({"spns": [SPN, "MSSQLSvc/db1.corp.example:1433"]}, "also serves MSSQLSvc"),
    ({"uac": 0x200 | 0x40000}, "userAccountControl 0x40200"),               # smart card required
    ({"uac": 0x200 | 0x80000}, "userAccountControl 0x80200"),               # trusted for delegation
    ({"admin_count": 1}, "protected group"),
    ({"classes": ["user", "computer"]}, "computer account"),
])
def test_takeover_refused(over, says):
    with pytest.raises(account.AccountError) as e:
        account.check_takeover(acct(**over), account="easyeap-cep", spn=SPN, known_guid=None, owners=OWNERS)
    assert e.value.step == "account" and says in str(e.value)


def test_known_guid_doesnt_excuse_a_protected_account():
    with pytest.raises(account.AccountError):
        account.check_takeover(acct(admin_count=1), account="easyeap-cep", spn=SPN, known_guid=GUID, owners=OWNERS)


def test_admin_sids(monkeypatch):
    conn = FakeConn({("DC=corp,DC=example", "sAMAccountName=helpdesk-admin"): [("CN=h,DC=corp,DC=example", {"_raw": {"objectSid": [sid_bytes("S-1-5-21-1-2-3-1500")]}})]})
    conn.extend = SimpleNamespace(standard=SimpleNamespace(who_am_i=lambda: "u:CORP\\helpdesk-admin"))
    got = account.admin_sids(conn, {**INFO, "sid": DOMAIN_SID})
    assert got == {"S-1-5-32-544", "S-1-5-18", f"{DOMAIN_SID}-512", f"{DOMAIN_SID}-519", "S-1-5-21-1-2-3-1500"}


def test_creates_the_account_disabled_then_password_then_enabled():
    dn = "CN=easyeap-cep,CN=Users,DC=corp,DC=example"
    conn = FakeConn({(dn, "objectClass=user"): [(dn, {"_raw": {"objectGUID": [uuid.UUID(GUID).bytes_le]}})]})
    assert account.create_account(conn, INFO, account="easyeap-cep", spn=SPN, container=None) == (dn, GUID)
    account.set_password(conn, dn, "Pw1!x", "easyeap-cep")
    account.finish_account(conn, dn, account="easyeap-cep", spn=SPN, spns=[SPN], created=True)
    add = next(c for c in conn.calls if c[0] == "add")
    attrs = add[3]
    assert add[2] == ["top", "person", "organizationalPerson", "user"]
    assert attrs["sAMAccountName"] == "easyeap-cep" and attrs["userPrincipalName"] == "easyeap-cep@corp.example"
    assert attrs["servicePrincipalName"] == [SPN] and attrs["msDS-SupportedEncryptionTypes"] == "24"
    assert attrs["description"].startswith(account.MARK)
    # Windows won't take unicodePwd in the add of a user: added disabled, then the password, then enabled.
    assert int(attrs["userAccountControl"]) == 0x200 | 0x2 and "unicodePwd" not in attrs
    mods = [c for c in conn.calls if c[0] == "modify"]
    assert mods[0][2] == {"unicodePwd": [(account.MODIFY_REPLACE, ['"Pw1!x"'.encode("utf-16-le")])]}
    assert mods[1][2]["userAccountControl"] == [(account.MODIFY_REPLACE, [str(0x200 | 0x10000 | 0x100000)])]  # normal, no expiry, not delegable
    assert "servicePrincipalName" not in mods[1][2]


def test_creates_it_in_the_container_given():
    dn, _ = account.create_account(FakeConn(), INFO, account="easyeap-cep", spn=SPN, container="OU=Svc,DC=corp,DC=example")
    assert dn == "CN=easyeap-cep,OU=Svc,DC=corp,DC=example"


def test_finish_adds_a_missing_spn():
    conn = FakeConn()
    account.finish_account(conn, "CN=x", account="easyeap-cep", spn=SPN, spns=[], created=False)
    assert conn.calls[0][2]["servicePrincipalName"] == [(account.MODIFY_ADD, [SPN])]
    account.finish_account(conn, "CN=x", account="easyeap-cep", spn=SPN, spns=[SPN.lower()], created=False)
    assert "servicePrincipalName" not in conn.calls[1][2]


def test_password_refused():
    conn = FakeConn(results=[{"result": 19, "description": "constraintViolation", "message": "0000052D: SvcErr"}])
    with pytest.raises(account.AccountError) as e:
        account.set_password(conn, "CN=x", "x", "easyeap-cep")
    assert e.value.step == "account" and "set the password" in str(e.value)


def test_duplicate_spn_from_the_dc():
    conn = FakeConn(results=[{"result": 19, "description": "constraintViolation",
                              "message": "000021C7: AtrErr: DSID-03200BBA, #1: 0: 000021C7: DSID-03200BBA, problem 1005 (CONSTRAINT_ATT_TYPE)"}])
    with pytest.raises(account.AccountError) as e:
        account.create_account(conn, INFO, account="easyeap-cep", spn=SPN, container=None)
    assert e.value.step == "spn"


def test_create_refused_for_want_of_rights():
    conn = FakeConn(results=[{"result": 50, "description": "insufficientAccessRights", "message": "00002098: SecErr"}])
    with pytest.raises(account.AccountError) as e:
        account.create_account(conn, INFO, account="easyeap-cep", spn=SPN, container=None)
    assert e.value.step == "permission"


def test_a_dropped_connection_is_an_account_error():
    from ldap3.core.exceptions import LDAPSocketReceiveError

    conn = FakeConn()

    def boom(*_a):
        raise LDAPSocketReceiveError("connection reset")
    conn.modify = boom
    with pytest.raises(account.AccountError) as e:
        account.set_password(conn, "CN=x", "x", "easyeap-cep")
    assert e.value.step == "directory"


def test_key_version():
    dn = "CN=easyeap-cep,CN=Users,DC=corp,DC=example"
    assert account.key_version(FakeConn({(dn, "objectClass"): [(dn, {"msDS-KeyVersionNumber": 3})]}), dn) == 3
    with pytest.raises(account.AccountError):
        account.key_version(FakeConn({(dn, "objectClass"): [(dn, {})]}), dn)


def test_spn_owners_falls_back_to_the_domain(monkeypatch):
    def no_gc(*_a, **_k):
        raise account.AccountError("directory", "no GC")
    monkeypatch.setattr(account, "connect", no_gc)
    conn = FakeConn({("DC=corp,DC=example", "servicePrincipalName=HTTP/easyeap"): [("CN=web,DC=corp,DC=example", {
        "sAMAccountName": "web", "_raw": {"objectGUID": [uuid.UUID(GUID).bytes_le]}})]})
    owners, forest = account.spn_owners(SimpleNamespace(), "u", "p", conn, INFO, "easyeap.corp.example")
    assert "(servicePrincipalName=HOST/easyeap.corp.example)" in conn.calls[0][2]
    assert forest is False and owners[0]["sAMAccountName"] == "web" and owners[0]["guid"] == GUID


def test_spn_owners_searches_the_forest(monkeypatch):
    gc = FakeConn({("", "servicePrincipalName=HTTP/easyeap"): [("CN=web,DC=other,DC=example", {"sAMAccountName": "web"})]})
    gc.unbind = lambda: None
    got = {}

    def connect(p, user, password, **kw):
        got.update(kw)
        return gc
    monkeypatch.setattr(account, "connect", connect)
    owners, forest = account.spn_owners(SimpleNamespace(), "u", "p", FakeConn(), INFO, "easyeap.corp.example")
    assert forest is True and owners[0]["dn"] == "CN=web,DC=other,DC=example"
    assert got["port"] == 3269 and got["ssl_only"] is True


def test_spn_owners_doesnt_claim_the_forest_when_the_gc_search_fails(monkeypatch):
    gc = FakeConn(search_result={"result": 1, "description": "operationsError"})
    gc.unbind = lambda: None
    monkeypatch.setattr(account, "connect", lambda *_a, **_k: gc)
    owners, forest = account.spn_owners(SimpleNamespace(), "u", "p", FakeConn(), INFO, "easyeap.corp.example")
    assert forest is False and owners == []


def test_kerberos_ready(monkeypatch):
    up = {"dc2.corp.example"}

    class Sock:
        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

    def connect(addr, timeout):
        if addr[0] in up and addr[1] == 88:
            return Sock()
        raise TimeoutError("timed out")
    monkeypatch.setattr(account.socket, "create_connection", connect)
    monkeypatch.setattr(account.shutil, "which", lambda _n: "/usr/bin/ktutil")
    assert account.kerberos_ready("CORP.EXAMPLE", ["dc1.corp.example", "dc2.corp.example"]) == ["dc2.corp.example", "dc1.corp.example"]
    up.clear()
    with pytest.raises(account.AccountError) as e:
        account.kerberos_ready("CORP.EXAMPLE", ["dc1.corp.example"])
    assert e.value.step == "kerberos" and "nothing in Active Directory was changed" in str(e.value)
    monkeypatch.setattr(account.shutil, "which", lambda _n: None)
    with pytest.raises(account.AccountError) as e:
        account.kerberos_ready("CORP.EXAMPLE", ["dc1.corp.example"])
    assert "ktutil" in str(e.value)


# ── The keytab ───────────────────────────────────────────────────────────────


def test_keytab_round_trip_reads_as_easyeaps_own():
    keys = [(5, 18, bytes(range(32))), (5, 17, bytes(range(16)))]
    data = account.write_keytab("CORP.EXAMPLE", ["HTTP", "easyeap.corp.example"], keys)
    assert account.read_keys(data) == keys
    entries = kerberos.parse_keytab(data)
    assert {(e.principal, e.realm, e.kvno, e.enctype) for e in entries} == {
        ("HTTP/easyeap.corp.example", "CORP.EXAMPLE", 5, 18), ("HTTP/easyeap.corp.example", "CORP.EXAMPLE", 5, 17)}
    s = kerberos.summarize(entries, "easyeap.corp.example")
    assert s["principal"] == "HTTP/easyeap.corp.example@CORP.EXAMPLE" and s["kvno"] == 5 and not s["problems"]
    assert kerberos.for_host(data, "easyeap.corp.example") == data


def test_keytab_kvno_over_255():
    data = account.write_keytab("CORP.EXAMPLE", ["HTTP", "h"], [(300, 18, b"k" * 32)])
    assert account.read_keys(data) == [(300, 18, b"k" * 32)]
    assert kerberos.parse_keytab(data)[0].kvno == 300


FAKE_KTUTIL = """#!{python}
import os, re, struct, sys
here = os.path.dirname(os.path.abspath(sys.argv[0]))  # derive_keytab passes only PATH and the Kerberos variables
script = sys.stdin.read()
open(os.path.join(here, "log"), "a").write(script + "\\n---\\n" + open(os.environ["KRB5_CONFIG"]).read() + "\\n" + repr(sorted(os.environ)))
mode = open(os.path.join(here, "mode")).read().strip() if os.path.exists(os.path.join(here, "mode")) else "ok"
if mode == "missing":
    sys.stderr.write("addent: Client 'easyeap-cep@CORP.EXAMPLE' not found in Kerberos database while getting salt\\n")
    sys.exit(0)
lines = script.splitlines()
entries = []
for i, line in enumerate(lines):
    m = re.match(r"addent -password -p (\\S+) -k (\\d+) -e (\\S+) -f$", line)
    if m:
        name, realm = m.group(1).split("@")
        et = {{"aes256-cts-hmac-sha1-96": 18, "aes128-cts-hmac-sha1-96": 17}}[m.group(3)]
        key = (lines[i + 1].encode() * 32)[: 32 if et == 18 else 16]
        entries.append((name, realm, int(m.group(2)), et, key))
    m = re.match(r"wkt (\\S+)$", line)
    if m:
        out = b"\\x05\\x02"
        for name, realm, kvno, et, key in entries:
            e = struct.pack(">H", 1) + struct.pack(">H", len(realm)) + realm.encode() + struct.pack(">H", len(name)) + name.encode()
            e += struct.pack(">IIB", 1, 0, kvno & 0xFF) + struct.pack(">HH", et, len(key)) + key + struct.pack(">I", kvno)
            out += struct.pack(">i", len(e)) + e
        open(m.group(1), "wb").write(out)
"""


@pytest.fixture()
def fake_ktutil(tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_SECRET", "x")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "ktutil"
    exe.write_text(FAKE_KTUTIL.format(python=sys.executable))
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setattr(account.time, "sleep", lambda _s: None)
    return bindir


def test_derive_keytab(fake_ktutil):
    data = account.derive_keytab(realm="CORP.EXAMPLE", kdcs=["dc1.corp.example", "10.0.0.5", "bad host;"], account="easyeap-cep",
                                 password="Secret1!", kvno=4, host="easyeap.corp.example")
    entries = kerberos.parse_keytab(data)
    assert {(e.principal, e.realm, e.kvno, e.enctype) for e in entries} == {
        ("HTTP/easyeap.corp.example", "CORP.EXAMPLE", 4, 18), ("HTTP/easyeap.corp.example", "CORP.EXAMPLE", 4, 17)}
    assert {k for _, _, k in account.read_keys(data)} == {(b"Secret1!" * 32)[:32], (b"Secret1!" * 32)[:16]}
    log = (fake_ktutil / "log").read_text()
    assert "addent -password -p easyeap-cep@CORP.EXAMPLE -k 4 -e aes256-cts-hmac-sha1-96 -f\nSecret1!\n" in log
    assert "kdc = dc1.corp.example" in log and "kdc = 10.0.0.5" in log and "bad host" not in log
    assert "udp_preference_limit = 0" in log
    assert "'KRB5_CONFIG'" in log and "'FAKE" not in log  # nothing else of the API's environment reaches ktutil


def test_derive_keytab_when_the_kdc_doesnt_know_the_account(fake_ktutil):
    (fake_ktutil / "mode").write_text("missing")
    with pytest.raises(account.AccountError) as e:
        account.derive_keytab(realm="CORP.EXAMPLE", kdcs=["dc1"], account="easyeap-cep", password="Secret1!", kvno=2, host="h.corp.example")
    assert e.value.step == "kerberos" and "doesn't know the account" in str(e.value)
    assert "Secret1!" not in e.value.detail and "not found" in e.value.detail
    assert (fake_ktutil / "log").read_text().count("wkt ") == 4  # retried while the account replicates


@pytest.mark.parametrize(("realm", "kdcs"), [("corp.example", ["dc1"]), ("CORP.EXAMPLE", []), ("CORP.EXAMPLE", ["-o x"]), ("A B", ["dc1"])])
def test_derive_keytab_refuses_odd_names(realm, kdcs):
    with pytest.raises(account.AccountError) as e:
        account.derive_keytab(realm=realm, kdcs=kdcs, account="easyeap-cep", password="x", kvno=1, host="h")
    assert e.value.step == "kerberos"


@pytest.mark.skipif(shutil.which("ktutil") is None, reason="MIT ktutil isn't installed (it is in the EasyEAP image)")
def test_real_ktutil_reads_the_password_from_stdin(tmp_path):
    """The real MIT ktutil takes the password on the line after addent when stdin isn't a terminal (with an explicit salt
    here: -f would ask a KDC), and its keytab reads back."""
    kt = tmp_path / "x.keytab"
    script = ("addent -password -p easyeap-cep@CORP.EXAMPLE -k 3 -e aes256-cts-hmac-sha1-96 -s CORP.EXAMPLEeasyeap-cep\nSecret1!\n"
              "addent -password -p easyeap-cep@CORP.EXAMPLE -k 3 -e aes128-cts-hmac-sha1-96 -s CORP.EXAMPLEeasyeap-cep\nSecret1!\n"
              f"wkt {kt}\nquit\n")
    p = subprocess.run(["ktutil"], input=script, capture_output=True, text=True, timeout=20, env={**os.environ, "KRB5_CONFIG": "/dev/null"})
    assert kt.exists(), p.stderr
    keys = account.read_keys(kt.read_bytes())
    assert [(k[0], k[1], len(k[2])) for k in keys] == [(3, 18, 32), (3, 17, 16)]
    # Deterministic: the same password and salt give the same key (and a different password doesn't).
    kt2 = tmp_path / "y.keytab"
    subprocess.run(["ktutil"], input=script.replace(str(kt), str(kt2)).replace("Secret1!", "Other2?"), capture_output=True, text=True,
                   timeout=20, env={**os.environ, "KRB5_CONFIG": "/dev/null"})
    assert account.read_keys(kt2.read_bytes())[0][2] != keys[0][2]


# ── The endpoint ─────────────────────────────────────────────────────────────


@pytest.fixture()
def endpoint(monkeypatch):
    from app.routers import autoenroll as r
    from app.security.ratelimit import limiter

    limiter._hits.clear()
    tid = uuid.uuid4()
    cfg = SimpleNamespace(service_account="easyeap-cep", keytab_ct=None, keytab_info={}, keytab_uploaded_at=None, keytab_test={}, updated_at=None)
    directory = SimpleNamespace(hosts=["dc1.corp.example:636", "dc2.corp.example"])
    commits = []
    session = SimpleNamespace(get=lambda _model, _id: directory, commit=lambda: commits.append(1))
    ctx = SimpleNamespace(id=tid, session=session, tenant=SimpleNamespace(slug="corp"), actor=SimpleNamespace(id="u1"))
    st = SimpleNamespace(ctx=ctx, cfg=cfg, audits=[], derived=[], tested=[], owners=[], existing=None, fail={}, kvno=[2], calls=[],
                         verified=True, conn=SimpleNamespace(unbound=False, server=SimpleNamespace(host="dc2.corp.example")))
    st.conn.unbind = lambda: setattr(st.conn, "unbound", True)

    def step(name, value=None):
        st.calls.append(name)
        if name in st.fail:
            raise st.fail[name]
        return value

    monkeypatch.setattr(r.svc, "ensure_config", lambda _s, _t: cfg)
    monkeypatch.setattr(r.svc, "realm", lambda _s, _t: "CORP.EXAMPLE")
    monkeypatch.setattr(r, "_lock_service_account", lambda _s, _t: step("lock"))
    monkeypatch.setattr(r, "console_host", lambda: "easyeap.corp.example")
    monkeypatch.setattr(r, "directory_params", lambda d: SimpleNamespace(transport="ldaps", hosts=d.hosts, verify_certificate=st.verified))
    monkeypatch.setattr(r, "_status", lambda _s, _t, c: {"config": {"keytab": c.keytab_info}})
    monkeypatch.setattr(r, "_run_test", lambda _s, _c, _cfg, prefer="": st.tested.append(prefer))
    monkeypatch.setattr(r, "_forget_keytab", lambda _t, _c: None)
    monkeypatch.setattr(r.crypto, "encrypt", lambda _t, data: b"ct:" + data)
    monkeypatch.setattr(r.audit, "record", lambda _s, _a, action, **kw: st.audits.append((action, kw)))
    monkeypatch.setattr(r.account, "kerberos_ready", lambda realm, kdcs: step("kerberos_ready", kdcs))
    monkeypatch.setattr(r.account, "connect", lambda p, user, password: step("connect", st.conn))
    monkeypatch.setattr(r.account, "domain_info", lambda _c: dict(INFO))
    monkeypatch.setattr(r.account, "find_account", lambda _c, _i, _a: st.existing)
    monkeypatch.setattr(r.account, "admin_sids", lambda _c, _i: OWNERS)
    monkeypatch.setattr(r.account, "spn_owners", lambda *_a: (st.owners, True))
    monkeypatch.setattr(r.account, "key_version", lambda _c, _dn: step("key_version", st.kvno.pop(0) if len(st.kvno) > 1 else st.kvno[0]))
    monkeypatch.setattr(r.account, "create_account", lambda _c, _i, *, account, spn, container:
                        step("create", (f"CN={account},{container or INFO['users']}", GUID)))

    def set_password(_c, dn, password, _a):
        step("set_password")
        st.password = password
    monkeypatch.setattr(r.account, "set_password", set_password)
    monkeypatch.setattr(r.account, "finish_account", lambda *_a, **_k: step("finish"))

    def derive(*, realm, kdcs, account, password, retries=4):
        step("derive")
        st.derived.append({"kdcs": kdcs, "account": account, "password": password})
        return [(18, b"k" * 32), (17, b"j" * 16)]
    monkeypatch.setattr(r.account, "derive_keys", derive)
    st.call = lambda **body: r.create_service_account(r.ServiceAccountIn(**{"username": "Administrator", "password": "AdminPw1!", **body}), ctx)
    return st


def test_endpoint_creates_stores_and_tests(endpoint):
    out = endpoint.call()
    assert out["service_account"] == {"dn": "CN=easyeap-cep,CN=Users,DC=corp,DC=example", "created": True, "forest_checked": True}
    # Nothing in AD before Kerberos is known to work; a new account gets its password, is enabled, then its keys.
    assert endpoint.calls == ["lock", "kerberos_ready", "connect", "create", "set_password", "finish", "key_version", "derive"]
    info = endpoint.cfg.keytab_info
    assert info["source"] == "console" and info["created_by"] == "Administrator@corp.example" and info["account_guid"] == GUID
    assert info["principal"] == "HTTP/easyeap.corp.example@CORP.EXAMPLE" and info["kvno"] == 2 and not info["problems"]
    assert endpoint.cfg.keytab_ct.startswith(b"ct:\x05\x02")
    assert endpoint.derived[0]["kdcs"][0] == "dc2.corp.example" and endpoint.derived[0]["password"] == endpoint.password
    assert endpoint.conn.unbound and endpoint.tested == ["dc2.corp.example"]  # tested against the DC that has the account
    action, kw = endpoint.audits[0]
    assert action == "autoenroll.service_account_created" and kw["detail"]["administrator"] == "Administrator@corp.example"
    blob = repr((endpoint.cfg.keytab_info, endpoint.audits))
    assert "AdminPw1!" not in blob and endpoint.password not in blob


def test_endpoint_reset_derives_the_keys_before_changing_anything(endpoint):
    endpoint.existing = acct()
    endpoint.kvno = [4, 5]
    out = endpoint.call()
    assert out["service_account"]["created"] is False
    assert endpoint.calls == ["lock", "kerberos_ready", "connect", "derive", "key_version", "set_password", "finish", "key_version"]
    assert endpoint.cfg.keytab_info["kvno"] == 5 and endpoint.audits[0][0] == "autoenroll.service_account_reset"


def test_endpoint_reset_stops_before_ad_when_the_kdc_fails(endpoint):
    endpoint.existing = acct()
    endpoint.cfg.keytab_ct, endpoint.cfg.keytab_info = b"old", {"principal": "HTTP/easyeap.corp.example@CORP.EXAMPLE"}
    endpoint.fail["derive"] = account.AccountError("kerberos", "Cannot contact any KDC")
    with pytest.raises(HTTPException) as e:
        endpoint.call()
    assert e.value.status_code == 400 and e.value.detail["step"] == "kerberos" and "was reset" not in e.value.detail["message"]
    assert "set_password" not in endpoint.calls and endpoint.cfg.keytab_ct == b"old"


def test_endpoint_keeps_the_new_key_when_a_later_step_fails(endpoint):
    """The password changed: the stored key must be the new one, with the unfinished step said."""
    endpoint.existing = acct()
    endpoint.kvno = [4]
    endpoint.cfg.keytab_ct = b"old"
    endpoint.fail["finish"] = account.AccountError("permission", "may not update easyeap-cep")
    with pytest.raises(HTTPException) as e:
        endpoint.call()
    assert e.value.status_code == 403 and "was changed and EasyEAP keeps the new key" in e.value.detail["message"]
    assert endpoint.cfg.keytab_ct.startswith(b"ct:") and endpoint.cfg.keytab_info["kvno"] == 5  # the old 4 + 1
    assert any("Not finished" in x for x in endpoint.cfg.keytab_info["problems"]) and endpoint.tested


def test_endpoint_half_made_account_says_so(endpoint):
    endpoint.fail["derive"] = account.AccountError("kerberos", "The domain controller doesn't know the account yet.")
    with pytest.raises(HTTPException) as e:
        endpoint.call()
    assert "was created in Active Directory, but then" in e.value.detail["message"] and endpoint.cfg.keytab_ct is None


def test_endpoint_finishes_a_disabled_account_first(endpoint):
    endpoint.existing = acct(uac=0x202)  # an earlier run stopped after the add: no KDC gives a disabled account's salt
    endpoint.call()
    assert endpoint.calls == ["lock", "kerberos_ready", "connect", "set_password", "finish", "key_version", "derive"]


def test_endpoint_refuses_unverified_tls_unless_confirmed(endpoint):
    endpoint.verified = False
    with pytest.raises(HTTPException) as e:
        endpoint.call()
    assert e.value.detail["step"] == "tls" and "connect" not in endpoint.calls
    endpoint.call(accept_unverified=True)
    assert endpoint.audits[0][1]["detail"]["unverified_tls"] is True


def test_endpoint_refuses_an_spn_another_account_holds(endpoint):
    endpoint.owners = [{"dn": "CN=web,CN=Users,DC=corp,DC=example", "sAMAccountName": ["websvc"], "guid": "1-2"}]
    with pytest.raises(HTTPException) as e:
        endpoint.call()
    assert e.value.status_code == 409 and e.value.detail["step"] == "spn" and "websvc" in e.value.detail["message"]
    assert endpoint.cfg.keytab_ct is None and endpoint.conn.unbound and "create" not in endpoint.calls


def test_endpoint_refuses_a_computer_with_that_name(endpoint):
    endpoint.owners = [{"dn": "CN=EASYEAP,CN=Computers,DC=corp,DC=example", "sAMAccountName": "EASYEAP$", "guid": "9",
                        "servicePrincipalName": ["HOST/easyeap.corp.example", "HOST/EASYEAP"]}]
    with pytest.raises(HTTPException) as e:
        endpoint.call()
    assert e.value.status_code == 409 and "A computer account (EASYEAP$)" in e.value.detail["message"]


def test_endpoint_compares_spn_owners_by_guid(endpoint):
    endpoint.existing = acct()
    endpoint.owners = [{"dn": acct()["dn"], "sAMAccountName": "easyeap-cep", "guid": GUID}]
    assert endpoint.call()["service_account"]["created"] is False
    # The same name in another domain of the forest is someone else's.
    endpoint.owners = [{"dn": "CN=easyeap-cep,CN=Users,DC=child,DC=corp,DC=example", "sAMAccountName": "easyeap-cep", "guid": "other"}]
    with pytest.raises(HTTPException) as e:
        endpoint.call()
    assert e.value.detail["step"] == "spn"


def test_endpoint_wont_take_over_a_squatted_account(endpoint):
    endpoint.existing = acct(owner="S-1-5-21-1-2-3-1105")
    with pytest.raises(HTTPException) as e:
        endpoint.call()
    assert e.value.status_code == 409 and "owned by" in e.value.detail["message"] and "set_password" not in endpoint.calls


def test_endpoint_container(endpoint):
    assert endpoint.call(container="OU=Service Accounts,DC=corp,DC=example")["service_account"]["dn"] == \
        "CN=easyeap-cep,OU=Service Accounts,DC=corp,DC=example"
    for bad, what in (("not a dn", "distinguished name"), ("OU=Svc,DC=other,DC=example", "must be inside")):
        with pytest.raises(HTTPException) as e:
            endpoint.call(container=bad)
        assert e.value.status_code == 409 and what in e.value.detail["message"]


def test_endpoint_permission_error_is_403(endpoint):
    endpoint.fail["create"] = account.AccountError("permission", "may not create users", "insufficientAccessRights")
    with pytest.raises(HTTPException) as e:
        endpoint.call()
    assert e.value.status_code == 403 and e.value.detail == {"step": "permission", "message": "may not create users",
                                                             "detail": "insufficientAccessRights"}


def test_endpoint_needs_a_dns_name(endpoint, monkeypatch):
    from app.routers import autoenroll as r
    monkeypatch.setattr(r, "console_host", lambda: "192.0.2.45")
    with pytest.raises(HTTPException) as e:
        endpoint.call()
    assert e.value.status_code == 400


def test_endpoint_realm_mismatch(endpoint, monkeypatch):
    from app.routers import autoenroll as r
    monkeypatch.setattr(r.account, "domain_info", lambda _c: {**INFO, "realm": "OTHER.EXAMPLE"})
    with pytest.raises(HTTPException) as e:
        endpoint.call()
    assert e.value.status_code == 400 and "OTHER.EXAMPLE" in e.value.detail["message"]


def test_endpoint_is_rate_limited(endpoint):
    for _ in range(5):
        endpoint.call()
    with pytest.raises(HTTPException) as e:
        endpoint.call()
    assert e.value.status_code == 429


def test_one_run_at_a_time():
    from app.routers import autoenroll as r

    class S:
        def execute(self, *_a):
            return SimpleNamespace(scalar=lambda: False)
    with pytest.raises(HTTPException) as e:
        r._lock_service_account(S(), uuid.uuid4())
    assert e.value.status_code == 409 and e.value.detail["step"] == "busy"


def test_password_is_not_in_the_model_repr():
    from app.routers.autoenroll import ServiceAccountIn
    assert "AdminPw1!" not in repr(ServiceAccountIn(username="a", password="AdminPw1!"))
