"""Device administration over TACACS+ (docs/plans/device-admin.md): passwords and masking shared by the API and the
agent, the generated Cisco configuration, the wired configuration's interaction with it, and the TACACS+ service
itself (codec, decisions, throttles, and a real socket session driven by an IOS-like client). No database."""
import asyncio
import importlib.util
import json
import re
import socket
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pyotp
import pytest

from app.admin import cisco, mask, passwords
from app.radius import wired

ROOT = Path(__file__).resolve().parents[2]
AGENT = ROOT / "services" / "radius" / "agent"


def _load(path: Path, name: str):
    if not path.exists():
        pytest.skip(f"{path} not available in this checkout")
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def tac():
    return _load(AGENT / "tacacs.py", "da_tacacs")


@pytest.fixture(scope="module")
def client():
    return _load(ROOT / "tests" / "radius" / "tacacs_client.py", "da_tacacs_client")


@pytest.fixture(scope="module")
def agent():
    return _load(AGENT / "easyeap_agent.py", "da_agent")


# ── Passwords ────────────────────────────────────────────────────────────────


def test_scrypt_hash_verifies_in_the_api_and_the_agent(tac):
    h = passwords.hash_password("correct horse battery staple")
    assert h.startswith("scrypt$15$8$1$")
    assert passwords.verify(h, "correct horse battery staple") and not passwords.verify(h, "wrong")
    assert tac.scrypt_verify(h, "correct horse battery staple") and not tac.scrypt_verify(h, "Correct horse battery staple")
    for bad in (None, "", "bcrypt$x", "scrypt$99$8$1$aa$bb", "scrypt$15$8$1$!!$??"):
        assert not passwords.verify(bad, "x") and not tac.scrypt_verify(bad, "x")


def test_password_policy_is_length_not_composition():
    assert passwords.problems("a long passphrase here", username="bob") == []
    assert passwords.problems("short1!", totp=True)  # 7 < 8
    assert passwords.problems("eightchr", totp=True) == []
    assert "15" in " ".join(passwords.problems("only ten ch"))
    assert passwords.problems("Password12345678!"), "a common password with digits appended"
    assert passwords.problems("ciscociscocisco1")  # 'ciscociscocisco' isn't listed, but…
    assert passwords.problems("abcdefghijklmnop")
    assert passwords.problems("aaaaaaaaaaaaaaaa")
    assert passwords.problems("netadmin-alice-2026!", username="alice"), "contains the username"
    assert passwords.problems(" leading space password")
    assert passwords.problems("x" * 129)
    assert passwords.USERNAME.match("ops.alice-2") and not passwords.USERNAME.match("Alice") and not passwords.USERNAME.match("a b")


# ── Masking ──────────────────────────────────────────────────────────────────

MASK_CORPUS = [
    ("username bob privilege 15 secret 0 Hunter2Hunter2 <cr>", "username bob privilege 15 secret 0 ***** <cr>"),
    # IOS takes the rest of the line as the password, so `privilege 15` typed after it is part of it.
    ("username bob password 12345 privilege 15 <cr>", "username bob password ***** <cr>"),
    ("username bob password 0 correct horse battery <cr>", "username bob password 0 ***** <cr>"),
    ("snmp-server host 10.0.0.1 version 2c Comm2c <cr>", "snmp-server host 10.0.0.1 version 2c ***** <cr>"),
    ("snmp-server host 10.0.0.1 vrf MGMT informs version 2c Comm2c udp-port 162 <cr>",
     "snmp-server host 10.0.0.1 vrf MGMT informs version 2c ***** udp-port 162 <cr>"),
    ("snmp-server host 10.0.0.1 CommV1 <cr>", "snmp-server host 10.0.0.1 ***** <cr>"),
    ("snmp-server host 10.0.0.1 version 3 priv snmpuser <cr>", "snmp-server host 10.0.0.1 version 3 priv snmpuser <cr>"),
    ("snmp-server user u g v3 auth sha 12345678 priv aes 128 87654321 <cr>", "snmp-server user u g v3 auth sha ***** priv aes 128 ***** <cr>"),
    ("pre-shared-key local 0 IkeLocal <cr>", "pre-shared-key local 0 ***** <cr>"),
    ("pre-shared-key remote IkeRemote <cr>", "pre-shared-key remote ***** <cr>"),
    ("standby 1 authentication text HsrpPw <cr>", "standby 1 authentication text ***** <cr>"),
    ("vrrp 2 authentication text VrrpPw <cr>", "vrrp 2 authentication text ***** <cr>"),
    ("standby 1 authentication md5 key-string 7 0822455D0A16 <cr>", "standby 1 authentication md5 key-string 7 ***** <cr>"),
    ("area-password IsisArea <cr>", "area-password ***** <cr>"),
    ("domain-password IsisDomain <cr>", "domain-password ***** <cr>"),
    ("aaa authentication login default group EASYEAP-ADMIN local <cr>", "aaa authentication login default group EASYEAP-ADMIN local <cr>"),
    ("enable secret 9 $9$abc$def <cr>", "enable secret 9 ***** <cr>"),
    ("snmp-server community s3cr3t RO <cr>", "snmp-server community ***** RO <cr>"),
    ("snmp-server user u g v3 auth sha AUTHP priv aes 128 PRIVP <cr>", "snmp-server user u g v3 auth sha ***** priv aes 128 ***** <cr>"),
    ("snmp-server group g v3 priv read V <cr>", "snmp-server group g v3 priv read V <cr>"),
    (" key 0 TacacsKey123", "key 0 *****"),
    ("radius-server key 7 0822455D0A16 <cr>", "radius-server key 7 ***** <cr>"),
    ("client 10.0.0.5 server-key 0 CoAkey <cr>", "client 10.0.0.5 server-key 0 ***** <cr>"),
    ("ip ospf message-digest-key 1 md5 7 K1 <cr>", "ip ospf message-digest-key 1 md5 7 ***** <cr>"),
    ("ntp authentication-key 1 md5 K2 7 <cr>", "ntp authentication-key 1 md5 ***** 7 <cr>"),
    ("crypto isakmp key K6 address 0.0.0.0 <cr>", "crypto isakmp key ***** address 0.0.0.0 <cr>"),
    ("wpa-psk ascii 0 MyPsk <cr>", "wpa-psk ascii 0 ***** <cr>"),
    ("security wpa akm psk set-key ascii 0 K5 <cr>", "security wpa akm psk set-key ascii 0 ***** <cr>"),
    ("key config-key password-encrypt K3 <cr>", "key config-key password-encrypt ***** <cr>"),
    ("crypto key generate rsa modulus 2048 <cr>", "crypto key generate rsa modulus 2048 <cr>"),
    ("show running-config <cr>", "show running-config <cr>"),
    ("configure terminal <cr>", "configure terminal <cr>"),
    ("interface GigabitEthernet1/0/5 <cr>", "interface GigabitEthernet1/0/5 <cr>"),
    ("line vty 0 4 password 7 045802150C2E <cr>", "line vty 0 4 password 7 ***** <cr>"),
]


@pytest.mark.parametrize(("cmd", "want"), MASK_CORPUS)
def test_secrets_are_masked_in_commands(cmd, want):
    assert mask.mask_command(cmd) == want


def test_agent_masks_with_the_same_code():
    assert (AGENT / "tacmask.py").read_text() == (Path(__file__).resolve().parents[1] / "app" / "admin" / "mask.py").read_text(), \
        "services/radius/agent/tacmask.py must stay identical to backend/app/admin/mask.py"


# ── Device configuration ─────────────────────────────────────────────────────


def _ctx(**kw):
    c = SimpleNamespace(name="Floor 2", vendor=kw.pop("vendor", "cisco-switch"), wired_profile=kw.pop("profile", {}))
    return cisco.ctx_for(c, SimpleNamespace(slug="corp"), "10.9.9.9", **kw)


def test_cisco_config_keeps_local_fallback_and_never_holds_the_key():
    g = cisco.guide(_ctx())
    cfg = g["config"]
    assert "tacacs server EASYEAP-ADMIN-CORP\n address ipv4 10.9.9.9\n key 0 <tacacs-key>" in cfg
    assert "aaa authentication login default group EASYEAP-ADMIN local" in cfg
    assert "aaa authentication login EASYEAP-CONSOLE local" in cfg and "line con 0\n login authentication EASYEAP-CONSOLE" in cfg
    assert "aaa authorization exec default group EASYEAP-ADMIN local if-authenticated" in cfg
    assert "aaa authentication enable default group EASYEAP-ADMIN enable" in cfg
    assert "aaa accounting commands 15 default start-stop group EASYEAP-ADMIN" in cfg
    assert "aaa authorization commands" not in cfg, "no command authorization in v1 (it would block the paste itself)"
    assert "single-connection" not in cfg
    assert g["key_placeholder"] == cisco.KEY_PLACEHOLDER and g["verified"] is False
    assert "no tacacs server EASYEAP-ADMIN-CORP" in g["rollback"] and "aaa authentication login default local" in g["rollback"]
    assert any("reload in 15" in s for s in g["steps"]) and any("reload cancel" in s for s in g["steps"])
    assert any("privilege 15" in p["look_for"] for p in g["preflight"])


def test_cisco_config_variants():
    legacy = cisco.config(_ctx(legacy=True))
    assert "tacacs-server host 10.9.9.9 key 0 <tacacs-key>" in legacy and " server 10.9.9.9" in legacy and "tacacs server " not in legacy
    vrf = cisco.config(_ctx(profile={"source_interface": "Vlan10", "vrf": "Mgmt-vrf"}))
    assert " ip tacacs source-interface Vlan10" in vrf and " ip vrf forwarding Mgmt-vrf" in vrf
    c9800 = cisco.guide(_ctx(vendor="cisco-9800"))
    assert "ip http authentication aaa login-authentication default" in c9800["config"]
    assert "no ip http authentication aaa login-authentication" in c9800["rollback"]
    assert cisco.server_name(cisco.Ctx(tenant_slug="a-very-long-tenant-slug-name", server="x", name="n", vendor="cisco-switch")).__len__() <= 31
    assert set(cisco.NOT_SUPPORTED) == {"unifi", "cisco-aireos", "other"}


def test_wired_configuration_leaves_admin_login_lists_alone():
    settings = SimpleNamespace(dedicated_ports=False, auth_port=1812, acct_port=1813)
    plan = wired.validate_profile("cisco-switch", {"interfaces": "Gi1/0/1-24", "exclude": "Gi1/0/24"})
    tenant = SimpleNamespace(slug="corp", name="Corp")
    plain = wired.guide("cisco-switch", client=SimpleNamespace(name="sw", admin_enabled=False), profile=plan, settings=settings,
                        radius_ip="10.9.9.9", vlans=[], tenant=tenant)
    admin = wired.guide("cisco-switch", client=SimpleNamespace(name="sw", admin_enabled=True), profile=plan, settings=settings,
                        radius_ip="10.9.9.9", vlans=[], tenant=tenant)
    text = lambda g: json.dumps(g)  # noqa: E731
    assert "aaa authentication login default local" in text(plain)
    assert "aaa authentication login default local" not in text(admin) and "aaa authorization exec default local" not in text(admin)
    assert "Admin logins come from EasyEAP device administration" in text(admin)
    assert "aaa authentication dot1x default group EASYEAP" in text(admin)


# ── TACACS+ codec ────────────────────────────────────────────────────────────


def test_pad_is_its_own_inverse_and_depends_on_every_input(tac):
    h = tac.Header(0xC0, 1, 1, 0, 0x12345678, 0)
    body = bytes(range(200))
    enc = tac.crypt(h, b"key", body)
    assert enc != body and tac.crypt(h, b"key", enc) == body
    assert tac.crypt(h, b"other", enc) != body
    assert tac.pad(1, b"k", 0xC0, 1, 40) != tac.pad(1, b"k", 0xC0, 3, 40) != tac.pad(2, b"k", 0xC0, 1, 40)
    assert len(tac.pad(1, b"k", 0xC0, 1, 33)) == 33


def test_codec_reads_what_the_test_client_writes(tac, client):
    s = tac.parse_authen_start(client.start_body("alice", b"pw", atype=2, service=2, priv=15, port="tty3", rem="10.1.1.1"))
    assert (s.action, s.priv_lvl, s.authen_type, s.service, s.user, s.port, s.rem_addr, s.data) == (1, 15, 2, 2, "alice", "tty3", "10.1.1.1", b"pw")
    msg, data, flags = tac.parse_authen_continue(client.continue_body("secret", abort=True))
    assert (msg, data, flags) == ("secret", b"", 1)
    r = tac.parse_author_request(client.args_body("bob", ["service=shell", "cmd*"]))
    assert r.user == "bob" and r.args == ["service=shell", "cmd*"]
    a = tac.parse_acct_request(client.args_body("bob", ["task_id=7", "cmd=show version <cr>"], acct_flags=0x04))
    assert a.flags == 0x04 and tac.args_dict(a.args) == {"task_id": "7", "cmd": "show version <cr>"}
    assert tac.args_dict(["service=shell", "cmd=show", "cmd-arg=running-config", "cmd-arg=<cr>"])["cmd-arg"] == "running-config <cr>"
    assert client.authen_status(tac.authen_reply(5, "Password: ", flags=1)) == ("GETPASS", "Password: ")


@pytest.mark.parametrize("body", [b"", b"\x01\x01\x01\x01\x05\x00\x00\x00abc", b"\x01\x01\x01\x01\x00\x00\x00\x00extra",
                                  b"\x09\x01\x01\x01\x00\x00\x00\x00", b"\x01\x10\x01\x01\x00\x00\x00\x00"])
def test_malformed_start_is_refused(tac, body):
    with pytest.raises(tac.BadPacket):
        tac.parse_authen_start(body)


def test_random_bytes_never_crash_the_parsers(tac):
    import random
    rnd = random.Random(8907)  # noqa: S311 — reproducible fuzz input, not a secret
    for _ in range(3000):
        b = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 40)))
        for parse in (tac.parse_authen_start, tac.parse_authen_continue, tac.parse_author_request, tac.parse_acct_request):
            try:
                parse(b)
            except tac.BadPacket:
                pass


def test_totp_matches_pyotp_and_is_used_once(tac):
    secret = pyotp.random_base32()
    now = time.time()
    code = pyotp.TOTP(secret).at(now)
    ctr = tac.totp_counter(secret, code, now)
    assert ctr == int(now // 30)
    assert tac.totp_counter(secret, code, now, after=ctr) is None, "the same code can't be used twice"
    assert tac.totp_counter(secret, pyotp.TOTP(secret).at(now - 30), now) == ctr - 1, "one step of clock drift"
    assert tac.totp_counter(secret, pyotp.TOTP(secret).at(now - 90), now) is None
    assert tac.totp_counter(secret, "12345", now) is None and tac.totp_counter(secret, "abcdef", now) is None


def test_bind_cap_stays_below_the_lockout_threshold(tac):
    assert [tac.ad_bind_cap(t) for t in (None, 0, 1, 2, 3, 5, 10)] == [1, 5, 1, 1, 1, 2, 4], "unknown threshold: 1"


# ── Decisions ────────────────────────────────────────────────────────────────

T = "11111111-1111-1111-1111-111111111111"
SID_NET, SID_HELP = "S-1-5-21-1-2-3-1101", "S-1-5-21-1-2-3-1102"


def _data(**over):
    h = passwords.hash_password("a long passphrase here")
    users = [{"id": "u-ops", "username": "ops", "hash": h, "totp": None, "priv": 15, "role": "Network administrator", "sites": [],
              "enabled": True, "expires_at": None, "unlocked_at": None},
             {"id": "u-ro", "username": "viewer", "hash": h, "totp": None, "priv": 1, "role": "Read-only", "sites": ["hq"],
              "enabled": True, "expires_at": None, "unlocked_at": None},
             {"id": "u-off", "username": "gone", "hash": h, "totp": None, "priv": 15, "sites": [], "enabled": False, "expires_at": None},
             {"id": "u-old", "username": "temp", "hash": h, "totp": None, "priv": 15, "sites": [], "enabled": True, "expires_at": 1000},
             {"id": "u-nopw", "username": "nopw", "hash": None, "totp": None, "priv": 15, "sites": [], "enabled": True}]
    part = {"clients": [{"id": "sw1", "name": "Floor 2", "address": "127.0.0.0/8", "site": "HQ", "keys": ["k-current", "k-old"],
                         "prev_until": int(time.time()) + 3600}],
            "users": users,
            "maps": [{"sid": SID_HELP, "group": "Helpdesk", "priv": 1, "role": "Read-only", "sites": ["branch"]},
                     {"sid": SID_NET, "group": "NetAdmins", "priv": 15, "role": "Network administrator", "sites": []}],
            "candidates": [{"id": "i-alice", "guid": "g1", "username": "alice", "upn": "alice@lab.example", "sids": [SID_NET]},
                           {"id": "i-hd", "username": "helen", "upn": None, "sids": [SID_HELP]}],
            "directory": {"hosts": ["dc1"], "port": 636, "transport": "ldaps", "verify": True, "domain": "lab.example", "lockout_threshold": 5},
            "local_only": ["breakglass"], "role_cache_hours": 12}
    part.update(over)
    return {"tenants": {T: {"version": 3, "valid_until": int(time.time()) + 3 * 86400, "admin": part}}}


class FakeLdap:
    def __init__(self, password="ad password", sids=(SID_NET,), result=None):  # noqa: S107 — a test double
        self.password, self.sids, self.result, self.calls = password, list(sids), result, 0

    def __call__(self, d, c, password):
        self.calls += 1
        if self.result:
            return self.result
        if password != self.password:
            return "fail", "admin_bad_password", [], None
        return "pass", None, self.sids, None


def _decider(tac, data=None, ldap=None):
    store = tac.Store(Path("/nonexistent"))
    store.load(data or _data())
    return tac.Decider(store, b"test-secret", ldap_login=ldap or FakeLdap()), store.device_for("127.0.0.1")


def test_device_lookup_and_keys(tac):
    d, dev = _decider(tac)
    assert dev.name == "Floor 2" and dev.site == "hq"
    assert d.store.device_for("10.1.1.1") is None and d.store.device_for("::ffff:127.0.0.5").id == "sw1"
    assert d.store.keys_for(dev, time.time()) == [b"k-current", b"k-old"]
    assert d.store.keys_for(dev, time.time() + 7200) == [b"k-current"], "the previous key stops working after its grace period"


def test_local_accounts(tac):
    d, dev = _decider(tac)
    ok = d.login(dev, "ops", "a long passphrase here", "10.0.0.9")
    assert (ok.status, ok.priv, ok.source, ok.user_id, ok.username) == ("pass", 15, "local", "u-ops", "ops")
    assert d.login(dev, "OPS", "a long passphrase here", "10.0.0.9").status == "pass", "names are case-folded"
    assert d.login(dev, "LAB\\ops", "a long passphrase here", "10.0.0.9").status == "pass"
    assert (d.login(dev, "ops", "wrong", "10.0.0.8").reason, d.login(dev, "gone", "a long passphrase here", "10.0.0.9").reason) == \
        ("admin_bad_password", "admin_disabled")
    assert d.login(dev, "temp", "a long passphrase here", "10.0.0.9").reason == "admin_expired"
    assert d.login(dev, "nopw", "anything", "10.0.0.9").reason == "admin_bad_password"
    assert d.login(dev, "viewer", "a long passphrase here", "10.0.0.9").priv == 1, "site HQ matches case-insensitively"
    other = tac.Device(tenant=T, id="sw2", name="Branch", site="branch", keys=[b"k"], prev_until=None)
    assert d.login(other, "viewer", "a long passphrase here", "10.0.0.9").reason == "admin_wrong_site"


def test_fail_and_error_are_kept_apart(tac):
    d, dev = _decider(tac)
    unknown = d.login(dev, "mallory", "x", "10.0.0.9")
    assert (unknown.status, unknown.reason) == ("fail", "admin_unknown_user")
    assert unknown.username.startswith("unknown:") and "mallory" not in unknown.username, "names typed at Username: aren't logged"
    lo = d.login(dev, "breakglass", "x", "10.0.0.9")
    assert (lo.status, lo.reason) == ("error", "admin_local_only"), "local-only names fall back to the device's account"
    assert d.login(dev, "$enab15$", "x", "10.0.0.9").status == "error"
    stale = _data()
    stale["tenants"][T]["valid_until"] = int(time.time()) - 1
    d2, dev2 = _decider(tac, stale)
    assert (d2.login(dev2, "ops", "a long passphrase here", "10.0.0.9").status, d2.authorize(dev2, "ops").status) == ("error", "error")
    down = FakeLdap(result=("error", "admin_directory_down", [], "timed out"))
    d3, dev3 = _decider(tac, ldap=down)
    assert d3.login(dev3, "alice", "ad password", "10.0.0.9").status == "error", "DCs down: ERROR, so the device uses its local account"


def test_enable_needs_the_level(tac):
    d, dev = _decider(tac)
    assert d.login(dev, "ops", "a long passphrase here", "10.0.0.9", enable_priv=15).status == "pass"
    hi = d.login(dev, "viewer", "a long passphrase here", "10.0.0.9", enable_priv=15)
    assert (hi.status, hi.reason) == ("fail", "admin_priv_too_high")


def test_totp_accounts(tac):
    secret = pyotp.random_base32()
    data = _data()
    data["tenants"][T]["admin"]["users"][0]["totp"] = secret
    d, dev = _decider(tac, data)
    code = pyotp.TOTP(secret).now()
    assert d.login(dev, "ops", "a long passphrase here" + code, "10.0.0.9").status == "pass"
    again = d.login(dev, "ops", "a long passphrase here" + code, "10.0.0.7")
    assert (again.status, again.reason) == ("fail", "admin_bad_code"), "a code is used once"
    assert d.login(dev, "ops", "a long passphrase here", "10.0.0.6").reason == "admin_bad_password"
    assert d.login(dev, "ops", "a long passphrase here" + code, "10.0.0.9", enable_priv=15).status == "pass", \
        "enable straight after the login may use the same code (once)"
    assert d.login(dev, "ops", "a long passphrase here" + code, "10.0.0.9", enable_priv=15).reason == "admin_bad_code"


def test_totp_code_is_used_once_under_concurrency(tac):
    """Check and use are one step: of many logins with the same code at once, one passes."""
    secret = pyotp.random_base32()
    data = _data()
    data["tenants"][T]["admin"]["users"][0]["totp"] = secret
    d, dev = _decider(tac, data)
    code, results = pyotp.TOTP(secret).now(), []
    threads = [threading.Thread(target=lambda i=i: results.append(d.login(dev, "ops", "a long passphrase here" + code, f"10.0.6.{i}").status))
               for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == ["fail"] * 5 + ["pass"]


def test_local_lockout_and_unlock(tac):
    d, dev = _decider(tac)
    now = time.time()
    reasons = [d.login(dev, "ops", "wrong", f"10.0.1.{i}", now=now + i).reason for i in range(10)]
    assert reasons[-1] == "admin_lockout" and set(reasons[:-1]) == {"admin_bad_password"}
    assert d.login(dev, "ops", "a long passphrase here", "10.0.2.1", now=now + 20).reason == "admin_locked"
    assert d.login(dev, "ops", "a long passphrase here", "10.0.2.1", now=now + 9 + 901).status == "pass", "a lock lasts 15 minutes"
    for i in range(10):
        d.login(dev, "ops", "wrong", f"10.0.3.{i}", now=now + 1000 + i)
    data = _data()
    data["tenants"][T]["admin"]["users"][0]["unlocked_at"] = int(now + 1015)
    d.store.load(data)
    assert d.login(dev, "ops", "a long passphrase here", "10.0.4.1", now=now + 1016).status == "pass", "Unlock in the console clears it"


def test_backoff_per_source(tac):
    d, dev = _decider(tac)
    now = time.time()
    for i in range(3):
        d.login(dev, "ops", "wrong", "10.0.0.9", now=now + i)
    assert d.login(dev, "ops", "a long passphrase here", "10.0.0.9", now=now + 2.5).reason == "admin_throttled"
    assert d.login(dev, "ops", "a long passphrase here", "10.0.0.10", now=now + 2.5).status == "pass", "another source isn't held back"
    assert d.login(dev, "ops", "a long passphrase here", "10.0.0.9", now=now + 4).status == "pass"


def test_directory_logins(tac):
    ldap = FakeLdap()
    d, dev = _decider(tac, ldap=ldap)
    for typed in ("alice", "ALICE@lab.example", "LAB\\alice"):
        o = d.login(dev, typed, "ad password", f"10.0.0.{len(typed)}")
        assert (o.status, o.priv, o.source, o.user_id, o.username) == ("pass", 15, "directory", "i-alice", "alice"), typed
    assert d.login(dev, "alice@other.example", "ad password", "10.0.0.9").reason == "admin_unknown_user"
    assert d.login(dev, "alice", "", "10.0.0.9").reason == "admin_bad_password" and ldap.calls == 3, "no bind with an empty password"
    # helen's group only maps at site "branch": refused at HQ
    hd = _decider(tac, ldap=FakeLdap(sids=(SID_HELP,)))
    assert hd[0].login(hd[1], "helen", "ad password", "10.0.0.9").reason == "admin_not_permitted"
    gone = _decider(tac, ldap=FakeLdap(sids=("S-1-5-21-9",)))
    assert gone[0].login(gone[1], "alice", "ad password", "10.0.0.9").reason == "admin_not_permitted", "live groups decide, not the synced ones"


def test_directory_binds_are_capped_and_repeats_not_rebound(tac):
    ldap = FakeLdap()
    d, dev = _decider(tac, ldap=ldap)
    now = time.time()
    assert d.login(dev, "alice", "typo-1", "10.0.0.1", now=now).reason == "admin_bad_password"
    assert d.login(dev, "alice", "typo-1", "10.0.0.2", now=now + 1).reason == "admin_bad_password" and ldap.calls == 1, \
        "the same wrong password isn't sent to AD again"
    d.login(dev, "alice", "typo-2", "10.0.0.3", now=now + 2)
    assert ldap.calls == 2
    # lockout threshold 5 → at most 2 failed binds per 30 minutes
    capped = d.login(dev, "alice", "ad password", "10.0.0.4", now=now + 3)
    assert (capped.reason, ldap.calls) == ("admin_throttled", 2)
    assert d.login(dev, "alice", "ad password", "10.0.0.4", now=now + 1801).status == "pass"


def test_bind_cap_follows_the_domain_policy(tac):
    now = time.time()
    # lockout window 1 hour: failures count for the hour, not 30 minutes
    data = _data()
    data["tenants"][T]["admin"]["directory"]["lockout_window"] = 3600
    d, dev = _decider(tac, data, ldap=FakeLdap())
    d.login(dev, "alice", "typo-1", "10.0.0.1", now=now)
    d.login(dev, "alice", "typo-2", "10.0.0.2", now=now + 1)
    assert d.login(dev, "alice", "ad password", "10.0.0.3", now=now + 1900).reason == "admin_throttled"
    assert d.login(dev, "alice", "ad password", "10.0.0.3", now=now + 3602).status == "pass"
    # threshold not read yet: one failed bind, then refused; successful binds aren't counted
    data = _data()
    data["tenants"][T]["admin"]["directory"]["lockout_threshold"] = None
    ldap = FakeLdap()
    d, dev = _decider(tac, data, ldap=ldap)
    assert all(d.login(dev, "alice", "ad password", f"10.0.1.{i}", now=now + i).status == "pass" for i in range(5))
    assert d.login(dev, "alice", "typo", "10.0.0.1", now=now + 10).reason == "admin_bad_password"
    assert d.login(dev, "alice", "ad password", "10.0.0.2", now=now + 11).reason == "admin_throttled" and ldap.calls == 6


def test_binds_in_flight_hold_their_place_under_the_cap(tac):
    """Concurrent logins can't all pass the cap check and then all fail on the password."""
    d, dev = _decider(tac, ldap=FakeLdap())  # threshold 5 → cap 2
    now = time.time()
    p = [d.begin(dev, "alice", f"guess-{i}", f"10.0.0.{i}", now=now) for i in range(3)]
    assert all(isinstance(x, tac.PendingBind) for x in p)
    assert d.reserve(p[0]) is None and d.reserve(p[1]) is None
    assert d.reserve(p[2]) is tac.BUSY, "two binds in flight fill the cap of 2: the third waits"
    assert d.complete(p[0], d.bind(p[0])).reason == "admin_bad_password"
    assert d.reserve(p[2]) is tac.BUSY, "one failure and one in flight"
    d.release(p[1])  # e.g. its bind ended without a password failure
    assert d.reserve(p[2]) is None
    assert d.complete(p[2], d.bind(p[2])).reason == "admin_bad_password"
    late = d.begin(dev, "alice", "ad password", "10.0.0.9", now=now + 1)
    assert d.reserve(late).reason == "admin_throttled", "two failures: refused without a bind"


def test_unusable_directory_is_an_error_not_a_denial(tac):
    d, dev = _decider(tac, _data(directory={"usable": False, "domain": "lab.example"}), ldap=FakeLdap())
    o = d.login(dev, "alice", "ad password", "10.0.0.9")
    assert (o.status, o.reason, o.username) == ("error", "admin_directory_unusable", "alice"), "the device's own accounts decide"
    assert d.login(dev, "alice@lab.example", "ad password", "10.0.0.9").reason == "admin_directory_unusable"


def test_authorization_needs_a_login_through_easyeap(tac):
    d, dev = _decider(tac, ldap=FakeLdap())
    no = d.authorize(dev, "ops")
    assert (no.status, no.reason, no.username) == ("error", "admin_not_easyeap_login", "ops"), \
        "a session EasyEAP didn't authenticate (the switch's local account): ERROR, the switch's own list decides"
    unknown = d.authorize(dev, "mallory")
    assert (unknown.status, unknown.reason) == ("error", "admin_not_easyeap_login") and unknown.username.startswith("unknown:")
    assert d.authorize(dev, "breakglass").reason == "admin_local_only"
    d.login(dev, "ops", "a long passphrase here", "10.0.0.9")
    assert (d.authorize(dev, "ops").status, d.authorize(dev, "ops").priv) == ("pass", 15)
    assert d.authorize(dev, "ops", authen_method=0x00).priv == 15, "authen_method not set"
    assert d.authorize(dev, "ops", authen_method=0x05).reason == "admin_not_easyeap_login", "authenticated by the switch's local accounts"
    other = tac.Device(tenant=T, id="sw2", name="Branch", site="branch", keys=[b"k"], prev_until=None)
    assert d.authorize(other, "ops").reason == "admin_not_easyeap_login", "a login to another device doesn't count"
    assert d.authorize(dev, "ops", now=time.time() + 13 * 3600).reason == "admin_not_easyeap_login", "remembered for 12 hours"
    # the role is worked out again from the current data
    d.login(dev, "alice", "ad password", "10.0.0.9")
    assert d.authorize(dev, "alice").priv == 15
    data = _data()
    data["tenants"][T]["admin"]["users"][0]["enabled"] = False
    data["tenants"][T]["admin"]["maps"] = data["tenants"][T]["admin"]["maps"][:1]  # NetAdmins mapping removed
    d.store.load(data)
    assert d.authorize(dev, "ops").reason == "admin_disabled", "disabled since the login"
    assert d.authorize(dev, "alice").reason == "admin_not_permitted", "the mapping that admitted her was removed"
    # the groups are the ones the domain controller gave at login, not the last sync's
    d2, dev2 = _decider(tac, ldap=FakeLdap(sids=(SID_NET,)))
    data = _data()
    data["tenants"][T]["admin"]["candidates"][0]["sids"] = []
    d2.store.load(data)
    d2.login(dev2, "alice", "ad password", "10.0.0.9")
    assert d2.authorize(dev2, "alice").priv == 15


def test_error_paths_never_log_the_typed_name(tac):
    stale = _data()
    stale["tenants"][T]["valid_until"] = int(time.time()) - 1
    d, dev = _decider(tac, stale)
    typed = "Hunter2Hunter2"  # a password typed at the Username: prompt
    for o in (d.login(dev, typed, "x", "10.0.0.9"), d.authorize(dev, typed)):
        assert o.status == "error" and o.username.startswith("unknown:") and typed.lower() not in o.username
    assert d.login(dev, "ops", "x", "10.0.0.9").username == "ops", "a known account is named"


# ── A real session over a socket ─────────────────────────────────────────────


@pytest.fixture()
def server(tac, tmp_path, monkeypatch):
    monkeypatch.setattr(tac, "FAIL_DELAY", 0.05)
    secret = pyotp.random_base32()
    data = _data()
    admin_file = tmp_path / "admin.json"
    admin_file.write_text(json.dumps(data))
    store = tac.Store(admin_file)
    spool = tac.Spool(tmp_path / "spool")
    srv = tac.Server(store, tac.Decider(store, b"s", ldap_login=FakeLdap()), spool)
    loop = asyncio.new_event_loop()
    ready = threading.Event()
    holder = {}

    async def main():
        holder["srv"] = await asyncio.start_server(srv.handle, host="127.0.0.1", port=0)
        ready.set()
        await holder["srv"].serve_forever()

    def run():
        try:
            loop.run_until_complete(main())
        except (asyncio.CancelledError, RuntimeError):
            pass

    threading.Thread(target=run, daemon=True).start()
    assert ready.wait(5)
    port = holder["srv"].sockets[0].getsockname()[1]

    def events():
        out = []
        for f in sorted((tmp_path / "spool").glob("admin-*.jsonl")):
            out += [json.loads(x) for x in f.read_text().splitlines()]
        return out

    yield SimpleNamespace(port=port, events=events, secret=secret, file=admin_file, srv=srv)
    loop.call_soon_threadsafe(holder["srv"].close)


def _c(client, server, key="k-current"):
    return client.Client("127.0.0.1", server.port, key, timeout=5)


def test_ios_like_sessions(client, server):
    c = _c(client, server)
    assert client.login(c, "ops", "a long passphrase here") == ["GETPASS", "PASS"]
    c = _c(client, server)
    assert client.login(c, "ops", "a long passphrase here", telnet=True) == ["GETUSER", "GETPASS", "PASS"], "telnet: no name in START"
    c = _c(client, server)
    assert client.login(c, "ops", "nope") == ["GETPASS", "FAIL"]
    c = _c(client, server, key="k-old")
    assert client.login(c, "ops", "a long passphrase here") == ["GETPASS", "PASS"], "the previous key during its grace period"
    c = _c(client, server, key="wrong-key")
    client.login(c, "ops", "a long passphrase here")  # answered ERROR under EasyEAP's key, which this client can't read
    c = _c(client, server)
    assert client.login(c, "breakglass", "x") == ["GETPASS", "ERROR"]
    c = _c(client, server)
    assert client.login(c, "viewer", "a long passphrase here", service=2, priv=15) == ["GETPASS", "FAIL"], "enable above the role's level"
    ev = server.events()
    kinds = [(e["kind"], e["result"], e.get("reason")) for e in ev]
    assert ("login", "pass", None) in kinds and ("login", "fail", "admin_bad_password") in kinds and ("login", "error", "admin_bad_key") in kinds
    assert ("enable", "fail", "admin_priv_too_high") in kinds
    assert all(e["tenant"] == T and e["client_id"] == "sw1" for e in ev)


def test_pap_chap_abort_plain(client, server):
    def one(fn):
        c = _c(client, server)
        try:
            return fn(c)
        finally:
            c.close()

    def pap(c, pw):
        c.send(client.AUTHEN, client.start_body("ops", pw.encode(), atype=2), minor=1)
        return client.authen_status(c.recv())[0]

    assert one(lambda c: pap(c, "a long passphrase here")) == "PASS"
    assert one(lambda c: pap(c, "bad")) == "FAIL"

    def chap(c):
        c.send(client.AUTHEN, client.start_body("ops", b"x" * 17, atype=3), minor=1)
        return client.authen_status(c.recv())

    st, msg = one(chap)
    assert st == "FAIL" and "ASCII or PAP" in msg

    def wrong_minor(c):
        c.send(client.AUTHEN, client.start_body("ops", b"pw", atype=2), minor=0)
        return client.authen_status(c.recv())[0]

    assert one(wrong_minor) == "ERROR"

    def abort(c):
        c.send(client.AUTHEN, client.start_body("ops"))
        c.recv()
        c.send(client.AUTHEN, client.continue_body("bye", abort=True))
        return c.recv()

    assert one(abort) is None, "no reply to ABORT"

    def plain(c):
        c.send(client.AUTHEN, client.start_body("ops"), flags=0x01)
        return c.recv()

    assert one(plain) is None, "unobfuscated packets are dropped"


def test_authorization_and_accounting(client, server):
    def author(user, args):
        c = _c(client, server)
        c.send(client.AUTHOR, client.args_body(user, args))
        r = c.recv()
        c.close()
        import struct
        st, n, ml, dl = struct.unpack("!BBHH", r[:6])
        lens, pos, pairs = list(r[6:6 + n]), 6 + n + ml + dl, []
        for ln in lens:
            pairs.append(r[pos:pos + ln].decode())
            pos += ln
        return client.AUTHOR_STATUS[st], pairs

    assert author("ops", ["service=shell", "cmd*"])[0] == "ERROR", "no login through EasyEAP yet"
    for user in ("ops", "viewer"):
        assert client.login(_c(client, server), user, "a long passphrase here") == ["GETPASS", "PASS"]
    assert author("ops", ["service=shell", "cmd*"]) == ("PASS_ADD", ["priv-lvl=15"])
    assert author("viewer", ["service=shell", "cmd*"]) == ("PASS_ADD", ["priv-lvl=1"])
    c = _c(client, server)
    c.send(client.AUTHOR, client.args_body("ops", ["service=shell", "cmd*"], method=5))
    assert client.AUTHOR_STATUS[c.recv()[0]] == "ERROR", "the device authenticated the session itself"
    c.close()
    assert author("mallory", ["service=shell", "cmd*"])[0] == "ERROR"
    assert author("breakglass", ["service=shell", "cmd*"])[0] == "ERROR"
    assert author("ops", ["service=ppp", "protocol=ip"])[0] == "FAIL"
    assert author("viewer", ["service=shell", "cmd=configure", "cmd-arg=terminal", "cmd-arg=<cr>"])[0] == "FAIL"
    assert author("ops", ["service=shell", "cmd=configure", "cmd-arg=terminal", "cmd-arg=<cr>"])[0] == "PASS_ADD"

    def acct(flags, args):
        c = _c(client, server)
        c.send(client.ACCT, client.args_body("ops", args, acct_flags=flags))
        r = c.recv()
        c.close()
        return client.ACCT_STATUS[r[4]]

    assert acct(0x02, ["task_id=9", "service=shell"]) == "SUCCESS"
    assert acct(0x04, ["task_id=10", "service=shell", "priv-lvl=15", "cmd=username bob secret 0 Hunter2Hunter2 <cr>"]) == "SUCCESS"
    assert acct(0x06, ["task_id=11"]) == "ERROR", "START and STOP together is invalid"
    ev = server.events()
    cmd = [e for e in ev if e["kind"] == "command"]
    assert cmd and cmd[-1]["command"] == "username bob secret 0 ***** <cr>" and cmd[-1]["task_id"] == "10"
    assert any(e["kind"] == "session" and e["result"] == "start" and e["username"] == "ops" for e in ev)
    assert "Hunter2" not in json.dumps(ev)


def test_slow_domain_controllers_dont_hold_up_other_logins(tac, client, server, monkeypatch):
    monkeypatch.setattr(tac, "LDAP_BUDGET", -1.0)  # a login deadline of 1 second
    gate = threading.Event()

    class Slow(FakeLdap):
        def __call__(self, d, c, password):
            gate.wait(10)
            return super().__call__(d, c, password)

    server.srv.decider.ldap_login = Slow()
    results = []
    threads = [threading.Thread(target=lambda i=i: results.append(client.login(_c(client, server), "alice", "ad password", rem=f"10.0.5.{i}")))
               for i in range(3)]
    for t in threads:
        t.start()
    time.sleep(0.2)
    t0 = time.monotonic()
    assert client.login(_c(client, server), "ops", "a long passphrase here") == ["GETPASS", "PASS"]
    assert time.monotonic() - t0 < 0.8, "a local login doesn't wait for the domain controllers"
    for t in threads:
        t.join(5)
    assert results == [["GETPASS", "ERROR"]] * 3, "too slow: ERROR, so the device uses its own accounts"
    reasons = sorted(e["reason"] for e in server.events() if e["kind"] == "login" and e.get("username") == "alice")
    assert reasons == ["admin_directory_busy", "admin_directory_timeout", "admin_directory_timeout"], \
        "two binds at once per tenant; the third waited for a place and gave up"
    gate.set()
    time.sleep(0.3)
    monkeypatch.setattr(tac, "LDAP_BUDGET", 3.0)
    assert client.login(_c(client, server), "alice", "ad password") == ["GETPASS", "PASS"], "finished binds give their places back"


def test_unregistered_addresses_get_nothing(tac, server):
    data = _data(clients=[{"id": "x", "name": "x", "address": "10.99.0.0/16", "site": "", "keys": ["k"], "prev_until": None}])
    server.file.write_text(json.dumps(data))
    time.sleep(0.01)
    s = socket.create_connection(("127.0.0.1", server.port), timeout=5)
    s.settimeout(3)
    assert s.recv(10) == b"", "the connection is closed without a byte"
    s.close()


# ── The agent's side ─────────────────────────────────────────────────────────


def test_agent_admin_store(agent, tmp_path):
    state = {"tenants": {}}
    snap = {"tenant_id": T, "admin_version": 4, "admin_valid_until": 1_000_000, "admin": {"clients": [{"id": "a"}], "users": []}}
    assert agent.apply_admin(state, snap) and agent.admin_versions(state) == {T: 4} and agent.admin_devices(state) == 1
    assert not agent.apply_admin(state, {"tenant_id": T, "admin_version": 4, "admin_valid_until": 1_000_100}), "a small extension isn't rewritten"
    assert agent.apply_admin(state, {"tenant_id": T, "admin_version": 4, "admin_valid_until": 1_000_400})
    assert state["tenants"][T]["valid_until"] == 1_000_400
    assert not agent.apply_admin(state, {"tenant_id": T, "version": 9}), "an API without device admin: nothing"
    path = tmp_path / "admin.json"
    agent.write_admin(state, path)
    assert oct(path.stat().st_mode & 0o777) == "0o600" and agent.load_admin(path) == state
    assert agent.load_admin(tmp_path / "missing.json") == {"tenants": {}}
    assert "tacacs" in agent.FEATURES
    item = {"uid": "u1", "ts": 1.0, "tenant": T, "kind": "login", "result": "pass", "username": "ops", "extra": "dropped"}
    out = agent.transform("admin-events", item)
    assert out["uid"] == "u1" and out["username"] == "ops" and "extra" not in out
    assert agent._CHILD_LINE.match("2026-11-07 10:00:00,000 tacacs WARNING Too many connections").group(1) == "WARNING"


def test_admin_reasons_labelled_in_console():
    """Every reason code the TACACS+ service logs has a label in the console's Admin log."""
    root = Path(__file__).resolve().parents[2]
    agent = root / "services" / "radius" / "agent" / "tacacs.py"
    ts = root / "frontend" / "src" / "app" / "api" / "deviceAdmin.ts"
    if not (agent.exists() and ts.exists()):
        pytest.skip("services/ and frontend/ aren't mounted")
    codes = set(re.findall(r'"(admin_[a-z_]+)"', agent.read_text()))
    assert len(codes) > 15
    text = ts.read_text()
    missing = sorted(c for c in codes if f"  {c}:" not in text)
    assert not missing, f"no console label for {missing}"


# ── Who may change a device administrators log in to ─────────────────────────


def test_radius_write_alone_cant_move_or_delete_an_admin_device():
    """A Wi-Fi administrator (radius:write) manages RADIUS clients, but the address and site of a device with admin
    logins decide who gets privileged access to it: those changes, and deleting it, need admin:write."""
    import uuid

    from fastapi import HTTPException

    from app.routers import radius as r

    tid = uuid.uuid4()
    dev = SimpleNamespace(id=uuid.uuid4(), tenant_id=tid, admin_enabled=True, address="10.0.0.5", vendor="cisco-switch", site="hq",
                          networks=["wired"], wired_profile={"mode": "monitor"}, name="sw1")
    ctx = SimpleNamespace(session=SimpleNamespace(get=lambda _model, _id: dev), id=tid, perms={"radius:write", "radius:read"}, actor=None)
    for change in ({"address": "10.0.0.6"}, {"site": "branch"}, {"vendor": "other"}):
        with pytest.raises(HTTPException) as e:
            r.update_client(dev.id, r.ClientUpdate(**change), ctx)
        assert e.value.status_code == 403, change
    with pytest.raises(HTTPException) as e:
        r.delete_client(dev.id, ctx)
    assert e.value.status_code == 403
    assert r._same_address(" 10.0.0.5 ", "10.0.0.5") and r._same_address("10.0.0.0/24", "10.0.0.0/24")
    assert not r._same_address("10.0.0.6", "10.0.0.5") and not r._same_address("nonsense", "10.0.0.5")


def test_console_bind_cap_matches_the_agent(tac):
    from app.admin import service

    assert all(service.ad_bind_cap(t) == tac.ad_bind_cap(t) for t in (None, -1, 0, 1, 2, 3, 4, 5, 6, 10, 50))
