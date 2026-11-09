"""The Linux setup script (enrollment/linux_setup.py): quoting, the generated bash, the TLS pin, the wpa_supplicant
block handling, the renewal script run for real (bash, openssl, python3) against a local HTTPS server that checks the
signature like the API does, and the endpoints that serve and answer it. The setup itself was run on Ubuntu 22.04,
24.04 and 26.04, Ubuntu Server 24.04, Debian 13 and Fedora 43 against EasyEAP's RADIUS (docs/enrollment.md)."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import ssl
import subprocess
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.enrollment import linux_setup as ls
from app.enrollment import service as enr
from app.routers import enroll_public as ep

BASH = shutil.which("bash")
OPENSSL = shutil.which("openssl")
needs_tools = pytest.mark.skipif(not (BASH and OPENSSL), reason="needs bash and openssl")


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject: str, pub, ikey, issuer: str, *, days: int = 365, ca: bool = False, san: str | None = None) -> x509.Certificate:
    now = datetime.now(UTC)
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer)).public_key(pub)
         .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
    return b.sign(ikey, hashes.SHA256())


def _pem(c: x509.Certificate) -> str:
    return c.public_bytes(serialization.Encoding.PEM).decode()


CA_KEY = ec.generate_private_key(ec.SECP256R1())
CA = _cert("Test Root", CA_KEY.public_key(), CA_KEY, "Test Root", days=3650, ca=True)


def _script(**kw) -> str:
    base = dict(api_base="https://easyeap.example/", token="T" * 43, org="Corp", slug="corp", ssid="Corp Wi-Fi", server_name="radius.corp.example",
                identity="nina@corp.example", wpa3=False, wired=True, ca_chain_pem=_pem(CA), renew_days=30, pin="")
    return ls.setup_script(**{**base, **kw})


def _config(script: str) -> str:
    """The generated settings block (everything before the shared functions)."""
    return script.split("\nif [ -t 1 ]", 1)[0]


# ── Quoting and the generated file ──────────────────────────────────────────


@needs_tools
@pytest.mark.parametrize("value", ["plain", "O'Brien", 'say "hi" $HOME `id` $(id) \\ ;|&<>', "Café ☕", "-n", "a'b'c''"])
def test_shell_quoting_round_trips(value):
    out = subprocess.run([BASH, "-c", f"x={ls.shq(value)}; printf '%s' \"$x\""], capture_output=True, text=True, check=True).stdout
    assert out == value


def test_control_characters_are_dropped():
    assert ls.shq("a\nb\rc\x00d") == "'abcd'"


@pytest.mark.parametrize("ssid,name", [("Corp Wi-Fi", "Corp Wi-Fi"), ("corp_5G-x", "corp_5G-x"), ("Café", "=436166c3a9"),
                                       ("a/b", "=612f62"), ("it's", "=69742773")])
def test_iwd_file_names(ssid, name):
    assert ls.iwd_name(ssid) == name


@needs_tools
def test_the_script_is_valid_bash_and_carries_its_settings():
    nasty = "Eve's \"Net\" $(touch /tmp/pwned) `id`"
    text = _script(ssid=nasty, org="O'Brien & Co", identity="o'brien@corp.example")
    subprocess.run([BASH, "-n"], input=text, text=True, check=True)
    assert text.startswith("#!/usr/bin/env bash\n")
    # Run the settings block alone and read the values back.
    probe = _config(text) + '\nprintf "%s\\n" "$SSID" "$ORG" "$IDENTITY" "$SSID_HEX" "$IWD_NAME" "$WIRED" "$DIR"\nprintf "%s" "$CA_CHAIN"'
    out = subprocess.run([BASH], input=probe, capture_output=True, text=True, check=True, env={"PATH": os.environ["PATH"]}).stdout
    lines = out.split("\n")
    assert lines[:7] == [nasty, "O'Brien & Co", "o'brien@corp.example", nasty.encode().hex(), "=" + nasty.encode().hex(), "1", "/etc/easyeap/corp"]
    assert "\n".join(lines[7:]) == _pem(CA).strip()
    assert not Path("/tmp/pwned").exists()


def test_the_renewal_is_embedded_once_with_a_unique_end_marker():
    text = _script()
    assert text.count(f"<<'{ls._RENEW_EOF}'") == 1 and text.count(f"\n{ls._RENEW_EOF}\n") == 1
    assert "__EASYEAP_RENEW_HEREDOC__" not in text
    renew = text.split(f"<<'{ls._RENEW_EOF}'\n", 1)[1].split(f"\n{ls._RENEW_EOF}\n", 1)[0]
    assert renew.startswith("#!/usr/bin/env bash") and "TOKEN" not in renew  # the renewal never carries the link
    assert "/api/enroll/renew?format=pem" in renew


def test_what_the_setup_configures():
    text = _script(wpa3=True)
    # NetworkManager: system-wide, no key password to ask for, the server name pinned, the earlier profile replaced.
    assert "802-1x.private-key-password-flags 4" in text and '802-1x.domain-suffix-match "$SERVER"' in text
    assert "connection.permissions" not in text and "wifi-sec.pmf required" in text
    assert "802-1x.optional yes" in text  # wired: ports without 802.1X still work
    assert "Replaced the earlier settings for this network" in text
    # wpa_supplicant: SSID in hex, server name checked; iwd: ServerDomainMask; never netplan (no server-name check).
    assert "ssid=$SSID_HEX" in text and 'domain_suffix_match="$SERVER"' in text and "EAP-TLS-ServerDomainMask=$SERVER" in text
    assert "/etc/netplan/" in text and "> /etc/netplan" not in text and "netplan apply" not in text
    # wpa_supplicant values in hex (quotes and # can't break them); our network found again by id_str.
    assert "identity=$IDENTITY_HEX" in text and 'id_str="easyeap-$SLUG"' in text
    # Wired profiles the computer has keep their settings: 802.1X goes on a preferred copy.
    assert "nmcli connection clone uuid" in text and "802-1x.auth-timeout 15" in text
    # iwd signs only with RSA.
    assert "iwd) STACK_TEXT=\"iwd\"; KEYTYPE=rsa" in text


def test_the_link_is_never_on_a_command_line():
    """/proc/<pid>/cmdline is readable by every user: the URL with the token goes to curl on stdin, to python3 in its
    environment."""
    text = _script()
    assert "-K -" in text and "printf 'url = \"%s\"\\n' \"$url\" | curl" in text and "EASYEAP_URL=$url python3" in text
    assert '"$url" 2>' not in text and 'curl "${args[@]}" "$url"' not in text


def test_the_ca_file_lists_the_root_first():
    issuing_key = ec.generate_private_key(ec.SECP256R1())
    issuing = _cert("Test Issuing", issuing_key.public_key(), CA_KEY, "Test Root", ca=True)
    chain = ls.root_first(_pem(issuing) + _pem(CA))
    assert chain.index(_pem(CA).strip()) < chain.index(_pem(issuing).strip())
    assert ls.root_first(_pem(CA)) == _pem(CA)


@needs_tools
def test_the_wpa_supplicant_block_is_removed_even_without_its_comments(tmp_path):
    text = _script()
    fn = text[text.index("drop_block() {"):]
    fn = fn[:fn.index("\n}\n") + 3]
    conf = tmp_path / "wpa.conf"
    other = 'network={\n\tssid="Home"\n\tpsk="x"\n}\n'
    ours = 'network={\n\tssid=00\n\tid_str="easyeap-corp"\n}\n'
    probe = f"SLUG=corp\n{fn}\ndrop_block \"$1\"; echo \"rc=$?\"\n"
    run = lambda: subprocess.run([BASH, "-c", probe, "x", str(conf)], capture_output=True, text=True, check=True).stdout  # noqa: E731
    conf.write_text("ctrl_interface=/run/wpa_supplicant\n" + other + ours)  # rewritten by wpa_cli save_config: no comments
    assert run() == "rc=0\n" and conf.read_text() == "ctrl_interface=/run/wpa_supplicant\n" + other
    conf.write_text(other + "# BEGIN EasyEAP corp\n" + ours + "# END EasyEAP corp\n" + other)
    assert run() == "rc=0\n" and conf.read_text() == other + other
    assert run() == "rc=1\n" and conf.read_text() == other + other  # nothing of ours left: unchanged


def test_the_page_never_sees_the_key():
    text = _script()
    assert "-----BEGIN" not in text.replace("-----BEGIN CERTIFICATE-----", "") and "\"key_origin\":\"device\"" in text and "?format=pem" in text


def test_tls_pin(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _cert("easyeap.example", key.public_key(), key, "easyeap.example")
    f = tmp_path / "tls.crt"
    f.write_text(_pem(cert) + _pem(CA))
    der_spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert ls.tls_pin(f) == base64.b64encode(hashlib.sha256(der_spki).digest()).decode()
    assert ls.tls_pin(tmp_path / "missing.crt") == ""


# ── The renewal script, for real ────────────────────────────────────────────


class _Api:
    """HTTPS on 127.0.0.1 with a self-signed certificate: POST /api/enroll/renew checks the request the way
    enrollment/service.py renew() does. A check-in (no csr) gets the JSON answer with renew_from; a renewal
    (?format=pem) gets a certificate for the new key (or 204, or a refusal)."""

    def __init__(self, tmp: Path, *, renew: bool = True, lose: int = 0, renew_from: datetime | None = None, superseded: bool = False,
                 checkin: int = 200, refuse: str | None = None, enabled: bool = True):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cert = _cert("localhost", self.key.public_key(), self.key, "localhost", san="localhost")
        (tmp / "srv.pem").write_text(_pem(self.cert))
        (tmp / "srv.key").write_bytes(self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tmp / "srv.pem", tmp / "srv.key")
        api = self
        self.requests: list[dict] = []
        self.renew = renew
        self.lose = lose  # answer this many renewals with 502, as if the answer got lost
        self.renew_from = renew_from or datetime.now(UTC) - timedelta(days=1)  # due by default
        self.superseded, self.checkin, self.refuse, self.enabled = superseded, checkin, refuse, enabled

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                api.requests.append({"path": self.path, **body})
                old = x509.load_der_x509_certificate(base64.b64decode(body["certificate"]))
                der, client, sig = old.public_bytes(serialization.Encoding.DER), body.get("client"), base64.b64decode(body["signature"])
                if body.get("csr") is None:  # a v2 check-in
                    if api.checkin != 200:
                        return self._answer(api.checkin, b'{"detail":"nope"}', "application/json")
                    if client is None or not enr.verify_signature(old, enr.check_message(der, body["signed_at"], client), sig):
                        return self._answer(400, json.dumps({"detail": "The request isn't signed by this certificate's key."}).encode(), "application/json")
                    enr.parse_client(client)
                    answer = {"renewed": False, "not_after": old.not_valid_after_utc.isoformat(), "superseded": api.superseded,
                              # superseded: the moment it answers, as EasyEAP does (a second or two after the script's start)
                              "renew_from": (datetime.now(UTC) + timedelta(seconds=2) if api.superseded else api.renew_from).isoformat(),
                              "renewal_enabled": api.enabled,
                              "trust": {"roots": [{"sha256": "ab" * 32, "pem": _pem(CA)}], "cross": []}}
                    return self._answer(200, json.dumps(answer).encode(), "application/json")
                csr_pem = body["csr"].strip() + "\n"
                ok = enr.verify_signature(old, enr.renewal_message(der, body["signed_at"], enr._csr_der(csr_pem), client), sig)
                if not ok:
                    self._answer(400, json.dumps({"detail": "The request isn't signed by this certificate's key."}).encode(), "application/json")
                elif api.lose:
                    api.lose -= 1
                    self._answer(502, b"Bad Gateway", "text/plain")
                elif api.refuse:
                    detail = {"renewed": "This certificate was already renewed. Use the newer one.", "clock": "The request's time is off."}[api.refuse]
                    self._answer(400, json.dumps({"detail": detail, "code": api.refuse}).encode(), "application/json")
                elif not api.renew:
                    self._answer(204, b"", "text/plain")
                else:
                    csr = x509.load_pem_x509_csr(csr_pem.encode())
                    self._answer(200, _pem(_cert("nina", csr.public_key(), CA_KEY, "Test Root")).encode(), "application/x-pem-file")

            def _answer(self, code, data, ctype):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def checkins(self) -> list[dict]:
        return [r for r in self.requests if r.get("csr") is None]

    def renewals(self) -> list[dict]:
        return [r for r in self.requests if r.get("csr") is not None]

    def pin(self) -> str:
        der_spki = self.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return base64.b64encode(hashlib.sha256(der_spki).digest()).decode()


def _install(tmp: Path, *, days: int, key=None) -> tuple[Path, ec.EllipticCurvePrivateKey]:
    d = tmp / "corp"
    d.mkdir()
    (d / "ca.pem").write_text(_pem(CA))
    key = key or ec.generate_private_key(ec.SECP256R1())
    (d / "client.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (d / "client.pem").write_text(_pem(_cert("nina", key.public_key(), CA_KEY, "Test Root", days=days)))
    return d, key


def _run_renewal(tmp: Path, api: _Api, d: Path, *, pin: str | None = None) -> subprocess.CompletedProcess:
    script = tmp / "renew.sh"
    script.write_text(ls.renew_script(api_base=f"https://localhost:{api.port}", org="Corp", slug="corp", renew_days=30,
                                      pin=api.pin() if pin is None else pin))
    # python3 is EasyEAP's own; no curl on PATH, so the script's python3 client is the one under test.
    bin_dir = tmp / "bin"
    bin_dir.mkdir(exist_ok=True)
    for tool in ("openssl", "python3", "sed", "awk", "grep", "date", "mktemp", "rm", "cp", "mv", "chmod", "cat", "head", "tail", "tr", "cut"):
        p = shutil.which(tool)
        if p and not (bin_dir / tool).exists():
            (bin_dir / tool).symlink_to(p)
    env = {"PATH": str(bin_dir), "EASYEAP_DIR": str(d), "TMPDIR": str(tmp), "HOME": str(tmp)}
    return subprocess.run([BASH, str(script)], capture_output=True, text=True, env=env, timeout=60)


@needs_tools
def test_renewal_signs_like_the_api_expects_and_swaps_the_files(tmp_path):
    api = _Api(tmp_path)
    d, old_key = _install(tmp_path, days=10)  # inside the 30-day window
    r = _run_renewal(tmp_path, api, d)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "Renewed" in r.stdout and len(api.checkins()) == 1 and len(api.renewals()) == 1
    chk, req = api.requests
    assert chk["path"] == "/api/enroll/renew" and json.loads(chk["client"])["kind"] == "linux"
    root = hashlib.sha256(CA.public_bytes(serialization.Encoding.DER)).hexdigest()
    assert json.loads(chk["client"]) == {"kind": "linux", "version": "2.0", "scope": "computer", "roots": [root]}
    assert req["path"] == "/api/enroll/renew?format=pem" and req["key_storage"] == "software" and req["client"] == chk["client"]
    new_key = serialization.load_pem_private_key((d / "client.key").read_bytes(), None)
    new_cert = x509.load_pem_x509_certificate((d / "client.pem").read_bytes())
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    assert new_cert.public_key().public_bytes(serialization.Encoding.DER, pub) == new_key.public_key().public_bytes(serialization.Encoding.DER, pub)
    assert new_key.public_key().public_bytes(serialization.Encoding.DER, pub) != old_key.public_key().public_bytes(serialization.Encoding.DER, pub)
    assert isinstance(new_key, ec.EllipticCurvePrivateKey)  # same kind of key as before
    assert (d / "client.key").stat().st_mode & 0o777 == 0o600
    assert "Renewed" in (d / "renew.log").read_text()
    assert not list(d.glob("*.new")) and not list(d.glob("renew-pending.*"))


@needs_tools
def test_a_lost_renewal_answer_is_asked_for_again_with_the_same_key(tmp_path):
    api = _Api(tmp_path, lose=1)
    d, old_key = _install(tmp_path, days=10)
    r = _run_renewal(tmp_path, api, d)
    assert r.returncode == 1 and "asking again next time" in r.stdout
    assert (d / "renew-pending.key").stat().st_mode & 0o777 == 0o600
    old_pub = old_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert serialization.load_pem_private_key((d / "client.key").read_bytes(), None).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == old_pub  # nothing swapped
    r = _run_renewal(tmp_path, api, d)
    assert r.returncode == 0, r.stdout + r.stderr
    first, again = api.renewals()
    assert first["csr"] == again["csr"] and len(api.checkins()) == 1  # the same request again, without checking in first
    assert not list(d.glob("renew-pending.*"))


@needs_tools
def test_renewal_waits_for_its_window(tmp_path):
    """EasyEAP's renew_from decides, not the days the script was made with."""
    api = _Api(tmp_path, renew_from=datetime.now(UTC) + timedelta(days=3))
    d, _ = _install(tmp_path, days=10)  # inside the baked 30 days, but EasyEAP says not yet
    before = (d / "client.pem").read_text()
    r = _run_renewal(tmp_path, api, d)
    assert r.returncode == 0 and len(api.checkins()) == 1 and api.renewals() == [] and (d / "client.pem").read_text() == before
    api.renew_from = datetime.now(UTC) - timedelta(minutes=5)
    d2 = tmp_path / "corp"
    _run_renewal(tmp_path, api, d2)
    assert len(api.renewals()) == 1


@needs_tools
def test_renewal_keeps_the_files_when_the_server_says_not_yet(tmp_path):
    api = _Api(tmp_path, renew=False)
    d, _ = _install(tmp_path, days=10)
    before = (d / "client.key").read_bytes()
    r = _run_renewal(tmp_path, api, d)
    assert r.returncode == 0 and len(api.renewals()) == 1
    assert (d / "client.key").read_bytes() == before and "doesn't renew it yet" in (d / "renew.log").read_text()


@needs_tools
def test_renewal_refuses_a_server_it_wasnt_made_for(tmp_path):
    api = _Api(tmp_path)
    d, _ = _install(tmp_path, days=10)
    before = (d / "client.key").read_bytes()
    r = _run_renewal(tmp_path, api, d, pin="x" * 43 + "=")  # another server's pin: the self-signed certificate isn't accepted
    assert r.returncode == 1 and api.requests == []
    assert "Couldn't reach EasyEAP" in r.stdout and (d / "client.key").read_bytes() == before


@needs_tools
@pytest.mark.parametrize(("checkin", "days", "renews", "message"), [
    (502, 200, False, "Couldn't reach"),   # EasyEAP down, outside the baked period: wait
    (502, 10, True, None),                 # down, inside it: renew anyway (protocol 2)
    (422, 10, True, None),                 # an EasyEAP from before check-ins: protocol 1
])
def test_without_a_check_in_answer_the_baked_period_decides(tmp_path, checkin, days, renews, message):
    api = _Api(tmp_path, checkin=checkin)
    d, _ = _install(tmp_path, days=days)
    r = _run_renewal(tmp_path, api, d)
    assert r.returncode == 0, r.stdout + r.stderr
    assert bool(api.renewals()) == renews
    if renews:
        assert ("client" in api.renewals()[0]) == (checkin != 422)  # v1 for a server that doesn't know v2
    if message:
        assert message not in r.stdout  # 502 is an answer: the server is there, just failing; nothing to shout about


@needs_tools
def test_a_superseded_certificate_with_nothing_waiting_asks_again(tmp_path):
    """The renewal's answer and its key were both lost: EasyEAP replaces the unused certificate (cert-renewal.md §15c)."""
    api = _Api(tmp_path, superseded=True)
    d, _ = _install(tmp_path, days=200)
    r = _run_renewal(tmp_path, api, d)
    assert r.returncode == 0, r.stdout + r.stderr
    assert len(api.renewals()) == 1 and "never arrived here" in r.stdout and "Renewed" in r.stdout


@needs_tools
def test_a_final_refusal_drops_the_request_and_isnt_asked_again(tmp_path):
    api = _Api(tmp_path, refuse="renewed")
    d, _ = _install(tmp_path, days=10)
    r = _run_renewal(tmp_path, api, d)
    assert r.returncode == 1 and "Renewal refused: This certificate was already renewed" in r.stdout
    assert not list(d.glob("renew-pending.*")) and (d / "renew-refused").exists()
    r = _run_renewal(tmp_path, api, d)
    assert r.returncode == 1 and len(api.renewals()) == 1 and len(api.checkins()) == 2 and "won't renew" in r.stdout


@needs_tools
def test_a_refusal_that_isnt_final_keeps_the_request(tmp_path):
    """After a wrong clock, EasyEAP may have issued a certificate for that key already: it's sent again, not dropped."""
    api = _Api(tmp_path, refuse="clock")
    d, _ = _install(tmp_path, days=10)
    r = _run_renewal(tmp_path, api, d)
    assert r.returncode == 1 and (d / "renew-pending.key").exists() and not (d / "renew-refused").exists()
    api.refuse = None
    r = _run_renewal(tmp_path, api, d)
    assert r.returncode == 0, r.stdout + r.stderr
    first, second = api.renewals()
    assert first["csr"] == second["csr"] and len(api.checkins()) == 1  # sent again at once, no check-in first


@needs_tools
def test_renewal_turned_off_is_said_once_due(tmp_path):
    api = _Api(tmp_path, enabled=False)
    d, _ = _install(tmp_path, days=10)
    r = _run_renewal(tmp_path, api, d)
    assert r.returncode == 1 and api.renewals() == [] and "turned off" in r.stdout


@needs_tools
def test_a_refused_check_in_is_logged(tmp_path):
    api = _Api(tmp_path, checkin=400)
    d, _ = _install(tmp_path, days=10)
    r = _run_renewal(tmp_path, api, d)
    assert r.returncode == 1 and "Check-in refused: nope" in r.stdout and api.renewals() == []


# ── The endpoints ───────────────────────────────────────────────────────────


def _issuing() -> str:
    k = ec.generate_private_key(ec.SECP256R1())
    return _pem(_cert("Test Issuing", k.public_key(), CA_KEY, "Test Root", ca=True))


@pytest.fixture()
def link(monkeypatch):
    e = SimpleNamespace(method="link", template_id=None, status="pending")
    tenant = SimpleNamespace(id="t1", name="Corp", slug="corp")
    ident = SimpleNamespace(upn="nina@corp.example", username="nina", id="i1")
    issuing = _issuing()
    net = {"ssid": "Corp Wi-Fi"}
    monkeypatch.setattr(ep, "_load", lambda token, request, s, pending=False: (e, tenant, ident))
    monkeypatch.setattr(ep, "_net", lambda s, t: (net["ssid"], "radius.corp.example", False))
    monkeypatch.setattr(ep, "_wired", lambda s, t: True)
    monkeypatch.setattr(ep.pki, "chain_pem", lambda s, t: (issuing, _pem(CA)))
    monkeypatch.setattr(ep, "get_settings", lambda: SimpleNamespace(public_url="https://easyeap.example"))
    return SimpleNamespace(e=e, net=net, issuing=issuing, s=SimpleNamespace(get=lambda *a: None))


def test_the_script_endpoint(link):
    r = ep.linux_script("tok-123", None, link.s)
    assert r.media_type.startswith("text/x-shellscript") and r.headers["cache-control"] == "no-store"
    assert r.headers["content-disposition"] == f'attachment; filename="{ls.FILENAME}"'
    text = r.body.decode()
    assert "TOKEN='tok-123'" in text and "SSID='Corp Wi-Fi'" in text and "WIRED=1" in text and "RENEW_DAYS=30" in text
    assert text.index(_pem(CA).splitlines()[1]) < text.index(link.issuing.splitlines()[1])  # root first


def test_the_script_endpoint_refuses_what_it_cant_set_up(link):
    link.e.method = "server"
    with pytest.raises(ep.HTTPException) as exc:
        ep.linux_script("tok", None, link.s)
    assert exc.value.status_code == 400
    link.e.method, link.net["ssid"] = "link", ""
    with pytest.raises(ep.HTTPException) as exc:
        ep.linux_script("tok", None, link.s)
    assert exc.value.status_code == 409


def test_the_certificate_as_pem(link, monkeypatch):
    cert = SimpleNamespace(id="c1", certificate_pem=_pem(CA), common_name="nina", serial="01", key_origin="device", key_storage="software",
                           purpose="user", not_after=datetime.now(UTC))
    monkeypatch.setattr(ep.enr, "complete_with_csr", lambda *a, **kw: cert)
    monkeypatch.setattr(ep, "OpenBao", lambda: None)
    monkeypatch.setattr(ep, "client_ip", lambda r: "192.0.2.1")
    monkeypatch.setattr(ep.audit, "record", lambda *a, **kw: None)
    link.e.device_name, link.e.platform = "laptop", "linux"
    body = ep.CsrIn(csr="x" * 100, key_origin="device")
    r = ep.submit_csr("tok", body, None, link.s, format="pem")
    assert r.body.decode() == cert.certificate_pem and r.media_type == "application/x-pem-file"
    assert ep.submit_csr("tok", body, None, link.s)["certificate_pem"] == cert.certificate_pem  # JSON as before


def test_renewal_as_pem(monkeypatch):
    audits = []
    old = SimpleNamespace(id="c0", tenant_id="t1", common_name="nina", serial="00", renewed_at=None, template_id=None, status="active",
                          purpose="user", not_before=datetime.now(UTC) - timedelta(days=100), not_after=datetime.now(UTC))
    new = SimpleNamespace(id="c1", tenant_id="t1", certificate_pem=_pem(CA), common_name="nina", serial="01", key_storage="software",
                          purpose="user", not_after=datetime.now(UTC), renewer="linux", renewer_version="1")
    result = {"v": (old, None)}

    def renew(*a, **kw):
        if result["v"][1] is not None:
            new.issued_now = old.renewed_at is None  # what a real renewal says; a resend of a lost answer isn't new
            old.renewed_at = old.renewed_at or datetime.now(UTC)
        return result["v"]

    monkeypatch.setattr(ep.limiter, "hit", lambda *a: True)
    monkeypatch.setattr(ep, "set_platform", lambda s: None)
    monkeypatch.setattr(ep, "set_tenant", lambda s, t: None)
    monkeypatch.setattr(ep, "client_ip", lambda r: "192.0.2.1")
    monkeypatch.setattr(ep, "OpenBao", lambda: None)
    monkeypatch.setattr(ep.enr, "renew", renew)
    monkeypatch.setattr(ep.pki, "chain_pem", lambda s, t: ("", None))
    monkeypatch.setattr(ep.renewal, "settings", lambda s, t: SimpleNamespace(renew_at_percent=80, user_certs=True, machine_certs=True, server_cert=True))
    monkeypatch.setattr(ep, "trust_block", lambda s, t: {"roots": [], "cross": []})
    monkeypatch.setattr(ep.audit, "record", lambda *a, **kw: audits.append(a[2]))
    body = ep.RenewIn(certificate=base64.b64encode(b"c" * 100).decode(), csr="x" * 100, signed_at=0, signature=base64.b64encode(b"s" * 40).decode())
    s = SimpleNamespace(get=lambda *a: None)
    assert ep.renew(body, None, s, format="pem").status_code == 204
    assert ep.renew(body, None, s)["renewed"] is False  # JSON as before
    result["v"] = (old, new)
    r = ep.renew(body, None, s, format="pem")
    assert r.body.decode() == new.certificate_pem and audits == ["certificate.renewed"]
    assert ep.renew(body, None, s, format="pem").body.decode() == new.certificate_pem and audits == ["certificate.renewed"]
