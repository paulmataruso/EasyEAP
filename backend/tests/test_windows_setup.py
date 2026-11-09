"""The Windows 11 setup (docs/plans/windows-setup.md): the generated file, the profiles' sign-in modes and issuer filter,
renewal signatures, and every renewal rule (no database: a small fake session). tests/windows/run.sh parses the
generated files with PowerShell and checks signatures made by the script's own PowerShell code; tests/e2e/run.sh runs
the whole flow against the real API, OpenBao and FreeRADIUS."""
from __future__ import annotations

import base64
import json
import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from app.enrollment import profiles
from app.enrollment import service as enr
from app.enrollment import windows_setup as ws
from app.pki import crypto

NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(cn: str, key, ikey=None, *, days=30, issuer="Test Issuing", ca=False, start=None) -> x509.Certificate:
    start = start or NOW - timedelta(days=1)
    return (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(issuer if not ca else cn)).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(start + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True).sign(ikey or key, hashes.SHA256()))


def _pem(c: x509.Certificate) -> str:
    return c.public_bytes(serialization.Encoding.PEM).decode()


ROOT_KEY = ec.generate_private_key(ec.SECP256R1())
ROOT = _pem(_cert("Test Root", ROOT_KEY, ca=True, days=3650))


def _options(**kw) -> ws.SetupOptions:
    base = dict(api="https://easyeap.example/", org="Corp", user_label="Nina (nina@corp.example)", user_code="U" * 43, computer_code="C" * 43,
                server_name="radius.corp.example", root_pem=ROOT, issuing_pem=ROOT, ssid="Corp", wpa3=False, wired=True, shared_pc=False,
                user_renew_days=30, computer_renew_days=45, expires="2026-11-10 12:00 UTC")
    return ws.SetupOptions(**{**base, **kw})


# ── The file ─────────────────────────────────────────────────────────────────


def test_the_file_is_a_cmd_that_powershell_reads_as_a_script():
    text = ws.build(_options())
    raw = text.encode()
    assert not raw.startswith(b"\xef\xbb\xbf")                       # a BOM would break cmd's first line
    assert text.startswith("<# :") and "\r\n#>\r\n" in text            # batch part hidden in a PowerShell block comment
    head = text.split("#>\r\n", 1)[0]
    assert head.isascii() and "exit /b" in head and "-ExecutionPolicy Bypass" in head
    assert "\n" not in text.replace("\r\n", "")                         # CRLF everywhere: cmd needs it
    assert "$UserCode = '" + "U" * 43 + "'" in text and "$ComputerCode = '" + "C" * 43 + "'" in text
    assert "PRIVATE KEY" not in text and "Exportable = FALSE" in text
    assert "Microsoft Platform Crypto Provider" in text and "Microsoft Software Key Storage Provider" in text  # TPM, then no-TPM PCs
    assert "$env:ProgramFiles" in text and "ProgramData" not in text.replace("not ProgramData", "")  # SYSTEM's script where users can't write


def test_names_cant_break_out_of_strings_or_comments():
    text = ws.build(_options(user_label="Eve <#\r\n Remove-Item C:\\ #> O'Hara", org="O'Brien"))
    header = text.split("#>\r\n", 1)[1].split("\r\n", 1)[0]
    assert header.startswith("# EasyEAP setup") and "<#" not in header and "#>" not in header
    assert "$ForUser = 'Eve <#\r\n Remove-Item C:\\ #> O''Hara'" in text  # inside a single-quoted string it's inert
    assert "$Org = 'O''Brien'" in text
    with pytest.raises(ValueError):
        ws._here("ok\n'@ evil")


@pytest.mark.parametrize(("user", "computer", "shared", "mode"), [
    (True, True, False, "machineOrUser"), (True, True, True, "machine"), (False, True, False, "machine"), (True, False, False, "user"),
    (True, False, True, "user")])
def test_sign_in_mode(user, computer, shared, mode):
    assert ws.mode_for(user, computer, shared) == mode
    text = ws.build(_options(user_code="U" if user else None, computer_code="C" if computer else None, shared_pc=shared))
    assert f"$Mode = '{mode}'" in text and f"<authMode>{mode}</authMode>" in text


def test_optional_parts():
    text = ws.build(_options(ssid=None, wired=False, computer_code=None))
    assert "$Ssid = ''" in text and "$Wired = $false" in text and "$LanXml = ''" in text and "$WlanXml = ''" in text
    assert ws.filename("nina@corp.example") == "EasyEAP-Setup-nina.cmd" and ws.filename("../..\\x y") == "EasyEAP-Setup-x-y.cmd"
    assert ws.filename("") == "EasyEAP-Setup-user.cmd"


def test_renewal_script_carries_the_issuer_and_windows():
    script = ws.renew_script(_options())
    assert "$RenewDays = @{ Computer = 45; User = 30 }[$Scope]" in script
    der = x509.load_pem_x509_certificate(ROOT.encode()).public_bytes(serialization.Encoding.DER)
    assert base64.b64encode(der).decode() in script and "/api/enroll/renew" in script and "-DeleteKey" in script
    assert "$Kind = 'windows-setup'" in script and "$RenewerVersion = '2.0'" in script and "easyeap-check-v2|" in script


def test_renewal_script_kinds_and_roots():
    issuing = _pem(_cert("Test Issuing", ec.generate_private_key(ec.SECP256R1()), ROOT_KEY, issuer="Test Root"))
    other = _pem(_cert("Next Root", ec.generate_private_key(ec.SECP256R1()), ca=True, days=3650))
    script = ws.renew_ps1(api="https://e.example/", kind="windows-helper", org="O'Brien", root_pems=[ROOT, other], issuing_pem=issuing,
                          user_days=21, computer_days=21)
    assert "$Kind = 'windows-helper'" in script and "$Api = 'https://e.example'" in script
    org = base64.b64encode(b"O'Brien").decode()
    assert f"$Org = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{org}'))" in script
    roots = [base64.b64encode(x509.load_pem_x509_certificate(p.encode()).public_bytes(serialization.Encoding.DER)).decode() for p in (ROOT, other)]
    assert f"$RootsDer = @('{roots[0]}', '{roots[1]}')" in script
    assert "__" not in script.replace("__RENEW", "")  # every placeholder filled
    with pytest.raises(ValueError):
        ws.renew_ps1(api="https://e.example", kind="linux", org="O", root_pems=[ROOT], issuing_pem=ROOT, user_days=1, computer_days=1)


def test_powershell_quotes_include_the_curly_ones():
    """PowerShell reads ‘ ’ ‚ ‛ as single quotes (about_Quoting_Rules): each is doubled, so the string stays literal."""
    assert profiles.ps_quote("O'Brien") == "'O''Brien'"
    assert profiles.ps_quote("Children\u2019s \u2018x\u2019 \u201ay\u201b") == "'Children\u2019\u2019s \u2018\u2018x\u2019\u2019 \u201a\u201ay\u201b\u201b'"
    assert not profiles.ps_here_ok("a\n\u2019@\nb") and profiles.ps_here_ok("a\n @\nb'@")


def test_the_renewal_script_is_ascii_whatever_the_names():
    """Windows PowerShell reads a file without a BOM as ANSI: renew.ps1 has nothing for it to misread."""
    script = ws.renew_ps1(api="https://e.example", kind="windows-helper", org="Children\u2019s Szko\u0142a \u5b66\u6821", root_pems=[ROOT],
                          issuing_pem=ROOT, user_days=30, computer_days=30)
    assert script.isascii()


def test_the_portal_helper_installs_its_renewal():
    renew = ws.renew_ps1(api="https://e.example", kind="windows-helper", org="Corp", root_pems=[ROOT], issuing_pem=ROOT, user_days=30, computer_days=30)
    script = profiles.windows_powershell("https://e.example", "tok", "Corp", "radius.corp.example", ROOT, ROOT, renew_ps1=renew)
    assert "$RenewPs1 = @'\n" + renew.rstrip("\n") + "\n'@\n" in script
    assert "renewer = $Renewer" in script and "EasyEAP renew certificate ($env:USERNAME)" in script and "-Scope User" in script
    assert "-TaskPath '\\EasyEAP\\' -TaskName 'Renew user certificate'" in script  # the setup file's shared task wins...
    root_b64 = base64.b64encode(x509.load_pem_x509_certificate(ROOT.encode()).public_bytes(serialization.Encoding.DER)).decode()
    assert f".Contains('{root_b64}')" in script  # ...when its script is for this EasyEAP
    plain = profiles.windows_powershell("https://e.example", "tok", "Corp", "radius.corp.example", ROOT, ROOT)
    assert "$RenewPs1 = ''\n" in plain
    with pytest.raises(ValueError):
        profiles.windows_powershell("https://e.example", "tok", "Corp", "r.example", ROOT, ROOT, renew_ps1="x\n'@\ny")


def test_every_request_accepts_the_pinned_server_certificate():
    """A PC that doesn't trust the server's certificate (EasyEAP's temporary one) accepts the one with the public key the
    file was made with: the setup file, its renew.ps1, and the portal helper with its own, before every request.
    tests/windows/tls-pin.ps1 runs the generated check against a self-signed HTTPS server."""
    pin = base64.b64encode(b"\x01" * 32).decode()
    renew = ws.renew_ps1(api="https://e.example", kind="windows-helper", org="Corp", root_pems=[ROOT], issuing_pem=ROOT,
                         user_days=30, computer_days=30, pin=pin)
    scripts = {"setup": ws.build(_options(pin=pin)), "setup renewal": ws.renew_script(_options(pin=pin)), "helper renewal": renew,
               "helper": profiles.windows_powershell("https://e.example", "tok", "Corp", "radius.corp.example", ROOT, ROOT, renew_ps1=renew, pin=pin)}
    for name, script in scripts.items():
        if "$RenewPs1 = @'" in script:  # the file's own code, not the renew.ps1 it carries (checked on its own)
            head, rest = script.split("$RenewPs1 = @'", 1)
            script = head + rest.split("\n'@", 1)[1]
        assert f"$TlsPin = '{pin}'" in script, name
        lines = script.splitlines()
        calls = [i for i, line in enumerate(lines) if "Invoke-RestMethod" in line]
        assert calls, name
        for i in calls:
            assert "Use-EasyEapPin" in [x.strip() for x in lines[i - 2:i]], (name, lines[i])
        assert "[EasyEapTlsPin]::Use($TlsPin)" in script and "-IgnoreWarnings" in script, name
    # Without a pin (no certificate file): nothing to accept beyond what Windows trusts.
    assert "$TlsPin = ''" in ws.build(_options())


def test_a_failed_request_says_when_the_certificate_check_isnt_in_place():
    """Where PowerShell can't compile the check (application control) or can't use it (PowerShell 7), a request that
    fails before EasyEAP answers says so; one EasyEAP refused keeps EasyEAP's own reason."""
    pin = base64.b64encode(b"\x02" * 32).decode()
    renew = ws.renew_script(_options(pin=pin))
    setup = ws.build(_options(pin=pin))
    helper = profiles.windows_powershell("https://e.example", "tok", "Corp", "radius.corp.example", ROOT, ROOT, renew_ps1=renew, pin=pin)
    for script in (renew, setup, helper):
        assert "$script:TlsPinProblem = \"Windows didn't allow that check here" in script
        assert "PSEdition -eq 'Core'" in script and "function Get-EasyEapPinHint($Err)" in script
        assert "-not ($Err -and $Err.Exception -and $Err.Exception.Response)" in script
    assert "$detail = $_.Exception.Message + (Get-EasyEapPinHint $_)" in renew
    for script in (setup, helper):
        assert "if ($hint) { throw ($_.Exception.Message + $hint) }" in script.replace("{{", "{").replace("}}", "}")


def test_the_certificate_request_is_read_as_plain_text():
    """Windows PowerShell 5.1's ConvertTo-Json writes a string from Get-Content as an object (with its PSPath notes),
    and EasyEAP refuses that csr ("Input should be a valid string"). tests/windows/request-bodies.ps1 runs the real code."""
    renew = ws.renew_script(_options())
    helper = profiles.windows_powershell("https://e.example", "tok", "Corp", "radius.corp.example", ROOT, ROOT, renew_ps1=renew)
    for name, script in {"setup": ws.build(_options()), "renewal": renew, "helper": helper}.items():
        assert "Pem = (Get-Content" not in script and "$Csr = Get-Content" not in script, name
    assert "Pem = [IO.File]::ReadAllText($csr)" in renew and "Pem = [IO.File]::ReadAllText($csr)" in ws.build(_options())
    assert '$Csr = [IO.File]::ReadAllText("$Work\\req.csr")' in helper


def test_windows_own_powershell_never_one_in_the_downloads_folder():
    """cmd.exe and Start-Process look in the current folder (Downloads, for a double-clicked file) before the PATH."""
    setup = ws.build(_options())
    first = setup.split("\r\n#>\r\n", 1)[0]
    assert '"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile' in first
    assert "\npowershell.exe" not in first.replace("\r\n", "\n")
    assert '$PowerShellExe = "$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"' in setup
    assert "Start-Process -FilePath $PowerShellExe -Verb RunAs" in setup and "Start-Process -FilePath 'powershell.exe'" not in setup


def test_the_helper_leaves_renewal_to_the_shared_task_only_when_it_has_the_pin():
    """A shared renew.ps1 from before the pin can't reach EasyEAP over a certificate Windows doesn't trust: the helper
    then adds its own task."""
    helper = profiles.windows_powershell("https://e.example", "tok", "Corp", "radius.corp.example", ROOT, ROOT, renew_ps1="x", pin="P")
    assert "$ours = $text.Contains(" in helper and "(-not $TlsPin -or $text.Contains(\"`$TlsPin = '$TlsPin'\"))" in helper
    # The setup file writes exactly that line into the shared renew.ps1.
    assert "$TlsPin = 'P'" in ws.renew_script(_options(pin="P"))


@pytest.mark.parametrize(("method", "platform", "origin", "renewer", "expected"), [
    ("link", "windows", "device", "windows-helper", "windows-helper"),
    ("link", "windows", "device", None, None),                       # an older helper, or one that couldn't install the task
    ("link", "windows", "browser", "windows-helper", None),
    ("link", "macos", "device", "windows-helper", None),
    ("link", "linux", "device", "windows-helper", "linux"),
    (enr.WINDOWS_SETUP, "windows", "device", None, "windows-setup"),
])
def test_what_will_renew_a_new_certificate(monkeypatch, method, platform, origin, renewer, expected):
    monkeypatch.setattr(enr.crypto, "csr_info", lambda pem: None)
    monkeypatch.setattr(enr, "_device", lambda s_, e_, hint: SimpleNamespace(id=1, name="PC-1"))
    monkeypatch.setattr(enr, "_names", lambda s_, e_: (None, SimpleNamespace(id=2), None, {}))
    monkeypatch.setattr(enr.pki, "sign_csr", lambda *a, **kw: SimpleNamespace(id=3))
    monkeypatch.setattr(enr, "_finish", lambda *a: None)
    e = SimpleNamespace(status="pending", method=method, platform=platform, device_name="PC-1", id=4)
    assert enr.complete_with_csr(None, None, e, "csr", origin, renewer=renewer).renewer == expected


def test_the_csr_body_takes_only_the_helper_as_renewer():
    from pydantic import ValidationError

    from app.routers import enroll_public as ep
    assert ep.CsrIn(csr="x" * 100, renewer="windows-helper").renewer == "windows-helper"
    assert ep.CsrIn(csr="x" * 100).renewer is None
    with pytest.raises(ValidationError):
        ep.CsrIn(csr="x" * 100, renewer="windows-setup")


def test_profiles_sign_in_mode_and_issuer_filter():
    issuing = _pem(_cert("Test Issuing", ec.generate_private_key(ec.SECP256R1()), ROOT_KEY, issuer="Test Root"))
    plain = profiles.windows_wlan_xml("Corp", "radius.corp.example", ROOT)
    assert "<authMode>user</authMode>" in plain and "TLSExtensions" not in plain  # what the portal sends is unchanged
    for xml in (profiles.windows_wlan_xml("Corp", "r.example", ROOT, auth_mode="machineOrUser", issuers=[ROOT, issuing]),
                profiles.windows_lan_xml("r.example", ROOT, auth_mode="machine", issuers=[ROOT, issuing])):
        tree = ET.fromstring(xml)
        hashes_ = [e.text for e in tree.iter() if e.tag.endswith("IssuerHash")]
        assert len(hashes_) == 2 and all(len(h.replace(" ", "")) == 40 for h in hashes_)
        assert any(e.tag.endswith("CAHashList") and e.get("Enabled") == "true" for e in tree.iter())
        assert any(e.tag.endswith("AcceptServerName") and e.text == "true" for e in tree.iter())
    with pytest.raises(ValueError):
        profiles.windows_lan_xml("r.example", ROOT, auth_mode="guest")


# ── Signatures ───────────────────────────────────────────────────────────────


def _csr(key=None, header="NEW CERTIFICATE REQUEST") -> tuple:
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(_name("EasyEAP")).sign(key, hashes.SHA256())
    return key, csr.public_bytes(serialization.Encoding.PEM).decode().replace("CERTIFICATE REQUEST", header)


def _p1363(key, msg: bytes) -> bytes:
    r, s = decode_dss_signature(key.sign(msg, ec.ECDSA(hashes.SHA256())))
    n = (key.curve.key_size + 7) // 8
    return r.to_bytes(n, "big") + s.to_bytes(n, "big")


def test_signature_formats():
    msg = b"easyeap-renew-v1|x"
    k = ec.generate_private_key(ec.SECP256R1())
    c = _cert("pc", k, ROOT_KEY)
    assert enr.verify_signature(c, msg, _p1363(k, msg))                            # .NET's ECDSA form
    assert enr.verify_signature(c, msg, k.sign(msg, ec.ECDSA(hashes.SHA256())))    # DER also accepted
    assert not enr.verify_signature(c, msg + b"!", _p1363(k, msg))
    k384 = ec.generate_private_key(ec.SECP384R1())
    assert enr.verify_signature(_cert("pc", k384, ROOT_KEY), msg, _p1363(k384, msg))
    rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rc = _cert("pc", rk, ROOT_KEY)
    assert enr.verify_signature(rc, msg, rk.sign(msg, padding.PKCS1v15(), hashes.SHA256()))
    assert not enr.verify_signature(rc, msg, b"\x00" * 256)
    ek = ed25519.Ed25519PrivateKey.generate()
    ecert = (x509.CertificateBuilder().subject_name(_name("pc")).issuer_name(_name("pc")).public_key(ek.public_key()).serial_number(1)
             .not_valid_before(NOW).not_valid_after(NOW + timedelta(days=1)).sign(ek, None))
    assert not enr.verify_signature(ecert, msg, ek.sign(msg))                       # not a key type Windows makes


def test_message_binds_certificate_time_and_request():
    a = enr.renewal_message(b"cert", 100, b"csr")
    assert a.startswith(b"easyeap-renew-v1|") and a != enr.renewal_message(b"cert2", 100, b"csr")
    assert a != enr.renewal_message(b"cert", 101, b"csr") and a != enr.renewal_message(b"cert", 100, b"csr2")


# ── Renewal rules ────────────────────────────────────────────────────────────


class FakeSession:
    def __init__(self, cert, identity, tpl, tenant, device):
        self.cert, self.objs, self.renewal = cert, {}, None
        self.successor, self.successor_used, self.tries = None, None, 1  # an earlier renewal's certificate, for a re-issue
        self.other_renewals = []  # more valid renewals, listed after self.renewal
        for o in (identity, tpl, tenant, device):
            if o is not None:
                self.objs[o.id] = o

    def scalars(self, stmt):
        sql = str(stmt.whereclause)
        if "renewal_of" in sql and "status !=" in sql:  # _replaceable_successor: the earlier renewal's, not revoked
            return SimpleNamespace(first=lambda: self.successor)
        if "renewal_of" in sql:  # _earlier_renewal: the valid certificates earlier renewals of it issued
            valid = [self.renewal] if self.renewal is not None and self.renewal.status == "active" and self.renewal.not_after > NOW else []
            return SimpleNamespace(all=lambda: valid + self.other_renewals)
        # The row only matches the fingerprint the code really looks up, in the stored format.
        wanted = stmt.whereclause.right.value
        return SimpleNamespace(first=lambda: self.cert if self.cert is not None and wanted == self.cert.fingerprint_sha256 else None)

    def scalar(self, stmt):
        sql = str(stmt)
        if "count(" in sql:  # renewals of this certificate so far
            return self.tries
        assert "min(auth_events.at)" in sql  # successor_used(): when RADIUS first accepted the successor
        return self.successor_used

    def get(self, _model, ident, **_lock):
        if self.cert is not None and ident == self.cert.id:  # re-read under a row lock before a renewal
            return self.cert
        return self.objs.get(ident)


@pytest.fixture()
def world(monkeypatch):
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = _cert("pc1.nina", key, ROOT_KEY, days=365, start=NOW - timedelta(days=340))  # 25 days left
    der = leaf.public_bytes(serialization.Encoding.DER)
    tenant = SimpleNamespace(id=uuid.uuid4(), status="active", domain="corp.example", slug="corp")
    identity = SimpleNamespace(id=uuid.uuid4(), account_state="enabled", upn="nina@corp.example", username="nina", email="", display_name="Nina")
    tpl = SimpleNamespace(id=uuid.uuid4(), renew_before_days=45, autoenroll_kind=None)
    device = SimpleNamespace(id=uuid.uuid4(), name="PC-NINA01")
    stored = crypto.cert_info(leaf.public_bytes(serialization.Encoding.PEM).decode()).fingerprint_sha256  # as sign_csr records it
    cert = SimpleNamespace(id=uuid.uuid4(), fingerprint_sha256=stored, status="active", renewed_at=None,
                           not_before=leaf.not_valid_before_utc, not_after=leaf.not_valid_after_utc, purpose="device",
                           identity_id=identity.id, template_id=tpl.id, tenant_id=tenant.id, device_id=device.id, key_origin="device",
                           enrollment_id=None, enrollment_source=None, renewal_of=None, renewer="windows-setup", renewer_version="1",
                           renewal_checked_at=None, trust_reported=None, serial="0A")
    issued = {}
    rset = SimpleNamespace(user_certs=True, machine_certs=True, server_cert=True, renew_at_percent=80)
    monkeypatch.setattr(enr.renewal, "settings", lambda s_, tid: rset)
    monkeypatch.setattr(enr, "set_tenant", lambda s_, tid: setattr(s_, "scoped", tid))

    def sign_csr(session, bao, tenant_, tpl_, csr_pem, names, **kw):
        issued.update(names=names, **kw)
        return SimpleNamespace(id=uuid.uuid4(), key_storage=None, renewal_of=None)

    monkeypatch.setattr(enr.pki, "sign_csr", sign_csr)
    monkeypatch.setattr(enr.pki, "revoke", lambda s_, bao, c, reason, actor: issued.setdefault("revoked", []).append((c, reason, actor)))
    monkeypatch.setattr(enr, "recompute_tenant", lambda s, t: issued.setdefault("recomputed", t))
    s = FakeSession(cert, identity, tpl, tenant, device)

    def call(*, csr_key=None, signer=None, signed_at=None, now=NOW, header="NEW CERTIFICATE REQUEST", certificate=None, client=None, check_in=False):
        at = int(now.timestamp()) if signed_at is None else signed_at
        cert_der = certificate or der
        if check_in:
            sig = _p1363(signer or key, enr.check_message(cert_der, at, client))
            return enr.renew(s, None, certificate_der=cert_der, csr_pem=None, signed_at=at, signature=sig, key_storage=None, client=client, now=now)
        _, csr_pem = _csr(csr_key, header)
        csr_der = x509.load_pem_x509_csr(csr_pem.encode()).public_bytes(serialization.Encoding.DER)
        sig = _p1363(signer or key, enr.renewal_message(cert_der, at, csr_der, client))
        return enr.renew(s, None, certificate_der=cert_der, csr_pem=csr_pem, signed_at=at, signature=sig, key_storage="tpm", client=client, now=now)

    return SimpleNamespace(call=call, cert=cert, identity=identity, tpl=tpl, tenant=tenant, key=key, issued=issued, session=s, renewal=rset,
                           cert_der=der)


def test_renews_inside_the_window(world):
    old, new = world.call()
    assert world.session.scoped == world.tenant.id  # the rest runs scoped to the certificate's tenant
    assert new is not None and new.key_storage == "tpm" and new.renewal_of == world.cert.id
    assert old.status == "superseded" and old.renewed_at == NOW and world.issued["recomputed"] == world.tenant.id
    assert world.issued["device_id"] == world.cert.device_id and world.issued["identity_id"] == world.identity.id
    assert world.issued["names"]["device"] == "pc-nina01" and world.issued["key_origin"] == "device"


def test_nothing_before_the_window(world):
    world.renewal.renew_at_percent = 90
    world.cert.not_before = NOW - timedelta(days=200)  # 200 of 225 days: 88.9 %
    old, new = world.call()
    assert new is None and old.status == "active" and "names" not in world.issued
    world.renewal.renew_at_percent = 88
    assert world.call()[1] is not None


def test_the_window_follows_the_percentage_not_the_template(world):
    """The template's days no longer decide: a certificate cut short by the CA renews at the same share of its life."""
    world.tpl.renew_before_days = 1
    world.cert.not_before, world.cert.not_after = NOW - timedelta(days=81), NOW + timedelta(days=19)  # 81 % of 100 days
    assert world.call()[1] is not None


@pytest.mark.parametrize(("purpose", "switch"), [("user", "user_certs"), ("device", "machine_certs")])
def test_renewal_turned_off(world, purpose, switch):
    world.cert.purpose = purpose
    setattr(world.renewal, switch, False)
    with pytest.raises(enr.RenewalRefused, match="turned off") as exc:
        world.call()
    assert exc.value.code == "off" and exc.value.cert is world.cert and "names" not in world.issued
    world.cert.not_before = NOW - timedelta(days=50)  # 50 of 75 days: before the window, just "not yet", nothing to audit
    assert world.call()[1] is None


def test_refusals_say_why(world):
    world.cert.status = "revoked"
    with pytest.raises(enr.RenewalRefused) as exc:
        world.call()
    assert exc.value.code == "revoked" and world.session.scoped == world.tenant.id
    world.session.scoped = None
    with pytest.raises(enr.EnrollmentError, match="isn't signed") as exc:
        world.call(signer=ec.generate_private_key(ec.SECP256R1()))
    # Not scoped, and not a refusal to audit: anyone can hold a copy of the certificate
    assert not isinstance(exc.value, enr.RenewalRefused) and world.session.scoped is None
    with pytest.raises(enr.RenewalRefused) as exc:
        world.call(signed_at=int((NOW - timedelta(minutes=11)).timestamp()))
    assert exc.value.code == "clock"  # signed by the key, so the wrong clock is the device's own
    world.session.cert = None
    with pytest.raises(enr.EnrollmentError) as exc:
        world.call()
    assert not isinstance(exc.value, enr.RenewalRefused)  # a certificate EasyEAP didn't issue isn't audited


def test_a_ca_too_close_to_expiry_is_a_refusal(world, monkeypatch):
    def fail(*a, **kw):
        raise enr.pki.PkiError("The issuing CA expires on 2026-11-09 00:00 UTC, too soon")
    monkeypatch.setattr(enr.pki, "sign_csr", fail)
    with pytest.raises(enr.RenewalRefused, match="too soon") as exc:
        world.call()
    assert exc.value.code == "ca"


@pytest.mark.parametrize(("setup", "message"), [
    (lambda w: setattr(w.session, "cert", None), "didn't issue"),
    (lambda w: setattr(w.cert, "status", "revoked"), "revoked"),
    (lambda w: setattr(w.cert, "status", "superseded"), "already renewed"),
    (lambda w: setattr(w.cert, "renewed_at", NOW), "already renewed"),
    (lambda w: setattr(w.cert, "not_after", NOW - timedelta(seconds=1)), "expired"),
    (lambda w: setattr(w.cert, "purpose", "radius-server"), "isn't renewed this way"),
    (lambda w: setattr(w.identity, "account_state", "disabled"), "disabled"),
    (lambda w: setattr(w.tenant, "status", "suspended"), "no longer exists"),
])
def test_refusals(world, setup, message):
    setup(world)
    with pytest.raises(enr.EnrollmentError, match=message):
        world.call()
    assert "names" not in world.issued


def test_a_lost_renewal_answer_is_sent_again(world):
    """The client asks again with the same pending key: it gets the certificate already issued for it, nothing new."""
    k = ec.generate_private_key(ec.SECP256R1())
    world.cert.status, world.cert.renewed_at = "superseded", NOW - timedelta(hours=3)
    world.session.renewal = SimpleNamespace(status="active", not_after=NOW + timedelta(days=300),
                                            certificate_pem=_pem(_cert("pc1.nina", k, ROOT_KEY, days=365)))
    old, again = world.call(csr_key=k)
    assert again is world.session.renewal and old is world.cert and "names" not in world.issued
    with pytest.raises(enr.EnrollmentError, match="already renewed"):
        world.call()  # another key: that's a second renewal, refused
    world.session.renewal.status = "revoked"
    with pytest.raises(enr.EnrollmentError, match="already renewed"):
        world.call(csr_key=k)


def test_a_resend_finds_its_certificate_among_several(world):
    """A replaced renewal and its replacement can expire in the same second: the key decides, not the order."""
    k = ec.generate_private_key(ec.SECP256R1())
    world.cert.status, world.cert.renewed_at = "superseded", NOW - timedelta(hours=3)
    mine = SimpleNamespace(status="active", not_after=NOW + timedelta(days=300), certificate_pem=_pem(_cert("pc1.nina", k, ROOT_KEY, days=365)))
    other = SimpleNamespace(status="active", not_after=NOW + timedelta(days=300),
                            certificate_pem=_pem(_cert("pc1.nina", ec.generate_private_key(ec.SECP256R1()), ROOT_KEY, days=365)))
    world.session.renewal, world.session.other_renewals = other, [mine]
    _, again = world.call(csr_key=k)
    assert again is mine and "names" not in world.issued


def test_signature_time_and_key_checks(world):
    with pytest.raises(enr.EnrollmentError, match="10 minutes"):
        world.call(signed_at=int((NOW - timedelta(minutes=11)).timestamp()))
    with pytest.raises(enr.EnrollmentError, match="isn't signed"):
        world.call(signer=ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(enr.EnrollmentError, match="new key"):
        world.call(csr_key=world.key)
    with pytest.raises(enr.EnrollmentError, match="isn't valid"):
        enr._csr_der("garbage")
    _, new = world.call(header="CERTIFICATE REQUEST")  # either PEM header
    assert new is not None


# ── Protocol v2: check-ins, client blocks, lost answers (docs/plans/cert-renewal.md §15b) ─────────────────────────


ROOT_HASH = "ab" * 32
CLIENT = json.dumps({"kind": "windows-setup", "version": "2.0", "scope": "computer", "roots": [ROOT_HASH.upper(), "nothex"],
                     "profile_roots": [ROOT_HASH]})


def test_parse_client():
    info = enr.parse_client(CLIENT)
    assert info == {"kind": "windows-setup", "version": "2.0", "scope": "computer", "roots": [ROOT_HASH], "profile_roots": [ROOT_HASH]}
    with pytest.raises(enr.EnrollmentError, match="JSON"):
        enr.parse_client("{")
    with pytest.raises(enr.EnrollmentError, match="kind"):
        enr.parse_client(json.dumps({"kind": "mdm"}))
    assert enr.parse_client(json.dumps({"kind": "linux", "roots": ["cd" * 32] * 40}))["roots"] == ["cd" * 32] * 16
    assert enr.parse_client(json.dumps({"kind": "linux", "roots": ["cd" * 32 + "\n"]}))["roots"] == []


def test_messages_v2():
    v1 = enr.renewal_message(b"cert", 100, b"csr")
    v2 = enr.renewal_message(b"cert", 100, b"csr", CLIENT)
    assert v2.startswith(b"easyeap-renew-v2|") and v2 != v1 and v2 != enr.renewal_message(b"cert", 100, b"csr", CLIENT + " ")
    chk = enr.check_message(b"cert", 100, CLIENT)
    assert chk.startswith(b"easyeap-check-v2|") and chk != enr.check_message(b"cert", 100, CLIENT.replace("2.0", "2.1"))


def test_a_check_in_records_the_renewer_and_issues_nothing(world):
    old, new = world.call(check_in=True, client=CLIENT)
    assert new is None and old is world.cert and old.status == "active" and "names" not in world.issued
    assert old.renewer == "windows-setup" and old.renewer_version == "2.0" and old.renewal_checked_at == NOW
    assert old.trust_reported["roots"] == [ROOT_HASH] and old.trust_reported["scope"] == "computer"


def test_a_check_in_must_be_signed_over_the_client_block(world):
    with pytest.raises(enr.EnrollmentError, match="isn't signed"):
        world.call(check_in=True, client=CLIENT, signer=ec.generate_private_key(ec.SECP256R1()))
    at = int(NOW.timestamp())
    sig = _p1363(world.key, enr.check_message(world.cert_der, at, CLIENT))
    with pytest.raises(enr.EnrollmentError, match="isn't signed"):  # the block changed after signing
        enr.renew(world.session, None, certificate_der=world.cert_der, csr_pem=None, signed_at=at, signature=sig, key_storage=None,
                  client=CLIENT.replace("computer", "user"), now=NOW)
    with pytest.raises(enr.EnrollmentError, match="needs a certificate request"):
        enr.renew(world.session, None, certificate_der=world.cert_der, csr_pem=None, signed_at=at, signature=sig, key_storage=None, now=NOW)
    assert world.cert.renewal_checked_at is None


def test_a_check_in_with_an_expired_certificate_is_refused(world):
    world.cert.not_after = NOW - timedelta(seconds=1)
    with pytest.raises(enr.RenewalRefused) as exc:
        world.call(check_in=True, client=CLIENT)
    assert exc.value.code == "expired"


def test_a_v2_renewal_records_its_renewer(world):
    _, new = world.call(client=CLIENT)
    assert new.renewer == "windows-setup" and new.renewer_version == "2.0" and new.issued_now
    # Issued isn't received: only a check-in signed with the new key says the device has it (retirement relies on it).
    assert getattr(new, "renewal_checked_at", None) is None and world.cert.renewal_checked_at == NOW
    assert new.replaced_serial is None and world.cert.status == "superseded"


def test_a_v1_renewal_inherits_the_renewer(world):
    world.cert.renewer = None  # issued before 0015 and missed by the backfill: read from how it was issued
    _, new = world.call()
    assert new.renewer == "renewed" and new.renewer_version == "1"
    world.cert.status, world.cert.renewed_at, world.cert.renewer = "active", None, "linux"
    assert world.call()[1].renewer == "linux"


def _renewed_before(world, *, days=2, source=None, template=None, device=None, checked=None):
    world.cert.status, world.cert.renewed_at = "superseded", NOW - timedelta(days=days)
    world.session.successor = SimpleNamespace(id=uuid.uuid4(), tenant_id=world.tenant.id, status="active", serial="0B", enrollment_source=source,
                                              template_id=template or world.tpl.id, device_id=device or world.cert.device_id,
                                              renewal_checked_at=checked)


def test_a_lost_answer_with_a_new_key_replaces_the_unused_successor(world):
    """v1 renew.ps1 throws its pending key away when the answer is lost, and asks the next day with a new one."""
    _renewed_before(world)
    _, new = world.call()
    assert new is not None and new.renewal_of == world.cert.id and new.replaced_serial == "0B" and new.issued_now
    (gone, reason, actor), = world.issued["revoked"]
    assert gone is world.session.successor and reason == "superseded" and actor == enr.REPLACED_BY
    assert world.cert.renewed_at == NOW - timedelta(days=2)  # the first renewal's time still bounds the re-issues


def test_a_used_successor_is_a_conflict(world):
    _renewed_before(world)
    world.session.successor_used = NOW - timedelta(hours=5)
    with pytest.raises(enr.RenewalRefused, match="in use") as exc:
        world.call()
    assert exc.value.code == "conflict" and "names" not in world.issued and "revoked" not in world.issued


def test_a_successor_its_device_checked_in_with_is_a_conflict(world):
    _renewed_before(world, checked=NOW - timedelta(hours=3))  # the device signed a check-in with the new key
    with pytest.raises(enr.RenewalRefused) as exc:
        world.call()
    assert exc.value.code == "conflict" and "revoked" not in world.issued


def test_three_replacements_at_most(world):
    _renewed_before(world)
    world.session.tries = 4  # the renewal and three replacements
    with pytest.raises(enr.RenewalRefused, match="already renewed"):
        world.call()
    world.session.tries = 3
    assert world.call()[1].replaced_serial == "0B"


def test_a_v2_renewer_that_lost_its_key_gets_the_same_replacement(world):
    """v2 keeps its request, but can still lose its key (a cleared TPM, a key that doesn't work): the same bounds as v1,
    since the version is the client's own claim (cert-renewal.md §15c)."""
    _renewed_before(world)
    _, new = world.call(client=CLIENT)
    assert new.replaced_serial == "0B" and new.renewer == "windows-setup"
    _renewed_before(world, days=15)
    with pytest.raises(enr.RenewalRefused, match="already renewed") as exc:
        world.call(client=CLIENT)
    assert exc.value.code == "renewed"
    assert exc.value.note[0]["kind"] == "windows-setup"  # still a signed check-in: recorded after the rollback


def test_a_refusal_carries_the_check_in_except_on_a_wrong_clock(world):
    world.cert.status = "revoked"
    with pytest.raises(enr.RenewalRefused) as exc:
        world.call(client=CLIENT)
    assert exc.value.note == (enr.parse_client(CLIENT), NOW)
    world.cert.status = "active"
    with pytest.raises(enr.RenewalRefused) as exc:
        world.call(client=CLIENT, signed_at=int((NOW - timedelta(minutes=11)).timestamp()))
    assert exc.value.code == "clock" and exc.value.note is None
    with pytest.raises(enr.RenewalRefused) as exc:
        world.cert.status = "revoked"
        world.call()
    assert exc.value.note is None  # v1: no client block to record


@pytest.mark.parametrize("setup", [
    lambda w: _renewed_before(w, days=15),                       # past 14 days since the renewal
    lambda w: _renewed_before(w, device=uuid.uuid4()),           # another device's certificate replaced it
    lambda w: _renewed_before(w, source="gpo"),                  # Group Policy took over: never replaced this way
    lambda w: _renewed_before(w, template=uuid.uuid4()),         # superseded by another template's certificate
    lambda w: setattr(w.cert, "status", "superseded"),           # superseded by a new enrollment: no successor
])
def test_no_reissue(world, setup):
    setup(world)
    with pytest.raises(enr.RenewalRefused, match="already renewed") as exc:
        world.call()
    assert exc.value.code == "renewed" and "revoked" not in world.issued


def test_a_superseded_certificate_can_check_in(world):
    _renewed_before(world)
    old, new = world.call(check_in=True, client=CLIENT)
    assert new is None and old.status == "superseded" and old.renewal_checked_at == NOW
