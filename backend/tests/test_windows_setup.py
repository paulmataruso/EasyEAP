"""The Windows 11 setup (docs/plans/windows-setup.md): the generated file, the profiles' sign-in modes and issuer filter,
renewal signatures, and every renewal rule (no database: a small fake session). tests/windows/run.sh parses the
generated files with PowerShell and checks signatures made by the script's own PowerShell code; tests/e2e/run.sh runs
the whole flow against the real API, OpenBao and FreeRADIUS."""
from __future__ import annotations

import base64
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
        self.cert, self.objs = cert, {}
        for o in (identity, tpl, tenant, device):
            if o is not None:
                self.objs[o.id] = o

    def scalars(self, stmt):
        # The row only matches the fingerprint the code really looks up, in the stored format.
        wanted = stmt.whereclause.right.value
        return SimpleNamespace(first=lambda: self.cert if self.cert is not None and wanted == self.cert.fingerprint_sha256 else None)

    def get(self, _model, ident):
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
                           not_after=leaf.not_valid_after_utc, purpose="device", identity_id=identity.id, template_id=tpl.id,
                           tenant_id=tenant.id, device_id=device.id, key_origin="device", enrollment_id=None)
    issued = {}

    def sign_csr(session, bao, tenant_, tpl_, csr_pem, names, **kw):
        issued.update(names=names, **kw)
        return SimpleNamespace(id=uuid.uuid4(), key_storage=None, renewal_of=None)

    monkeypatch.setattr(enr.pki, "sign_csr", sign_csr)
    monkeypatch.setattr(enr, "recompute_tenant", lambda s, t: issued.setdefault("recomputed", t))
    s = FakeSession(cert, identity, tpl, tenant, device)

    def call(*, csr_key=None, signer=None, signed_at=None, now=NOW, header="NEW CERTIFICATE REQUEST", certificate=None):
        _, csr_pem = _csr(csr_key, header)
        csr_der = x509.load_pem_x509_csr(csr_pem.encode()).public_bytes(serialization.Encoding.DER)
        at = int(now.timestamp()) if signed_at is None else signed_at
        cert_der = certificate or der
        sig = _p1363(signer or key, enr.renewal_message(cert_der, at, csr_der))
        return enr.renew(s, None, certificate_der=cert_der, csr_pem=csr_pem, signed_at=at, signature=sig, key_storage="tpm", now=now)

    return SimpleNamespace(call=call, cert=cert, identity=identity, tpl=tpl, tenant=tenant, key=key, issued=issued, session=s)


def test_renews_inside_the_window(world):
    old, new = world.call()
    assert new is not None and new.key_storage == "tpm" and new.renewal_of == world.cert.id
    assert old.status == "superseded" and old.renewed_at == NOW and world.issued["recomputed"] == world.tenant.id
    assert world.issued["device_id"] == world.cert.device_id and world.issued["identity_id"] == world.identity.id
    assert world.issued["names"]["device"] == "pc-nina01" and world.issued["key_origin"] == "device"


def test_nothing_before_the_window(world):
    world.tpl.renew_before_days = 10
    old, new = world.call()
    assert new is None and old.status == "active" and "names" not in world.issued


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
