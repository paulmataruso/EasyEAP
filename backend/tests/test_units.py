"""Unit tests that need no database or OpenBao."""
import plistlib
import xml.etree.ElementTree as ET
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app import audit
from app import models as m
from app.enrollment import profiles
from app.enrollment.service import build_pkcs12, generate_password
from app.pki import crypto
from app.pki.service import render_names
from app.radius.explain import EXPLANATIONS, classify
from app.security.passwords import hash_password, password_problems, verify_password
from app.security.rbac import PERMISSIONS, permissions_for
from app.security.redact import redact
from app.security.tokens import new_shared_secret, token_hash


def _self_signed(cn="Test Root"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(0x00ABCDEF)
            .not_valid_before(now).not_valid_after(now.replace(year=now.year + 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    return key, cert.public_bytes(serialization.Encoding.PEM).decode()


def test_audit_chain_detects_tampering():
    rows, prev = [], audit.GENESIS
    for i in range(3):
        r = m.AuditEvent(tenant_id=None, at=datetime(2026, 11, 5, 10, i, tzinfo=UTC), actor_type="admin", actor_id="1", actor_label="a@b",
                         action=f"x.{i}", target_type="t", target_id=None, target_label="", detail={"n": i}, ip=None, prev_hash=prev)
        r.hash = audit.compute_hash(prev, r)
        prev = r.hash
        rows.append(r)
    assert audit.compute_hash(rows[0].prev_hash, rows[1]) != rows[1].hash  # wrong link
    rows[1].detail = {"n": 99}
    assert audit.compute_hash(rows[1].prev_hash, rows[1]) != rows[1].hash  # edited content


def test_audit_scrubs_secret_keys():
    assert audit._scrub({"shared_secret": "abc", "nested": {"password": "x"}, "ok": 1}) == {"shared_secret": "[withheld]", "nested": {"password": "[withheld]"}, "ok": 1}


def test_failure_classification():
    assert classify("eap_tls: (TLS) OpenSSL says error 23 : certificate revoked") == "cert_revoked"
    assert classify("(TLS) OpenSSL says error 10 : certificate has expired") == "cert_expired"
    assert classify("eap_tls: (TLS) OpenSSL says error 18 : self-signed certificate") == "unknown_ca"
    assert classify("OpenSSL says error 20 : unable to get local issuer certificate") == "unknown_ca"
    assert classify("TLS Alert read:fatal:unknown CA") == "unknown_ca"
    assert classify(None) is None
    for code in ("unknown_ca", "cert_expired", "cert_revoked", "snapshot_stale", "policy_deny", "account_disabled"):
        assert EXPLANATIONS[code]["explanation"] and EXPLANATIONS[code]["fix"]
    assert EXPLANATIONS["unknown_ca"]["explanation"] == "The device presented a certificate issued by an authority that this RADIUS server does not trust."


def test_serial_formats():
    assert crypto.normalize_serial("00:3f:9a:0c") == "3F9A0C"
    assert crypto.bao_serial("3F9A0C") == "3f:9a:0c"
    assert crypto.bao_serial("F9A0C") == "0f:9a:0c"


def test_cert_info_and_upn_parsing():
    _, pem = _self_signed()
    info = crypto.cert_info(pem)
    assert info.serial == "ABCDEF" and info.is_ca and info.key_algorithm == "ecdsa-p256" and len(info.fingerprint_sha256) == 64


def test_template_names_are_built_by_the_ra_not_the_csr():
    tpl = m.CertificateTemplate(subject_pattern="CN={upn}", san_patterns=["upn:{upn}", "email:{email}"])
    cn, alt, other = render_names(tpl, {"upn": "jsmith@corp.example", "email": ""})
    assert cn == "jsmith@corp.example" and alt == [] and other == ["1.3.6.1.4.1.311.20.2.3;UTF8:jsmith@corp.example"]


def test_root_key_is_encrypted_for_export():
    key, _ = _self_signed()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    out = crypto.encrypt_private_key_pem(pem, "correct horse battery staple")
    assert b"ENCRYPTED PRIVATE KEY" in out
    assert serialization.load_pem_private_key(out, password=b"correct horse battery staple")


def test_pkcs12_uses_aes_and_password():
    key, root = _self_signed()
    kpem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    pw = generate_password()
    p12 = build_pkcs12(kpem, root, [root], pw, "test")
    from cryptography.hazmat.primitives.serialization import pkcs12
    k, c, _extra = pkcs12.load_key_and_certificates(p12, pw.encode())
    assert c is not None and k is not None
    try:
        pkcs12.load_key_and_certificates(p12, b"wrong")
        raise AssertionError("wrong password accepted")
    except ValueError:
        pass


def test_profiles():
    _, root = _self_signed()
    xml = profiles.windows_wlan_xml("Corp", "radius.corp.example", root)
    tree = ET.fromstring(xml)  # noqa: S314 — parsing our own generated profile
    assert tree.tag.endswith("WLANProfile") and "radius.corp.example" in xml and "<useOneX>true</useOneX>" in xml
    mc = profiles.apple_mobileconfig(ssid="Corp", server_name="radius.corp.example", root_pem=root, issuing_pem=root, org="Corp", tenant_slug="corp", identity_label="j")
    assert profiles.PKCS12_MARKER.encode() in mc
    filled = profiles.apple_mobileconfig(ssid="Corp", server_name="radius.corp.example", root_pem=root, issuing_pem=root, org="Corp", tenant_slug="corp",
                                         identity_label="j", pkcs12_b64="AAAA")
    plist = plistlib.loads(filled)
    wifi = next(p for p in plist["PayloadContent"] if p["PayloadType"] == "com.apple.wifi.managed")
    assert wifi["EAPClientConfiguration"]["AcceptEAPTypes"] == [13] and wifi["EAPClientConfiguration"]["TLSTrustedServerNames"] == ["radius.corp.example"]
    assert "domain-suffix-match=radius.corp.example" in profiles.networkmanager("Corp", "radius.corp.example", "j@corp")
    ps = profiles.windows_powershell("https://e.example", "TOKEN", "Corp", "radius.corp.example", root, root)
    assert "Microsoft Platform Crypto Provider" in ps and "Exportable = FALSE" in ps


def test_password_hashing_and_policy():
    h = hash_password("a-very-long-password-1")
    assert h.startswith("$argon2id$") and verify_password(h, "a-very-long-password-1") and not verify_password(h, "nope")
    assert not verify_password(None, "anything")
    assert password_problems("short")
    assert password_problems("jane-is-the-best-123", "jane@corp.example")


def test_rbac_separates_issue_from_ca_management():
    wifi = permissions_for(None, ["wifi_admin"])
    assert "certificates:issue" in wifi and "ca:manage" not in wifi and "radius:secrets" not in wifi
    assert "enrollment:server_keygen" not in PERMISSIONS["pki_admin"]
    assert permissions_for(None, ["auditor"]) <= {p for p in PERMISSIONS["auditor"]} and not any(p.endswith(":write") for p in PERMISSIONS["auditor"])


def test_redaction():
    assert "[REDACTED]" in redact("bind_password=hunter2 token: abc")
    assert "hunter2" not in redact('{"shared_secret": "hunter2"}')
    assert "[REDACTED PRIVATE KEY]" in redact("-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----")


def test_tokens():
    s = new_shared_secret()
    assert len(s) == 32 and s.isalnum()
    assert len(token_hash("x")) == 64
