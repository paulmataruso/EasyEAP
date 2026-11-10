"""Fixtures for tests/windows/run.sh: sample setup files and certificates (make), then the check of what PowerShell
signed (verify). Runs in the API test image with the backend on PYTHONPATH."""
from __future__ import annotations

import base64
import datetime as dt
import json
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.enrollment import linux_setup, profiles
from app.enrollment import service as enr
from app.enrollment import windows_setup as ws

OUT = Path(sys.argv[2] if len(sys.argv) > 2 else "/out")
NOW = dt.datetime.now(dt.UTC)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(cn: str, key, issuer: str, ikey, *, ca: bool, eku=ExtendedKeyUsageOID.CLIENT_AUTH, template: bool = False) -> x509.Certificate:
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(issuer)).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(NOW - dt.timedelta(minutes=5)).not_valid_after(NOW + dt.timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if not ca:
        b = b.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    if template:  # what Group Policy's certificates carry (szOID_CERTIFICATE_TEMPLATE)
        b = b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.311.21.7"), bytes.fromhex("3009060137020101020100")), critical=False)
    return b.sign(ikey, hashes.SHA256())


def _pfx(path: Path, key, cert: x509.Certificate) -> None:
    path.write_bytes(pkcs12.serialize_key_and_certificates(b"leaf", key, cert, None, serialization.BestAvailableEncryption(b"test")))


def _pem(c: x509.Certificate) -> str:
    return c.public_bytes(serialization.Encoding.PEM).decode()


def _tls(name: str, key) -> str:
    """A self-signed server certificate for easyeap.test (as install.sh's temporary one), its key, and its pin."""
    c = _cert("easyeap.test", key, "easyeap.test", key, ca=False, eku=ExtendedKeyUsageOID.SERVER_AUTH)
    (OUT / f"{name}.crt").write_text(_pem(c))
    (OUT / f"{name}.cer").write_bytes(c.public_bytes(serialization.Encoding.DER))
    (OUT / f"{name}.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return linux_setup.tls_pin(OUT / f"{name}.crt")


def make() -> None:
    # The pin every generated file carries (the server tls-pin.ps1 talks to), and an RSA one for the parser.
    pins = {"tls": _tls("tls", ec.generate_private_key(ec.SECP256R1())),
            "tls-rsa": _tls("tls-rsa", rsa.generate_private_key(public_exponent=65537, key_size=2048))}
    (OUT / "pins.json").write_text(json.dumps(pins))
    rk, ik = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    root, issuing = _cert("Test Root", rk, "Test Root", rk, ca=True), _cert("Test Issuing", ik, "Test Root", rk, ca=True)
    # renew.ps1's selection (Test-EasyEapCertificate): EasyEAP's own, and the ones it must leave alone.
    for name, c in (("root", root), ("issuing", issuing)):
        (OUT / f"{name}.cer").write_bytes(c.public_bytes(serialization.Encoding.DER))
    for name, kw in (("sel-ok", {}), ("sel-gpo", {"template": True}), ("sel-server", {"eku": ExtendedKeyUsageOID.SERVER_AUTH})):
        k = ec.generate_private_key(ec.SECP256R1())
        _pfx(OUT / f"{name}.pfx", k, _cert(f"pc1.{name}", k, "Test Issuing", ik, ca=False, **kw))
    ok_cert = x509.load_der_x509_certificate(pkcs12.load_key_and_certificates((OUT / "sel-ok.pfx").read_bytes(), b"test")[1].public_bytes(serialization.Encoding.DER))
    (OUT / "sel-nokey.cer").write_bytes(ok_cert.public_bytes(serialization.Encoding.DER))
    ork, oik, k = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    _pfx(OUT / "sel-foreign.pfx", k, _cert("pc1.foreign", k, "Other Issuing", oik, ca=False))
    (OUT / "other-issuing.cer").write_bytes(_cert("Other Issuing", oik, "Other Root", ork, ca=True).public_bytes(serialization.Encoding.DER))
    variants = {"full": dict(user_code="UCODE", computer_code="CCODE", ssid="Corp's <Wi-Fi>", wired=True, shared_pc=False),
                "user-only": dict(user_code="UCODE", computer_code=None, ssid="Corp", wired=False, shared_pc=False),
                "shared-pc": dict(user_code=None, computer_code="CCODE", ssid=None, wired=True, shared_pc=True),
                # PowerShell reads ‘ ’ ‚ ‛ as quotes: names with them must still parse (and a non-ASCII one stay intact).
                "quotes": dict(user_code="UCODE", computer_code=None, ssid="Children\u2019s \u2018Guest\u2019 \"$x\"", wired=False, shared_pc=False,
                               org="Children\u2019s Szko\u0142a \u201aQ\u201b", user_label="Zo\u00eb \u2018Z\u2019 (zoe@corp.example)")}
    for name, kw in variants.items():
        kw = {"org": "O'Brien & Co <#x#>", "user_label": "Nina O'Neil (nina@corp.example)", **kw}
        o = ws.SetupOptions(api="https://easyeap.example/",
                            server_name="radius.corp.example", root_pem=_pem(root), issuing_pem=_pem(issuing), wpa3=False,
                            user_renew_days=30, computer_renew_days=45, expires="2026-11-10 12:00 UTC", pin=pins["tls"], **kw)
        (OUT / f"{name}.cmd").write_bytes(ws.build(o).encode())
        (OUT / f"{name}-renew.ps1").write_text(ws.renew_script(o))
    # The portal's helper, with its own renewal script (kind windows-helper).
    helper_renew = ws.renew_ps1(api="https://easyeap.example", kind="windows-helper", org="O'Brien & Co", root_pems=[_pem(root)],
                                issuing_pem=_pem(issuing), user_days=30, computer_days=30, pin=pins["tls"])
    (OUT / "helper-renew.ps1").write_text(helper_renew)
    (OUT / "helper.ps1").write_text(profiles.windows_powershell("https://easyeap.example", "TOKEN", "Corp's <Wi-Fi>", "radius.corp.example",
                                                                _pem(root), _pem(issuing), renew_ps1=helper_renew, pin=pins["tls"]))
    # As Windows PowerShell would read a helper without its BOM (ANSI): the renewal script inside must still parse.
    quoted = ws.renew_ps1(api="https://easyeap.example", kind="windows-helper", org="Children\u2019s Szko\u0142a", root_pems=[_pem(root)],
                          issuing_pem=_pem(issuing), user_days=30, computer_days=30)
    (OUT / "quotes-helper.ps1").write_text(profiles.windows_powershell("https://easyeap.example", "TOKEN", "Caf\u00e9 \u2018Guest\u2019 \"$x\"",
                                                                       "radius.corp.example", _pem(root), _pem(issuing), renew_ps1=quoted),
                                           encoding="utf-8-sig")  # served with a BOM
    (OUT / "quotes-renew-as-ansi.ps1").write_bytes(quoted.encode("utf-8").decode("cp1252", errors="replace").encode("utf-8"))
    # The certificates PowerShell signs renewals with: one ECDSA (P1363 signatures), one RSA (PKCS#1 v1.5).
    for kind, key in (("ec", ec.generate_private_key(ec.SECP256R1())), ("rsa", rsa.generate_private_key(public_exponent=65537, key_size=2048))):
        leaf = _cert(f"pc1.nina-{kind}", key, "Test Issuing", ik, ca=False)
        (OUT / f"{kind}.pfx").write_bytes(pkcs12.serialize_key_and_certificates(b"leaf", key, leaf, None, serialization.BestAvailableEncryption(b"test")))
        newkey = ec.generate_private_key(ec.SECP256R1())
        csr = x509.CertificateSigningRequestBuilder().subject_name(_name("EasyEAP")).sign(newkey, hashes.SHA256())
        pem = csr.public_bytes(serialization.Encoding.PEM).decode().replace("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST")
        (OUT / f"{kind}.csr").write_text(pem)  # as certreq writes it
    print("fixtures written")


def verify() -> None:
    bad = 0
    for kind in ("ec", "rsa"):
        # The v2 renewal: certificate, time, request and client block, as EasyEAP checks them.
        body = json.loads((OUT / f"{kind}-body.json").read_text())
        der = base64.b64decode(body["certificate"])
        cert = x509.load_der_x509_certificate(der)
        csr_der = enr._csr_der(body["csr"])
        client = body["client"]
        sig = base64.b64decode(body["signature"])
        ok = enr.verify_signature(cert, enr.renewal_message(der, int(body["signed_at"]), csr_der, client), sig)
        tampered = enr.verify_signature(cert, enr.renewal_message(der, int(body["signed_at"]) + 1, csr_der, client), sig)
        other_client = enr.verify_signature(cert, enr.renewal_message(der, int(body["signed_at"]), csr_der, client.replace("user", "computer")), sig)
        info = enr.parse_client(client)
        fresh = abs(NOW.timestamp() - int(body["signed_at"])) < 600
        good = (ok and not tampered and not other_client and fresh and body["key_storage"] == "software"
                and info == {"kind": "windows-setup", "version": "2.0", "scope": "user", "roots": ["ab" * 32], "profile_roots": []})
        bad += not good
        print(f"  {'PASS' if good else 'FAIL'} {kind} renewal: signature verifies={ok}, tampered time={tampered}, other client block={other_client}, "
              f"fresh={fresh}, client={info}, signature {len(sig)} bytes")
        # The check-in: certificate, time and client block.
        body = json.loads((OUT / f"{kind}-check.json").read_text())
        sig = base64.b64decode(body["signature"])
        ok = enr.verify_signature(cert, enr.check_message(der, int(body["signed_at"]), body["client"]), sig)
        tampered = enr.verify_signature(cert, enr.check_message(der, int(body["signed_at"]) - 1, body["client"]), sig)
        good = ok and not tampered and "csr" not in body and body["client"] == client
        bad += not good
        print(f"  {'PASS' if good else 'FAIL'} {kind} check-in: signature verifies={ok}, tampered time={tampered}")
    sys.exit(bad)


if __name__ == "__main__":
    {"make": make, "verify": verify}[sys.argv[1]]()
