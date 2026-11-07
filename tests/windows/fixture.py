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

from app.enrollment import service as enr
from app.enrollment import windows_setup as ws

OUT = Path(sys.argv[2] if len(sys.argv) > 2 else "/out")
NOW = dt.datetime.now(dt.UTC)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(cn: str, key, issuer: str, ikey, *, ca: bool) -> x509.Certificate:
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(issuer)).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(NOW - dt.timedelta(minutes=5)).not_valid_after(NOW + dt.timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if not ca:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    return b.sign(ikey, hashes.SHA256())


def _pem(c: x509.Certificate) -> str:
    return c.public_bytes(serialization.Encoding.PEM).decode()


def make() -> None:
    rk, ik = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    root, issuing = _cert("Test Root", rk, "Test Root", rk, ca=True), _cert("Test Issuing", ik, "Test Root", rk, ca=True)
    variants = {"full": dict(user_code="UCODE", computer_code="CCODE", ssid="Corp's <Wi-Fi>", wired=True, shared_pc=False),
                "user-only": dict(user_code="UCODE", computer_code=None, ssid="Corp", wired=False, shared_pc=False),
                "shared-pc": dict(user_code=None, computer_code="CCODE", ssid=None, wired=True, shared_pc=True)}
    for name, kw in variants.items():
        o = ws.SetupOptions(api="https://easyeap.example/", org="O'Brien & Co <#x#>", user_label="Nina O'Neil (nina@corp.example)",
                            server_name="radius.corp.example", root_pem=_pem(root), issuing_pem=_pem(issuing), wpa3=False,
                            user_renew_days=30, computer_renew_days=45, expires="2026-11-10 12:00 UTC", **kw)
        (OUT / f"{name}.cmd").write_bytes(ws.build(o).encode())
        (OUT / f"{name}-renew.ps1").write_text(ws.renew_script(o))
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
        body = json.loads((OUT / f"{kind}-body.json").read_text())
        der = base64.b64decode(body["certificate"])
        cert = x509.load_der_x509_certificate(der)
        csr_der = enr._csr_der(body["csr"])
        message = enr.renewal_message(der, int(body["signed_at"]), csr_der)
        sig = base64.b64decode(body["signature"])
        ok = enr.verify_signature(cert, message, sig)
        tampered = enr.verify_signature(cert, enr.renewal_message(der, int(body["signed_at"]) + 1, csr_der), sig)
        fresh = abs(NOW.timestamp() - int(body["signed_at"])) < 600
        good = ok and not tampered and fresh and body["key_storage"] == "software"
        bad += not good
        print(f"  {'PASS' if good else 'FAIL'} {kind}: PowerShell's signature verifies={ok}, tampered time verifies={tampered}, fresh={fresh}, "
              f"signature {len(sig)} bytes")
    sys.exit(bad)


if __name__ == "__main__":
    {"make": make, "verify": verify}[sys.argv[1]]()
