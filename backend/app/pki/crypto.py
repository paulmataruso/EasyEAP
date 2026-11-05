"""Envelope encryption of stored secrets with per-tenant OpenBao Transit keys, plus X.509 helpers.

Secrets (AD bind passwords, RADIUS shared secrets, escrowed PKCS#12, the RADIUS server key, admin TOTP seeds)
are encrypted by OpenBao; the database only ever holds `vault:v1:` ciphertext. Deleting a tenant's Transit key
crypto-shreds its secrets.
"""
from __future__ import annotations

import base64
import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app.pki.openbao import OpenBao


def _key_name(tenant_id: uuid.UUID | None) -> str:
    return "platform" if tenant_id is None else f"t-{tenant_id}"


def ensure_tenant_key(bao: OpenBao, tenant_id: uuid.UUID) -> None:
    if bao.read(f"transit/keys/{_key_name(tenant_id)}") is None:
        bao.write(f"transit/keys/{_key_name(tenant_id)}", {"type": "aes256-gcm96"})


def destroy_tenant_key(bao: OpenBao, tenant_id: uuid.UUID) -> None:
    name = _key_name(tenant_id)
    bao.write(f"transit/keys/{name}/config", {"deletion_allowed": True})
    bao.delete(f"transit/keys/{name}")


def encrypt(tenant_id: uuid.UUID | None, plaintext: bytes | str, bao: OpenBao | None = None) -> str:
    bao = bao or OpenBao()
    data = plaintext.encode() if isinstance(plaintext, str) else plaintext
    res = bao.write(f"transit/encrypt/{_key_name(tenant_id)}", {"plaintext": base64.b64encode(data).decode()})
    return res["data"]["ciphertext"]


def decrypt(tenant_id: uuid.UUID | None, ciphertext: str, bao: OpenBao | None = None) -> bytes:
    bao = bao or OpenBao()
    res = bao.write(f"transit/decrypt/{_key_name(tenant_id)}", {"ciphertext": ciphertext})
    return base64.b64decode(res["data"]["plaintext"])


def decrypt_str(tenant_id: uuid.UUID | None, ciphertext: str, bao: OpenBao | None = None) -> str:
    return decrypt(tenant_id, ciphertext, bao).decode()


# ── X.509 helpers (parsing and packaging only; no CA operations happen here) ──


@dataclass
class CertInfo:
    serial: str
    subject: str
    common_name: str
    sans: list[str]
    not_before: datetime
    not_after: datetime
    fingerprint_sha256: str
    key_algorithm: str
    issuer: str
    is_ca: bool


def load_cert(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode())


def key_algorithm_of(public_key) -> str:
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return {"secp256r1": "ecdsa-p256", "secp384r1": "ecdsa-p384"}.get(public_key.curve.name, f"ecdsa-{public_key.curve.name}")
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"rsa-{public_key.key_size}"
    return "unknown"


def cert_info(pem: str) -> CertInfo:
    cert = load_cert(pem)
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans += [f"dns:{n}" for n in ext.get_values_for_type(x509.DNSName)]
        sans += [f"email:{n}" for n in ext.get_values_for_type(x509.RFC822Name)]
        sans += [f"ip:{n}" for n in ext.get_values_for_type(x509.IPAddress)]
        for other in ext.get_values_for_type(x509.OtherName):
            if other.type_id.dotted_string == "1.3.6.1.4.1.311.20.2.3":
                sans.append(f"upn:{_decode_utf8_der(other.value)}")
    except x509.ExtensionNotFound:
        pass
    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    return CertInfo(
        serial=format(cert.serial_number, "X"),
        subject=cert.subject.rfc4514_string(),
        common_name=str(cn_attrs[0].value) if cn_attrs else "",
        sans=sans,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex().upper(),
        key_algorithm=key_algorithm_of(cert.public_key()),
        issuer=cert.issuer.rfc4514_string(),
        is_ca=is_ca,
    )


def _decode_utf8_der(value: bytes) -> str:
    # DER UTF8String: tag 0x0C, length, bytes (short form is enough for UPNs)
    if len(value) > 2 and value[0] == 0x0C:
        length = value[1]
        if length < 0x80:
            return value[2 : 2 + length].decode(errors="replace")
    return value.decode(errors="replace")


def normalize_serial(serial: str) -> str:
    """'3f:9a:0c' or '3F9A0C' → '3F9A0C' (no leading-zero stripping beyond OpenSSL's integer form)."""
    s = serial.replace(":", "").replace(" ", "").upper()
    return s.lstrip("0") or "0"


def bao_serial(serial: str) -> str:
    """'3F9A0C' → '3f:9a:0c' (OpenBao's serial format)."""
    s = serial.replace(":", "").lower()
    if len(s) % 2:
        s = "0" + s
    return ":".join(s[i : i + 2] for i in range(0, len(s), 2))


def csr_info(csr_pem: str) -> tuple[x509.CertificateSigningRequest, str]:
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    if not csr.is_signature_valid:
        raise ValueError("The certificate request signature is invalid.")
    algo = key_algorithm_of(csr.public_key())
    if algo not in {"ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"}:
        raise ValueError(f"Unsupported key type {algo}; use ECDSA P-256/P-384 or RSA 2048+.")
    return csr, algo


def encrypt_private_key_pem(key_pem: str, passphrase: str) -> bytes:
    """Re-encrypt a PEM private key as PKCS#8 under a passphrase (AES-256-CBC, PBKDF2 via BestAvailableEncryption)."""
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode()),
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
