"""Enrollment: one-time links (device-side keys, the default) and opt-in server-generated PKCS#12 (admin mode)."""
from __future__ import annotations

import base64
import secrets
import string
import uuid
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import models as m
from app.config import get_settings
from app.pki import crypto
from app.pki import service as pki
from app.pki.openbao import OpenBao
from app.policy.service import policy_settings, recompute_tenant
from app.security.tokens import new_token, token_hash

PLATFORMS = ("windows", "macos", "ios", "android", "linux")
METHODS = ("link", "server")
P12_ITERATIONS = 600_000


class EnrollmentError(ValueError):
    pass


def _expires(hours: int | None = None) -> datetime:
    return datetime.now(UTC) + timedelta(hours=hours or get_settings().enrollment_link_ttl_hours)


def create_link(session: Session, tenant: m.Tenant, identity: m.Identity, tpl: m.CertificateTemplate, device_name: str,
                platform: str, created_by: str, ttl_hours: int | None = None, renewal_of: uuid.UUID | None = None) -> tuple[m.Enrollment, str]:
    if identity.account_state != "enabled":
        raise EnrollmentError(f"This account is {identity.account_state} in the directory, so it cannot be enrolled.")
    if platform not in PLATFORMS:
        raise EnrollmentError("Choose a platform.")
    if not tpl.allow_client_keygen:
        raise EnrollmentError("This template only allows server-generated keys.")
    pki.issuing_ca(session, tenant.id)  # PKI must be initialised
    token = new_token(32)
    e = m.Enrollment(tenant_id=tenant.id, identity_id=identity.id, device_name=device_name.strip()[:120] or "Device", platform=platform,
                     method="link", template_id=tpl.id, token_hash=token_hash(token), status="pending", created_by=created_by,
                     expires_at=_expires(ttl_hours), renewal_of=renewal_of)
    session.add(e)
    session.flush()
    return e, token


def find_by_token(session: Session, token: str) -> m.Enrollment | None:
    """Platform-scoped lookup (the enrollee is not authenticated; the token is the credential)."""
    if not token or len(token) > 128:
        return None
    e = session.scalars(select(m.Enrollment).where(m.Enrollment.token_hash == token_hash(token))).first()
    if e is None:
        return None
    if e.status == "pending" and e.expires_at <= datetime.now(UTC):
        e.status = "expired"
    return e


def _device(session: Session, e: m.Enrollment, hint: str | None = None) -> m.Device:
    if e.device_id:
        d = session.get(m.Device, e.device_id)
        if d:
            return d
    d = m.Device(tenant_id=e.tenant_id, identity_id=e.identity_id, name=e.device_name or (hint or "Device")[:120], platform=e.platform)
    session.add(d)
    session.flush()
    e.device_id = d.id
    return d


def _names(session: Session, e: m.Enrollment) -> tuple[m.Tenant, m.Identity, m.CertificateTemplate, dict[str, str]]:
    tenant = session.get(m.Tenant, e.tenant_id)
    identity = session.get(m.Identity, e.identity_id)
    tpl = session.get(m.CertificateTemplate, e.template_id)
    if not tenant or not identity or not tpl:
        raise EnrollmentError("This enrollment is no longer valid.")
    if identity.account_state != "enabled":
        raise EnrollmentError("Your directory account is not enabled. Contact your IT team.")
    return tenant, identity, tpl, pki.names_for_identity(identity, e.device_name, tenant)


def complete_with_csr(session: Session, bao: OpenBao, e: m.Enrollment, csr_pem: str, key_origin: str) -> m.Certificate:
    if e.status != "pending":
        raise EnrollmentError("This enrollment link has already been used or has expired. Ask your IT team for a new one.")
    if key_origin not in ("device", "browser", "csr"):
        key_origin = "csr"
    try:
        crypto.csr_info(csr_pem)
    except ValueError as exc:
        raise EnrollmentError(str(exc)) from exc
    tenant, identity, tpl, names = _names(session, e)
    device = _device(session, e)
    cert = pki.sign_csr(session, bao, tenant, tpl, csr_pem, names, key_origin=key_origin, identity_id=identity.id,
                        device_id=device.id, enrollment_id=e.id)
    _finish(session, e, cert, identity)
    return cert


def _finish(session: Session, e: m.Enrollment, cert: m.Certificate, identity: m.Identity) -> None:
    e.status, e.completed_at, e.certificate_id, e.token_hash = "completed", datetime.now(UTC), cert.id, None
    identity.enrolled = True
    if e.renewal_of:
        old = session.get(m.Certificate, e.renewal_of)
        if old and old.status == "active":
            old.status = "superseded"
    recompute_tenant(session, e.tenant_id)


def generate_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits
    groups = ["".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(length // 5)]
    return "-".join(groups)


def build_pkcs12(key_pem: str, cert_pem: str, chain_pems: list[str], password: str, friendly_name: str, legacy: bool = False) -> bytes:
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    cas = [x509.load_pem_x509_certificate(p.encode()) for p in chain_pems if p]
    if legacy:
        # Compatibility for older Android/macOS keychains only; never the default.
        enc = (serialization.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(50_000)
               .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).hmac_hash(hashes.SHA1()).build(password.encode()))  # noqa: S303 — opt-in legacy format
    else:
        enc = (serialization.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(P12_ITERATIONS)
               .key_cert_algorithm(pkcs12.PBES.PBESv2SHA256AndAES256CBC).hmac_hash(hashes.SHA256()).build(password.encode()))
    return pkcs12.serialize_key_and_certificates(friendly_name.encode()[:64], key, cert, cas or None, enc)


def issue_server_side(session: Session, bao: OpenBao, tenant: m.Tenant, identity: m.Identity, tpl: m.CertificateTemplate,
                      device_name: str, platform: str, created_by: str, *, legacy_p12: bool = False,
                      ttl_hours: int | None = None) -> tuple[m.Enrollment, str, str]:
    """Admin mode. Returns (enrollment, one-time download token, PKCS#12 password). Requires the tenant setting and
    the template to allow server keygen. The key exists in plaintext only inside this call."""
    ps = policy_settings(session, tenant.id)
    if not ps.allow_server_keygen:
        raise EnrollmentError("Server-generated keys are turned off for this tenant (Settings → Enrollment).")
    if not tpl.allow_server_keygen:
        raise EnrollmentError("This template does not allow server-generated keys.")
    if identity.account_state != "enabled":
        raise EnrollmentError(f"This account is {identity.account_state} in the directory, so it cannot be enrolled.")
    token = new_token(32)
    e = m.Enrollment(tenant_id=tenant.id, identity_id=identity.id, device_name=device_name.strip()[:120] or "Device", platform=platform,
                     method="server", template_id=tpl.id, token_hash=token_hash(token), status="pending", created_by=created_by,
                     expires_at=_expires(ttl_hours))
    session.add(e)
    session.flush()
    _, _, _, names = _names(session, e)
    device = _device(session, e)
    cert, key_pem = pki.issue_with_server_key(session, bao, tenant, tpl, names, identity_id=identity.id, device_id=device.id, enrollment_id=e.id)
    issuing, root = pki.chain_pem(session, tenant.id)
    password = generate_password()
    p12 = build_pkcs12(key_pem, cert.certificate_pem, [issuing, root or ""], password, f"{identity.username} Wi-Fi", legacy=legacy_p12)
    del key_pem
    session.add(m.KeyEscrow(tenant_id=tenant.id, enrollment_id=e.id, p12_ct=crypto.encrypt(tenant.id, p12, bao), expires_at=e.expires_at))
    e.certificate_id = cert.id
    identity.enrolled = True
    recompute_tenant(session, tenant.id)
    return e, token, password


def take_escrow(session: Session, bao: OpenBao, e: m.Enrollment) -> bytes:
    """Return the PKCS#12 once, then delete it."""
    esc = session.scalars(select(m.KeyEscrow).where(m.KeyEscrow.enrollment_id == e.id)).first()
    if esc is None or e.status != "pending":
        raise EnrollmentError("This download has already been used or has expired. Ask your IT team for a new one.")
    if esc.expires_at <= datetime.now(UTC):
        session.delete(esc)
        e.status = "expired"
        raise EnrollmentError("This download has expired. Ask your IT team for a new one.")
    data = crypto.decrypt(e.tenant_id, esc.p12_ct, bao)
    session.delete(esc)
    e.status, e.completed_at, e.token_hash = "completed", datetime.now(UTC), None
    return data


def purge_expired(session: Session) -> int:
    """Platform-scoped job: delete expired escrow and expire stale links."""
    now = datetime.now(UTC)
    n = 0
    for esc in session.scalars(select(m.KeyEscrow).where(m.KeyEscrow.expires_at <= now)):
        session.delete(esc)
        n += 1
    for e in session.scalars(select(m.Enrollment).where(m.Enrollment.status == "pending", m.Enrollment.expires_at <= now)):
        e.status, e.token_hash = "expired", None
    return n


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()
