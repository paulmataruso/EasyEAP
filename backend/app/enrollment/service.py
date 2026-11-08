"""Enrollment: one-time links (device-side keys, the default) and opt-in server-generated PKCS#12 (admin mode)."""
from __future__ import annotations

import base64
import hashlib
import secrets
import string
import uuid
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
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
# Enrollments made by the Windows setup (docs/plans/windows-setup.md): the PC reports its own name.
WINDOWS_SETUP = "windows-setup"
PC_PLACEHOLDER = "Windows PC"
KEY_STORAGE = ("tpm", "software")
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
                     method="link", template_id=tpl.id, token_hash=token_hash(token), token_ct=crypto.encrypt(tenant.id, token),
                     status="pending", created_by=created_by, expires_at=_expires(ttl_hours), renewal_of=renewal_of)
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
        e.status, e.token_ct = "expired", None
    return e


def link_token(e: m.Enrollment, bao: OpenBao | None = None) -> str | None:
    """The token of a pending, unexpired link enrollment, for the admin to copy again; None when there's none to show
    (used, cancelled, expired, or created before EasyEAP kept links)."""
    if e.method != "link" or e.status != "pending" or e.token_ct is None or e.expires_at <= datetime.now(UTC):
        return None
    return crypto.decrypt_str(e.tenant_id, e.token_ct, bao)


def _pc_name(hint: str | None) -> str | None:
    """A computer name as Windows reports it ($env:COMPUTERNAME): letters, digits and dashes, at most 63."""
    name = "".join(c for c in (hint or "").strip() if c.isalnum() or c in "-_")[:63]
    return name or None


def _device(session: Session, e: m.Enrollment, hint: str | None = None) -> m.Device:
    if e.device_id:
        d = session.get(m.Device, e.device_id)
        if d:
            # The Windows setup creates the PC's device before it knows the name; the first request names it.
            if e.method == WINDOWS_SETUP and d.name == PC_PLACEHOLDER and _pc_name(hint):
                d.name = _pc_name(hint)
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


def complete_with_csr(session: Session, bao: OpenBao, e: m.Enrollment, csr_pem: str, key_origin: str, *,
                      key_storage: str | None = None, device_hint: str | None = None) -> m.Certificate:
    if e.status != "pending":
        raise EnrollmentError("This enrollment link has already been used or has expired. Ask your IT team for a new one.")
    if key_origin not in ("device", "browser", "csr"):
        key_origin = "csr"
    try:
        crypto.csr_info(csr_pem)
    except ValueError as exc:
        raise EnrollmentError(str(exc)) from exc
    device = _device(session, e, device_hint)
    if e.method == WINDOWS_SETUP and e.device_name == PC_PLACEHOLDER:
        e.device_name = device.name  # the PC's own name, for the certificate's {device}
    tenant, identity, tpl, names = _names(session, e)
    cert = pki.sign_csr(session, bao, tenant, tpl, csr_pem, names, key_origin=key_origin, identity_id=identity.id,
                        device_id=device.id, enrollment_id=e.id)
    cert.key_storage = key_storage if key_storage in KEY_STORAGE else None
    _finish(session, e, cert, identity)
    return cert


def _finish(session: Session, e: m.Enrollment, cert: m.Certificate, identity: m.Identity) -> None:
    e.status, e.completed_at, e.certificate_id, e.token_ct = "completed", datetime.now(UTC), cert.id, None
    identity.enrolled = True
    if e.renewal_of:
        old = session.get(m.Certificate, e.renewal_of)
        if old and old.status == "active":
            old.status = "superseded"
    recompute_tenant(session, e.tenant_id)


def create_windows_setup(session: Session, tenant: m.Tenant, identity: m.Identity, *, user: bool, computer: bool, created_by: str,
                         ttl_hours: int | None = None) -> tuple[m.Device, dict[str, tuple[m.Enrollment, str, m.CertificateTemplate]]]:
    """The enrollments behind one Windows setup download (docs/plans/windows-setup.md §4): the user's certificate
    and the PC's own (a device certificate of the same user, in the computer's store). Both belong to one Device,
    named by the PC when it first asks. Returns the device and {"user"|"device": (enrollment, one-time code, template)}."""
    if identity.account_state != "enabled":
        raise EnrollmentError(f"This account is {identity.account_state} in the directory, so it cannot be enrolled.")
    if not user and not computer:
        raise EnrollmentError("Choose the user's certificate, the computer's, or both.")
    pki.issuing_ca(session, tenant.id)
    templates = {}
    for purpose in [p for p, on in (("user", user), ("device", computer)) if on]:
        tpl = session.scalars(select(m.CertificateTemplate).where(m.CertificateTemplate.tenant_id == tenant.id, m.CertificateTemplate.purpose == purpose,
                                                                  m.CertificateTemplate.allow_client_keygen.is_(True),
                                                                  m.CertificateTemplate.autoenroll_kind.is_(None))
                              .order_by(m.CertificateTemplate.created_at)).first()
        if tpl is None:
            raise EnrollmentError(f"No {purpose} certificate template accepts keys made on the device.")
        templates[purpose] = tpl
    device = m.Device(tenant_id=tenant.id, identity_id=identity.id, name=PC_PLACEHOLDER, platform="windows")
    session.add(device)
    session.flush()
    out = {}
    for purpose, tpl in templates.items():
        token = new_token(32)
        e = m.Enrollment(tenant_id=tenant.id, identity_id=identity.id, device_id=device.id, device_name=PC_PLACEHOLDER, platform="windows",
                         method=WINDOWS_SETUP, template_id=tpl.id, token_hash=token_hash(token), status="pending", created_by=created_by,
                         expires_at=_expires(ttl_hours))
        session.add(e)
        out[purpose] = (e, token, tpl)
    session.flush()
    return device, out


# ── Renewal by the certificate's own key ─────────────────────────────────────

RENEW_SKEW = timedelta(minutes=10)


def renewal_message(certificate_der: bytes, signed_at: int, csr_der: bytes) -> bytes:
    """What the current certificate's key signs to renew it. Binds the certificate, the time and the new request."""
    return (f"easyeap-renew-v1|{hashlib.sha256(certificate_der).hexdigest()}|{signed_at}|"
            f"{hashlib.sha256(csr_der).hexdigest()}").encode()


def verify_signature(cert: x509.Certificate, message: bytes, signature: bytes) -> bool:
    """ECDSA (IEEE P1363 r||s as .NET's SignData returns it, or DER) or RSA PKCS#1 v1.5, SHA-256."""
    pub = cert.public_key()
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            n = (pub.curve.key_size + 7) // 8
            if len(signature) == 2 * n:
                signature = encode_dss_signature(int.from_bytes(signature[:n], "big"), int.from_bytes(signature[n:], "big"))
            pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False
    except InvalidSignature:
        return False
    return True


def _spki(key) -> bytes:
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def renew(session: Session, bao: OpenBao, *, certificate_der: bytes, csr_pem: str, signed_at: int, signature: bytes,
          key_storage: str | None, now: datetime | None = None) -> tuple[m.Certificate, m.Certificate | None]:
    """Renew a certificate on behalf of its key holder (docs/plans/windows-setup.md §4). Returns (current, new); new is
    None when the certificate isn't inside its renewal window yet. The session must be platform-scoped."""
    now = now or datetime.now(UTC)
    fingerprint = hashlib.sha256(certificate_der).hexdigest().upper()  # as crypto.cert_info stores it
    old = session.scalars(select(m.Certificate).where(m.Certificate.fingerprint_sha256 == fingerprint)).first()
    if old is None:
        raise EnrollmentError("EasyEAP didn't issue this certificate.")
    if abs(now.timestamp() - signed_at) > RENEW_SKEW.total_seconds():
        raise EnrollmentError("The request's time is more than 10 minutes off. Check the computer's clock.")
    if not verify_signature(x509.load_der_x509_certificate(certificate_der), renewal_message(certificate_der, signed_at, _csr_der(csr_pem)), signature):
        raise EnrollmentError("The request isn't signed by this certificate's key.")
    if old.status == "revoked":
        raise EnrollmentError("This certificate was revoked, so it can't be renewed. Enroll again.")
    if old.status == "superseded" or old.renewed_at is not None:
        again = _earlier_renewal(session, old, csr_pem, now)
        if again is not None:  # the answer to the same request got lost on the way: send it again
            return old, again
        raise EnrollmentError("This certificate was already renewed. Use the newer one.")
    if old.not_after <= now:
        raise EnrollmentError("This certificate has expired, so it can't be renewed. Enroll again.")
    if old.purpose not in ("user", "device") or old.identity_id is None:
        raise EnrollmentError("This kind of certificate isn't renewed this way.")
    identity = session.get(m.Identity, old.identity_id)
    tpl = session.get(m.CertificateTemplate, old.template_id) if old.template_id else None
    tenant = session.get(m.Tenant, old.tenant_id)
    if identity is None or tpl is None or tenant is None or tenant.status != "active":
        raise EnrollmentError("This certificate's user or template no longer exists. Enroll again.")
    if tpl.autoenroll_kind:
        raise EnrollmentError("Windows renews this certificate itself, through Group Policy autoenrollment.")
    if identity.account_state != "enabled":
        raise EnrollmentError(f"The account is {identity.account_state} in the directory, so its certificate isn't renewed.")
    if now < old.not_after - timedelta(days=tpl.renew_before_days):
        return old, None
    try:
        csr, _ = crypto.csr_info(csr_pem)
    except ValueError as exc:
        raise EnrollmentError(str(exc)) from exc
    if _spki(csr.public_key()) == _spki(x509.load_der_x509_certificate(certificate_der).public_key()):
        raise EnrollmentError("The renewal request must use a new key.")
    device = session.get(m.Device, old.device_id) if old.device_id else None
    names = pki.names_for_identity(identity, device.name if device else "device", tenant)
    new = pki.sign_csr(session, bao, tenant, tpl, csr_pem, names, key_origin=old.key_origin, identity_id=identity.id,
                       device_id=old.device_id, enrollment_id=old.enrollment_id)
    new.key_storage = key_storage if key_storage in KEY_STORAGE else None
    new.renewal_of = old.id
    old.status, old.renewed_at = "superseded", now  # still accepted until it expires, as after any renewal
    recompute_tenant(session, tenant.id)
    return old, new


def _earlier_renewal(session: Session, old: m.Certificate, csr_pem: str, now: datetime) -> m.Certificate | None:
    """The certificate an earlier renewal of `old` issued for this request's key, still valid; else None. A client
    whose renewal answer was lost (timeout, sleep, Wi-Fi drop) keeps its pending key and asks again with it."""
    prev = session.scalars(select(m.Certificate).where(m.Certificate.renewal_of == old.id).order_by(m.Certificate.not_after.desc())).first()
    if prev is None or prev.status != "active" or prev.not_after <= now:
        return None
    try:
        csr, _ = crypto.csr_info(csr_pem)
        issued = x509.load_pem_x509_certificate(prev.certificate_pem.encode())
    except ValueError:
        return None
    return prev if _spki(csr.public_key()) == _spki(issued.public_key()) else None


def _csr_der(csr_pem: str) -> bytes:
    try:
        return x509.load_pem_x509_csr(csr_pem.encode()).public_bytes(serialization.Encoding.DER)
    except ValueError as exc:
        raise EnrollmentError("The certificate request isn't valid.") from exc


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
    e.status, e.completed_at = "completed", datetime.now(UTC)
    return data


def purge_expired(session: Session) -> int:
    """Platform-scoped job: delete expired escrow and expire stale links."""
    now = datetime.now(UTC)
    n = 0
    for esc in session.scalars(select(m.KeyEscrow).where(m.KeyEscrow.expires_at <= now)):
        session.delete(esc)
        n += 1
    for e in session.scalars(select(m.Enrollment).where(m.Enrollment.status == "pending", m.Enrollment.expires_at <= now)):
        e.status, e.token_ct = "expired", None
    return n


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()
