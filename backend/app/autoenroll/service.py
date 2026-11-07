"""Group Policy autoenrollment: who's asking, which templates they get, and issuing (docs/plans/gpo-autoenrollment.md).

The routers (app/routers/autoenroll.py) authenticate the caller with Kerberos; everything after that is here.
"""
from __future__ import annotations

import base64
import logging
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app import audit
from app import models as m
from app.autoenroll import cms, soap
from app.autoenroll.kerberos import Caller, clean_text
from app.directory import ldap
from app.directory import sync as dsync
from app.pki import crypto
from app.pki import service as pki
from app.pki.openbao import OpenBao

log = logging.getLogger("easyeap.autoenroll")

KINDS = ("computer", "user")
TEMPLATE_NAMES = {"computer": "Domain computer", "user": "Domain user"}
COMMON_NAMES = {"computer": "EasyEAP-Computer", "user": "EasyEAP-User"}
ROLES = {"computer": "ae-computer", "user": "ae-user"}
REFRESH = timedelta(hours=6)            # re-read a known computer from AD after this long
PER_DEVICE_PER_DAY = 4                  # certificates per identity, template and PC in 24 hours
PER_IDENTITY_PER_DAY = 30               # per identity and template in 24 hours (hot desks, labs)
EVENTS_KEPT = 2000                      # request log rows kept per tenant
AD_DOWN_SECONDS = 60                    # after AD didn't answer, policy requests use what EasyEAP knows this long
_ad_down: dict[uuid.UUID, float] = {}
PROVIDER_STORAGE = {"microsoft platform crypto provider": "tpm", "microsoft software key storage provider": "software"}


class Denied(Exception):
    """A request EasyEAP refuses: `code` for the request log, `hresult` for Windows' event log."""

    def __init__(self, code: str, message: str, hresult: int = soap.CERTSRV_E_ENROLL_DENIED):
        super().__init__(message)
        self.code = code
        self.hresult = hresult


# ── Configuration ────────────────────────────────────────────────────────────


def _random_oid_root() -> str:
    """Like an AD forest's enterprise OID root: Microsoft's 1.3.6.1.4.1.311.21.8 plus random arcs, each below 2^24 so
    every Windows ASN.1 path (32-bit arcs) handles it."""
    arcs = [secrets.randbelow((1 << 24) - 1) + 1 for _ in range(5)] + [secrets.randbelow(254) + 1]
    return "1.3.6.1.4.1.311.21.8." + ".".join(map(str, arcs))


def ensure_config(session: Session, tenant_id: uuid.UUID) -> m.AutoenrollConfig:
    cfg = session.get(m.AutoenrollConfig, tenant_id)
    if cfg is None:
        cfg = m.AutoenrollConfig(tenant_id=tenant_id, enabled=False, computers=True, users=False,
                                 policy_id="{" + str(uuid.uuid4()).upper() + "}", oid_root=_random_oid_root(),
                                 service_account="easyeap-cep", keytab_info={}, keytab_test={}, require_channel_binding=True,
                                 response_format="unsigned")
        session.add(cfg)
        session.flush()
    return cfg


def realm(session: Session, tenant_id: uuid.UUID) -> str | None:
    d = session.get(m.DirectoryConfig, tenant_id)
    return d.domain.upper() if d and d.domain else None


def templates(session: Session, tenant_id: uuid.UUID) -> dict[str, m.CertificateTemplate]:
    rows = session.scalars(select(m.CertificateTemplate).where(m.CertificateTemplate.tenant_id == tenant_id,
                                                               m.CertificateTemplate.autoenroll_kind.is_not(None)))
    return {t.autoenroll_kind: t for t in rows if t.autoenroll_kind in KINDS}


def ensure_templates(session: Session, bao: OpenBao, tenant: m.Tenant, cfg: m.AutoenrollConfig) -> dict[str, m.CertificateTemplate]:
    """The two autoenroll templates and their CEL roles, created on first use."""
    have = templates(session, tenant.id)
    for kind in KINDS:
        tpl = have.get(kind)
        if tpl is None:
            tpl = m.CertificateTemplate(
                tenant_id=tenant.id, name=TEMPLATE_NAMES[kind], purpose=kind, key_algorithm="rsa-2048", validity_days=365,
                renew_before_days=42, extended_key_usage=["clientAuth"], key_usage=["digitalSignature"],
                subject_pattern="CN={dns}" if kind == "computer" else "CN={upn}",
                san_patterns=["dns:{dns}"] if kind == "computer" else ["upn:{upn}"],
                allow_client_keygen=True, allow_server_keygen=False, bao_role=ROLES[kind],
                template_oid=f"{cfg.oid_root}.{secrets.randbelow((1 << 24) - 1) + 1}.{secrets.randbelow((1 << 24) - 1) + 1}",
                revision_major=100, revision_minor=0, autoenroll_kind=kind)
            session.add(tpl)
            session.flush()
            have[kind] = tpl
        pki.write_autoenroll_role(bao, tenant.id, tpl)
    return have


def template_policy(tpl: m.CertificateTemplate) -> soap.TemplatePolicy:
    kind = tpl.autoenroll_kind or "user"
    eku = cms.seq(cms.oid("1.3.6.1.5.5.7.3.2"))
    return soap.TemplatePolicy(
        common_name=COMMON_NAMES[kind], display_name=f"EasyEAP {TEMPLATE_NAMES[kind].lower()}", oid=tpl.template_oid or "",
        major=tpl.revision_major, minor=tpl.revision_minor, validity_seconds=tpl.validity_days * 86400,
        renewal_seconds=tpl.renew_before_days * 86400, machine=kind == "computer",
        extensions=((soap.OID_TEMPLATE_EXT, False, cms.template_extension(tpl.template_oid or "", tpl.revision_major, tpl.revision_minor)),
                    (soap.OID_EKU, False, eku),
                    (soap.OID_KEY_USAGE, True, bytes.fromhex("03020780")),  # digitalSignature
                    (soap.OID_APP_POLICIES, False, cms.seq(eku))))


# ── Who's asking ─────────────────────────────────────────────────────────────


def _computer_from_directory(session: Session, tenant_id: uuid.UUID, name: str) -> ldap.DirComputer:
    dcfg = session.get(m.DirectoryConfig, tenant_id)
    if dcfg is None or not dcfg.enabled:
        raise Denied("no_directory", "The tenant has no Active Directory connection, which autoenrollment needs to check computers.")
    try:
        conn = ldap.connect(dsync.params(dcfg))
    except ldap.DirectoryError as exc:
        raise Denied("directory", f"EasyEAP couldn't reach Active Directory to check {name}: {exc}", soap.E_FAIL) from None
    try:
        found = ldap.lookup_computer(conn, dsync.params(dcfg), name)
    finally:
        conn.unbind()
    if found is None:
        raise Denied("not_computer", f"{name} isn't a computer account in Active Directory.")
    return found


def identify(session: Session, tenant_id: uuid.UUID, cfg: m.AutoenrollConfig, caller: Caller, *, now: datetime | None = None) -> m.Identity:
    """The identity behind a Kerberos principal. A computer is checked against AD (cached for REFRESH) and created on
    first contact; a user must be a synced, enabled identity. Raises Denied."""
    now = now or datetime.now(UTC)
    name = caller.name
    if caller.claims_computer:
        ident = session.scalars(select(m.Identity).where(
            m.Identity.tenant_id == tenant_id, m.Identity.kind == "computer", func.lower(m.Identity.username) == name.lower())).first()
        stale = ident is None or ident.last_synced_at is None or ident.last_synced_at < now - REFRESH
        c = None
        if stale and not (ident is not None and _ad_down.get(tenant_id, 0) > time.monotonic()):
            try:
                c = _computer_from_directory(session, tenant_id, name)
            except Denied as exc:
                if exc.code != "directory" or ident is None:
                    raise
                _ad_down[tenant_id] = time.monotonic() + AD_DOWN_SECONDS
                log.warning("Autoenrollment: AD unreachable, using what EasyEAP knows about %s: %s", name, exc)
        if c is not None:
            if not c.workstation:
                raise Denied("not_workstation", f"{name} isn't a workstation or member server account (it may be a domain controller, "
                                                "a read-only domain controller or a trust account).")
            if ident is not None and ident.object_guid != c.object_guid:
                # Another computer account has this name now: the old one was deleted (the PC rejoined) or renamed.
                # The old identity steps aside; the directory sync renames it or marks it deleted.
                _step_aside(session, ident)
                ident = None
            if ident is None:
                ident = session.scalars(select(m.Identity).where(m.Identity.tenant_id == tenant_id, m.Identity.object_guid == c.object_guid)).first()
                if ident is not None and ident.kind != "computer":
                    ident.kind = "computer"  # synced as a user by an older version or a broad user filter
            if ident is None:
                clash = session.scalars(select(m.Identity).where(m.Identity.tenant_id == tenant_id, m.Identity.username == c.username)).first()
                if clash is not None:
                    if clash.source != "ad":
                        raise Denied("name_taken", f"A local EasyEAP account is called {c.username}; rename it so the computer can "
                                                   "have its name.")
                    _step_aside(session, clash)
                ident = m.Identity(tenant_id=tenant_id, source="ad", kind="computer", object_guid=c.object_guid, username=c.username,
                                   display_name=c.name)
                session.add(ident)
            if c.group_sids is None and (ident.id is None or cfg.computer_group_id):
                raise Denied("directory", f"EasyEAP couldn't read {name}'s groups in Active Directory.", soap.E_FAIL)
            dsync.apply_computer(ident, c, _groups_by_sid(session, tenant_id), now)
            session.flush()
        if ident.account_state != "enabled":
            raise Denied("account_state", f"The computer account {name} is {ident.account_state} in Active Directory.")
        if cfg.computer_group_id and cfg.computer_group_id not in {g.id for g in ident.groups}:
            group = session.get(m.DirectoryGroup, cfg.computer_group_id)
            raise Denied("not_in_group", f"{name} isn't in {group.name if group else 'the computer group'}, which autoenrollment is "
                                         "limited to.", soap.CERTSRV_E_TEMPLATE_DENIED)
        return ident
    dcfg = session.get(m.DirectoryConfig, tenant_id)
    if dcfg is None or not dcfg.enabled:
        raise Denied("no_directory", "The tenant's Active Directory connection is off, so its users can't be checked.")
    ident = session.scalars(select(m.Identity).where(
        m.Identity.tenant_id == tenant_id, m.Identity.kind == "user", m.Identity.source == "ad",
        func.lower(m.Identity.username) == name.lower())).first()
    if ident is None:
        raise Denied("unknown_user", f"{name} isn't one of the tenant's synced users (outside the directory search base or "
                                     "filter, or not synced yet).", soap.CERTSRV_E_TEMPLATE_DENIED)
    if ident.account_state != "enabled":
        raise Denied("account_state", f"{name} is {ident.account_state} in Active Directory.")
    return ident


def _step_aside(session: Session, ident: m.Identity) -> None:
    """Free a name for another account; the identity keeps its history and state until the sync settles it."""
    ident.username = f"{ident.username}~{(ident.object_guid or str(ident.id))[:8]}"[:256]
    session.flush()  # before another identity takes the name (unique per tenant)


def _groups_by_sid(session: Session, tenant_id: uuid.UUID) -> dict[str, m.DirectoryGroup]:
    return {g.sid: g for g in session.scalars(select(m.DirectoryGroup).where(
        m.DirectoryGroup.tenant_id == tenant_id, m.DirectoryGroup.sid.is_not(None), m.DirectoryGroup.deleted.is_(False)))}


def confirm_computer(session: Session, tenant_id: uuid.UUID, cfg: m.AutoenrollConfig, ident: m.Identity,
                     now: datetime) -> ldap.DirComputer:
    """Before issuing: the computer account read from AD now, by objectGUID, not the cached identity. It must still
    be called what the PC's ticket says, be an enabled workstation, and be in the computer group; its DNS name and
    groups are refreshed for the certificate and the access decision. Raises Denied."""
    dcfg = session.get(m.DirectoryConfig, tenant_id)
    if dcfg is None or not dcfg.enabled:
        raise Denied("no_directory", "The tenant has no Active Directory connection, which autoenrollment needs to check computers.")
    try:
        conn = ldap.connect(dsync.params(dcfg))
    except ldap.DirectoryError as exc:
        raise Denied("directory", f"EasyEAP couldn't reach Active Directory to check {ident.username} before issuing: {exc}",
                     soap.E_FAIL) from None
    try:
        c = ldap.lookup_computer_by_guid(conn, dsync.params(dcfg), ident.object_guid or "") if ident.object_guid else None
    except ldap.DirectoryError as exc:
        raise Denied("directory", f"Active Directory didn't answer for {ident.username}: {exc}", soap.E_FAIL) from None
    finally:
        conn.unbind()
    if c is None or c.username.lower() != ident.username.lower():
        now_called = f"is now {c.username}" if c is not None else "was deleted"
        raise Denied("not_computer", f"The computer account EasyEAP knows as {ident.username} {now_called} in Active Directory, so "
                                     "this request is from another account with the old name. EasyEAP checks again at the next "
                                     "request.", soap.E_FAIL)
    if not c.workstation:
        raise Denied("not_workstation", f"{ident.username} isn't a workstation or member server account.")
    if c.group_sids is None:
        raise Denied("directory", f"EasyEAP couldn't read {ident.username}'s groups in Active Directory.", soap.E_FAIL)
    dsync.apply_computer(ident, c, _groups_by_sid(session, tenant_id), now)
    session.flush()
    if ident.account_state != "enabled":
        raise Denied("account_state", f"The computer account {ident.username} is {ident.account_state} in Active Directory.")
    if cfg.computer_group_id and cfg.computer_group_id not in {g.id for g in ident.groups}:
        raise Denied("not_in_group", f"{ident.username} isn't in the computer group autoenrollment is limited to.",
                     soap.CERTSRV_E_TEMPLATE_DENIED)
    return c


def dns_name_problem(session: Session, tenant_id: uuid.UUID, ident: m.Identity, domain: str | None) -> str | None:
    """Whoever creates a computer account can write its dNSHostName, so the name the certificate gets must be the
    account's own: its first label the computer's name (NetBIOS names are cut to 15 characters), in the AD domain, and
    no other enabled computer's."""
    dns = (ident.dns_name or "").lower().rstrip(".")
    short = ident.username.lower().removesuffix("$")
    label, _, suffix = dns.partition(".")
    if not (label == short or (len(short) == 15 and label.startswith(short))):
        return f"{ident.username}'s DNS host name {dns} doesn't match its account name."
    if domain and suffix != domain.lower() and not suffix.endswith("." + domain.lower()):
        return (f"{ident.username}'s DNS host name {dns} isn't in the Active Directory domain {domain.lower()} (a disjoint "
                "namespace isn't supported).")
    other = session.scalars(select(m.Identity.username).where(
        m.Identity.tenant_id == tenant_id, m.Identity.kind == "computer", m.Identity.id != ident.id,
        m.Identity.account_state == "enabled", func.lower(m.Identity.dns_name) == dns)).first()
    if other:
        return f"{other} has the same DNS host name ({dns}) in Active Directory."
    return None


def offered(cfg: m.AutoenrollConfig, tpls: dict[str, m.CertificateTemplate], identity: m.Identity) -> list[m.CertificateTemplate]:
    """The templates a caller may autoenroll for: the computer one for computers, the user one for users, when on."""
    kind = identity.kind if identity.kind in KINDS else "user"
    on = cfg.enabled and (cfg.computers if kind == "computer" else cfg.users)
    tpl = tpls.get(kind)
    return [tpl] if on and tpl is not None and tpl.template_oid else []


# ── Enrollment ───────────────────────────────────────────────────────────────


@dataclass
class Issued:
    certificate: m.Certificate
    response_der: bytes   # the CMC full PKI response (or the PKCS#7) for BinarySecurityToken
    certificate_der: bytes


def _storage(csr_der: bytes) -> str | None:
    """Where Windows made the key, from the request's provider attribute (1.3.6.1.4.1.311.13.2.2)."""
    marker = cms.oid("1.3.6.1.4.1.311.13.2.2")
    i = csr_der.find(marker)
    if i < 0:
        return None
    try:
        j = csr_der.index(b"\x1e", i + len(marker))  # the BMPString provider name
        _, cs, ce = cms.read_tlv(csr_der, j)
        name = csr_der[cs:ce].decode("utf-16-be", "replace").strip().lower()
    except ValueError:
        return None
    return PROVIDER_STORAGE.get(name)


def _device(session: Session, identity: m.Identity, machine: str) -> m.Device:
    short = machine.split(".", 1)[0][:120] or machine[:120]
    dev = session.scalars(select(m.Device).where(m.Device.identity_id == identity.id, func.lower(m.Device.name) == short.lower(),
                                                 m.Device.platform == "windows")).first()
    if dev is None:
        dev = m.Device(tenant_id=identity.tenant_id, identity_id=identity.id, name=short, platform="windows")
        session.add(dev)
        session.flush()
    return dev


def _choose_template(csr: x509.CertificateSigningRequest, allowed: list[m.CertificateTemplate], kind: str) -> m.CertificateTemplate:
    tpl_oid, tpl_name = cms.template_of(csr)
    if tpl_oid:
        for t in allowed:
            if t.template_oid == tpl_oid:
                return t
        raise Denied("template", f"The request is for template {tpl_oid}, which this {kind} may not enroll for.", soap.CERTSRV_E_TEMPLATE_DENIED)
    if tpl_name:
        for t in allowed:
            if COMMON_NAMES.get(t.autoenroll_kind or "") == tpl_name:
                return t
    if allowed:
        return allowed[0]
    raise Denied("template", f"No autoenrollment template is on for this {kind}.", soap.CERTSRV_E_TEMPLATE_DENIED)


def _ttl(session: Session, tenant_id: uuid.UUID, tpl: m.CertificateTemplate, now: datetime) -> timedelta:
    """The template's validity, unless the issuing CA expires sooner. A certificate cut so short that it's already in
    its renewal period would make every PC enroll again at every refresh, so that's refused instead."""
    ttl = timedelta(days=tpl.validity_days)
    ca = pki.issuing_ca(session, tenant_id)
    left = ca.not_after - now - timedelta(hours=1)
    if left < ttl:
        if left < timedelta(days=tpl.renew_before_days + 1):
            raise Denied("ca_expiring", f"The issuing CA expires on {ca.not_after:%Y-%m-%d}, too soon to issue a certificate that "
                                        f"isn't already due for renewal ({tpl.renew_before_days} days). Renew the issuing CA.", soap.E_FAIL)
        ttl = left
    return ttl


def _limits(session: Session, identity: m.Identity, tpl: m.CertificateTemplate, device: m.Device | None, now: datetime) -> None:
    since = now - timedelta(days=1)
    base = select(func.count()).select_from(m.Certificate).where(
        m.Certificate.identity_id == identity.id, m.Certificate.template_id == tpl.id, m.Certificate.created_at >= since)
    if device is not None and (session.scalar(base.where(m.Certificate.device_id == device.id)) or 0) >= PER_DEVICE_PER_DAY:
        raise Denied("limit", f"{identity.username} already got {PER_DEVICE_PER_DAY} certificates on {device.name} in the last 24 hours.")
    n = session.scalar(base) or 0
    cap = PER_DEVICE_PER_DAY if identity.kind == "computer" else PER_IDENTITY_PER_DAY
    if n >= cap:
        raise Denied("limit", f"{identity.username} already got {n} certificates from this template in the last 24 hours.")


def _supersede(session: Session, identity: m.Identity, tpl: m.CertificateTemplate, device: m.Device | None, new: m.Certificate,
               now: datetime, *, setup_file_too: bool = False) -> int:
    """Mark the certificates the new one replaces as superseded (still accepted until they expire, as after any
    renewal). With `setup_file_too`, that includes the computer certificate a Windows setup file made on a PC of the
    same name, so its renewal task stops: one PC, one machine certificate source."""
    q = select(m.Certificate).where(m.Certificate.identity_id == identity.id, m.Certificate.template_id == tpl.id,
                                    m.Certificate.id != new.id, m.Certificate.status == "active", m.Certificate.renewed_at.is_(None))
    if device is not None:
        q = q.where(m.Certificate.device_id == device.id)
    old = list(session.scalars(q))
    if setup_file_too:
        old += list(session.scalars(
            select(m.Certificate).join(m.Device, m.Device.id == m.Certificate.device_id)
            .join(m.Enrollment, m.Enrollment.id == m.Certificate.enrollment_id)
            .where(m.Certificate.tenant_id == identity.tenant_id, m.Certificate.purpose == "device", m.Certificate.status == "active",
                   m.Certificate.renewed_at.is_(None), m.Enrollment.method == "windows-setup",
                   func.lower(m.Device.name) == (identity.display_name or "").lower())))
    for c in old:
        c.status, c.renewed_at = "superseded", now
    if old:
        new.renewal_of = max(old, key=lambda c: c.not_after).id
    return len(old)


def _chain_der(session: Session, tenant_id: uuid.UUID) -> list[bytes]:
    issuing, root = pki.chain_pem(session, tenant_id)
    out = [x509.load_pem_x509_certificate(issuing.encode()).public_bytes(serialization.Encoding.DER)]
    if root:
        out.append(x509.load_pem_x509_certificate(root.encode()).public_bytes(serialization.Encoding.DER))
    return out


def enroll(session: Session, bao: OpenBao, tenant: m.Tenant, cfg: m.AutoenrollConfig, identity: m.Identity,
           req: soap.RequestSecurityToken, *, now: datetime | None = None) -> tuple[Issued, cms.ParsedRequest]:
    """Issue a certificate for one WSTEP request. Raises Denied."""
    now = now or datetime.now(UTC)
    # One request per identity at a time: the daily limits and superseding count what's already there.
    session.execute(select(m.Identity.id).where(m.Identity.id == identity.id).with_for_update())
    if req.request_type and req.request_type != soap.REQUEST_ISSUE:
        raise Denied("request_type", f"Only certificate requests (Issue) are supported, not {req.request_type.rsplit('/', 1)[-1]}.",
                     soap.E_INVALIDARG)
    try:
        parsed = cms.parse_request(req.token)
    except ValueError as exc:
        raise Denied("bad_request", f"The certificate request can't be used: {exc}", soap.E_INVALIDARG) from None
    problem = cms.key_problem(parsed.csr)
    if problem:
        raise Denied("key", problem, soap.CERTSRV_E_KEY_LENGTH)
    kind = identity.kind if identity.kind in KINDS else "user"
    tpl = _choose_template(parsed.csr, offered(cfg, templates(session, tenant.id), identity), kind)

    device, computer = None, None
    if kind == "user":
        machine = parsed.machine or req.context.get("ccm") or req.context.get("rmd")
        device = _device(session, identity, machine) if machine else None
        names = pki.names_for_identity(identity, "", tenant)
        common_name, san = names["upn"], cms.san_extension(upn=names["upn"])
    else:
        computer = confirm_computer(session, tenant.id, cfg, identity, now)
        if not identity.dns_name:
            raise Denied("no_dns_name", f"{identity.username} has no DNS host name (dNSHostName) in Active Directory, which the "
                                        "certificate is issued to.", soap.CERTSRV_E_BAD_REQUESTSUBJECT)
        problem = dns_name_problem(session, tenant.id, identity, realm(session, tenant.id))
        if problem:
            raise Denied("dns_name", problem, soap.CERTSRV_E_BAD_REQUESTSUBJECT)
        common_name, san = identity.dns_name, cms.san_extension(dns=[identity.dns_name])
    _limits(session, identity, tpl, device, now)
    ttl = _ttl(session, tenant.id, tpl, now)

    csr_pem = parsed.csr.public_bytes(serialization.Encoding.PEM).decode()
    cert = pki.sign_autoenroll(session, bao, tenant, tpl, csr_pem, common_name=common_name, san_der=san,
                               template_ext_der=cms.template_extension(tpl.template_oid or "", tpl.revision_major, tpl.revision_minor),
                               ttl=ttl, identity_id=identity.id, device_id=device.id if device else None)
    cert.enrollment_source = "gpo"
    cert.key_storage = _storage(parsed.csr.public_bytes(serialization.Encoding.DER))
    # A computer a user added with their machine account quota could be named after another PC: it doesn't stop that
    # PC's setup-file certificate.
    replaced = _supersede(session, identity, tpl, device, cert, now,
                          setup_file_too=kind == "computer" and computer is not None and not computer.added_by_user)
    session.flush()

    from app.policy.service import decide_certificate  # local import: policy imports models only
    decide_certificate(session, cert)
    audit.record(session, audit.Actor("system", f"Group Policy ({identity.username})"), "certificate.autoenrolled", tenant_id=tenant.id,
                 target_type="certificate", target_id=cert.id, target_label=cert.common_name,
                 detail={"identity": identity.username, "kind": kind, "template": tpl.name, "serial": cert.serial,
                         "machine": device.name if device else None, "key_storage": cert.key_storage, "replaced": replaced,
                         "request_form": parsed.form})

    leaf_der = x509.load_pem_x509_certificate(cert.certificate_pem.encode()).public_bytes(serialization.Encoding.DER)
    chain = [leaf_der, *_chain_der(session, tenant.id)]
    content = cms.pki_response(issued_der=leaf_der, body_part=parsed.body_part_id)
    if cfg.response_format == "pkcs7":
        response = cms.chain_pkcs7(chain)
    elif cfg.response_format == "signed":
        signer_cert, signer_key = signer(session, bao, tenant, cfg, now=now)
        response = cms.signed_response(content, chain, signer_cert, signer_key)
    else:
        response = cms.unsigned_response(content, chain)
    return Issued(certificate=cert, response_der=response, certificate_der=leaf_der), parsed


# ── The enrollment-service certificate (response format "signed") ─────────


def signer(session: Session, bao: OpenBao, tenant: m.Tenant, cfg: m.AutoenrollConfig, *, now: datetime | None = None):
    """(certificate, key) that signs CMC responses when the response format is "signed": RSA 2048, issued by the
    tenant's issuing CA through the computer template's role, key encrypted with the tenant's Transit key; replaced
    30 days before it expires."""
    now = now or datetime.now(UTC)
    if cfg.signer_cert_pem and cfg.signer_key_ct:
        cert = x509.load_pem_x509_certificate(cfg.signer_cert_pem.encode())
        if cert.not_valid_after_utc - now > timedelta(days=30):
            key = serialization.load_der_private_key(crypto.decrypt(tenant.id, cfg.signer_key_ct, bao), None)
            return cert, key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = f"EasyEAP enrollment service ({tenant.slug})"
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])) \
        .sign(key, hashes.SHA256())
    tpl = templates(session, tenant.id)["computer"]
    data = bao.write(f"{pki.tenant_mount(tenant.id)}/cel/sign/{tpl.bao_role}", {
        "csr": csr.public_bytes(serialization.Encoding.PEM).decode(), "cn": name,
        "san": base64.b64encode(cms.san_extension(dns=[f"enrollment-service.{tenant.slug}.invalid"])).decode(),
        "template_ext": base64.b64encode(cms.template_extension(tpl.template_oid or "", 1, 0)).decode(),
        "ttl": f"{min(365, tpl.validity_days) * 86400}s"})["data"]
    cfg.signer_cert_pem = data["certificate"]
    cfg.signer_key_ct = crypto.encrypt(tenant.id, key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                                                    serialization.NoEncryption()), bao)
    session.flush()
    return x509.load_pem_x509_certificate(data["certificate"].encode()), key


# ── Request log ──────────────────────────────────────────────────────────────


def record_event(session: Session, tenant_id: uuid.UUID, *, service: str, caller: str, kind: str | None, outcome: str, code: str = "",
                 message: str = "", template: str | None = None, machine: str | None = None, certificate_id: uuid.UUID | None = None,
                 ip: str | None = None) -> m.AutoenrollEvent:
    message = clean_text(message)
    ev = m.AutoenrollEvent(tenant_id=tenant_id, service=service, caller=clean_text(caller, 256), kind=kind, outcome=outcome, code=code[:32],
                           message=message, template=template, machine=(machine or None) and machine[:253],
                           certificate_id=certificate_id, ip=ip)
    session.add(ev)
    session.flush()
    if ev.id % 200 == 0:  # keep the log bounded
        cutoff = session.scalar(select(m.AutoenrollEvent.id).where(m.AutoenrollEvent.tenant_id == tenant_id)
                                .order_by(m.AutoenrollEvent.id.desc()).offset(EVENTS_KEPT).limit(1))
        if cutoff:
            session.execute(delete(m.AutoenrollEvent).where(m.AutoenrollEvent.tenant_id == tenant_id, m.AutoenrollEvent.id <= cutoff))
    cfg = session.get(m.AutoenrollConfig, tenant_id)
    if cfg is not None:
        if outcome == "ok":
            cfg.last_success_at = datetime.now(UTC)
        elif outcome == "error" or code in ("keytab", "binding", "ntlm", "directory"):
            cfg.last_error_at, cfg.last_error = datetime.now(UTC), message
    return ev
