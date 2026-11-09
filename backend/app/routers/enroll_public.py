"""End-user enrollment portal API. The one-time token in the URL is the only credential."""
from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app import audit
from app import models as m
from app.autoenroll.kerberos import PROXY_CERT
from app.config import get_settings
from app.db import set_platform, set_tenant
from app.deps import client_ip, db
from app.enrollment import linux_setup, profiles, windows_setup
from app.enrollment import service as enr
from app.pki import renewal
from app.pki import service as pki
from app.pki.openbao import OpenBao
from app.security.ratelimit import limiter

router = APIRouter(prefix="/api/enroll", tags=["enroll"])


SPENT = {"completed": "This link has already been used. Each link works once. Ask your IT team for a new one if you need it.",
         "cancelled": "Your IT team cancelled this link. Ask them for a new one.",
         "expired": "This link has expired. Ask your IT team for a new one."}


def _load(token: str, request: Request, s: Session, *, pending: bool = False) -> tuple[m.Enrollment, m.Tenant, m.Identity]:
    # Per address (generous: a whole office can share one NAT address) and per link (tight: guessing is pointless,
    # tokens are 256-bit, but a single page has no reason to call more often).
    if not limiter.hit(f"enroll:{client_ip(request)}", 120) or not limiter.hit(f"enroll-token:{token[:64]}", 30):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many requests. Wait a minute and try again.")
    set_platform(s)
    e = enr.find_by_token(s, token)
    if e is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "This enrollment link isn't valid. Ask your IT team for a new one.")
    set_tenant(s, e.tenant_id)
    tenant = s.get(m.Tenant, e.tenant_id)
    ident = s.get(m.Identity, e.identity_id)
    if tenant is None or ident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "This enrollment link isn't valid.")
    if pending and e.status != "pending":
        s.commit()  # keep an expiry noticed by find_by_token
        raise HTTPException(status.HTTP_410_GONE, SPENT.get(e.status, "This link can't be used any more."))
    return e, tenant, ident


def _net(s: Session, tenant_id) -> tuple[str, str, bool]:
    rs = s.get(m.RadiusSettings, tenant_id)
    return (rs.ssid if rs else "", rs.server_hostname if rs else "", rs.wpa3 if rs else False)


def _wired(s: Session, tenant_id) -> bool:
    """Whether enrollment packages include wired 802.1X settings (RADIUS settings → wired)."""
    rs = s.get(m.RadiusSettings, tenant_id)
    return bool(rs and rs.wired_enabled)


@router.get("/{token}")
def info(token: str, request: Request, s: Session = Depends(db)) -> dict:
    e, tenant, ident = _load(token, request, s)
    ssid, server, wpa3 = _net(s, tenant.id)
    wired = _wired(s, tenant.id)
    if e.status != "pending":
        s.commit()
        return {"status": e.status, "tenant": tenant.name}
    return {"status": e.status, "tenant": tenant.name, "user": {"display_name": ident.display_name, "upn": ident.upn or ident.username},
            "device_name": e.device_name, "platform": e.platform, "method": e.method, "expires_at": e.expires_at.isoformat(),
            "network": {"ssid": ssid, "server_name": server, "wpa3": wpa3, "wired": wired},
            "instructions": profiles.instructions(e.platform, ssid, server, wired)}


class CsrIn(BaseModel):
    csr: str = Field(min_length=100, max_length=20_000)
    key_origin: str = "browser"
    device_hint: str | None = Field(default=None, max_length=120)
    key_storage: str | None = Field(default=None, max_length=16)  # tpm | software (Windows setup and helper)
    renewer: Literal["windows-helper"] | None = None  # the portal's Windows helper installs a renewal task (cert-renewal.md §15c)


@router.post("/{token}/csr")
def submit_csr(token: str, body: CsrIn, request: Request, s: Session = Depends(db), format: str = "json") -> dict:
    """`format=pem`: only the certificate, as PEM text (the Linux setup script has everything else already)."""
    e, tenant, ident = _load(token, request, s, pending=True)
    if e.method not in ("link", enr.WINDOWS_SETUP):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This link is for a prepared package. Download it instead.")
    try:
        cert = enr.complete_with_csr(s, OpenBao(), e, body.csr.strip() + "\n", body.key_origin, key_storage=body.key_storage,
                                     device_hint=body.device_hint, renewer=body.renewer)
    except (enr.EnrollmentError, pki.PkiError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    issuing, root = pki.chain_pem(s, tenant.id)
    ssid, server, wpa3 = _net(s, tenant.id)
    wired = _wired(s, tenant.id)
    org = tenant.name
    audit.record(s, audit.Actor("enrollee", ident.username, str(ident.id), client_ip(request)), "enrollment.completed", tenant_id=tenant.id,
                 target_type="certificate", target_id=cert.id, target_label=f"{cert.common_name} ({cert.serial})",
                 detail={"device": e.device_name, "platform": e.platform, "key_origin": cert.key_origin, "key_storage": cert.key_storage,
                         "method": e.method, "purpose": cert.purpose})
    if format == "pem":
        return PlainTextResponse(cert.certificate_pem, media_type="application/x-pem-file")
    identity_name = ident.upn or ident.username
    return {
        "certificate_pem": cert.certificate_pem, "issuing_ca_pem": issuing, "root_ca_pem": root, "serial": cert.serial,
        "not_after": cert.not_after.isoformat(), "network": {"ssid": ssid, "server_name": server, "wpa3": wpa3, "wired": wired},
        "profiles": {
            "windows_xml": profiles.windows_wlan_xml(ssid, server, root or issuing, wpa3) if ssid else None,
            "mobileconfig_template": profiles.apple_mobileconfig(ssid=ssid, server_name=server, root_pem=root or issuing, issuing_pem=issuing, org=org,
                                                                 tenant_slug=tenant.slug, identity_label=identity_name, wpa3=wpa3,
                                                                 wired=wired and e.platform == "macos").decode() if ssid else None,
            "mobileconfig_marker": profiles.PKCS12_MARKER,
            "networkmanager": profiles.networkmanager(ssid, server, identity_name, wpa3) if ssid else None,
            "wpa_supplicant": profiles.wpa_supplicant(ssid, server, identity_name) if ssid else None,
            # Wired 802.1X (Linux). Windows wired is set up by IT (RADIUS → Windows wired kit); Macs get it in the profile.
            "networkmanager_wired": profiles.networkmanager_wired(server, identity_name) if wired else None,
            "wpa_supplicant_wired": profiles.wpa_supplicant_wired(server, identity_name) if wired else None,
        },
        "identity": identity_name, "instructions": profiles.instructions(e.platform, ssid, server, wired),
    }


class RenewIn(BaseModel):
    certificate: str = Field(min_length=100, max_length=20_000)  # the current certificate, base64 DER
    csr: str | None = Field(default=None, min_length=100, max_length=20_000)  # the new key's request (PEM); none: a v2 check-in
    signed_at: int                                              # Unix time the signature was made
    signature: str = Field(min_length=40, max_length=2_000)      # base64, by the current certificate's key
    key_storage: str | None = Field(default=None, max_length=16)
    client: str | None = Field(default=None, max_length=4_000)   # v2: the renewer's client block, JSON text, signed as sent


def _refused(s: Session, exc: enr.RenewalRefused, request: Request) -> None:
    """Audit a turned-down renewal of a certificate EasyEAP issued, once a day per certificate and reason (a device's
    renewal task asks daily, and some ask hourly), and commit it: the request still fails. A conflict (another key
    renewed it and that certificate is in use) is its own, critical event."""
    c = exc.cert
    cid, tenant_id, label, cn, purpose = c.id, c.tenant_id, f"{c.common_name} ({c.serial})", c.common_name, c.purpose
    cert_id = str(cid)
    action = "certificate.renewal_conflict" if exc.code == "conflict" else "certificate.renewal_refused"
    s.rollback()  # whatever the refused renewal changed goes; the audit row stays
    wrote = exc.note is not None
    if wrote:  # the device signed a check-in with the key: it's alive, just refused (overdue, not silent)
        info, at = exc.note
        set_tenant(s, tenant_id)
        s.execute(update(m.Certificate).where(m.Certificate.id == cid).values(
            renewer=info["kind"], renewer_version=info["version"], renewal_checked_at=at, trust_reported=enr.note_trust(info, at)))
    else:
        set_platform(s)
    if not seen_today(s, action, cert_id, exc.code):
        audit.record(s, audit.Actor("certificate", cn, cert_id, client_ip(request)), action, tenant_id=tenant_id, target_type="certificate",
                     target_id=cert_id, target_label=label, detail={"reason": exc.code, "message": str(exc), "purpose": purpose})
        wrote = True
    if wrote:
        s.commit()


def seen_today(s: Session, action: str, cert_id: str, code: str) -> bool:
    return bool(s.scalar(select(func.count()).select_from(m.AuditEvent).where(
        m.AuditEvent.action == action, m.AuditEvent.target_id == cert_id,
        m.AuditEvent.at >= datetime.now(UTC) - timedelta(days=1), m.AuditEvent.detail["reason"].astext == code)))


def trust_block(s: Session, tenant_id) -> dict:
    """The tenant's trust anchors, in every v2 answer (docs/plans/cert-renewal.md §4.2). During a root rollover (phase
    6) `cross` carries the certificate by which the old root vouches for the new one; devices take a new root only then."""
    roots = s.scalars(select(m.CertificateAuthority).where(m.CertificateAuthority.tenant_id == tenant_id, m.CertificateAuthority.role == "root",
                                                           m.CertificateAuthority.status == "active")).all()
    return {"roots": [{"sha256": r.fingerprint_sha256.lower(), "pem": r.certificate_pem.strip() + "\n"} for r in roots], "cross": []}


@router.post("/renew")
def renew(body: RenewIn, request: Request, s: Session = Depends(db), format: str = "json") -> dict:
    """Renew a certificate with its own key (docs/plans/windows-setup.md §4, cert-renewal.md §4.2): renewal tasks call
    this daily; nothing is issued until the certificate is inside its renewal window. v2 renewers send a client block,
    and check in without a request when they aren't due; every JSON answer says when renewal starts.
    `format=pem` (the v1 Linux renewal script): the new certificate as PEM text, or 204 when it isn't renewed yet."""
    if not limiter.hit(f"renew:{client_ip(request)}", 60):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many requests. Wait a minute and try again.")
    try:
        der = base64.b64decode(body.certificate, validate=True)
        signature = base64.b64decode(body.signature, validate=True)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The certificate or signature isn't valid base64.") from exc
    if not limiter.hit(f"renew-cert:{hashlib.sha256(der).hexdigest()}", 10):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many requests for this certificate. Try again later.")
    set_platform(s)
    try:
        old, new = enr.renew(s, OpenBao(), certificate_der=der, csr_pem=body.csr.strip() + "\n" if body.csr else None, signed_at=body.signed_at,
                             signature=signature, key_storage=body.key_storage, client=body.client)
    except enr.RenewalRefused as exc:
        _refused(s, exc, request)
        # `code` tells a renewer whether its waiting request is finished with (cert-renewal.md §15c): after "clock" or
        # "off", a certificate may already exist for it, so it keeps the key.
        return JSONResponse({"detail": str(exc), "code": exc.code}, status_code=status.HTTP_400_BAD_REQUEST)
    except (enr.EnrollmentError, pki.PkiError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if new is None:
        if format == "pem":
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        st = renewal.settings(s, old.tenant_id)
        superseded = old.status == "superseded"
        return {"renewed": False, "not_after": old.not_after.isoformat(), "superseded": superseded,
                # superseded: a renewer holding a request from a lost answer sends it again now; one without asks again
                # with a new key, and an unused successor is replaced (cert-renewal.md §15c)
                "renew_from": (datetime.now(UTC) if superseded else renewal.renew_from(old, st.renew_at_percent)).isoformat(),
                "renewal_enabled": renewal.enabled_for(st, old.purpose), "trust": trust_block(s, old.tenant_id)}
    set_tenant(s, new.tenant_id)
    issuing, root = pki.chain_pem(s, new.tenant_id)
    if getattr(new, "issued_now", False):  # not a resend of an earlier renewal's lost answer
        audit.record(s, audit.Actor("certificate", old.common_name, str(old.id), client_ip(request)), "certificate.renewed", tenant_id=new.tenant_id,
                     target_type="certificate", target_id=new.id, target_label=f"{new.common_name} ({new.serial})",
                     detail={"previous_serial": old.serial, "key_storage": new.key_storage, "purpose": new.purpose, "renewer": new.renewer,
                             "renewer_version": new.renewer_version, "replaced_unused_serial": getattr(new, "replaced_serial", None)})
    if format == "pem":
        return PlainTextResponse(new.certificate_pem, media_type="application/x-pem-file")
    return {"renewed": True, "certificate_pem": new.certificate_pem, "serial": new.serial, "not_after": new.not_after.isoformat(),
            "issuing_ca_pem": issuing, "root_ca_pem": root, "trust": trust_block(s, new.tenant_id)}


@router.get("/{token}/windows.ps1", response_class=PlainTextResponse)
def windows_script(token: str, request: Request, s: Session = Depends(db)) -> Response:
    e, tenant, _ = _load(token, request, s, pending=True)
    if e.method != "link":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This link is for a prepared package. Download it instead.")
    issuing, root = pki.chain_pem(s, tenant.id)
    ssid, server, wpa3 = _net(s, tenant.id)
    tpl = s.get(m.CertificateTemplate, e.template_id) if e.template_id else None
    days = tpl.renew_before_days if tpl else 30
    # The helper leaves a per-user renewal task behind (cert-renewal.md §15c item 8), so the certificate renews itself.
    renew = windows_setup.renew_ps1(api=get_settings().public_url, kind="windows-helper", org=tenant.name, root_pems=[root or issuing],
                                    issuing_pem=issuing, user_days=days, computer_days=days)
    script = profiles.windows_powershell(get_settings().public_url, token, ssid, server, root or issuing, issuing, wpa3, renew_ps1=renew)
    # With a BOM: Windows PowerShell reads a .ps1 without one as ANSI, which garbles a non-ASCII network or org name.
    return Response("\ufeff" + script, media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="EasyEAP-WiFi-Setup.ps1"', "Cache-Control": "no-store"})


def linux_script_for(s: Session, e: m.Enrollment, tenant: m.Tenant, ident: m.Identity, token: str) -> str | None:
    """The Linux setup script for a link (enrollment/linux_setup.py), or None when the Wi-Fi network name isn't set.
    The portal serves it to the user; the console gives it to the admin (routers/enrollments.py linux_script_again)."""
    ssid, server, wpa3 = _net(s, tenant.id)
    if not ssid:
        return None
    issuing, root = pki.chain_pem(s, tenant.id)
    tpl = s.get(m.CertificateTemplate, e.template_id) if e.template_id else None
    return linux_setup.setup_script(
        api_base=get_settings().public_url, token=token, org=tenant.name, slug=tenant.slug, ssid=ssid, server_name=server,
        identity=ident.upn or ident.username, wpa3=wpa3, wired=_wired(s, tenant.id), ca_chain_pem=issuing + (root or ""),
        renew_days=tpl.renew_before_days if tpl else 30, pin=linux_setup.tls_pin(PROXY_CERT))


@router.get("/{token}/linux.sh", response_class=PlainTextResponse)
def linux_script(token: str, request: Request, s: Session = Depends(db)) -> Response:
    """The Linux setup script (enrollment/linux_setup.py): key on the computer, CSR with this link, then the network
    for NetworkManager, iwd or wpa_supplicant. Doesn't use the link; the script does, when it runs."""
    e, tenant, ident = _load(token, request, s, pending=True)
    if e.method != "link":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This link is for a prepared package. Download it instead.")
    script = linux_script_for(s, e, tenant, ident, token)
    if script is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Your IT team hasn't set up the Wi-Fi network name yet.")
    return Response(script, media_type="text/x-shellscript; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{linux_setup.FILENAME}"', "Cache-Control": "no-store"})


@router.get("/{token}/wifi.xml")
def windows_profile(token: str, request: Request, s: Session = Depends(db)) -> Response:
    """Windows WLAN profile (EAP-TLS, server name pinned, Root CA trusted). Contains nothing secret."""
    _, tenant, _ = _load(token, request, s, pending=True)
    issuing, root = pki.chain_pem(s, tenant.id)
    ssid, server, wpa3 = _net(s, tenant.id)
    if not ssid:
        raise HTTPException(status.HTTP_409_CONFLICT, "Your IT team hasn't set up the Wi-Fi network name yet.")
    return Response(profiles.windows_wlan_xml(ssid, server, root or issuing, wpa3), media_type="application/xml",
                    headers={"Content-Disposition": f'attachment; filename="{tenant.slug}-wifi.xml"', "Cache-Control": "no-store"})


@router.post("/{token}/package")
def download_package(token: str, request: Request, s: Session = Depends(db), format: str = "p12") -> Response:
    """Server-generated PKCS#12 (admin mode): one download, then the escrow copy is deleted.

    `format=mobileconfig` wraps the same password-protected PKCS#12 in an Apple configuration profile with the CA
    chain and the Wi-Fi network, for iPhone, iPad and Mac."""
    if format not in ("p12", "mobileconfig"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown package format.")
    e, tenant, ident = _load(token, request, s, pending=True)
    if e.method != "server":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This link creates the key on your device instead.")
    try:
        data = enr.take_escrow(s, OpenBao(), e)
    except enr.EnrollmentError as exc:
        s.commit()
        raise HTTPException(status.HTTP_410_GONE, str(exc)) from exc
    audit.record(s, audit.Actor("enrollee", ident.username, str(ident.id), client_ip(request)), "enrollment.package_downloaded", tenant_id=tenant.id,
                 target_type="enrollment", target_id=e.id, target_label=e.device_name, detail={"by": "enrollee", "format": format})
    if format == "mobileconfig":
        issuing, root = pki.chain_pem(s, tenant.id)
        ssid, server, wpa3 = _net(s, tenant.id)
        profile = profiles.apple_mobileconfig(ssid=ssid or tenant.name, server_name=server, root_pem=root or issuing, issuing_pem=issuing,
                                              org=tenant.name, tenant_slug=tenant.slug, identity_label=ident.upn or ident.username, wpa3=wpa3,
                                              pkcs12_b64=base64.b64encode(data).decode(), wired=_wired(s, tenant.id) and e.platform == "macos")
        return Response(profile, media_type="application/x-apple-aspen-config",
                        headers={"Content-Disposition": f'attachment; filename="{tenant.slug}-wifi.mobileconfig"', "Cache-Control": "no-store"})
    return Response(data, media_type="application/x-pkcs12", headers={"Content-Disposition": f'attachment; filename="{tenant.slug}-wifi.p12"', "Cache-Control": "no-store"})


@router.get("/{token}/ca.pem", response_class=PlainTextResponse)
def ca_chain(token: str, request: Request, s: Session = Depends(db)) -> str:
    _, tenant, _ = _load(token, request, s)
    issuing, root = pki.chain_pem(s, tenant.id)
    return issuing + (root or "")
