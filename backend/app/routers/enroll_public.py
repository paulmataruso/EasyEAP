"""End-user enrollment portal API. The one-time token in the URL is the only credential."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import audit
from app import models as m
from app.config import get_settings
from app.db import set_platform, set_tenant
from app.deps import client_ip, db
from app.enrollment import profiles
from app.enrollment import service as enr
from app.pki import service as pki
from app.pki.openbao import OpenBao
from app.security.ratelimit import limiter

router = APIRouter(prefix="/api/enroll", tags=["enroll"])


def _load(token: str, request: Request, s: Session) -> tuple[m.Enrollment, m.Tenant, m.Identity]:
    if not limiter.hit(f"enroll:{client_ip(request)}", 30):
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
    return e, tenant, ident


def _net(s: Session, tenant_id) -> tuple[str, str, bool]:
    rs = s.get(m.RadiusSettings, tenant_id)
    return (rs.ssid if rs else "", rs.server_hostname if rs else "", rs.wpa3 if rs else False)


@router.get("/{token}")
def info(token: str, request: Request, s: Session = Depends(db)) -> dict:
    e, tenant, ident = _load(token, request, s)
    ssid, server, wpa3 = _net(s, tenant.id)
    if e.status != "pending":
        s.commit()
        return {"status": e.status, "tenant": tenant.name}
    return {"status": e.status, "tenant": tenant.name, "user": {"display_name": ident.display_name, "upn": ident.upn or ident.username},
            "device_name": e.device_name, "platform": e.platform, "method": e.method, "expires_at": e.expires_at.isoformat(),
            "network": {"ssid": ssid, "server_name": server, "wpa3": wpa3}, "instructions": profiles.instructions(e.platform, ssid, server)}


class CsrIn(BaseModel):
    csr: str = Field(min_length=100, max_length=20_000)
    key_origin: str = "browser"
    device_hint: str | None = Field(default=None, max_length=120)


@router.post("/{token}/csr")
def submit_csr(token: str, body: CsrIn, request: Request, s: Session = Depends(db)) -> dict:
    e, tenant, ident = _load(token, request, s)
    if e.method != "link":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This link is for a prepared package. Download it instead.")
    try:
        cert = enr.complete_with_csr(s, OpenBao(), e, body.csr.strip() + "\n", body.key_origin)
    except (enr.EnrollmentError, pki.PkiError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    issuing, root = pki.chain_pem(s, tenant.id)
    ssid, server, wpa3 = _net(s, tenant.id)
    org = tenant.name
    audit.record(s, audit.Actor("enrollee", ident.username, str(ident.id), client_ip(request)), "enrollment.completed", tenant_id=tenant.id,
                 target_type="certificate", target_id=cert.id, target_label=f"{cert.common_name} ({cert.serial})",
                 detail={"device": e.device_name, "platform": e.platform, "key_origin": cert.key_origin})
    identity_name = ident.upn or ident.username
    return {
        "certificate_pem": cert.certificate_pem, "issuing_ca_pem": issuing, "root_ca_pem": root, "serial": cert.serial,
        "not_after": cert.not_after.isoformat(), "network": {"ssid": ssid, "server_name": server, "wpa3": wpa3},
        "profiles": {
            "windows_xml": profiles.windows_wlan_xml(ssid, server, root or issuing, wpa3) if ssid else None,
            "mobileconfig_template": profiles.apple_mobileconfig(ssid=ssid, server_name=server, root_pem=root or issuing, issuing_pem=issuing, org=org,
                                                                 tenant_slug=tenant.slug, identity_label=identity_name, wpa3=wpa3).decode() if ssid else None,
            "mobileconfig_marker": profiles.PKCS12_MARKER,
            "networkmanager": profiles.networkmanager(ssid, server, identity_name, wpa3) if ssid else None,
            "wpa_supplicant": profiles.wpa_supplicant(ssid, server, identity_name) if ssid else None,
        },
        "identity": identity_name, "instructions": profiles.instructions(e.platform, ssid, server),
    }


@router.get("/{token}/windows.ps1", response_class=PlainTextResponse)
def windows_script(token: str, request: Request, s: Session = Depends(db)) -> Response:
    e, tenant, _ = _load(token, request, s)
    if e.status != "pending" or e.method != "link":
        raise HTTPException(status.HTTP_410_GONE, "This enrollment link has already been used or has expired.")
    issuing, root = pki.chain_pem(s, tenant.id)
    ssid, server, wpa3 = _net(s, tenant.id)
    script = profiles.windows_powershell(get_settings().public_url, token, ssid, server, root or issuing, issuing, wpa3)
    return Response(script, media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="EasyEAP-WiFi-Setup.ps1"', "Cache-Control": "no-store"})


@router.post("/{token}/package")
def download_package(token: str, request: Request, s: Session = Depends(db)) -> Response:
    """Server-generated PKCS#12 (admin mode): one download, then the escrow copy is deleted."""
    e, tenant, ident = _load(token, request, s)
    if e.method != "server":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This link creates the key on your device instead.")
    try:
        data = enr.take_escrow(s, OpenBao(), e)
    except enr.EnrollmentError as exc:
        s.commit()
        raise HTTPException(status.HTTP_410_GONE, str(exc)) from exc
    audit.record(s, audit.Actor("enrollee", ident.username, str(ident.id), client_ip(request)), "enrollment.package_downloaded", tenant_id=tenant.id,
                 target_type="enrollment", target_id=e.id, target_label=e.device_name, detail={"by": "enrollee"})
    return Response(data, media_type="application/x-pkcs12", headers={"Content-Disposition": f'attachment; filename="{tenant.slug}-wifi.p12"', "Cache-Control": "no-store"})


@router.get("/{token}/ca.pem", response_class=PlainTextResponse)
def ca_chain(token: str, request: Request, s: Session = Depends(db)) -> str:
    _, tenant, _ = _load(token, request, s)
    issuing, root = pki.chain_pem(s, tenant.id)
    return issuing + (root or "")
