"""RADIUS settings, server certificate, wireless controllers (NAS clients) and vendor guides."""
from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app import audit
from app import models as m
from app.config import get_settings
from app.db import set_platform, set_tenant
from app.deps import TenantCtx, require
from app.pki import crypto
from app.pki.openbao import OpenBao
from app.radius import guides
from app.radius.state import RadiusConfigError, bump, check_address_unique, ensure_server_certificate, parse_address
from app.security.tokens import new_shared_secret

router = APIRouter(prefix="/api/tenants/{tenant_id}/radius", tags=["radius"])
VENDORS = ("cisco-9800", "cisco-aireos", "unifi", "other")


def settings_out(rs: m.RadiusSettings | None, s) -> dict | None:
    if rs is None:
        return None
    cert = s.get(m.Certificate, rs.server_certificate_id) if rs.server_certificate_id else None
    return {"server_hostname": rs.server_hostname, "ssid": rs.ssid, "wpa3": rs.wpa3, "auth_port": rs.auth_port, "acct_port": rs.acct_port,
            "dedicated_ports": rs.dedicated_ports, "tls_min_version": rs.tls_min_version, "tls_session_cache": rs.tls_session_cache,
            "session_timeout_seconds": rs.session_timeout_seconds,
            "server_certificate": {"id": str(cert.id), "serial": cert.serial, "common_name": cert.common_name, "not_after": cert.not_after.isoformat(),
                                   "fingerprint_sha256": cert.fingerprint_sha256} if cert else None,
            "snapshot_version": rs.snapshot_version, "snapshot_built_at": rs.snapshot_built_at.isoformat() if rs.snapshot_built_at else None,
            **controller_address()}


def controller_address() -> dict:
    """The address controllers are told to send RADIUS to. A loopback or unspecified address (a lab default, or a
    bind address copied by mistake) can't be reached by a controller, so it is withheld and the reason reported."""
    raw = get_settings().radius_public_address.strip()
    try:
        ip = ipaddress.ip_address(raw)
        unusable = ip.is_loopback or ip.is_unspecified
    except ValueError:
        unusable = raw.lower() in ("localhost", "localhost.localdomain")
    if unusable:
        return {"radius_address": "", "radius_address_problem":
                f"EASYEAP_RADIUS_ADDRESS is set to {raw}, which a wireless controller can't reach. Set it in the deploy .env file "
                "to the address controllers use for this server, then restart the stack."}
    return {"radius_address": raw, "radius_address_problem": None}


def client_out(c: m.RadiusClient) -> dict:
    return {"id": str(c.id), "name": c.name, "vendor": c.vendor, "address": c.address, "site": c.site, "coa_enabled": c.coa_enabled,
            "coa_port": c.coa_port, "secret_set_at": c.secret_set_at.isoformat() if c.secret_set_at else None,
            "last_request_at": c.last_request_at.isoformat() if c.last_request_at else None}


# The agent polls every 15 s and FreeRADIUS starts in seconds, so a tenant activated longer ago than this should be served.
STARTING_WINDOW = timedelta(minutes=2)


def radius_state(s, a: m.AgentStatus, now: datetime) -> str:
    """running | idle | starting | stopped.

    The agent keeps FreeRADIUS stopped while no tenant is active, because there is nothing to serve. That is
    "idle", not a fault. "starting" covers the poll interval right after an activation. Activations are read from the
    audit trail, so in a tenant-scoped session (RLS) only that tenant's activation counts.
    """
    if a.radius_running:
        return "running"
    if not s.scalar(select(func.count()).select_from(m.Tenant).where(m.Tenant.status == "active")):
        return "idle"
    activated = s.scalar(select(func.max(m.AuditEvent.at)).where(m.AuditEvent.action == "tenant.updated",
                                                                 m.AuditEvent.detail["status"].astext == "active"))
    if activated and now - activated < STARTING_WINDOW:
        return "starting"
    return "stopped"


def agent_out(s) -> dict | None:
    a = s.scalars(select(m.AgentStatus).order_by(m.AgentStatus.last_seen_at.desc())).first()
    out = None
    if a:
        now = datetime.now(UTC)
        out = {"agent_id": a.agent_id, "last_seen_at": a.last_seen_at.isoformat(), "config_ok": a.config_ok, "config_error": a.config_error,
               "radius_running": a.radius_running, "state": radius_state(s, a, now), "serving": (a.detail or {}).get("tenants"),
               "serving_ids": (a.detail or {}).get("tenant_ids"),
               "snapshot_versions": a.snapshot_versions, "config_version": a.config_version,
               "online": (now - a.last_seen_at).total_seconds() < 90, "detail": a.detail}
    return out


@router.get("")
def get_radius(ctx: TenantCtx = Depends(require("radius:read"))) -> dict:
    s = ctx.session
    rs = s.get(m.RadiusSettings, ctx.id)
    clients = s.scalars(select(m.RadiusClient).where(m.RadiusClient.tenant_id == ctx.id).order_by(m.RadiusClient.name)).all()
    out = {"settings": settings_out(rs, s), "clients": [client_out(c) for c in clients], "unattributed": unattributed(s, ctx.id)}
    out["agent"] = agent_out(s)
    if out["agent"] and rs:
        applied = (out["agent"]["snapshot_versions"] or {}).get(str(ctx.id))
        out["agent"]["tenant_snapshot_applied"] = applied
        out["agent"]["tenant_in_sync"] = applied == rs.snapshot_version
    return out


def unattributed(s, tenant_id: uuid.UUID) -> dict | None:
    """Requests from the last 7 days that couldn't be tied to a controller, so the console never says "no requests"
    while RADIUS is answering them."""
    since = datetime.now(UTC) - timedelta(days=7)
    rows = s.execute(select(m.AuthEvent.nas_ip, func.count(), func.max(m.AuthEvent.at))
                     .where(m.AuthEvent.tenant_id == tenant_id, m.AuthEvent.nas_client_id.is_(None), m.AuthEvent.at >= since)
                     .group_by(m.AuthEvent.nas_ip).order_by(func.count().desc())).all()
    if not rows:
        return None
    return {"count": sum(n for _, n, _ in rows), "last_at": max(at for _, _, at in rows).isoformat(),
            "nas_addresses": [ip for ip, _, _ in rows if ip][:5], "days": 7}


class SettingsIn(BaseModel):
    server_hostname: str = Field(min_length=3, max_length=253, pattern=r"^[A-Za-z0-9.-]+$")
    ssid: str = Field(min_length=1, max_length=32)
    wpa3: bool = False
    dedicated_ports: bool = False
    auth_port: int = Field(default=1812, ge=1024, le=65535)
    acct_port: int = Field(default=1813, ge=1024, le=65535)
    tls_min_version: str = Field(default="1.2", pattern=r"^1\.[23]$")
    tls_session_cache: bool = False
    session_timeout_seconds: int = Field(default=28_800, ge=600, le=86_400 * 7)


@router.put("")
def save_settings(body: SettingsIn, ctx: TenantCtx = Depends(require("radius:write"))) -> dict:
    s = ctx.session
    rs = s.get(m.RadiusSettings, ctx.id)
    if body.dedicated_ports:
        if body.auth_port == body.acct_port or {body.auth_port, body.acct_port} & {1812, 1813, 18120}:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Dedicated ports must be two different ports other than 1812, 1813 and 18120.")
        set_platform(s)
        clash = s.scalars(select(m.RadiusSettings).where(m.RadiusSettings.tenant_id != ctx.id, m.RadiusSettings.dedicated_ports.is_(True),
                                                         (m.RadiusSettings.auth_port.in_((body.auth_port, body.acct_port))) | (m.RadiusSettings.acct_port.in_((body.auth_port, body.acct_port))))).first()
        set_tenant(s, ctx.id)
        if clash:
            raise HTTPException(status.HTTP_409_CONFLICT, "Another tenant already uses one of these ports.")
    hostname_changed = rs is None or rs.server_hostname != body.server_hostname.lower()
    if rs is None:
        rs = m.RadiusSettings(tenant_id=ctx.id, server_hostname=body.server_hostname.lower())
        s.add(rs)
    for k, v in body.model_dump().items():
        setattr(rs, k, v.lower() if k == "server_hostname" else v)
    s.flush()
    issued = None
    if hostname_changed or rs.server_certificate_id is None:
        try:
            issued = ensure_server_certificate(s, OpenBao(), ctx.tenant, rs.server_hostname)
        except Exception as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Settings need an initialized PKI to issue the RADIUS server certificate: {exc}") from exc
    rs.config_version += 1
    audit.record(s, ctx.actor, "radius.settings_saved", tenant_id=ctx.id, target_type="radius", target_label=body.server_hostname,
                 detail={**body.model_dump(), "server_certificate_issued": bool(issued)})
    return {"settings": settings_out(rs, s)}


@router.post("/server-certificate/rotate")
def rotate_server_cert(ctx: TenantCtx = Depends(require("radius:write"))) -> dict:
    rs = ctx.session.get(m.RadiusSettings, ctx.id)
    if rs is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Save RADIUS settings first.")
    cert = ensure_server_certificate(ctx.session, OpenBao(), ctx.tenant, rs.server_hostname)
    audit.record(ctx.session, ctx.actor, "radius.server_certificate_rotated", tenant_id=ctx.id, target_type="certificate", target_id=cert.id, target_label=cert.common_name)
    return {"settings": settings_out(rs, ctx.session)}


class ClientIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    vendor: str
    address: str = Field(min_length=3, max_length=64)
    site: str = Field(default="", max_length=120)
    coa_enabled: bool = False
    coa_port: int | None = Field(default=None, ge=1, le=65535)


@router.post("/clients", status_code=201)
def create_client(body: ClientIn, ctx: TenantCtx = Depends(require("radius:write"))) -> dict:
    if body.vendor not in VENDORS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Choose a controller type.")
    s = ctx.session
    try:
        net = parse_address(body.address)
        set_platform(s)
        check_address_unique(s, ctx.id, body.address)
        set_tenant(s, ctx.id)
    except RadiusConfigError as exc:
        set_tenant(s, ctx.id)
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    secret = new_shared_secret()
    c = m.RadiusClient(tenant_id=ctx.id, name=body.name, vendor=body.vendor, address=str(net) if net.num_addresses > 1 else str(net.network_address),
                       site=body.site, secret_ct=crypto.encrypt(ctx.id, secret), coa_enabled=body.coa_enabled,
                       coa_port=body.coa_port or (1700 if body.vendor == "cisco-9800" else 3799))
    s.add(c)
    s.flush()
    bump(s, ctx.id)
    audit.record(s, ctx.actor, "radius.client_created", tenant_id=ctx.id, target_type="radius_client", target_id=c.id, target_label=f"{c.name} ({c.address})",
                 detail={"vendor": c.vendor, "coa": c.coa_enabled})
    # The secret is returned once and never again.
    return {"client": client_out(c), "shared_secret": secret}


@router.put("/clients/{client_id}")
def update_client(client_id: uuid.UUID, body: ClientIn, ctx: TenantCtx = Depends(require("radius:write"))) -> dict:
    s = ctx.session
    c = s.get(m.RadiusClient, client_id)
    if c is None or c.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Controller not found.")
    try:
        net = parse_address(body.address)
        set_platform(s)
        check_address_unique(s, ctx.id, body.address, exclude_id=c.id)
        set_tenant(s, ctx.id)
    except RadiusConfigError as exc:
        set_tenant(s, ctx.id)
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    c.name, c.vendor, c.site, c.coa_enabled = body.name, body.vendor, body.site, body.coa_enabled
    c.address = str(net) if net.num_addresses > 1 else str(net.network_address)
    c.coa_port = body.coa_port or c.coa_port
    bump(s, ctx.id)
    audit.record(s, ctx.actor, "radius.client_updated", tenant_id=ctx.id, target_type="radius_client", target_id=c.id, target_label=c.name, detail=body.model_dump())
    return {"client": client_out(c)}


@router.post("/clients/{client_id}/rotate-secret")
def rotate_secret(client_id: uuid.UUID, ctx: TenantCtx = Depends(require("radius:secrets"))) -> dict:
    c = ctx.session.get(m.RadiusClient, client_id)
    if c is None or c.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Controller not found.")
    secret = new_shared_secret()
    c.secret_ct, c.secret_set_at = crypto.encrypt(ctx.id, secret), datetime.now(UTC)
    bump(ctx.session, ctx.id)
    audit.record(ctx.session, ctx.actor, "radius.client_secret_rotated", tenant_id=ctx.id, target_type="radius_client", target_id=c.id, target_label=c.name)
    return {"client": client_out(c), "shared_secret": secret}


@router.delete("/clients/{client_id}")
def delete_client(client_id: uuid.UUID, ctx: TenantCtx = Depends(require("radius:write"))) -> dict:
    c = ctx.session.get(m.RadiusClient, client_id)
    if c is None or c.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Controller not found.")
    label = f"{c.name} ({c.address})"
    ctx.session.delete(c)
    bump(ctx.session, ctx.id)
    audit.record(ctx.session, ctx.actor, "radius.client_deleted", tenant_id=ctx.id, target_type="radius_client", target_id=client_id, target_label=label)
    return {"ok": True}


@router.get("/guide/{vendor}")
def guide(vendor: str, ctx: TenantCtx = Depends(require("radius:read")), client_id: uuid.UUID | None = None) -> dict:
    if vendor not in VENDORS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown controller type.")
    s = ctx.session
    rs = s.get(m.RadiusSettings, ctx.id)
    if rs is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Save RADIUS settings first.")
    client = s.get(m.RadiusClient, client_id) if client_id else None
    vlans = list(s.scalars(select(m.Vlan).where(m.Vlan.tenant_id == ctx.id)))
    return guides.guide(vendor, client=client, settings=rs, radius_ip=controller_address()["radius_address"], vlans=vlans, tenant=ctx.tenant)


@router.get("/coa")
def coa_requests(ctx: TenantCtx = Depends(require("radius:read"))) -> dict:
    rows = ctx.session.scalars(select(m.CoaRequest).where(m.CoaRequest.tenant_id == ctx.id).order_by(m.CoaRequest.created_at.desc()).limit(100)).all()
    return {"items": [{"id": str(r.id), "kind": r.kind, "attributes": r.attributes, "reason": r.reason, "status": r.status, "result_detail": r.result_detail,
                       "created_at": r.created_at.isoformat() if r.created_at else None, "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                       "nas_client_id": str(r.nas_client_id)} for r in rows]}
