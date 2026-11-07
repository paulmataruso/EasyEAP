"""RADIUS settings, server certificate, wireless controllers and switches (NAS clients), and vendor guides."""
from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import func, or_, select

from app import audit
from app import models as m
from app.config import get_settings
from app.db import set_platform, set_tenant
from app.deps import TenantCtx, require
from app.pki import crypto
from app.pki.openbao import OpenBao
from app.radius import guides, wired
from app.radius.state import RadiusConfigError, bump, check_address_unique, ensure_server_certificate, parse_address
from app.security.tokens import new_shared_secret

router = APIRouter(prefix="/api/tenants/{tenant_id}/radius", tags=["radius"])
VENDORS = ("cisco-9800", "cisco-aireos", "cisco-switch", "unifi", "other")
NETWORKS = ("wireless", "wired")
# A switch left in monitor mode longer than this becomes a needs-action item (app/posture.py).
MONITOR_NUDGE = timedelta(days=14)


def settings_out(rs: m.RadiusSettings | None, s) -> dict | None:
    if rs is None:
        return None
    cert = s.get(m.Certificate, rs.server_certificate_id) if rs.server_certificate_id else None
    return {"server_hostname": rs.server_hostname, "ssid": rs.ssid, "wpa3": rs.wpa3, "auth_port": rs.auth_port, "acct_port": rs.acct_port,
            "dedicated_ports": rs.dedicated_ports, "tls_min_version": rs.tls_min_version, "tls_session_cache": rs.tls_session_cache,
            "session_timeout_seconds": rs.session_timeout_seconds, "wired_enabled": rs.wired_enabled,
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
    networks = [n for n in NETWORKS if n in (c.networks or [])]
    profile = c.wired_profile or {}
    return {"id": str(c.id), "name": c.name, "vendor": c.vendor, "address": c.address, "site": c.site, "coa_enabled": c.coa_enabled,
            "coa_port": c.coa_port, "secret_set_at": c.secret_set_at.isoformat() if c.secret_set_at else None,
            "last_request_at": c.last_request_at.isoformat() if c.last_request_at else None,
            "networks": networks, "wired_profile": profile or None,
            # Monitor mode is what EasyEAP was told; it can't read the switch. Without a port plan (a client registered
            # before wired 802.1X) EasyEAP sends VLANs on wired requests as it always did: "enforce".
            "wired_mode": (profile.get("mode") or "enforce") if "wired" in networks else None}


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
        out["agent"].update(config_sync(out["agent"], ctx.id, rs))
    return out


def config_sync(agent: dict, tenant_id: uuid.UUID, rs: m.RadiusSettings) -> dict:
    """Whether FreeRADIUS runs this tenant's latest configuration change (clients, monitor/enforce, certificates).
    None when the agent is older and doesn't report it."""
    versions = (agent.get("detail") or {}).get("config_versions")
    if not isinstance(versions, dict):
        return {"tenant_config_applied": None, "tenant_config_in_sync": None}
    applied = versions.get(str(tenant_id))
    return {"tenant_config_applied": applied, "tenant_config_in_sync": isinstance(applied, int) and applied >= rs.config_version}


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
    # Include wired settings in enrollment packages. None keeps the current value (consoles from before wired 802.1X).
    wired_enabled: bool | None = None


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
    for k, v in body.model_dump(exclude_none=True).items():
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
    # What this client may authenticate. Default: wired for a Cisco switch, Wi-Fi for everything else.
    networks: list[str] | None = Field(default=None, max_length=2)
    wired_profile: dict | None = None  # the port plan (app/radius/wired.py WiredProfile)


class ClientUpdate(BaseModel):
    """Partial update: omitted fields keep their values."""
    name: str | None = Field(default=None, min_length=1, max_length=120)
    vendor: str | None = None
    address: str | None = Field(default=None, min_length=3, max_length=64)
    site: str | None = Field(default=None, max_length=120)
    coa_enabled: bool | None = None
    coa_port: int | None = Field(default=None, ge=1, le=65535)
    networks: list[str] | None = Field(default=None, max_length=2)
    wired_profile: dict | None = None


def _bad(field: str, message: str) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, {"field": field, "message": message})


def _networks(vendor: str, networks: list[str] | None) -> list[str]:
    if networks is None:
        return ["wired"] if vendor == "cisco-switch" else ["wireless"]
    out = [n for n in NETWORKS if n in networks]
    if not out or len(set(networks)) != len(out):
        raise _bad("networks", "Choose Wi-Fi, wired or both.")
    return out


def _profile(vendor: str, networks: list[str], data: dict | None, current: dict | None, actor: str) -> dict:
    """A validated port plan. Keeps the rollout mode and its history; a new plan starts in monitor mode."""
    if "wired" not in networks:
        return current or {}
    if data is None:
        return current or {}
    cur = current or {}
    data = {**data}
    data.pop("mode_set_at", None)
    data.pop("mode_set_by", None)
    if cur.get("mode") == "enforce" and any(data.get(k) != cur.get(k) for k in data if k != "mode"):
        raise _bad("wired_profile", "This switch is enforcing. Move it back to monitor mode before changing its port plan, "
                   "so the configuration on the switch and in EasyEAP stay the same.")
    data["mode"] = cur.get("mode") or "monitor"
    try:
        out = wired.validate_profile(vendor, data)
    except wired.WiredConfigError as exc:
        raise _bad(exc.field, str(exc)) from exc
    except ValidationError as exc:
        err = exc.errors()[0]
        raise _bad(".".join(str(x) for x in err.get("loc", ())) or "wired_profile", str(err.get("msg", "Invalid port plan")).removeprefix("Value error, ")) from exc
    out["mode_set_at"] = cur.get("mode_set_at") or datetime.now(UTC).isoformat()
    out["mode_set_by"] = cur.get("mode_set_by") or actor
    return out


def _check_address(s, tenant_id: uuid.UUID, address: str, exclude_id: uuid.UUID | None = None):
    try:
        net = parse_address(address)
        set_platform(s)
        check_address_unique(s, tenant_id, address, exclude_id=exclude_id)
        set_tenant(s, tenant_id)
    except RadiusConfigError as exc:
        set_tenant(s, tenant_id)
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return net


def _norm(net) -> str:
    return str(net) if net.num_addresses > 1 else str(net.network_address)


@router.post("/clients", status_code=201)
def create_client(body: ClientIn, ctx: TenantCtx = Depends(require("radius:write"))) -> dict:
    if body.vendor not in VENDORS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Choose a controller or switch type.")
    s = ctx.session
    networks = _networks(body.vendor, body.networks)
    profile = _profile(body.vendor, networks, body.wired_profile if body.wired_profile is not None else ({} if "wired" in networks else None),
                       None, ctx.actor.label) if body.vendor in ("cisco-switch", "unifi", "other") else {}
    net = _check_address(s, ctx.id, body.address)
    secret = new_shared_secret()
    c = m.RadiusClient(tenant_id=ctx.id, name=body.name, vendor=body.vendor, address=_norm(net), networks=networks, wired_profile=profile,
                       site=body.site, secret_ct=crypto.encrypt(ctx.id, secret), coa_enabled=body.coa_enabled,
                       coa_port=body.coa_port or (1700 if body.vendor in ("cisco-9800", "cisco-switch") else 3799))
    s.add(c)
    s.flush()
    bump(s, ctx.id)
    audit.record(s, ctx.actor, "radius.client_created", tenant_id=ctx.id, target_type="radius_client", target_id=c.id, target_label=f"{c.name} ({c.address})",
                 detail={"vendor": c.vendor, "coa": c.coa_enabled, "networks": networks, "wired_mode": profile.get("mode") if profile else None})
    # The secret is returned once and never again.
    return {"client": client_out(c), "shared_secret": secret}


@router.put("/clients/{client_id}")
def update_client(client_id: uuid.UUID, body: ClientUpdate, ctx: TenantCtx = Depends(require("radius:write"))) -> dict:
    s = ctx.session
    c = s.get(m.RadiusClient, client_id)
    if c is None or c.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Controller or switch not found.")
    given = body.model_dump(exclude_unset=True)
    vendor = given.get("vendor") or c.vendor
    if vendor not in VENDORS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Choose a controller or switch type.")
    networks = _networks(vendor, body.networks) if "networks" in given else list(c.networks or ["wireless"])
    if "wired" in networks and vendor in ("cisco-switch", "unifi", "other"):
        plan = body.wired_profile if "wired_profile" in given else (None if c.wired_profile else {})
        profile = _profile(vendor, networks, plan, c.wired_profile, ctx.actor.label)
    else:
        profile = c.wired_profile or {}
    if "address" in given and body.address:
        c.address = _norm(_check_address(s, ctx.id, body.address, exclude_id=c.id))
    for k in ("name", "site", "coa_enabled", "coa_port"):
        if k in given and given[k] is not None:
            setattr(c, k, given[k])
    c.vendor, c.networks, c.wired_profile = vendor, networks, profile
    bump(s, ctx.id)
    audit.record(s, ctx.actor, "radius.client_updated", tenant_id=ctx.id, target_type="radius_client", target_id=c.id, target_label=c.name,
                 detail={k: v for k, v in given.items()})
    return {"client": client_out(c)}


class WiredModeIn(BaseModel):
    mode: str = Field(pattern="^(monitor|enforce)$")
    # Enforcing: the admin confirms they looked at the switch's own sessions (or chose to skip that).
    confirmed: bool = False


@router.post("/clients/{client_id}/wired-mode")
def set_wired_mode(client_id: uuid.UUID, body: WiredModeIn, ctx: TenantCtx = Depends(require("radius:write"))) -> dict:
    """Record the switch's rollout mode. EasyEAP starts (or stops) sending VLANs to it; the admin pastes the change."""
    s = ctx.session
    c = s.get(m.RadiusClient, client_id)
    if c is None or c.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Switch not found.")
    if "wired" not in (c.networks or []):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This client isn't registered for wired 802.1X.")
    if body.mode == "enforce" and not body.confirmed:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Confirm you've checked which devices would lose access.")
    before = (c.wired_profile or {}).get("mode") or "enforce"
    c.wired_profile = {**(c.wired_profile or {}), "mode": body.mode, "mode_set_at": datetime.now(UTC).isoformat(), "mode_set_by": ctx.actor.label}
    bump(s, ctx.id)
    audit.record(s, ctx.actor, "radius.wired_mode_changed", tenant_id=ctx.id, target_type="radius_client", target_id=c.id, target_label=c.name,
                 detail={"from": before, "to": body.mode})
    return {"client": client_out(c), "guide": _wired_guide(ctx, c)}


def _wired_guide(ctx: TenantCtx, c: m.RadiusClient, profile: dict | None = None) -> dict:
    rs = ctx.session.get(m.RadiusSettings, ctx.id)
    if rs is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Save RADIUS settings first.")
    vlans = list(ctx.session.scalars(select(m.Vlan).where(m.Vlan.tenant_id == ctx.id)))
    plan = c.wired_profile if profile is None else profile
    if c.vendor == "cisco-switch" and not (plan or {}).get("interfaces"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This switch has no port plan yet. Edit it and list its access ports.")
    return wired.guide(c.vendor, client=c, profile=plan or {}, settings=rs, radius_ip=controller_address()["radius_address"], vlans=vlans, tenant=ctx.tenant)


@router.get("/clients/{client_id}/wired-guide")
def wired_guide(client_id: uuid.UUID, ctx: TenantCtx = Depends(require("radius:read"))) -> dict:
    c = ctx.session.get(m.RadiusClient, client_id)
    if c is None or c.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Switch not found.")
    if "wired" not in (c.networks or []) or c.vendor not in ("cisco-switch", "unifi", "other"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This client isn't a switch registered for wired 802.1X.")
    return _wired_guide(ctx, c)


def _since(hours: int) -> datetime:
    return datetime.now(UTC) - timedelta(hours=hours)


@router.get("/clients/{client_id}/readiness")
def readiness(client_id: uuid.UUID, ctx: TenantCtx = Depends(require("radius:read")), hours: int = 24) -> dict:
    """What EasyEAP saw from this switch, by port: the evidence for Enforce. Devices that never try 802.1X don't
    appear here, which is why Enforce also asks for the switch's own session list."""
    s = ctx.session
    c = s.get(m.RadiusClient, client_id)
    if c is None or c.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Switch not found.")
    hours = max(1, min(hours, 24 * 14))
    rows = s.scalars(select(m.AuthEvent).where(m.AuthEvent.tenant_id == ctx.id, m.AuthEvent.nas_client_id == c.id,
                                               m.AuthEvent.network == "wired", m.AuthEvent.at >= _since(hours))
                     .order_by(m.AuthEvent.at.desc()).limit(5000)).all()
    ports: dict[str, dict] = {}
    for e in rows:  # newest first: the first event per port and device is its latest result
        key = (e.nas_port_id or "(port not reported)", e.calling_station_id or "")
        p = ports.setdefault(key[0], {"port": key[0], "devices": {}, "accepted": 0, "rejected": 0})
        if key[1] not in p["devices"]:
            p["devices"][key[1]] = {"mac": key[1] or None, "username": e.username, "result": e.result, "reason_code": e.reason_code,
                                    "vlan_id": e.vlan_id, "monitor": e.monitor, "at": e.at.isoformat()}
            p["accepted" if e.result == "accept" else "rejected"] += 1
    out = [{**p, "devices": list(p["devices"].values())} for p in sorted(ports.values(), key=lambda p: p["port"])]
    vlans = sorted({d["vlan_id"] for p in out for d in p["devices"] if d["vlan_id"] and d["result"] == "accept"})
    return {"hours": hours, "ports": out, "events": len(rows), "would_assign_vlans": vlans,
            "rejected_devices": sum(p["rejected"] for p in out), "session_command": wired.session_command(c.wired_profile)}


class SessionsIn(BaseModel):
    text: str = Field(max_length=500_000)


@router.post("/clients/{client_id}/readiness/sessions")
def readiness_sessions(client_id: uuid.UUID, body: SessionsIn, ctx: TenantCtx = Depends(require("radius:read"))) -> dict:
    """Parse the pasted `show access-session` output: every session that isn't authorized loses access on Enforce."""
    c = ctx.session.get(m.RadiusClient, client_id)
    if c is None or c.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Switch not found.")
    rows = wired.parse_sessions(body.text)
    return {"sessions": len(rows), "authorized": sum(r["authorized"] for r in rows),
            "would_lose_access": [r for r in rows if not r["authorized"]][:1000], "parsed": bool(rows)}


# FreeRADIUS's own words for the two silent failures (it answers neither, so the switch only sees a timeout).
UNKNOWN_CLIENT = "unknown client"
BAD_SECRET = "Message-Authenticator"  # noqa: S105 — log text to match, not a secret


@router.get("/clients/{client_id}/activity")
def activity(client_id: uuid.UUID, ctx: TenantCtx = Depends(require("radius:read")), minutes: int = 30) -> dict:
    """The wizard's "waiting for the first request": the latest requests from this client, or why none arrived."""
    s = ctx.session
    c = s.get(m.RadiusClient, client_id)
    if c is None or c.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Controller or switch not found.")
    since = datetime.now(UTC) - timedelta(minutes=max(1, min(minutes, 24 * 60)))
    from app.routers.events import event_out
    events = s.scalars(select(m.AuthEvent).where(m.AuthEvent.tenant_id == ctx.id, m.AuthEvent.nas_client_id == c.id, m.AuthEvent.at >= since)
                       .order_by(m.AuthEvent.id.desc()).limit(10)).all()
    hints = [] if events else _silent_failures(s, ctx.id, c, since)
    return {"events": [event_out(e) for e in events], "last_request_at": c.last_request_at.isoformat() if c.last_request_at else None,
            "diagnostics": hints}


def _near(net: ipaddress.IPv4Network | ipaddress.IPv6Network, ip: str) -> bool:
    """In the registered range, or in the same /24 (/64) as it: the switch sending from another of its addresses."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a in net:
        return True
    wide = ipaddress.ip_network(f"{net.network_address}/{24 if net.version == 4 else 64}", strict=False)
    return a in wide


_IP_IN_LOG = __import__("re").compile(r"(?:from (?:unknown )?client |Received packet from )([0-9a-fA-F:.]+)")


def _silent_failures(s, tenant_id: uuid.UUID, c: m.RadiusClient, since: datetime) -> list[dict]:
    """System-log lines from FreeRADIUS about requests it dropped from near this client's address. The system log is
    platform-wide, so only lines naming an address near this client's are returned (never another tenant's)."""
    try:
        net = parse_address(c.address)
    except RadiusConfigError:
        return []
    set_platform(s)
    try:
        rows = s.scalars(select(m.SystemLog).where(m.SystemLog.source == "freeradius", m.SystemLog.at >= since,
                                                   or_(m.SystemLog.message.contains(UNKNOWN_CLIENT), m.SystemLog.message.contains(BAD_SECRET)))
                         .order_by(m.SystemLog.id.desc()).limit(200)).all()
    finally:
        set_tenant(s, tenant_id)
    out: dict[tuple[str, str], dict] = {}
    for r in rows:
        mt = _IP_IN_LOG.search(r.message)
        if not mt or not _near(net, mt.group(1)):
            continue
        ip = mt.group(1)
        if UNKNOWN_CLIENT in r.message:
            kind, text = "unknown_client", (f"EasyEAP received requests from {ip}, which isn't registered. The switch sends RADIUS from that address: "
                                            f"change this registration's address to {ip}, or set the source interface on the switch.")
        else:
            kind, text = "bad_secret", (f"Requests from {ip} have the wrong shared secret, so FreeRADIUS drops them. Paste the configuration again "
                                        "with the secret EasyEAP showed, or rotate the secret and use the new one.")
        out.setdefault((kind, ip), {"kind": kind, "address": ip, "at": r.at.isoformat(), "message": text})
    return list(out.values())


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


@router.get("/wired-kit")
def wired_kit(ctx: TenantCtx = Depends(require("radius:read"))) -> dict:
    """The Windows wired kit for IT (docs/plans/wired-8021x.md §7): LAN profile, install script, Group Policy steps.
    Contains no secrets: each user's existing EasyEAP certificate is what connects."""
    rs = ctx.session.get(m.RadiusSettings, ctx.id)
    if rs is None or not rs.server_hostname:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Save RADIUS settings first.")
    from app.enrollment import profiles
    from app.pki import service as pki
    issuing, root = pki.chain_pem(ctx.session, ctx.id)
    anchor = root or issuing
    slug = ctx.tenant.slug
    return {"server_name": rs.server_hostname,
            "files": [{"name": f"{slug}-wired.xml", "type": "application/xml", "content": profiles.windows_lan_xml(rs.server_hostname, anchor)},
                      {"name": f"{slug}-wired-setup.ps1", "type": "text/plain",
                       "content": profiles.windows_wired_script(rs.server_hostname, anchor, issuing, ctx.tenant.name)}],
            "gpo_steps": profiles.WINDOWS_GPO_STEPS,
            "notes": ["Run the script as administrator or SYSTEM: Intune (Scripts), an RMM, or a computer startup script.",
                      "It uses the EasyEAP certificate each user already has, so enroll users for Wi-Fi first.",
                      "With user certificates, wired 802.1X starts after sign-in: the sign-in screen has no network on an enforced port, "
                      "so domain-joined PCs need cached credentials. Machine certificates are planned."]}


@router.get("/coa")
def coa_requests(ctx: TenantCtx = Depends(require("radius:read"))) -> dict:
    rows = ctx.session.scalars(select(m.CoaRequest).where(m.CoaRequest.tenant_id == ctx.id).order_by(m.CoaRequest.created_at.desc()).limit(100)).all()
    return {"items": [{"id": str(r.id), "kind": r.kind, "attributes": r.attributes, "reason": r.reason, "status": r.status, "result_detail": r.result_detail,
                       "created_at": r.created_at.isoformat() if r.created_at else None, "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                       "nas_client_id": str(r.nas_client_id)} for r in rows]}
