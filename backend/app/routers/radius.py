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
from app.admin import cisco as admin_cisco
from app.admin import service as admin_service
from app.config import get_settings
from app.db import set_platform, set_tenant
from app.deps import TenantCtx, require
from app.pki import crypto
from app.pki.openbao import OpenBao
from app.radius import cisco_platforms as cp
from app.radius import guides, wired
from app.radius.state import RadiusConfigError, bump, check_address_unique, ensure_server_certificate, parse_address
from app.security.tokens import new_shared_secret

router = APIRouter(prefix="/api/tenants/{tenant_id}/radius", tags=["radius"])
VENDORS = ("cisco-9800", "cisco-aireos", "cisco-switch", "meraki", "unifi", "other")
SWITCH_VENDORS = ("cisco-switch", "meraki", "unifi", "other")  # vendors with a wired port plan
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
    caps = cp.caps_for(c.vendor, profile) if profile else None
    return {"id": str(c.id), "name": c.name, "vendor": c.vendor, "address": c.address, "site": c.site, "coa_enabled": c.coa_enabled,
            "coa_port": c.coa_port, "secret_set_at": c.secret_set_at.isoformat() if c.secret_set_at else None,
            "last_request_at": c.last_request_at.isoformat() if c.last_request_at else None,
            "networks": networks, "wired_profile": profile or None,
            # Monitor mode is what EasyEAP was told; it can't read the switch. Without a port plan (a client registered
            # before wired 802.1X) EasyEAP sends VLANs on wired requests as it always did: "enforce".
            "wired_mode": (profile.get("mode") or "enforce") if "wired" in networks else None,
            # Switch audit (SNMP): set up, and polling.
            "monitoring": {"set_up": bool((c.monitoring or {}).get("host") and c.snmp_secret_ct), "enabled": bool((c.monitoring or {}).get("enabled"))},
            # Cisco and Meraki: what this switch is and can do (app/radius/cisco_platforms.py), for the console's panel.
            "capabilities": caps.out() if caps else None, "switch_family": cp.describe(c.vendor, profile) if caps else None}


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


def agent_features(s) -> set[str]:
    """What the RADIUS agents that reported in the last 10 minutes support (an older agent reports none)."""
    since = datetime.now(UTC) - timedelta(minutes=10)
    out: set[str] = set()
    for a in s.scalars(select(m.AgentStatus).where(m.AgentStatus.last_seen_at >= since)):
        feats = (a.detail or {}).get("features")
        if isinstance(feats, list):
            out |= {str(f) for f in feats}
    return out


AGENT_TOO_OLD = ("RADIUS needs updating before it can answer this kind of switch. Update the EasyEAP RADIUS container (System "
                 "health shows its version), then save again.")


def _check_agent_answers(s, vendor: str, profile: dict | None) -> None:
    """Refuse a switch plan the RADIUS agents can't answer yet (cp.agent_needs)."""
    caps = cp.caps_for(vendor, profile) if profile else None
    if cp.agent_needs(caps) - agent_features(s):
        raise HTTPException(status.HTTP_409_CONFLICT, AGENT_TOO_OLD)


def agent_out(s) -> dict | None:
    a = s.scalars(select(m.AgentStatus).order_by(m.AgentStatus.last_seen_at.desc())).first()
    out = None
    if a:
        now = datetime.now(UTC)
        out = {"agent_id": a.agent_id, "last_seen_at": a.last_seen_at.isoformat(), "config_ok": a.config_ok, "config_error": a.config_error,
               "radius_running": a.radius_running, "state": radius_state(s, a, now), "serving": (a.detail or {}).get("tenants"),
               "serving_ids": (a.detail or {}).get("tenant_ids"),
               "snapshot_versions": a.snapshot_versions, "config_version": a.config_version,
               "online": (now - a.last_seen_at).total_seconds() < 90, "detail": a.detail,
               "features": sorted(agent_features(s))}
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
        # The MAC allow list has its own version; an agent from before MAC authentication doesn't report it (None).
        macs = (out["agent"].get("detail") or {}).get("mac_versions")
        out["agent"]["tenant_mac_in_sync"] = (macs.get(str(ctx.id)) == rs.mac_version) if isinstance(macs, dict) else None
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
        return ["wired"] if vendor in ("cisco-switch", "meraki") else ["wireless"]
    out = [n for n in NETWORKS if n in networks]
    if not out or len(set(networks)) != len(out):
        raise _bad("networks", "Choose Wi-Fi, wired or both.")
    return out


# Port-plan fields only EasyEAP sets: the rollout mode and its history, MAC authentication (changed through its own
# change, POST …/mab) and which control policy EasyEAP's latest change attached.
MANAGED = ("mode", "mode_set_at", "mode_set_by", "mab", "policy", "policy_prev", "last_change")


def _profile(vendor: str, networks: list[str], data: dict | None, current: dict | None, actor: str) -> dict:
    """A validated port plan. Keeps the rollout mode, MAC authentication and their history; a new plan starts in
    monitor mode (with MAC authentication as asked)."""
    if "wired" not in networks:
        return current or {}
    if data is None:
        return current or {}
    cur = current or {}
    new = not cur
    data = {**data}
    mab_asked = bool(data.get("mab"))
    for k in MANAGED:
        data.pop(k, None)
    if cur.get("mode") == "enforce" and any(data.get(k) != cur.get(k) for k in data):
        raise _bad("wired_profile", "This switch is enforcing. Move it back to monitor mode before changing its port plan, "
                   "so the configuration on the switch and in EasyEAP stay the same.")
    data["mode"] = cur.get("mode") or "monitor"
    data["mab"] = mab_asked if new else bool(cur.get("mab"))
    try:
        out = wired.validate_profile(vendor, data)
    except wired.WiredConfigError as exc:
        raise _bad(exc.field, str(exc)) from exc
    except ValidationError as exc:
        err = exc.errors()[0]
        raise _bad(".".join(str(x) for x in err.get("loc", ())) or "wired_profile", str(err.get("msg", "Invalid port plan")).removeprefix("Value error, ")) from exc
    out["mode_set_at"] = cur.get("mode_set_at") or datetime.now(UTC).isoformat()
    out["mode_set_by"] = cur.get("mode_set_by") or actor
    if new:
        cisco_ibns2 = vendor == "cisco-switch" and out.get("platform", "ibns2") == "ibns2"
        out["policy"] = wired.monitor_policy(wired.WiredProfile.model_validate(out)) if cisco_ibns2 else None
        out["last_change"] = "created"
    elif vendor == "cisco-switch" and (cur.get("platform") or "ibns2") != out.get("platform"):
        # Another platform (a corrected family): EasyEAP's configuration starts again, in monitor mode.
        ibns2 = out.get("platform") == "ibns2"
        out["policy"] = wired.monitor_policy(wired.WiredProfile.model_validate(out)) if ibns2 else None
        out["policy_prev"], out["last_change"] = None, "created"
    else:
        for k in ("policy", "policy_prev", "last_change"):
            out[k] = cur.get(k)
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


def _check_admin_address(s, tenant_id: uuid.UUID, address: str, exclude_id: uuid.UUID | None) -> None:
    """Admin logins share TCP 49 across tenants: the address must not overlap another tenant's admin-enabled device."""
    set_platform(s)
    try:
        clash = admin_service.overlapping_admin_client(s, tenant_id, address, exclude_id)
    finally:
        set_tenant(s, tenant_id)
    if clash is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "This address overlaps a device of another tenant that has admin logins on. "
                                                      "Each device needs a unique management address for TACACS+.")


def _norm(net) -> str:
    return str(net) if net.num_addresses > 1 else str(net.network_address)


def _same_address(typed: str, stored: str) -> bool:
    try:
        return _norm(ipaddress.ip_network(typed.strip(), strict=False)) == stored
    except ValueError:
        return False


@router.post("/clients", status_code=201)
def create_client(body: ClientIn, ctx: TenantCtx = Depends(require("radius:write"))) -> dict:
    if body.vendor not in VENDORS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Choose a controller or switch type.")
    s = ctx.session
    networks = _networks(body.vendor, body.networks)
    profile = _profile(body.vendor, networks, body.wired_profile if body.wired_profile is not None else ({} if "wired" in networks else None),
                       None, ctx.actor.label) if body.vendor in SWITCH_VENDORS else {}
    _check_agent_answers(s, body.vendor, profile)
    net = _check_address(s, ctx.id, body.address)
    secret = new_shared_secret()
    c = m.RadiusClient(tenant_id=ctx.id, name=body.name, vendor=body.vendor, address=_norm(net), networks=networks, wired_profile=profile,
                       site=body.site, secret_ct=crypto.encrypt(ctx.id, secret), coa_enabled=body.coa_enabled,
                       coa_port=body.coa_port or (1700 if body.vendor in ("cisco-9800", "cisco-switch", "meraki") else 3799))
    s.add(c)
    s.flush()
    bump(s, ctx.id)
    audit.record(s, ctx.actor, "radius.client_created", tenant_id=ctx.id, target_type="radius_client", target_id=c.id, target_label=f"{c.name} ({c.address})",
                 detail={"vendor": c.vendor, "coa": c.coa_enabled, "networks": networks, "wired_mode": profile.get("mode") if profile else None})
    # The secret is returned once and never again.
    return {"client": client_out(c), "shared_secret": secret}


_ADMIN_DEVICE = ("Administrators log in to this device through EasyEAP (Device administration). Changing its address, type or site, or "
                 "deleting it, needs a tenant administrator.")


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
    if c.admin_enabled and "admin:write" not in ctx.perms and (
            (given.get("address") and not _same_address(given["address"], c.address)) or vendor != c.vendor
            or ("site" in given and given["site"] is not None and given["site"] != c.site)):
        # The address decides which connections get TACACS+ answers and the site which administrators may log in.
        raise HTTPException(status.HTTP_403_FORBIDDEN, _ADMIN_DEVICE)
    networks = _networks(vendor, body.networks) if "networks" in given else list(c.networks or ["wireless"])
    if "wired" in networks and vendor in SWITCH_VENDORS:
        # A new vendor re-checks the plan it keeps (a Catalyst plan says nothing a Meraki switch can do, and back).
        plan = body.wired_profile if "wired_profile" in given else (dict(c.wired_profile) if c.wired_profile and vendor != c.vendor
                                                                     else None if c.wired_profile else {})
        profile = _profile(vendor, networks, plan, c.wired_profile, ctx.actor.label)
    else:
        profile = c.wired_profile or {}
    if vendor != c.vendor or profile != (c.wired_profile or {}):
        _check_agent_answers(s, vendor, profile)
        from app.routers.switch_audit import removal_changes
        if removal_changes(c, vendor, profile):
            # The switch audit's SNMP lines on the switch are the ones for its current family: removing them later must
            # use those, so the audit goes first (its Remove shows the lines).
            raise HTTPException(status.HTTP_409_CONFLICT, "This switch has the switch audit set up for its current type and "
                                "release. Remove the switch audit first (it shows the lines to take off the switch), then "
                                "change the switch, then set the audit up again.")
    was_admin = c.admin_enabled
    if "address" in given and body.address:
        c.address = _norm(_check_address(s, ctx.id, body.address, exclude_id=c.id))
        if c.admin_enabled:
            _check_admin_address(s, ctx.id, c.address, c.id)
    for k in ("name", "site", "coa_enabled", "coa_port"):
        if k in given and given[k] is not None:
            setattr(c, k, given[k])
    c.vendor, c.networks, c.wired_profile = vendor, networks, profile
    if c.admin_enabled and admin_cisco.unsupported(c) is not None:
        c.admin_enabled = False  # the device (type, or platform after a plan change) has no TACACS+ EasyEAP generates
    if was_admin:
        admin_service.bump(s, ctx.id)
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
    profile = dict(c.wired_profile or {})
    if body.mode == "enforce" and before == "monitor" and profile.get("mab"):
        _check_mab_answered(s, ctx.id, c)
    if c.vendor in ("cisco-switch", "meraki") and body.mode == "enforce" and before != "enforce":
        # A plan saved before EasyEAP knew the platform's limits must still be one the switch can carry out.
        try:
            wired.check_capabilities(c.vendor, wired.WiredProfile.model_validate(profile))
        except wired.WiredConfigError as exc:
            raise _bad(exc.field, f"{exc} Edit the switch's port plan first.") from exc
        except ValidationError:
            pass
    if c.vendor == "cisco-switch" and profile.get("interfaces"):
        try:
            p = wired.WiredProfile.model_validate(profile)
        except ValidationError:
            p = None
        if p is not None and p.platform == "ibns2" and before != body.mode:
            old = wired.attached_policy(p)
            p.mode = body.mode
            profile.update({"policy": wired.closed_policy(p) if body.mode == "enforce" else wired.monitor_policy(p), "policy_prev": old,
                            "last_change": body.mode})
    c.wired_profile = {**profile, "mode": body.mode, "mode_set_at": datetime.now(UTC).isoformat(), "mode_set_by": ctx.actor.label}
    bump(s, ctx.id)
    audit.record(s, ctx.actor, "radius.wired_mode_changed", tenant_id=ctx.id, target_type="radius_client", target_id=c.id, target_label=c.name,
                 detail={"from": before, "to": body.mode})
    return {"client": client_out(c), "guide": _wired_guide(ctx, c)}


def _check_mab_answered(s, tenant_id: uuid.UUID, c: m.RadiusClient) -> None:
    """Enforcing a switch with MAC authentication needs proof that EasyEAP answers its MAC requests: a switch whose
    MAB requests lack Message-Authenticator gets no answer at all (FreeRADIUS drops them without a trace) and would
    mark EasyEAP dead for every device on it (docs/plans/mac-auth.md §6.5)."""
    answered = s.scalar(select(func.count()).select_from(m.AuthEvent).where(
        m.AuthEvent.tenant_id == tenant_id, m.AuthEvent.nas_client_id == c.id, m.AuthEvent.method.in_(("mab", "mab-eap")),
        or_(m.AuthEvent.reason_code.is_(None), m.AuthEvent.reason_code != "mab_not_enabled"), m.AuthEvent.at >= _since(24 * 14)))
    if not answered:
        raise HTTPException(status.HTTP_409_CONFLICT, {"field": "mab", "message": (
            "EasyEAP hasn't answered a MAC authentication request from this switch yet, so enforcing could cut off its devices without "
            "802.1X. Plug in a device without 802.1X (a printer, say) and wait for its request in the Authentication log. If none "
            "arrives, the switch may send MAC requests without Message-Authenticator, which EasyEAP requires: check with "
            "debug radius on the switch.")})


class DetectIn(BaseModel):
    text: str = Field(max_length=20000)


@router.post("/cisco/detect")
def detect_cisco(body: DetectIn, ctx: TenantCtx = Depends(require("radius:read"))) -> dict:
    """What a pasted `show version` (or Cisco Business `show system`) says the switch is, and what that switch can do.
    Pure: the text isn't stored."""
    d = cp.detect(body.text)
    caps = cp.caps(d.platform, d.series, d.version, d.lan_lite) if d.platform and not d.unsupported else None
    return {"detected": d.out(), "capabilities": caps.out() if caps else None}


@router.get("/cisco/platforms")
def cisco_platforms(platform: str = "ibns2", series: str = "", version: str = "", lan_lite: bool = False, vendor: str = "cisco-switch",
                    ctx: TenantCtx = Depends(require("radius:read"))) -> dict:
    """The families, series and what a given switch can do: the console's port-plan form offers only these choices."""
    if platform not in cp.PLATFORMS or vendor not in ("cisco-switch", "meraki"):
        raise _bad("platform", "Unknown switch family.")
    caps = cp.caps(platform, series, cp.clean_version(version), lan_lite, vendor)
    return {"platforms": list(cp.PLATFORMS), "series": {k: list(v) for k, v in cp.SERIES.items()}, "series_labels": cp.SERIES_LABELS,
            "capabilities": caps.out()}


class MabIn(BaseModel):
    enabled: bool


@router.post("/clients/{client_id}/mab")
def set_mab(client_id: uuid.UUID, body: MabIn, ctx: TenantCtx = Depends(require("radius:write"))) -> dict:
    """Turn MAC authentication on or off for a switch (docs/plans/mac-auth.md §6.5). Monitor mode only: the change
    swaps the ports' control policy, which is safe only while they're open. Returns the change to paste."""
    s = ctx.session
    c = s.get(m.RadiusClient, client_id)
    if c is None or c.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Switch not found.")
    if "wired" not in (c.networks or []) or c.vendor not in ("cisco-switch", "meraki", "unifi") or not c.wired_profile:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MAC authentication is available for Cisco and UniFi switches with a port plan.")
    profile = dict(c.wired_profile)
    caps = cp.caps_for(c.vendor, profile)
    if caps is not None and caps.mab is None and body.enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "This switch can't do MAC authentication: " + " ".join(caps.notes[:1]))
    if caps is not None and caps.monitor == "server" and not body.enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MAC authentication stays on for this switch: it has no open (monitor) mode, so "
                            "EasyEAP's monitor mode accepts its MAC requests, and that's how devices without 802.1X keep working.")
    if profile.get("mode") != "monitor":
        raise HTTPException(status.HTTP_409_CONFLICT, "Move this switch back to monitor mode first: MAC authentication is turned on or off "
                            "while its ports are open, and proves itself there before you enforce again.")
    if body.enabled and "mab" not in agent_features(s):
        raise HTTPException(status.HTTP_409_CONFLICT, "RADIUS doesn't support MAC authentication yet. Update the EasyEAP RADIUS container "
                            "(System health shows its version), then try again.")
    if bool(profile.get("mab")) == body.enabled:
        return {"client": client_out(c), "guide": _wired_guide(ctx, c)}
    p = wired.WiredProfile.model_validate(profile)
    ibns2 = c.vendor == "cisco-switch" and p.platform == "ibns2"
    old = wired.attached_policy(p) if ibns2 else None
    p.mab = body.enabled
    profile.update({"mab": body.enabled, "last_change": "mab", "policy_prev": old, "policy": wired.monitor_policy(p) if ibns2 else None})
    c.wired_profile = profile
    bump(s, ctx.id)
    audit.record(s, ctx.actor, "radius.mab_changed", tenant_id=ctx.id, target_type="radius_client", target_id=c.id, target_label=c.name,
                 detail={"enabled": body.enabled})
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
    if "wired" not in (c.networks or []) or c.vendor not in SWITCH_VENDORS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This client isn't a switch registered for wired 802.1X.")
    return _wired_guide(ctx, c)


def wired_mac(mac: str) -> str:
    from app.mac import format_mac
    return format_mac(mac)


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
        key = (e.nas_port_id or "(port not reported)", e.mac or e.calling_station_id or "")
        p = ports.setdefault(key[0], {"port": key[0], "devices": {}, "accepted": 0, "rejected": 0})
        if key[1] not in p["devices"]:
            p["devices"][key[1]] = {"mac": e.calling_station_id or (wired_mac(e.mac) if e.mac else None), "username": e.username,
                                    "result": e.result, "reason_code": e.reason_code, "vlan_id": e.vlan_id, "monitor": e.monitor,
                                    "at": e.at.isoformat(), "method": "mac" if e.method in ("mab", "mab-eap") else "certificate"}
            p["accepted" if e.result == "accept" else "rejected"] += 1
    out = [{**p, "devices": list(p["devices"].values())} for p in sorted(ports.values(), key=lambda p: p["port"])]
    vlans = sorted({d["vlan_id"] for p in out for d in p["devices"] if d["vlan_id"] and d["result"] == "accept"})
    profile = c.wired_profile or {}
    mab_rows = [e for e in rows if e.method in ("mab", "mab-eap") and e.reason_code != "mab_not_enabled"]
    from app.switchaudit.service import polled_sessions
    return {"hours": hours, "ports": out, "events": len(rows), "would_assign_vlans": vlans,
            "rejected_devices": sum(p["rejected"] for p in out), "session_command": wired.session_command(profile, c.vendor),
            # The switch's own session list from the switch audit's latest poll, when monitoring is on: no paste needed.
            "switch_sessions": polled_sessions(s.get(m.SwitchState, c.id), int((c.monitoring or {}).get("interval_minutes") or 15))
            if (c.monitoring or {}).get("enabled") else None,
            # MAC authentication health: requests answered in the window (unknown devices are logged once an hour each).
            "mab": {"enabled": bool(profile.get("mab")), "answered": len(mab_rows), "accepted": sum(e.result == "accept" for e in mab_rows),
                    "unknown": len({e.mac for e in mab_rows if e.reason_code == "mac_unknown"}),
                    "last_at": max((e.at for e in mab_rows), default=None),
                    "unknown_action": "vlan" if profile.get("no_supplicant") == "vlan" else "block",
                    "unknown_vlan": profile.get("no_supplicant_vlan")} if profile.get("mab") else None}


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


@router.post("/clients/{client_id}/secret")
def show_secret(client_id: uuid.UUID, ctx: TenantCtx = Depends(require("radius:secrets"))) -> dict:
    """The shared secret again, to fill in the configuration: whoever may rotate it may see it. Each showing is audited."""
    c = ctx.session.get(m.RadiusClient, client_id)
    if c is None or c.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Controller or switch not found.")
    secret = crypto.decrypt_str(ctx.id, c.secret_ct)
    audit.record(ctx.session, ctx.actor, "radius.client_secret_shown", tenant_id=ctx.id, target_type="radius_client", target_id=c.id,
                 target_label=c.name)
    return {"shared_secret": secret}


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
    if c.admin_enabled:
        if "admin:write" not in ctx.perms:
            raise HTTPException(status.HTTP_403_FORBIDDEN, _ADMIN_DEVICE)
        admin_service.bump(ctx.session, ctx.id)
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
                      "With user certificates, wired 802.1X starts after sign-in: the sign-in screen has no network on an enforced port. "
                      "For network at the sign-in screen, use the Windows setup file (a user's page → Windows setup) instead: it adds "
                      "the computer's certificate and its own wired profile.",
                      "For domain PCs, Windows Group Policy (next to this kit) has the full steps: trust, services, Wi-Fi and wired policies."]}


@router.get("/group-policy")
def group_policy(ctx: TenantCtx = Depends(require("radius:read"))) -> dict:
    """Group Policy for domain PCs (docs/windows-group-policy.md) with the tenant's values and files. No secrets."""
    rs = ctx.session.get(m.RadiusSettings, ctx.id)
    if rs is None or not rs.server_hostname:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Save RADIUS settings first.")
    from app.enrollment import profiles
    from app.pki import service as pki
    issuing, root = pki.chain_pem(ctx.session, ctx.id)
    return profiles.group_policy_guide(server_name=rs.server_hostname, ssid=rs.ssid or "EasyEAP", wpa3=bool(rs.wpa3),
                                       root_pem=root or issuing, issuing_pem=issuing, slug=ctx.tenant.slug)


@router.get("/coa")
def coa_requests(ctx: TenantCtx = Depends(require("radius:read"))) -> dict:
    rows = ctx.session.scalars(select(m.CoaRequest).where(m.CoaRequest.tenant_id == ctx.id).order_by(m.CoaRequest.created_at.desc()).limit(100)).all()
    return {"items": [{"id": str(r.id), "kind": r.kind, "attributes": r.attributes, "reason": r.reason, "status": r.status, "result_detail": r.result_detail,
                       "created_at": r.created_at.isoformat() if r.created_at else None, "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                       "nas_client_id": str(r.nas_client_id)} for r in rows]}
