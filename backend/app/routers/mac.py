"""The MAC allow list (docs/plans/mac-auth.md §7): device groups, MAC devices, import/export, and the MACs switches
asked about that aren't on it ("Seen, not allowed").

Every change bumps the allow list's own snapshot version, and changes that affect a live session queue CoA for it:
block, delete, a group turned off → Disconnect; unblock → re-authenticate; a new VLAN → bounce the port (Cisco).
"""
from __future__ import annotations

import csv
import io
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select

from app import audit
from app import models as m
from app.deps import TenantCtx, require
from app.mac import MacError, format_mac, normalize_mac
from app.policy.service import wired_vlan_map
from app.radius import mab

router = APIRouter(prefix="/api/tenants/{tenant_id}/mac", tags=["mac"])
MAX_IMPORT_LINES = 1000
COA_CAP = 500  # CoA requests queued by one group change; beyond that, sessions update at their next re-authentication


def _bad(field: str, message: str, code: str | None = None) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, {"field": field, "message": message, **({"code": code} if code else {})})


def _vlans(ctx: TenantCtx) -> tuple[dict[uuid.UUID, m.Vlan], dict[int, int | None]]:
    s = ctx.session
    return ({v.id: v for v in s.scalars(select(m.Vlan).where(m.Vlan.tenant_id == ctx.id))}, wired_vlan_map(s, ctx.id))


def group_out(g: m.DeviceGroup, vlans: dict[uuid.UUID, m.Vlan], mapping: dict[int, int | None], devices: int,
              cert_vlans: set[uuid.UUID]) -> dict:
    v = vlans.get(g.vlan_ref) if g.vlan_ref else None
    return {"id": str(g.id), "name": g.name, "description": g.description, "vlan_ref": str(g.vlan_ref) if g.vlan_ref else None,
            "vlan_id": v.vlan_id if v else None, "vlan_name": v.name if v else None, "port_vlan": g.port_vlan, "enabled": g.enabled,
            "switch_vlan": mab.group_switch_vlan(g, {k: x.vlan_id for k, x in vlans.items()}, mapping), "devices": devices,
            # The same VLAN as certificate users: a copied MAC lands next to them.
            "shared_with_certificates": bool(g.vlan_ref and g.vlan_ref in cert_vlans)}


def status_of(d: m.MacDevice, g: m.DeviceGroup | None, now: datetime) -> str:
    if not d.enabled:
        return "blocked"
    if d.expires_at and d.expires_at <= now:
        return "expired"
    if g is not None and not g.enabled:
        return "group_off"
    return "allowed"


def device_out(d: m.MacDevice, groups: dict[uuid.UUID, m.DeviceGroup], clients: dict[uuid.UUID, str], now: datetime) -> dict:
    g = groups.get(d.group_id)
    return {"id": str(d.id), "mac": format_mac(d.mac), "name": d.name, "notes": d.notes, "group_id": str(d.group_id),
            "group_name": g.name if g else None, "enabled": d.enabled, "expires_at": d.expires_at.isoformat() if d.expires_at else None,
            "source": d.source, "created_at": d.created_at.isoformat() if d.created_at else None, "created_by": d.created_by,
            "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
            "last_seen_client": clients.get(d.last_seen_client_id) if d.last_seen_client_id else None, "last_seen_port": d.last_seen_port,
            "status": status_of(d, g, now), "randomized": is_randomized(d.mac)}


def is_randomized(mac: str) -> bool:
    """Locally administered (the second-lowest bit of the first octet): phones and laptops randomise these per network,
    so an entry for one stops matching when the device picks a new one."""
    return bool(int(mac[1], 16) & 2)


def _cert_vlans(ctx: TenantCtx) -> set[uuid.UUID]:
    return {r for (r,) in ctx.session.execute(select(m.AccessRule.vlan_ref).where(m.AccessRule.tenant_id == ctx.id, m.AccessRule.action == "allow",
                                                                                   m.AccessRule.vlan_ref.is_not(None)))}


def _clients(ctx: TenantCtx) -> dict[uuid.UUID, str]:
    return {c.id: c.name for c in ctx.session.scalars(select(m.RadiusClient).where(m.RadiusClient.tenant_id == ctx.id))}


def certificate_macs(ctx: TenantCtx, macs: set[str] | None = None) -> set[str]:
    """MACs of devices that authenticate with certificates (EAP-TLS accepts in 90 days, or an enrolled device's last-seen
    MAC). Listing one would let anyone who copies that MAC skip the certificate."""
    s = ctx.session
    q = select(m.AuthEvent.mac).where(m.AuthEvent.tenant_id == ctx.id, m.AuthEvent.result == "accept", m.AuthEvent.cert_serial.is_not(None),
                                      m.AuthEvent.mac.is_not(None), m.AuthEvent.at >= datetime.now(UTC) - timedelta(days=90)).distinct()
    if macs is not None:
        q = q.where(m.AuthEvent.mac.in_(macs))
    out = {x for (x,) in s.execute(q)}
    for (raw,) in s.execute(select(m.Device.last_seen_mac).where(m.Device.tenant_id == ctx.id, m.Device.last_seen_mac.is_not(None))):
        try:
            out.add(normalize_mac(raw))
        except MacError:
            continue
    return out if macs is None else out & macs


# ── Overview ─────────────────────────────────────────────────────────────────


@router.get("")
def overview(ctx: TenantCtx = Depends(require("mac:read"))) -> dict:
    s = ctx.session
    now = datetime.now(UTC)
    vlans, mapping = _vlans(ctx)
    groups = {g.id: g for g in s.scalars(select(m.DeviceGroup).where(m.DeviceGroup.tenant_id == ctx.id).order_by(m.DeviceGroup.name))}
    counts = dict(s.execute(select(m.MacDevice.group_id, func.count()).where(m.MacDevice.tenant_id == ctx.id).group_by(m.MacDevice.group_id)).all())
    clients = _clients(ctx)
    devices = s.scalars(select(m.MacDevice).where(m.MacDevice.tenant_id == ctx.id).order_by(m.MacDevice.name, m.MacDevice.mac).limit(mab.MAX_DEVICES)).all()
    cert = _cert_vlans(ctx)
    switches = [c for c in s.scalars(select(m.RadiusClient).where(m.RadiusClient.tenant_id == ctx.id)) if "wired" in (c.networks or [])]
    return {"groups": [group_out(g, vlans, mapping, counts.get(g.id, 0), cert) for g in groups.values()],
            "devices": [device_out(d, groups, clients, now) for d in devices],
            "limits": {"devices": mab.MAX_DEVICES, "groups": mab.MAX_GROUPS, "import_lines": MAX_IMPORT_LINES},
            "switches_with_mab": [{"id": str(c.id), "name": c.name, "mode": (c.wired_profile or {}).get("mode")} for c in switches
                                  if (c.wired_profile or {}).get("mab")]}


# ── Groups ───────────────────────────────────────────────────────────────────


class GroupIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(default="", max_length=300)
    vlan_ref: uuid.UUID | None = None
    port_vlan: bool = False
    enabled: bool = True


def _check_group_vlan(ctx: TenantCtx, body: GroupIn) -> None:
    if body.port_vlan and body.vlan_ref:
        raise _bad("vlan_ref", "Choose a VLAN or the port's own VLAN, not both.")
    if not body.port_vlan and not body.vlan_ref:
        raise _bad("vlan_ref", "Choose the VLAN for devices in this group. A MAC address is easy to copy, so give them a VLAN that reaches only what they need.")
    if body.vlan_ref:
        v = ctx.session.get(m.Vlan, body.vlan_ref)
        if v is None or v.tenant_id != ctx.id:
            raise _bad("vlan_ref", "That VLAN doesn't exist. Add it in Access policy first.")


def _name_taken(ctx: TenantCtx, name: str, exclude: uuid.UUID | None = None) -> bool:
    q = select(m.DeviceGroup.id).where(m.DeviceGroup.tenant_id == ctx.id, func.lower(m.DeviceGroup.name) == name.strip().lower())
    if exclude:
        q = q.where(m.DeviceGroup.id != exclude)
    return ctx.session.scalar(q) is not None


@router.post("/groups", status_code=201)
def create_group(body: GroupIn, ctx: TenantCtx = Depends(require("mac:write"))) -> dict:
    s = ctx.session
    _check_group_vlan(ctx, body)
    if s.scalar(select(func.count()).select_from(m.DeviceGroup).where(m.DeviceGroup.tenant_id == ctx.id)) >= mab.MAX_GROUPS:
        raise _bad("name", f"A tenant can have at most {mab.MAX_GROUPS} groups.")
    if _name_taken(ctx, body.name):
        raise _bad("name", "A group with this name already exists.")
    g = m.DeviceGroup(tenant_id=ctx.id, name=body.name.strip(), description=body.description, vlan_ref=body.vlan_ref,
                      port_vlan=body.port_vlan, enabled=body.enabled)
    s.add(g)
    s.flush()
    mab.bump_mac(s, ctx.id)
    audit.record(s, ctx.actor, "device_group.created", tenant_id=ctx.id, target_type="device_group", target_id=g.id, target_label=g.name,
                 detail={"vlan_ref": str(g.vlan_ref) if g.vlan_ref else None, "port_vlan": g.port_vlan})
    vlans, mapping = _vlans(ctx)
    return group_out(g, vlans, mapping, 0, _cert_vlans(ctx))


def _coa_group(ctx: TenantCtx, g: m.DeviceGroup, kind: str, reason: str) -> dict:
    total = {"sessions": 0, "queued": 0, "without_coa": 0, "skipped": 0}
    devices = ctx.session.scalars(select(m.MacDevice).where(m.MacDevice.tenant_id == ctx.id, m.MacDevice.group_id == g.id,
                                                            m.MacDevice.enabled.is_(True))).all()
    for i, d in enumerate(devices):
        if i >= COA_CAP:
            total["skipped"] += 1
            continue
        r = mab.coa_for_mac(ctx.session, ctx.id, d.mac, kind, reason)
        for k in ("sessions", "queued", "without_coa"):
            total[k] += r[k]
    return total


@router.put("/groups/{group_id}")
def update_group(group_id: uuid.UUID, body: GroupIn, ctx: TenantCtx = Depends(require("mac:write"))) -> dict:
    s = ctx.session
    g = s.get(m.DeviceGroup, group_id)
    if g is None or g.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Group not found.")
    _check_group_vlan(ctx, body)
    if _name_taken(ctx, body.name, exclude=g.id):
        raise _bad("name", "A group with this name already exists.")
    vlans, mapping = _vlans(ctx)
    ids = {k: v.vlan_id for k, v in vlans.items()}
    before_vlan, before_enabled = mab.group_switch_vlan(g, ids, mapping), g.enabled
    g.name, g.description, g.vlan_ref, g.port_vlan, g.enabled = body.name.strip(), body.description, body.vlan_ref, body.port_vlan, body.enabled
    s.flush()
    mab.bump_mac(s, ctx.id)
    coa = None
    if before_enabled and not g.enabled:
        coa = _coa_group(ctx, g, "disconnect", f"MAC allow-list group {g.name} turned off")
    elif not before_enabled and g.enabled:
        coa = _coa_group(ctx, g, "reauthenticate", f"MAC allow-list group {g.name} turned on")
    elif g.enabled and mab.group_switch_vlan(g, ids, mapping) != before_vlan:
        # A new VLAN needs a new address: bouncing the port makes the device ask for one (disruptive on shared ports).
        coa = _coa_group(ctx, g, "bounce", f"MAC allow-list group {g.name} moved to another VLAN")
    audit.record(s, ctx.actor, "device_group.updated", tenant_id=ctx.id, target_type="device_group", target_id=g.id, target_label=g.name,
                 detail={**body.model_dump(mode="json"), "coa": coa})
    count = s.scalar(select(func.count()).select_from(m.MacDevice).where(m.MacDevice.group_id == g.id)) or 0
    return {**group_out(g, vlans, mapping, count, _cert_vlans(ctx)), "coa": coa}


@router.delete("/groups/{group_id}")
def delete_group(group_id: uuid.UUID, ctx: TenantCtx = Depends(require("mac:write"))) -> dict:
    s = ctx.session
    g = s.get(m.DeviceGroup, group_id)
    if g is None or g.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Group not found.")
    n = s.scalar(select(func.count()).select_from(m.MacDevice).where(m.MacDevice.group_id == g.id)) or 0
    if n:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{n} device{' is' if n == 1 else 's are'} in this group. Move or delete them first.")
    s.delete(g)
    mab.bump_mac(s, ctx.id)
    audit.record(s, ctx.actor, "device_group.deleted", tenant_id=ctx.id, target_type="device_group", target_id=group_id, target_label=g.name)
    return {"ok": True}


# ── Devices ──────────────────────────────────────────────────────────────────


class DeviceIn(BaseModel):
    mac: str = Field(min_length=12, max_length=17)
    name: str = Field(min_length=1, max_length=120)
    group_id: uuid.UUID
    notes: str = Field(default="", max_length=500)
    expires_at: datetime | None = None
    enabled: bool = True
    # The MAC belongs to a device that uses a certificate: the admin confirmed listing it anyway.
    confirm_certificate: bool = False


class DeviceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    group_id: uuid.UUID | None = None
    notes: str | None = Field(default=None, max_length=500)
    expires_at: datetime | None = None
    clear_expiry: bool = False
    enabled: bool | None = None


def _group(ctx: TenantCtx, group_id: uuid.UUID) -> m.DeviceGroup:
    g = ctx.session.get(m.DeviceGroup, group_id)
    if g is None or g.tenant_id != ctx.id:
        raise _bad("group_id", "Choose a group.")
    return g


def _room(ctx: TenantCtx, adding: int) -> None:
    n = ctx.session.scalar(select(func.count()).select_from(m.MacDevice).where(m.MacDevice.tenant_id == ctx.id)) or 0
    if n + adding > mab.MAX_DEVICES:
        raise _bad("mac", f"A tenant can list at most {mab.MAX_DEVICES:,} devices ({n:,} now).")


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _detail(ctx: TenantCtx, d: m.MacDevice) -> dict:
    s = ctx.session
    groups = {g.id: g for g in s.scalars(select(m.DeviceGroup).where(m.DeviceGroup.tenant_id == ctx.id))}
    return device_out(d, groups, _clients(ctx), datetime.now(UTC))


@router.post("/devices", status_code=201)
def create_device(body: DeviceIn, ctx: TenantCtx = Depends(require("mac:write"))) -> dict:
    s = ctx.session
    try:
        mac = normalize_mac(body.mac)
    except MacError as exc:
        raise _bad("mac", str(exc)) from exc
    g = _group(ctx, body.group_id)
    if s.scalar(select(m.MacDevice.id).where(m.MacDevice.tenant_id == ctx.id, m.MacDevice.mac == mac)):
        raise _bad("mac", f"{format_mac(mac)} is already on the MAC allow list.")
    if not body.confirm_certificate and certificate_macs(ctx, {mac}):
        raise _bad("mac", f"{format_mac(mac)} belongs to a device that signs in with a certificate. Listing it lets anything that copies "
                   "this address onto the network without one.", code="certificate_device")
    _room(ctx, 1)
    d = m.MacDevice(tenant_id=ctx.id, mac=mac, name=body.name.strip(), notes=body.notes, group_id=g.id, enabled=body.enabled,
                    expires_at=_utc(body.expires_at), source="manual", created_by=ctx.actor.label[:254])
    s.add(d)
    s.flush()
    _learned(ctx, d)
    mab.bump_mac(s, ctx.id)
    coa = mab.coa_for_mac(s, ctx.id, mac, "reauthenticate", "Added to the MAC allow list") if d.enabled else None
    audit.record(s, ctx.actor, "mac_device.created", tenant_id=ctx.id, target_type="mac_device", target_id=d.id,
                 target_label=f"{d.name} ({format_mac(mac)})", detail={"group": g.name, "certificate_confirmed": body.confirm_certificate})
    return {**_detail(ctx, d), "coa": coa}


def _learned(ctx: TenantCtx, d: m.MacDevice) -> None:
    """A MAC allowed from "Seen, not allowed" keeps where it was seen and leaves that list."""
    rows = ctx.session.scalars(select(m.MacSighting).where(m.MacSighting.tenant_id == ctx.id, m.MacSighting.mac == d.mac)
                               .order_by(m.MacSighting.last_seen.desc())).all()
    if rows:
        d.source = "learned" if d.source == "manual" else d.source
        d.last_seen_at, d.last_seen_client_id, d.last_seen_port = rows[0].last_seen, rows[0].client_id, rows[0].port or None
        for r in rows:
            ctx.session.delete(r)


@router.get("/devices/{device_id}")
def get_device(device_id: uuid.UUID, ctx: TenantCtx = Depends(require("mac:read"))) -> dict:
    s = ctx.session
    d = s.get(m.MacDevice, device_id)
    if d is None or d.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found.")
    clients = _clients(ctx)
    events = s.scalars(select(m.AuthEvent).where(m.AuthEvent.tenant_id == ctx.id, m.AuthEvent.mac == d.mac)
                       .order_by(m.AuthEvent.at.desc()).limit(50)).all()
    eap_rejects = [e for e in events if e.result == "reject" and e.method not in ("mab", "mab-eap") and e.at >= datetime.now(UTC) - timedelta(days=7)]
    return {**_detail(ctx, d),
            "events": [{"id": e.id, "at": e.at.isoformat(), "result": e.result, "reason_code": e.reason_code, "method": e.method,
                        "switch": clients.get(e.nas_client_id) if e.nas_client_id else None, "port": e.nas_port_id, "vlan_id": e.vlan_id,
                        "monitor": e.monitor} for e in events],
            # It answers 802.1X and fails, so the switch never tries MAB for it (docs/plans/mac-auth.md §6.2).
            "answers_8021x": bool(eap_rejects), "certificate_device": bool(certificate_macs(ctx, {d.mac}))}


@router.put("/devices/{device_id}")
def update_device(device_id: uuid.UUID, body: DeviceUpdate, ctx: TenantCtx = Depends(require("mac:write"))) -> dict:
    s = ctx.session
    d = s.get(m.MacDevice, device_id)
    if d is None or d.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found.")
    vlans, mapping = _vlans(ctx)
    ids = {k: v.vlan_id for k, v in vlans.items()}
    old_group = s.get(m.DeviceGroup, d.group_id)
    before = {"enabled": d.enabled, "vlan": mab.group_switch_vlan(old_group, ids, mapping) if old_group else None,
              "group_enabled": old_group.enabled if old_group else True}
    if body.name is not None:
        d.name = body.name.strip()
    if body.notes is not None:
        d.notes = body.notes
    if body.group_id is not None:
        d.group_id = _group(ctx, body.group_id).id
    if body.clear_expiry:
        d.expires_at = None
    elif body.expires_at is not None:
        d.expires_at = _utc(body.expires_at)
    if body.enabled is not None:
        d.enabled = body.enabled
    s.flush()
    mab.bump_mac(s, ctx.id)
    g = s.get(m.DeviceGroup, d.group_id)
    now = datetime.now(UTC)
    ok_now = d.enabled and g.enabled and not (d.expires_at and d.expires_at <= now)
    ok_before = before["enabled"] and before["group_enabled"]
    coa = None
    if ok_before and not ok_now:
        coa = mab.coa_for_mac(s, ctx.id, d.mac, "disconnect", "Blocked on the MAC allow list" if not d.enabled else "MAC allow-list entry no longer valid")
    elif ok_now and not ok_before:
        coa = mab.coa_for_mac(s, ctx.id, d.mac, "reauthenticate", "Allowed on the MAC allow list")
    elif ok_now and mab.group_switch_vlan(g, ids, mapping) != before["vlan"]:
        coa = mab.coa_for_mac(s, ctx.id, d.mac, "bounce", "Moved to another VLAN on the MAC allow list")
    action = "mac_device.blocked" if before["enabled"] and not d.enabled else "mac_device.unblocked" if not before["enabled"] and d.enabled else "mac_device.updated"
    audit.record(s, ctx.actor, action, tenant_id=ctx.id, target_type="mac_device", target_id=d.id, target_label=f"{d.name} ({format_mac(d.mac)})",
                 detail={**body.model_dump(mode="json", exclude_unset=True), "coa": coa})
    return {**_detail(ctx, d), "coa": coa}


@router.delete("/devices/{device_id}")
def delete_device(device_id: uuid.UUID, ctx: TenantCtx = Depends(require("mac:write"))) -> dict:
    s = ctx.session
    d = s.get(m.MacDevice, device_id)
    if d is None or d.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found.")
    label = f"{d.name} ({format_mac(d.mac)})"
    coa = mab.coa_for_mac(s, ctx.id, d.mac, "disconnect", "Removed from the MAC allow list") if d.enabled else None
    s.delete(d)
    mab.bump_mac(s, ctx.id)
    audit.record(s, ctx.actor, "mac_device.deleted", tenant_id=ctx.id, target_type="mac_device", target_id=device_id, target_label=label, detail={"coa": coa})
    return {"ok": True, "coa": coa}


# ── Import / export / bulk allow ─────────────────────────────────────────────


class ImportIn(BaseModel):
    text: str = Field(max_length=200_000)
    group_id: uuid.UUID  # for lines without a group
    confirm_certificate: bool = False


@router.post("/devices/import")
def import_devices(body: ImportIn, ctx: TenantCtx = Depends(require("mac:write"))) -> dict:
    """Lines of `MAC[,name[,group]]` (a header line and blank lines are skipped). Nothing is added unless every line is
    valid, so a typo never half-imports a list."""
    s = ctx.session
    default = _group(ctx, body.group_id)
    groups = {g.name.lower(): g for g in s.scalars(select(m.DeviceGroup).where(m.DeviceGroup.tenant_id == ctx.id))}
    existing = {x for (x,) in s.execute(select(m.MacDevice.mac).where(m.MacDevice.tenant_id == ctx.id))}
    lines = [ln for ln in body.text.splitlines()]
    if len([ln for ln in lines if ln.strip()]) > MAX_IMPORT_LINES:
        raise _bad("text", f"Import at most {MAX_IMPORT_LINES} lines at a time.")
    errors: list[dict[str, Any]] = []
    rows: list[tuple[str, str, m.DeviceGroup]] = []
    seen: set[str] = set()
    for n, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in next(csv.reader([line]))]
        if n == 1 and parts and parts[0].lower() in ("mac", "mac address", "address"):
            continue
        try:
            mac = normalize_mac(parts[0])
        except MacError as exc:
            errors.append({"line": n, "text": line[:200], "message": str(exc)})
            continue
        name = (parts[1] if len(parts) > 1 and parts[1] else format_mac(mac))[:120]
        g = default
        if len(parts) > 2 and parts[2]:
            g = groups.get(parts[2].lower())
            if g is None:
                errors.append({"line": n, "text": line[:200], "message": f"There's no group “{parts[2][:80]}”."})
                continue
        if mac in existing or mac in seen:
            errors.append({"line": n, "text": line[:200], "message": f"{format_mac(mac)} is already on the list."})
            continue
        seen.add(mac)
        rows.append((mac, name, g))
    cert = certificate_macs(ctx, {r[0] for r in rows}) if rows else set()
    if cert and not body.confirm_certificate:
        errors += [{"line": None, "text": format_mac(mac), "message": "This MAC belongs to a device that signs in with a certificate.",
                    "code": "certificate_device"} for mac, _, _ in rows if mac in cert]
    if errors:
        return {"added": 0, "errors": sorted(errors, key=lambda e: e["line"] or 0)[:500], "valid": len(rows)}
    _room(ctx, len(rows))
    for mac, name, g in rows:
        d = m.MacDevice(tenant_id=ctx.id, mac=mac, name=name, group_id=g.id, source="import", created_by=ctx.actor.label[:254])
        s.add(d)
        s.flush()
        _learned(ctx, d)
    if rows:
        mab.bump_mac(s, ctx.id)
    audit.record(s, ctx.actor, "mac_device.imported", tenant_id=ctx.id, target_type="mac_device", target_label=f"{len(rows)} devices",
                 detail={"count": len(rows), "certificate_confirmed": sorted(format_mac(x) for x in cert)})
    return {"added": len(rows), "errors": [], "valid": len(rows)}


@router.get("/devices.csv")
def export_devices(ctx: TenantCtx = Depends(require("mac:read"))) -> Response:
    s = ctx.session
    now = datetime.now(UTC)
    groups = {g.id: g for g in s.scalars(select(m.DeviceGroup).where(m.DeviceGroup.tenant_id == ctx.id))}
    clients = _clients(ctx)
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["mac", "name", "group", "status", "expires_at", "last_seen_at", "last_seen_switch", "last_seen_port", "notes"])
    for d in s.scalars(select(m.MacDevice).where(m.MacDevice.tenant_id == ctx.id).order_by(m.MacDevice.mac)):
        g = groups.get(d.group_id)
        # A leading = + - @ would be a formula in a spreadsheet.
        safe = [("'" + x if x[:1] in "=+-@" else x) for x in (d.name, g.name if g else "", d.notes)]
        w.writerow([format_mac(d.mac), safe[0], safe[1], status_of(d, g, now), d.expires_at.isoformat() if d.expires_at else "",
                    d.last_seen_at.isoformat() if d.last_seen_at else "", clients.get(d.last_seen_client_id, "") if d.last_seen_client_id else "",
                    d.last_seen_port or "", safe[2]])
    return Response(out.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{ctx.tenant.slug}-mac-allow-list.csv"'})


class BulkIn(BaseModel):
    macs: list[str] = Field(min_length=1, max_length=MAX_IMPORT_LINES)
    group_id: uuid.UUID
    confirm_certificate: bool = False


@router.post("/devices/bulk")
def bulk_allow(body: BulkIn, ctx: TenantCtx = Depends(require("mac:write"))) -> dict:
    """Allow several MACs from "Seen, not allowed" in one group, each named after where it was seen."""
    s = ctx.session
    g = _group(ctx, body.group_id)
    try:
        macs = sorted({normalize_mac(x) for x in body.macs})
    except MacError as exc:
        raise _bad("macs", str(exc)) from exc
    existing = {x for (x,) in s.execute(select(m.MacDevice.mac).where(m.MacDevice.tenant_id == ctx.id, m.MacDevice.mac.in_(macs)))}
    macs = [x for x in macs if x not in existing]
    cert = certificate_macs(ctx, set(macs))
    if cert and not body.confirm_certificate:
        raise _bad("macs", f"{len(cert)} of these belong{'s' if len(cert) == 1 else ''} to devices that sign in with a certificate: "
                   + ", ".join(format_mac(x) for x in sorted(cert)[:5]), code="certificate_device")
    _room(ctx, len(macs))
    clients = _clients(ctx)
    added = []
    for mac in macs:
        seen = s.scalars(select(m.MacSighting).where(m.MacSighting.tenant_id == ctx.id, m.MacSighting.mac == mac)
                         .order_by(m.MacSighting.last_seen.desc())).first()
        where = f" on {clients.get(seen.client_id, 'a switch')} {seen.port}".rstrip() if seen else ""
        d = m.MacDevice(tenant_id=ctx.id, mac=mac, name=f"Device {format_mac(mac)}{where}"[:120], group_id=g.id, source="learned",
                        created_by=ctx.actor.label[:254])
        s.add(d)
        s.flush()
        _learned(ctx, d)
        mab.coa_for_mac(s, ctx.id, mac, "reauthenticate", "Allowed on the MAC allow list")
        added.append(format_mac(mac))
    if added:
        mab.bump_mac(s, ctx.id)
    audit.record(s, ctx.actor, "mac_device.bulk_allowed", tenant_id=ctx.id, target_type="device_group", target_id=g.id, target_label=g.name,
                 detail={"macs": added[:200], "count": len(added), "already_listed": len(existing)})
    return {"added": len(added), "already_listed": len(existing)}


# ── Seen, not allowed ────────────────────────────────────────────────────────


@router.get("/sightings")
def sightings(ctx: TenantCtx = Depends(require("mac:read")), days: int = 30) -> dict:
    """MACs switches asked about that aren't on the allow list, newest first."""
    s = ctx.session
    days = max(1, min(days, 90))
    listed = select(m.MacDevice.mac).where(m.MacDevice.tenant_id == ctx.id)
    rows = s.scalars(select(m.MacSighting).where(m.MacSighting.tenant_id == ctx.id, m.MacSighting.mac.not_in(listed),
                                                 m.MacSighting.last_seen >= datetime.now(UTC) - timedelta(days=days))
                     .order_by(m.MacSighting.last_seen.desc()).limit(2000)).all()
    clients = _clients(ctx)
    cert = certificate_macs(ctx, {r.mac for r in rows}) if rows else set()
    return {"days": days, "sightings": [
        {"id": r.id, "mac": format_mac(r.mac), "switch": clients.get(r.client_id), "client_id": str(r.client_id), "port": r.port or None,
         "first_seen": r.first_seen.isoformat(), "last_seen": r.last_seen.isoformat(), "attempts": r.count, "reason_code": r.last_reason,
         "certificate_device": r.mac in cert, "randomized": is_randomized(r.mac)} for r in rows]}


@router.delete("/sightings/{sighting_id}")
def dismiss_sighting(sighting_id: int, ctx: TenantCtx = Depends(require("mac:write"))) -> dict:
    s = ctx.session
    r = s.get(m.MacSighting, sighting_id)
    if r is None or r.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")
    s.delete(r)
    return {"ok": True}


@router.get("/search")
def search_devices(q: str = "", ctx: TenantCtx = Depends(require("mac:read"))) -> dict:
    q = q.strip()[:64]
    return {"items": search(ctx, q) if q else []}


def search(ctx: TenantCtx, q: str, limit: int = 8) -> list[dict]:
    """Allow-list entries for the console's search: by name, or by MAC in any notation (or a fragment of one)."""
    hexpart = "".join(c for c in q.upper() if c in "0123456789ABCDEF")
    cond = [m.MacDevice.name.ilike(f"%{q}%")]
    if len(hexpart) >= 4:
        cond.append(m.MacDevice.mac.like(f"%{hexpart}%"))
    rows = ctx.session.scalars(select(m.MacDevice).where(m.MacDevice.tenant_id == ctx.id, or_(*cond)).limit(limit)).all()
    return [{"id": str(d.id), "mac": format_mac(d.mac), "name": d.name} for d in rows]
