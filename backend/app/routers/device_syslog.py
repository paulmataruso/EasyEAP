"""Device syslog (docs/plans/syslog-full.md): the live view of everything switches and controllers send, each device's
syslog panel (how to send, today's counters, what it said, the sessions it logged) and its syslog switch.

The receiver (app/switchaudit/syslog.py) writes; this only reads, under the tenant's row-level security. The live view
polls with a cursor (`seq`, set on every insert and update of a row): `after` returns what's new, oldest first.
"""
from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app import audit
from app import models as m
from app.db import set_platform, set_tenant
from app.deps import TenantCtx, require
from app.routers.switch_audit import _heartbeat, _port_514, _syslog_target, stats_out
from app.switchaudit import devicelog, service
from app.switchaudit.syslog import claim_network

router = APIRouter(prefix="/api/tenants/{tenant_id}", tags=["device-syslog"])
MAX_ADDRESSES = 8
MAX_EXTRA_RANGE = 256   # an extra address is a console or a service port: a /24 at most
_SPECIAL = [ipaddress.ip_network(n) for n in ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3", "::/128", "::1/128",
                                              "fe80::/10", "ff00::/8")]


def _client(ctx: TenantCtx, client_id: uuid.UUID) -> m.RadiusClient:
    c = ctx.session.get(m.RadiusClient, client_id)
    if c is None or c.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such controller or switch.")
    return c


def _via_audit(c: m.RadiusClient) -> bool:
    """A Cisco switch with the switch audit set up sends from its verified SNMP address: no syslog switch needed."""
    mon = c.monitoring or {}
    return c.vendor == "cisco-switch" and bool(mon.get("host") and c.snmp_secret_ct)


def _sends(c: m.RadiusClient) -> bool:
    return bool((c.syslog or {}).get("enabled")) or (_via_audit(c) and bool((c.monitoring or {}).get("enabled")))


def _norm(net) -> str:
    return str(net) if net.num_addresses > 1 else str(net.network_address)


def _receiver(s) -> dict:
    target = _syslog_target()
    return {"receiving": target is not None, "listening": _heartbeat(s, "syslog_heartbeat")["alive"],
            "address": target[0] if target else None, "port": target[1] if target else None, "port_514": _port_514()}


def _row(r: m.SwitchSyslog, names: dict[uuid.UUID, str]) -> dict:
    return {**service.syslog_out(r), "client_id": str(r.client_id), "device": names.get(r.client_id)}


# ── The live view ────────────────────────────────────────────────────────────


@router.get("/syslog/live")
def live(after: int | None = Query(default=None, ge=0), before: int | None = Query(default=None, ge=1),
         client_id: uuid.UUID | None = None, limit: int = Query(default=200, ge=1, le=500), meta: bool = False,
         ctx: TenantCtx = Depends(require("radius:read"))) -> dict:
    """`after`: what arrived since (oldest first, at most `limit`); `before`: the page before (for "load earlier");
    neither: the newest `limit`. `cursor` is what to pass as `after` next; `reset` says the table was replaced (a
    restore) and the view should start over. `meta` adds the receiver's status and the devices that send."""
    s = ctx.session
    q = select(m.SwitchSyslog).where(m.SwitchSyslog.tenant_id == ctx.id)   # explicit: the index is (tenant_id, seq)
    if client_id is not None:
        q = q.where(m.SwitchSyslog.client_id == client_id)
    top = s.scalar(select(func.max(m.SwitchSyslog.seq)).where(m.SwitchSyslog.tenant_id == ctx.id)) or 0
    reset = False
    if after is not None:
        rows = list(s.scalars(q.where(m.SwitchSyslog.seq > after).order_by(m.SwitchSyslog.seq).limit(limit)))
        reset = not rows and after > top
    else:
        if before is not None:
            q = q.where(m.SwitchSyslog.seq < before)
        rows = list(reversed(s.scalars(q.order_by(m.SwitchSyslog.seq.desc()).limit(limit)).all()))
    names = dict(s.execute(select(m.RadiusClient.id, m.RadiusClient.name).where(m.RadiusClient.tenant_id == ctx.id)).all())
    if after is not None and not reset:
        cursor = max([after, *(r.seq for r in rows)])
    elif before is not None:
        cursor = None
    else:
        cursor = top
    out: dict = {"messages": [_row(r, names) for r in rows], "cursor": cursor, "reset": reset,
                 "more": len(rows) == limit, "earliest": rows[0].seq if rows else None}
    if meta:
        out["receiver"] = _receiver(s)
        clients = s.scalars(select(m.RadiusClient).where(m.RadiusClient.tenant_id == ctx.id).order_by(m.RadiusClient.name)).all()
        stats = {st.client_id: st for st in s.scalars(select(m.SyslogStats).where(m.SyslogStats.tenant_id == ctx.id))}
        out["devices"] = [{"id": str(c.id), "name": c.name, "vendor": c.vendor, "address": c.address, "sends": _sends(c),
                           "via_audit": _via_audit(c), "addresses": (c.syslog or {}).get("addresses") or [],
                           "stats": stats_out(stats.get(c.id))} for c in clients]
        if "platform:read" in ctx.principal.perms(None):
            out["unknown"] = _unknown_sources(s)
    return out


def _unknown_sources(s) -> dict:
    """Platform operators only: the addresses syslog arrives from that aren't a device with syslog on (any tenant's)."""
    tid = s.info.get("tenant_id")
    set_platform(s)
    try:
        hb = s.get(m.PlatformSetting, "syslog_heartbeat")
    finally:
        set_tenant(s, tid)
    v = (hb.value or {}) if hb else {}
    return {"at": v.get("at"), "unknown": v.get("unknown_source", 0), "ambiguous": v.get("ambiguous", 0), "disabled": v.get("disabled", 0),
            "kernel_drops": v.get("kernel_drops"), "top": v.get("unknown_top") or []}


# ── One device ───────────────────────────────────────────────────────────────


@router.get("/radius/clients/{client_id}/syslog")
def device_syslog(client_id: uuid.UUID, ctx: TenantCtx = Depends(require("radius:read"))) -> dict:
    s = ctx.session
    c = _client(ctx, client_id)
    sl = c.syslog or {}
    target = _syslog_target()
    recent = service.recent_syslog(s, c.id, notable=True, limit=30)
    return {"settings": {"enabled": bool(sl.get("enabled")), "addresses": sl.get("addresses") or []}, "via_audit": _via_audit(c),
            "receiver": _receiver(s), "guide": devicelog.guide(c.vendor, c.address, sl.get("addresses") or [], target, _port_514()),
            "stats": stats_out(s.get(m.SyslogStats, c.id)), "recent": [service.syslog_out(r) for r in recent],
            "sessions": devicelog.syslog_sessions(devicelog.decode_rows(s, c.id))}


class SyslogSettingsIn(BaseModel):
    enabled: bool
    addresses: list[str] = Field(default_factory=list, max_length=MAX_ADDRESSES)


def _bad(field: str, message: str, code: int = status.HTTP_422_UNPROCESSABLE_ENTITY) -> HTTPException:
    return HTTPException(code, {"field": field, "message": message})


def _claims(c: m.RadiusClient) -> list:
    """What the receiver attributes to this device: its RADIUS address, its SNMP address, and its extra addresses
    while syslog is on (a switched-off claim blocks nobody)."""
    sl = c.syslog or {}
    extra = (sl.get("addresses") or []) if sl.get("enabled") else []
    out = []
    for a in [c.address, *extra, (c.monitoring or {}).get("host") or ""]:
        net = claim_network(a) if a else None
        if net is not None:
            out.append(net)
    return out


def syslog_conflict(s, tenant_id: uuid.UUID, nets: list, exclude_id: uuid.UUID) -> str | None:
    """Why these source networks can't attribute syslog to one device, or None. Syslog has one port for every tenant,
    so a network that overlaps any other tenant's device (whatever its RADIUS ports) is refused; within the tenant the
    longest prefix decides, and the same network twice is refused. Platform-scoped query; says nothing about the other
    tenant's addresses."""
    set_platform(s)
    try:
        for c in s.scalars(select(m.RadiusClient).where(m.RadiusClient.id != exclude_id)):
            for other in _claims(c):
                for net in nets:
                    if net.version != other.version or not net.overlaps(other):
                        continue
                    if c.tenant_id != tenant_id:
                        return ("This address overlaps a device of another tenant on this server: syslog arrives on one port for "
                                "every tenant, so their messages couldn't be told apart. Use the device's own address.")
                    if net == other:
                        return f"“{c.name}” already has this address: their messages couldn't be told apart."
    finally:
        set_tenant(s, tenant_id)
    return None


@router.put("/radius/clients/{client_id}/syslog")
def set_device_syslog(client_id: uuid.UUID, body: SyslogSettingsIn, ctx: TenantCtx = Depends(require("radius:write"))) -> dict:
    """Turn a device's syslog on or off, and the extra addresses it sends from (a 9800's service port, a UniFi console)."""
    s = ctx.session
    c = _client(ctx, client_id)
    addrs: list[str] = []
    nets = []
    for a in body.addresses:
        a = a.strip()
        if not a:
            continue
        try:
            ipaddress.ip_network(a, strict=False)
        except ValueError:
            raise _bad("addresses", f"“{a[:64]}” isn't an IP address or range.") from None
        net = claim_network(a)
        if net is None or net.num_addresses > MAX_EXTRA_RANGE:
            raise _bad("addresses", f"“{a[:64]}”: use an IPv4 or IPv6 address, or a range of at most {MAX_EXTRA_RANGE} addresses "
                                    "(IPv4-compatible and NAT64 addresses aren't accepted).")
        if any(net.version == sp.version and net.overlaps(sp) for sp in _SPECIAL):
            raise _bad("addresses", f"“{a[:64]}” is a loopback, link-local or multicast address: no device sends syslog from it.")
        if _norm(net) not in addrs:
            addrs.append(_norm(net))
            nets.append(net)
    if body.enabled or nets:   # extra addresses only claim while syslog is on, but they're checked whenever they're saved
        own = claim_network(c.address) if body.enabled else None
        why = syslog_conflict(s, ctx.id, [*nets, *([own] if own else [])], c.id)
        if why:
            raise _bad("addresses" if nets else "enabled", why, status.HTTP_409_CONFLICT)
    before = dict(c.syslog or {})
    c.syslog = {"enabled": body.enabled, "addresses": addrs}
    if before != c.syslog:
        audit.record(s, ctx.actor, "radius.syslog_changed", tenant_id=ctx.id, target_type="radius_client", target_id=c.id,
                     target_label=c.name, detail={"enabled": body.enabled, "addresses": addrs})
    return {"settings": {"enabled": body.enabled, "addresses": addrs}, "at": datetime.now(UTC).isoformat()}
