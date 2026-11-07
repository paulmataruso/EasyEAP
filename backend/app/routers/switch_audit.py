"""Switch audit: SNMP monitoring of a Cisco switch, its polled ports and sessions, and audit findings
(docs/plans/switch-audit.md). Polling itself runs in the collector; "Test connection" runs here."""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import func, select

from app import audit
from app import models as m
from app.deps import TenantCtx, require
from app.pki import crypto
from app.security.ratelimit import limiter
from app.switchaudit import service
from app.switchaudit.service import MonitoringError, MonitoringIn

router = APIRouter(prefix="/api/tenants/{tenant_id}/radius", tags=["switch-audit"])
COLLECTOR_STALE = timedelta(minutes=3)


def _switch(ctx: TenantCtx, client_id: uuid.UUID) -> m.RadiusClient:
    c = ctx.session.get(m.RadiusClient, client_id)
    if c is None or c.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Switch not found.")
    if c.vendor != "cisco-switch":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The switch audit reads Cisco Catalyst switches over SNMP; this isn't one.")
    return c


def _source_address() -> str:
    from app.routers.radius import controller_address
    return controller_address()["radius_address"]


def collector_status(s) -> dict:
    from app.db import set_platform, set_tenant
    tid = s.info.get("tenant_id")
    set_platform(s)
    try:
        hb = s.get(m.PlatformSetting, "collector_heartbeat")
    finally:
        set_tenant(s, tid)
    at = datetime.fromisoformat(hb.value["at"]) if hb and (hb.value or {}).get("at") else None
    return {"alive": bool(at and datetime.now(UTC) - at < COLLECTOR_STALE), "last_seen_at": at.isoformat() if at else None}


def _bad(field: str, message: str) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, {"field": field, "message": message})


@router.get("/clients/{client_id}/monitoring")
def get_monitoring(client_id: uuid.UUID, ctx: TenantCtx = Depends(require("radius:read"))) -> dict:
    s = ctx.session
    c = _switch(ctx, client_id)
    mon = c.monitoring or {}
    st = s.get(m.SwitchState, c.id)
    rows = s.scalars(select(m.SwitchFinding).where(m.SwitchFinding.client_id == c.id, m.SwitchFinding.resolved_at.is_(None))
                     .order_by(m.SwitchFinding.severity, m.SwitchFinding.first_seen_at)).all()
    resolved = s.scalars(select(m.SwitchFinding).where(m.SwitchFinding.client_id == c.id, m.SwitchFinding.resolved_at.is_not(None))
                         .order_by(m.SwitchFinding.resolved_at.desc()).limit(20)).all()
    requested = st.poll_requested_at if st else None
    return {"monitoring": service.monitoring_out(c), "default_host": service.default_host(c), "state": service.state_out(st),
            "findings": [service.finding_out(f) for f in rows if f.opened_at is not None],
            "pending": sum(1 for f in rows if f.opened_at is None), "resolved": [service.finding_out(f) for f in resolved],
            "config": service.config_block(mon or {"version": "v2c"}, _source_address()) if mon.get("host") else None,
            "removal": service.removal_block(mon) if mon.get("host") else None,
            "source_address": _source_address() or None, "collector": collector_status(s),
            "poll_requested_at": requested.isoformat() if requested else None}


@router.post("/clients/{client_id}/monitoring/setup")
def setup_monitoring(client_id: uuid.UUID, body: dict, ctx: TenantCtx = Depends(require("radius:secrets"))) -> dict:
    """Save how to reach the switch and generate new credentials, shown once. Monitoring stays off until a test passes."""
    c = _switch(ctx, client_id)
    try:
        cfg = MonitoringIn.model_validate(body)
        cfg.check()
    except ValidationError as exc:
        err = exc.errors()[0]
        raise _bad(str(err["loc"][0]) if err.get("loc") else "host", str(err["msg"]).removeprefix("Value error, ")) from None
    except MonitoringError as exc:
        raise _bad(exc.field, str(exc)) from None
    old = c.monitoring or {}
    old_community = None
    if c.snmp_secret_ct and old.get("version", "v2c") == "v2c":
        try:
            old_community = json.loads(crypto.decrypt_str(ctx.id, c.snmp_secret_ct)).get("community")
        except Exception:  # noqa: BLE001 — only used to print the line that retires it
            old_community = None
    creds = service.new_credentials(cfg.version)
    now = datetime.now(UTC)
    mon = {**cfg.model_dump(), "enabled": False, "credentials_set_at": now.isoformat(), "set_by": ctx.actor.label[:254],
           "pinned": old.get("pinned") if old.get("host") == cfg.host else {}}
    c.monitoring, c.snmp_secret_ct = mon, crypto.encrypt(ctx.id, json.dumps(creds))
    audit.record(ctx.session, ctx.actor, "radius.monitoring_setup", tenant_id=ctx.id, target_type="radius_client", target_id=c.id,
                 target_label=c.name, detail={"host": cfg.host, "version": cfg.version, "interval_minutes": cfg.interval_minutes,
                                              "rotated": bool(old.get("host"))})
    retire = None
    if old_community and old_community != creds.get("community"):
        retire = f"no snmp-server community {old_community}\n"
    elif old.get("version") == "v3" and (cfg.version != "v3" or (old.get("user") or "easyeap") != cfg.user):
        retire = service.removal_block(old).split("no snmp-server view")[0]
    return {"monitoring": service.monitoring_out(c), "credentials": {**creds, "user": cfg.user if cfg.version == "v3" else None},
            "config": service.config_block(mon, _source_address()), "retire": retire}


class MonitoringUpdate(BaseModel):
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    interval_minutes: int | None = Field(default=None, ge=5, le=60)
    enabled: bool | None = None


@router.put("/clients/{client_id}/monitoring")
def update_monitoring(client_id: uuid.UUID, body: MonitoringUpdate, ctx: TenantCtx = Depends(require("radius:write"))) -> dict:
    """Change the address, port, interval, or turn polling on or off. New credentials or protocols go through setup."""
    c = _switch(ctx, client_id)
    mon = dict(c.monitoring or {})
    if not mon.get("host") or not c.snmp_secret_ct:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Set up monitoring for this switch first.")
    merged = {**mon, **{k: v for k, v in body.model_dump().items() if v is not None and k != "enabled"}}
    try:
        cfg = MonitoringIn.model_validate(merged)
    except ValidationError as exc:
        err = exc.errors()[0]
        raise _bad(str(err["loc"][0]) if err.get("loc") else "host", str(err["msg"]).removeprefix("Value error, ")) from None
    if (cfg.host, cfg.port) != (mon.get("host"), int(mon.get("port") or 161)) and "radius:secrets" not in ctx.perms:
        # The stored community would go to the new address, in clear text with v2c: only someone who may see it can.
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Changing the switch's SNMP address needs the radius:secrets permission.")
    if cfg.host != mon.get("host"):
        merged["pinned"] = {}
    merged.update(cfg.model_dump())
    if body.enabled is not None:
        merged["enabled"] = body.enabled
    c.monitoring = merged
    st = ctx.session.get(m.SwitchState, c.id)
    if st is not None and merged.get("enabled"):
        st.next_poll_at = datetime.now(UTC)  # poll soon with the new settings
    if body.enabled is False:
        _resolve_open(ctx, c)
    audit.record(ctx.session, ctx.actor, "radius.monitoring_changed", tenant_id=ctx.id, target_type="radius_client", target_id=c.id,
                 target_label=c.name, detail={k: v for k, v in body.model_dump().items() if v is not None})
    return {"monitoring": service.monitoring_out(c)}


def _resolve_open(ctx: TenantCtx, c: m.RadiusClient) -> None:
    now = datetime.now(UTC)
    for f in ctx.session.scalars(select(m.SwitchFinding).where(m.SwitchFinding.client_id == c.id, m.SwitchFinding.resolved_at.is_(None))):
        if f.opened_at is None:
            ctx.session.delete(f)
        else:
            f.resolved_at = now


@router.post("/clients/{client_id}/monitoring/test")
def test_monitoring(client_id: uuid.UUID, ctx: TenantCtx = Depends(require("radius:write"))) -> dict:
    """Probe the switch with the stored credentials (about 10 s at most). When it answers, monitoring turns on."""
    c = _switch(ctx, client_id)
    try:
        t = service.target(c)
    except Exception:  # noqa: BLE001 — OpenBao sealed or unreachable
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "EasyEAP couldn't read this switch's stored SNMP credentials. Check System health.") from None
    if t is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Set up monitoring for this switch first.")
    if not limiter.hit(f"switch-test:{c.id}", 6, 60):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many tests of this switch; wait a minute.")
    ctx.session.commit()  # no transaction stays open while the switch is asked
    res = service.run_poll(t, budget=service.TEST_BUDGET_SECONDS, probe_only=True, timeout=2.0, retries=1)
    ctx.session.refresh(c, with_for_update=True)  # settings may have changed meanwhile; a poll being stored finishes first
    mon = dict(c.monitoring or {})
    mon["last_test"] = {"at": datetime.now(UTC).isoformat(), "ok": res["ok"], "error": res.get("error")}
    if res["ok"]:
        facts = res.get("facts") or {}
        was_on = bool(mon.get("enabled"))
        mon["enabled"] = True
        mon["pinned"] = service.pin_missing(mon.get("pinned") or {}, facts)
        st = ctx.session.get(m.SwitchState, c.id) or m.SwitchState(client_id=c.id, tenant_id=ctx.id, failures=0)
        st.next_poll_at = datetime.now(UTC)
        ctx.session.add(st)
        if not was_on:
            audit.record(ctx.session, ctx.actor, "radius.monitoring_enabled", tenant_id=ctx.id, target_type="radius_client", target_id=c.id,
                         target_label=c.name, detail={"host": mon.get("host"), "model": facts.get("model"), "version": facts.get("version")})
    c.monitoring = mon
    return {**{k: res.get(k) for k in ("ok", "error_kind", "error", "duration_ms", "facts", "capabilities")},
            "monitoring": service.monitoring_out(c)}


@router.post("/clients/{client_id}/monitoring/poll", status_code=202)
def poll_now(client_id: uuid.UUID, ctx: TenantCtx = Depends(require("radius:write"))) -> dict:
    c = _switch(ctx, client_id)
    if not (c.monitoring or {}).get("enabled"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Monitoring is off for this switch.")
    now = datetime.now(UTC)
    st = ctx.session.get(m.SwitchState, c.id) or m.SwitchState(client_id=c.id, tenant_id=ctx.id, failures=0)
    if st.poll_requested_at:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "A poll of this switch is already waiting for the collector.")
    if not limiter.hit(f"switch-poll:{c.id}", 1, service.POLL_NOW_EVERY.total_seconds()):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Poll now works once a minute per switch.")
    st.poll_requested_at = now
    ctx.session.add(st)
    return {"requested_at": now.isoformat()}


class AckIn(BaseModel):
    note: str = Field(default="", max_length=500)


@router.post("/clients/{client_id}/monitoring/findings/{finding_id}/ack")
def acknowledge(client_id: uuid.UUID, finding_id: uuid.UUID, body: AckIn, ctx: TenantCtx = Depends(require("radius:write"))) -> dict:
    c = _switch(ctx, client_id)
    f = ctx.session.get(m.SwitchFinding, finding_id)
    if f is None or f.client_id != c.id or f.tenant_id != ctx.id or f.resolved_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found, or already resolved.")
    service.acknowledge(ctx.session, c, f, ctx.actor.label, body.note.strip())
    audit.record(ctx.session, ctx.actor, "radius.audit_finding_acknowledged", tenant_id=ctx.id, target_type="radius_client", target_id=c.id,
                 target_label=c.name, detail={"kind": f.kind, "port": f.port or None, "mac": f.mac or None, "note": body.note.strip()[:200]})
    return {"finding": service.finding_out(f)}


@router.delete("/clients/{client_id}/monitoring")
def remove_monitoring(client_id: uuid.UUID, ctx: TenantCtx = Depends(require("radius:write"))) -> dict:
    """Stop polling and forget the credentials. Returns the lines that remove EasyEAP's SNMP access from the switch."""
    c = _switch(ctx, client_id)
    old = c.monitoring or {}
    removal = service.removal_block(old) if old.get("host") else None
    _resolve_open(ctx, c)
    st = ctx.session.get(m.SwitchState, c.id)
    if st is not None:
        ctx.session.delete(st)
    c.monitoring, c.snmp_secret_ct = {}, None
    audit.record(ctx.session, ctx.actor, "radius.monitoring_removed", tenant_id=ctx.id, target_type="radius_client", target_id=c.id,
                 target_label=c.name, detail={"host": old.get("host")})
    return {"removal": removal}


@router.get("/switch-audit")
def summary(ctx: TenantCtx = Depends(require("radius:read"))) -> dict:
    """Every monitored switch: last poll and open findings by severity."""
    s = ctx.session
    counts: dict[uuid.UUID, dict[str, int]] = {}
    for cid, sev, n in s.execute(select(m.SwitchFinding.client_id, m.SwitchFinding.severity, func.count())
                                 .where(m.SwitchFinding.tenant_id == ctx.id, m.SwitchFinding.resolved_at.is_(None),
                                        m.SwitchFinding.opened_at.is_not(None), m.SwitchFinding.acknowledged_at.is_(None))
                                 .group_by(m.SwitchFinding.client_id, m.SwitchFinding.severity)):
        counts.setdefault(cid, {})[sev] = n
    out = []
    for c in s.scalars(select(m.RadiusClient).where(m.RadiusClient.tenant_id == ctx.id, m.RadiusClient.vendor == "cisco-switch")):
        mon = c.monitoring or {}
        if not mon.get("host"):
            continue
        st = s.get(m.SwitchState, c.id)
        out.append({"client_id": str(c.id), "name": c.name, "enabled": bool(mon.get("enabled")),
                    "polled_at": st.polled_at.isoformat() if st and st.polled_at else None, "ok": st.ok if st else None,
                    "critical": counts.get(c.id, {}).get("critical", 0), "warning": counts.get(c.id, {}).get("warning", 0)})
    return {"switches": out, "collector": collector_status(s)}
