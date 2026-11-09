"""Switch audit: SNMP monitoring of a Cisco switch, its polled ports and sessions, and audit findings
(docs/plans/switch-audit.md). Polling itself runs in the collector; "Test connection" runs here."""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import func, select

from app import audit
from app import models as m
from app.config import get_settings
from app.deps import TenantCtx, require
from app.pki import crypto
from app.radius import cisco_platforms as cp
from app.security.ratelimit import limiter
from app.switchaudit import devicelog, platforms, service, syslog
from app.switchaudit.service import MonitoringError, MonitoringIn

router = APIRouter(prefix="/api/tenants/{tenant_id}/radius", tags=["switch-audit"])
COLLECTOR_STALE = timedelta(minutes=3)


def unavailable(vendor: str, profile: dict | None) -> str | None:
    """Why the switch audit can't run on this switch, or None when it can."""
    if vendor != "cisco-switch":
        return ("The switch audit reads Cisco switches over SNMP (Catalyst, Nexus, Cisco Business); this isn't one."
                + (" Meraki MS has no 802.1X data over SNMP." if vendor == "meraki" else ""))
    caps = cp.caps_for(vendor, profile)
    if caps is None or caps.audit is not None:
        return None
    if caps.dialect == "web":
        return ("The SG200 and SF200 have no command line for EasyEAP's SNMP settings: the switch audit isn't available for "
                "them.")
    if caps.dialect == "dot1x":
        return ("IOS before 12.2(50)SE has no authentication manager for EasyEAP to read over SNMP: the switch audit needs "
                "12.2(50)SE or later.")
    return "The switch audit isn't available for this switch's family."


def _switch(ctx: TenantCtx, client_id: uuid.UUID, read_only: bool = False) -> m.RadiusClient:
    """The tenant's switch, for the switch audit. `read_only` (viewing, acknowledging, removing) also works on a switch
    whose audit is no longer available, so what it found can still be read and the SNMP lines removed."""
    c = ctx.session.get(m.RadiusClient, client_id)
    if c is None or c.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Switch not found.")
    why = unavailable(c.vendor, getattr(c, "wired_profile", None))
    if why and not (read_only and (c.monitoring or {}).get("host")):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, why)
    return c


def removal_changes(c: m.RadiusClient, vendor: str, profile: dict | None) -> bool:
    """Whether changing the switch's type or plan would change the lines that remove the audit's SNMP settings from it
    (another family, series or release): those on the switch are the ones generated before."""
    mon = c.monitoring or {}
    if not mon.get("host"):
        return False
    if unavailable(vendor, profile):
        return True
    return _removal(mon, c) != service.removal_block(mon, syslog=_syslog_target(), source=_source_address(), profile=profile, port_514=_port_514(),
                                                     vendor=vendor)


def _source_address() -> str:
    from app.routers.radius import controller_address
    return controller_address()["radius_address"]


def _syslog_target() -> tuple[str, int] | None:
    """Where switches send syslog (address, port), when this server publishes easyeap-syslog (EASYEAP_SYSLOG_BIND): the
    bind address, or the RADIUS address when it binds every interface."""
    st = get_settings()
    if not st.syslog_receiving:
        return None
    bind = st.syslog_bind.strip()
    dest = _source_address() if bind in ("0.0.0.0", "::") else bind  # noqa: S104 — comparing, not binding
    return (dest or "<EasyEAP's address>", st.syslog_port)


def _port_514() -> bool:
    """EasyEAP also receives syslog on UDP 514 (deploy/docker-compose.syslog514.yml), for devices that can't send elsewhere."""
    st = get_settings()
    return st.syslog_receiving and (st.syslog_std_port == 514 or st.syslog_port == 514)


def _removal(mon: dict, c: m.RadiusClient, community: str | None = None) -> str:
    return service.removal_block(mon, community=community, syslog=_syslog_target(), source=_source_address(), profile=c.wired_profile,
                                 vendor=c.vendor, port_514=_port_514())


def _heartbeat(s, key: str) -> dict:
    from app.db import set_platform, set_tenant
    tid = s.info.get("tenant_id")
    set_platform(s)
    try:
        hb = s.get(m.PlatformSetting, key)
    finally:
        set_tenant(s, tid)
    at = datetime.fromisoformat(hb.value["at"]) if hb and (hb.value or {}).get("at") else None
    return {"alive": bool(at and datetime.now(UTC) - at < COLLECTOR_STALE), "last_seen_at": at.isoformat() if at else None}


def collector_status(s) -> dict:
    return _heartbeat(s, "collector_heartbeat")


def _heard_since(s, client_id: uuid.UUID):
    """Whether EasyEAP has had a RADIUS request from the switch since `at`."""
    def check(at: datetime) -> bool:
        return s.scalar(select(m.AuthEvent.id).where(m.AuthEvent.nas_client_id == client_id, m.AuthEvent.at > at).limit(1)) is not None
    return check


def _bad(field: str, message: str) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, {"field": field, "message": message})


@router.get("/clients/{client_id}/monitoring")
def get_monitoring(client_id: uuid.UUID, ctx: TenantCtx = Depends(require("radius:read"))) -> dict:
    s = ctx.session
    c = _switch(ctx, client_id, read_only=True)
    mon = c.monitoring or {}
    st = s.get(m.SwitchState, c.id)
    rows = s.scalars(select(m.SwitchFinding).where(m.SwitchFinding.client_id == c.id, m.SwitchFinding.resolved_at.is_(None))
                     .order_by(m.SwitchFinding.severity, m.SwitchFinding.first_seen_at)).all()
    resolved = s.scalars(select(m.SwitchFinding).where(m.SwitchFinding.client_id == c.id, m.SwitchFinding.resolved_at.is_not(None))
                         .order_by(m.SwitchFinding.resolved_at.desc()).limit(20)).all()
    requested = st.poll_requested_at if st else None
    # Notable messages only: the whole log (links, PoE, …) would push the evidence out. RADIUS servers on their own query,
    # so a server reported dead hours ago still shows.
    said = service.recent_syslog(s, c.id, notable=True) if mon.get("host") else []
    servers = service.recent_syslog(s, c.id, limit=50, facilities=syslog.RADIUS_FACILITIES) if mon.get("host") else []
    target = _syslog_target()
    stats = s.get(m.SyslogStats, c.id)
    return {"monitoring": service.monitoring_out(c), "default_host": service.default_host(c), "state": service.state_out(st),
            "findings": [{**service.finding_out(f), "switch_says": service.says_about(said, f.port, f.mac)} for f in rows if f.opened_at is not None],
            "pending": sum(1 for f in rows if f.opened_at is None), "resolved": [service.finding_out(f) for f in resolved],
            "config": service.config_block(mon or {"version": "v2c"}, _source_address(), target, c.wired_profile, c.vendor, _port_514())
            if mon.get("host") else None,
            "removal": _removal(mon, c) if mon.get("host") else None,
            "source_address": _source_address() or None, "collector": collector_status(s),
            "poll_requested_at": requested.isoformat() if requested else None,
            "syslog": {"receiving": target is not None, "listening": _heartbeat(s, "syslog_heartbeat")["alive"],
                       "address": target[0] if target else None, "port": target[1] if target else None,
                       "stats": stats_out(stats), "recent": [service.syslog_out(r) for r in said[:30]],
                       "radius_down": service.radius_down(servers, _source_address(), _heard_since(s, c.id)),
                       "sessions": devicelog.syslog_sessions(devicelog.decode_rows(s, c.id)) if mon.get("host") else []}}


def stats_out(st: m.SyslogStats | None) -> dict:
    """Today's counters for one device (yesterday's read as nothing)."""
    if st is None or st.day != datetime.now(UTC).date():
        return {}
    return {"day": st.day.isoformat(), "received": st.received, "kept": st.kept, "quota": st.quota,
            "last_at": st.last_at.isoformat() if st.last_at else None, "last_tag": st.last_tag or None}


@router.get("/clients/{client_id}/monitoring/syslog")
def switch_syslog(client_id: uuid.UUID, hours: int = Query(default=24, ge=1, le=24 * 14), port: str = Query(default="", max_length=64),
                  mac: str = Query(default="", max_length=17), ctx: TenantCtx = Depends(require("radius:read"))) -> dict:
    """What the switch said over syslog (14 days at most), newest first; filtered by port or MAC."""
    from app.radius.wired import canonical_port
    from app.switchaudit.syslog import mac_of
    c = _switch(ctx, client_id, read_only=True)
    rows = service.recent_syslog(ctx.session, c.id, hours=hours, limit=500, port=canonical_port(port) if port else "",
                                 mac=mac_of(mac) or mac.replace(":", "").replace("-", "").replace(".", "").upper()[:12] if mac else "")
    return {"messages": [service.syslog_out(r) for r in rows], "truncated": len(rows) == 500}


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
    if cfg.version == "v3" and (c.wired_profile or {}).get("platform") == "nxos":
        # NX-OS makes every SNMPv3 user a local login with the same name and password (research nxos.md §10).
        raise _bad("version", "On NX-OS an SNMPv3 user is also a login account on the switch. Choose SNMPv2c: the community is "
                   "limited to EasyEAP's address and a read-only role.")
    fixed = platforms.v3_algorithms(c.wired_profile) if cfg.version == "v3" else None
    if fixed and fixed[1] == "des":
        raise _bad("version", "SG300 and SF300 switches encrypt SNMPv3 with DES only, which EasyEAP doesn't use. Choose SNMPv2c.")
    if fixed:
        cfg.auth, cfg.priv = fixed  # what this family's block configures (switchaudit/platforms.py)
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
           "pinned": old.get("pinned") if old.get("host") == cfg.host else {},
           # 2: the syslog block without a discriminator. A switch first set up before keeps 1 (its block removes the filter).
           "syslog_form": old.get("syslog_form") or (1 if old.get("credentials_set_at") else 2)}
    c.monitoring, c.snmp_secret_ct = mon, crypto.encrypt(ctx.id, json.dumps(creds))
    audit.record(ctx.session, ctx.actor, "radius.monitoring_setup", tenant_id=ctx.id, target_type="radius_client", target_id=c.id,
                 target_label=c.name, detail={"host": cfg.host, "version": cfg.version, "interval_minutes": cfg.interval_minutes,
                                              "rotated": bool(old.get("host"))})
    retire = None
    if old_community and old_community != creds.get("community"):
        # The family's own form (Cisco Business names the address the community was limited to).
        retire = "".join(line + "\n" for line in service.removal_block(old, community=old_community, source=_source_address(),
                                                                        profile=c.wired_profile, vendor=c.vendor).splitlines()
                         if line.startswith("no snmp-server community"))
    elif old.get("version") == "v3" and (cfg.version != "v3" or (old.get("user") or "easyeap") != cfg.user):
        # Only the old user and group: the view, ACL and logging host stay for the new credentials.
        retire = "".join(line + "\n" for line in service.removal_block(old, profile=c.wired_profile, vendor=c.vendor).splitlines()
                         if line.startswith(("no snmp-server user", "no snmp-server group")))
    return {"monitoring": service.monitoring_out(c), "credentials": {**creds, "user": cfg.user if cfg.version == "v3" else None},
            "config": service.config_block(mon, _source_address(), _syslog_target(), c.wired_profile, c.vendor, _port_514()), "retire": retire}


class MonitoringUpdate(BaseModel):
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    interval_minutes: int | None = Field(default=None, ge=1, le=60)
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
    c = _switch(ctx, client_id, read_only=True)
    f = ctx.session.get(m.SwitchFinding, finding_id)
    if f is None or f.client_id != c.id or f.tenant_id != ctx.id or f.resolved_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found, or already resolved.")
    service.acknowledge(ctx.session, c, f, ctx.actor.label, body.note.strip())
    audit.record(ctx.session, ctx.actor, "radius.audit_finding_acknowledged", tenant_id=ctx.id, target_type="radius_client", target_id=c.id,
                 target_label=c.name, detail={"kind": f.kind, "port": f.port or None, "mac": f.mac or None, "note": body.note.strip()[:200]})
    return {"finding": service.finding_out(f)}


@router.post("/clients/{client_id}/monitoring/credentials")
def show_credentials(client_id: uuid.UUID, ctx: TenantCtx = Depends(require("radius:secrets"))) -> dict:
    """The SNMP credentials again, to fill in the block (whoever may generate new ones may see these); audited."""
    c = _switch(ctx, client_id, read_only=True)
    mon = c.monitoring or {}
    if not mon.get("host") or not c.snmp_secret_ct:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Set up monitoring for this switch first.")
    creds = json.loads(crypto.decrypt_str(ctx.id, c.snmp_secret_ct))
    audit.record(ctx.session, ctx.actor, "radius.monitoring_credentials_shown", tenant_id=ctx.id, target_type="radius_client",
                 target_id=c.id, target_label=c.name)
    return {"credentials": {**creds, "user": (mon.get("user") or "easyeap") if mon.get("version") == "v3" else None}}


@router.delete("/clients/{client_id}/monitoring")
def remove_monitoring(client_id: uuid.UUID, ctx: TenantCtx = Depends(require("radius:write"))) -> dict:
    """Stop polling and forget the credentials. Returns the lines that remove EasyEAP's SNMP access from the switch."""
    c = _switch(ctx, client_id, read_only=True)
    old = c.monitoring or {}
    community = None
    if old.get("version", "v2c") == "v2c" and c.snmp_secret_ct and "radius:secrets" in ctx.perms:
        # The lines are shown once and the credentials forgotten: IOS needs the community itself to remove it.
        try:
            community = json.loads(crypto.decrypt_str(ctx.id, c.snmp_secret_ct)).get("community")
        except Exception:  # noqa: BLE001 — the placeholder stays, as for an admin without radius:secrets
            community = None
    removal = _removal(old, c, community) if old.get("host") else None
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
