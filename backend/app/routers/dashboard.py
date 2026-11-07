"""Tenant dashboard and MSP overview, computed from real events, certificates and service health."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app import models as m
from app.db import set_platform
from app.deps import Principal, TenantCtx, db, principal, require
from app.policy.service import policy_settings
from app.posture import enforcement, needs_action
from app.radius.explain import explain
from app.routers.events import event_out
from app.routers.radius import agent_out
from app.routers.tenants import health_for, tenant_out

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/tenants/{tenant_id}/dashboard")
def dashboard(ctx: TenantCtx = Depends(require("tenant:read"))) -> dict:
    s = ctx.session
    now = datetime.now(UTC)
    start = (now - timedelta(hours=23)).replace(minute=0, second=0, microsecond=0)
    hourly_rows = s.execute(text(
        "SELECT date_trunc('hour', at) AS h, result, count(*) FROM auth_events WHERE tenant_id = :t AND at >= :since GROUP BY 1, 2"
    ), {"t": ctx.id, "since": start}).all()
    buckets = {start + timedelta(hours=i): {"accept": 0, "reject": 0} for i in range(24)}
    for h, result, n in hourly_rows:
        key = h.astimezone(UTC).replace(minute=0, second=0, microsecond=0)
        if key in buckets:
            buckets[key][result] = n
    hourly = [{"hour": k.isoformat(), **v} for k, v in sorted(buckets.items())]
    day = now - timedelta(hours=24)
    reasons = s.execute(select(m.AuthEvent.reason_code, func.count()).where(m.AuthEvent.tenant_id == ctx.id, m.AuthEvent.result == "reject",
                                                                            m.AuthEvent.at >= day).group_by(m.AuthEvent.reason_code).order_by(func.count().desc())).all()
    vlans = {v.vlan_id: v for v in s.scalars(select(m.Vlan).where(m.Vlan.tenant_id == ctx.id))}
    vlan_usage = s.execute(select(m.AuthEvent.vlan_id, func.count()).where(m.AuthEvent.tenant_id == ctx.id, m.AuthEvent.result == "accept",
                                                                           m.AuthEvent.at >= day).group_by(m.AuthEvent.vlan_id)).all()
    warn = policy_settings(s, ctx.id).expiry_warning_days
    expiring = s.execute(select(m.Certificate, m.Identity).outerjoin(m.Identity, m.Identity.id == m.Certificate.identity_id).where(
        m.Certificate.tenant_id == ctx.id, m.Certificate.status == "active", m.Certificate.not_after > now,
        m.Certificate.not_after <= now + timedelta(days=warn), m.Certificate.purpose.in_(m.CLIENT_PURPOSES)).order_by(m.Certificate.not_after).limit(10)).all()
    recent = s.scalars(select(m.AuthEvent).where(m.AuthEvent.tenant_id == ctx.id).order_by(m.AuthEvent.id.desc()).limit(12)).all()
    rs = s.get(m.RadiusSettings, ctx.id)
    issuing = s.scalars(select(m.CertificateAuthority).where(m.CertificateAuthority.tenant_id == ctx.id, m.CertificateAuthority.role == "issuing")).first()
    agent = agent_out(s)
    snapshot_age = (now - rs.snapshot_built_at).total_seconds() if rs and rs.snapshot_built_at else None
    enf = enforcement(s, ctx.tenant, agent, now)
    return {
        "enforcement": enf, "queue": needs_action(s, ctx.tenant, agent, enf, now),
        "tenant": tenant_out(ctx.tenant), "generated_at": now.isoformat(), "health": health_for(s, ctx.tenant),
        "hourly": hourly,
        "failure_reasons": [{"reason_code": r, "count": n, "title": (explain(r) or {}).get("title", r or "Unknown")} for r, n in reasons],
        "vlan_usage": [{"vlan_id": v, "name": vlans[v].name if v in vlans else None, "color": vlans[v].color if v in vlans else None, "count": n}
                       for v, n in vlan_usage if v is not None],
        "expiry_warning_days": warn,
        "expiring": [{"id": str(c.id), "common_name": c.common_name, "serial": c.serial, "not_after": c.not_after.isoformat(),
                      "identity": {"id": str(i.id), "display_name": i.display_name} if i else None} for c, i in expiring],
        "recent_events": [event_out(e) for e in recent],
        "services": {
            "radius_agent": agent,
            "snapshot": {"built_at": rs.snapshot_built_at.isoformat() if rs and rs.snapshot_built_at else None, "age_seconds": snapshot_age,
                         "max_age_seconds": policy_settings(s, ctx.id).max_snapshot_age_seconds,
                         "applied": ((agent or {}).get("snapshot_versions") or {}).get(str(ctx.id)) == (rs.snapshot_version if rs else None)},
            "issuing_ca": {"common_name": issuing.common_name, "not_after": issuing.not_after.isoformat()} if issuing else None,
        },
    }


@router.get("/overview")
def overview(p: Principal = Depends(principal), s: Session = Depends(db)) -> dict:
    set_platform(s)
    allowed = p.accessible_tenant_ids()
    q = select(m.Tenant).order_by(m.Tenant.name)
    if allowed is not None:
        q = q.where(m.Tenant.id.in_(allowed)) if allowed else q.where(False)
    agent = agent_out(s)
    tenants = []
    for t in s.scalars(q):
        enf = enforcement(s, t, agent)
        queue = needs_action(s, t, agent, enf)
        tenants.append({**tenant_out(t), "health": health_for(s, t), "enforcement": enf, "queue_top": queue[:3], "queue_count": len(queue)})
    totals = {"tenants": len(tenants), "accept_24h": sum(t["health"]["auth_24h"]["accept"] for t in tenants),
              "reject_24h": sum(t["health"]["auth_24h"]["reject"] for t in tenants),
              "active_certificates": sum(t["health"]["certificates"]["active"] for t in tenants),
              "expiring_certificates": sum(t["health"]["certificates"]["expiring"] for t in tenants),
              "critical_issues": sum(1 for t in tenants for i in t["health"]["issues"] if i["severity"] == "critical")}
    return {"tenants": tenants, "totals": totals, "radius_agent": agent, "platform_queue": platform_queue(s, p),
            "generated_at": datetime.now(UTC).isoformat()}


BACKUP_MAX_AGE = timedelta(days=7)


def platform_queue(s: Session, p: Principal, now: datetime | None = None) -> list[dict]:
    """Platform-wide risks, ranked like a tenant's needs-action queue. Each item is shown only to someone who can open
    its next action: backups to anyone who can read System health, other administrators' two-factor to owners."""
    now = now or datetime.now(UTC)
    perms = p.perms(None)
    items: list[dict] = []

    def add(code: str, severity: str, title: str, detail: str, label: str, target: str, affected: int = 0, source_at: datetime | None = None) -> None:
        items.append({"code": code, "severity": severity, "title": title, "detail": detail, "action": {"label": label, "target": target},
                      "affected": affected, "impact_at": None, "source_at": source_at.isoformat() if source_at else None})

    if "platform:read" in perms:
        b = s.get(m.PlatformSetting, "last_backup")
        at = datetime.fromisoformat(b.value["at"]) if b and b.value.get("at") else None
        if at is None:
            add("no_backup", "warning", "No backup downloaded yet",
                "If this server is lost, every tenant's issuing CA, policy and audit trail go with it. Create a backup in System health, "
                "download it and keep it with its passphrase somewhere safe.",
                "Create a backup", "system")
        elif now - at > BACKUP_MAX_AGE:
            add("backup_overdue", "warning", f"Last backup {(now - at).days} days ago",
                "Anything changed since then can't be restored. Create a new backup in System health and download it.", "Create a backup", "system",
                source_at=at)
    if not p.admin.mfa_enabled:
        add("own_mfa_off", "critical" if p.admin.platform_role == "platform_owner" else "warning", "Your account has no two-factor authentication",
            "Anyone with your password can sign in with your role. Turn on an authenticator app.", "Set up two-factor", "account", affected=1)
    if "admins:manage" in perms:
        others = list(s.scalars(select(m.Admin).where(m.Admin.is_active.is_(True), m.Admin.mfa_enabled.is_(False), m.Admin.id != p.admin.id)))
        owners = sum(1 for a in others if a.platform_role == "platform_owner")
        if others:
            add("admins_mfa_off", "critical" if owners else "warning",
                f"{len(others)} other administrator{'s' if len(others) != 1 else ''} without two-factor",
                (f"Including {owners} Super Administrator{'s' if owners != 1 else ''}, who can change administrators and delete tenants. " if owners else "")
                + "Ask them to turn it on under Account.", "Open Administrators", "admins", affected=len(others))
    items.sort(key=lambda i: {"critical": 0, "warning": 1}.get(i["severity"], 2))
    return items
