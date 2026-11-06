"""System health, version and backup information."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app import __version__
from app import models as m
from app.db import set_platform
from app.deps import Principal, db, platform
from app.pki.openbao import OpenBao
from app.routers.radius import agent_out

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/health")
def liveness(s: Session = Depends(db)) -> dict:
    """Unauthenticated liveness for container health checks. Reveals nothing beyond up/down. During a restore the
    database is being replaced, which is expected: the API is alive, so it stays healthy."""
    from app.backup.engine import maintenance
    if maintenance():
        return {"status": "maintenance"}
    s.execute(text("SELECT 1"))
    return {"status": "ok"}


@router.get("/system/health")
def health(p: Principal = Depends(platform("platform:read")), s: Session = Depends(db)) -> dict:
    set_platform(s)
    now = datetime.now(UTC)
    checks = []

    def check(service: str, ok: bool, tone: str, label: str, detail: str, **kw) -> None:
        checks.append({"service": service, "ok": ok, "tone": tone, "label": label, "detail": detail, **kw})

    try:
        s.execute(text("SELECT 1"))
        check("database", True, "valid", "Reachable", "PostgreSQL reachable", checked_at=now.isoformat())
    except Exception as exc:  # noqa: BLE001
        check("database", False, "crit", "Unreachable", str(exc)[:200], checked_at=now.isoformat())
    check_pki(check)
    agent = agent_out(s)
    check_radius(s, check, agent, now)
    hb = s.get(m.PlatformSetting, "worker_heartbeat")
    last = datetime.fromisoformat(hb.value["at"]) if hb and hb.value.get("at") else None
    alive = bool(last and now - last < timedelta(minutes=3))
    check("worker", alive, "valid" if alive else "crit", "Running" if alive else "Not running",
          "Background jobs running" if alive else "No recent worker heartbeat", last_seen_at=last.isoformat() if last else None)
    from app.logs import syslog
    dests = [d for d in syslog.load_destinations(s) if d.enabled]
    if dests:
        st = syslog.load_state(s)
        failing = [(d, (st.get(d.id) or {}).get("error")) for d in dests if (st.get(d.id) or {}).get("error")]
        sent = [(st.get(d.id) or {}).get("last_sent_at") for d in dests]
        if not alive:
            # The worker does the forwarding: nothing is sent while it's down (messages wait and are sent later).
            check("syslog", False, "warn", "Paused", "The background worker isn't running, so nothing is forwarded. Messages wait and are sent when it's back.",
                  last_seen_at=max((x for x in sent if x), default=None))
        else:
            check("syslog", not failing, "crit" if failing else "valid", "Failing" if failing else "Delivering",
                  (f"{failing[0][0].name} ({failing[0][0].host}): {failing[0][1]}" + (f" (+{len(failing) - 1} more failing)" if len(failing) > 1 else ""))
                  if failing else f"Forwarding to {len(dests)} destination{'s' if len(dests) != 1 else ''}",
                  last_seen_at=max((x for x in sent if x), default=None))
    failed = s.scalar(select(func.count()).select_from(m.Job).where(m.Job.status == "failed", m.Job.finished_at >= now - timedelta(days=1))) or 0
    queued = s.scalar(select(func.count()).select_from(m.Job).where(m.Job.status == "queued")) or 0
    recent_failed = [{"kind": j.kind, "error": (j.last_error or "")[:300], "at": j.finished_at.isoformat() if j.finished_at else None}
                     for j in s.scalars(select(m.Job).where(m.Job.status == "failed").order_by(m.Job.finished_at.desc()).limit(5))]
    backup = s.get(m.PlatformSetting, "last_backup")
    return {"version": __version__, "checked_at": now.isoformat(), "checks": checks, "jobs": {"queued": queued, "failed_24h": failed, "recent_failed": recent_failed},
            "backup": backup.value if backup else None}


def check_pki(check) -> None:
    """Unsealed is not enough: EasyEAP's own token must still work, or nothing can be issued or revoked."""
    at = lambda: datetime.now(UTC).isoformat()  # noqa: E731
    try:
        h = OpenBao(token="").health()
    except Exception as exc:  # noqa: BLE001
        check("pki", False, "crit", "Unreachable", f"OpenBao unreachable: {exc}"[:200], checked_at=at())
        return
    version = h.get("version", "")
    if not h.get("initialized") or h.get("sealed"):
        check("pki", False, "crit", "Sealed", f"OpenBao {version} is sealed: certificates can't be issued or revoked", checked_at=at())
        return
    try:
        info = (OpenBao().read("auth/token/lookup-self") or {}).get("data") or {}
    except Exception as exc:  # noqa: BLE001
        status = getattr(exc, "status", None)
        check("pki", False, "crit", "Access refused" if status == 403 else "Problem",
              (f"OpenBao {version} refused EasyEAP's token (expired or revoked): certificates can't be issued or revoked"
               if status == 403 else f"OpenBao {version} didn't answer EasyEAP's token check: {exc}")[:200], checked_at=at())
        return
    ttl = info.get("ttl") or 0
    if ttl and ttl < 3 * 86_400:
        check("pki", True, "warn", "Token expiring",
              f"OpenBao {version} unsealed, but EasyEAP's token expires in {max(1, ttl // 3600)} hours. The worker renews it every 12 hours; check that it's running.",
              checked_at=at())
        return
    check("pki", True, "valid", "Ready", f"OpenBao {version} unsealed, EasyEAP's access confirmed", checked_at=at())


def check_radius(s: Session, check, agent: dict | None, now: datetime) -> None:
    if agent is None:
        check("radius", False, "crit", "Never reported", "No heartbeat from the RADIUS agent yet", last_seen_at=None)
        return
    seen = agent["last_seen_at"]
    if not agent["online"]:
        check("radius", False, "crit", "Not reporting", "The RADIUS agent has stopped reporting. If RADIUS is still running it keeps using its last snapshots.",
              last_seen_at=seen)
        return
    if not agent["config_ok"]:
        check("radius", False, "crit", "Configuration rejected", agent.get("config_error") or "RADIUS rejected its latest configuration", last_seen_at=seen)
        return
    state = agent["state"]
    if state == "idle":
        check("radius", True, "neutral", "Idle", "RADIUS idle: it starts when the first tenant is activated", last_seen_at=seen)
        return
    if state == "starting":
        check("radius", True, "neutral", "Starting", "RADIUS starting for a newly activated tenant", last_seen_at=seen)
        return
    if state != "running":
        check("radius", False, "crit", "Stopped", "FreeRADIUS is not running, so nobody can connect", last_seen_at=seen)
        return
    # Tenants RADIUS should serve (as in its desired configuration) but its running configuration doesn't include.
    from app.posture import APPLY_GRACE
    served = agent.get("serving_ids")
    expected = s.execute(select(m.Tenant.id, m.Tenant.name, m.RadiusSettings.snapshot_built_at)
                         .join(m.RadiusSettings, m.RadiusSettings.tenant_id == m.Tenant.id)
                         .where(m.Tenant.status == "active", m.RadiusSettings.server_certificate_id.is_not(None),
                                m.RadiusSettings.server_key_ct.is_not(None))).all()
    missing = [] if served is None else [
        name for tid, name, built in expected if str(tid) not in served and not (built and now - built <= APPLY_GRACE)]
    if missing:
        check("radius", False, "crit", "Missing tenants",
              f"RADIUS is running, but its configuration doesn't include {', '.join(missing[:3])}{f' and {len(missing) - 3} more' if len(missing) > 3 else ''}",
              last_seen_at=seen)
        return
    n = len(expected)
    check("radius", True, "valid", "Running",
          f"RADIUS running, configuration applied for {n} tenant{'s' if n != 1 else ''}" if served is not None else "RADIUS running, configuration applied",
          last_seen_at=seen)
