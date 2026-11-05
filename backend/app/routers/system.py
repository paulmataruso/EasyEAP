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
    """Unauthenticated liveness for container health checks. Reveals nothing beyond up/down."""
    s.execute(text("SELECT 1"))
    return {"status": "ok"}


@router.get("/system/health")
def health(p: Principal = Depends(platform("platform:read")), s: Session = Depends(db)) -> dict:
    set_platform(s)
    now = datetime.now(UTC)
    checks = []
    try:
        s.execute(text("SELECT 1"))
        checks.append({"service": "database", "ok": True, "detail": "PostgreSQL reachable", "checked_at": now.isoformat()})
    except Exception as exc:  # noqa: BLE001
        checks.append({"service": "database", "ok": False, "detail": str(exc)[:200], "checked_at": now.isoformat()})
    try:
        h = OpenBao(token="").health()
        ok = h.get("initialized") and not h.get("sealed")
        checks.append({"service": "pki", "ok": bool(ok), "detail": f"OpenBao {h.get('version', '')} {'unsealed' if not h.get('sealed') else 'SEALED'}",
                       "checked_at": datetime.now(UTC).isoformat()})
    except Exception as exc:  # noqa: BLE001
        checks.append({"service": "pki", "ok": False, "detail": f"OpenBao unreachable: {exc}"[:200], "checked_at": datetime.now(UTC).isoformat()})
    agent = agent_out(s)
    checks.append({"service": "radius", "ok": bool(agent and agent["online"] and agent["config_ok"] and agent["radius_running"]),
                   "detail": ("RADIUS running, configuration applied" if agent and agent["config_ok"] and agent["radius_running"] else
                              (agent or {}).get("config_error") or "No heartbeat from the RADIUS agent") if agent else "No heartbeat from the RADIUS agent yet",
                   "last_seen_at": agent["last_seen_at"] if agent else None})
    hb = s.get(m.PlatformSetting, "worker_heartbeat")
    last = datetime.fromisoformat(hb.value["at"]) if hb and hb.value.get("at") else None
    checks.append({"service": "worker", "ok": bool(last and now - last < timedelta(minutes=3)), "detail": "Background jobs running" if last and now - last < timedelta(minutes=3) else "No recent worker heartbeat",
                   "last_seen_at": last.isoformat() if last else None})
    failed = s.scalar(select(func.count()).select_from(m.Job).where(m.Job.status == "failed", m.Job.finished_at >= now - timedelta(days=1))) or 0
    queued = s.scalar(select(func.count()).select_from(m.Job).where(m.Job.status == "queued")) or 0
    recent_failed = [{"kind": j.kind, "error": (j.last_error or "")[:300], "at": j.finished_at.isoformat() if j.finished_at else None}
                     for j in s.scalars(select(m.Job).where(m.Job.status == "failed").order_by(m.Job.finished_at.desc()).limit(5))]
    backup = s.get(m.PlatformSetting, "last_backup")
    return {"version": __version__, "checked_at": now.isoformat(), "checks": checks, "jobs": {"queued": queued, "failed_24h": failed, "recent_failed": recent_failed},
            "backup": backup.value if backup else None}
