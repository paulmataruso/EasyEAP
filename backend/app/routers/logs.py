"""System log (System → System log) and remote syslog destinations (System → Remote syslog).

Reading needs platform:read (Super Administrator, MSP Auditor). Changing destinations needs platform:write and is
audited. Destinations hold no secrets: syslog has no credentials, and a CA bundle is public.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app import models as m
from app.db import set_platform
from app.deps import Principal, db, platform
from app.logs import syslog
from app.logs.dbhandler import SOURCES
from app.security.ratelimit import limiter

router = APIRouter(prefix="/api/system", tags=["logs"])
reader = platform("platform:read")
owner = platform("platform:write")
LEVELS = ("debug", "info", "warning", "error", "critical")


@router.get("/logs")
def system_logs(level: str = Query("info"), source: str | None = None, q: str | None = Query(None, max_length=200),
                before: int | None = None, limit: int = Query(100, ge=1, le=500), p: Principal = Depends(reader),
                s: Session = Depends(db)) -> dict:
    set_platform(s)
    if level not in LEVELS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown level.")
    stmt = select(m.SystemLog).where(m.SystemLog.level.in_(LEVELS[LEVELS.index(level):]))
    if source:
        if source not in SOURCES:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown source.")
        stmt = stmt.where(m.SystemLog.source == source)
    if q:
        needle = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        stmt = stmt.where(m.SystemLog.message.ilike(f"%{needle}%", escape="\\"))
    if before:
        stmt = stmt.where(m.SystemLog.id < before)
    rows = list(s.scalars(stmt.order_by(m.SystemLog.id.desc()).limit(limit + 1)))
    more = len(rows) > limit
    rows = rows[:limit]
    return {"logs": [{"id": r.id, "at": r.at.isoformat(), "level": r.level, "source": r.source, "logger": r.logger, "message": r.message} for r in rows],
            "next_before": rows[-1].id if more and rows else None, "sources": list(SOURCES)}


def _public(d: syslog.Destination, st: dict[str, Any]) -> dict:
    out = d.model_dump(exclude={"start_after"})
    error = st.get("error")
    out["status"] = {
        "state": "disabled" if not d.enabled else "failing" if error else "delivering" if st.get("last_sent_at") else "waiting",
        "error": error, "error_at": st.get("error_at") if error else None, "last_sent_at": st.get("last_sent_at"),
        "sent": int(st.get("sent") or 0), "backlog": st.get("backlog"),
    }
    return out


@router.get("/syslog")
def get_syslog(p: Principal = Depends(reader), s: Session = Depends(db)) -> dict:
    set_platform(s)
    state = syslog.load_state(s)
    hb = s.get(m.PlatformSetting, "worker_heartbeat")
    return {"destinations": [_public(d, state.get(d.id) or {}) for d in syslog.load_destinations(s)],
            "max_destinations": syslog.MAX_DESTINATIONS, "facilities": list(syslog.FACILITIES), "hostname": syslog.hostname(),
            "worker_seen_at": (hb.value or {}).get("at") if hb else None}


def _detail(d: syslog.Destination) -> dict:
    return {"name": d.name, "host": d.host, "port": d.port, "transport": d.transport, "format": d.format, "body": d.body,
            "categories": d.categories, "enabled": d.enabled, "custom_ca": bool(d.ca_pem)}


@router.post("/syslog", status_code=201)
def add_destination(body: syslog.Destination, p: Principal = Depends(owner), s: Session = Depends(db)) -> dict:
    set_platform(s)
    dests = syslog.load_destinations(s)
    if len(dests) >= syslog.MAX_DESTINATIONS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"EasyEAP sends to at most {syslog.MAX_DESTINATIONS} destinations. Remove one first.")
    # A new destination starts with what happens from now on; it doesn't replay the history.
    d = body.model_copy(update={"id": uuid.uuid4().hex[:12], "created_at": datetime.now(UTC).isoformat(),
                                "start_after": syslog.newest_ids(s.connection())})
    syslog.save_destinations(s, [*dests, d])
    audit.record(s, p.actor, "system.syslog_added", target_type="syslog", target_id=d.id, target_label=d.name, detail=_detail(d))
    return _public(d, {})


@router.put("/syslog/{dest_id}")
def update_destination(dest_id: str, body: syslog.Destination, p: Principal = Depends(owner), s: Session = Depends(db)) -> dict:
    set_platform(s)
    dests = syslog.load_destinations(s)
    cur = next((d for d in dests if d.id == dest_id), None)
    if cur is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "That syslog destination no longer exists.")
    # A category added now starts from now, like a new destination; the forwarder takes the later of this and its cursor.
    added = set(body.categories) - set(cur.categories)
    start_after = dict(cur.start_after)
    if added:
        newest = syslog.newest_ids(s.connection())
        start_after.update({c: newest[c] for c in added})
    d = body.model_copy(update={"id": cur.id, "created_at": cur.created_at, "start_after": start_after})
    syslog.save_destinations(s, [d if x.id == dest_id else x for x in dests])
    audit.record(s, p.actor, "system.syslog_updated", target_type="syslog", target_id=d.id, target_label=d.name, detail=_detail(d))
    return _public(d, syslog.load_state(s).get(d.id) or {})


@router.delete("/syslog/{dest_id}")
def remove_destination(dest_id: str, p: Principal = Depends(owner), s: Session = Depends(db)) -> dict:
    set_platform(s)
    dests = syslog.load_destinations(s)
    cur = next((d for d in dests if d.id == dest_id), None)
    if cur is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "That syslog destination no longer exists.")
    syslog.save_destinations(s, [x for x in dests if x.id != dest_id])
    audit.record(s, p.actor, "system.syslog_removed", target_type="syslog", target_id=cur.id, target_label=cur.name, detail=_detail(cur))
    return {"ok": True}


@router.post("/syslog/test")
async def test_destination(body: syslog.Destination, p: Principal = Depends(owner)) -> dict:
    """Send one test message to the destination as entered (saved or not). Reports the connection error if it fails."""
    if not limiter.hit(f"syslog-test:{p.admin.id}", 10):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many test messages. Wait a minute.")
    try:
        await run_in_threadpool(syslog.send_test, body, p.admin.email)
    except (OSError, ValueError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"The test message couldn't be sent: {syslog.describe_error(exc)}") from exc
    note = " UDP gives no delivery confirmation: check that it arrived." if body.transport == "udp" else ""
    return {"ok": True, "detail": f"Sent to {body.host}:{body.port} over {body.transport.upper()}.{note}"}
