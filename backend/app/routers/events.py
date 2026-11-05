"""Authentication events (with plain-language explanations), accounting sessions and the audit log."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app import audit as audit_mod
from app import models as m
from app.db import set_platform
from app.deps import Principal, TenantCtx, db, platform, require
from app.radius.explain import explain

router = APIRouter(prefix="/api", tags=["events"])


def event_out(e: m.AuthEvent) -> dict:
    return {"id": str(e.id), "at": e.at.isoformat(), "result": e.result, "reason_code": e.reason_code, "explanation": explain(e.reason_code),
            "username": e.username, "identity_id": str(e.identity_id) if e.identity_id else None, "device_id": str(e.device_id) if e.device_id else None,
            "cert_serial": e.cert_serial, "cert_issuer": e.cert_issuer, "calling_station_id": e.calling_station_id, "called_station_id": e.called_station_id,
            "ssid": e.ssid, "nas_ip": e.nas_ip, "nas_client_id": str(e.nas_client_id) if e.nas_client_id else None, "vlan_id": e.vlan_id,
            "rule_id": str(e.rule_id) if e.rule_id else None, "raw_message": e.raw_message}


@router.get("/tenants/{tenant_id}/events")
def list_events(ctx: TenantCtx = Depends(require("events:read")), result: str = "", reason: str = "", q: str = "", hours: int = Query(24, ge=1, le=24 * 90),
                identity_id: uuid.UUID | None = None, nas_client_id: uuid.UUID | None = None, before_id: int | None = None,
                page_size: int = Query(100, ge=1, le=500)) -> dict:
    s = ctx.session
    stmt = select(m.AuthEvent).where(m.AuthEvent.tenant_id == ctx.id, m.AuthEvent.at >= datetime.now(UTC) - timedelta(hours=hours))
    if result in ("accept", "reject"):
        stmt = stmt.where(m.AuthEvent.result == result)
    if reason:
        stmt = stmt.where(m.AuthEvent.reason_code == reason)
    if identity_id:
        stmt = stmt.where(m.AuthEvent.identity_id == identity_id)
    if nas_client_id:
        stmt = stmt.where(m.AuthEvent.nas_client_id == nas_client_id)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(m.AuthEvent.username.ilike(like), m.AuthEvent.calling_station_id.ilike(like), m.AuthEvent.cert_serial.ilike(like.replace(":", "")),
                              m.AuthEvent.nas_ip.ilike(like)))
    if before_id:
        stmt = stmt.where(m.AuthEvent.id < before_id)
    rows = s.scalars(stmt.order_by(m.AuthEvent.id.desc()).limit(page_size)).all()
    reasons = s.execute(select(m.AuthEvent.reason_code, func.count()).where(m.AuthEvent.tenant_id == ctx.id, m.AuthEvent.result == "reject",
                                                                            m.AuthEvent.at >= datetime.now(UTC) - timedelta(hours=hours)).group_by(m.AuthEvent.reason_code)).all()
    return {"items": [event_out(e) for e in rows], "next_before_id": rows[-1].id if len(rows) == page_size else None,
            "reasons": [{"reason_code": r, "count": n, "title": (explain(r) or {}).get("title", r)} for r, n in reasons]}


@router.get("/tenants/{tenant_id}/events/{event_id}")
def get_event(event_id: int, ctx: TenantCtx = Depends(require("events:read"))) -> dict:
    e = ctx.session.get(m.AuthEvent, event_id)
    if e is None or e.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Event not found.")
    out = event_out(e)
    if e.cert_serial:
        c = ctx.session.scalars(select(m.Certificate).where(m.Certificate.tenant_id == ctx.id, m.Certificate.serial == e.cert_serial)).first()
        out["certificate_id"] = str(c.id) if c else None
        dec = ctx.session.get(m.Decision, c.id) if c else None
        out["decision_steps"] = dec.steps if dec else None
    return out


@router.get("/tenants/{tenant_id}/sessions")
def sessions(ctx: TenantCtx = Depends(require("events:read")), active: bool = True) -> dict:
    stmt = select(m.AccountingSession).where(m.AccountingSession.tenant_id == ctx.id)
    if active:
        stmt = stmt.where(m.AccountingSession.stopped_at.is_(None), m.AccountingSession.updated_at >= datetime.now(UTC) - timedelta(hours=26))
    rows = ctx.session.scalars(stmt.order_by(m.AccountingSession.updated_at.desc()).limit(500)).all()
    return {"items": [{"id": str(r.id), "username": r.username, "calling_station_id": r.calling_station_id, "called_station_id": r.called_station_id,
                       "nas_ip": r.nas_ip, "framed_ip": r.framed_ip, "vlan_id": r.vlan_id, "started_at": r.started_at.isoformat() if r.started_at else None,
                       "updated_at": r.updated_at.isoformat(), "stopped_at": r.stopped_at.isoformat() if r.stopped_at else None,
                       "input_octets": r.input_octets, "output_octets": r.output_octets} for r in rows]}


def audit_out(a: m.AuditEvent) -> dict:
    return {"id": a.id, "tenant_id": str(a.tenant_id) if a.tenant_id else None, "at": a.at.isoformat(), "actor_type": a.actor_type, "actor": a.actor_label,
            "action": a.action, "target_type": a.target_type, "target_id": a.target_id, "target": a.target_label, "detail": a.detail, "ip": a.ip}


@router.get("/tenants/{tenant_id}/audit")
def tenant_audit(ctx: TenantCtx = Depends(require("audit:read")), q: str = "", before_id: int | None = None, page_size: int = Query(100, ge=1, le=500)) -> dict:
    stmt = select(m.AuditEvent).where(m.AuditEvent.tenant_id == ctx.id)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(m.AuditEvent.action.ilike(like), m.AuditEvent.actor_label.ilike(like), m.AuditEvent.target_label.ilike(like)))
    if before_id:
        stmt = stmt.where(m.AuditEvent.id < before_id)
    rows = ctx.session.scalars(stmt.order_by(m.AuditEvent.id.desc()).limit(page_size)).all()
    return {"items": [audit_out(a) for a in rows], "next_before_id": rows[-1].id if len(rows) == page_size else None}


@router.get("/audit")
def platform_audit(p: Principal = Depends(platform("platform:read")), s: Session = Depends(db), q: str = "",
                   before_id: int | None = None, page_size: int = Query(100, ge=1, le=500)) -> dict:
    set_platform(s)
    stmt = select(m.AuditEvent)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(m.AuditEvent.action.ilike(like), m.AuditEvent.actor_label.ilike(like), m.AuditEvent.target_label.ilike(like)))
    if before_id:
        stmt = stmt.where(m.AuditEvent.id < before_id)
    rows = s.scalars(stmt.order_by(m.AuditEvent.id.desc()).limit(page_size)).all()
    return {"items": [audit_out(a) for a in rows], "next_before_id": rows[-1].id if len(rows) == page_size else None}


@router.post("/audit/verify")
def verify(p: Principal = Depends(platform("platform:read")), s: Session = Depends(db)) -> dict:
    set_platform(s)
    ok, bad, n = audit_mod.verify_chain(s)
    return {"ok": ok, "first_bad_id": bad, "checked": n}
