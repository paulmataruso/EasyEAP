"""radius-agent channel (bearer token). The agent pulls desired state and snapshots and pushes events; RADIUS keeps
authenticating from its local copy whenever this channel is unavailable."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import models as m
from app.admin import service as admin_svc
from app.db import set_platform
from app.deps import agent_auth, db
from app.pki.openbao import OpenBao
from app.policy.service import snapshot
from app.radius import events as ev
from app.radius import mab
from app.radius.state import desired_state

router = APIRouter(prefix="/api/agent", tags=["agent"], dependencies=[Depends(agent_auth)])


@router.get("/config")
def config(s: Session = Depends(db)) -> dict:
    set_platform(s)
    return desired_state(s, OpenBao())


def _pairs(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for part in text.split(","):
        if ":" in part:
            t, v = part.split(":", 1)
            if v.isdigit():
                out[t] = int(v)
    return out


@router.get("/snapshots")
def snapshots(have: str = "", have_mac: str | None = None, have_admin: str | None = None, s: Session = Depends(db)) -> dict:
    """`have` = comma-separated tenant:version pairs the agent already applied; only changed snapshots are returned.
    `have_mac`, from agents that know the MAC allow list, is the same for its part: each snapshot then carries
    `mac_version`, and `mac_entries` when the agent's version differs (docs/plans/mac-auth.md §4). Older agents don't
    send it and get no MAC part. `have_admin` does the same for device administration (docs/plans/device-admin.md §4):
    `admin_version` and `admin_valid_until` always, `admin` when the agent's copy is another version."""
    set_platform(s)
    known = _pairs(have)
    known_mac = _pairs(have_mac) if have_mac is not None else None
    known_admin = _pairs(have_admin) if have_admin is not None else None
    out = []
    versions = {}
    for rs in s.scalars(select(m.RadiusSettings).join(m.Tenant, m.Tenant.id == m.RadiusSettings.tenant_id).where(m.Tenant.status == "active")):
        versions[str(rs.tenant_id)] = rs.snapshot_version
        if known.get(str(rs.tenant_id)) != rs.snapshot_version or rs.snapshot_built_at is None:
            out.append(snapshot(s, rs.tenant_id))
        else:
            # Unchanged entries: still refresh validity so a healthy system never trips the staleness limit.
            ps = s.get(m.PolicySettings, rs.tenant_id)
            out.append({"tenant_id": str(rs.tenant_id), "version": rs.snapshot_version, "unchanged": True,
                        "built_at": int(rs.snapshot_built_at.timestamp()),
                        "valid_until": int(rs.snapshot_built_at.timestamp()) + (ps.max_snapshot_age_seconds if ps else 86_400)})
        if known_mac is not None:
            out[-1].update(mab.snapshot_part(s, rs.tenant_id, known_mac.get(str(rs.tenant_id))))
        if known_admin is not None:
            ps = s.get(m.PolicySettings, rs.tenant_id)
            out[-1].update(admin_svc.snapshot_part(s, rs.tenant_id, known_admin.get(str(rs.tenant_id)), ps.max_snapshot_age_seconds if ps else 86_400))
    return {"snapshots": out, "tenants": list(versions)}


class Batch(BaseModel):
    items: list[dict[str, Any]] = Field(max_length=5000)


@router.post("/events")
def push_events(body: Batch, s: Session = Depends(db)) -> dict:
    set_platform(s)
    return {"stored": ev.ingest_auth(s, body.items)}


class LogBatch(BaseModel):
    items: list[dict[str, Any]] = Field(max_length=1000)


@router.post("/admin-events")
def push_admin_events(body: Batch, s: Session = Depends(db)) -> dict:
    """Device-administration logins, enables, authorizations, sessions and commands from the TACACS+ service."""
    set_platform(s)
    return {"stored": admin_svc.ingest(s, body.items)}


@router.post("/logs")
def push_logs(body: LogBatch, s: Session = Depends(db)) -> dict:
    """Warnings and errors from the agent and FreeRADIUS, buffered on the RADIUS host while the API is away."""
    from app.logs.dbhandler import MAX_MESSAGE
    from app.security.redact import redact
    now = datetime.now(UTC)
    rows = []
    for it in body.items:
        level = str(it.get("level") or "info").lower()
        try:
            at = datetime.fromtimestamp(float(it.get("at") or 0), UTC) if it.get("at") else now
        except (TypeError, ValueError, OverflowError, OSError):
            at = now
        rows.append({"at": min(at, now), "level": level if level in ("debug", "info", "warning", "error", "critical") else "info",
                     "source": it.get("source") if it.get("source") in ("radius-agent", "freeradius") else "radius-agent",
                     "logger": str(it.get("logger") or "")[:100], "message": redact(str(it.get("message") or ""))[:MAX_MESSAGE]})
    if rows:
        s.execute(m.SystemLog.__table__.insert(), rows)
    return {"stored": len(rows)}


@router.post("/accounting")
def push_accounting(body: Batch, s: Session = Depends(db)) -> dict:
    set_platform(s)
    return {"stored": ev.ingest_accounting(s, body.items)}


@router.get("/coa")
def pending_coa(s: Session = Depends(db)) -> dict:
    set_platform(s)
    rows = s.execute(select(m.CoaRequest, m.RadiusClient).join(m.RadiusClient, m.RadiusClient.id == m.CoaRequest.nas_client_id)
                     .where(m.CoaRequest.status == "pending").order_by(m.CoaRequest.created_at).limit(100)).all()
    out = []
    for r, c in rows:
        r.status = "sent"
        # Send to the NAS that reported the session; fall back to the client address when it is a single host.
        target = (r.attributes or {}).get("NAS-IP-Address") or (c.address if "/" not in c.address else "")
        if not target:
            r.status, r.result_detail = "failed", "No NAS address known for this session"
            continue
        out.append({"id": str(r.id), "tenant_id": str(r.tenant_id), "nas_client_id": str(c.id), "address": target, "port": c.coa_port,
                    "kind": r.kind, "attributes": r.attributes})
    return {"requests": out}


class CoaResult(BaseModel):
    status: str = Field(pattern="^(acked|nak|failed)$")
    detail: str = Field(default="", max_length=2000)


@router.post("/coa/{request_id}")
def coa_result(request_id: uuid.UUID, body: CoaResult, s: Session = Depends(db)) -> dict:
    set_platform(s)
    r = s.get(m.CoaRequest, request_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown request")
    r.status, r.result_detail, r.completed_at = body.status, body.detail, datetime.now(UTC)
    return {"ok": True}


class StatusIn(BaseModel):
    agent_id: str = Field(min_length=1, max_length=64)
    config_version: str = ""
    config_ok: bool = True
    config_error: str | None = Field(default=None, max_length=4000)
    snapshot_versions: dict[str, int] = {}
    radius_running: bool = False
    detail: dict[str, Any] = {}


@router.post("/status")
def push_status(body: StatusIn, s: Session = Depends(db)) -> dict:
    set_platform(s)
    a = s.get(m.AgentStatus, body.agent_id) or m.AgentStatus(agent_id=body.agent_id)
    a.last_seen_at, a.config_ok, a.config_error = datetime.now(UTC), body.config_ok, body.config_error
    a.snapshot_versions, a.radius_running = body.snapshot_versions, body.radius_running
    a.detail = {**body.detail, "config_digest": body.config_version}
    s.add(a)
    return {"ok": True}
