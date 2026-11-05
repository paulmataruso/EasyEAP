"""Append-only, hash-chained audit trail.

Each row stores sha256(prev_hash || canonical JSON of the row). The application role has no UPDATE/DELETE grant on
audit_events, and `verify_chain` detects any edit made with owner privileges. Never put secrets into `detail`.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app import models as m

GENESIS = "0" * 64
_LOCK_KEY = 0x45415041  # "EAPA": serialises chain appends across api/worker processes
_FORBIDDEN_KEYS = {"password", "secret", "shared_secret", "passphrase", "private_key", "token", "bind_password", "p12", "pkcs12"}


class Actor:
    def __init__(self, kind: str, label: str, actor_id: str | None = None, ip: str | None = None):
        self.kind, self.label, self.id, self.ip = kind, label, actor_id, ip

    @classmethod
    def system(cls, label: str = "EasyEAP") -> Actor:
        return cls("system", label)


def _scrub(detail: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in detail.items():
        if k.lower() in _FORBIDDEN_KEYS:
            out[k] = "[withheld]"
        elif isinstance(v, dict):
            out[k] = _scrub(v)
        else:
            out[k] = v
    return out


def _canonical(row: m.AuditEvent) -> str:
    return json.dumps({
        "tenant_id": str(row.tenant_id) if row.tenant_id else None,
        "at": row.at.isoformat(),
        "actor_type": row.actor_type, "actor_id": row.actor_id, "actor_label": row.actor_label,
        "action": row.action, "target_type": row.target_type, "target_id": row.target_id, "target_label": row.target_label,
        "detail": row.detail, "ip": row.ip,
    }, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(prev_hash: str, row: m.AuditEvent) -> str:
    return hashlib.sha256((prev_hash + _canonical(row)).encode()).hexdigest()


def record(session: Session, actor: Actor, action: str, *, tenant_id: uuid.UUID | None = None, target_type: str = "",
           target_id: Any = None, target_label: str = "", detail: dict[str, Any] | None = None) -> m.AuditEvent:
    session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _LOCK_KEY})
    prev = session.scalar(select(m.AuditEvent.hash).order_by(m.AuditEvent.id.desc()).limit(1)) or GENESIS
    row = m.AuditEvent(
        tenant_id=tenant_id, at=datetime.now(UTC), actor_type=actor.kind, actor_id=actor.id, actor_label=actor.label[:254],
        action=action, target_type=target_type, target_id=str(target_id) if target_id is not None else None,
        target_label=(target_label or "")[:254], detail=json.loads(json.dumps(_scrub(detail or {}), default=str)), ip=actor.ip,
        prev_hash=prev,
    )
    row.hash = compute_hash(prev, row)
    session.add(row)
    session.flush()
    return row


def verify_chain(session: Session, limit: int | None = None) -> tuple[bool, int | None, int]:
    """Return (ok, first_bad_id, rows_checked)."""
    prev = GENESIS
    checked = 0
    q = select(m.AuditEvent).order_by(m.AuditEvent.id)
    if limit:
        q = q.limit(limit)
    for row in session.scalars(q).yield_per(500):
        if row.prev_hash != prev or compute_hash(prev, row) != row.hash:
            return False, row.id, checked
        prev = row.hash
        checked += 1
    return True, None, checked
