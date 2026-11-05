"""Postgres-backed job queue (SELECT … FOR UPDATE SKIP LOCKED). Jobs survive restarts and are deduplicated."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app import models as m

MAX_ATTEMPTS = 5


def enqueue(session: Session, kind: str, *, tenant_id: uuid.UUID | None = None, payload: dict[str, Any] | None = None,
            dedupe_key: str | None = None, delay_seconds: float = 0) -> None:
    stmt = insert(m.Job).values(
        kind=kind, tenant_id=tenant_id, payload=payload or {}, dedupe_key=dedupe_key,
        run_at=datetime.now(UTC) + timedelta(seconds=delay_seconds), status="queued", attempts=0,
    )
    if dedupe_key:
        stmt = stmt.on_conflict_do_nothing(index_elements=["dedupe_key"])
    session.execute(stmt)


def claim(session: Session) -> m.Job | None:
    row = session.execute(text(
        "SELECT id FROM jobs WHERE status = 'queued' AND run_at <= now() ORDER BY run_at, id LIMIT 1 FOR UPDATE SKIP LOCKED"
    )).first()
    if not row:
        return None
    job = session.get(m.Job, row[0])
    if job is None:
        return None
    job.status = "running"
    job.attempts += 1
    job.run_at = datetime.now(UTC)  # while running, run_at records the start time
    return job


def finish(session: Session, job: m.Job, error: str | None = None) -> None:
    now = datetime.now(UTC)
    if error is None:
        job.status, job.finished_at, job.dedupe_key, job.last_error = "done", now, None, None
        return
    job.last_error = error[:2000]
    if job.attempts >= MAX_ATTEMPTS:
        job.status, job.finished_at, job.dedupe_key = "failed", now, None
    else:
        job.status = "queued"
        job.run_at = now + timedelta(seconds=min(30 * 2 ** job.attempts, 1800))


def recover_stuck(session: Session, older_than_minutes: int = 60) -> None:
    """Jobs left 'running' by a crashed worker go back to the queue."""
    session.execute(text(
        "UPDATE jobs SET status = 'queued', run_at = now() WHERE status = 'running' "
        "AND run_at < now() - make_interval(mins => :m)"
    ), {"m": older_than_minutes})


def prune(session: Session, keep_days: int = 14) -> None:
    session.execute(text("DELETE FROM jobs WHERE status IN ('done','failed') AND finished_at < now() - make_interval(days => :d)"), {"d": keep_days})
