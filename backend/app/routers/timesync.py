"""System → Time: the NTP servers the host's chronyd uses, and how well the clock is kept.

Reading needs platform:read (Super Administrator, MSP Auditor); changing the servers needs platform:write and is
audited. The time service (easyeap-time) applies a saved change within a few seconds and reports back.
"""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.orm import Session

from app import audit
from app.db import set_platform
from app.deps import Principal, db, platform
from app.security.ratelimit import limiter
from app.timesync import config, sntp

router = APIRouter(prefix="/api/system", tags=["time"])
reader = platform("platform:read")
owner = platform("platform:write")


def _settings(t: config.TimeSettings) -> dict:
    return {"servers": [x.model_dump() for x in t.servers], "only_these": t.only_these, "revision": t.revision,
            "updated_at": t.updated_at, "updated_by": t.updated_by}


@router.get("/time")
def get_time(p: Principal = Depends(reader), s: Session = Depends(db)) -> dict:
    set_platform(s)
    now = datetime.now(UTC)
    settings, st = config.load_for_display(s), config.load_status(s)
    at = datetime.fromisoformat(st["at"]) if st and st.get("at") else None
    stale = at is None or (now - at).total_seconds() > config.STALE_SECONDS
    tone, line = config.assess(st, settings) if st and not stale else (None, None)
    return {"settings": _settings(settings), "status": st, "stale": stale,
            "assessment": {"tone": tone, "line": line} if tone else None, "max_servers": config.MAX_SERVERS,
            "now": now.isoformat(), "warn_offset": config.WARN_OFFSET, "crit_offset": config.CRIT_OFFSET}


@router.put("/time")
def put_time(body: config.SettingsIn, p: Principal = Depends(owner), s: Session = Depends(db)) -> dict:
    set_platform(s)
    saved = config.save(s, body, p.admin.email)   # SettingsIn validated it: a mistake is already a 422
    audit.record(s, p.actor, "system.time_updated", target_type="time", target_label="NTP servers",
                 detail={"servers": [x.directive() for x in saved.servers], "only_these": saved.only_these, "revision": saved.revision})
    return {"settings": _settings(saved)}


class TestIn(BaseModel):
    address: str = Field(min_length=1, max_length=253)


@router.post("/time/test")
async def test_server(body: TestIn, p: Principal = Depends(owner)) -> dict:
    """Ask the server for the time once (plain NTP, from EasyEAP's API container) and say how far the clock is from it:
    offset positive when EasyEAP's clock is ahead of the server's."""
    try:
        addr = config.Server(address=body.address).address
    except ValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, exc.errors()[0]["msg"].removeprefix("Value error, ")) from exc
    if not limiter.hit(f"time-test:{p.admin.id}", 20):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many tests. Wait a minute.")
    try:
        r = await run_in_threadpool(sntp.query, addr)
    except sntp.SntpError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{addr} didn't give the time: {exc}") from exc
    return {"address": r.address, "offset": -r.offset, "delay": r.delay, "stratum": r.stratum, "leap": r.leap}
