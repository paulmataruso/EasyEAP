"""First-run setup: create the first Super Administrator with the one-time setup token.

No default account exists. The token is generated on first start into the API's secrets volume and printed only by
`docker compose exec easyeap-api easyeap setup-token` (never logged).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app import models as m
from app.db import set_platform
from app.deps import client_ip, db
from app.routers.auth import me_payload, start_session
from app.secrets_store import consume_setup_token, setup_token_path
from app.security.passwords import hash_password, password_problems
from app.security.ratelimit import limiter
from app.security.tokens import constant_eq

router = APIRouter(prefix="/api/setup", tags=["setup"])


def needs_setup(s: Session) -> bool:
    set_platform(s)
    return (s.scalar(select(func.count()).select_from(m.Admin)) or 0) == 0


@router.get("/status")
def setup_status(s: Session = Depends(db)) -> dict:
    return {"needs_setup": needs_setup(s), "product": "EasyEAP"}


class SetupIn(BaseModel):
    setup_token: str = Field(min_length=10, max_length=200)
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=12, max_length=256)


@router.post("/admin")
def create_first_admin(body: SetupIn, request: Request, response: Response, s: Session = Depends(db)) -> dict:
    if not limiter.hit(f"setup:{client_ip(request)}", 5):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts. Wait a minute.")
    if not needs_setup(s):
        raise HTTPException(status.HTTP_409_CONFLICT, "Setup is already complete.")
    path = setup_token_path()
    if not path.exists() or not constant_eq(path.read_text().strip(), body.setup_token.strip()):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "The setup token is incorrect. Print it with: docker compose exec easyeap-api easyeap setup-token")
    problems = password_problems(body.password, body.email)
    if problems:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, " ".join(problems))
    s.execute(select(func.pg_advisory_xact_lock(0x45415053)))
    if not needs_setup(s):
        raise HTTPException(status.HTTP_409_CONFLICT, "Setup is already complete.")
    admin = m.Admin(email=body.email.lower(), display_name=body.display_name.strip(), password_hash=hash_password(body.password),
                    platform_role="platform_owner", is_active=True)
    s.add(admin)
    s.flush()
    consume_setup_token()
    sess = start_session(s, response, request, admin, mfa_passed=True)
    audit.record(s, audit.Actor("admin", admin.email, str(admin.id), client_ip(request)), "setup.first_admin_created",
                 target_type="admin", target_id=admin.id, target_label=admin.email)
    return me_payload(s, admin, sess)
