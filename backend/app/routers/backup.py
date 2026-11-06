"""Backup and restore in the console (System → Backup and restore) and on the first-run screen.

Making or restoring a backup is limited to the Super Administrator (platform:write) and asks for the password (and the
two-factor code when it is on) again. On a fresh instance, the one-time setup token authorises a restore instead.
Passphrases are never stored or logged: they are used for the one request and dropped.
"""
from __future__ import annotations

import os
from typing import Any

import pyotp
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from starlette.requests import ClientDisconnect

from app import audit
from app import models as m
from app.backup import engine, pkictl
from app.backup.bundle import BundleError
from app.deps import Principal, client_ip, db, platform
from app.pki import crypto
from app.routers.setup import needs_setup
from app.secrets_store import setup_token_path
from app.security.passwords import verify_password
from app.security.ratelimit import limiter
from app.security.tokens import constant_eq

router = APIRouter(prefix="/api/system", tags=["backup"])
setup_router = APIRouter(prefix="/api/setup/restore", tags=["setup"])
owner = platform("platform:write")


def _bad(exc: Exception) -> HTTPException:
    return HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))


def _reauth(p: Principal, s: Session, request: Request, password: str, totp: str | None) -> None:
    """Confirm it is still the administrator at the keyboard. 403 (not 401), so the console doesn't sign out."""
    if not limiter.hit(f"reauth:{p.admin.id}", 5):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts. Wait a minute.")
    if not verify_password(p.admin.password_hash, password):
        audit.record(s, p.actor, "auth.reauth_failed", target_type="admin", target_id=p.admin.id, target_label=p.admin.email)
        s.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Your password is incorrect.")
    if p.admin.mfa_enabled:
        secret = crypto.decrypt_str(None, p.admin.mfa_secret_ct or "")
        if not totp or not pyotp.TOTP(secret).verify(totp.replace(" ", ""), valid_window=1):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Enter the current code from your authenticator app.")


async def _receive(request: Request, source: str) -> dict[str, Any]:
    """Stream the request body to the backups volume (never into memory)."""
    length = request.headers.get("content-length")
    try:
        engine.check_space(int(length) if length and length.isdigit() else None)
    except BundleError as exc:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, str(exc)) from exc
    rid, partial = engine.new_upload_path()
    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    received = 0
    try:
        with os.fdopen(fd, "wb") as f:
            async for chunk in request.stream():
                received += len(chunk)
                if received > engine.MAX_UPLOAD:
                    raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "That file is too large to be an EasyEAP backup.")
                f.write(chunk)
    except ClientDisconnect:
        partial.unlink(missing_ok=True)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The upload was interrupted.") from None
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    if received == 0:
        partial.unlink(missing_ok=True)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Choose a backup file to upload.")
    try:
        return await run_in_threadpool(engine.finish_upload, rid, partial, source)
    except BundleError as exc:
        raise _bad(exc) from exc


# ── Console (running system) ─────────────────────────────────────────────────

@router.get("/maintenance")
def maintenance_status() -> dict:
    """Public: the restore progress page polls this before anyone can sign in."""
    current = engine.maintenance()
    last = engine.restore_state()
    return {"maintenance": current, "last_restore": engine.public_state(last) if last and not current else None}


@router.get("/backups")
def backups(p: Principal = Depends(owner), s: Session = Depends(db)) -> dict:
    from app.config import get_settings
    last = engine.restore_state()
    setting = s.get(m.PlatformSetting, "last_backup")
    return {"backups": engine.list_backups(), "supervisor": pkictl.available(),
            "recovery_keys": engine.recovery_keys_present(), "last_backup": setting.value if setting else None,
            "last_restore": engine.public_state(last) if last else None, "retention_hours": get_settings().backup_retention_hours}


class BackupIn(BaseModel):
    passphrase: str = Field(min_length=1, max_length=1024)
    password: str = Field(min_length=1, max_length=256)
    totp: str | None = Field(default=None, max_length=10)


@router.post("/backups", status_code=202)
def create_backup(body: BackupIn, request: Request, p: Principal = Depends(owner), s: Session = Depends(db)) -> dict:
    _reauth(p, s, request, body.password, body.totp)
    try:
        return engine.start_backup(p.actor, body.passphrase)
    except BundleError as exc:
        raise _bad(exc) from exc


@router.get("/backups/{rid}")
def backup_status(rid: str, p: Principal = Depends(owner)) -> dict:
    try:
        rec, _ = engine.get_backup(rid)
    except BundleError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    return engine.public_record(rec)


@router.get("/backups/{rid}/download")
def download_backup(rid: str, p: Principal = Depends(owner)) -> FileResponse:
    try:
        rec, path = engine.get_backup(rid)
    except BundleError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    if rec.get("status") != "done" or not path.is_file():
        raise HTTPException(status.HTTP_409_CONFLICT, "This backup isn't ready to download.")
    engine.mark_downloaded(rid, p.actor)
    return FileResponse(path, filename=rec["file_name"], media_type="application/octet-stream",
                        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


@router.delete("/backups/{rid}")
def delete_backup(rid: str, p: Principal = Depends(owner), s: Session = Depends(db)) -> dict:
    try:
        rec, _ = engine.get_backup(rid)
        engine.delete_backup(rid)
    except BundleError as exc:
        raise _bad(exc) from exc
    audit.record(s, p.actor, "system.backup_deleted", target_type="backup", target_label=rec.get("file_name") or rid)
    return {"ok": True}


@router.post("/restore/upload", status_code=201)
async def upload_backup(request: Request, p: Principal = Depends(owner)) -> dict:
    return await _receive(request, f"console:{p.admin.email}")


class PassphraseIn(BaseModel):
    passphrase: str = Field(min_length=1, max_length=1024)


@router.post("/restore/{rid}/inspect")
def inspect_backup(rid: str, body: PassphraseIn, request: Request, p: Principal = Depends(owner)) -> dict:
    if not limiter.hit(f"inspect:{p.admin.id}", 10):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts. Wait a minute.")
    try:
        return engine.inspect(rid, body.passphrase)
    except BundleError as exc:
        raise _bad(exc) from exc


class RestoreIn(BaseModel):
    passphrase: str = Field(min_length=1, max_length=1024)
    password: str = Field(min_length=1, max_length=256)
    totp: str | None = Field(default=None, max_length=10)
    confirm: str = Field(max_length=20)


@router.post("/restore/{rid}/start", status_code=202)
def start_restore(rid: str, body: RestoreIn, request: Request, p: Principal = Depends(owner), s: Session = Depends(db)) -> dict:
    if body.confirm.strip() != "RESTORE":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Type RESTORE to confirm.")
    _reauth(p, s, request, body.password, body.totp)
    audit.record(s, p.actor, "system.restore_started", target_type="backup", target_label=rid)
    s.commit()
    try:
        return engine.start_restore(rid, body.passphrase, actor_label=p.admin.email, source="console")
    except BundleError as exc:
        raise _bad(exc) from exc


@router.delete("/restore/{rid}")
def discard_upload(rid: str, p: Principal = Depends(owner)) -> dict:
    engine.discard_upload(rid)
    return {"ok": True}


# ── First run (no administrator yet) ─────────────────────────────────────────

def _setup_guard(s: Session, request: Request, token: str | None) -> None:
    if not limiter.hit(f"setup:{client_ip(request)}", 10):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts. Wait a minute.")
    if not needs_setup(s):
        raise HTTPException(status.HTTP_409_CONFLICT, "Setup is already complete. Restore from System → Backup and restore instead.")
    path = setup_token_path()
    if not token or not path.exists() or not constant_eq(path.read_text().strip(), token.strip()):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "The setup token is incorrect. The installer printed it; "
                                                       "print it again with: docker compose exec easyeap-api easyeap setup-token")


@setup_router.post("/upload", status_code=201)
async def setup_upload(request: Request, x_setup_token: str | None = Header(default=None), s: Session = Depends(db)) -> dict:
    await run_in_threadpool(_setup_guard, s, request, x_setup_token)
    s.close()
    return await _receive(request, "first-run")


class SetupRestoreIn(BaseModel):
    setup_token: str = Field(min_length=10, max_length=200)
    passphrase: str = Field(min_length=1, max_length=1024)


@setup_router.post("/{rid}/inspect")
def setup_inspect(rid: str, body: SetupRestoreIn, request: Request, s: Session = Depends(db)) -> dict:
    _setup_guard(s, request, body.setup_token)
    try:
        return engine.inspect(rid, body.passphrase)
    except BundleError as exc:
        raise _bad(exc) from exc


@setup_router.post("/{rid}/start", status_code=202)
def setup_start(rid: str, body: SetupRestoreIn, request: Request, s: Session = Depends(db)) -> dict:
    _setup_guard(s, request, body.setup_token)
    s.close()
    try:
        return engine.start_restore(rid, body.passphrase, actor_label=f"first-run setup from {client_ip(request) or 'unknown address'}",
                                    source="first-run")
    except BundleError as exc:
        raise _bad(exc) from exc
