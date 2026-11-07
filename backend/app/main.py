"""EasyEAP API application."""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app import __version__
from app.backup import engine as backup_engine
from app.backup.bundle import BundleError
from app.backup.pkictl import PkiControlError
from app.config import get_settings
from app.directory.ldap import DirectoryError
from app.enrollment.service import EnrollmentError
from app.logs.dbhandler import install as install_db_logging
from app.pki.openbao import OpenBaoError
from app.pki.service import PkiError
from app.radius.state import RadiusConfigError
from app.routers import (
    admins,
    agent,
    auth,
    autoenroll,
    backup,
    certificates,
    dashboard,
    device_admin,
    directory,
    enroll_public,
    enrollments,
    events,
    identities,
    logs,
    mac,
    pki,
    pki_public,
    policy,
    radius,
    setup,
    switch_audit,
    system,
    tenants,
)
from app.security.redact import configure_logging

configure_logging()
log = logging.getLogger("easyeap.api")
settings = get_settings()

app = FastAPI(
    title="EasyEAP API", version=__version__, description="Enterprise Wi-Fi Authentication, Simplified.",
    docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json",
)

for r in (setup, auth, tenants, admins, dashboard, identities, directory, pki, certificates, enrollments, enroll_public, policy, radius,
          events, system, backup, logs, agent, pki_public, mac, device_admin, autoenroll, switch_audit):
    app.include_router(r.router)
app.include_router(backup.setup_router)
app.include_router(autoenroll.public)  # /cep and /ces: Windows, Kerberos

# While a backup is being restored the database and PKI are being replaced: everything except these answers 503 with
# the progress, which the console shows full-page. RADIUS keeps authenticating from its local data meanwhile.
_OPEN_DURING_RESTORE = ("/api/system/maintenance", "/api/health")


@app.middleware("http")
async def maintenance_gate(request: Request, call_next):
    if request.url.path not in _OPEN_DURING_RESTORE:
        state = backup_engine.maintenance()
        if state:
            return JSONResponse({"detail": "EasyEAP is restoring a backup. The console is back as soon as it finishes.", "maintenance": state},
                                status_code=503, headers={"Retry-After": "5", "Cache-Control": "no-store"})
    return await call_next(request)


@app.on_event("startup")
def _clean_backups() -> None:
    install_db_logging("api")
    log.info("EasyEAP API %s started", __version__)
    try:
        backup_engine.purge_expired()
    except OSError as exc:
        log.warning("Backup directory cleanup skipped: %s", exc)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


def _bad(message: str, hint: str | None = None, code: int = 400) -> JSONResponse:
    body = {"detail": message}
    if hint:
        body["hint"] = hint
    return JSONResponse(body, status_code=code)


@app.exception_handler(PkiError)
async def pki_error(_: Request, exc: PkiError):
    return _bad(str(exc))


@app.exception_handler(EnrollmentError)
async def enrollment_error(_: Request, exc: EnrollmentError):
    return _bad(str(exc))


@app.exception_handler(RadiusConfigError)
async def radius_error(_: Request, exc: RadiusConfigError):
    return _bad(str(exc))


@app.exception_handler(DirectoryError)
async def directory_error(_: Request, exc: DirectoryError):
    return _bad(str(exc), exc.hint, 502)


@app.exception_handler(OpenBaoError)
async def bao_error(_: Request, exc: OpenBaoError):
    log.error("PKI service error: %s", exc)
    return _bad("The PKI service rejected the request.", "; ".join(exc.errors)[:300] if settings.is_dev else "See the API log for details.", 502)


@app.exception_handler(BundleError)
async def bundle_error(_: Request, exc: BundleError):
    return _bad(str(exc))


@app.exception_handler(PkiControlError)
async def pki_control_error(_: Request, exc: PkiControlError):
    return _bad(str(exc), code=503)


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, exc: RequestValidationError):
    errors = []
    for e in exc.errors():
        loc = ".".join(str(x) for x in e.get("loc", []) if x not in ("body", "query", "path"))
        errors.append({"field": loc, "message": e.get("msg", "Invalid value")})
    first = errors[0] if errors else {"field": "", "message": "Invalid request"}
    return JSONResponse({"detail": f"{first['field']}: {first['message']}" if first["field"] else first["message"], "errors": errors}, status_code=422)
