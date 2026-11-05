"""EasyEAP API application."""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app import __version__
from app.config import get_settings
from app.directory.ldap import DirectoryError
from app.enrollment.service import EnrollmentError
from app.pki.openbao import OpenBaoError
from app.pki.service import PkiError
from app.radius.state import RadiusConfigError
from app.routers import (admins, agent, auth, certificates, dashboard, directory, enroll_public, enrollments, events, identities,
                         pki, pki_public, policy, radius, setup, system, tenants)
from app.security.redact import configure_logging

configure_logging()
log = logging.getLogger("easyeap.api")
settings = get_settings()

app = FastAPI(
    title="EasyEAP API", version=__version__, description="Enterprise Wi-Fi Authentication, Simplified.",
    docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json",
)

for r in (setup, auth, tenants, admins, dashboard, identities, directory, pki, certificates, enrollments, enroll_public, policy, radius,
          events, system, agent, pki_public):
    app.include_router(r.router)


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


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, exc: RequestValidationError):
    errors = []
    for e in exc.errors():
        loc = ".".join(str(x) for x in e.get("loc", []) if x not in ("body", "query", "path"))
        errors.append({"field": loc, "message": e.get("msg", "Invalid value")})
    first = errors[0] if errors else {"field": "", "message": "Invalid request"}
    return JSONResponse({"detail": f"{first['field']}: {first['message']}" if first["field"] else first["message"], "errors": errors}, status_code=422)
