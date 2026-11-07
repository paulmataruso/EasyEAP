"""Group Policy autoenrollment (docs/plans/gpo-autoenrollment.md).

`public`: the two endpoints Windows calls, POST /cep/{slug} (MS-XCEP, which templates) and POST /ces/{slug}
(MS-WSTEP, issue), authenticated with Kerberos (HTTP Negotiate) and bound to the TLS connection.
`router`: the console's settings, keytab, test, scripts and request log.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import logging
import re
import time
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app import audit
from app import models as m
from app.autoenroll import kerberos, keytab_test, soap
from app.autoenroll import service as svc
from app.config import get_settings
from app.db import set_platform, set_tenant
from app.deps import TenantCtx, client_ip, db, require
from app.directory import ldap
from app.directory.sync import params as directory_params
from app.pki import crypto
from app.pki import service as pki
from app.pki.openbao import OpenBao
from app.security.ratelimit import limiter

log = logging.getLogger("easyeap.autoenroll")

public = APIRouter(tags=["autoenroll"], include_in_schema=False)
router = APIRouter(prefix="/api/tenants/{tenant_id}/autoenroll", tags=["autoenroll"])

PER_CALLER_PER_MINUTE = 60
FAILURES_LOGGED_PER_MINUTE = 20     # per tenant and address: unauthenticated noise mustn't flush the request log
FAILURES_LOGGED_PER_TENANT = 120    # per tenant and minute, from all addresses together
CEP_LOG_EVERY = 6 * 3600            # a caller's routine policy request is logged at most this often (seconds)
REPEAT_LOG_EVERY = 3600             # the same refusal of the same caller is logged at most this often (seconds)
CODES_INVALID_REQUEST = {"bad_request", "key", "request_type", "no_dns_name", "dns_name"}
# Callers autoenrollment isn't for get an empty policy, as from AD CS, rather than a fault Windows would log at
# every policy refresh.
CODES_OUT_OF_SCOPE = {"not_in_group", "unknown_user", "account_state", "not_computer", "not_workstation"}
TENANT_CACHE_SECONDS = 30


# ── Windows: /cep and /ces ───────────────────────────────────────────────────

_keytabs: dict[uuid.UUID, tuple[str, bytes]] = {}
# slug → (until, answering): lets the first, credential-less request of each exchange get its 401 without a database
# connection. One API process (entrypoint.sh), so saving the settings clears it.
_tenants: dict[str, tuple[float, bool]] = {}


def _keytab(tenant_id: uuid.UUID, cfg: m.AutoenrollConfig) -> bytes:
    """The tenant's keytab, decrypted once per upload (one Transit call, not one per request), with only its keys for
    HTTP/<console host> (kerberos.for_host)."""
    hit = _keytabs.get(tenant_id)
    if hit and hit[0] == cfg.keytab_ct:
        return hit[1]
    data = kerberos.for_host(crypto.decrypt(tenant_id, cfg.keytab_ct or ""), console_host())
    _keytabs[tenant_id] = (cfg.keytab_ct or "", data)
    return data


def _forget_keytab(tenant_id: uuid.UUID, cfg: m.AutoenrollConfig) -> None:
    if cfg.keytab_ct:
        try:
            kerberos.forget(_keytab(tenant_id, cfg))
        except Exception:  # only tidying tmpfs
            log.warning("Couldn't remove the replaced keytab's file", exc_info=True)
    _keytabs.pop(tenant_id, None)


_MESSAGE_ID = re.compile(rb"<(?:\w+:)?MessageID[^>]*>\s*([^<\s]{1,200})\s*<", re.IGNORECASE)


def _message_id(body: bytes) -> str:
    """Best effort, for faults about a message that can't be parsed."""
    found = _MESSAGE_ID.search(body[:8192])
    return found.group(1).decode("ascii", "replace") if found else ""


def _soap(xml: str, code: int = 200, reply: str | None = None) -> Response:
    headers = {"Cache-Control": "no-store"}
    if reply:
        headers["WWW-Authenticate"] = f"Negotiate {reply}"
    return Response(content=xml.encode(), status_code=code, media_type=soap.CONTENT_TYPE, headers=headers)


def _challenge() -> Response:
    return Response(status_code=401, headers={"WWW-Authenticate": "Negotiate", "Cache-Control": "no-store"})


def _fault(service: str, relates_to: str, reason: str, *, hresult: int = soap.E_FAIL, request_id: int | None = None,
           invalid: bool = False, reply: str | None = None, code: int = 500) -> Response:
    if service == "ces":
        xml = soap.wstep_fault(relates_to=relates_to, reason=reason, error_code=hresult, invalid_request=invalid, request_id=request_id)
    else:
        xml = soap.soap_fault(relates_to=relates_to, reason=reason)
    return _soap(xml, code, reply)


def _ca_der(s: Session, tenant_id: uuid.UUID) -> bytes:
    return x509.load_pem_x509_certificate(pki.issuing_ca(s, tenant_id).certificate_pem.encode()).public_bytes(serialization.Encoding.DER)


def _base_url() -> str:
    return get_settings().public_url.rstrip("/")


def _serve(service: str, slug: str, body: bytes, authorization: str | None, ip: str | None, s: Session) -> Response:
    if not authorization:
        hit = _tenants.get(slug)
        if hit and hit[0] > time.monotonic():
            return _challenge() if hit[1] else Response(status_code=404)
    set_platform(s)
    tenant = s.scalars(select(m.Tenant).where(m.Tenant.slug == slug)).first()
    cfg = None
    if tenant is not None and tenant.status != "suspended":
        set_tenant(s, tenant.id)
        cfg = s.get(m.AutoenrollConfig, tenant.id)
    answering = cfg is not None and cfg.enabled
    if len(_tenants) > 10_000:
        _tenants.clear()
    _tenants[slug] = (time.monotonic() + TENANT_CACHE_SECONDS, answering)
    if not answering:
        return Response(status_code=404)
    relates = _message_id(body)

    def failed(code: str, message: str, *, outcome: str = "denied", caller: str = "", kind: str | None = None) -> None:
        if caller:  # the same refusal of the same account, again at every refresh, is logged now and then
            log_it = limiter.hit(f"ae-rep:{tenant.id}:{service}:{caller.lower()}:{code}", 1, REPEAT_LOG_EVERY)
        else:  # no account: anyone can send these, so they're capped per address and per tenant
            log_it = (limiter.hit(f"ae-fail:{tenant.id}:{ip}", FAILURES_LOGGED_PER_MINUTE)
                      and limiter.hit(f"ae-fail:{tenant.id}", FAILURES_LOGGED_PER_TENANT))
        if log_it:
            svc.record_event(s, tenant.id, service=service, caller=caller, kind=kind, outcome=outcome, code=code, message=message, ip=ip)
            s.commit()

    # Kerberos. Windows sends the request without credentials first, and again with a ticket after the 401.
    try:
        token = kerberos.negotiate_token(authorization)
    except kerberos.KerberosError as exc:
        failed(exc.code, str(exc))
        return _challenge()
    if token is None:
        return _challenge()
    if not cfg.keytab_ct:
        failed("keytab", "A PC asked for certificates, but there's no keytab: upload one under Group Policy → Autoenrollment.", outcome="error")
        return _fault(service, relates, "EasyEAP isn't set up for Kerberos yet (no keytab).")
    r = svc.realm(s, tenant.id) or (cfg.keytab_info or {}).get("realm")
    # Only when required: bindings given to the acceptor must match the PC's, so behind a TLS-inspecting proxy (the
    # reason to turn the requirement off) every ticket would be refused.
    binding = kerberos.proxy_binding() if cfg.require_channel_binding else None
    try:
        caller = kerberos.accept(token, _keytab(tenant.id, cfg), [r] if r else [], binding=binding)
    except kerberos.KerberosError as exc:
        failed(exc.code, str(exc), outcome="error" if exc.code == "keytab" else "denied")
        return _challenge() if exc.code in ("invalid", "ntlm") else _fault(service, relates, str(exc))
    who, kind = caller.principal, ("computer" if caller.claims_computer else "user")
    if cfg.require_channel_binding and not caller.channel_bound:
        if binding is None:
            msg = ("EasyEAP can't check channel binding: the API can't read the proxy's certificate (/etc/easyeap/proxy-tls.crt; "
                   "see the upgrade notes). Update the compose file, or turn off Require channel binding.")
        else:
            msg = ("The PC's Kerberos ticket wasn't bound to its TLS connection to EasyEAP (Extended Protection). Something "
                   "between them may end TLS, or the PC is set not to send channel bindings. Refused.")
        failed("binding", msg, outcome="error" if binding is None else "denied", caller=who, kind=kind)
        return _fault(service, relates, msg, hresult=soap.CERTSRV_E_ENROLL_DENIED, reply=caller.reply)
    if not limiter.hit(f"ae:{tenant.id}:{who.lower()}", PER_CALLER_PER_MINUTE):
        return _fault(service, relates, "Too many requests from this account; try again in a minute.", reply=caller.reply, code=503)

    denied: svc.Denied | None = None
    try:
        with s.begin_nested():  # a database or directory failure mustn't leave the session unusable for the event
            try:
                ident = svc.identify(s, tenant.id, cfg, caller)
            except svc.Denied as d:
                denied = d  # what identify learned (a computer's refreshed groups and state) is kept
    except Exception as exc:
        log.exception("Autoenrollment: identifying %s failed", who)
        failed("internal", f"EasyEAP couldn't check {who}: {exc}", outcome="error", caller=who, kind=kind)
        return _fault(service, relates, "EasyEAP couldn't check this account; see the request log in the console.", reply=caller.reply)
    if denied is not None:
        failed(denied.code, str(denied), caller=who, kind=kind)
        if service == "cep" and denied.code in CODES_OUT_OF_SCOPE:
            return _policies(s, tenant, cfg, None, kind, body, who, ip, caller.reply)
        return _fault(service, relates, str(denied), hresult=denied.hresult, reply=caller.reply)

    if service == "cep":
        return _policies(s, tenant, cfg, ident, ident.kind, body, who, ip, caller.reply)
    return _enroll(s, tenant, cfg, ident, body, who, ip, caller.reply)


def _policies(s: Session, tenant: m.Tenant, cfg: m.AutoenrollConfig, ident: m.Identity | None, kind: str, body: bytes, who: str,
              ip: str | None, reply: str | None) -> Response:
    """The policy for an identity, or an empty one (ident None) for a caller autoenrollment isn't for, whose reason
    is already in the request log."""
    try:
        gp = soap.parse_get_policies(body)
    except soap.SoapError as exc:
        svc.record_event(s, tenant.id, service="cep", caller=who, kind=kind, outcome="denied", code="bad_request", message=str(exc), ip=ip)
        s.commit()
        return _fault("cep", _message_id(body), str(exc), reply=reply, code=400)
    tpls = svc.offered(cfg, svc.templates(s, tenant.id), ident) if ident is not None else []
    if gp.policy_oids:
        tpls = [t for t in tpls if t.template_oid in gp.policy_oids]
    try:
        ca_der = _ca_der(s, tenant.id)
    except pki.PkiError as exc:
        svc.record_event(s, tenant.id, service="cep", caller=who, kind=kind, outcome="error", code="pki", message=str(exc), ip=ip)
        s.commit()
        return _fault("cep", gp.message_id, str(exc), reply=reply)
    xml = soap.get_policies_response(relates_to=gp.message_id, policy_id=cfg.policy_id, friendly_name=f"EasyEAP ({tenant.name})",
                                     ces_uri=f"{_base_url()}/ces/{tenant.slug}", ca_der=ca_der,
                                     templates=[svc.template_policy(t) for t in tpls])
    # Every PC asks at each policy refresh (about every 8 hours, and at sign-in for users): log a caller's routine
    # request now and then, and always one that's offered nothing (a setting or the GPO is off for it).
    if ident is None:
        pass  # the refusal is the log line
    elif limiter.hit(f"ae-cep-log:{tenant.id}:{who.lower()}:{bool(tpls)}", 1, CEP_LOG_EVERY):
        on = cfg.computers if kind == "computer" else cfg.users
        if tpls:
            message = "Offered " + ", ".join(t.name for t in tpls) + "."
        elif not on:
            message = f"Offered nothing: autoenrollment is off for {kind}s."
        else:
            message = "Offered nothing (the request asked for other templates)."
        svc.record_event(s, tenant.id, service="cep", caller=who, kind=kind, outcome="ok", code="" if tpls else "none",
                         message=message, ip=ip)
    elif cfg.last_success_at is None or cfg.last_success_at < datetime.now(UTC) - timedelta(minutes=5):
        cfg.last_success_at = datetime.now(UTC)
    s.commit()
    return _soap(xml, reply=reply)


def _enroll(s: Session, tenant: m.Tenant, cfg: m.AutoenrollConfig, ident: m.Identity, body: bytes, who: str, ip: str | None,
            reply: str | None) -> Response:
    try:
        rst = soap.parse_rst(body)
    except soap.SoapError as exc:
        ev = svc.record_event(s, tenant.id, service="ces", caller=who, kind=ident.kind, outcome="denied", code="bad_request",
                              message=str(exc), ip=ip)
        s.commit()
        return _fault("ces", _message_id(body), str(exc), hresult=soap.E_INVALIDARG, request_id=ev.id, invalid=True, reply=reply, code=400)
    machine = rst.context.get("ccm") or rst.context.get("rmd")
    try:
        with s.begin_nested():
            issued, parsed = svc.enroll(s, OpenBao(), tenant, cfg, ident, rst)
    except svc.Denied as d:
        ev = svc.record_event(s, tenant.id, service="ces", caller=who, kind=ident.kind, outcome="denied", code=d.code, message=str(d),
                              machine=machine, ip=ip)
        s.commit()
        return _fault("ces", rst.message_id, str(d), hresult=d.hresult, request_id=ev.id, invalid=d.code in CODES_INVALID_REQUEST, reply=reply)
    except Exception as exc:  # Windows gets a fault and the console the reason, whatever failed
        log.exception("Autoenrollment for %s failed", who)
        ev = svc.record_event(s, tenant.id, service="ces", caller=who, kind=ident.kind, outcome="error", code="internal",
                              message=f"EasyEAP couldn't issue the certificate: {exc}", machine=machine, ip=ip)
        s.commit()
        return _fault("ces", rst.message_id, "EasyEAP couldn't issue the certificate; see the request log in the console.",
                      request_id=ev.id, reply=reply)
    cert = issued.certificate
    device = s.get(m.Device, cert.device_id) if cert.device_id else None
    tpl = s.get(m.CertificateTemplate, cert.template_id) if cert.template_id else None
    ev = svc.record_event(s, tenant.id, service="ces", caller=who, kind=ident.kind, outcome="ok",
                          message=f"Issued {cert.common_name} (serial {cert.serial}, key in {cert.key_storage or 'unknown storage'}, "
                                  f"{parsed.form} request).",
                          template=tpl.name if tpl else None, machine=device.name if device else machine, certificate_id=cert.id, ip=ip)
    xml = soap.issued_response(relates_to=rst.message_id, request_id=ev.id, response_der=issued.response_der,
                               certificate_der=issued.certificate_der)
    s.commit()
    return _soap(xml, reply=reply)


async def _read(request: Request) -> bytes | Response:
    try:
        if int(request.headers.get("content-length") or 0) > soap.MAX_BODY:
            return Response(status_code=413)
    except ValueError:
        return Response(status_code=400)
    body = await request.body()
    return Response(status_code=413) if len(body) > soap.MAX_BODY else body


@public.post("/cep/{slug}")
async def cep(slug: str, request: Request, s: Session = Depends(db)) -> Response:
    body = await _read(request)
    if isinstance(body, Response):
        return body
    return await run_in_threadpool(_serve, "cep", slug, body, request.headers.get("authorization"), client_ip(request), s)


@public.post("/ces/{slug}")
async def ces(slug: str, request: Request, s: Session = Depends(db)) -> Response:
    body = await _read(request)
    if isinstance(body, Response):
        return body
    return await run_in_threadpool(_serve, "ces", slug, body, request.headers.get("authorization"), client_ip(request), s)


# ── Console ──────────────────────────────────────────────────────────────────


def console_host() -> str:
    """The host name PCs reach EasyEAP by, which the SPN and the keytab must name."""
    return (urlparse(_base_url()).hostname or "").lower()


def _host_problem(host: str) -> str | None:
    if not host:
        return "EasyEAP's public URL has no host name."
    try:
        ipaddress.ip_address(host)
        return (f"PCs reach EasyEAP by an IP address ({host}). Kerberos needs a DNS name: set EASYEAP_HOSTNAME to the console's "
                "DNS name.")
    except ValueError:
        pass
    if host == "localhost" or host.endswith((".localhost", ".invalid", ".local")) or "." not in host:
        return f"{host} isn't a DNS name PCs can use. Set EASYEAP_HOSTNAME to the console's DNS name in your domain's DNS."
    return None


def _event_out(e: m.AutoenrollEvent) -> dict:
    return {"id": e.id, "at": e.at.isoformat(), "service": e.service, "caller": e.caller, "kind": e.kind, "outcome": e.outcome,
            "code": e.code, "message": e.message, "template": e.template, "machine": e.machine,
            "certificate_id": str(e.certificate_id) if e.certificate_id else None, "ip": e.ip}


def _template_out(t: m.CertificateTemplate) -> dict:
    return {"id": str(t.id), "kind": t.autoenroll_kind, "name": t.name, "common_name": svc.COMMON_NAMES.get(t.autoenroll_kind or ""),
            "oid": t.template_oid, "revision": f"{t.revision_major}.{t.revision_minor}", "validity_days": t.validity_days,
            "renew_before_days": t.renew_before_days}


def _readiness(s: Session, tenant: m.Tenant, cfg: m.AutoenrollConfig, host: str) -> list[dict]:
    """What's missing before PCs can enroll. level error: autoenrollment won't work; warning: it works, but look."""
    out: list[dict] = []

    def item(key: str, level: str, message: str) -> None:
        out.append({"key": key, "level": level, "message": message})

    problem = _host_problem(host)
    item("host", "error" if problem else "ok", problem or f"PCs reach EasyEAP at {host}.")

    d = s.get(m.DirectoryConfig, tenant.id)
    if d is None or not d.enabled:
        item("directory", "error", "Connect Active Directory (Directory): EasyEAP checks every computer and user there.")
    elif d.last_sync_status not in (None, "ok"):
        item("directory", "warning", f"The last directory sync failed: {d.last_sync_error or d.last_sync_status}.")
    else:
        item("directory", "ok", f"Active Directory {d.domain} is connected.")

    try:
        pki.issuing_ca(s, tenant.id)
        item("pki", "ok", "The issuing CA is ready.")
    except pki.PkiError:
        item("pki", "error", "Set up the certificate authority (Certificates → CA) first.")

    info = cfg.keytab_info or {}
    want = svc.realm(s, tenant.id)
    if not cfg.keytab_ct:
        item("keytab", "error", f"Upload the keytab for HTTP/{host} (run the service-account script to make it).")
    elif info.get("problems"):
        item("keytab", "error", " ".join(info["problems"]))
    elif want and info.get("realm") and info["realm"].upper() != want:
        item("keytab", "error", f"The keytab is for realm {info['realm']}, but the directory is {want}.")
    else:
        item("keytab", "ok", f"Keytab for {info.get('principal')} (key version {info.get('kvno')}).")

    t = cfg.keytab_test or {}
    uploaded = cfg.keytab_uploaded_at.isoformat() if cfg.keytab_uploaded_at else ""
    if cfg.keytab_ct and not t:
        item("keytab_test", "warning", "Test the keytab: EasyEAP gets a ticket from your domain controller the way a PC does.")
    elif t and t.get("uploaded_at") != uploaded:
        item("keytab_test", "warning", "The keytab changed since the last test; test it again.")
    elif t and not t.get("ok"):
        item("keytab_test", "warning" if t.get("step") in ("login", "kdc") else "error", t.get("message", "The test failed."))
    elif t:
        item("keytab_test", "ok", t.get("message", "The keytab works."))

    if kerberos.proxy_binding() is None:
        item("binding", "error" if cfg.require_channel_binding else "warning",
             "The API can't read the proxy's certificate, so it can't check channel binding. Update docker-compose.yml (see the "
             "upgrade notes)" + (", or turn off Require channel binding." if cfg.require_channel_binding else "."))
    elif not cfg.require_channel_binding:
        item("binding", "warning", "Channel binding isn't required: a ticket relayed from another TLS connection would be accepted.")
    else:
        item("binding", "ok", "Kerberos tickets must be bound to the PC's TLS connection to EasyEAP.")

    if cfg.computers:
        # A computer certificate is decided as the computer (its AD groups), with purpose computer: a rule must say so.
        allows = s.scalar(select(func.count()).select_from(m.AccessRule).where(
            m.AccessRule.tenant_id == tenant.id, m.AccessRule.enabled.is_(True), m.AccessRule.action == "allow",
            or_(m.AccessRule.purposes.is_(None), func.cardinality(m.AccessRule.purposes) == 0, m.AccessRule.purposes.any("computer")))) or 0
        ps = s.get(m.PolicySettings, tenant.id)
        if not allows and not (ps and ps.default_action == "allow"):
            item("policy", "warning", "No access rule lets computer certificates on the network. Add one in Access policy, for "
                                      "example Domain Computers → your PC VLAN, applying to Domain computers.")
    if cfg.computers and cfg.machine_account_quota and not cfg.computer_group_id:
        item("quota", "warning", f"Any domain user can join up to {cfg.machine_account_quota} computers to the domain "
                                 "(ms-DS-MachineAccountQuota), and each gets a computer certificate. Set the quota to 0, or "
                                 "limit autoenrollment to a computer group.")
    return out


def _status(s: Session, tenant: m.Tenant, cfg: m.AutoenrollConfig) -> dict:
    host = console_host()
    group = s.get(m.DirectoryGroup, cfg.computer_group_id) if cfg.computer_group_id else None
    readiness = _readiness(s, tenant, cfg, host)
    tpls = svc.templates(s, tenant.id)
    computers = s.scalar(select(func.count()).select_from(m.Identity).where(
        m.Identity.tenant_id == tenant.id, m.Identity.kind == "computer", m.Identity.account_state != "deleted")) or 0
    certs = s.scalar(select(func.count()).select_from(m.Certificate).where(
        m.Certificate.tenant_id == tenant.id, m.Certificate.enrollment_source == "gpo", m.Certificate.status == "active",
        m.Certificate.not_after > datetime.now(UTC))) or 0
    events = s.scalars(select(m.AutoenrollEvent).where(m.AutoenrollEvent.tenant_id == tenant.id)
                       .order_by(m.AutoenrollEvent.id.desc()).limit(25)).all()
    return {
        "config": {"enabled": cfg.enabled, "computers": cfg.computers, "users": cfg.users,
                   "computer_group": {"id": str(group.id), "name": group.name} if group else None,
                   "require_channel_binding": cfg.require_channel_binding, "response_format": cfg.response_format,
                   "service_account": cfg.service_account, "policy_id": cfg.policy_id,
                   "keytab": ({**(cfg.keytab_info or {}), "uploaded_at": cfg.keytab_uploaded_at.isoformat() if cfg.keytab_uploaded_at else None}
                              if cfg.keytab_ct else None),
                   "keytab_test": cfg.keytab_test or None, "machine_account_quota": cfg.machine_account_quota,
                   "last_success_at": cfg.last_success_at.isoformat() if cfg.last_success_at else None,
                   "last_error_at": cfg.last_error_at.isoformat() if cfg.last_error_at else None, "last_error": cfg.last_error},
        "host": host, "realm": svc.realm(s, tenant.id),
        "urls": {"policy": f"{_base_url()}/cep/{tenant.slug}", "enrollment": f"{_base_url()}/ces/{tenant.slug}"},
        "templates": [_template_out(tpls[k]) for k in svc.KINDS if k in tpls],
        "readiness": readiness, "ready": not any(i["level"] == "error" for i in readiness),
        "counts": {"computers": computers, "certificates": certs},
        "events": [_event_out(e) for e in events],
    }


@router.get("")
def get_status(ctx: TenantCtx = Depends(require("directory:read"))) -> dict:
    cfg = svc.ensure_config(ctx.session, ctx.id)
    ctx.session.commit()
    return _status(ctx.session, ctx.tenant, cfg)


class SettingsIn(BaseModel):
    enabled: bool
    computers: bool = True
    users: bool = False
    computer_group_id: uuid.UUID | None = None
    require_channel_binding: bool = True
    response_format: str = Field(default="unsigned", pattern="^(unsigned|signed|pkcs7)$")
    computer_validity_days: int | None = Field(default=None, ge=30, le=825)
    computer_renew_before_days: int | None = Field(default=None, ge=7, le=600)
    user_validity_days: int | None = Field(default=None, ge=30, le=825)
    user_renew_before_days: int | None = Field(default=None, ge=7, le=600)


@router.put("")
def update_settings(body: SettingsIn, ctx: TenantCtx = Depends(require("directory:write"))) -> dict:
    s = ctx.session
    cfg = svc.ensure_config(s, ctx.id)
    if body.computer_group_id:
        g = s.get(m.DirectoryGroup, body.computer_group_id)
        if g is None or g.tenant_id != ctx.id or g.deleted:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "That group isn't one of this tenant's directory groups.")
    if body.enabled:
        try:
            pki.issuing_ca(s, ctx.id)
        except pki.PkiError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Set up the certificate authority before turning on autoenrollment.") from None
        if s.get(m.DirectoryConfig, ctx.id) is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Connect Active Directory before turning on autoenrollment.")

    before = {"enabled": cfg.enabled, "computers": cfg.computers, "users": cfg.users, "computer_group_id": str(cfg.computer_group_id or ""),
              "require_channel_binding": cfg.require_channel_binding, "response_format": cfg.response_format}
    cfg.enabled, cfg.computers, cfg.users = body.enabled, body.computers, body.users
    cfg.computer_group_id, cfg.require_channel_binding, cfg.response_format = body.computer_group_id, body.require_channel_binding, body.response_format
    cfg.updated_at = datetime.now(UTC)
    changes = {k: v for k, v in {"enabled": cfg.enabled, "computers": cfg.computers, "users": cfg.users,
                                  "computer_group_id": str(cfg.computer_group_id or ""), "require_channel_binding": cfg.require_channel_binding,
                                  "response_format": cfg.response_format}.items() if before[k] != v}

    tpls = svc.templates(s, ctx.id)
    validity = {"computer": (body.computer_validity_days, body.computer_renew_before_days),
                "user": (body.user_validity_days, body.user_renew_before_days)}
    _tenants.pop(ctx.tenant.slug, None)
    if body.enabled:  # off needs nothing from OpenBao (it may be why it's being turned off); on rewrites every role
        bao = OpenBao()
        tpls = svc.ensure_templates(s, bao, ctx.tenant, cfg)
        for kind, (days, renew) in validity.items():
            tpl = tpls[kind]
            days, renew = days or tpl.validity_days, renew or tpl.renew_before_days
            if renew * 4 > days * 3:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, f"The {kind} certificate's renewal period ({renew} days) can be at most "
                                                                 f"three quarters of its validity ({days} days).")
            if (days, renew) != (tpl.validity_days, tpl.renew_before_days):
                changes[f"{kind}_validity"] = f"{tpl.validity_days}/{tpl.renew_before_days} → {days}/{renew} days"
                tpl.validity_days, tpl.renew_before_days = days, renew
                tpl.revision_minor += 1  # PCs pick up the new renewal period at their next policy refresh
                pki.write_autoenroll_role(bao, ctx.id, tpl)
    elif any((days or tpls[kind].validity_days, renew or tpls[kind].renew_before_days)
             != (tpls[kind].validity_days, tpls[kind].renew_before_days) if kind in tpls else (days, renew) != (None, None)
             for kind, (days, renew) in validity.items()):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Turn on autoenrollment before changing certificate validity.")
    if changes:
        audit.record(s, ctx.actor, "autoenroll.updated", tenant_id=ctx.id, target_type="autoenroll", target_label=ctx.tenant.slug,
                     detail=changes)
    s.commit()
    return _status(s, ctx.tenant, cfg)


class ReenrollIn(BaseModel):
    kind: str = Field(pattern="^(computer|user)$")


@router.post("/reenroll")
def reenroll(body: ReenrollIn, ctx: TenantCtx = Depends(require("directory:write"))) -> dict:
    """Like AD CS's Reenroll All Certificate Holders: a new major revision, so every PC enrolls again at its next refresh."""
    s = ctx.session
    cfg = svc.ensure_config(s, ctx.id)
    tpl = svc.templates(s, ctx.id).get(body.kind)
    if tpl is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Turn on autoenrollment first.")
    tpl.revision_major += 1
    tpl.revision_minor = 0
    audit.record(s, ctx.actor, "autoenroll.reenroll", tenant_id=ctx.id, target_type="template", target_id=tpl.id, target_label=tpl.name,
                 detail={"revision": f"{tpl.revision_major}.0"})
    s.commit()
    return _status(s, ctx.tenant, cfg)


class KeytabIn(BaseModel):
    keytab_b64: str = Field(min_length=8, max_length=200_000)


@router.put("/keytab")
def upload_keytab(body: KeytabIn, ctx: TenantCtx = Depends(require("directory:write"))) -> dict:
    s = ctx.session
    cfg = svc.ensure_config(s, ctx.id)
    try:
        data = base64.b64decode("".join(body.keytab_b64.split()), validate=True)
        entries = kerberos.parse_keytab(data)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"That file can't be used: {exc}") from None
    host = console_host()
    problem = kerberos.upload_problem(entries)
    if problem:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, problem)
    summary = kerberos.summarize(entries, host)
    if summary["principal"] is None and not any(e.principal.lower() == f"http/{host}" for e in entries):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, " ".join(summary["problems"]) or f"It has no key for HTTP/{host}.")
    want = svc.realm(s, ctx.id)
    if want and summary.get("realm") and summary["realm"].upper() != want:
        summary["problems"].append(f"It's for realm {summary['realm']}, but the directory is {want}.")
    data = kerberos.for_host(data, host)  # only EasyEAP's own keys are kept
    now = datetime.now(UTC)
    _forget_keytab(ctx.id, cfg)
    cfg.keytab_ct = crypto.encrypt(ctx.id, data)
    cfg.keytab_info = {**summary, "entries": len(kerberos.parse_keytab(data)), "sha256": hashlib.sha256(data).hexdigest()[:16]}
    cfg.keytab_uploaded_at, cfg.keytab_test, cfg.updated_at = now, {}, now
    audit.record(s, ctx.actor, "autoenroll.keytab_uploaded", tenant_id=ctx.id, target_type="autoenroll", target_label=summary.get("principal") or host,
                 detail={"kvno": summary.get("kvno"), "enctypes": summary.get("enctypes"), "problems": summary["problems"]})
    s.commit()
    return _status(s, ctx.tenant, cfg)


@router.delete("/keytab")
def delete_keytab(ctx: TenantCtx = Depends(require("directory:write"))) -> dict:
    s = ctx.session
    cfg = svc.ensure_config(s, ctx.id)
    _forget_keytab(ctx.id, cfg)
    cfg.keytab_ct, cfg.keytab_info, cfg.keytab_uploaded_at, cfg.keytab_test = None, {}, None, {}
    audit.record(s, ctx.actor, "autoenroll.keytab_removed", tenant_id=ctx.id, target_type="autoenroll", target_label=ctx.tenant.slug)
    s.commit()
    return _status(s, ctx.tenant, cfg)


@router.post("/keytab/test")
def test_keytab(ctx: TenantCtx = Depends(require("directory:write"))) -> dict:
    """Ask the domain controller for a ticket to HTTP/<host> with the directory's bind account and open it with the keytab."""
    s = ctx.session
    cfg = svc.ensure_config(s, ctx.id)
    if not cfg.keytab_ct:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Upload a keytab first.")
    if not limiter.hit(f"ae-test:{ctx.id}", 6):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Wait a minute before testing again.")
    d = s.get(m.DirectoryConfig, ctx.id)
    r = svc.realm(s, ctx.id)
    if d is None or not d.bind_password_ct or not r:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Connect Active Directory first: the test signs in with its bind account.")
    p = directory_params(d)
    try:
        conn = ldap.connect(p)
        try:
            user = ldap.bind_account_name(conn, p)
        finally:
            conn.unbind()
    except ldap.DirectoryError as exc:
        result = {"ok": False, "step": "directory", "message": f"EasyEAP couldn't reach Active Directory: {exc}"}
    else:
        if user:
            kdcs = [h.strip().split(":", 1)[0] for h in d.hosts if h.strip()]
            result = keytab_test.run(realm=r, kdcs=kdcs, user=user, password=p.bind_password, host=console_host(),
                                     keytab=_keytab(ctx.id, cfg))
        else:
            result = {"ok": False, "step": "directory", "message": "EasyEAP couldn't work out the bind account's sAMAccountName."}
    result = {**result, "at": datetime.now(UTC).isoformat(),
              "uploaded_at": cfg.keytab_uploaded_at.isoformat() if cfg.keytab_uploaded_at else ""}
    cfg.keytab_test = result
    s.commit()
    return _status(s, ctx.tenant, cfg)


def windows_script(*, host: str, realm: str, account: str, tenant: str) -> str:
    return f"""# EasyEAP: the Kerberos service account for Group Policy certificate autoenrollment ({tenant}).
#
# Run on a domain controller, or a PC with the RSAT Active Directory tools, as a Domain Admin:
#   powershell -ExecutionPolicy Bypass -File .\\easyeap-service-account.ps1
# It creates the account {account}, registers HTTP/{host} on it, and writes easyeap-cep.keytab next to this
# script. Upload that file in EasyEAP (Group Policy -> Autoenrollment -> Keytab), then delete it.
# Running it again sets a new password: upload the new keytab afterwards.
#Requires -Modules ActiveDirectory
$ErrorActionPreference = "Stop"
$Account = "{account}"
$ServiceHost = "{host}"
$Realm = "{realm}"
$Spn = "HTTP/$ServiceHost"
$Out = Join-Path $PSScriptRoot "easyeap-cep.keytab"

$Domain = Get-ADDomain
if ($Domain.DNSRoot.ToUpper() -ne $Realm) {{
    throw "This is domain $($Domain.DNSRoot.ToUpper()), but EasyEAP's directory is $Realm. Run the script in that domain."
}}
# An SPN must be on exactly one account in the forest, or Kerberos fails for it.
$Gc = (Get-ADDomainController -Discover -Service GlobalCatalog).HostName[0] + ":3268"
$Owner = Get-ADObject -Server $Gc -LDAPFilter "(servicePrincipalName=$Spn)" -Properties sAMAccountName
if ($Owner -and $Owner.sAMAccountName -ne $Account) {{
    throw "$Spn is registered to $($Owner.sAMAccountName). Remove it there (setspn -D $Spn $($Owner.sAMAccountName)) and run this again."
}}

$Bytes = New-Object byte[] 30
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($Bytes)
$Password = [Convert]::ToBase64String($Bytes) + "-Aa1"
$Secure = ConvertTo-SecureString $Password -AsPlainText -Force

if (-not (Get-ADUser -Filter "sAMAccountName -eq '$Account'")) {{
    New-ADUser -Name $Account -SamAccountName $Account -AccountPassword $Secure -Enabled $true -PasswordNeverExpires $true `
        -CannotChangePassword $true -AccountNotDelegated $true -KerberosEncryptionType AES128,AES256 `
        -Description "EasyEAP certificate enrollment (Kerberos service). Not for signing in."
    Write-Host "Created $Account."
}} else {{
    Set-ADUser $Account -KerberosEncryptionType AES128,AES256 -AccountNotDelegated $true
}}

# ktpass sets the password, maps HTTP/{host} to the account and writes the AES-256 key.
& ktpass.exe -princ "$Spn@$Realm" -mapuser "$($Domain.NetBIOSName)\\$Account" -mapop set -crypto AES256-SHA1 `
    -ptype KRB5_NT_PRINCIPAL -pass $Password -out $Out | Out-Null
if ($LASTEXITCODE -ne 0) {{ throw "ktpass failed (exit code $LASTEXITCODE)." }}
Remove-Variable Password, Secure
Write-Host ""
Write-Host "Done. Upload $Out in EasyEAP (Group Policy -> Autoenrollment -> Keytab), then delete the file."
"""


def samba_script(*, host: str, realm: str, account: str, tenant: str) -> str:
    return f"""#!/bin/sh
# EasyEAP: the Kerberos service account for Group Policy certificate autoenrollment ({tenant}), Samba AD.
# Run as root on a Samba AD domain controller of {realm}. It creates {account}, registers HTTP/{host} on it,
# and writes easyeap-cep.keytab here. Upload that file in EasyEAP (Group Policy -> Autoenrollment -> Keytab),
# then delete it.
set -eu
ACCOUNT='{account}'
SPN='HTTP/{host}'
if ! samba-tool user show "$ACCOUNT" >/dev/null 2>&1; then
    samba-tool user add "$ACCOUNT" --random-password --description="EasyEAP certificate enrollment (Kerberos service)"
    samba-tool user setexpiry "$ACCOUNT" --noexpiry
fi
if ! samba-tool spn list "$ACCOUNT" | grep -qi "^[[:space:]]*$SPN\\$"; then
    samba-tool spn add "$SPN" "$ACCOUNT"
fi
# AES only (msDS-SupportedEncryptionTypes 24): without it Samba gives a user account's SPN RC4 tickets and exports only
# its RC4 key, which EasyEAP refuses.
DN=$(samba-tool user show "$ACCOUNT" | sed -n 's/^dn: //p' | head -n 1)
PRIVATE=$(samba -b 2>/dev/null | sed -n 's/^[[:space:]]*PRIVATE_DIR:[[:space:]]*//p' | head -n 1)
ldbmodify -H "${{PRIVATE:-/var/lib/samba/private}}/sam.ldb" >/dev/null <<EOF
dn: $DN
changetype: modify
replace: msDS-SupportedEncryptionTypes
msDS-SupportedEncryptionTypes: 24
EOF
rm -f easyeap-cep.keytab
samba-tool domain exportkeytab easyeap-cep.keytab --principal="$SPN"
chmod 600 easyeap-cep.keytab
echo "Done. Upload $(pwd)/easyeap-cep.keytab in EasyEAP (Group Policy -> Autoenrollment -> Keytab), then delete it."
"""


_REALM = re.compile(r"^[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?)+$")
_ACCOUNT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$")


@router.get("/script")
def service_account_script(flavor: str = Query("windows", pattern="^(windows|samba)$"),
                           ctx: TenantCtx = Depends(require("directory:read"))) -> dict:
    """The script that makes the service account, its SPN and the keytab. Everything put into it is checked or
    reduced to characters that can't end a string or a comment in PowerShell or sh."""
    cfg = svc.ensure_config(ctx.session, ctx.id)
    ctx.session.commit()
    host, realm = console_host(), svc.realm(ctx.session, ctx.id) or ""
    if _host_problem(host):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, _host_problem(host))
    if not _REALM.match(realm):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Connect Active Directory first: the script needs the domain's DNS name.")
    if not _ACCOUNT.match(cfg.service_account):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The service account name isn't valid.")
    args = {"host": host, "realm": realm, "account": cfg.service_account, "tenant": re.sub(r"[^\w .,()&+-]", " ", ctx.tenant.name)}
    if flavor == "samba":
        return {"filename": "easyeap-service-account.sh", "content": samba_script(**args)}
    return {"filename": "easyeap-service-account.ps1", "content": windows_script(**args).replace("\n", "\r\n")}


@router.get("/events")
def list_events(ctx: TenantCtx = Depends(require("directory:read")), outcome: str = Query("", pattern="^(|ok|denied|error)$"),
                before: int | None = None, limit: int = Query(100, ge=1, le=500)) -> dict:
    q = select(m.AutoenrollEvent).where(m.AutoenrollEvent.tenant_id == ctx.id)
    if outcome:
        q = q.where(m.AutoenrollEvent.outcome == outcome)
    if before:
        q = q.where(m.AutoenrollEvent.id < before)
    rows = ctx.session.scalars(q.order_by(m.AutoenrollEvent.id.desc()).limit(limit)).all()
    return {"events": [_event_out(e) for e in rows], "more": len(rows) == limit}
