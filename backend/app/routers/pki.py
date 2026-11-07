"""Tenant PKI: ceremony, CA details, templates, CRL."""
from __future__ import annotations

import base64
import uuid

from cryptography import x509
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from app import audit
from app import models as m
from app.config import get_settings
from app.deps import TenantCtx, require
from app.pki import service as pki
from app.pki.openbao import OpenBao

router = APIRouter(prefix="/api/tenants/{tenant_id}/pki", tags=["pki"])


def ca_out(ca: m.CertificateAuthority) -> dict:
    return {"id": str(ca.id), "role": ca.role, "common_name": ca.common_name, "subject": ca.subject, "key_algorithm": ca.key_algorithm,
            "serial": ca.serial, "fingerprint_sha256": ca.fingerprint_sha256, "not_before": ca.not_before.isoformat(),
            "not_after": ca.not_after.isoformat(), "offline": ca.offline, "status": ca.status,
            "crl_next_update": ca.crl_next_update.isoformat() if ca.crl_next_update else None}


def template_out(t: m.CertificateTemplate) -> dict:
    return {"id": str(t.id), "name": t.name, "purpose": t.purpose, "key_algorithm": t.key_algorithm, "validity_days": t.validity_days,
            "renew_before_days": t.renew_before_days, "extended_key_usage": t.extended_key_usage, "subject_pattern": t.subject_pattern,
            "san_patterns": t.san_patterns, "allow_client_keygen": t.allow_client_keygen, "allow_server_keygen": t.allow_server_keygen,
            # Group Policy autoenrollment's templates: edited under RADIUS → Windows Group Policy, not here.
            "autoenroll_kind": t.autoenroll_kind, "template_oid": t.template_oid,
            "revision": f"{t.revision_major}.{t.revision_minor}" if t.autoenroll_kind else None}


@router.get("")
def overview(ctx: TenantCtx = Depends(require("certificates:read"))) -> dict:
    s = ctx.session
    cas = s.scalars(select(m.CertificateAuthority).where(m.CertificateAuthority.tenant_id == ctx.id).order_by(m.CertificateAuthority.role.desc())).all()
    tpls = s.scalars(select(m.CertificateTemplate).where(m.CertificateTemplate.tenant_id == ctx.id).order_by(m.CertificateTemplate.name)).all()
    return {"initialized": any(c.role == "issuing" for c in cas), "authorities": [ca_out(c) for c in cas], "templates": [template_out(t) for t in tpls],
            "urls": pki.pki_urls(ctx.id), "lab_mode": get_settings().lab_mode,
            "crl": _issuing_crl(ctx.id) if any(c.role == "issuing" for c in cas) else None}


def _issuing_crl(tenant_id: uuid.UUID) -> dict:
    """The issuing CA's current CRL as OpenBao publishes it: when it was built, when it must be rebuilt, how many entries."""
    try:
        crl = x509.load_pem_x509_crl(pki.crl_pem(OpenBao(), tenant_id).encode())
    except Exception:  # noqa: BLE001 — the CA page must render even if OpenBao is briefly unreachable
        return {"available": False, "this_update": None, "next_update": None, "revoked_count": None}
    return {"available": True, "this_update": crl.last_update_utc.isoformat(),
            "next_update": crl.next_update_utc.isoformat() if crl.next_update_utc else None, "revoked_count": len(crl)}


class CeremonyIn(BaseModel):
    organization: str = Field(min_length=2, max_length=64)
    country: str = Field(default="", max_length=2)
    state: str = Field(default="", max_length=64)
    locality: str = Field(default="", max_length=64)
    root_common_name: str = Field(min_length=3, max_length=64)
    issuing_common_name: str = Field(min_length=3, max_length=64)
    key_algorithm: str = "ecdsa-p384"
    root_validity_years: int = Field(default=20, ge=5, le=30)
    issuing_validity_years: int = Field(default=8, ge=1, le=15)
    root_passphrase: str | None = Field(default=None, max_length=256)
    keep_root_online: bool = False


@router.post("/initialize")
def initialize(body: CeremonyIn, ctx: TenantCtx = Depends(require("ca:manage"))) -> dict:
    req = pki.CeremonyRequest(**body.model_dump())
    result = pki.run_ceremony(ctx.session, OpenBao(), ctx.tenant, req)
    audit.record(ctx.session, ctx.actor, "pki.initialized", tenant_id=ctx.id, target_type="ca", target_id=result.issuing.id,
                 target_label=result.issuing.common_name,
                 detail={"root": result.root.common_name, "key_algorithm": body.key_algorithm, "root_offline": not body.keep_root_online,
                         "root_fingerprint": result.root.fingerprint_sha256})
    out = {"root": ca_out(result.root), "issuing": ca_out(result.issuing)}
    if result.encrypted_root_key_pem:
        # Returned exactly once. EasyEAP keeps no copy: the online root key was destroyed with the ceremony mount.
        out["root_key_file"] = {"filename": f"{ctx.tenant.slug}-root-ca.key.pem", "content_b64": base64.b64encode(result.encrypted_root_key_pem).decode()}
        out["root_cert_file"] = {"filename": f"{ctx.tenant.slug}-root-ca.crt.pem", "content_b64": base64.b64encode(result.root.certificate_pem.encode()).decode()}
    return out


@router.get("/chain.pem", response_class=PlainTextResponse)
def chain(ctx: TenantCtx = Depends(require("certificates:read"))) -> str:
    issuing, root = pki.chain_pem(ctx.session, ctx.id)
    return issuing + (root or "")


@router.post("/crl/rotate")
def rotate(ctx: TenantCtx = Depends(require("ca:manage"))) -> dict:
    pki.rotate_crl(OpenBao(), ctx.id, ctx.session)
    from app.radius.state import bump
    bump(ctx.session, ctx.id)
    audit.record(ctx.session, ctx.actor, "pki.crl_rotated", tenant_id=ctx.id, target_type="ca")
    return {"ok": True}


class TemplateIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    purpose: str = Field(pattern="^(user|device)$")
    key_algorithm: str = Field(default="ecdsa-p256", pattern="^(ecdsa-p256|ecdsa-p384|rsa-2048|rsa-3072|rsa-4096)$")
    validity_days: int = Field(default=365, ge=1, le=825)
    renew_before_days: int = Field(default=30, ge=1, le=180)
    subject_pattern: str = Field(default="CN={upn}", max_length=200)
    san_patterns: list[str] = ["upn:{upn}", "email:{email}"]
    allow_client_keygen: bool = True
    allow_server_keygen: bool = False


def _check_patterns(body: TemplateIn) -> None:
    allowed = {"upn", "username", "email", "display_name", "device", "domain", "tenant"}
    import re
    for p in [body.subject_pattern, *body.san_patterns]:
        for f in re.findall(r"\{(\w+)\}", p):
            if f not in allowed:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown field {{{f}}}. Use one of: {', '.join(sorted(allowed))}.")
    for p in body.san_patterns:
        if p.split(":", 1)[0] not in ("upn", "email", "dns"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "SAN patterns start with upn:, email: or dns:.")
    if not body.subject_pattern.startswith("CN="):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "The subject pattern must start with CN=.")


@router.post("/templates", status_code=201)
def create_template(body: TemplateIn, ctx: TenantCtx = Depends(require("templates:write"))) -> dict:
    _check_patterns(body)
    issuing = pki.issuing_ca(ctx.session, ctx.id)
    t = m.CertificateTemplate(tenant_id=ctx.id, extended_key_usage=["clientAuth"], key_usage=["digitalSignature"],
                              bao_role=f"tpl-{uuid.uuid4().hex[:12]}", **body.model_dump())
    ctx.session.add(t)
    ctx.session.flush()
    org = issuing.subject.split("O=", 1)[1].split(",", 1)[0] if "O=" in issuing.subject else ""
    pki.write_role(OpenBao(), ctx.id, t, organization=org)
    audit.record(ctx.session, ctx.actor, "template.created", tenant_id=ctx.id, target_type="template", target_id=t.id, target_label=t.name, detail=body.model_dump())
    return template_out(t)


@router.put("/templates/{template_id}")
def update_template(template_id: uuid.UUID, body: TemplateIn, ctx: TenantCtx = Depends(require("templates:write"))) -> dict:
    _check_patterns(body)
    t = ctx.session.get(m.CertificateTemplate, template_id)
    if t is None or t.tenant_id != ctx.id or t.purpose == "radius-server":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Template not found.")
    if t.autoenroll_kind:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This template belongs to Group Policy autoenrollment. Change its validity under "
                                                         "RADIUS → Windows Group Policy → Autoenrollment.")
    for k, v in body.model_dump().items():
        setattr(t, k, v)
    issuing = pki.issuing_ca(ctx.session, ctx.id)
    org = issuing.subject.split("O=", 1)[1].split(",", 1)[0] if "O=" in issuing.subject else ""
    pki.write_role(OpenBao(), ctx.id, t, organization=org)
    audit.record(ctx.session, ctx.actor, "template.updated", tenant_id=ctx.id, target_type="template", target_id=t.id, target_label=t.name, detail=body.model_dump())
    return template_out(t)
