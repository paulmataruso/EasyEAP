"""Unauthenticated PKI distribution: CA certificates, CRLs and OCSP (served over plain HTTP by the proxy, as RFC 5280
relying parties expect). Nothing secret is reachable here; CA signing keys never leave OpenBao."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app import models as m
from app.db import set_tenant
from app.deps import db
from app.pki import service as pki
from app.pki.openbao import OpenBao

router = APIRouter(prefix="/pki/{tenant_id}", tags=["pki-public"])


def _der_cert(pem: str) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    return x509.load_pem_x509_certificate(pem.encode()).public_bytes(Encoding.DER)


def _scope(s: Session, tenant_id: uuid.UUID) -> None:
    set_tenant(s, tenant_id)


@router.get("/ca.crt")
def issuing_cert(tenant_id: uuid.UUID, s: Session = Depends(db)) -> Response:
    _scope(s, tenant_id)
    try:
        ca = pki.issuing_ca(s, tenant_id)
    except pki.PkiError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found") from exc
    return Response(_der_cert(ca.certificate_pem), media_type="application/pkix-cert", headers={"Cache-Control": "public, max-age=3600"})


@router.get("/root.crt")
def root_cert(tenant_id: uuid.UUID, s: Session = Depends(db)) -> Response:
    _scope(s, tenant_id)
    ca = pki.root_ca(s, tenant_id)
    if ca is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    return Response(_der_cert(ca.certificate_pem), media_type="application/pkix-cert", headers={"Cache-Control": "public, max-age=86400"})


@router.get("/crl")
def crl(tenant_id: uuid.UUID, s: Session = Depends(db)) -> Response:
    _scope(s, tenant_id)
    if s.get(m.Tenant, tenant_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    try:
        data = pki.crl_der(OpenBao(), tenant_id)
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "CRL temporarily unavailable") from exc
    return Response(data, media_type="application/pkix-crl", headers={"Cache-Control": "public, max-age=300"})


@router.get("/root.crl")
def root_crl(tenant_id: uuid.UUID, s: Session = Depends(db)) -> Response:
    _scope(s, tenant_id)
    ca = pki.root_ca(s, tenant_id)
    if ca is None or not ca.crl_pem:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    der = x509.load_pem_x509_crl(ca.crl_pem.encode()).public_bytes(Encoding.DER)
    return Response(der, media_type="application/pkix-crl", headers={"Cache-Control": "public, max-age=3600"})


@router.post("/ocsp")
async def ocsp_post(tenant_id: uuid.UUID, request: Request) -> Response:
    body = await request.body()
    if len(body) > 10_000:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Request too large")
    r = OpenBao(token="").post_raw(f"{pki.tenant_mount(tenant_id)}/ocsp", body, "application/ocsp-request")
    return Response(r.content, status_code=r.status_code, media_type="application/ocsp-response")


@router.get("/ocsp/{encoded:path}")
def ocsp_get(tenant_id: uuid.UUID, encoded: str) -> Response:
    r = OpenBao(token="")._client.get(f"/v1/{pki.tenant_mount(tenant_id)}/ocsp/{encoded}")
    return Response(r.content, status_code=r.status_code, media_type="application/ocsp-response")
