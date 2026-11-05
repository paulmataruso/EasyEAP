"""Desired RADIUS state served to the radius-agent, and RADIUS server-certificate management."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import models as m
from app.pki import crypto
from app.pki import service as pki
from app.pki.openbao import OpenBao

DEFAULT_PORTS = (1812, 1813)
log = logging.getLogger("easyeap.radius")


class RadiusConfigError(ValueError):
    pass


def parse_address(address: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        net = ipaddress.ip_network(address.strip(), strict=False)
    except ValueError as exc:
        raise RadiusConfigError("Enter an IP address or CIDR range, for example 10.20.0.5 or 10.20.0.0/28.") from exc
    if net.num_addresses > 65_536:
        raise RadiusConfigError("The address range is too broad. Use /16 or narrower so each controller is identifiable.")
    return net


def check_address_unique(session: Session, tenant_id: uuid.UUID, address: str, exclude_id: uuid.UUID | None = None) -> None:
    """Controller source addresses must not overlap across tenants that share the RADIUS ports (platform-scoped query)."""
    net = parse_address(address)
    mine = session.get(m.RadiusSettings, tenant_id)
    my_ports = (mine.auth_port, mine.acct_port) if mine and mine.dedicated_ports else DEFAULT_PORTS
    for c, rs in session.execute(select(m.RadiusClient, m.RadiusSettings).outerjoin(m.RadiusSettings, m.RadiusSettings.tenant_id == m.RadiusClient.tenant_id)):
        if exclude_id and c.id == exclude_id:
            continue
        ports = (rs.auth_port, rs.acct_port) if rs and rs.dedicated_ports else DEFAULT_PORTS
        if ports != my_ports:
            continue
        if parse_address(c.address).overlaps(net):
            if c.tenant_id == tenant_id:
                raise RadiusConfigError(f"This address overlaps the existing controller “{c.name}”.")
            raise RadiusConfigError("This address overlaps a controller that belongs to another tenant on the same RADIUS ports. "
                                    "Give this tenant dedicated RADIUS ports (RADIUS settings → Advanced) or use a unique source address.")


def ensure_server_certificate(session: Session, bao: OpenBao, tenant: m.Tenant, hostname: str) -> m.Certificate:
    rs = session.get(m.RadiusSettings, tenant.id)
    if rs is None:
        raise RadiusConfigError("Save the RADIUS settings before issuing a server certificate.")
    tpl = session.scalars(select(m.CertificateTemplate).where(m.CertificateTemplate.tenant_id == tenant.id, m.CertificateTemplate.purpose == "radius-server")).first()
    if tpl is None:
        raise RadiusConfigError("The RADIUS server certificate template is missing. Initialize the tenant PKI first.")
    cert, key_pem = pki.issue_with_server_key(session, bao, tenant, tpl, {"server": hostname}, identity_id=None, device_id=None)
    rs.server_key_ct = crypto.encrypt(tenant.id, key_pem, bao)
    del key_pem
    old = session.get(m.Certificate, rs.server_certificate_id) if rs.server_certificate_id else None
    rs.server_certificate_id = cert.id
    rs.server_hostname = hostname
    rs.config_version += 1
    if old is not None and old.id != cert.id:
        old.status = "superseded"  # kept valid until expiry so roaming devices finish; not revoked
    return cert


def bump(session: Session, tenant_id: uuid.UUID) -> None:
    rs = session.get(m.RadiusSettings, tenant_id)
    if rs:
        rs.config_version += 1


def desired_state(session: Session, bao: OpenBao) -> dict:
    """Platform-scoped. Includes decrypted shared secrets and server keys: served only to the authenticated agent."""
    tenants = []
    for t in session.scalars(select(m.Tenant).where(m.Tenant.status == "active")):
        rs = session.get(m.RadiusSettings, t.id)
        if rs is None or rs.server_certificate_id is None or rs.server_key_ct is None:
            continue
        server_cert = session.get(m.Certificate, rs.server_certificate_id)
        try:
            issuing, root = pki.chain_pem(session, t.id)
            crl = pki.crl_pem(bao, t.id)
        except Exception as exc:  # noqa: BLE001 — a tenant with broken PKI is skipped, never served half-configured
            log.warning("tenant %s omitted from RADIUS config: PKI unavailable (%s)", t.id, type(exc).__name__)
            continue
        root_ca = pki.root_ca(session, t.id)
        clients = [{
            "id": str(c.id), "name": c.name, "vendor": c.vendor, "address": c.address,
            "secret": crypto.decrypt_str(t.id, c.secret_ct, bao), "coa": c.coa_enabled, "coa_port": c.coa_port,
        } for c in session.scalars(select(m.RadiusClient).where(m.RadiusClient.tenant_id == t.id))]
        tenants.append({
            "id": str(t.id), "slug": t.slug, "name": t.name,
            "auth_port": rs.auth_port if rs.dedicated_ports else DEFAULT_PORTS[0],
            "acct_port": rs.acct_port if rs.dedicated_ports else DEFAULT_PORTS[1],
            "dedicated_ports": rs.dedicated_ports, "tls_min_version": rs.tls_min_version,
            "tls_session_cache": rs.tls_session_cache, "session_timeout": rs.session_timeout_seconds,
            "server_cert_pem": server_cert.certificate_pem if server_cert else "",
            "server_key_pem": crypto.decrypt_str(t.id, rs.server_key_ct, bao),
            "ca_pem": issuing + (root or ""), "crl_pem": "\n".join(x.strip() for x in (crl, root_ca.crl_pem if root_ca else None) if x and x.strip()) + "\n",
            "clients": clients, "config_version": rs.config_version, "snapshot_version": rs.snapshot_version,
        })
    # Content digest: the agent re-renders FreeRADIUS only when something it uses changed (clients, certs, CRL).
    version = hashlib.sha256(json.dumps([{k: v for k, v in t.items() if k != "snapshot_version"} for t in tenants], sort_keys=True).encode()).hexdigest()[:24]
    return {"generated_at": datetime.now(UTC).isoformat(), "version": version, "tenants": tenants}
