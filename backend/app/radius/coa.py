"""Change-of-Authorization: Disconnect-Requests after revocation or access changes.

EasyEAP queues requests; the radius-agent (which holds the shared secrets and sits next to the controllers) sends
them with radclient and reports the result. Only controllers with CoA enabled receive requests; for the others the
session lasts until the controller re-authenticates (Session-Timeout).
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import models as m


def disconnect_for_certificate(session: Session, cert: m.Certificate, reason: str) -> dict:
    """Queue Disconnect-Requests for live sessions that authenticated with this certificate."""
    since = datetime.now(UTC) - timedelta(days=2)
    macs = {e.calling_station_id for e in session.scalars(select(m.AuthEvent).where(
        m.AuthEvent.tenant_id == cert.tenant_id, m.AuthEvent.cert_serial == cert.serial, m.AuthEvent.result == "accept",
        m.AuthEvent.at >= since)) if e.calling_station_id}
    return _disconnect_macs(session, cert.tenant_id, macs, reason)


def disconnect_for_identity(session: Session, tenant_id: uuid.UUID, identity_id: uuid.UUID, reason: str) -> dict:
    since = datetime.now(UTC) - timedelta(days=2)
    macs = {e.calling_station_id for e in session.scalars(select(m.AuthEvent).where(
        m.AuthEvent.tenant_id == tenant_id, m.AuthEvent.identity_id == identity_id, m.AuthEvent.result == "accept",
        m.AuthEvent.at >= since)) if e.calling_station_id}
    return _disconnect_macs(session, tenant_id, macs, reason)


def _disconnect_macs(session: Session, tenant_id: uuid.UUID, macs: set[str], reason: str) -> dict:
    if not macs:
        return {"sessions": 0, "queued": 0, "without_coa": 0}
    sessions = session.scalars(select(m.AccountingSession).where(
        m.AccountingSession.tenant_id == tenant_id, m.AccountingSession.calling_station_id.in_(macs),
        m.AccountingSession.stopped_at.is_(None))).all()
    tenant_clients = list(session.scalars(select(m.RadiusClient).where(m.RadiusClient.tenant_id == tenant_id)))
    by_id = {c.id: c for c in tenant_clients}
    clients = {c.address: c for c in tenant_clients}
    queued = without = 0
    targets: list[tuple[m.RadiusClient | None, dict]] = []
    if sessions:
        for s in sessions:
            nas = by_id.get(s.nas_client_id) if s.nas_client_id else _client_for(clients, s.nas_ip)
            targets.append((nas, {"NAS-IP-Address": s.nas_ip, "Acct-Session-Id": s.acct_session_id,
                                  "Calling-Station-Id": s.calling_station_id or "", "User-Name": s.username or ""}))
    else:
        # No accounting from this controller: fall back to the most recent accepting NAS for each MAC.
        for mac in macs:
            ev = session.scalars(select(m.AuthEvent).where(m.AuthEvent.tenant_id == tenant_id, m.AuthEvent.calling_station_id == mac,
                                                           m.AuthEvent.result == "accept").order_by(m.AuthEvent.at.desc()).limit(1)).first()
            nas = session.get(m.RadiusClient, ev.nas_client_id) if ev and ev.nas_client_id else None
            targets.append((nas, {"NAS-IP-Address": ev.nas_ip if ev and ev.nas_ip else "", "Calling-Station-Id": mac,
                                  "User-Name": ev.username if ev and ev.username else ""}))
    for nas, attrs in targets:
        if nas is None or not nas.coa_enabled:
            without += 1
            continue
        session.add(m.CoaRequest(tenant_id=tenant_id, nas_client_id=nas.id, kind="disconnect", attributes={k: v for k, v in attrs.items() if v},
                                 reason=reason[:200], status="pending"))
        queued += 1
    return {"sessions": len(targets), "queued": queued, "without_coa": without}


def _client_for(clients: dict[str, m.RadiusClient], ip: str) -> m.RadiusClient | None:
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for address, c in clients.items():
        try:
            if addr in ipaddress.ip_network(address, strict=False):
                return c
        except ValueError:
            continue
    return None
