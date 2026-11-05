"""Ingestion of authentication events and accounting records shipped by the radius-agent."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app import models as m
from app.pki.crypto import normalize_serial
from app.radius.explain import classify


def _ts(v: Any) -> datetime:
    try:
        return datetime.fromtimestamp(float(v), UTC)
    except (TypeError, ValueError):
        return datetime.now(UTC)


def _clean(v: Any, n: int) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s[:n] if s and s not in ("-", "(null)") else None


def ingest_auth(session: Session, events: list[dict[str, Any]]) -> int:
    """Platform-scoped: events arrive tagged with their tenant by the tenant's virtual server."""
    tenants = {str(t) for t in session.scalars(select(m.Tenant.id))}
    clients_by_tenant: dict[str, list[m.RadiusClient]] = {}
    stored = 0
    for e in events:
        tid = str(e.get("tenant") or "")
        if tid not in tenants or not e.get("uid"):
            continue
        tenant_id = uuid.UUID(tid)
        serial = normalize_serial(e["serial"]) if _clean(e.get("serial"), 64) else None
        cert = session.scalars(select(m.Certificate).where(m.Certificate.tenant_id == tenant_id, m.Certificate.serial == serial)).first() if serial else None
        result = "accept" if e.get("result") == "accept" else "reject"
        reason = _clean(e.get("reason"), 32)
        message = _clean(e.get("message"), 2000)
        if result == "reject" and not reason:
            reason = classify(message) or "tls_handshake"
        nas_ip = _clean(e.get("nas_ip"), 64)
        if tid not in clients_by_tenant:
            clients_by_tenant[tid] = list(session.scalars(select(m.RadiusClient).where(m.RadiusClient.tenant_id == tenant_id)))
        nas = _match_client(clients_by_tenant[tid], nas_ip)
        vlan = _clean(e.get("vlan"), 8)
        rule = _clean(e.get("rule"), 36)
        at = _ts(e.get("ts"))
        stmt = insert(m.AuthEvent).values(
            tenant_id=tenant_id, event_uid=str(e["uid"])[:64], at=at, result=result, reason_code=reason if result == "reject" else None,
            username=_clean(e.get("user"), 256), identity_id=cert.identity_id if cert else None, device_id=cert.device_id if cert else None,
            cert_serial=serial, cert_issuer=_clean(e.get("issuer"), 300), calling_station_id=_clean(e.get("mac"), 64),
            called_station_id=_clean(e.get("called"), 128), nas_ip=nas_ip, nas_client_id=nas.id if nas else None,
            ssid=_ssid(_clean(e.get("called"), 128)), vlan_id=int(vlan) if vlan and vlan.isdigit() else None,
            rule_id=uuid.UUID(rule) if rule and _is_uuid(rule) else None, raw_message=message,
        ).on_conflict_do_nothing(index_elements=["event_uid"])
        if session.execute(stmt).rowcount:
            stored += 1
            if nas:
                nas.last_request_at = max(nas.last_request_at or at, at)
            if cert and cert.identity_id and result == "accept":
                ident = session.get(m.Identity, cert.identity_id)
                if ident:
                    ident.last_auth_at = max(ident.last_auth_at or at, at)
    return stored


def ingest_accounting(session: Session, records: list[dict[str, Any]]) -> int:
    tenants = {str(t) for t in session.scalars(select(m.Tenant.id))}
    n = 0
    for r in records:
        tid = str(r.get("tenant") or "")
        sid = _clean(r.get("session_id"), 128)
        nas_ip = _clean(r.get("nas_ip"), 64)
        if tid not in tenants or not sid or not nas_ip:
            continue
        tenant_id = uuid.UUID(tid)
        status = (r.get("status") or "").lower()
        at = _ts(r.get("ts"))
        row = session.scalars(select(m.AccountingSession).where(m.AccountingSession.tenant_id == tenant_id, m.AccountingSession.nas_ip == nas_ip,
                                                                 m.AccountingSession.acct_session_id == sid)).first()
        if row is None:
            row = m.AccountingSession(tenant_id=tenant_id, acct_session_id=sid, nas_ip=nas_ip, started_at=at)
            session.add(row)
        row.username = _clean(r.get("user"), 256) or row.username
        row.calling_station_id = _clean(r.get("mac"), 64) or row.calling_station_id
        row.called_station_id = _clean(r.get("called"), 128) or row.called_station_id
        row.framed_ip = _clean(r.get("framed_ip"), 64) or row.framed_ip
        vlan = _clean(r.get("vlan"), 8)
        if vlan and vlan.isdigit():
            row.vlan_id = int(vlan)
        row.input_octets = int(r.get("in_octets") or row.input_octets or 0)
        row.output_octets = int(r.get("out_octets") or row.output_octets or 0)
        row.updated_at = at
        if status == "stop":
            row.stopped_at = at
            row.terminate_cause = _clean(r.get("cause"), 64)
        n += 1
    return n


def _match_client(clients: list[m.RadiusClient], ip: str | None) -> m.RadiusClient | None:
    if not ip:
        return None
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for c in clients:
        try:
            if addr in ipaddress.ip_network(c.address, strict=False):
                return c
        except ValueError:
            continue
    return None


def _ssid(called: str | None) -> str | None:
    # Called-Station-Id is usually "AA-BB-CC-DD-EE-FF:SSID"
    if called and ":" in called:
        tail = called.rsplit(":", 1)[-1]
        if len(tail) > 2 and not all(c in "0123456789abcdefABCDEF-" for c in tail):
            return tail[:64]
    return None


def _is_uuid(s: str) -> bool:
    try:
        uuid.UUID(s)
        return True
    except ValueError:
        return False
