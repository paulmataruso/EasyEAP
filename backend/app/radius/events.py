"""Ingestion of authentication events and accounting records shipped by the radius-agent."""
from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app import models as m
from app.mac import try_mac
from app.pki.crypto import normalize_serial
from app.radius import mab
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
        # Server-side monitor (docs/plans/cisco-platforms.md §4): the switch got an Accept so the device keeps working,
        # but EasyEAP refused it; it's logged as the refusal it will be once the switch is enforced.
        monitor = e.get("monitor") in ("yes", "accepted")
        if e.get("monitor") == "accepted":
            result = "reject"
        reason = _clean(e.get("reason"), 32)
        message = _clean(e.get("message"), 2000)
        if result == "reject" and not reason:
            reason = classify(message) or "tls_handshake"
        nas_ip = _clean(e.get("nas_ip"), 64)
        if tid not in clients_by_tenant:
            clients_by_tenant[tid] = list(session.scalars(select(m.RadiusClient).where(m.RadiusClient.tenant_id == tenant_id)))
        nas = attribute_client(clients_by_tenant[tid], _clean(e.get("src_ip"), 64), nas_ip)
        vlan = _clean(e.get("vlan"), 8)
        rule = _clean(e.get("rule"), 36)
        at = _ts(e.get("ts"))
        uid = str(e["uid"])[:64]
        mac = mab.event_mac(e)
        method = mab.method_of(e)
        mac_device = _clean(e.get("mac_device"), 36)
        if method:
            # MAC authentication: last seen, sightings, and coalescing of an unknown device's retries (§5.2). A resent
            # event (already stored) is skipped first so it isn't counted twice.
            if session.scalar(select(m.AuthEvent.id).where(m.AuthEvent.event_uid == uid)) is not None:
                continue
            port = _clean(e.get("port_id"), 64)
            if not mab.note_mab(session, tenant_id, mac=mac, client_id=nas.id if nas else None, port=port, result=result,
                                reason=reason, at=at, device_id=mac_device):
                continue
        stmt = insert(m.AuthEvent).values(
            tenant_id=tenant_id, event_uid=uid, at=at, result=result, reason_code=reason if result == "reject" else None,
            username=_clean(e.get("user"), 256), identity_id=cert.identity_id if cert else None, device_id=cert.device_id if cert else None,
            cert_serial=serial, cert_issuer=_clean(e.get("issuer"), 300), calling_station_id=_clean(e.get("mac"), 64),
            called_station_id=_clean(e.get("called"), 128), nas_ip=nas_ip, nas_client_id=nas.id if nas else None,
            ssid=_ssid(_clean(e.get("called"), 128)), vlan_id=int(vlan) if vlan and vlan.isdigit() else None,
            network=_network(e.get("network")), nas_port_id=_clean(e.get("port_id"), 64), monitor=monitor,
            rule_id=uuid.UUID(rule) if rule and _is_uuid(rule) else None, raw_message=message,
            mac=mac, method=method or ("eap-tls" if serial else None),
            mac_device_id=uuid.UUID(mac_device) if mac_device and _is_uuid(mac_device) else None,
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
    clients_by_tenant: dict[str, list[m.RadiusClient]] = {}
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
        if tid not in clients_by_tenant:
            clients_by_tenant[tid] = list(session.scalars(select(m.RadiusClient).where(m.RadiusClient.tenant_id == tenant_id)))
        nas = attribute_client(clients_by_tenant[tid], _clean(r.get("src_ip"), 64), nas_ip)
        if nas:
            row.nas_client_id = nas.id
            nas.last_request_at = max(nas.last_request_at or at, at)
        row.username = _clean(r.get("user"), 256) or row.username
        row.calling_station_id = _clean(r.get("mac"), 64) or row.calling_station_id
        row.mac = try_mac(row.calling_station_id) or row.mac
        row.called_station_id = _clean(r.get("called"), 128) or row.called_station_id
        row.framed_ip = _clean(r.get("framed_ip"), 64) or row.framed_ip
        row.network = _network(r.get("network")) or row.network
        row.nas_port_id = _clean(r.get("port_id"), 64) or row.nas_port_id
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


def _network(v: Any) -> str | None:
    return v if v in ("wireless", "wired") else None


def attribute_client(clients: list[m.RadiusClient], src_ip: str | None, nas_ip: str | None) -> m.RadiusClient | None:
    """The controller or switch a request came from: by the packet's source address (what FreeRADIUS matched the
    client on), then by the NAS-IP-Address it reported. The most specific registration wins, as in FreeRADIUS, so a
    switch registered inside a UniFi range is told apart. None when neither falls inside a registered range."""
    return _match_client(clients, src_ip) or _match_client(clients, nas_ip)


def _match_client(clients: list[m.RadiusClient], ip: str | None) -> m.RadiusClient | None:
    if not ip:
        return None
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    best: tuple[int, m.RadiusClient] | None = None
    for c in clients:
        try:
            net = ipaddress.ip_network(c.address, strict=False)
        except ValueError:
            continue
        if addr in net and (best is None or net.prefixlen > best[0]):
            best = (net.prefixlen, c)
    return best[1] if best else None


# "MAC:SSID", the same test FreeRADIUS uses to tell Wi-Fi from wired (services/radius/agent/render.py MAC_RE).
_CALLED_SSID = re.compile(r"^(?:[0-9A-Fa-f]{2}[-:.]?){5}[0-9A-Fa-f]{2}:(.+)$")


def _ssid(called: str | None) -> str | None:
    # Called-Station-Id is usually "AA-BB-CC-DD-EE-FF:SSID"
    mt = _CALLED_SSID.match(called or "")
    if mt:
        return mt.group(1)[:64]
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
