"""MAC authentication on switch ports (docs/plans/mac-auth.md): the MAC allow list's snapshot part, what ingest
records about MAC requests, and Change of Authorization for MAC devices.

The allow list has its own snapshot version (RadiusSettings.mac_version), bumped only by admin edits: certificate
recomputes never resend MAC entries, and last-seen updates at ingest never re-version anything. Expiry is checked by
RADIUS itself (the entry carries `expires_at`), so an entry expiring needs no new version.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app import models as m
from app.mac import try_mac
from app.policy.service import wired_vlan_map
from app.radius import cisco_platforms as cp

MAX_DEVICES = 20_000
MAX_GROUPS = 100
MAX_SIGHTINGS = 50_000
SIGHTING_RETENTION_DAYS = 90
# A device that isn't on the list retries every few minutes; one stored event per hour per (MAC, switch, port) is
# enough for the log, and the sighting counts the rest.
UNKNOWN_EVENT_EVERY = timedelta(hours=1)
MAB_METHODS = ("mab", "mab-eap")


def bump_mac(session: Session, tenant_id: uuid.UUID) -> None:
    rs = session.get(m.RadiusSettings, tenant_id)
    if rs is not None:
        # Milliseconds, like the certificate snapshot: strictly increasing and never reused after a restore.
        rs.mac_version = max(int(datetime.now(UTC).timestamp() * 1000), (rs.mac_version or 0) + 1)


def group_switch_vlan(group: m.DeviceGroup, vlans: dict[uuid.UUID, int], mapping: dict[int, int | None]) -> int | None:
    """The VLAN a switch port gets for devices in this group (None: the port keeps its own VLAN)."""
    if group.port_vlan or not group.vlan_ref:
        return None
    vid = vlans.get(group.vlan_ref)
    if vid is None:
        return None
    return mapping.get(vid, vid)


def entries(session: Session, tenant_id: uuid.UUID) -> list[dict]:
    """The MAC part of the snapshot: one decision per listed MAC."""
    vlans = {v.id: v.vlan_id for v in session.scalars(select(m.Vlan).where(m.Vlan.tenant_id == tenant_id))}
    mapping = wired_vlan_map(session, tenant_id)
    groups = {g.id: g for g in session.scalars(select(m.DeviceGroup).where(m.DeviceGroup.tenant_id == tenant_id))}
    out = []
    for d in session.scalars(select(m.MacDevice).where(m.MacDevice.tenant_id == tenant_id).order_by(m.MacDevice.mac)):
        g = groups.get(d.group_id)
        if g is None:
            continue
        if not d.enabled:
            outcome, reason = "deny", "mac_disabled"
        elif not g.enabled:
            outcome, reason = "deny", "mac_group_disabled"
        else:
            outcome, reason = "allow", None
        out.append({"mac": d.mac, "outcome": outcome, "reason": reason,
                    "vlan": group_switch_vlan(g, vlans, mapping) if outcome == "allow" else None,
                    "device_id": str(d.id), "group_id": str(g.id),
                    "expires_at": int(d.expires_at.timestamp()) if d.expires_at else None})
    return out


def snapshot_part(session: Session, tenant_id: uuid.UUID, have: int | None) -> dict:
    """`mac_version`, plus `mac_entries` when the agent's copy (`have`) is a different version."""
    rs = session.get(m.RadiusSettings, tenant_id)
    version = rs.mac_version if rs else 0
    out: dict = {"mac_version": version}
    if have != version:
        out["mac_entries"] = entries(session, tenant_id)
    return out


# ── Ingest ───────────────────────────────────────────────────────────────────


def event_mac(e: dict) -> str | None:
    """The device MAC of a shipped event: RADIUS's normalised MAB identity, else the Calling-Station-Id."""
    return try_mac(e.get("device_mac")) or try_mac(e.get("mac"))


def method_of(e: dict) -> str | None:
    v = e.get("method")
    return v if v in MAB_METHODS else None


def note_mab(session: Session, tenant_id: uuid.UUID, *, mac: str | None, client_id: uuid.UUID | None, port: str | None,
             result: str, reason: str | None, at: datetime, device_id: str | None) -> bool:
    """Bookkeeping for one MAC authentication: last seen on accept, a sighting on refusal. Returns False when the event
    itself shouldn't be stored (a repeat of an unknown MAC within the hour)."""
    if not mac:
        return True
    if result == "accept":
        dev = session.get(m.MacDevice, uuid.UUID(device_id)) if device_id and _is_uuid(device_id) else None
        if dev is None or dev.tenant_id != tenant_id:
            dev = session.scalars(select(m.MacDevice).where(m.MacDevice.tenant_id == tenant_id, m.MacDevice.mac == mac)).first()
        if dev is not None and (dev.last_seen_at is None or at >= dev.last_seen_at):
            dev.last_seen_at, dev.last_seen_client_id, dev.last_seen_port = at, client_id, (port or None)
        return True
    if client_id is None or reason in (None, "mab_not_enabled"):
        return True
    key = {"tenant_id": tenant_id, "mac": mac, "client_id": client_id, "port": (port or "")[:64]}
    row = session.scalars(select(m.MacSighting).filter_by(**key)).first()
    store = True
    if row is None:
        session.execute(insert(m.MacSighting).values(**key, first_seen=at, last_seen=at, count=1, last_reason=reason, last_event_at=at)
                        .on_conflict_do_nothing(index_elements=["tenant_id", "mac", "client_id", "port"]))
        return True
    row.count += 1
    if at > row.last_seen:
        row.last_seen, row.last_reason = at, reason
    if reason == "mac_unknown" and row.last_event_at and at - row.last_event_at < UNKNOWN_EVENT_EVERY:
        store = False
    else:
        row.last_event_at = at
    return store


def prune_sightings(session: Session) -> None:
    """Platform-scoped retention: 90 days, and at most MAX_SIGHTINGS per tenant (oldest first)."""
    cutoff = datetime.now(UTC) - timedelta(days=SIGHTING_RETENTION_DAYS)
    session.execute(m.MacSighting.__table__.delete().where(m.MacSighting.last_seen < cutoff))
    for tid, n in session.execute(select(m.MacSighting.tenant_id, func.count()).group_by(m.MacSighting.tenant_id)).all():
        if n > MAX_SIGHTINGS:
            keep = select(m.MacSighting.id).where(m.MacSighting.tenant_id == tid).order_by(m.MacSighting.last_seen.desc()).limit(MAX_SIGHTINGS)
            session.execute(m.MacSighting.__table__.delete().where(m.MacSighting.tenant_id == tid, m.MacSighting.id.not_in(keep)))


# ── Change of Authorization ──────────────────────────────────────────────────


def _sessions_for(session: Session, tenant_id: uuid.UUID, mac: str) -> list[tuple[m.RadiusClient | None, dict]]:
    """Open sessions of this device, by the normalised MAC; without accounting, the switch of its last accept."""
    clients = {c.id: c for c in session.scalars(select(m.RadiusClient).where(m.RadiusClient.tenant_id == tenant_id))}
    rows = session.scalars(select(m.AccountingSession).where(m.AccountingSession.tenant_id == tenant_id, m.AccountingSession.mac == mac,
                                                             m.AccountingSession.stopped_at.is_(None))).all()
    if rows:
        return [(clients.get(r.nas_client_id) if r.nas_client_id else None,
                 {"NAS-IP-Address": r.nas_ip, "Acct-Session-Id": r.acct_session_id, "Calling-Station-Id": r.calling_station_id or "",
                  "User-Name": r.username or ""}) for r in rows]
    ev = session.scalars(select(m.AuthEvent).where(m.AuthEvent.tenant_id == tenant_id, m.AuthEvent.mac == mac, m.AuthEvent.result == "accept",
                                                   m.AuthEvent.at >= datetime.now(UTC) - timedelta(days=2))
                         .order_by(m.AuthEvent.at.desc()).limit(1)).first()
    if ev is None:
        return []
    return [(clients.get(ev.nas_client_id) if ev.nas_client_id else None,
             {"NAS-IP-Address": ev.nas_ip or "", "Calling-Station-Id": ev.calling_station_id or "", "User-Name": ev.username or ""})]


def coa_for_mac(session: Session, tenant_id: uuid.UUID, mac: str, kind: str, reason: str) -> dict:
    """Queue a Disconnect-Request ("disconnect"), or a Cisco CoA-Request to re-authenticate ("reauthenticate") or bounce
    the port ("bounce"), for every live session of this device on a switch with CoA on."""
    queued = without = 0
    targets = _sessions_for(session, tenant_id, mac)
    for nas, attrs in targets:
        if nas is None or not nas.coa_enabled:
            without += 1
            continue
        attrs = {k: v for k, v in attrs.items() if v}
        caps = cp.caps_for(nas.vendor, nas.wired_profile) if nas.vendor == "cisco-switch" else None
        if kind in ("reauthenticate", "bounce"):
            if caps is None or caps.dialect not in ("ibns2", "authmgr", "nxos"):
                # Only Catalyst and Nexus document these commands; elsewhere a disconnect makes the switch authenticate again.
                kind_here = "disconnect"
            else:
                # NX-OS can re-authenticate a session but not bounce its port (docs/plans/cisco-platforms.md §3).
                kind_here = "reauthenticate" if kind == "reauthenticate" or caps.coa == "no-bounce" else kind
                attrs["Cisco-AVPair"] = "subscriber:command=reauthenticate" if kind_here == "reauthenticate" else "subscriber:command=bounce-host-port"
        else:
            kind_here = "disconnect"
        session.add(m.CoaRequest(tenant_id=tenant_id, nas_client_id=nas.id, kind=kind_here, attributes=attrs, reason=reason[:200], status="pending"))
        queued += 1
    return {"sessions": len(targets), "queued": queued, "without_coa": without}


def sweep_expired(session: Session, since: datetime, until: datetime) -> int:
    """Platform-scoped: disconnect devices whose allow-list entry expired in (since, until]."""
    n = 0
    for d in session.scalars(select(m.MacDevice).where(m.MacDevice.expires_at > since, m.MacDevice.expires_at <= until, m.MacDevice.enabled.is_(True))):
        coa_for_mac(session, d.tenant_id, d.mac, "disconnect", "MAC allow-list entry expired")
        n += 1
    return n


def _is_uuid(s: str) -> bool:
    try:
        uuid.UUID(s)
        return True
    except ValueError:
        return False
