"""Switch audit: monitoring settings, the switch configuration block, polling a switch and recording what it reported,
and the findings' hysteresis and acknowledgement (docs/plans/switch-audit.md).

Polls run in the collector (app/switchaudit/collector.py) and, for "Test connection", in the API. The SNMP exchange
never happens inside a database transaction: credentials are read and decrypted first, the session is closed, the
switch is polled, then the result is written in one transaction.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import secrets
import string
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import models as m
from app.radius.wired import planned_ports
from app.switchaudit import collect, snmp
from app.switchaudit.findings import KINDS, TEXT, Context, Found, Key, Seen, detail_hash, evaluate, failure, family

log = logging.getLogger("easyeap.switchaudit")

DEFAULT_INTERVAL = 15
POLL_BUDGET_SECONDS = 120      # a whole poll, every walk included
TEST_BUDGET_SECONDS = 10       # "Test connection" in the API
POLL_NOW_EVERY = timedelta(minutes=1)
SLOW_SECONDS = 60              # a poll longer than this: the switch is polled half as often
HISTORY_DAYS = 90
MAX_STATE_BYTES = 1_048_576
_ALNUM = string.ascii_letters + string.digits
VIEW = [("1.3.6.1.2.1.1", "system"), ("1.3.6.1.2.1.2.2.1", "ifTable"), ("1.3.6.1.2.1.31.1.1.1", "ifXTable"),
        ("1.3.6.1.2.1.47.1.1.1.1", "entPhysicalTable"), ("1.3.6.1.4.1.9.9.656", "CISCO-AUTH-FRAMEWORK-MIB"),
        ("1.3.6.1.4.1.9.9.548", "CISCO-ERR-DISABLE-MIB")]


class MonitoringError(ValueError):
    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field


class MonitoringIn(BaseModel):
    """radius_clients.monitoring, as the console edits it. No secrets."""
    host: str = Field(max_length=64)
    port: int = Field(default=161, ge=1, le=65535)
    version: Literal["v2c", "v3"] = "v2c"
    user: str = Field(default="easyeap", min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_.-]+$")
    auth: Literal["sha256", "sha"] = "sha256"
    priv: Literal["aes128", "aes256"] = "aes128"
    interval_minutes: int = Field(default=DEFAULT_INTERVAL, ge=5, le=60)

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        v = v.strip()
        try:
            ip = ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError("Enter the switch's management IP address.") from exc
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or (ip.version == 4 and str(ip) == "255.255.255.255"):
            raise ValueError("That address can't be a switch's management address.")
        return str(ip)

    def check(self) -> None:
        if self.version == "v3" and self.priv == "aes256" and self.auth != "sha256":
            raise MonitoringError("priv", "AES-256 needs SHA-256 authentication.")


def default_host(c: m.RadiusClient) -> str:
    """The RADIUS client's address when it's a single host (a switch registered by a range has no obvious one)."""
    raw = (c.address or "").strip()
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return ""
    return str(net.network_address) if net.num_addresses == 1 else ""


def new_credentials(version: str) -> dict:
    if version == "v3":
        return {"auth_key": "".join(secrets.choice(_ALNUM) for _ in range(24)), "priv_key": "".join(secrets.choice(_ALNUM) for _ in range(24))}
    return {"community": "".join(secrets.choice(_ALNUM) for _ in range(24))}


def creds_for(mon: dict, secret: dict) -> snmp.V2c | snmp.V3:
    if mon.get("version") == "v3":
        return snmp.V3(mon.get("user") or "easyeap", secret["auth_key"], secret["priv_key"], mon.get("auth") or "sha256", mon.get("priv") or "aes128")
    return snmp.V2c(secret["community"])


# ── The switch configuration ─────────────────────────────────────────────────

COMMUNITY_PLACEHOLDER = "<community>"  # the console fills these in once
AUTH_PLACEHOLDER = "<authentication key>"
PRIV_PLACEHOLDER = "<privacy key>"


def config_block(mon: dict, source: str) -> str:
    """The lines to paste on the switch: a read-only view of the six subtrees EasyEAP reads, an ACL that only lets
    EasyEAP in, and the community or SNMPv3 user. Nothing global changes (no logging, timestamps or AAA)."""
    src = source or "<EasyEAP's address>"
    v6 = ":" in src
    acl = "EASYEAP-SNMP6" if v6 else "EASYEAP-SNMP"
    out = ["! EasyEAP switch audit: read-only SNMP for the 802.1X tables, from EasyEAP's address only.",
           f"! {src} is the address the switch sees EasyEAP's requests come from (normally EasyEAP's RADIUS address)."]
    out += [f"ipv6 access-list {acl}", f" permit ipv6 host {src} any"] if v6 else [f"ip access-list standard {acl}", f" permit host {src}", " deny any"]
    out.append("!")
    out += [f"snmp-server view EASYEAP-RO {o} included" for o, _ in VIEW]
    acl_ref = f"ipv6 {acl}" if v6 else acl
    if mon.get("version") == "v3":
        auth = "sha-2 256" if mon.get("auth", "sha256") == "sha256" else "sha"
        priv = "aes 256" if mon.get("priv") == "aes256" else "aes 128"
        out += [f"snmp-server group EASYEAP v3 priv read EASYEAP-RO access {acl_ref}",
                f"snmp-server user {mon.get('user') or 'easyeap'} EASYEAP v3 auth {auth} {AUTH_PLACEHOLDER} priv {priv} {PRIV_PLACEHOLDER}"]
        if auth == "sha-2 256":
            out.append("! sha-2 256 needs IOS-XE 16.10 or later; on older software choose SHA-1 in EasyEAP instead.")
    else:
        out.append(f"snmp-server community {COMMUNITY_PLACEHOLDER} view EASYEAP-RO RO {acl_ref}")
    return "\n".join(out) + "\n"


def removal_block(mon: dict, community: str | None = None) -> str:
    """Undo config_block (also how the old community is retired when credentials are regenerated)."""
    out = []
    if mon.get("version") == "v3":
        out += [f"no snmp-server user {mon.get('user') or 'easyeap'} EASYEAP v3", "no snmp-server group EASYEAP v3 priv"]
    else:
        out.append(f"no snmp-server community {community or COMMUNITY_PLACEHOLDER}")
    out.append("no snmp-server view EASYEAP-RO")
    out += ["no ip access-list standard EASYEAP-SNMP", "no ipv6 access-list EASYEAP-SNMP6"]
    return "\n".join(out) + "\n"


# ── Polling ──────────────────────────────────────────────────────────────────


@dataclass
class Target:
    client_id: uuid.UUID
    tenant_id: uuid.UUID
    host: str
    port: int
    creds: snmp.V2c | snmp.V3


def target(c: m.RadiusClient) -> Target | None:
    """What to poll, with the credentials decrypted (OpenBao Transit), or None when monitoring isn't set up."""
    mon = c.monitoring or {}
    if not mon.get("host") or not c.snmp_secret_ct:
        return None
    from app.pki import crypto
    secret = json.loads(crypto.decrypt_str(c.tenant_id, c.snmp_secret_ct))
    return Target(c.id, c.tenant_id, mon["host"], int(mon.get("port") or 161), creds_for(mon, secret))


def run_poll(t: Target, budget: float = POLL_BUDGET_SECONDS, probe_only: bool = False, timeout: float = 3.0, retries: int = 2) -> dict:
    """Poll a switch. Never raises for the switch's sake: {"ok": False, "error_kind", "error"} instead."""
    started = time.monotonic()
    try:
        with snmp.Session(t.host, t.creds, port=t.port, timeout=timeout, retries=retries, deadline=started + budget) as s:
            data = collect.probe(s) if probe_only else collect.poll(s)
            data["requests"] = s.requests
        return {"ok": True, **data, "duration_ms": int((time.monotonic() - started) * 1000)}
    except snmp.SnmpError as exc:
        return {"ok": False, "error_kind": exc.kind, "error": str(exc)[:300], "duration_ms": int((time.monotonic() - started) * 1000)}
    except Exception as exc:  # whatever the switch sent, a poll ends with a result, never an exception
        log.warning("Switch %s: unexpected error reading its answer", t.host, exc_info=True)
        return {"ok": False, "error_kind": "protocol", "error": f"EasyEAP couldn't read the switch's answer ({type(exc).__name__}).",
                "duration_ms": int((time.monotonic() - started) * 1000)}


def _fit(state: dict) -> dict:
    """Keep the stored state under MAX_STATE_BYTES: sessions go first (the findings already carry what matters)."""
    sessions = state.get("sessions") or []
    while sessions and len(json.dumps({**state, "sessions": sessions}, default=str)) > MAX_STATE_BYTES:
        sessions = sessions[: len(sessions) // 2]
        state = {**state, "truncated": True}
    return {**state, "sessions": sessions}


def context(s: Session, c: m.RadiusClient, state: dict) -> Context:
    """The plan and EasyEAP's own records for the MACs the switch reported authorized."""
    profile = c.wired_profile or {}
    mon = c.monitoring or {}
    macs = sorted({x["mac"] for x in state.get("sessions") or [] if x.get("mac") and x.get("authorized")})
    ctx = Context(mode=profile.get("mode") or "enforce", planned=planned_ports(profile), mab=bool(profile.get("mab")),
                  pinned=mon.get("pinned") or {}, version=mon.get("version") or "v2c")
    since = datetime.now(UTC) - timedelta(days=180)
    accepts: dict[Key, m.AuthEvent] = {}
    for i in range(0, len(macs), 500):
        # The latest answer per MAC, result and method; then the latest per method family.
        rows = s.scalars(select(m.AuthEvent).where(m.AuthEvent.nas_client_id == c.id, m.AuthEvent.mac.in_(macs[i:i + 500]), m.AuthEvent.at >= since)
                         .distinct(m.AuthEvent.mac, m.AuthEvent.result, m.AuthEvent.method)
                         .order_by(m.AuthEvent.mac, m.AuthEvent.result, m.AuthEvent.method, m.AuthEvent.at.desc())).all()
        for e in rows:
            key = (e.mac, family(e.method))
            latest = ctx.latest_accept if e.result == "accept" else ctx.latest_reject
            if key in latest and latest[key].at >= e.at:
                continue
            latest[key] = Seen(e.result, e.at, e.vlan_id if not e.monitor else None, bool(e.monitor), e.method, e.reason_code)
            if e.result == "accept":
                accepts[key] = e
    ctx.denied_now = denied_now(s, c.tenant_id, list(accepts.values()))
    return ctx


def denied_now(s: Session, tenant_id: uuid.UUID, accepts: list[m.AuthEvent]) -> dict[Key, str]:
    """For each accept, by (MAC, family): why EasyEAP would refuse the device behind it today, when it would."""
    now, out = datetime.now(UTC), {}
    mab = [e for e in accepts if e.method in ("mab", "mab-eap")]
    certs = [e for e in accepts if e.method not in ("mab", "mab-eap") and e.cert_serial]
    if mab:
        devices = {d.mac: d for d in s.scalars(select(m.MacDevice).where(m.MacDevice.tenant_id == tenant_id, m.MacDevice.mac.in_([e.mac for e in mab])))}
        for e in mab:
            d = devices.get(e.mac)
            why = ("removed from the MAC allow list" if d is None else "blocked on the MAC allow list" if not d.enabled
                   else "its MAC allow-list entry expired" if d.expires_at and d.expires_at <= now else None)
            if why:
                out[(e.mac, "mab")] = why
    if certs:
        by_serial = {x.serial: x for x in s.scalars(select(m.Certificate).where(m.Certificate.tenant_id == tenant_id,
                                                                                 m.Certificate.serial.in_({e.cert_serial for e in certs})))}
        decisions = {d.certificate_id: d for d in s.scalars(select(m.Decision).where(m.Decision.certificate_id.in_([x.id for x in by_serial.values()])))} if by_serial else {}
        for e in certs:
            cert = by_serial.get(e.cert_serial)
            if cert is None:
                continue
            d = decisions.get(cert.id)
            if cert.status == "revoked":
                out[(e.mac, "dot1x")] = "its certificate was revoked"
            elif d is not None and d.outcome == "deny":
                out[(e.mac, "dot1x")] = f"policy now denies it ({d.reason_code})" if d.reason_code else "policy now denies it"
    return out


def record(s: Session, c: m.RadiusClient, result: dict, now: datetime | None = None) -> m.SwitchState:
    """Store a poll's result and update the findings. The caller commits."""
    now = now or datetime.now(UTC)
    mon = dict(c.monitoring or {})
    st = s.get(m.SwitchState, c.id) or m.SwitchState(client_id=c.id, tenant_id=c.tenant_id, failures=0)
    s.add(st)
    interval = timedelta(minutes=int(mon.get("interval_minutes") or DEFAULT_INTERVAL))
    st.polled_at, st.duration_ms, st.poll_requested_at = now, result.get("duration_ms"), None
    st.slow = bool(result.get("duration_ms") and result["duration_ms"] > SLOW_SECONDS * 1000)
    st.next_poll_at = now + (interval * 2 if st.slow else interval)
    skip = None
    if result.get("ok"):
        data = _fit({k: result.get(k) for k in ("facts", "capabilities", "ports", "sessions", "truncated")})
        st.ok, st.error_kind, st.error, st.failures, st.last_ok_at = True, None, None, 0, now
        st.facts, st.capabilities, st.ports, st.sessions, st.truncated = (data["facts"] or {}, data["capabilities"] or {}, data["ports"] or [],
                                                                         data["sessions"] or [], bool(data["truncated"]))
        pinned = pin_missing(mon.get("pinned") or {}, st.facts)
        if pinned != (mon.get("pinned") or {}):
            c.monitoring = {**mon, "pinned": pinned}
        found, evaluated = evaluate(result, context(s, c, result))
        skip = _past_the_cut(result)
    else:
        st.ok, st.error_kind, st.error, st.failures = False, result.get("error_kind"), result.get("error"), (st.failures or 0) + 1
        found, evaluated = failure(result.get("error_kind") or "timeout", result.get("error") or ""), {"snmp_unreachable", "snmp_auth"}
    apply_findings(s, c, found, evaluated, now, skip)
    return st


def pin_missing(pinned: dict, facts: dict) -> dict:
    """Record the serial number and engine ID the switch reports where none is recorded yet (each on its own: a switch
    moved from v2c to v3 gets its engine ID pinned at the first v3 poll)."""
    out = {"serial": pinned.get("serial") or "", "engine_id": pinned.get("engine_id") or ""}
    for k in out:
        if not out[k] and facts.get(k):
            out[k] = facts[k]
    return out


def _past_the_cut(result: dict):
    """When the switch's port or session list was cut short: a predicate for the open findings it gave no evidence for."""
    partial = result.get("partial") or {}
    if not (partial.get("ports") or partial.get("sessions")):
        return None
    ports = {p.get("name") for p in result.get("ports") or []}
    macs = {x.get("mac") for x in result.get("sessions") or []}
    return lambda r: bool((partial.get("sessions") and r.mac and r.mac not in macs)
                          or (partial.get("ports") and not r.mac and r.port and r.port not in ports))


def defer(s: Session, c: m.RadiusClient, error: str, now: datetime | None = None) -> None:
    """A poll whose result couldn't be stored: note it and wait an interval, so the switch isn't re-polled at once."""
    now = now or datetime.now(UTC)
    st = s.get(m.SwitchState, c.id) or m.SwitchState(client_id=c.id, tenant_id=c.tenant_id, failures=0)
    s.add(st)
    interval = timedelta(minutes=int((c.monitoring or {}).get("interval_minutes") or DEFAULT_INTERVAL))
    st.polled_at, st.poll_requested_at, st.next_poll_at = now, None, now + interval
    st.ok, st.error_kind, st.error, st.failures = False, "internal", error[:300], (st.failures or 0) + 1


def apply_findings(s: Session, c: m.RadiusClient, found: list[Found], evaluated: set[str], now: datetime, skip=None) -> None:
    rows = {(r.kind, r.port, r.mac): r for r in s.scalars(select(m.SwitchFinding).where(
        m.SwitchFinding.client_id == c.id, m.SwitchFinding.resolved_at.is_(None)))}
    added, gone = transition(rows, found, evaluated, now,
                             lambda f: m.SwitchFinding(tenant_id=c.tenant_id, client_id=c.id, kind=f.kind, port=f.port[:64], mac=f.mac[:12],
                                                       first_seen_at=now, seen_count=0, missing_count=0), skip)
    for r in added:
        s.add(r)
    for r in gone:
        s.delete(r)


def transition(rows: dict, found: list[Found], evaluated: set[str], now: datetime, make, skip=None) -> tuple[list, list]:
    """Hysteresis over the open rows (keyed kind, port, MAC): a finding opens after `open_after` consecutive polls show
    it and resolves after `resolve_after` polls without it (sticky ones only when acknowledged); one that never opened
    is forgotten when it disappears. Kinds not in `evaluated`, and rows `skip` says the poll gave no evidence for, are
    left alone. Returns (rows to add, rows to delete)."""
    current = {f.key: f for f in found if f.kind in evaluated}
    added, gone = [], []
    for key, f in current.items():
        h = detail_hash(f.detail)
        r = rows.get(key)
        if r is None:
            r = make(f)
            added.append(r)
        r.severity, r.detail, r.last_seen_at = f.severity, f.detail, now
        r.seen_count, r.missing_count = (r.seen_count or 0) + 1, 0
        if r.ack_hash and r.ack_hash != h:  # what was acknowledged changed: show it again
            r.acknowledged_at = r.acknowledged_by = r.ack_note = r.ack_hash = None
        r.detail_hash = h
        if r.opened_at is None and r.seen_count >= KINDS[f.kind].open_after:
            r.opened_at = now
    for key, r in rows.items():
        if key in current or r.kind not in evaluated or r.kind not in KINDS or (skip is not None and skip(r)):
            continue
        spec = KINDS[r.kind]
        if spec.sticky:
            continue
        r.missing_count = (r.missing_count or 0) + 1
        if r.opened_at is None:
            gone.append(r)
        elif r.missing_count >= spec.resolve_after:
            r.resolved_at = now
    return added, gone


def acknowledge(s: Session, c: m.RadiusClient, f: m.SwitchFinding, who: str, note: str, now: datetime | None = None) -> None:
    now = now or datetime.now(UTC)
    f.acknowledged_at, f.acknowledged_by, f.ack_note, f.ack_hash = now, who[:254], note[:500], f.detail_hash
    if KINDS.get(f.kind, KINDS["port_not_covered"]).sticky:
        # Acknowledging a changed switch accepts it: pin what answers now, and close the finding.
        st = s.get(m.SwitchState, c.id)
        facts = (st.facts if st else {}) or {}
        c.monitoring = {**(c.monitoring or {}), "pinned": {"serial": facts.get("serial") or "", "engine_id": facts.get("engine_id") or ""}}
        f.resolved_at = now


def poll_client(client_id: uuid.UUID, tenant_id: uuid.UUID) -> dict:
    """Poll one switch and record the result (the collector, and `python -m app.switchaudit.collector --once`)."""
    from app.db import new_session, set_tenant
    s = new_session()
    try:
        set_tenant(s, tenant_id)
        c = s.get(m.RadiusClient, client_id)
        if c is None or not (c.monitoring or {}).get("enabled"):
            return {"ok": False, "error": "Monitoring isn't on for this switch."}
        try:
            t = target(c)
        except Exception as exc:  # noqa: BLE001 — OpenBao sealed or unreachable: recorded, and retried at the next interval
            log.warning("Switch %s: can't read its SNMP credentials: %s", client_id, exc)
            t = None
        s.commit()
    finally:
        s.close()
    result = run_poll(t) if t is not None else {"ok": False, "error_kind": "config", "error": "EasyEAP couldn't read this switch's stored SNMP credentials."}
    from app.backup.engine import maintenance
    if maintenance():  # a restore started during the poll: the database is being replaced, drop the result
        return {"ok": False, "error": "A restore is in progress; the poll's result was dropped."}
    try:
        stored = _write(client_id, tenant_id, lambda s, c: record(s, c, result))
    except Exception as exc:
        log.warning("Switch %s: couldn't store the poll's result", client_id, exc_info=True)
        # Record that much, so the switch waits an interval instead of being polled again straight away.
        why = f"EasyEAP couldn't store this poll's result ({type(exc).__name__})."
        _write(client_id, tenant_id, lambda s, c: defer(s, c, why))
        raise
    if not stored:
        return {"ok": False, "error": "Monitoring was turned off during the poll."}
    return {k: result.get(k) for k in ("ok", "error_kind", "error", "duration_ms")} | {"sessions": len(result.get("sessions") or []),
                                                                                      "ports": len(result.get("ports") or [])}


def _write(client_id: uuid.UUID, tenant_id: uuid.UUID, fn) -> bool:
    """fn(session, switch) in one transaction, holding the switch's row so two polls of one switch (the service and a
    `--once`, or a test connection) apply one after the other. False when monitoring was turned off meanwhile."""
    from app.db import new_session, set_tenant
    s = new_session()
    try:
        set_tenant(s, tenant_id)
        c = s.get(m.RadiusClient, client_id, with_for_update=True)
        if c is None or not (c.monitoring or {}).get("enabled"):
            s.rollback()
            return False
        fn(s, c)
        s.commit()
        return True
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def prune(s: Session) -> int:
    """Platform-scoped: forget findings resolved more than HISTORY_DAYS ago."""
    cutoff = datetime.now(UTC) - timedelta(days=HISTORY_DAYS)
    rows = s.scalars(select(m.SwitchFinding).where(m.SwitchFinding.resolved_at.is_not(None), m.SwitchFinding.resolved_at < cutoff).limit(5000)).all()
    for r in rows:
        s.delete(r)
    return len(rows)


# ── Output ───────────────────────────────────────────────────────────────────


def finding_out(f: m.SwitchFinding) -> dict:
    meaning, fix = TEXT.get(f.kind, ("", ""))
    return {"id": str(f.id), "kind": f.kind, "severity": f.severity, "port": f.port or None, "mac": f.mac or None, "detail": f.detail,
            "meaning": meaning, "fix": fix, "first_seen_at": f.first_seen_at.isoformat(), "last_seen_at": f.last_seen_at.isoformat(),
            "opened_at": f.opened_at.isoformat() if f.opened_at else None, "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
            "acknowledged_at": f.acknowledged_at.isoformat() if f.acknowledged_at else None, "acknowledged_by": f.acknowledged_by,
            "ack_note": f.ack_note}


def monitoring_out(c: m.RadiusClient) -> dict:
    mon = c.monitoring or {}
    return {"enabled": bool(mon.get("enabled")), "host": mon.get("host") or None, "port": mon.get("port") or 161,
            "version": mon.get("version") or "v2c", "user": mon.get("user") or "easyeap", "auth": mon.get("auth") or "sha256",
            "priv": mon.get("priv") or "aes128", "interval_minutes": mon.get("interval_minutes") or DEFAULT_INTERVAL,
            "credentials_set": bool(c.snmp_secret_ct), "credentials_set_at": mon.get("credentials_set_at"),
            "pinned": mon.get("pinned") or None, "set_up": bool(mon.get("host") and c.snmp_secret_ct)}


def state_out(st: m.SwitchState | None) -> dict | None:
    if st is None or st.polled_at is None:
        return None
    return {"polled_at": st.polled_at.isoformat(), "ok": st.ok, "error_kind": st.error_kind, "error": st.error, "duration_ms": st.duration_ms,
            "failures": st.failures, "last_ok_at": st.last_ok_at.isoformat() if st.last_ok_at else None, "facts": st.facts or {},
            "capabilities": st.capabilities or {}, "ports": st.ports or [], "sessions": st.sessions or [], "truncated": st.truncated,
            "slow": st.slow, "next_poll_at": st.next_poll_at.isoformat() if st.next_poll_at else None,
            "poll_requested_at": st.poll_requested_at.isoformat() if st.poll_requested_at else None}


def polled_sessions(st: m.SwitchState | None, interval_minutes: int) -> dict | None:
    """Readiness from the switch's own session list, when a recent successful poll has it."""
    if st is None or not st.ok or not st.last_ok_at or not (st.capabilities or {}).get("caf"):
        return None
    if datetime.now(UTC) - st.last_ok_at > timedelta(minutes=interval_minutes * 3):
        return None
    rows = [{"interface": x.get("port"), "mac": x.get("mac"), "method": x.get("method") or "", "domain": x.get("domain") or "",
             "status": x.get("status") or "", "authorized": bool(x.get("authorized"))} for x in st.sessions or []]
    return {"at": st.last_ok_at.isoformat(), "sessions": len(rows), "authorized": sum(r["authorized"] for r in rows),
            "would_lose_access": [r for r in rows if not r["authorized"]][:1000]}
