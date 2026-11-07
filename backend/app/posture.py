"""Tenant posture: whether RADIUS can enforce the tenant, when it would fail closed, and what needs action next.

Every item states its source data's age through the timestamps it carries; nothing here is estimated or invented.
Ranking: severity, then time until users are affected (soonest first), then how many people are affected.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from app import models as m
from app.policy.service import policy_settings
from app.radius.explain import explain

SEVERITY = {"critical": 0, "warning": 1, "info": 2}
# Reject reasons that indicate something to fix (policy_deny is the policy working as configured).
ACTIONABLE_REJECTS = {"unknown_ca", "cert_unknown", "cert_expired", "cert_revoked", "identity_unauthorized", "account_disabled",
                      "snapshot_stale", "vlan_assignment", "tls_handshake", "client_timeout", "network_not_enabled", "mab_unsupported"}
# A switch left in monitor mode this long is a reminder: its ports aren't protected yet (docs/plans/wired-8021x.md §6.2).
MONITOR_NUDGE = timedelta(days=14)


# The worker heartbeats every minute and rebuilds every tenant's snapshot hourly.
WORKER_STALE = timedelta(minutes=3)
REBUILD_OVERDUE = timedelta(minutes=75)
# The agent polls every few seconds; a new snapshot or configuration not applied after this is a real delay.
APPLY_GRACE = timedelta(minutes=2)
# The issuing CA's revocation list is rebuilt daily and valid for 72 hours (FreeRADIUS: allow_expired_crl = no).
CRL_WARN = timedelta(hours=48)
CRL_CRIT = timedelta(hours=12)
ROOT_CRL_WARN = timedelta(days=60)


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


def worker_seen_at(s: Session) -> datetime | None:
    hb = s.get(m.PlatformSetting, "worker_heartbeat")
    at = (hb.value or {}).get("at") if hb else None
    return datetime.fromisoformat(at) if at else None


def certificate_holders(s: Session, tenant_id: uuid.UUID, now: datetime) -> int:
    return s.scalar(select(func.count(distinct(m.Certificate.identity_id))).where(
        m.Certificate.tenant_id == tenant_id, m.Certificate.status != "revoked", m.Certificate.not_after > now,
        m.Certificate.purpose.in_(m.CLIENT_PURPOSES))) or 0


def enforcement(s: Session, t: m.Tenant, agent: dict | None, now: datetime | None = None) -> dict:
    """Can RADIUS enforce this tenant now, and until when does its local snapshot stay valid?"""
    now = now or datetime.now(UTC)
    ps = policy_settings(s, t.id)
    rs = s.get(m.RadiusSettings, t.id)
    dc = s.get(m.DirectoryConfig, t.id)
    has_ca = s.scalar(select(func.count()).select_from(m.CertificateAuthority).where(
        m.CertificateAuthority.tenant_id == t.id, m.CertificateAuthority.role == "issuing")) or 0
    clients = s.scalar(select(func.count()).select_from(m.RadiusClient).where(m.RadiusClient.tenant_id == t.id)) or 0
    missing = []
    if not has_ca:
        missing.append({"code": "pki", "message": "Initialize the tenant's certificate authority", "target": "setup"})
    if rs is None or rs.server_certificate_id is None:
        missing.append({"code": "radius_certificate", "message": "Configure RADIUS and issue its server certificate", "target": "radius"})
    if clients == 0:
        missing.append({"code": "controllers", "message": "Add a wireless controller or switch", "target": "radius"})
    if t.status != "active":
        missing.append({"code": "tenant_status", "message": "Activate the tenant" if t.status == "setup" else "The tenant is suspended",
                        "target": "setup" if t.status == "setup" else "tenant"})
    max_age = timedelta(seconds=ps.max_snapshot_age_seconds)
    built = rs.snapshot_built_at if rs else None
    directory_fresh = dc is None or not dc.enabled or bool(dc.last_sync_status == "ok" and dc.last_sync_at and now - dc.last_sync_at < max_age)
    worker_at = worker_seen_at(s)
    worker_alive = bool(worker_at and now - worker_at < WORKER_STALE)
    applied = ((agent or {}).get("snapshot_versions") or {}).get(str(t.id))
    serving = (agent or {}).get("serving_ids")
    e = {
        "enforceable": not missing, "missing": missing,
        "snapshot_built_at": _iso(built), "snapshot_version": rs.snapshot_version if rs else None,
        "deadline_at": _iso(built + max_age) if built else None, "max_snapshot_age_seconds": ps.max_snapshot_age_seconds,
        # While the directory is healthy and the worker is running, the snapshot is rebuilt hourly, so the deadline keeps
        # moving forward. `refresh_blocked_by` says which of the two stopped it.
        "auto_refresh": directory_fresh and worker_alive,
        "refresh_blocked_by": None if directory_fresh and worker_alive else ("worker" if not worker_alive else "directory"),
        "refresh_overdue": bool(built and now - built > REBUILD_OVERDUE),
        "directory_fresh": directory_fresh,
        "worker_alive": worker_alive, "worker_seen_at": _iso(worker_at),
        "agent_online": bool(agent and agent.get("online")),
        "radius_state": (agent or {}).get("state"),
        "config_ok": (agent or {}).get("config_ok"),
        # None when the agent doesn't report which tenants its configuration serves (older agents).
        "served": None if serving is None else str(t.id) in serving,
        "snapshot_expired": bool(built and now >= built + max_age),
        "agent_applied_version": applied,
        "agent_in_sync": applied is not None and rs is not None and applied == rs.snapshot_version,
        # A change is normally applied within seconds; until APPLY_GRACE has passed, "not applied yet" is not a fault.
        "applying": bool(built and now - built <= APPLY_GRACE),
    }
    e["status"] = status_of(t, e, dc)
    return e


def _status(state: str, tone: str, label: str, detail: str) -> dict:
    return {"state": state, "tone": tone, "label": label, "detail": detail}


def status_of(t: m.Tenant, e: dict, dc: m.DirectoryConfig | None) -> dict:
    """One answer to "is RADIUS enforcing this tenant?", shared by every chip, panel and list in the console.

    tone: valid (enforcing), warn (enforcing, but something is late), crit (denying everyone or about to), neutral
    (by design: not set up, suspended, or applying a change right now).
    """
    if t.status == "suspended":
        return _status("suspended", "neutral", "Suspended", "Nobody in this tenant can connect while it's suspended.")
    if not e["enforceable"]:
        return _status("setup", "neutral", "Not enforceable yet", "Setup isn't finished, so nobody can connect yet.")
    if not e["agent_online"]:
        return _status("radius_offline", "crit", "RADIUS not reporting",
                       "EasyEAP hasn't heard from the RADIUS agent. If RADIUS is still running it keeps using its last snapshot.")
    if e["config_ok"] is False:
        return _status("radius_config", "crit", "Configuration rejected", "RADIUS rejected its latest configuration and is running the previous one.")
    if e["radius_state"] == "stopped":
        return _status("radius_stopped", "crit", "RADIUS stopped", "FreeRADIUS isn't running, so nobody can connect.")
    if e["radius_state"] == "starting":
        return _status("starting", "neutral", "Starting", "RADIUS is starting for this newly activated tenant.")
    if not e["snapshot_built_at"]:
        return _status("no_snapshot", "crit", "Denying everyone", "No authorization snapshot has been built yet, so RADIUS denies everyone.")
    if e["snapshot_expired"]:
        return _status("expired", "crit", "Denying everyone", "The authorization snapshot is past its limit, so RADIUS fails closed.")
    if e["served"] is False and not e["applying"]:
        return _status("not_served", "crit", "Not served by RADIUS", "RADIUS's running configuration doesn't include this tenant, so nobody can connect.")
    if not e["auto_refresh"]:
        if e["refresh_blocked_by"] == "worker":
            return _status("at_risk", "crit", "At risk", "The background worker isn't running, so the snapshot isn't refreshed. RADIUS denies everyone when it expires.")
        failing = dc is not None and dc.last_sync_status == "failed"
        return _status("at_risk", "crit", "At risk",
                       ("Directory sync is failing" if failing else "The directory hasn't synced recently" if dc and dc.last_sync_at else "The directory has never synced")
                       + ", so the snapshot isn't refreshed. RADIUS denies everyone when it expires.")
    if e["served"] is False or not e["agent_in_sync"]:
        if e["applying"]:
            return _status("applying", "neutral", "Applying a change", "A new snapshot was just built; RADIUS normally applies it within seconds.")
        return _status("pending", "warn", "Update pending", "RADIUS is still using an older snapshot, so recent changes (including revocations) aren't enforced yet.")
    if e["refresh_overdue"]:
        return _status("overdue", "warn", "Refresh overdue", "The snapshot hasn't been rebuilt in over an hour. Check the background jobs.")
    return _status("enforcing", "valid", "Enforcing", "RADIUS is enforcing this tenant's latest policy.")


def needs_action(s: Session, t: m.Tenant, agent: dict | None, enf: dict, now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(UTC)
    ps = policy_settings(s, t.id)
    holders = certificate_holders(s, t.id, now)
    users = s.scalar(select(func.count()).select_from(m.Identity).where(m.Identity.tenant_id == t.id, m.Identity.kind == "user",
                                                                     m.Identity.account_state != "deleted")) or 0
    deadline = datetime.fromisoformat(enf["deadline_at"]) if enf["deadline_at"] else None
    items: list[dict] = []

    def add(code: str, severity: str, title: str, detail: str, action: str, target: str, *, affected: int, impact_at: datetime | None,
            source_at: datetime | None) -> None:
        items.append({"code": code, "severity": severity, "title": title, "detail": detail, "action": {"label": action, "target": target},
                      "affected": affected, "impact_at": _iso(impact_at), "source_at": _iso(source_at)})

    if t.status == "suspended":
        add("tenant_suspended", "warning", "Tenant is suspended",
            "Nobody in this tenant can connect while it's suspended. Its certificates, policy and directory settings are kept.",
            "Reactivate the tenant", "tenant", affected=holders, impact_at=None, source_at=None)
    elif enf["missing"]:
        steps = "; ".join(x["message"] for x in enf["missing"])
        add("not_enforceable", "warning", "Not enforceable yet", f"Nobody in this tenant can connect until setup is finished: {steps}.",
            "Continue setup", enf["missing"][0]["target"], affected=users, impact_at=None, source_at=now)
    else:
        if agent is None or not agent.get("online"):
            seen = datetime.fromisoformat(agent["last_seen_at"]) if agent else None
            add("radius_offline", "critical", "RADIUS service is not reporting",
                "EasyEAP has not heard from the RADIUS agent. If RADIUS is still running it keeps authenticating from its last snapshot; "
                "if it is down, nobody can connect.", "Check RADIUS service", "system", affected=holders, impact_at=deadline, source_at=seen)
        elif agent.get("config_ok") is False:
            add("radius_config", "critical", "RADIUS rejected its configuration", agent.get("config_error") or "The last configuration failed to load.",
                "Review RADIUS settings", "radius", affected=holders, impact_at=None, source_at=datetime.fromisoformat(agent["last_seen_at"]))
        elif enf["radius_state"] == "stopped":
            add("radius_stopped", "critical", "FreeRADIUS isn't running",
                "The RADIUS agent is reporting, but FreeRADIUS itself has stopped, so nobody can connect. "
                "The System log (source: FreeRADIUS) shows why.", "Check RADIUS service", "system", affected=holders, impact_at=now,
                source_at=datetime.fromisoformat(agent["last_seen_at"]))
        elif enf["served"] is False and not enf["applying"]:
            add("radius_not_serving", "critical", "RADIUS isn't serving this tenant",
                "The configuration RADIUS is running doesn't include this tenant, so its controllers get no answer.",
                "Check RADIUS service", "system", affected=holders, impact_at=now, source_at=datetime.fromisoformat(agent["last_seen_at"]))
        elif not enf["agent_in_sync"] and enf["snapshot_built_at"] and not enf["applying"]:
            add("snapshot_pending", "warning", "RADIUS hasn't applied the latest policy",
                "The newest authorization snapshot was built but RADIUS is still using an older one, so recent changes (including revocations) "
                "are not enforced yet.", "Check RADIUS service", "system", affected=holders,
                impact_at=None, source_at=datetime.fromisoformat(agent["last_seen_at"]))
        if not enf["snapshot_built_at"]:
            add("snapshot_missing", "critical", "RADIUS has no authorization data for this tenant",
                "The tenant is active, but no authorization snapshot has been built yet, so RADIUS denies everyone. "
                "Snapshots are built by the background worker.", "Check system health", "system",
                affected=holders, impact_at=now, source_at=now)
        elif enf["snapshot_expired"]:
            cause = ("The background worker isn't running, so it isn't rebuilt." if enf["refresh_blocked_by"] == "worker" else
                     "Directory data is out of date, so it isn't rebuilt. Fix the directory sync." if enf["refresh_blocked_by"] == "directory" else
                     "The worker is running but the rebuild hasn't happened. Check the background jobs for failures.")
            add("snapshot_expired", "critical", "RADIUS is denying everyone",
                f"This tenant's authorization snapshot is past its limit, so RADIUS fails closed. {cause}", "Check system health", "system" if enf["refresh_blocked_by"] != "directory" else "directory",
                affected=holders, impact_at=deadline, source_at=datetime.fromisoformat(enf["snapshot_built_at"]))
        elif not enf["worker_alive"]:
            seen = datetime.fromisoformat(enf["worker_seen_at"]) if enf["worker_seen_at"] else None
            add("worker_offline", "critical", "Background worker is not running",
                "Authorization snapshots, directory syncs and CRL updates have stopped. RADIUS keeps using its last snapshot "
                "until it expires, then denies everyone.", "Check system health", "system",
                affected=holders, impact_at=deadline, source_at=seen)
        elif enf["refresh_overdue"] and enf["directory_fresh"]:
            add("snapshot_overdue", "warning", "Authorization snapshot is overdue",
                "The worker is running, but this tenant's snapshot hasn't been rebuilt in over an hour. Check the background jobs "
                "for failures. RADIUS denies everyone when the snapshot expires.", "Check system health", "system",
                affected=holders, impact_at=deadline, source_at=datetime.fromisoformat(enf["snapshot_built_at"]))

    dc = s.get(m.DirectoryConfig, t.id)
    if (dc is not None and dc.enabled and dc.last_sync_status != "failed" and not enf["directory_fresh"] and enf["worker_alive"]
            and t.status == "active"):
        add("directory_stale", "critical", "Directory hasn't synced recently" if dc.last_sync_at else "Directory has never synced",
            (f"The last successful sync is older than the {round(ps.max_snapshot_age_seconds / 3600)}-hour limit, " if dc.last_sync_at else
             "No sync has completed yet, ") + "so the snapshot isn't refreshed and RADIUS denies everyone when it expires. "
            "Start a sync from the Directory page.", "Open directory", "directory",
            affected=holders, impact_at=deadline, source_at=dc.last_sync_at)
    if dc is not None and dc.enabled and dc.last_sync_status == "failed":
        detail = f"The last sync failed: {dc.last_sync_error or 'no detail recorded'}. "
        detail += ("Account and group changes in Active Directory are not reaching RADIUS. The snapshot is no longer refreshed, "
                   "so RADIUS denies everyone when it expires." if not enf["directory_fresh"] else
                   "Account and group changes in Active Directory are not reaching RADIUS until it recovers.")
        add("directory_failed", "critical", "Directory sync is failing", detail, "Fix directory connection", "directory",
            affected=holders, impact_at=deadline if not enf["directory_fresh"] else None, source_at=dc.last_sync_at)

    rs = s.get(m.RadiusSettings, t.id)
    if rs is not None and rs.server_certificate_id:
        sc = s.get(m.Certificate, rs.server_certificate_id)
        if sc is not None and sc.not_after <= now + timedelta(days=30):
            add("server_cert_expiring", "critical", "RADIUS server certificate expires soon" if sc.not_after > now else "RADIUS server certificate has expired",
                "Devices refuse to connect to a server whose certificate has expired. Rotating it is seamless: devices trust the CA, not the certificate.",
                "Rotate server certificate", "radius", affected=holders, impact_at=sc.not_after, source_at=sc.not_before)

    ca = s.scalars(select(m.CertificateAuthority).where(m.CertificateAuthority.tenant_id == t.id, m.CertificateAuthority.role == "issuing")).first()
    if ca is not None and ca.not_after <= now:
        add("issuing_ca_expired", "critical", "Issuing CA has expired",
            "Every certificate it issued has stopped working, and no new ones can be issued. A new issuing CA from the offline root is needed.",
            "Review PKI", "pki", affected=holders, impact_at=ca.not_after, source_at=ca.not_before)
    elif ca is not None and ca.not_after <= now + timedelta(days=180):
        add("issuing_ca_expiring", "warning", "Issuing CA expires within six months",
            "Certificates can't outlive the CA that issued them. Plan a new issuing CA from the offline root before it expires.",
            "Review PKI", "pki", affected=holders, impact_at=ca.not_after, source_at=ca.not_before)
    if ca is not None and ca.not_after > now and ca.crl_next_update is not None and ca.crl_next_update - now <= CRL_WARN:
        lapsed = ca.crl_next_update <= now
        add("crl_expiring", "critical" if ca.crl_next_update - now <= CRL_CRIT else "warning",
            "Revocation list has expired" if lapsed else "Revocation list expires soon",
            ("RADIUS rejects every certificate from this CA until a new list is published. " if lapsed else
             "It's normally rebuilt every day, so the last rebuilds have failed. When it expires, RADIUS rejects every certificate from this CA. ")
            + "Rebuild it from the PKI page, and check the background jobs in System health.",
            "Rebuild revocation list", "pki", affected=holders, impact_at=ca.crl_next_update, source_at=None)
    root = s.scalars(select(m.CertificateAuthority).where(m.CertificateAuthority.tenant_id == t.id, m.CertificateAuthority.role == "root")).first()
    if root is not None and root.crl_next_update is not None and root.crl_next_update - now <= ROOT_CRL_WARN:
        add("root_crl_expiring", "warning", "Root revocation list has expired" if root.crl_next_update <= now else "Root revocation list expires soon",
            "RADIUS checks only the issuing CA's list, so Wi-Fi isn't affected. Devices and controllers that check the whole chain may "
            "start refusing the RADIUS server when it lapses. Renewing it needs the offline root key.",
            "Review PKI", "pki", affected=holders, impact_at=root.crl_next_update, source_at=None)

    for c in s.scalars(select(m.RadiusClient).where(m.RadiusClient.tenant_id == t.id)):
        prof = c.wired_profile or {}
        set_at = prof.get("mode_set_at")
        if "wired" not in (c.networks or []) or prof.get("mode") != "monitor" or not set_at:
            continue
        since = datetime.fromisoformat(set_at)
        if now - since >= MONITOR_NUDGE:
            add(f"wired_monitor:{c.id}", "info", f"{c.name} has been in monitor mode for {(now - since).days} days",
                "Its ports are open: devices that fail 802.1X, or don't try it, still get on the network. Review the evidence and "
                "enforce when every device that should connect is accepted.", "Review the switch", f"radius:client:{c.id}",
                affected=0, impact_at=None, source_at=since)

    # Switch audit: open findings nobody has acknowledged, one item per switch (docs/plans/switch-audit.md §7).
    from app.switchaudit.findings import TEXT as AUDIT_TEXT
    open_rows = s.execute(select(m.SwitchFinding, m.RadiusClient.name).join(m.RadiusClient, m.RadiusClient.id == m.SwitchFinding.client_id)
                          .where(m.SwitchFinding.tenant_id == t.id, m.SwitchFinding.resolved_at.is_(None), m.SwitchFinding.opened_at.is_not(None),
                                 m.SwitchFinding.acknowledged_at.is_(None))
                          .order_by(m.SwitchFinding.opened_at)).all()
    by_switch: dict[uuid.UUID, list] = {}
    for f, name in open_rows:
        by_switch.setdefault(f.client_id, []).append((f, name))
    for cid, rows in by_switch.items():
        crit = [f for f, _ in rows if f.severity == "critical"]
        top = (crit or [f for f, _ in rows])[0]
        n = len(rows)
        where = f" ({top.port})" if top.port else ""
        add(f"switch_audit:{cid}", "critical" if crit else "warning", f"{rows[0][1]}: {n} switch audit finding{'s' if n != 1 else ''}",
            AUDIT_TEXT.get(top.kind, ("", ""))[0] + where + (f" And {n - 1} more." if n > 1 else ""),
            "Review the switch audit", f"radius:client:{cid}", affected=0, impact_at=None, source_at=top.opened_at)

    soon = now + timedelta(days=ps.expiry_warning_days)
    exp = s.execute(select(func.count(), func.min(m.Certificate.not_after), func.count(distinct(m.Certificate.identity_id))).where(
        m.Certificate.tenant_id == t.id, m.Certificate.status == "active", m.Certificate.not_after > now, m.Certificate.not_after <= soon,
        m.Certificate.purpose.in_(m.CLIENT_PURPOSES))).one()
    if exp[0]:
        add("certs_expiring", "warning", f"{exp[0]} certificate{'s' if exp[0] != 1 else ''} expire within {ps.expiry_warning_days} days",
            "Devices that aren't re-enrolled stop connecting when their certificate expires. Create a renewal link from each user's record.",
            "Review expiring certificates", "certificates:expiring", affected=exp[2], impact_at=exp[1], source_at=now)

    day = now - timedelta(hours=24)
    rows = s.execute(select(m.AuthEvent.reason_code, func.count(), func.count(distinct(m.AuthEvent.calling_station_id)), func.max(m.AuthEvent.at))
                     .where(m.AuthEvent.tenant_id == t.id, m.AuthEvent.result == "reject", m.AuthEvent.at >= day,
                            m.AuthEvent.reason_code.in_(ACTIONABLE_REJECTS))
                     .group_by(m.AuthEvent.reason_code).order_by(func.count().desc())).all()
    for reason, n, devices, last in rows:
        if n < 5 and reason != "snapshot_stale":
            continue
        e = explain(reason) or {}
        add(f"rejects:{reason}", "critical" if reason == "snapshot_stale" else "info", f"{n} rejected attempt{'s' if n != 1 else ''}: {e.get('title', reason)}",
            f"{e.get('explanation', '')} {e.get('fix', '')}".strip(), "See the attempts", f"events:{reason}",
            affected=devices, impact_at=None, source_at=last)

    far = datetime.max.replace(tzinfo=UTC)
    items.sort(key=lambda i: (SEVERITY[i["severity"]], datetime.fromisoformat(i["impact_at"]) if i["impact_at"] else far, -i["affected"]))
    return items
