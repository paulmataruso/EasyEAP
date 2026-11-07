"""Directory synchronisation into identities/groups, then policy recomputation."""
from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import models as m
from app.directory import ldap
from app.pki import crypto

log = logging.getLogger("easyeap.directory")
SAFETY_DELETE_FRACTION = 0.5


def params(cfg: m.DirectoryConfig, password: str | None = None) -> ldap.DirectoryParams:
    return ldap.DirectoryParams(
        hosts=list(cfg.hosts), port=cfg.port, transport=cfg.transport, verify_certificate=cfg.verify_certificate,
        ca_bundle_pem=cfg.ca_bundle_pem, base_dn=cfg.base_dn, user_search_base=cfg.user_search_base,
        group_search_base=cfg.group_search_base, user_filter=cfg.user_filter, group_filter=cfg.group_filter,
        bind_dn=cfg.bind_dn, bind_password=password if password is not None else crypto.decrypt_str(cfg.tenant_id, cfg.bind_password_ct),
    )


def sync_tenant(session: Session, tenant_id: uuid.UUID, *, force: bool = False) -> dict:
    cfg = session.get(m.DirectoryConfig, tenant_id)
    if cfg is None or not cfg.enabled:
        return {"skipped": True}
    started = datetime.now(UTC)
    try:
        conn = ldap.connect(params(cfg))
        try:
            groups = ldap.fetch_groups(conn, params(cfg))
            users = ldap.fetch_users(conn, params(cfg))
            threshold, window = ldap.lockout_policy(conn, cfg.base_dn)
        finally:
            conn.unbind()
    except Exception as exc:  # noqa: BLE001 — recorded, never silently ignored
        cfg.last_sync_at, cfg.last_sync_status = started, "failed"
        cfg.last_sync_error = f"{exc}" + (f" — {exc.hint}" if isinstance(exc, ldap.DirectoryError) and exc.hint else "") + \
            (f" ({exc.detail})" if isinstance(exc, ldap.DirectoryError) and exc.detail else "")
        log.warning("Directory sync failed for tenant %s: %s", tenant_id, exc)
        return {"ok": False, "error": cfg.last_sync_error}

    existing_users = {i.object_guid: i for i in session.scalars(select(m.Identity).where(m.Identity.tenant_id == tenant_id, m.Identity.source == "ad"))}
    seen = {u.object_guid for u in users}
    to_delete = [i for g, i in existing_users.items() if g not in seen and i.account_state != "deleted"]
    active_known = len([i for i in existing_users.values() if i.account_state != "deleted"])
    if not force and active_known >= 10 and len(to_delete) > active_known * SAFETY_DELETE_FRACTION:
        cfg.last_sync_at, cfg.last_sync_status = started, "failed"
        cfg.last_sync_error = (f"Safety stop: this sync would mark {len(to_delete)} of {active_known} users as deleted. "
                               "Check the search base and filter, then run a forced sync if the change is intended.")
        return {"ok": False, "error": cfg.last_sync_error}

    # Groups
    existing_groups = {g.object_guid: g for g in session.scalars(select(m.DirectoryGroup).where(m.DirectoryGroup.tenant_id == tenant_id, m.DirectoryGroup.source == "ad"))}
    by_sid: dict[str, m.DirectoryGroup] = {}
    seen_groups = set()
    for g in groups:
        row = existing_groups.get(g.object_guid)
        if row is None:
            row = m.DirectoryGroup(tenant_id=tenant_id, object_guid=g.object_guid, source="ad", dn=g.dn, name=g.name, sid=g.sid)
            session.add(row)
        row.dn, row.name, row.sid, row.deleted = g.dn, g.name, g.sid, False
        seen_groups.add(g.object_guid)
        if g.sid:
            by_sid[g.sid] = row
    for guid, row in existing_groups.items():
        if guid not in seen_groups:
            row.deleted = True
    session.flush()

    # Users
    created = updated = 0
    taken_usernames = {i.username.lower(): i for i in existing_users.values()}
    for u in users:
        row = existing_users.get(u.object_guid)
        if row is None:
            clash = taken_usernames.get(u.username.lower())
            if clash is not None and clash.object_guid != u.object_guid:
                clash.username = f"{clash.username}~{clash.object_guid[:8]}"  # renamed/recreated account keeps history
            row = m.Identity(tenant_id=tenant_id, source="ad", object_guid=u.object_guid, username=u.username, display_name=u.display_name)
            session.add(row)
            created += 1
        else:
            updated += 1
        row.username, row.upn, row.email, row.display_name = u.username, u.upn, u.email, u.display_name
        row.department, row.title, row.account_state, row.last_synced_at = u.department, u.title, u.account_state, started
        row.groups = [by_sid[s] for s in u.group_sids if s in by_sid]
    for row in to_delete:
        row.account_state = "deleted"
        row.groups = []
    session.flush()

    # Device administration: who a group mapping admits may have changed, and the AD bind cap follows the lockout
    # threshold (docs/plans/device-admin.md §4).
    if threshold is not None:
        cfg.lockout_threshold, cfg.lockout_window = threshold, window
    if session.scalar(select(m.AdminGroupMap.id).where(m.AdminGroupMap.tenant_id == tenant_id).limit(1)) is not None:
        from app.admin.service import bump as admin_bump
        admin_bump(session, tenant_id)

    from app.policy.service import recompute_tenant  # local import avoids a cycle
    decisions = recompute_tenant(session, tenant_id)
    stats = {"users": len(users), "groups": len(groups), "created": created, "updated": updated, "deleted": len(to_delete),
             "decisions": decisions, "duration_ms": int((datetime.now(UTC) - started).total_seconds() * 1000)}
    cfg.last_sync_at, cfg.last_sync_status, cfg.last_sync_error, cfg.last_sync_stats = started, "ok", None, stats
    return {"ok": True, **stats}
