"""Device administration (TACACS+): roles, who may log in, the agent's snapshot part, and event ingest.

docs/plans/device-admin.md. The RADIUS agent's TACACS+ service decides every login from the snapshot part built here,
so logins keep working while the API is down; the API only ever sees the results (admin events).
"""
from __future__ import annotations

import ipaddress
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import models as m
from app.admin.mask import mask_command
from app.pki import crypto

BUILTIN_ROLES = (
    ("Network administrator", 15, "Full access (privilege 15): configuration, reload, everything."),
    ("Read-only", 1, "Privilege 1: show commands that don't reveal the configuration (not show running-config)."),
)
KEY_LENGTH = 40  # characters; ≥ 32 (§7)
ROTATION_GRACE = timedelta(hours=24)
ROLE_CACHE_HOURS = 12
KINDS = ("login", "enable", "authz", "session", "command")
RESULTS = ("pass", "fail", "error", "start", "stop", "update")
_KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"  # no 0/O/1/l/I: read aloud, typed by hand


def new_key() -> str:
    return "".join(secrets.choice(_KEY_ALPHABET) for _ in range(KEY_LENGTH))


def ensure_roles(s: Session, tenant_id: uuid.UUID) -> list[m.AdminRole]:
    roles = list(s.scalars(select(m.AdminRole).where(m.AdminRole.tenant_id == tenant_id).order_by(m.AdminRole.priv_lvl.desc(), m.AdminRole.name)))
    if not any(r.builtin for r in roles):
        for name, lvl, desc in BUILTIN_ROLES:
            r = m.AdminRole(tenant_id=tenant_id, name=name, priv_lvl=lvl, description=desc, builtin=True)
            s.add(r)
            roles.append(r)
        s.flush()
    return roles


def settings_of(s: Session, tenant_id: uuid.UUID, *, create: bool = False) -> m.AdminSettings | None:
    st = s.get(m.AdminSettings, tenant_id)
    if st is None and create:
        st = m.AdminSettings(tenant_id=tenant_id, local_only_usernames=[], retention_days=180)
        s.add(st)
        s.flush()
    return st


def bump(s: Session, tenant_id: uuid.UUID) -> None:
    """Every change to who may log in, roles, devices or keys: the agent fetches the admin part again."""
    rs = s.get(m.RadiusSettings, tenant_id)
    if rs is not None:
        rs.admin_version = (rs.admin_version or 0) + 1


def ad_bind_cap(threshold: int | None) -> int:
    """Mirrors services/radius/agent/tacacs.py ad_bind_cap (a test keeps them equal): failed AD binds per account per
    lockout window, per RADIUS node."""
    if threshold is None:
        return 1
    if threshold <= 0:
        return 5
    return max(1, (threshold - 1) // 2)


def directory_usable(cfg: m.DirectoryConfig | None) -> tuple[bool, str | None]:
    """AD admin logins send the typed password to a domain controller: only over TLS with a verified certificate."""
    if cfg is None or not cfg.enabled:
        return False, "No directory is connected."
    if cfg.transport not in ("ldaps", "starttls"):
        return False, "The directory uses plain LDAP. AD admin logins need LDAPS or StartTLS."
    if not cfg.verify_certificate:
        return False, "Certificate verification is off for the directory. AD admin logins send passwords to the domain controller, so they need it on."
    return True, None


def overlapping_admin_client(s: Session, tenant_id: uuid.UUID, address: str, exclude_id: uuid.UUID | None = None) -> m.RadiusClient | None:
    """TCP 49 is shared by every tenant: an admin-enabled address must not overlap another tenant's (whatever the RADIUS
    ports). Platform-scoped query; within a tenant the longest prefix wins, as for RADIUS."""
    net = ipaddress.ip_network(address.strip(), strict=False)
    for c in s.scalars(select(m.RadiusClient).where(m.RadiusClient.admin_enabled.is_(True), m.RadiusClient.tenant_id != tenant_id)):
        if exclude_id and c.id == exclude_id:
            continue
        try:
            if ipaddress.ip_network(c.address, strict=False).overlaps(net):
                return c
        except ValueError:
            continue
    return None


def candidates(s: Session, tenant_id: uuid.UUID, maps: list[m.AdminGroupMap]) -> list[dict]:
    """Synced directory users that a mapping could admit: enabled and members (transitively, from tokenGroups at sync)
    of at least one mapped group. The login itself checks the live group membership again (§4.5)."""
    if not maps:
        return []
    mapped = {mp.group_id for mp in maps}
    sid_of = {g.id: g.sid for g in s.scalars(select(m.DirectoryGroup).where(m.DirectoryGroup.id.in_(mapped), m.DirectoryGroup.deleted.is_(False)))}
    rows = s.execute(select(m.Identity, m.IdentityGroup.group_id).join(m.IdentityGroup, m.IdentityGroup.identity_id == m.Identity.id)
                     .where(m.Identity.tenant_id == tenant_id, m.Identity.source == "ad", m.Identity.account_state == "enabled",
                            m.IdentityGroup.group_id.in_(mapped))).all()
    out: dict[uuid.UUID, dict] = {}
    for ident, gid in rows:
        if not sid_of.get(gid):
            continue
        d = out.setdefault(ident.id, {"id": str(ident.id), "guid": ident.object_guid, "username": ident.username.lower(),
                                      "upn": (ident.upn or "").lower() or None, "display_name": ident.display_name, "sids": []})
        d["sids"].append(sid_of[gid])
    return sorted(out.values(), key=lambda d: d["username"])


def _ts(dt: datetime | None) -> int | None:
    return int(dt.timestamp()) if dt else None


def build_part(s: Session, tenant_id: uuid.UUID, now: datetime | None = None) -> dict:
    """What the TACACS+ service needs for one tenant. Sensitive (keys, password hashes, TOTP secrets): served only to
    the authenticated agent, which keeps it in a 0600 file."""
    now = now or datetime.now(UTC)
    roles = {r.id: r for r in s.scalars(select(m.AdminRole).where(m.AdminRole.tenant_id == tenant_id))}
    clients = []
    for c in s.scalars(select(m.RadiusClient).where(m.RadiusClient.tenant_id == tenant_id, m.RadiusClient.admin_enabled.is_(True))):
        if not c.tacacs_key_ct:
            continue
        keys = [crypto.decrypt_str(tenant_id, c.tacacs_key_ct)]
        prev_until = c.tacacs_prev_until if c.tacacs_prev_key_ct and c.tacacs_prev_until and c.tacacs_prev_until > now else None
        if prev_until:
            keys.append(crypto.decrypt_str(tenant_id, c.tacacs_prev_key_ct))
        clients.append({"id": str(c.id), "name": c.name, "address": c.address, "site": c.site or "", "vendor": c.vendor,
                        "keys": keys, "prev_until": _ts(prev_until)})
    users = []
    for u in s.scalars(select(m.AdminUser).where(m.AdminUser.tenant_id == tenant_id)):
        role = roles.get(u.role_id)
        if role is None:
            continue
        users.append({"id": str(u.id), "username": u.username, "display_name": u.display_name, "hash": u.password_hash,
                      "totp": crypto.decrypt_str(tenant_id, u.totp_secret_ct) if u.totp_enabled and u.totp_secret_ct else None,
                      "priv": role.priv_lvl, "role": role.name, "sites": [x.lower() for x in (u.sites or [])], "enabled": u.enabled,
                      "expires_at": _ts(u.expires_at), "unlocked_at": _ts(u.unlocked_at)})
    maps = list(s.scalars(select(m.AdminGroupMap).where(m.AdminGroupMap.tenant_id == tenant_id).order_by(m.AdminGroupMap.position, m.AdminGroupMap.created_at)))
    groups = {g.id: g for g in s.scalars(select(m.DirectoryGroup).where(m.DirectoryGroup.id.in_([mp.group_id for mp in maps])))} if maps else {}
    map_out = [{"sid": groups[mp.group_id].sid, "group": groups[mp.group_id].name, "priv": roles[mp.role_id].priv_lvl, "role": roles[mp.role_id].name,
                "sites": [x.lower() for x in (mp.sites or [])]}
               for mp in maps if mp.group_id in groups and groups[mp.group_id].sid and not groups[mp.group_id].deleted and mp.role_id in roles]
    cfg = s.get(m.DirectoryConfig, tenant_id)
    usable, _ = directory_usable(cfg)
    directory = None
    if cfg is not None and map_out:
        # Sent even when it can't be used (plain LDAP, verification off, disabled): a mapped user then gets ERROR (the
        # device's local accounts) rather than FAIL "unknown user".
        directory = {"usable": False}
        if usable:
            directory = {"usable": True, "hosts": list(cfg.hosts), "port": cfg.port, "transport": cfg.transport,
                         "verify": cfg.verify_certificate, "ca_pem": cfg.ca_bundle_pem or None, "domain": cfg.domain.lower(),
                         "lockout_threshold": cfg.lockout_threshold, "lockout_window": cfg.lockout_window}
    st = settings_of(s, tenant_id)
    return {"clients": clients, "users": users, "maps": map_out,
            "candidates": candidates(s, tenant_id, maps) if directory else [],
            "directory": directory, "local_only": sorted({x.lower() for x in (st.local_only_usernames if st else [])}),
            "role_cache_hours": ROLE_CACHE_HOURS}


def snapshot_part(s: Session, tenant_id: uuid.UUID, have: int | None, max_age: int) -> dict:
    """`admin_version` and `admin_valid_until` on every poll; `admin` itself when the agent's copy is another version."""
    rs = s.get(m.RadiusSettings, tenant_id)
    version = rs.admin_version if rs else 0
    out: dict[str, Any] = {"admin_version": version, "admin_valid_until": int(datetime.now(UTC).timestamp()) + max_age}
    if have != version:
        out["admin"] = build_part(s, tenant_id)
    return out


# ── Ingest ───────────────────────────────────────────────────────────────────


def _clean(v: Any, n: int) -> str | None:
    if v is None:
        return None
    text = str(v).replace("\x00", "").strip()
    return text[:n] or None


def _uuid(v: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(v)) if v else None
    except ValueError:
        return None


def ingest(s: Session, items: list[dict]) -> int:
    """Platform-scoped: each event is tagged with its tenant by the TACACS+ service (from the device's address)."""
    from sqlalchemy.dialects.postgresql import insert
    tenants = {str(t) for t in s.scalars(select(m.Tenant.id))}
    now = datetime.now(UTC)
    rows, logins = [], {}
    for e in items:
        tid = str(e.get("tenant") or "")
        if tid not in tenants or not e.get("uid"):
            continue
        kind, result = e.get("kind"), e.get("result")
        if kind not in KINDS or result not in RESULTS:
            continue
        try:
            at = min(datetime.fromtimestamp(float(e.get("ts") or 0), UTC), now) if e.get("ts") else now
        except (TypeError, ValueError, OverflowError, OSError):
            at = now
        priv = e.get("priv_lvl")
        rows.append({"tenant_id": uuid.UUID(tid), "event_uid": str(e["uid"])[:64], "at": at, "client_id": _uuid(e.get("client_id")),
                     "nas_ip": _clean(e.get("nas_ip"), 64), "username": _clean(e.get("username"), 256), "user_id": _uuid(e.get("user_id")),
                     "source": e.get("source") if e.get("source") in ("local", "directory") else None, "kind": kind, "result": result,
                     "reason": _clean(e.get("reason"), 32), "priv_lvl": priv if isinstance(priv, int) and 0 <= priv <= 15 else None,
                     "command": _clean(mask_command(_clean(e.get("command"), 4000)), 4000), "rem_addr": _clean(e.get("rem_addr"), 64),
                     "port": _clean(e.get("port"), 64), "task_id": _clean(e.get("task_id"), 32), "message": _clean(e.get("message"), 500)})
        uid = _uuid(e.get("user_id"))
        if kind == "login" and result == "pass" and e.get("source") == "local" and uid:
            logins[uid] = max(at, logins.get(uid, at))
    if rows:
        s.execute(insert(m.AdminEvent).values(rows).on_conflict_do_nothing(index_elements=["event_uid"]))
    for uid, at in logins.items():
        u = s.get(m.AdminUser, uid)
        if u is not None and (u.last_login_at is None or at > u.last_login_at):
            u.last_login_at = at
    return len(rows)
