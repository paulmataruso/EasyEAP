"""Device administration (docs/plans/device-admin.md §6): administrators log in to switches and controllers with
their AD accounts or EasyEAP's own local accounts, over TACACS+.

Devices are the tenant's registered RADIUS clients; turning admin logins on gives the device a TACACS+ key (shown
once) and a configuration to paste. Every change bumps the admin part of the agent's snapshot.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pyotp
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select

from app import audit
from app import models as m
from app.admin import cisco, passwords
from app.admin import service as svc
from app.db import set_platform, set_tenant
from app.deps import TenantCtx, require
from app.pki import crypto
from app.routers.radius import agent_features, agent_out, controller_address

router = APIRouter(prefix="/api/tenants/{tenant_id}/device-admin", tags=["device-admin"])
LOCK_WINDOW = timedelta(minutes=15)


def _bad(field: str, message: str, code: str | None = None, status_code: int = status.HTTP_422_UNPROCESSABLE_ENTITY) -> HTTPException:
    return HTTPException(status_code, {"field": field, "message": message, **({"code": code} if code else {})})


def _sites(v: list[str]) -> list[str]:
    out = []
    for x in v:
        x = x.strip()
        if x and x.lower() not in {y.lower() for y in out}:
            out.append(x[:120])
    return out


def _client(ctx: TenantCtx, client_id: uuid.UUID) -> m.RadiusClient:
    c = ctx.session.get(m.RadiusClient, client_id)
    if c is None or c.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found.")
    return c


def _user(ctx: TenantCtx, user_id: uuid.UUID) -> m.AdminUser:
    u = ctx.session.get(m.AdminUser, user_id)
    if u is None or u.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Account not found.")
    return u


def _role(ctx: TenantCtx, role_id: uuid.UUID) -> m.AdminRole:
    r = ctx.session.get(m.AdminRole, role_id)
    if r is None or r.tenant_id != ctx.id:
        raise _bad("role_id", "Choose a role.")
    return r


def _locks(ctx: TenantCtx) -> dict[uuid.UUID, datetime]:
    """Local accounts a RADIUS node locked in the last 15 minutes (the failure that started the lock is logged as
    admin_lockout; refusals during it as admin_locked): user id → locked until, unless someone unlocked it since."""
    since = datetime.now(UTC) - LOCK_WINDOW
    out: dict[uuid.UUID, datetime] = {}
    for uid, at in ctx.session.execute(select(m.AdminEvent.user_id, func.max(m.AdminEvent.at)).where(
            m.AdminEvent.tenant_id == ctx.id, m.AdminEvent.reason == "admin_lockout", m.AdminEvent.source == "local",
            m.AdminEvent.at >= since, m.AdminEvent.user_id.is_not(None)).group_by(m.AdminEvent.user_id)):
        out[uid] = at + LOCK_WINDOW
    return out


def device_out(c: m.RadiusClient, last: dict[uuid.UUID, datetime]) -> dict:
    now = datetime.now(UTC)
    return {"id": str(c.id), "name": c.name, "vendor": c.vendor, "address": c.address, "site": c.site,
            "admin_enabled": c.admin_enabled, "supported": c.vendor in cisco.SUPPORTED, "not_supported": cisco.NOT_SUPPORTED.get(c.vendor),
            "key_set_at": c.tacacs_key_set_at.isoformat() if c.tacacs_key_set_at else None,
            "previous_key_until": c.tacacs_prev_until.isoformat() if c.tacacs_prev_key_ct and c.tacacs_prev_until and c.tacacs_prev_until > now else None,
            "classic": (c.wired_profile or {}).get("platform") == "classic",
            "last_login_at": last[c.id].isoformat() if c.id in last else None}


def user_out(u: m.AdminUser, roles: dict[uuid.UUID, m.AdminRole], locks: dict[uuid.UUID, datetime], clash: set[str]) -> dict:
    now = datetime.now(UTC)
    r = roles.get(u.role_id)
    locked = locks.get(u.id)
    if locked and (locked <= now or (u.unlocked_at and u.unlocked_at >= locked - LOCK_WINDOW)):  # expired, or unlocked since
        locked = None
    status_ = ("disabled" if not u.enabled else "expired" if u.expires_at and u.expires_at <= now else "locked" if locked
               else "no_password" if not u.password_hash else "active")
    return {"id": str(u.id), "username": u.username, "display_name": u.display_name, "email": u.email,
            "role_id": str(u.role_id), "role": r.name if r else None, "priv_lvl": r.priv_lvl if r else None, "sites": u.sites or [],
            "enabled": u.enabled, "expires_at": u.expires_at.isoformat() if u.expires_at else None, "has_password": bool(u.password_hash),
            "password_set_at": u.password_set_at.isoformat() if u.password_set_at else None, "totp_enabled": u.totp_enabled,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None, "locked_until": locked.isoformat() if locked else None,
            "status": status_, "clashes_with_directory": u.username in clash, "created_at": u.created_at.isoformat() if u.created_at else None,
            "created_by": u.created_by}


def role_out(r: m.AdminRole, used: int) -> dict:
    return {"id": str(r.id), "name": r.name, "priv_lvl": r.priv_lvl, "description": r.description, "builtin": r.builtin, "used": used}


def _admits(ctx: TenantCtx, maps: list[m.AdminGroupMap], roles: dict[uuid.UUID, m.AdminRole]) -> list[dict]:
    """Who the mappings admit now (synced membership), with the role the first matching mapping gives."""
    groups = {g.id: g for g in ctx.session.scalars(select(m.DirectoryGroup).where(m.DirectoryGroup.id.in_([mp.group_id for mp in maps])))} if maps else {}
    sid_to_map = [(groups[mp.group_id].sid, mp) for mp in maps if mp.group_id in groups and groups[mp.group_id].sid and not groups[mp.group_id].deleted]
    out = []
    for c in svc.candidates(ctx.session, ctx.id, maps):
        first = next((mp for sid, mp in sid_to_map if sid in c["sids"]), None)
        if first is None:
            continue
        r = roles.get(first.role_id)
        out.append({"id": c["id"], "username": c["username"], "upn": c["upn"], "display_name": c["display_name"],
                    "role": r.name if r else None, "priv_lvl": r.priv_lvl if r else None, "group": groups[first.group_id].name,
                    "sites": first.sites or []})
    return out


@router.get("")
def overview(ctx: TenantCtx = Depends(require("admin:read"))) -> dict:
    s = ctx.session
    roles_list = svc.ensure_roles(s, ctx.id)
    roles = {r.id: r for r in roles_list}
    clients = list(s.scalars(select(m.RadiusClient).where(m.RadiusClient.tenant_id == ctx.id).order_by(m.RadiusClient.name)))
    last = dict(s.execute(select(m.AdminEvent.client_id, func.max(m.AdminEvent.at)).where(
        m.AdminEvent.tenant_id == ctx.id, m.AdminEvent.kind == "login", m.AdminEvent.result == "pass").group_by(m.AdminEvent.client_id)).all())
    users = list(s.scalars(select(m.AdminUser).where(m.AdminUser.tenant_id == ctx.id).order_by(m.AdminUser.username)))
    maps = list(s.scalars(select(m.AdminGroupMap).where(m.AdminGroupMap.tenant_id == ctx.id).order_by(m.AdminGroupMap.position, m.AdminGroupMap.created_at)))
    admits = _admits(ctx, maps, roles)
    names = {a["username"] for a in admits}
    locks = _locks(ctx)
    used = {rid: n for rid, n in s.execute(select(m.AdminUser.role_id, func.count()).where(m.AdminUser.tenant_id == ctx.id).group_by(m.AdminUser.role_id))}
    for mp in maps:
        used[mp.role_id] = used.get(mp.role_id, 0) + 1
    groups = {g.id: g for g in s.scalars(select(m.DirectoryGroup).where(m.DirectoryGroup.id.in_([mp.group_id for mp in maps])))} if maps else {}
    per_map: dict[str, int] = {}
    for a in admits:
        per_map[a["group"]] = per_map.get(a["group"], 0) + 1
    cfg = s.get(m.DirectoryConfig, ctx.id)
    usable, problem = svc.directory_usable(cfg)
    st = svc.settings_of(s, ctx.id)
    rs = s.get(m.RadiusSettings, ctx.id)
    agent = agent_out(s)
    detail = (agent or {}).get("detail") or {}
    versions = detail.get("admin_versions")
    feats = agent_features(s)
    return {
        "devices": [device_out(c, last) for c in clients],
        "users": [user_out(u, roles, locks, names) for u in users],
        "roles": [role_out(r, used.get(r.id, 0)) for r in roles_list],
        "maps": [{"id": str(mp.id), "group_id": str(mp.group_id), "group": groups[mp.group_id].name if mp.group_id in groups else None,
                  "group_deleted": mp.group_id not in groups or groups[mp.group_id].deleted, "role_id": str(mp.role_id),
                  "role": roles[mp.role_id].name if mp.role_id in roles else None, "priv_lvl": roles[mp.role_id].priv_lvl if mp.role_id in roles else None,
                  "sites": mp.sites or [], "position": i, "admits": per_map.get(groups[mp.group_id].name, 0) if mp.group_id in groups else 0}
                 for i, mp in enumerate(maps)],
        "admits": admits,
        "directory": {"connected": cfg is not None and cfg.enabled, "usable": usable, "problem": problem, "domain": cfg.domain if cfg else None,
                      "lockout_threshold": cfg.lockout_threshold if cfg else None,
                      "lockout_window_minutes": max(30, (cfg.lockout_window or 0) // 60) if cfg else 30,
                      "bind_cap": svc.ad_bind_cap(cfg.lockout_threshold if cfg else None)},
        "settings": {"local_only_usernames": (st.local_only_usernames if st else []) or [], "retention_days": st.retention_days if st else 180},
        "agent": {"supported": "tacacs" in feats, "online": bool(agent and agent.get("online")),
                  "in_sync": (versions.get(str(ctx.id)) == rs.admin_version) if isinstance(versions, dict) and rs else None,
                  "running": detail.get("tacacs_running")},
        "server": {**controller_address(), "port": cisco.PORT},
        "radius_configured": rs is not None,
    }


# ── Devices ─────────────────────────────────────────────────────────────────


class EnableIn(BaseModel):
    enabled: bool


@router.post("/devices/{client_id}/enable")
def set_enabled(client_id: uuid.UUID, body: EnableIn, ctx: TenantCtx = Depends(require("admin:write"))) -> dict:
    s = ctx.session
    c = _client(ctx, client_id)
    if s.get(m.RadiusSettings, ctx.id) is None:
        raise _bad("enabled", "Save the RADIUS settings first.")
    key = None
    if body.enabled and not c.admin_enabled:
        if c.vendor not in cisco.SUPPORTED:
            raise _bad("enabled", cisco.NOT_SUPPORTED.get(c.vendor) or "Not supported for this device.", "not_supported")
        if "tacacs" not in agent_features(s):
            raise _bad("enabled", "RADIUS needs updating before admin logins can be turned on (System health shows its version).", "agent_too_old",
                       status.HTTP_409_CONFLICT)
        set_platform(s)
        try:
            clash = svc.overlapping_admin_client(s, ctx.id, c.address, c.id)
        finally:
            set_tenant(s, ctx.id)
        if clash is not None:
            raise _bad("enabled", "This device's address overlaps a device of another tenant that has admin logins on. Each device needs a "
                                  "unique management address for TACACS+.", "address_overlap", status.HTTP_409_CONFLICT)
        if not c.tacacs_key_ct:
            key = svc.new_key()
            c.tacacs_key_ct, c.tacacs_key_set_at = crypto.encrypt(ctx.id, key), datetime.now(UTC)
    if body.enabled != c.admin_enabled:
        c.admin_enabled = body.enabled
        svc.bump(s, ctx.id)
        audit.record(s, ctx.actor, "device_admin.device_enabled" if body.enabled else "device_admin.device_disabled", tenant_id=ctx.id,
                     target_type="radius_client", target_id=c.id, target_label=c.name)
    # The key is returned once, when it is created; afterwards only a rotation shows a new one.
    return {"device": device_out(c, {}), "key": key}


@router.post("/devices/{client_id}/rotate-key")
def rotate_key(client_id: uuid.UUID, ctx: TenantCtx = Depends(require("admin:write"))) -> dict:
    s = ctx.session
    c = _client(ctx, client_id)
    if not c.admin_enabled:
        raise _bad("key", "Turn admin logins on first.")
    key = svc.new_key()
    now = datetime.now(UTC)
    # The old key keeps working for a day, so devices can be changed one by one.
    c.tacacs_prev_key_ct, c.tacacs_prev_until = c.tacacs_key_ct, now + svc.ROTATION_GRACE
    c.tacacs_key_ct, c.tacacs_key_set_at = crypto.encrypt(ctx.id, key), now
    svc.bump(s, ctx.id)
    audit.record(s, ctx.actor, "device_admin.key_rotated", tenant_id=ctx.id, target_type="radius_client", target_id=c.id, target_label=c.name)
    return {"device": device_out(c, {}), "key": key}


@router.get("/devices/{client_id}/config")
def device_config(client_id: uuid.UUID, legacy: bool = False, ctx: TenantCtx = Depends(require("admin:read"))) -> dict:
    c = _client(ctx, client_id)
    if c.vendor not in cisco.SUPPORTED:
        raise _bad("vendor", cisco.NOT_SUPPORTED.get(c.vendor) or "Not supported for this device.", "not_supported")
    return cisco.guide(cisco.ctx_for(c, ctx.tenant, controller_address()["radius_address"], legacy=legacy))


# ── Local accounts ──────────────────────────────────────────────────────────


class UserIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    display_name: str = Field(default="", max_length=120)
    email: str = Field(default="", max_length=254)
    role_id: uuid.UUID
    sites: list[str] = Field(default_factory=list, max_length=50)
    expires_at: datetime | None = None
    password: str | None = Field(default=None, max_length=256)

    @field_validator("username")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip().lower()
        if not passwords.USERNAME.match(v):
            raise ValueError("Use lowercase letters, digits, dot, dash and underscore (up to 64).")
        return v


class UserUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=120)
    email: str | None = Field(default=None, max_length=254)
    role_id: uuid.UUID | None = None
    sites: list[str] | None = Field(default=None, max_length=50)
    enabled: bool | None = None
    expires_at: datetime | None = None


def _check_password(password: str, username: str, totp: bool) -> None:
    problems = passwords.problems(password, username=username, totp=totp)
    if problems:
        raise _bad("password", " ".join(problems), "weak_password")


def _overview_user(ctx: TenantCtx, u: m.AdminUser) -> dict:
    roles = {r.id: r for r in ctx.session.scalars(select(m.AdminRole).where(m.AdminRole.tenant_id == ctx.id))}
    names = {c["username"] for c in svc.candidates(ctx.session, ctx.id, list(ctx.session.scalars(
        select(m.AdminGroupMap).where(m.AdminGroupMap.tenant_id == ctx.id))))}
    return user_out(u, roles, _locks(ctx), names)


@router.post("/users", status_code=201)
def create_user(body: UserIn, ctx: TenantCtx = Depends(require("admin:write"))) -> dict:
    s = ctx.session
    svc.ensure_roles(s, ctx.id)
    _role(ctx, body.role_id)
    if s.scalar(select(m.AdminUser.id).where(m.AdminUser.tenant_id == ctx.id, m.AdminUser.username == body.username)):
        raise _bad("username", "An account with this username exists.", "duplicate")
    st = svc.settings_of(s, ctx.id)
    if st and body.username in {x.lower() for x in st.local_only_usernames or []}:
        raise _bad("username", "This name is a local-only username: devices always use their own account for it.", "local_only")
    u = m.AdminUser(tenant_id=ctx.id, username=body.username, display_name=body.display_name.strip(), email=body.email.strip(),
                    role_id=body.role_id, sites=_sites(body.sites), expires_at=body.expires_at, enabled=True, created_by=ctx.actor.label[:254])
    if body.password:
        _check_password(body.password, body.username, totp=False)
        u.password_hash, u.password_set_at = passwords.hash_password(body.password), datetime.now(UTC)
    s.add(u)
    s.flush()
    svc.bump(s, ctx.id)
    audit.record(s, ctx.actor, "device_admin.user_created", tenant_id=ctx.id, target_type="admin_user", target_id=u.id, target_label=u.username,
                 detail={"role_id": str(body.role_id), "sites": u.sites, "password_set": bool(body.password)})
    return {"user": _overview_user(ctx, u)}


@router.patch("/users/{user_id}")
def update_user(user_id: uuid.UUID, body: UserUpdate, ctx: TenantCtx = Depends(require("admin:write"))) -> dict:
    s = ctx.session
    u = _user(ctx, user_id)
    given = body.model_dump(exclude_unset=True)
    if given.get("role_id"):
        _role(ctx, body.role_id)
        u.role_id = body.role_id
    if "sites" in given and body.sites is not None:
        u.sites = _sites(body.sites)
    for k in ("display_name", "email"):
        if given.get(k) is not None:
            setattr(u, k, given[k].strip())
    if "enabled" in given and body.enabled is not None:
        u.enabled = body.enabled
    if "expires_at" in given:
        u.expires_at = body.expires_at
    svc.bump(s, ctx.id)
    audit.record(s, ctx.actor, "device_admin.user_updated", tenant_id=ctx.id, target_type="admin_user", target_id=u.id, target_label=u.username,
                 detail={k: (str(v) if isinstance(v, (uuid.UUID, datetime)) else v) for k, v in given.items()})
    return {"user": _overview_user(ctx, u)}


class PasswordIn(BaseModel):
    password: str = Field(min_length=1, max_length=256)


@router.post("/users/{user_id}/password")
def set_password(user_id: uuid.UUID, body: PasswordIn, ctx: TenantCtx = Depends(require("admin:write"))) -> dict:
    u = _user(ctx, user_id)
    _check_password(body.password, u.username, totp=u.totp_enabled)
    u.password_hash, u.password_set_at = passwords.hash_password(body.password), datetime.now(UTC)
    svc.bump(ctx.session, ctx.id)
    audit.record(ctx.session, ctx.actor, "device_admin.password_set", tenant_id=ctx.id, target_type="admin_user", target_id=u.id, target_label=u.username)
    return {"user": _overview_user(ctx, u)}


@router.post("/users/{user_id}/totp/setup")
def totp_setup(user_id: uuid.UUID, ctx: TenantCtx = Depends(require("admin:write"))) -> dict:
    u = _user(ctx, user_id)
    if u.totp_enabled:
        raise _bad("totp", "This account already uses an authenticator code. Remove it first to set up a new one.")
    secret = pyotp.random_base32()
    u.totp_secret_ct = crypto.encrypt(ctx.id, secret)
    return {"secret": secret, "otpauth_uri": pyotp.TOTP(secret).provisioning_uri(name=u.username, issuer_name=f"EasyEAP device admin ({ctx.tenant.slug})")}


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=10)


@router.post("/users/{user_id}/totp/confirm")
def totp_confirm(user_id: uuid.UUID, body: CodeIn, ctx: TenantCtx = Depends(require("admin:write"))) -> dict:
    u = _user(ctx, user_id)
    if not u.totp_secret_ct or u.totp_enabled:
        raise _bad("code", "Start the authenticator setup first.")
    if not pyotp.TOTP(crypto.decrypt_str(ctx.id, u.totp_secret_ct)).verify(body.code.replace(" ", ""), valid_window=1):
        raise _bad("code", "That code didn't match. Check the authenticator app's clock and try again.", "bad_code")
    u.totp_enabled = True
    svc.bump(ctx.session, ctx.id)
    audit.record(ctx.session, ctx.actor, "device_admin.totp_enabled", tenant_id=ctx.id, target_type="admin_user", target_id=u.id, target_label=u.username)
    return {"user": _overview_user(ctx, u)}


@router.post("/users/{user_id}/totp/remove")
def totp_remove(user_id: uuid.UUID, body: PasswordIn, ctx: TenantCtx = Depends(require("admin:write"))) -> dict:
    """Without the second factor the password must meet the longer rule, so removing it sets a new password too."""
    u = _user(ctx, user_id)
    _check_password(body.password, u.username, totp=False)
    u.totp_enabled, u.totp_secret_ct = False, None
    u.password_hash, u.password_set_at = passwords.hash_password(body.password), datetime.now(UTC)
    svc.bump(ctx.session, ctx.id)
    audit.record(ctx.session, ctx.actor, "device_admin.totp_removed", tenant_id=ctx.id, target_type="admin_user", target_id=u.id, target_label=u.username)
    return {"user": _overview_user(ctx, u)}


@router.post("/users/{user_id}/unlock")
def unlock_user(user_id: uuid.UUID, ctx: TenantCtx = Depends(require("admin:write"))) -> dict:
    u = _user(ctx, user_id)
    u.unlocked_at = datetime.now(UTC)
    svc.bump(ctx.session, ctx.id)
    audit.record(ctx.session, ctx.actor, "device_admin.user_unlocked", tenant_id=ctx.id, target_type="admin_user", target_id=u.id, target_label=u.username)
    return {"user": _overview_user(ctx, u)}


@router.delete("/users/{user_id}")
def delete_user(user_id: uuid.UUID, ctx: TenantCtx = Depends(require("admin:write"))) -> dict:
    u = _user(ctx, user_id)
    name = u.username
    ctx.session.delete(u)
    svc.bump(ctx.session, ctx.id)
    audit.record(ctx.session, ctx.actor, "device_admin.user_deleted", tenant_id=ctx.id, target_type="admin_user", target_id=user_id, target_label=name)
    return {"ok": True}


# ── Directory access (AD group → role) ──────────────────────────────────────


class MapIn(BaseModel):
    group_id: uuid.UUID
    role_id: uuid.UUID
    sites: list[str] = Field(default_factory=list, max_length=50)


class MapUpdate(BaseModel):
    role_id: uuid.UUID | None = None
    sites: list[str] | None = Field(default=None, max_length=50)


class OrderIn(BaseModel):
    ids: list[uuid.UUID] = Field(max_length=500)


@router.post("/maps", status_code=201)
def create_map(body: MapIn, ctx: TenantCtx = Depends(require("admin:write"))) -> dict:
    s = ctx.session
    _role(ctx, body.role_id)
    g = s.get(m.DirectoryGroup, body.group_id)
    if g is None or g.tenant_id != ctx.id or g.deleted:
        raise _bad("group_id", "Choose a directory group.")
    if g.source != "ad" or not g.sid:
        raise _bad("group_id", "Only Active Directory groups can be mapped: logins check the group in AD itself.", "not_ad")
    if s.scalar(select(m.AdminGroupMap.id).where(m.AdminGroupMap.tenant_id == ctx.id, m.AdminGroupMap.group_id == g.id)):
        raise _bad("group_id", "This group is already mapped.", "duplicate")
    pos = (s.scalar(select(func.max(m.AdminGroupMap.position)).where(m.AdminGroupMap.tenant_id == ctx.id)) or 0) + 1
    mp = m.AdminGroupMap(tenant_id=ctx.id, group_id=g.id, role_id=body.role_id, sites=_sites(body.sites), position=pos)
    s.add(mp)
    s.flush()
    svc.bump(s, ctx.id)
    audit.record(s, ctx.actor, "device_admin.map_created", tenant_id=ctx.id, target_type="admin_group_map", target_id=mp.id, target_label=g.name,
                 detail={"role_id": str(body.role_id), "sites": mp.sites})
    return {"id": str(mp.id)}


@router.patch("/maps/{map_id}")
def update_map(map_id: uuid.UUID, body: MapUpdate, ctx: TenantCtx = Depends(require("admin:write"))) -> dict:
    s = ctx.session
    mp = s.get(m.AdminGroupMap, map_id)
    if mp is None or mp.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Mapping not found.")
    if body.role_id:
        _role(ctx, body.role_id)
        mp.role_id = body.role_id
    if body.sites is not None:
        mp.sites = _sites(body.sites)
    svc.bump(s, ctx.id)
    audit.record(s, ctx.actor, "device_admin.map_updated", tenant_id=ctx.id, target_type="admin_group_map", target_id=mp.id,
                 detail={"role_id": str(mp.role_id), "sites": mp.sites})
    return {"ok": True}


@router.post("/maps/order")
def order_maps(body: OrderIn, ctx: TenantCtx = Depends(require("admin:write"))) -> dict:
    s = ctx.session
    maps = {mp.id: mp for mp in s.scalars(select(m.AdminGroupMap).where(m.AdminGroupMap.tenant_id == ctx.id))}
    if set(body.ids) != set(maps):
        raise _bad("ids", "List every mapping once.")
    for i, mid in enumerate(body.ids):
        maps[mid].position = i
    svc.bump(s, ctx.id)
    audit.record(s, ctx.actor, "device_admin.maps_reordered", tenant_id=ctx.id, target_type="admin_group_map", detail={"ids": [str(x) for x in body.ids]})
    return {"ok": True}


@router.delete("/maps/{map_id}")
def delete_map(map_id: uuid.UUID, ctx: TenantCtx = Depends(require("admin:write"))) -> dict:
    s = ctx.session
    mp = s.get(m.AdminGroupMap, map_id)
    if mp is None or mp.tenant_id != ctx.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Mapping not found.")
    s.delete(mp)
    svc.bump(s, ctx.id)
    audit.record(s, ctx.actor, "device_admin.map_deleted", tenant_id=ctx.id, target_type="admin_group_map", target_id=map_id)
    return {"ok": True}


# ── Roles ───────────────────────────────────────────────────────────────────


class RoleIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    priv_lvl: int = Field(ge=0, le=15)
    description: str = Field(default="", max_length=300)


@router.post("/roles", status_code=201)
def create_role(body: RoleIn, ctx: TenantCtx = Depends(require("admin:write"))) -> dict:
    s = ctx.session
    svc.ensure_roles(s, ctx.id)
    if s.scalar(select(m.AdminRole.id).where(m.AdminRole.tenant_id == ctx.id, func.lower(m.AdminRole.name) == body.name.strip().lower())):
        raise _bad("name", "A role with this name exists.", "duplicate")
    r = m.AdminRole(tenant_id=ctx.id, name=body.name.strip(), priv_lvl=body.priv_lvl, description=body.description.strip(), builtin=False)
    s.add(r)
    s.flush()
    audit.record(s, ctx.actor, "device_admin.role_created", tenant_id=ctx.id, target_type="admin_role", target_id=r.id, target_label=r.name,
                 detail={"priv_lvl": r.priv_lvl})
    return {"role": role_out(r, 0)}


@router.put("/roles/{role_id}")
def update_role(role_id: uuid.UUID, body: RoleIn, ctx: TenantCtx = Depends(require("admin:write"))) -> dict:
    s = ctx.session
    r = _role(ctx, role_id)
    if r.builtin and (body.priv_lvl != r.priv_lvl or body.name.strip() != r.name):
        raise _bad("name", "Built-in roles keep their name and level. Create a role for a different level.", "builtin")
    if s.scalar(select(m.AdminRole.id).where(m.AdminRole.tenant_id == ctx.id, m.AdminRole.id != r.id, func.lower(m.AdminRole.name) == body.name.strip().lower())):
        raise _bad("name", "A role with this name exists.", "duplicate")
    r.name, r.priv_lvl, r.description = body.name.strip(), body.priv_lvl, body.description.strip()
    svc.bump(s, ctx.id)
    audit.record(s, ctx.actor, "device_admin.role_updated", tenant_id=ctx.id, target_type="admin_role", target_id=r.id, target_label=r.name,
                 detail={"priv_lvl": r.priv_lvl})
    return {"role": role_out(r, 0)}


@router.delete("/roles/{role_id}")
def delete_role(role_id: uuid.UUID, ctx: TenantCtx = Depends(require("admin:write"))) -> dict:
    s = ctx.session
    r = _role(ctx, role_id)
    if r.builtin:
        raise _bad("role_id", "Built-in roles can't be deleted.", "builtin")
    if s.scalar(select(m.AdminUser.id).where(m.AdminUser.role_id == r.id).limit(1)) or s.scalar(select(m.AdminGroupMap.id).where(m.AdminGroupMap.role_id == r.id).limit(1)):
        raise _bad("role_id", "Accounts or directory mappings use this role. Give them another role first.", "in_use")
    s.delete(r)
    audit.record(s, ctx.actor, "device_admin.role_deleted", tenant_id=ctx.id, target_type="admin_role", target_id=role_id, target_label=r.name)
    return {"ok": True}


# ── Settings ────────────────────────────────────────────────────────────────


class SettingsIn(BaseModel):
    local_only_usernames: list[str] = Field(default_factory=list, max_length=50)
    retention_days: int = Field(default=180, ge=30, le=730)

    @field_validator("local_only_usernames")
    @classmethod
    def _names(cls, v: list[str]) -> list[str]:
        out = []
        for x in v:
            x = x.strip().lower()
            if not x:
                continue
            if len(x) > 64 or any(ch.isspace() for ch in x):
                raise ValueError("Usernames have no spaces and up to 64 characters.")
            if x not in out:
                out.append(x)
        return out


@router.put("/settings")
def save_settings(body: SettingsIn, ctx: TenantCtx = Depends(require("admin:write"))) -> dict:
    s = ctx.session
    st = svc.settings_of(s, ctx.id, create=True)
    clash = s.scalars(select(m.AdminUser.username).where(m.AdminUser.tenant_id == ctx.id, m.AdminUser.username.in_(body.local_only_usernames))).all()
    if clash:
        raise _bad("local_only_usernames", f"EasyEAP accounts use these names: {', '.join(clash)}. Rename or delete them first.", "clash")
    st.local_only_usernames, st.retention_days = body.local_only_usernames, body.retention_days
    svc.bump(s, ctx.id)
    audit.record(s, ctx.actor, "device_admin.settings_saved", tenant_id=ctx.id, target_type="admin_settings",
                 detail={"local_only_usernames": body.local_only_usernames, "retention_days": body.retention_days})
    return {"settings": {"local_only_usernames": st.local_only_usernames, "retention_days": st.retention_days}}


# ── Admin log ───────────────────────────────────────────────────────────────


def event_out(e: m.AdminEvent, clients: dict[uuid.UUID, str]) -> dict:
    return {"id": e.id, "at": e.at.isoformat(), "client_id": str(e.client_id) if e.client_id else None,
            "client": clients.get(e.client_id) if e.client_id else None, "nas_ip": e.nas_ip, "username": e.username,
            "user_id": str(e.user_id) if e.user_id else None, "source": e.source, "kind": e.kind, "result": e.result, "reason": e.reason,
            "priv_lvl": e.priv_lvl, "command": e.command, "rem_addr": e.rem_addr, "port": e.port, "task_id": e.task_id, "message": e.message}


@router.get("/events")
def list_events(ctx: TenantCtx = Depends(require("admin:read")), hours: int = Query(24, ge=1, le=24 * 730),
                kind: str = Query("", pattern="^(|login|enable|authz|session|command)$"), result: str = Query("", pattern="^(|pass|fail|error)$"),
                client_id: uuid.UUID | None = None, user_id: uuid.UUID | None = None, q: str = Query("", max_length=100),
                before_id: int | None = None, page_size: int = Query(100, ge=1, le=500)) -> dict:
    s = ctx.session
    stmt = select(m.AdminEvent).where(m.AdminEvent.tenant_id == ctx.id, m.AdminEvent.at >= datetime.now(UTC) - timedelta(hours=hours))
    if kind:
        stmt = stmt.where(m.AdminEvent.kind == kind)
    if result:
        stmt = stmt.where(m.AdminEvent.result == result)
    if client_id:
        stmt = stmt.where(m.AdminEvent.client_id == client_id)
    if user_id:
        stmt = stmt.where(m.AdminEvent.user_id == user_id)
    if q.strip():
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(m.AdminEvent.username.ilike(like), m.AdminEvent.command.ilike(like), m.AdminEvent.rem_addr.ilike(like),
                              m.AdminEvent.nas_ip.ilike(like)))
    if before_id:
        stmt = stmt.where(m.AdminEvent.id < before_id)
    rows = s.scalars(stmt.order_by(m.AdminEvent.id.desc()).limit(page_size)).all()
    clients = {c.id: c.name for c in s.scalars(select(m.RadiusClient).where(m.RadiusClient.tenant_id == ctx.id))}
    return {"items": [event_out(e, clients) for e in rows], "next_before_id": rows[-1].id if len(rows) == page_size else None}


@router.get("/search")
def search(q: str = Query(min_length=2, max_length=64), ctx: TenantCtx = Depends(require("admin:read"))) -> dict:
    like = f"%{q.strip().lower()}%"
    rows = ctx.session.scalars(select(m.AdminUser).where(m.AdminUser.tenant_id == ctx.id, or_(m.AdminUser.username.ilike(like),
                                                                                              m.AdminUser.display_name.ilike(like))).limit(10)).all()
    return {"items": [{"id": str(u.id), "username": u.username, "display_name": u.display_name} for u in rows]}
