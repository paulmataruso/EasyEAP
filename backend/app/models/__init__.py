"""SQLAlchemy models. Tenant-scoped tables carry tenant_id and are protected by row-level security
(see alembic/versions/0001_initial.py). Private keys are never stored here in plaintext; secret columns
(*_ct) hold OpenBao Transit ciphertext."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base

TS = DateTime(timezone=True)

# Certificates that authenticate to RADIUS: a user's, a user's device's, and a domain computer's (Group Policy
# autoenrollment). The others (radius-server, admin) never get a policy decision.
CLIENT_PURPOSES = ("user", "device", "computer")


def uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


def tenant_fk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)


# ── Platform ────────────────────────────────────────────────────────────────


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[uuid.UUID] = uuid_pk()
    slug: Mapped[str] = mapped_column(String(48), unique=True)
    name: Mapped[str] = mapped_column(String(160))
    domain: Mapped[str] = mapped_column(String(253), default="")
    status: Mapped[str] = mapped_column(String(16), default="setup")  # setup | active | suspended
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


class PlatformSetting(Base):
    __tablename__ = "platform_settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSONB, default=dict)


class Admin(Base):
    __tablename__ = "admins"
    id: Mapped[uuid.UUID] = uuid_pk()
    email: Mapped[str] = mapped_column(String(254), unique=True)
    display_name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(Text)
    platform_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_secret_ct: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    grants: Mapped[list[RoleGrant]] = relationship(back_populates="admin", cascade="all, delete-orphan", lazy="selectin")


class RoleGrant(Base):
    __tablename__ = "role_grants"
    __table_args__ = (UniqueConstraint("admin_id", "tenant_id", "role"),)
    id: Mapped[uuid.UUID] = uuid_pk()
    admin_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("admins.id", ondelete="CASCADE"))
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    role: Mapped[str] = mapped_column(String(32))
    admin: Mapped[Admin] = relationship(back_populates="grants")


class AdminSession(Base):
    __tablename__ = "admin_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    admin_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("admins.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(TS)
    mfa_passed: Mapped[bool] = mapped_column(Boolean, default=False)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(300), nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), index=True)
    actor_type: Mapped[str] = mapped_column(String(16))  # admin | system | enrollee | agent
    actor_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actor_label: Mapped[str] = mapped_column(String(254))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str] = mapped_column(String(32), default="")
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_label: Mapped[str] = mapped_column(String(254), default="")
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(String(64), index=True)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict)
    dedupe_key: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    run_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), index=True)
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)  # queued|running|done|failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)


# ── PKI ─────────────────────────────────────────────────────────────────────


class CertificateAuthority(Base):
    __tablename__ = "certificate_authorities"
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    role: Mapped[str] = mapped_column(String(16))  # root | issuing
    common_name: Mapped[str] = mapped_column(String(200))
    subject: Mapped[str] = mapped_column(Text)
    key_algorithm: Mapped[str] = mapped_column(String(16))
    serial: Mapped[str] = mapped_column(String(64))
    fingerprint_sha256: Mapped[str] = mapped_column(String(64))
    not_before: Mapped[datetime] = mapped_column(TS)
    not_after: Mapped[datetime] = mapped_column(TS)
    certificate_pem: Mapped[str] = mapped_column(Text)
    offline: Mapped[bool] = mapped_column(Boolean, default=False)
    mount: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="active")
    crl_pem: Mapped[str | None] = mapped_column(Text, nullable=True)  # root CRL issued at ceremony
    crl_next_update: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


class CertificateTemplate(Base):
    __tablename__ = "certificate_templates"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    name: Mapped[str] = mapped_column(String(80))
    purpose: Mapped[str] = mapped_column(String(16))  # user | device | radius-server | admin
    key_algorithm: Mapped[str] = mapped_column(String(16), default="ecdsa-p256")
    validity_days: Mapped[int] = mapped_column(Integer, default=365)
    renew_before_days: Mapped[int] = mapped_column(Integer, default=30)
    extended_key_usage: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    key_usage: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    subject_pattern: Mapped[str] = mapped_column(String(200), default="CN={upn}")
    san_patterns: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    allow_client_keygen: Mapped[bool] = mapped_column(Boolean, default=True)
    allow_server_keygen: Mapped[bool] = mapped_column(Boolean, default=False)
    bao_role: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    # Group Policy autoenrollment (docs/plans/gpo-autoenrollment.md §2.4): the template OID and revision Windows sees
    # in the policy and finds in the certificate template extension; autoenroll_kind = computer | user (None: not
    # offered to Windows).
    template_oid: Mapped[str | None] = mapped_column(String(128), nullable=True)
    revision_major: Mapped[int] = mapped_column(Integer, default=100, server_default="100")
    revision_minor: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    autoenroll_kind: Mapped[str | None] = mapped_column(String(10), nullable=True)


class Certificate(Base):
    __tablename__ = "certificates"
    __table_args__ = (UniqueConstraint("issuer_ca_id", "serial"),)
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    serial: Mapped[str] = mapped_column(String(64), index=True)  # uppercase hex, no colons
    issuer_ca_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("certificate_authorities.id"))
    template_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("certificate_templates.id", ondelete="SET NULL"), nullable=True)
    identity_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("identities.id", ondelete="SET NULL"), nullable=True, index=True)
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    purpose: Mapped[str] = mapped_column(String(16), default="user")
    subject: Mapped[str] = mapped_column(Text)
    common_name: Mapped[str] = mapped_column(String(200))
    sans: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    not_before: Mapped[datetime] = mapped_column(TS)
    not_after: Mapped[datetime] = mapped_column(TS, index=True)
    key_algorithm: Mapped[str] = mapped_column(String(16))
    key_origin: Mapped[str] = mapped_column(String(16))  # device | browser | csr | server
    fingerprint_sha256: Mapped[str] = mapped_column(String(64))
    certificate_pem: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | revoked
    revoked_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(254), nullable=True)
    enrollment_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    # Where Windows created the key: tpm | software (a PC without a TPM) | None (not reported). docs/plans/windows-setup.md
    key_storage: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Renewal by the certificate's own key (POST /api/enroll/renew): the certificate this one replaced, and when this
    # one was replaced. A certificate renews once.
    renewal_of: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    renewed_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    # gpo: Windows enrolled it through Group Policy (no enrollment link or setup file). None otherwise.
    enrollment_source: Mapped[str | None] = mapped_column(String(16), nullable=True)


# ── Directory & identity ────────────────────────────────────────────────────


class DirectoryConfig(Base):
    __tablename__ = "directory_configs"
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    hosts: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    port: Mapped[int] = mapped_column(Integer, default=636)
    transport: Mapped[str] = mapped_column(String(16), default="ldaps")  # ldaps | starttls | plain
    verify_certificate: Mapped[bool] = mapped_column(Boolean, default=True)
    ca_bundle_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    domain: Mapped[str] = mapped_column(String(253))
    base_dn: Mapped[str] = mapped_column(String(500))
    user_search_base: Mapped[str] = mapped_column(String(500), default="")
    group_search_base: Mapped[str] = mapped_column(String(500), default="")
    user_filter: Mapped[str] = mapped_column(String(500), default="(&(objectCategory=person)(objectClass=user))")
    group_filter: Mapped[str] = mapped_column(String(500), default="(objectClass=group)")
    bind_dn: Mapped[str] = mapped_column(String(500))
    bind_password_ct: Mapped[str] = mapped_column(Text)
    sync_interval_minutes: Mapped[int] = mapped_column(Integer, default=15)
    # The domain's lockoutThreshold (0 = no lockout), read at sync: device-admin logins cap AD binds below it.
    lockout_threshold: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # The domain's lockOutObservationWindow in seconds (read with the threshold at each sync).
    lockout_window: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    last_sync_status: Mapped[str | None] = mapped_column(String(16), nullable=True)  # ok | failed
    last_sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_sync_stats: Mapped[dict] = mapped_column(JSONB, default=dict)


class DirectoryGroup(Base):
    __tablename__ = "directory_groups"
    __table_args__ = (UniqueConstraint("tenant_id", "object_guid"),)
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    object_guid: Mapped[str] = mapped_column(String(64))
    sid: Mapped[str | None] = mapped_column(String(184), nullable=True, index=True)
    dn: Mapped[str] = mapped_column(String(500))
    name: Mapped[str] = mapped_column(String(256))
    source: Mapped[str] = mapped_column(String(8), default="ad")  # ad | local
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)


class Identity(Base):
    __tablename__ = "identities"
    __table_args__ = (UniqueConstraint("tenant_id", "object_guid"), UniqueConstraint("tenant_id", "username"))
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    source: Mapped[str] = mapped_column(String(8))  # ad | local
    # user | computer (an AD computer that enrolled through Group Policy; username NAME$, dns_name its dNSHostName)
    kind: Mapped[str] = mapped_column(String(10), default="user", server_default="user")
    dns_name: Mapped[str | None] = mapped_column(String(253), nullable=True)
    object_guid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    username: Mapped[str] = mapped_column(String(256))
    upn: Mapped[str | None] = mapped_column(String(256), nullable=True)
    email: Mapped[str | None] = mapped_column(String(254), nullable=True)
    display_name: Mapped[str] = mapped_column(String(256))
    department: Mapped[str | None] = mapped_column(String(128), nullable=True)
    title: Mapped[str | None] = mapped_column(String(128), nullable=True)
    account_state: Mapped[str] = mapped_column(String(16), default="enabled")  # enabled|disabled|locked|deleted
    enrolled: Mapped[bool] = mapped_column(Boolean, default=False)  # has a Wi-Fi enrollment record
    last_auth_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    groups: Mapped[list[DirectoryGroup]] = relationship(secondary="identity_groups", lazy="selectin")


class IdentityGroup(Base):
    __tablename__ = "identity_groups"
    identity_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("identities.id", ondelete="CASCADE"), primary_key=True)
    group_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("directory_groups.id", ondelete="CASCADE"), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_fk()


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    identity_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("identities.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    platform: Mapped[str] = mapped_column(String(16))  # windows | macos | ios | android | linux
    last_seen_mac: Mapped[str | None] = mapped_column(String(17), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


# ── Policy ──────────────────────────────────────────────────────────────────


class Vlan(Base):
    __tablename__ = "vlans"
    __table_args__ = (UniqueConstraint("tenant_id", "vlan_id"),)
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    vlan_id: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(80))
    description: Mapped[str] = mapped_column(String(300), default="")
    color: Mapped[str] = mapped_column(String(16), default="blue")
    # What a switch port gets when a rule assigns this VLAN: the same VLAN ID, the port's own VLAN (none assigned),
    # or another VLAN (wired_vlan_id). docs/plans/wired-8021x.md §3.
    wired_mode: Mapped[str] = mapped_column(String(8), default="same")  # same | port | vlan
    wired_vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)


class AccessRule(Base):
    __tablename__ = "access_rules"
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(String(500), default="")
    priority: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    action: Mapped[str] = mapped_column(String(8))  # allow | deny
    vlan_ref: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("vlans.id", ondelete="RESTRICT"), nullable=True)
    purposes: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    extra_attributes: Mapped[list[dict]] = mapped_column(JSONB, default=list)
    groups: Mapped[list[DirectoryGroup]] = relationship(secondary="access_rule_groups", lazy="selectin")


class AccessRuleGroup(Base):
    __tablename__ = "access_rule_groups"
    rule_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("access_rules.id", ondelete="CASCADE"), primary_key=True)
    group_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("directory_groups.id", ondelete="CASCADE"), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_fk()


class PolicySettings(Base):
    __tablename__ = "policy_settings"
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    default_action: Mapped[str] = mapped_column(String(8), default="deny")
    default_vlan_ref: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("vlans.id", ondelete="SET NULL"), nullable=True)
    max_snapshot_age_seconds: Mapped[int] = mapped_column(Integer, default=86_400)
    allow_server_keygen: Mapped[bool] = mapped_column(Boolean, default=False)
    expiry_warning_days: Mapped[int] = mapped_column(Integer, default=30)


class Decision(Base):
    __tablename__ = "decisions"
    certificate_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("certificates.id", ondelete="CASCADE"), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    identity_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    outcome: Mapped[str] = mapped_column(String(8))
    reason_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    deciding_rule_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    wired_vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)  # on switch ports, from the VLAN's mapping; None = assign none
    attributes: Mapped[list[dict]] = mapped_column(JSONB, default=list)
    steps: Mapped[list[dict]] = mapped_column(JSONB, default=list)
    computed_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


# ── RADIUS ──────────────────────────────────────────────────────────────────


class RadiusSettings(Base):
    __tablename__ = "radius_settings"
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    server_hostname: Mapped[str] = mapped_column(String(253))
    ssid: Mapped[str] = mapped_column(String(32), default="")
    wpa3: Mapped[bool] = mapped_column(Boolean, default=False)
    auth_port: Mapped[int] = mapped_column(Integer, default=1812)
    acct_port: Mapped[int] = mapped_column(Integer, default=1813)
    dedicated_ports: Mapped[bool] = mapped_column(Boolean, default=False)
    tls_min_version: Mapped[str] = mapped_column(String(4), default="1.2")
    tls_session_cache: Mapped[bool] = mapped_column(Boolean, default=False)
    session_timeout_seconds: Mapped[int] = mapped_column(Integer, default=28_800)
    wired_enabled: Mapped[bool] = mapped_column(Boolean, default=False)  # include wired settings in enrollment packages
    server_certificate_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("certificates.id", ondelete="SET NULL"), nullable=True)
    server_key_ct: Mapped[str | None] = mapped_column(Text, nullable=True)
    snapshot_version: Mapped[int] = mapped_column(BigInteger, default=0)
    snapshot_built_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    config_version: Mapped[int] = mapped_column(BigInteger, default=0)
    # The MAC allow list's own snapshot version (docs/plans/mac-auth.md §4): bumped by admin edits to MAC devices and
    # device groups only, so certificate recomputes never resend MAC entries and last-seen updates never re-version.
    mac_version: Mapped[int] = mapped_column(BigInteger, default=0)
    # Device administration (docs/plans/device-admin.md): its own snapshot part, bumped by admin-login changes only.
    admin_version: Mapped[int] = mapped_column(BigInteger, default=0)


class RadiusClient(Base):
    __tablename__ = "radius_clients"
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    name: Mapped[str] = mapped_column(String(120))
    vendor: Mapped[str] = mapped_column(String(16))  # cisco-9800 | cisco-aireos | cisco-switch | unifi | other
    networks: Mapped[list[str]] = mapped_column(ARRAY(String), default=lambda: ["wireless"])  # wireless | wired: what it may authenticate
    wired_profile: Mapped[dict] = mapped_column(JSONB, default=dict)  # the switch port plan and rollout mode (app/radius/wired.py); no secrets
    address: Mapped[str] = mapped_column(String(64), index=True)  # IP or CIDR; uniqueness across shared-port tenants enforced in service
    site: Mapped[str] = mapped_column(String(120), default="")
    secret_ct: Mapped[str] = mapped_column(Text)
    secret_set_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    coa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    coa_port: Mapped[int] = mapped_column(Integer, default=3799)
    last_request_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    # Device administration: TACACS+ logins from this device, with its own key (and the previous one during rotation).
    admin_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    tacacs_key_ct: Mapped[str | None] = mapped_column(Text, nullable=True)
    tacacs_key_set_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    tacacs_prev_key_ct: Mapped[str | None] = mapped_column(Text, nullable=True)
    tacacs_prev_until: Mapped[datetime | None] = mapped_column(TS, nullable=True)


class AuthEvent(Base):
    __tablename__ = "auth_events"
    __table_args__ = (Index("ix_auth_events_tenant_network_at", "tenant_id", "network", "at"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    event_uid: Mapped[str] = mapped_column(String(64), unique=True)  # dedupe key from the agent
    at: Mapped[datetime] = mapped_column(TS, index=True)
    result: Mapped[str] = mapped_column(String(8))  # accept | reject
    reason_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    username: Mapped[str | None] = mapped_column(String(256), nullable=True)
    identity_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    device_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    cert_serial: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    cert_issuer: Mapped[str | None] = mapped_column(String(300), nullable=True)
    calling_station_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    called_station_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    nas_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    nas_client_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    ssid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    network: Mapped[str | None] = mapped_column(String(8), nullable=True)  # wireless | wired
    nas_port_id: Mapped[str | None] = mapped_column(String(64), nullable=True)  # the switch port, e.g. GigabitEthernet1/0/5
    monitor: Mapped[bool] = mapped_column(Boolean, default=False)  # monitor mode: vlan_id is what would have been assigned
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rule_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    raw_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    # The device's MAC, normalised (12 uppercase hex digits; app/mac.py), from Calling-Station-Id or a MAB User-Name.
    mac: Mapped[str | None] = mapped_column(String(12), nullable=True)
    method: Mapped[str | None] = mapped_column(String(8), nullable=True)  # eap-tls | mab | mab-eap; NULL = certificate (older rows)
    mac_device_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)


class AccountingSession(Base):
    __tablename__ = "accounting_sessions"
    __table_args__ = (UniqueConstraint("tenant_id", "nas_ip", "acct_session_id"),)
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    acct_session_id: Mapped[str] = mapped_column(String(128))
    nas_ip: Mapped[str] = mapped_column(String(64))
    # The controller the accounting came from (by packet source). No foreign key, like AuthEvent: history outlives a
    # deleted controller.
    nas_client_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    username: Mapped[str | None] = mapped_column(String(256), nullable=True)
    calling_station_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    called_station_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    framed_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    network: Mapped[str | None] = mapped_column(String(8), nullable=True)
    nas_port_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    stopped_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    input_octets: Mapped[int] = mapped_column(BigInteger, default=0)
    output_octets: Mapped[int] = mapped_column(BigInteger, default=0)
    terminate_cause: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mac: Mapped[str | None] = mapped_column(String(12), nullable=True)  # normalised Calling-Station-Id, for CoA by device


class CoaRequest(Base):
    __tablename__ = "coa_requests"
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    nas_client_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("radius_clients.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(16), default="disconnect")
    attributes: Mapped[dict] = mapped_column(JSONB, default=dict)  # User-Name, Calling-Station-Id, Acct-Session-Id
    reason: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending | sent | acked | nak | failed
    result_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)


class DeviceGroup(Base):
    """A group on the MAC allow list: devices in it get its switch VLAN (docs/plans/mac-auth.md §3)."""
    __tablename__ = "device_groups"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    name: Mapped[str] = mapped_column(String(80))
    description: Mapped[str] = mapped_column(String(300), default="")
    # A VLAN from Access policy (mapped for switch ports like any VLAN), or explicitly the port's own VLAN.
    vlan_ref: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("vlans.id", ondelete="RESTRICT"), nullable=True)
    port_vlan: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


class MacDevice(Base):
    """A device on the MAC allow list. `enabled = False` is blocked. The last-seen columns are filled at ingest and are
    not part of the snapshot."""
    __tablename__ = "mac_devices"
    __table_args__ = (UniqueConstraint("tenant_id", "mac"),)
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    mac: Mapped[str] = mapped_column(String(12))  # normalised: 12 uppercase hex digits
    name: Mapped[str] = mapped_column(String(120))
    notes: Mapped[str] = mapped_column(String(500), default="")
    group_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("device_groups.id", ondelete="RESTRICT"), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    source: Mapped[str] = mapped_column(String(8), default="manual")  # manual | import | learned
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    created_by: Mapped[str] = mapped_column(String(254), default="")
    last_seen_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    last_seen_client_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    last_seen_port: Mapped[str | None] = mapped_column(String(64), nullable=True)


class MacSighting(Base):
    """A MAC that tried MAC authentication and was refused, per switch and port: what "Seen, not allowed" lists."""
    __tablename__ = "mac_sightings"
    __table_args__ = (UniqueConstraint("tenant_id", "mac", "client_id", "port"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    mac: Mapped[str] = mapped_column(String(12))
    client_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    port: Mapped[str] = mapped_column(String(64), default="")
    first_seen: Mapped[datetime] = mapped_column(TS)
    last_seen: Mapped[datetime] = mapped_column(TS, index=True)
    count: Mapped[int] = mapped_column(Integer, default=1)
    last_reason: Mapped[str] = mapped_column(String(32))
    last_event_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)  # last attempt stored as an auth event


# ── Device administration (TACACS+) ─────────────────────────────────────────


class AdminRole(Base):
    """What an administrator gets on a device: an IOS privilege level. Two built-ins per tenant."""
    __tablename__ = "admin_roles"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    name: Mapped[str] = mapped_column(String(60))
    priv_lvl: Mapped[int] = mapped_column(Integer)
    description: Mapped[str] = mapped_column(String(300), default="")
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


class AdminUser(Base):
    """A local device-administration account (not an EasyEAP console administrator)."""
    __tablename__ = "admin_users"
    __table_args__ = (UniqueConstraint("tenant_id", "username"),)
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    username: Mapped[str] = mapped_column(String(64))  # case-folded
    display_name: Mapped[str] = mapped_column(String(120), default="")
    email: Mapped[str] = mapped_column(String(254), default="")
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)  # scrypt$… (app/admin/passwords.py); None = no password yet
    password_set_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    totp_secret_ct: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("admin_roles.id", ondelete="RESTRICT"))
    sites: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)  # empty = every site
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    unlocked_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)  # clears a lockout on the RADIUS nodes
    last_login_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    created_by: Mapped[str] = mapped_column(String(254), default="")
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


class AdminGroupMap(Base):
    """Members of this directory group may log in to devices with this role (ordered: first match wins)."""
    __tablename__ = "admin_group_maps"
    __table_args__ = (UniqueConstraint("tenant_id", "group_id"),)
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    group_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("directory_groups.id", ondelete="CASCADE"))
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("admin_roles.id", ondelete="RESTRICT"))
    sites: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    position: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


class AdminSettings(Base):
    __tablename__ = "admin_settings"
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    # Break-glass names: EasyEAP answers ERROR, so the device falls back to its own local account even while EasyEAP is up.
    local_only_usernames: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    retention_days: Mapped[int] = mapped_column(Integer, default=180)


class AdminEvent(Base):
    """A device-administration login, enable, authorization, exec session or command (TACACS+), from the agent."""
    __tablename__ = "admin_events"
    __table_args__ = (Index("ix_admin_events_tenant_at", "tenant_id", "at"), Index("ix_admin_events_tenant_user", "tenant_id", "user_id"))
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    event_uid: Mapped[str] = mapped_column(String(64), unique=True)
    at: Mapped[datetime] = mapped_column(TS)
    client_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    nas_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    username: Mapped[str | None] = mapped_column(String(256), nullable=True)  # verbatim for known accounts, a keyed hash otherwise
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)  # admin_users.id or identities.id
    source: Mapped[str | None] = mapped_column(String(10), nullable=True)  # local | directory
    kind: Mapped[str] = mapped_column(String(12))  # login | enable | authz | session | command
    result: Mapped[str] = mapped_column(String(8))  # pass | fail | error | start | stop | update
    reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    priv_lvl: Mapped[int | None] = mapped_column(Integer, nullable=True)
    command: Mapped[str | None] = mapped_column(Text, nullable=True)  # masked (app/admin/mask.py)
    rem_addr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    port: Mapped[str | None] = mapped_column(String(64), nullable=True)
    task_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    message: Mapped[str | None] = mapped_column(String(500), nullable=True)


class AgentStatus(Base):
    __tablename__ = "agent_status"
    agent_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_seen_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    config_version: Mapped[int] = mapped_column(BigInteger, default=0)
    config_ok: Mapped[bool] = mapped_column(Boolean, default=True)
    config_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    snapshot_versions: Mapped[dict] = mapped_column(JSONB, default=dict)
    radius_running: Mapped[bool] = mapped_column(Boolean, default=False)
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)


class SystemLog(Base):
    """Operational log of every EasyEAP component (API, worker, RADIUS agent, FreeRADIUS): EasyEAP's own messages
    at INFO and above, libraries' at WARNING and above. Redacted before it is written. Kept 30 days and forwarded to
    remote syslog with the audit trail and authentication events."""
    __tablename__ = "system_logs"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), index=True)
    level: Mapped[str] = mapped_column(String(8))  # debug | info | warning | error | critical
    source: Mapped[str] = mapped_column(String(32), index=True)  # api | worker | radius-agent | freeradius
    logger: Mapped[str] = mapped_column(String(100), default="")
    message: Mapped[str] = mapped_column(Text)


# ── Enrollment ──────────────────────────────────────────────────────────────


class Enrollment(Base):
    __tablename__ = "enrollments"
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    identity_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("identities.id", ondelete="CASCADE"), index=True)
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    device_name: Mapped[str] = mapped_column(String(120))
    platform: Mapped[str] = mapped_column(String(16))
    method: Mapped[str] = mapped_column(String(16))  # browser | windows | csr | server
    template_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("certificate_templates.id"))
    token_hash: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|completed|expired|cancelled
    created_by: Mapped[str] = mapped_column(String(254))
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(TS)
    completed_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    certificate_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    renewal_of: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)


class AutoenrollConfig(Base):
    """Group Policy autoenrollment for one tenant (docs/plans/gpo-autoenrollment.md)."""
    __tablename__ = "autoenroll_configs"
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    computers: Mapped[bool] = mapped_column(Boolean, default=True)
    users: Mapped[bool] = mapped_column(Boolean, default=False)
    policy_id: Mapped[str] = mapped_column(String(64))  # stable: Group Policy stores it ("Validate Server")
    oid_root: Mapped[str] = mapped_column(String(128))  # 1.3.6.1.4.1.311.21.8.<6 random arcs>
    service_account: Mapped[str] = mapped_column(String(20), default="easyeap-cep")
    keytab_ct: Mapped[str | None] = mapped_column(Text, nullable=True)
    keytab_info: Mapped[dict] = mapped_column(JSONB, default=dict)  # principal, realm, kvno, enctypes, problems
    keytab_uploaded_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    keytab_test: Mapped[dict] = mapped_column(JSONB, default=dict)  # ok, message, at
    require_channel_binding: Mapped[bool] = mapped_column(Boolean, default=True)
    computer_group_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("directory_groups.id", ondelete="SET NULL"), nullable=True)
    response_format: Mapped[str] = mapped_column(String(16), default="unsigned")  # unsigned | signed | pkcs7
    machine_account_quota: Mapped[int | None] = mapped_column(Integer, nullable=True)  # read at each directory sync
    signer_cert_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    signer_key_ct: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    last_error_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())


class AutoenrollEvent(Base):
    """One policy or enrollment request from Windows, for the console's request log. The id is the WSTEP RequestID."""
    __tablename__ = "autoenroll_events"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), index=True)
    service: Mapped[str] = mapped_column(String(8))  # cep | ces
    caller: Mapped[str] = mapped_column(String(256), default="")
    kind: Mapped[str | None] = mapped_column(String(10), nullable=True)  # computer | user
    outcome: Mapped[str] = mapped_column(String(8))  # ok | denied | error
    code: Mapped[str] = mapped_column(String(32), default="")
    message: Mapped[str] = mapped_column(Text, default="")
    template: Mapped[str | None] = mapped_column(String(80), nullable=True)
    machine: Mapped[str | None] = mapped_column(String(253), nullable=True)
    certificate_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)


class KeyEscrow(Base):
    """Server-generated PKCS#12 held for exactly one download (admin mode)."""

    __tablename__ = "key_escrow"
    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = tenant_fk()
    enrollment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("enrollments.id", ondelete="CASCADE"), unique=True)
    p12_ct: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(TS)


TENANT_TABLES = [
    "certificate_authorities", "certificate_templates", "certificates", "directory_configs", "directory_groups",
    "identities", "identity_groups", "devices", "vlans", "access_rules", "access_rule_groups", "policy_settings",
    "decisions", "radius_settings", "radius_clients", "auth_events", "accounting_sessions", "coa_requests",
    "enrollments", "key_escrow", "device_groups", "mac_devices", "mac_sightings",
    "admin_roles", "admin_users", "admin_group_maps", "admin_settings", "admin_events",
]
