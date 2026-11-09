"""MAC authentication on switch ports: the MAC allow list, sightings, and the device MAC on events and sessions

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-07 15:00:00

docs/plans/mac-auth.md §3. Nothing that works before this migration changes after it: MAC authentication is off on
every switch (it lives in the port plan, default off), the allow list starts empty, and the new event columns are
filled for recent rows so CoA and the device sheet find sessions that started before the upgrade.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None

NEW_TABLES = ("device_groups", "mac_devices", "mac_sightings")
# Calling-Station-Id → 12 uppercase hex digits, only when it is exactly a MAC in one of the usual notations.
NORMALISE = ("CASE WHEN calling_station_id ~ '^[0-9A-Fa-f]{2}([-:.]?[0-9A-Fa-f]{2}){5}$' OR calling_station_id ~ '^[0-9A-Fa-f]{4}\\.[0-9A-Fa-f]{4}\\.[0-9A-Fa-f]{4}$' "
             "THEN upper(regexp_replace(calling_station_id, '[^0-9A-Fa-f]', '', 'g')) END")


def upgrade() -> None:
    op.add_column('radius_settings', sa.Column('mac_version', sa.BigInteger(), nullable=False, server_default='0'))

    op.create_table(
        'device_groups',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('tenant_id', sa.UUID(), nullable=False),
        sa.Column('name', sa.String(length=80), nullable=False),
        sa.Column('description', sa.String(length=300), nullable=False, server_default=''),
        sa.Column('vlan_ref', sa.UUID(), nullable=True),
        sa.Column('port_vlan', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['vlan_ref'], ['vlans.id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'name'),
        # A group has a VLAN, or is explicitly "the port's own VLAN": never neither.
        sa.CheckConstraint('(vlan_ref IS NOT NULL) <> port_vlan', name='ck_device_groups_vlan'),
    )
    op.create_index('ix_device_groups_tenant_id', 'device_groups', ['tenant_id'])

    op.create_table(
        'mac_devices',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('tenant_id', sa.UUID(), nullable=False),
        sa.Column('mac', sa.String(length=12), nullable=False),
        sa.Column('name', sa.String(length=120), nullable=False),
        sa.Column('notes', sa.String(length=500), nullable=False, server_default=''),
        sa.Column('group_id', sa.UUID(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('expires_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column('source', sa.String(length=8), nullable=False, server_default='manual'),
        sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('created_by', sa.String(length=254), nullable=False, server_default=''),
        sa.Column('last_seen_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column('last_seen_client_id', sa.UUID(), nullable=True),
        sa.Column('last_seen_port', sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['group_id'], ['device_groups.id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'mac'),
        sa.CheckConstraint("mac ~ '^[0-9A-F]{12}$'", name='ck_mac_devices_mac'),
        sa.CheckConstraint("source IN ('manual', 'import', 'learned')", name='ck_mac_devices_source'),
    )
    op.create_index('ix_mac_devices_tenant_id', 'mac_devices', ['tenant_id'])
    op.create_index('ix_mac_devices_group_id', 'mac_devices', ['group_id'])

    op.create_table(
        'mac_sightings',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('tenant_id', sa.UUID(), nullable=False),
        sa.Column('mac', sa.String(length=12), nullable=False),
        sa.Column('client_id', sa.UUID(), nullable=False),
        sa.Column('port', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('first_seen', postgresql.TIMESTAMP(timezone=True), nullable=False),
        sa.Column('last_seen', postgresql.TIMESTAMP(timezone=True), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('last_reason', sa.String(length=32), nullable=False),
        sa.Column('last_event_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'mac', 'client_id', 'port'),
    )
    op.create_index('ix_mac_sightings_tenant_id', 'mac_sightings', ['tenant_id'])
    op.create_index('ix_mac_sightings_last_seen', 'mac_sightings', ['last_seen'])

    op.add_column('auth_events', sa.Column('mac', sa.String(length=12), nullable=True))
    op.add_column('auth_events', sa.Column('method', sa.String(length=8), nullable=True))
    op.add_column('auth_events', sa.Column('mac_device_id', sa.UUID(), nullable=True))
    op.create_index('ix_auth_events_tenant_mac', 'auth_events', ['tenant_id', 'mac'])
    op.add_column('accounting_sessions', sa.Column('mac', sa.String(length=12), nullable=True))
    op.create_index('ix_accounting_sessions_tenant_mac', 'accounting_sessions', ['tenant_id', 'mac'])
    # Open sessions and the last 30 days of events: enough for CoA, readiness and the device sheet.
    op.execute(f"UPDATE accounting_sessions SET mac = {NORMALISE} WHERE calling_station_id IS NOT NULL")
    op.execute(f"UPDATE auth_events SET mac = {NORMALISE} WHERE calling_station_id IS NOT NULL AND at > now() - interval '30 days'")
    # Switches configured before control policies were named by content carry EASYEAP_MONITOR or EASYEAP_CLOSED: record
    # that as the attached policy, so the next change swaps it out instead of naming one the switch doesn't have.
    op.execute(
        "UPDATE radius_clients SET wired_profile = wired_profile || jsonb_build_object('policy', "
        "CASE WHEN wired_profile->>'mode' = 'enforce' THEN 'EASYEAP_CLOSED' ELSE 'EASYEAP_MONITOR' END) "
        "WHERE vendor = 'cisco-switch' AND coalesce(wired_profile->>'platform', 'ibns2') = 'ibns2' "
        "AND coalesce(wired_profile->>'interfaces', '') <> '' AND NOT wired_profile ? 'policy'"
    )

    for table in NEW_TABLES:
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO easyeap_app")
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} USING ("
            f"current_setting('easyeap.platform', true) = 'on' OR "
            f"tenant_id::text = current_setting('easyeap.tenant_id', true))"
        )
    op.execute("GRANT USAGE, SELECT ON SEQUENCE mac_sightings_id_seq TO easyeap_app")


def downgrade() -> None:
    op.drop_index('ix_accounting_sessions_tenant_mac', table_name='accounting_sessions')
    op.drop_column('accounting_sessions', 'mac')
    op.drop_index('ix_auth_events_tenant_mac', table_name='auth_events')
    op.drop_column('auth_events', 'mac_device_id')
    op.drop_column('auth_events', 'method')
    op.drop_column('auth_events', 'mac')
    for table in reversed(NEW_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.drop_table(table)
    op.drop_column('radius_settings', 'mac_version')
