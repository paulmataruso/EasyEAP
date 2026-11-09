"""Device administration: TACACS+ logins to switches and controllers with AD or local accounts

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-07 20:00:00

docs/plans/device-admin.md §3. Nothing changes for existing installations: admin logins are off on every device
(admin_enabled defaults to false), no local accounts or group mappings exist, and the TACACS+ listener only starts
once a device has admin logins on (and is only reachable when EASYEAP_TACACS_BIND publishes it).
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None

NEW_TABLES = ("admin_roles", "admin_users", "admin_group_maps", "admin_settings", "admin_events")
TS = postgresql.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.add_column('radius_settings', sa.Column('admin_version', sa.BigInteger(), nullable=False, server_default='0'))
    op.add_column('directory_configs', sa.Column('lockout_threshold', sa.Integer(), nullable=True))
    op.add_column('directory_configs', sa.Column('lockout_window', sa.Integer(), nullable=True))
    op.add_column('radius_clients', sa.Column('admin_enabled', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column('radius_clients', sa.Column('tacacs_key_ct', sa.Text(), nullable=True))
    op.add_column('radius_clients', sa.Column('tacacs_key_set_at', TS, nullable=True))
    op.add_column('radius_clients', sa.Column('tacacs_prev_key_ct', sa.Text(), nullable=True))
    op.add_column('radius_clients', sa.Column('tacacs_prev_until', TS, nullable=True))

    op.create_table(
        'admin_roles',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('tenant_id', sa.UUID(), nullable=False),
        sa.Column('name', sa.String(length=60), nullable=False),
        sa.Column('priv_lvl', sa.Integer(), nullable=False),
        sa.Column('description', sa.String(length=300), nullable=False, server_default=''),
        sa.Column('builtin', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_at', TS, server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'name'),
        sa.CheckConstraint('priv_lvl BETWEEN 0 AND 15', name='ck_admin_roles_priv_lvl'),
    )
    op.create_index('ix_admin_roles_tenant_id', 'admin_roles', ['tenant_id'])

    op.create_table(
        'admin_users',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('tenant_id', sa.UUID(), nullable=False),
        sa.Column('username', sa.String(length=64), nullable=False),
        sa.Column('display_name', sa.String(length=120), nullable=False, server_default=''),
        sa.Column('email', sa.String(length=254), nullable=False, server_default=''),
        sa.Column('password_hash', sa.Text(), nullable=True),
        sa.Column('password_set_at', TS, nullable=True),
        sa.Column('totp_secret_ct', sa.Text(), nullable=True),
        sa.Column('totp_enabled', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('role_id', sa.UUID(), nullable=False),
        sa.Column('sites', postgresql.ARRAY(sa.String()), nullable=False, server_default='{}'),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('expires_at', TS, nullable=True),
        sa.Column('unlocked_at', TS, nullable=True),
        sa.Column('last_login_at', TS, nullable=True),
        sa.Column('created_by', sa.String(length=254), nullable=False, server_default=''),
        sa.Column('created_at', TS, server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['role_id'], ['admin_roles.id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'username'),
    )
    op.create_index('ix_admin_users_tenant_id', 'admin_users', ['tenant_id'])

    op.create_table(
        'admin_group_maps',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('tenant_id', sa.UUID(), nullable=False),
        sa.Column('group_id', sa.UUID(), nullable=False),
        sa.Column('role_id', sa.UUID(), nullable=False),
        sa.Column('sites', postgresql.ARRAY(sa.String()), nullable=False, server_default='{}'),
        sa.Column('position', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', TS, server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['group_id'], ['directory_groups.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['role_id'], ['admin_roles.id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'group_id'),
    )
    op.create_index('ix_admin_group_maps_tenant_id', 'admin_group_maps', ['tenant_id'])

    op.create_table(
        'admin_settings',
        sa.Column('tenant_id', sa.UUID(), nullable=False),
        sa.Column('local_only_usernames', postgresql.ARRAY(sa.String()), nullable=False, server_default='{}'),
        sa.Column('retention_days', sa.Integer(), nullable=False, server_default='180'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('tenant_id'),
    )

    op.create_table(
        'admin_events',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('tenant_id', sa.UUID(), nullable=False),
        sa.Column('event_uid', sa.String(length=64), nullable=False),
        sa.Column('at', TS, nullable=False),
        sa.Column('client_id', sa.UUID(), nullable=True),
        sa.Column('nas_ip', sa.String(length=64), nullable=True),
        sa.Column('username', sa.String(length=256), nullable=True),
        sa.Column('user_id', sa.UUID(), nullable=True),
        sa.Column('source', sa.String(length=10), nullable=True),
        sa.Column('kind', sa.String(length=12), nullable=False),
        sa.Column('result', sa.String(length=8), nullable=False),
        sa.Column('reason', sa.String(length=32), nullable=True),
        sa.Column('priv_lvl', sa.Integer(), nullable=True),
        sa.Column('command', sa.Text(), nullable=True),
        sa.Column('rem_addr', sa.String(length=64), nullable=True),
        sa.Column('port', sa.String(length=64), nullable=True),
        sa.Column('task_id', sa.String(length=32), nullable=True),
        sa.Column('message', sa.String(length=500), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('event_uid'),
    )
    op.create_index('ix_admin_events_tenant_at', 'admin_events', ['tenant_id', 'at'])
    op.create_index('ix_admin_events_tenant_user', 'admin_events', ['tenant_id', 'user_id'])

    for table in NEW_TABLES:
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO easyeap_app")
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} USING ("
            f"current_setting('easyeap.platform', true) = 'on' OR "
            f"tenant_id::text = current_setting('easyeap.tenant_id', true))"
        )
    op.execute("GRANT USAGE, SELECT ON SEQUENCE admin_events_id_seq TO easyeap_app")


def downgrade() -> None:
    for table in reversed(NEW_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.drop_table(table)
    for col in ('tacacs_prev_until', 'tacacs_prev_key_ct', 'tacacs_key_set_at', 'tacacs_key_ct', 'admin_enabled'):
        op.drop_column('radius_clients', col)
    op.drop_column('directory_configs', 'lockout_window')
    op.drop_column('directory_configs', 'lockout_threshold')
    op.drop_column('radius_settings', 'admin_version')
