"""wired 802.1X: networks and port plans on RADIUS clients, wired VLAN mapping, network and switch port on events

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-07 09:00:00

Nothing that works before this migration changes after it (docs/plans/wired-8021x.md §3):
- every existing RADIUS client may authenticate both networks (a switch may have been registered as "Catalyst 9800"
  or "other"; Embedded Wireless Controllers and Remote-LAN ports send wired-looking requests through 9800s);
- every existing VLAN maps to the same VLAN ID on switch ports, and every existing decision's wired VLAN is its VLAN,
  which is what switch ports got before;
- wired settings stay out of enrollment packages until an admin turns them on.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('radius_settings', sa.Column('wired_enabled', sa.Boolean(), nullable=False, server_default=sa.false()))

    op.add_column('radius_clients', sa.Column('networks', postgresql.ARRAY(sa.String()), nullable=False, server_default='{wireless,wired}'))
    op.add_column('radius_clients', sa.Column('wired_profile', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'))

    op.add_column('vlans', sa.Column('wired_mode', sa.String(length=8), nullable=False, server_default='same'))
    op.add_column('vlans', sa.Column('wired_vlan_id', sa.Integer(), nullable=True))
    op.create_check_constraint('ck_vlans_wired_mode', 'vlans', "wired_mode IN ('same', 'port', 'vlan')")
    op.create_check_constraint('ck_vlans_wired_vlan', 'vlans', "(wired_mode = 'vlan') = (wired_vlan_id IS NOT NULL)")

    op.add_column('decisions', sa.Column('wired_vlan_id', sa.Integer(), nullable=True))
    op.execute("UPDATE decisions SET wired_vlan_id = vlan_id")

    op.add_column('auth_events', sa.Column('network', sa.String(length=8), nullable=True))
    op.add_column('auth_events', sa.Column('nas_port_id', sa.String(length=64), nullable=True))
    op.add_column('auth_events', sa.Column('monitor', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_index('ix_auth_events_tenant_network_at', 'auth_events', ['tenant_id', 'network', 'at'])
    op.add_column('accounting_sessions', sa.Column('network', sa.String(length=8), nullable=True))
    op.add_column('accounting_sessions', sa.Column('nas_port_id', sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column('accounting_sessions', 'nas_port_id')
    op.drop_column('accounting_sessions', 'network')
    op.drop_index('ix_auth_events_tenant_network_at', table_name='auth_events')
    op.drop_column('auth_events', 'monitor')
    op.drop_column('auth_events', 'nas_port_id')
    op.drop_column('auth_events', 'network')
    op.drop_column('decisions', 'wired_vlan_id')
    op.drop_constraint('ck_vlans_wired_vlan', 'vlans', type_='check')
    op.drop_constraint('ck_vlans_wired_mode', 'vlans', type_='check')
    op.drop_column('vlans', 'wired_vlan_id')
    op.drop_column('vlans', 'wired_mode')
    op.drop_column('radius_clients', 'wired_profile')
    op.drop_column('radius_clients', 'networks')
    op.drop_column('radius_settings', 'wired_enabled')
