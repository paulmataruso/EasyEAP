"""Switch audit: SNMP monitoring of Cisco switches, their polled state and audit findings

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-08 06:00:00

docs/plans/switch-audit.md. Nothing changes for existing installations: monitoring is off on every switch until it's
set up, and the collector polls nothing until then.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None

TS = postgresql.TIMESTAMP(timezone=True)
NEW_TABLES = ("switch_states", "switch_findings")


def upgrade() -> None:
    op.add_column('radius_clients', sa.Column('monitoring', postgresql.JSONB(), nullable=False, server_default='{}'))
    op.add_column('radius_clients', sa.Column('snmp_secret_ct', sa.Text(), nullable=True))
    op.create_index('ix_auth_events_client_mac_at', 'auth_events', ['nas_client_id', 'mac', 'at'])

    op.create_table(
        'switch_states',
        sa.Column('client_id', sa.UUID(), nullable=False),
        sa.Column('tenant_id', sa.UUID(), nullable=False),
        sa.Column('polled_at', TS, nullable=True),
        sa.Column('ok', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('error_kind', sa.String(length=16), nullable=True),
        sa.Column('error', sa.String(length=300), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('failures', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_ok_at', TS, nullable=True),
        sa.Column('facts', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('capabilities', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('ports', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('sessions', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('truncated', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('slow', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('next_poll_at', TS, nullable=True),
        sa.Column('poll_requested_at', TS, nullable=True),
        sa.ForeignKeyConstraint(['client_id'], ['radius_clients.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('client_id'),
    )
    op.create_index('ix_switch_states_tenant_id', 'switch_states', ['tenant_id'])

    op.create_table(
        'switch_findings',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('tenant_id', sa.UUID(), nullable=False),
        sa.Column('client_id', sa.UUID(), nullable=False),
        sa.Column('kind', sa.String(length=32), nullable=False),
        sa.Column('severity', sa.String(length=8), nullable=False),
        sa.Column('port', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('mac', sa.String(length=12), nullable=False, server_default=''),
        sa.Column('detail', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('detail_hash', sa.String(length=32), nullable=False, server_default=''),
        sa.Column('first_seen_at', TS, nullable=False),
        sa.Column('last_seen_at', TS, nullable=False),
        sa.Column('seen_count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('missing_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('opened_at', TS, nullable=True),
        sa.Column('resolved_at', TS, nullable=True),
        sa.Column('acknowledged_at', TS, nullable=True),
        sa.Column('acknowledged_by', sa.String(length=254), nullable=True),
        sa.Column('ack_note', sa.String(length=500), nullable=True),
        sa.Column('ack_hash', sa.String(length=32), nullable=True),
        sa.ForeignKeyConstraint(['client_id'], ['radius_clients.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_switch_findings_tenant_id', 'switch_findings', ['tenant_id'])
    op.create_index('ix_switch_findings_client_id', 'switch_findings', ['client_id'])
    op.create_index('ix_switch_findings_tenant_resolved', 'switch_findings', ['tenant_id', 'resolved_at'])
    op.create_index('uq_switch_findings_open', 'switch_findings', ['client_id', 'kind', 'port', 'mac'], unique=True,
                    postgresql_where=sa.text('resolved_at IS NULL'))

    for table in NEW_TABLES:
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO easyeap_app")
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} USING ("
            f"current_setting('easyeap.platform', true) = 'on' OR "
            f"tenant_id::text = current_setting('easyeap.tenant_id', true))"
        )


def downgrade() -> None:
    for table in reversed(NEW_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.drop_table(table)
    op.drop_index('ix_auth_events_client_mac_at', table_name='auth_events')
    op.drop_column('radius_clients', 'snmp_secret_ct')
    op.drop_column('radius_clients', 'monitoring')
