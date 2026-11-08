"""Switch audit: syslog from monitored switches ("the switch says")

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-08 09:00:00

docs/plans/switch-audit.md §0a. Nothing is received until EASYEAP_SYSLOG_BIND publishes the easyeap-syslog service's
port and a switch sends to it.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None

TS = postgresql.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.add_column('switch_states', sa.Column('syslog', postgresql.JSONB(), nullable=False, server_default='{}'))
    op.create_table(
        'switch_syslog',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('tenant_id', sa.UUID(), nullable=False),
        sa.Column('client_id', sa.UUID(), nullable=False),
        sa.Column('first_at', TS, nullable=False),
        sa.Column('last_at', TS, nullable=False),
        sa.Column('count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('severity', sa.Integer(), nullable=False),
        sa.Column('facility', sa.String(length=32), nullable=False),
        sa.Column('mnemonic', sa.String(length=48), nullable=False),
        sa.Column('port', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('mac', sa.String(length=12), nullable=False, server_default=''),
        sa.Column('session_id', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('subject', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('text', sa.String(length=500), nullable=False),
        sa.ForeignKeyConstraint(['client_id'], ['radius_clients.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_switch_syslog_tenant_id', 'switch_syslog', ['tenant_id'])
    op.create_index('ix_switch_syslog_last_at', 'switch_syslog', ['last_at'])
    op.create_index('ix_switch_syslog_client_last', 'switch_syslog', ['client_id', 'last_at'])
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON switch_syslog TO easyeap_app")
    op.execute("ALTER TABLE switch_syslog ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON switch_syslog USING ("
        "current_setting('easyeap.platform', true) = 'on' OR "
        "tenant_id::text = current_setting('easyeap.tenant_id', true))"
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON switch_syslog")
    op.drop_table('switch_syslog')
    op.drop_column('switch_states', 'syslog')
