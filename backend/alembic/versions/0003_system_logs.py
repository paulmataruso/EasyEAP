"""system log (forwarded to remote syslog with the audit trail and authentication events)

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-06 09:00:00
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'system_logs',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('level', sa.String(length=8), nullable=False),
        sa.Column('source', sa.String(length=32), nullable=False),
        sa.Column('logger', sa.String(length=100), nullable=False, server_default=''),
        sa.Column('message', sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_system_logs_at', 'system_logs', ['at'])
    op.create_index('ix_system_logs_source', 'system_logs', ['source'])
    # Platform-wide (no tenant), so no row-level security. The application may add, read and expire rows, never edit.
    op.execute("GRANT SELECT, INSERT, DELETE ON system_logs TO easyeap_app")
    op.execute("GRANT USAGE, SELECT ON SEQUENCE system_logs_id_seq TO easyeap_app")


def downgrade() -> None:
    op.drop_index('ix_system_logs_source', table_name='system_logs')
    op.drop_index('ix_system_logs_at', table_name='system_logs')
    op.drop_table('system_logs')
