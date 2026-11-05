"""accounting sessions record the controller they came from

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-05 13:10:00
"""
from alembic import op
import sqlalchemy as sa

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('accounting_sessions', sa.Column('nas_client_id', sa.UUID(), nullable=True))


def downgrade() -> None:
    op.drop_column('accounting_sessions', 'nas_client_id')
