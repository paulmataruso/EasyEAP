"""Enrollment links: keep a pending link's token, encrypted, so the admin can copy the link again

Revision ID: 0011
Revises: 0010
Create Date: 2026-11-08 18:00:00

The token is encrypted with the tenant's transit key and cleared when the link is used, cancelled or expires. Links
created before this revision have none: the console offers to cancel them and create a new one.
"""
from alembic import op
import sqlalchemy as sa

revision = '0011'
down_revision = '0010'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('enrollments', sa.Column('token_ct', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('enrollments', 'token_ct')
