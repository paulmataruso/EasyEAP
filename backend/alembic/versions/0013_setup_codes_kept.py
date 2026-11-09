"""Windows setup files: keep a waiting file's one-time codes and choices, so the admin can download it again

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-08 20:00:00

A Windows setup enrollment now keeps its one-time code in `token_ct` (encrypted with the tenant's transit key, as
links have since 0011; cleared when the code is used, cancelled or expires) and the choices the file was made with in
`setup_options` (Wi-Fi, wired, shared PC, which certificates: nothing secret). Files made before this revision have
neither: the console offers to cancel them and make a new one.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0013'
down_revision = '0012'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('enrollments', sa.Column('setup_options', postgresql.JSONB(), nullable=True))
    # The worker expired links without clearing their kept token (link_token checks the expiry, so none was shown).
    op.execute("UPDATE enrollments SET token_ct = NULL WHERE status <> 'pending' AND token_ct IS NOT NULL")


def downgrade() -> None:
    # The previous version keeps no setup codes and doesn't clear them on expiry.
    op.execute("UPDATE enrollments SET token_ct = NULL WHERE method = 'windows-setup'")
    op.drop_column('enrollments', 'setup_options')
