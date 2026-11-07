"""Windows 11 setup: where each certificate's key lives, and certificate renewal

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-07 23:00:00

docs/plans/windows-setup.md. Nothing that works before this migration changes after it: `key_storage` is NULL (not
reported) for every existing certificate, and renewal only applies to certificates whose key signs the request.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None

TS = postgresql.TIMESTAMP(timezone=True)


def upgrade() -> None:
    # tpm | software | NULL (not reported): from the Windows setup and helper, which know where Windows created the key.
    op.add_column('certificates', sa.Column('key_storage', sa.String(length=16), nullable=True))
    # The certificate this one renewed (POST /api/enroll/renew), and when this one was renewed.
    op.add_column('certificates', sa.Column('renewal_of', sa.UUID(), nullable=True))
    op.add_column('certificates', sa.Column('renewed_at', TS, nullable=True))


def downgrade() -> None:
    op.drop_column('certificates', 'renewed_at')
    op.drop_column('certificates', 'renewal_of')
    op.drop_column('certificates', 'key_storage')
