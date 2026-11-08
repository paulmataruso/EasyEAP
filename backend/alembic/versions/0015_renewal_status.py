"""Certificate renewal, phase 2a: who renews each certificate, check-ins, retirement of superseded certificates

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-08 22:00:00

docs/plans/cert-renewal.md §15b. `certificates.renewer` (windows-setup | windows-helper | linux | gpo | NULL: needs the
user), its version, the last signed check-in and the roots it reported, and when a superseded certificate was retired.
Existing certificates get `renewer` from how they were issued (the phase 1 heuristic); a renewal inherits its
predecessor's. `renewal_settings.retire_superseded` (on).
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0015'
down_revision = '0014'
branch_labels = None
depends_on = None

TS = postgresql.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.add_column('certificates', sa.Column('renewer', sa.String(16), nullable=True))
    op.add_column('certificates', sa.Column('renewer_version', sa.String(8), nullable=True))
    op.add_column('certificates', sa.Column('renewal_checked_at', TS, nullable=True))
    op.add_column('certificates', sa.Column('trust_reported', postgresql.JSONB(), nullable=True))
    op.add_column('certificates', sa.Column('retired_at', TS, nullable=True))
    op.add_column('renewal_settings', sa.Column('retire_superseded', sa.Boolean(), nullable=False, server_default=sa.true()))
    # Who renews what was issued so far (app/pki/renewal.py renewer()).
    op.execute("""
        UPDATE certificates c SET renewer = 'gpo', renewer_version = NULL
        WHERE c.purpose IN ('user', 'device', 'computer') AND (c.enrollment_source = 'gpo' OR EXISTS (
            SELECT 1 FROM certificate_templates t WHERE t.id = c.template_id AND t.autoenroll_kind IS NOT NULL))""")
    op.execute("""
        UPDATE certificates c SET renewer = CASE WHEN e.method = 'windows-setup' THEN 'windows-setup' ELSE 'linux' END, renewer_version = '1'
        FROM enrollments e
        WHERE c.renewer IS NULL AND e.id = c.enrollment_id AND c.purpose IN ('user', 'device', 'computer')
          AND (e.method = 'windows-setup' OR (e.platform = 'linux' AND c.key_origin = 'device'))""")
    for _ in range(6):  # renewal chains: each renewal inherits its predecessor's renewer
        op.execute("""
            UPDATE certificates c SET renewer = p.renewer, renewer_version = p.renewer_version
            FROM certificates p WHERE c.renewer IS NULL AND c.renewal_of = p.id AND p.renewer IS NOT NULL""")
    op.create_index('ix_certificates_renewal_of', 'certificates', ['renewal_of'])


def downgrade() -> None:
    op.drop_index('ix_certificates_renewal_of', table_name='certificates')
    op.drop_column('renewal_settings', 'retire_superseded')
    for col in ('retired_at', 'trust_reported', 'renewal_checked_at', 'renewer_version', 'renewer'):
        op.drop_column('certificates', col)
