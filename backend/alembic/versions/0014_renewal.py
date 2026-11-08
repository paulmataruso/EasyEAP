"""Certificate renewal, phase 1: per-tenant switches and percentage, RADIUS server certificate rollback

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-08 21:00:00

docs/plans/cert-renewal.md §15a. `renewal_settings`: one row per tenant (made on first read when missing) with
whether user, machine and RADIUS server certificates renew by themselves and at what share of their lifetime.
`radius_settings` keeps the previous server certificate and key for 14 days after a rotation, for a rollback.
Templates other than Group Policy's take their renewal period from the percentage (80 %: a fifth of the validity).
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0014'
down_revision = '0013'
branch_labels = None
depends_on = None

TS = postgresql.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.create_table(
        'renewal_settings',
        sa.Column('tenant_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('tenants.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('user_certs', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('machine_certs', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('server_cert', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('renew_at_percent', sa.Integer(), nullable=False, server_default='80'),
        sa.Column('updated_at', TS, nullable=True),
        sa.Column('updated_by', sa.String(254), nullable=True),
        sa.CheckConstraint('renew_at_percent BETWEEN 50 AND 90', name='ck_renewal_percent'),
    )
    op.execute("INSERT INTO renewal_settings (tenant_id) SELECT id FROM tenants")  # every tenant starts with the defaults
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON renewal_settings TO easyeap_app")
    op.execute("ALTER TABLE renewal_settings ENABLE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY tenant_isolation ON renewal_settings USING ("
               "current_setting('easyeap.platform', true) = 'on' OR tenant_id::text = current_setting('easyeap.tenant_id', true))")

    op.add_column('radius_settings', sa.Column('previous_server_certificate_id', postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column('radius_settings', sa.Column('previous_server_key_ct', sa.Text(), nullable=True))
    op.add_column('radius_settings', sa.Column('server_cert_rotated_at', TS, nullable=True))

    # 80 % of each certificate's lifetime: renewal starts a fifth of the validity before expiry. Group Policy's
    # templates keep the period set on the Autoenroll screen.
    op.execute("UPDATE certificate_templates SET renew_before_days = GREATEST(1, CEIL(validity_days * 0.2)::int) WHERE autoenroll_kind IS NULL")


def downgrade() -> None:
    # The templates' recalculated renewal days stay: they're valid without renewal settings, and the old values are gone.
    op.drop_column('radius_settings', 'server_cert_rotated_at')
    op.drop_column('radius_settings', 'previous_server_key_ct')
    op.drop_column('radius_settings', 'previous_server_certificate_id')
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON renewal_settings")
    op.drop_table('renewal_settings')
