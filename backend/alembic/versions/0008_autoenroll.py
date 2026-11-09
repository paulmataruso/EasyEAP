"""Group Policy autoenrollment: computer identities, Kerberos, autoenroll templates, request log

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-08 00:00:00

docs/plans/gpo-autoenrollment.md §3. Nothing that works before this migration changes after it: every existing
identity is a user, existing templates have no template OID (not offered to Windows), and autoenrollment is off.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None

TS = postgresql.TIMESTAMP(timezone=True)
NEW_TABLES = ("autoenroll_configs", "autoenroll_events")


def upgrade() -> None:
    # Computers enrolled through Group Policy are identities too (kind computer, username NAME$), so policy, RADIUS and
    # the console treat them like users.
    op.add_column('identities', sa.Column('kind', sa.String(length=10), nullable=False, server_default='user'))
    op.add_column('identities', sa.Column('dns_name', sa.String(length=253), nullable=True))
    op.create_index('ix_identities_tenant_kind', 'identities', ['tenant_id', 'kind'])

    # A template Windows can autoenroll for: its OID (AD CS style, 32-bit arcs) and revision, which go into the
    # certificate template extension; autoenroll_kind says who gets it (computer | user).
    op.add_column('certificate_templates', sa.Column('template_oid', sa.String(length=128), nullable=True))
    op.add_column('certificate_templates', sa.Column('revision_major', sa.Integer(), nullable=False, server_default='100'))
    op.add_column('certificate_templates', sa.Column('revision_minor', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('certificate_templates', sa.Column('autoenroll_kind', sa.String(length=10), nullable=True))

    # gpo for certificates Windows enrolled through Group Policy (no enrollment link or setup file).
    op.add_column('certificates', sa.Column('enrollment_source', sa.String(length=16), nullable=True))

    op.create_table(
        'autoenroll_configs',
        sa.Column('tenant_id', sa.UUID(), sa.ForeignKey('tenants.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('computers', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('users', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('policy_id', sa.String(length=64), nullable=False),
        sa.Column('oid_root', sa.String(length=128), nullable=False),
        sa.Column('service_account', sa.String(length=20), nullable=False, server_default='easyeap-cep'),
        sa.Column('keytab_ct', sa.Text(), nullable=True),
        sa.Column('keytab_info', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('keytab_uploaded_at', TS, nullable=True),
        sa.Column('keytab_test', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('require_channel_binding', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('computer_group_id', sa.UUID(), sa.ForeignKey('directory_groups.id', ondelete='SET NULL'), nullable=True),
        sa.Column('response_format', sa.String(length=16), nullable=False, server_default='unsigned'),
        # ms-DS-MachineAccountQuota, read at each directory sync: how many computers any domain user may add.
        sa.Column('machine_account_quota', sa.Integer(), nullable=True),
        sa.Column('signer_cert_pem', sa.Text(), nullable=True),
        sa.Column('signer_key_ct', sa.Text(), nullable=True),
        sa.Column('last_success_at', TS, nullable=True),
        sa.Column('last_error_at', TS, nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('updated_at', TS, nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        'autoenroll_events',
        sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('tenant_id', sa.UUID(), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('at', TS, nullable=False, server_default=sa.func.now(), index=True),
        sa.Column('service', sa.String(length=8), nullable=False),  # cep | ces
        sa.Column('caller', sa.String(length=256), nullable=False, server_default=''),
        sa.Column('kind', sa.String(length=10), nullable=True),  # computer | user
        sa.Column('outcome', sa.String(length=8), nullable=False),  # ok | denied | error
        sa.Column('code', sa.String(length=32), nullable=False, server_default=''),
        sa.Column('message', sa.Text(), nullable=False, server_default=''),
        sa.Column('template', sa.String(length=80), nullable=True),
        sa.Column('machine', sa.String(length=253), nullable=True),
        sa.Column('certificate_id', sa.UUID(), nullable=True),
        sa.Column('ip', sa.String(length=64), nullable=True),
    )
    for table in NEW_TABLES:
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO easyeap_app")
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} USING ("
            f"current_setting('easyeap.platform', true) = 'on' OR "
            f"tenant_id::text = current_setting('easyeap.tenant_id', true))"
        )
    op.execute("GRANT USAGE, SELECT ON SEQUENCE autoenroll_events_id_seq TO easyeap_app")


def downgrade() -> None:
    # What 0007 can't tell apart from its own rows. Computers would read as users (marked deleted by the next sync, or
    # tripping its safety stop): they're marked deleted now, so their certificates stop working as they would without
    # autoenrollment. The Group Policy templates would read as ordinary ones that enrollment links could pick: they go
    # (their certificates keep their records, with no template). 0007 has no computer purpose.
    op.execute("UPDATE identities SET account_state = 'deleted' WHERE kind = 'computer'")
    op.execute("UPDATE certificates SET purpose = 'device' WHERE purpose = 'computer'")
    op.execute("DELETE FROM certificate_templates WHERE autoenroll_kind IS NOT NULL "
               "AND id NOT IN (SELECT template_id FROM enrollments WHERE template_id IS NOT NULL)")
    for table in reversed(NEW_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.drop_table(table)
    op.drop_column('certificates', 'enrollment_source')
    for col in ('autoenroll_kind', 'revision_minor', 'revision_major', 'template_oid'):
        op.drop_column('certificate_templates', col)
    op.drop_index('ix_identities_tenant_kind', table_name='identities')
    op.drop_column('identities', 'dns_name')
    op.drop_column('identities', 'kind')
