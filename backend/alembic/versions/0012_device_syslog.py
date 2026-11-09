"""Device syslog: every message from switches and controllers, a live cursor, per-device counters

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-08 14:00:00

docs/plans/syslog-full.md. `switch_syslog` keeps its name and now holds every message of every device that sends
syslog: `seq` (set by a trigger on insert and update, the live view's cursor), `notable` (what EasyEAP decodes: kept
14 days, the rest 3) and `source` (the sender's address). Existing rows were all from the old keep list: notable.
`radius_clients.syslog` holds a device's syslog switch and extra source addresses. `syslog_stats` replaces
`switch_states.syslog` (the column stays, unused, for a downgrade). Server defaults on every new column let the
previous receiver keep inserting while the upgrade runs.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0012'
down_revision = '0011'
branch_labels = None
depends_on = None

TS = postgresql.TIMESTAMP(timezone=True)


def upgrade() -> None:
    op.add_column('radius_clients', sa.Column('syslog', postgresql.JSONB(), nullable=False, server_default='{}'))

    # CACHE 1 (the default): values are handed out in call order, so with one writer, commit order = seq order.
    op.execute("CREATE SEQUENCE switch_syslog_seq AS bigint CACHE 1")
    op.execute("GRANT USAGE, SELECT ON SEQUENCE switch_syslog_seq TO easyeap_app")
    op.add_column('switch_syslog', sa.Column('seq', sa.BigInteger(), nullable=False, server_default=sa.text("nextval('switch_syslog_seq')")))
    op.add_column('switch_syslog', sa.Column('notable', sa.Boolean(), nullable=False, server_default=sa.text('true')))
    op.add_column('switch_syslog', sa.Column('source', sa.String(length=64), nullable=False, server_default=''))
    op.execute(
        "CREATE FUNCTION easyeap_switch_syslog_seq() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN NEW.seq := nextval('switch_syslog_seq'); RETURN NEW; END $$")
    op.execute("CREATE TRIGGER switch_syslog_seq BEFORE INSERT OR UPDATE ON switch_syslog "
               "FOR EACH ROW EXECUTE FUNCTION easyeap_switch_syslog_seq()")
    op.create_index('ix_switch_syslog_tenant_seq', 'switch_syslog', ['tenant_id', 'seq'])
    op.create_index('ix_switch_syslog_client_seq', 'switch_syslog', ['client_id', 'seq'])

    op.create_table(
        'syslog_stats',
        sa.Column('client_id', sa.UUID(), nullable=False),
        sa.Column('tenant_id', sa.UUID(), nullable=False),
        sa.Column('day', sa.Date(), nullable=False),
        sa.Column('received', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('kept', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('quota', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('bytes', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('last_at', TS, nullable=True),
        sa.Column('last_tag', sa.String(length=100), nullable=False, server_default=''),
        sa.ForeignKeyConstraint(['client_id'], ['radius_clients.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('client_id'),
    )
    op.create_index('ix_syslog_stats_tenant_id', 'syslog_stats', ['tenant_id'])
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON syslog_stats TO easyeap_app")
    op.execute("ALTER TABLE syslog_stats ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON syslog_stats USING ("
        "current_setting('easyeap.platform', true) = 'on' OR "
        "tenant_id::text = current_setting('easyeap.tenant_id', true))"
    )
    # Today's counters move over; bytes from what's stored today (the quota used to sum the table).
    op.execute(
        "INSERT INTO syslog_stats (client_id, tenant_id, day, received, kept, quota, bytes, last_at, last_tag) "
        "SELECT s.client_id, s.tenant_id, (s.syslog->>'day')::date, COALESCE((s.syslog->>'received')::bigint, 0), "
        "COALESCE((s.syslog->>'kept')::bigint, 0), COALESCE((s.syslog->>'quota')::bigint, 0), "
        "COALESCE((SELECT sum(length(l.text) + 200) FROM switch_syslog l WHERE l.client_id = s.client_id "
        "AND l.first_at >= (s.syslog->>'day')::date), 0), "
        "(s.syslog->>'last_at')::timestamptz, COALESCE(s.syslog->>'last_tag', '') "
        "FROM switch_states s WHERE s.syslog ? 'day'")


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON syslog_stats")
    op.drop_table('syslog_stats')
    op.drop_index('ix_switch_syslog_client_seq', table_name='switch_syslog')
    op.drop_index('ix_switch_syslog_tenant_seq', table_name='switch_syslog')
    op.execute("DROP TRIGGER IF EXISTS switch_syslog_seq ON switch_syslog")
    op.execute("DROP FUNCTION IF EXISTS easyeap_switch_syslog_seq()")
    op.drop_column('switch_syslog', 'source')
    op.drop_column('switch_syslog', 'notable')
    op.drop_column('switch_syslog', 'seq')
    op.execute("DROP SEQUENCE IF EXISTS switch_syslog_seq")
    op.drop_column('radius_clients', 'syslog')
