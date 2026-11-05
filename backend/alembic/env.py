from alembic import context
from sqlalchemy import create_engine, pool, text

from app.config import get_settings
from app.db import Base
import app.models  # noqa: F401  (register models)

target_metadata = Base.metadata


def run_migrations_online() -> None:
    # Migrations run as the database owner; the application role is subject to RLS.
    engine = create_engine(get_settings().database_owner_url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        connection.execute(text("SELECT pg_advisory_lock(424242)"))  # one migrator at a time
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()
        connection.execute(text("SELECT pg_advisory_unlock(424242)"))
        connection.commit()


run_migrations_online()
