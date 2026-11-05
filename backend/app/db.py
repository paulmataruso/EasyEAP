"""Database engine and session helpers, including tenant context for row-level security."""
from __future__ import annotations

import contextlib
import uuid
from collections.abc import Iterator

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


_engine = None
_SessionLocal: sessionmaker[Session] | None = None


def engine():
    global _engine, _SessionLocal
    if _engine is None:
        _engine = create_engine(get_settings().database_url, pool_pre_ping=True, pool_size=10, max_overflow=10)
        _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def reset_engine() -> None:
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine, _SessionLocal = None, None


def new_session() -> Session:
    engine()
    assert _SessionLocal is not None
    return _SessionLocal()


def _apply_scope(session: Session, connection) -> None:
    tenant = session.info.get("tenant_id")
    platform = "on" if session.info.get("platform") else "off"
    connection.execute(
        text("SELECT set_config('easyeap.tenant_id', :t, true), set_config('easyeap.platform', :p, true)"),
        {"t": str(tenant) if tenant else "", "p": platform},
    )


@event.listens_for(Session, "after_begin")
def _scope_on_begin(session: Session, transaction, connection) -> None:  # noqa: ARG001
    """Re-apply the tenant/platform scope at the start of every transaction (SET LOCAL is per-transaction)."""
    _apply_scope(session, connection)


def set_tenant(session: Session, tenant_id: uuid.UUID | None) -> None:
    """Scope this session to one tenant for row-level security."""
    session.info["tenant_id"] = tenant_id
    session.info["platform"] = False
    if session.in_transaction():
        _apply_scope(session, session.connection())


def set_platform(session: Session) -> None:
    """Allow cross-tenant access for explicit platform operations (MSP overview, worker jobs)."""
    session.info["platform"] = True
    if session.in_transaction():
        _apply_scope(session, session.connection())


@contextlib.contextmanager
def platform_session() -> Iterator[Session]:
    s = new_session()
    try:
        set_platform(s)
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


@contextlib.contextmanager
def tenant_session(tenant_id: uuid.UUID) -> Iterator[Session]:
    s = new_session()
    try:
        set_tenant(s, tenant_id)
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()
