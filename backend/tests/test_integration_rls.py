"""Row-level security: a tenant-scoped session can never read or write another tenant's rows.

Runs against a real PostgreSQL with the EasyEAP migrations applied, connected as the non-owner app role.
Enable with EASYEAP_TEST_INTEGRATION=1 (the dev stack in DEVELOPMENT.md sets this up).
"""
import os
import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

pytestmark = [pytest.mark.integration,
              pytest.mark.skipif(os.environ.get("EASYEAP_TEST_INTEGRATION") != "1", reason="integration stack not enabled")]

from app import models as m  # noqa: E402
from app.db import new_session, set_platform, set_tenant  # noqa: E402


@pytest.fixture()
def two_tenants():
    s = new_session()
    set_platform(s)
    ids = []
    for label in ("rls-a", "rls-b"):
        t = m.Tenant(slug=f"{label}-{uuid.uuid4().hex[:6]}", name=label)
        s.add(t)
        s.flush()
        s.add(m.Identity(tenant_id=t.id, source="local", username=f"{label}-user", display_name=label))
        ids.append(t.id)
    s.commit()
    s.close()
    yield ids
    s = new_session()
    set_platform(s)
    for tid in ids:
        s.execute(text("DELETE FROM identities WHERE tenant_id = :t"), {"t": tid})
        s.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": tid})
    s.commit()
    s.close()


def test_connected_role_is_not_owner():
    s = new_session()
    try:
        row = s.execute(text("SELECT current_user, rolbypassrls, rolsuper FROM pg_roles WHERE rolname = current_user")).one()
        assert row[1] is False and row[2] is False, f"{row[0]} must not bypass RLS"
    finally:
        s.close()


def test_scoped_session_sees_only_its_tenant(two_tenants):
    a, b = two_tenants
    s = new_session()
    try:
        set_tenant(s, a)
        names = s.scalars(select(m.Identity.username).where(m.Identity.tenant_id.in_([a, b]))).all()
        assert names == ["rls-a-user"]
    finally:
        s.close()


def test_unscoped_session_sees_nothing(two_tenants):
    a, _ = two_tenants
    s = new_session()
    try:
        assert s.scalars(select(m.Identity).where(m.Identity.tenant_id == a)).all() == []
    finally:
        s.close()


def test_cross_tenant_insert_is_rejected(two_tenants):
    a, b = two_tenants
    s = new_session()
    try:
        set_tenant(s, a)
        s.add(m.Identity(tenant_id=b, source="local", username="smuggled", display_name="x"))
        with pytest.raises(DBAPIError):
            s.flush()
        s.rollback()
    finally:
        s.close()


def test_cross_tenant_update_affects_no_rows(two_tenants):
    a, b = two_tenants
    s = new_session()
    try:
        set_tenant(s, a)
        res = s.execute(text("UPDATE identities SET display_name = 'pwned' WHERE tenant_id = :b"), {"b": b})
        assert res.rowcount == 0
        s.rollback()
    finally:
        s.close()


@pytest.mark.parametrize("stmt", ["UPDATE audit_events SET action = 'x'", "DELETE FROM audit_events"])
def test_audit_log_is_append_only(stmt):
    """The app role holds no UPDATE/DELETE grant, so even a platform-scoped session cannot rewrite history."""
    s = new_session()
    try:
        set_platform(s)
        with pytest.raises(DBAPIError, match="permission denied"):
            s.execute(text(stmt))
        s.rollback()
    finally:
        s.close()
