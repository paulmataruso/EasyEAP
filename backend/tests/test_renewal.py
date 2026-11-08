"""Certificate renewal, phase 1 (docs/plans/cert-renewal.md §15a): windows, templates' days, who renews, the lifetime cap,
the RADIUS server certificate's rotation and rollback, and refusals audited once a day."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app import models as m
from app.autoenroll import service as ae
from app.pki import renewal
from app.pki import service as pki
from app.routers import enroll_public as ep

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)


def _cert(days_in: float, days_left: float, **kw):
    return SimpleNamespace(id=uuid.uuid4(), not_before=NOW - timedelta(days=days_in), not_after=NOW + timedelta(days=days_left),
                           status="active", serial=kw.pop("serial", "AB"), common_name="radius.corp.example", **kw)


# ── Windows and templates ───────────────────────────────────────────────────


def test_renew_from_is_a_share_of_the_certificates_own_life():
    c = _cert(0, 365)
    assert renewal.renew_from(c, 80) == NOW + timedelta(days=292)
    short = _cert(0, 30)  # cut short by an expiring CA: renews in proportion, not at once
    assert renewal.renew_from(short, 80) == NOW + timedelta(days=24)
    assert renewal.renew_from(c, 50) == NOW + timedelta(days=182.5)


@pytest.mark.parametrize(("validity", "percent", "days"), [(365, 80, 73), (730, 80, 146), (397, 80, 80), (365, 90, 37), (365, 50, 183), (1, 90, 1)])
def test_templates_days_come_from_the_percentage(validity, percent, days):
    assert renewal.derived_days(validity, percent) == days


def test_apply_to_templates_leaves_group_policy_alone():
    gp = SimpleNamespace(name="EasyEAP computer", validity_days=365, renew_before_days=42, autoenroll_kind="computer")
    user = SimpleNamespace(name="User Wi-Fi", validity_days=365, renew_before_days=30, autoenroll_kind=None)
    same = SimpleNamespace(name="Device Wi-Fi", validity_days=730, renew_before_days=146, autoenroll_kind=None)

    class S:
        def scalars(self, stmt):
            assert "autoenroll_kind IS NULL" in str(stmt)
            return [user, same]

    assert renewal.apply_to_templates(S(), uuid.uuid4(), 80) == {"User Wi-Fi": "30 → 73 days"}
    assert user.renew_before_days == 73 and gp.renew_before_days == 42


def test_switches_by_purpose():
    st = SimpleNamespace(user_certs=True, machine_certs=False, server_cert=True)
    assert renewal.enabled_for(st, "user") and renewal.enabled_for(st, "radius-server")
    assert not renewal.enabled_for(st, "device") and not renewal.enabled_for(st, "computer") and not renewal.enabled_for(st, None)


@pytest.mark.parametrize(("cert", "enrollment", "tpl", "who"), [
    ({"enrollment_source": "gpo"}, None, None, "gpo"),
    ({}, None, {"autoenroll_kind": "user"}, "gpo"),
    ({}, {"method": "windows-setup", "platform": "windows"}, {}, "windows-setup"),
    ({"key_origin": "device"}, {"method": "link", "platform": "linux"}, {}, "linux"),
    ({"key_origin": "browser"}, {"method": "link", "platform": "linux"}, {}, None),  # the portal's by-hand route
    ({"key_origin": "device"}, {"method": "link", "platform": "ios"}, {}, None),
    ({"renewal_of": uuid.uuid4()}, {"method": "link", "platform": "macos"}, {}, "renewed"),
    ({}, {"method": "server", "platform": "android"}, {}, None),
])
def test_who_renews(cert, enrollment, tpl, who):
    c = SimpleNamespace(**{"enrollment_source": None, "key_origin": "csr", "renewal_of": None, **cert})
    e = SimpleNamespace(**enrollment) if enrollment is not None else None
    t = SimpleNamespace(**{"autoenroll_kind": None, **tpl}) if tpl is not None else None
    assert renewal.renewer(c, e, t) == who


def test_overdue_waits_for_copies_made_before_this_change():
    """Setup files and scripts made before 0014 ask from 30 or 45 days before expiry: not overdue before 14 days left."""
    c = SimpleNamespace(not_before=NOW - timedelta(days=330), not_after=NOW + timedelta(days=35))
    assert renewal.overdue_at(c, 80) == c.not_after - timedelta(days=14)
    short = SimpleNamespace(not_before=NOW, not_after=NOW + timedelta(days=60))  # 80 % + 14 days is later than 14 days left
    assert renewal.overdue_at(short, 80) == NOW + timedelta(days=62)


# ── The lifetime cap ────────────────────────────────────────────────────────


def test_a_leaf_never_outlives_the_issuing_ca():
    ca = SimpleNamespace(not_after=NOW + timedelta(days=100))
    assert pki.capped_ttl_hours(ca, 365, NOW) == 100 * 24 - 1
    assert pki.capped_ttl_hours(ca, 30, NOW) == 30 * 24
    with pytest.raises(pki.PkiError, match="too soon"):
        pki.capped_ttl_hours(SimpleNamespace(not_after=NOW + timedelta(hours=20)), 365, NOW)


def test_group_policy_renewal_period_stays_under_a_fifth():
    tpl = SimpleNamespace(autoenroll_kind="computer", template_oid="1.2.3", revision_major=100, revision_minor=0, validity_days=365,
                          renew_before_days=200)  # an older setting, from when ¾ was allowed
    assert ae.template_policy(tpl).renewal_seconds == 365 * 86400 * 19 // 100
    tpl.renew_before_days = 42
    assert ae.template_policy(tpl).renewal_seconds == 42 * 86400


# ── The RADIUS server certificate ───────────────────────────────────────────


class Store:
    """get() by id over a few objects; RadiusSettings by tenant id."""

    def __init__(self, *objs, rs=None):
        self.objs = {o.id: o for o in objs}
        self.rs = rs

    def get(self, model, ident, **kw):
        if model is m.RadiusSettings:
            return self.rs
        return self.objs.get(ident)


def _rs(cur, prev=None, rotated=None):
    return SimpleNamespace(tenant_id=uuid.uuid4(), server_hostname="radius.corp.example", server_certificate_id=cur.id, server_key_ct="key-cur",
                           previous_server_certificate_id=prev.id if prev else None, previous_server_key_ct="key-prev" if prev else None,
                           server_cert_rotated_at=rotated, config_version=7)


@pytest.fixture()
def rotation(monkeypatch):
    st = SimpleNamespace(user_certs=True, machine_certs=True, server_cert=True, renew_at_percent=80)
    monkeypatch.setattr(renewal, "settings", lambda s, tid: st)
    ca = SimpleNamespace(not_after=NOW + timedelta(days=1000))
    monkeypatch.setattr(pki, "issuing_ca", lambda s, tid: ca)
    issued = []

    def ensure(session, bao, tenant, hostname, now=None):
        issued.append(hostname)
        return SimpleNamespace(id=uuid.uuid4())

    import app.radius.state as state
    monkeypatch.setattr(state, "ensure_server_certificate", ensure)
    return SimpleNamespace(settings=st, ca=ca, issued=issued)


def test_server_rotates_once_due(rotation):
    tenant = SimpleNamespace(id=uuid.uuid4())
    cur = _cert(300, 97)  # 300 of 397 days: 75.6 %
    s = Store(cur, rs=_rs(cur))
    assert renewal.rotate_server_cert_if_due(s, None, tenant, NOW) is None and rotation.issued == []
    cur.not_before = NOW - timedelta(days=400)  # 400 of 497 days: 80.5 %
    assert renewal.rotate_server_cert_if_due(s, None, tenant, NOW) is not None and rotation.issued == ["radius.corp.example"]


def test_server_rotation_waits_for_switch_and_ca(rotation):
    tenant = SimpleNamespace(id=uuid.uuid4())
    cur = _cert(390, 7)
    s = Store(cur, rs=_rs(cur))
    rotation.settings.server_cert = False
    assert renewal.rotate_server_cert_if_due(s, None, tenant, NOW) is None
    rotation.settings.server_cert = True
    rotation.ca.not_after = NOW + timedelta(days=20)  # would give a 20-day certificate that rotates again in 16
    assert renewal.rotate_server_cert_if_due(s, None, tenant, NOW) is None and rotation.issued == []


def test_old_key_is_dropped_after_the_rollback_period(rotation):
    tenant = SimpleNamespace(id=uuid.uuid4())
    prev, cur = _cert(400, -3), _cert(20, 377)
    rs = _rs(cur, prev, rotated=NOW - timedelta(days=15))
    renewal.rotate_server_cert_if_due(Store(cur, prev, rs=rs), None, tenant, NOW)
    assert rs.previous_server_key_ct is None and rs.previous_server_certificate_id is None


def test_rollback_swaps_and_pauses_rotation(rotation):
    prev, cur = _cert(330, 67, serial="01"), _cert(1, 396, serial="02")
    prev.status = "superseded"
    rs = _rs(cur, prev, rotated=NOW - timedelta(days=1))
    s = Store(cur, prev, rs=rs)
    restored, aside = renewal.rollback_server_cert(s, rs.tenant_id, "admin@corp.example", NOW)
    assert restored is prev and aside is cur and prev.status == "active" and cur.status == "superseded"
    assert rs.server_certificate_id == prev.id and rs.server_key_ct == "key-prev"
    assert rs.previous_server_certificate_id == cur.id and rs.previous_server_key_ct == "key-cur"
    assert rs.config_version == 8 and rotation.settings.server_cert is False and rotation.settings.updated_by == "admin@corp.example"
    renewal.rollback_server_cert(s, rs.tenant_id, "admin@corp.example", NOW)  # and back again
    assert rs.server_certificate_id == cur.id and rs.server_key_ct == "key-cur"


@pytest.mark.parametrize("why", ["late", "expiring", "revoked", "no key", "other name"])
def test_no_rollback_when_it_cant_work(rotation, why):
    prev, cur = _cert(330, 67), _cert(1, 396)
    rs = _rs(cur, prev, rotated=NOW - timedelta(days=1))
    if why == "late":
        rs.server_cert_rotated_at = NOW - timedelta(days=15)
    elif why == "expiring":
        prev.not_after = NOW + timedelta(hours=12)
    elif why == "revoked":
        prev.status = "revoked"
    elif why == "no key":
        rs.previous_server_key_ct = None
    else:
        rs.server_hostname = "radius2.corp.example"  # renamed since: the old certificate would fail every new profile
    with pytest.raises(renewal.RenewalError, match="no previous server certificate"):
        renewal.rollback_server_cert(Store(cur, prev, rs=rs), rs.tenant_id, "admin@corp.example", NOW)
    assert rs.server_certificate_id == cur.id


def test_server_status(rotation):
    prev, cur = _cert(330, 67, serial="01"), _cert(10, 387, serial="02")
    rs = _rs(cur, prev, rotated=NOW - timedelta(days=10))
    out = renewal.server_status(Store(cur, prev, rs=rs), rs.tenant_id, NOW)
    assert out["serial"] == "02" and out["rotates_at"] == renewal.renew_from(cur, 80).isoformat()
    assert out["previous"]["serial"] == "01" and out["previous"]["until"] == (NOW + timedelta(days=4)).isoformat()
    rotation.settings.server_cert = False
    assert renewal.server_status(Store(cur, prev, rs=rs), rs.tenant_id, NOW)["rotates_at"] is None


@pytest.mark.parametrize("hostname", ["radius.corp.example", "radius2.corp.example"])
def test_ensure_server_certificate_keeps_the_previous_one(monkeypatch, hostname):
    import app.radius.state as state
    tid = uuid.uuid4()
    old = SimpleNamespace(id=uuid.uuid4(), status="active", common_name="radius.corp.example")
    new = SimpleNamespace(id=uuid.uuid4(), status="active")
    rs = SimpleNamespace(server_certificate_id=old.id, server_key_ct="key-old", previous_server_certificate_id=None, previous_server_key_ct=None,
                         server_cert_rotated_at=None, server_hostname="radius.corp.example", config_version=1)
    tpl = SimpleNamespace(purpose="radius-server")

    class S:
        def get(self, model, ident):
            return rs if model is m.RadiusSettings else {old.id: old}.get(ident)

        def scalars(self, stmt):
            return SimpleNamespace(first=lambda: tpl)

    monkeypatch.setattr(state.pki, "issue_with_server_key", lambda *a, **kw: (new, "PEM"))
    monkeypatch.setattr(state.crypto, "encrypt", lambda t, k, b: "key-new")
    state.ensure_server_certificate(S(), None, SimpleNamespace(id=tid), hostname, now=NOW)
    if hostname == "radius.corp.example":
        assert rs.previous_server_certificate_id == old.id and rs.previous_server_key_ct == "key-old"
    else:  # a new name: nothing to put back
        assert rs.previous_server_certificate_id is None and rs.previous_server_key_ct is None
    assert rs.server_cert_rotated_at == NOW
    assert rs.server_certificate_id == new.id and rs.server_key_ct == "key-new" and old.status == "superseded"


# ── Refusals: audited once a day per certificate and reason ─────────────────


def test_refusal_audited_once_a_day(monkeypatch):
    cert = SimpleNamespace(id=uuid.uuid4(), tenant_id=uuid.uuid4(), common_name="nina", serial="0A", purpose="user")
    audits, committed, seen = [], [], {"n": 0}

    class S:
        def rollback(self):
            pass

        def commit(self):
            committed.append(True)

        def scalar(self, stmt):
            assert "certificate.renewal_refused" in str(stmt.compile(compile_kwargs={"literal_binds": True}))
            return seen["n"]

    monkeypatch.setattr(ep, "set_platform", lambda s: None)
    monkeypatch.setattr(ep, "client_ip", lambda r: "192.0.2.1")
    monkeypatch.setattr(ep.audit, "record", lambda s, actor, action, **kw: audits.append((action, kw["detail"]["reason"])))
    exc = ep.enr.RenewalRefused("turned off", cert, "off")
    ep._refused(S(), exc, None)
    assert audits == [("certificate.renewal_refused", "off")] and committed == [True]
    seen["n"] = 1
    ep._refused(S(), exc, None)
    assert len(audits) == 1 and len(committed) == 1


# ── The CA schedule ─────────────────────────────────────────────────────────


def test_ca_schedule():
    tid = uuid.uuid4()
    issuing = SimpleNamespace(role="issuing", common_name="Corp Issuing CA", not_before=NOW - timedelta(days=365),
                              not_after=NOW + timedelta(days=5 * 365 - 365))
    root = SimpleNamespace(role="root", common_name="Corp Root CA", not_after=NOW + timedelta(days=20 * 365), crl_next_update=NOW + timedelta(days=300))

    class S:
        def scalars(self, stmt):
            return SimpleNamespace(all=lambda: [root, issuing])

        def scalar(self, stmt):
            return 730

    out = renewal.ca_schedule(S(), tid, NOW)
    e = issuing.not_after
    assert out["issuing"]["switch_by"] == (e - timedelta(days=730 + 90)).isoformat()
    # P = min(S − 180 days, halfway through the CA's life)
    assert out["issuing"]["prepare_by"] == min(e - timedelta(days=730 + 90 + 180), issuing.not_before + (e - issuing.not_before) / 2).isoformat()
    assert out["issuing"]["shortening"] is False and out["root"]["common_name"] == "Corp Root CA" and out["longest_validity_days"] == 730
