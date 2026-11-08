"""Certificate renewal, phases 1 and 2a (docs/plans/cert-renewal.md §15a, §15b): windows, templates' days, who renews,
the lifetime cap, the RADIUS server certificate's rotation and rollback, refusals audited once a day, how each client
certificate stands, superseded certificates retired, and revocation of a renewal chain."""
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


def test_the_recorded_renewer_wins():
    c = SimpleNamespace(renewer="windows-helper", enrollment_source="gpo", key_origin="csr", renewal_of=None)
    assert renewal.renewer(c, None, None) == "windows-helper"
    c.renewer = None
    assert renewal.renewer(c, None, None) == "gpo"


def _row(days_in, days_left, *, renewer="windows-setup", checked=None, purpose="device", method=None):
    return SimpleNamespace(not_before=NOW - timedelta(days=days_in), not_after=NOW + timedelta(days=days_left), purpose=purpose,
                           renewer=renewer, renewal_checked_at=checked, method=method, platform=None, enrollment_source=None,
                           key_origin="device", renewal_of=None, autoenroll_kind=None)


ON = SimpleNamespace(user_certs=True, machine_certs=True, server_cert=True, renew_at_percent=80)


@pytest.mark.parametrize(("row", "settings", "state"), [
    (_row(10, 355, renewer=None), ON, "manual"),                                  # an Apple profile: needs a new link
    (_row(10, 355), SimpleNamespace(**{**vars(ON), "machine_certs": False}), "manual"),  # renewal turned off
    (_row(10, 355, renewer="gpo"), SimpleNamespace(**{**vars(ON), "machine_certs": False}), "auto"),  # Windows decides
    (_row(300, 65), ON, "auto"),                                                   # v1, due, not yet 14 days left
    (_row(352, 13), ON, "overdue"),                                                # v1 with 13 days left
    (_row(300, 65, checked=NOW - timedelta(hours=20)), ON, "auto"),               # v2, due 8 days ago, checking in
    (_row(310, 55, checked=NOW - timedelta(hours=20)), ON, "overdue"),            # v2, due 18 days ago, not renewed
    (_row(300, 65, checked=NOW - timedelta(days=8)), ON, "silent"),               # v2, due, quiet for 8 days
    (_row(100, 265, checked=NOW - timedelta(days=60)), ON, "auto"),               # v2 quiet, but not due: nothing to say
])
def test_classify(row, settings, state):
    assert renewal.classify(row, settings, NOW) == state


@pytest.mark.parametrize(("first", "last", "checked", "used", "retire"), [
    (None, None, None, False, False),                                   # nothing shows the device has the successor
    (None, None, NOW - timedelta(days=1), False, True),                 # a check-in signed with the successor's key
    (NOW - timedelta(days=20), NOW - timedelta(days=21), None, False, True),  # switched over three weeks ago
    (NOW - timedelta(days=3), NOW - timedelta(days=3, hours=1), None, False, False),  # switched, but the old one isn't quiet a week
    (NOW - timedelta(days=20), NOW - timedelta(days=10), None, True, True),   # used 10 days after the switch, quiet since
    (NOW - timedelta(days=20), NOW - timedelta(hours=2), None, True, False),  # still in use: flagged, not cut off
])
def test_judge_superseded(first, last, checked, used, retire):
    assert renewal.judge_superseded(first, last, checked, NOW) == (used, retire)


def test_successors_walk_the_chain():
    tpl, dev = uuid.uuid4(), uuid.uuid4()
    a, b, c, d = (SimpleNamespace(id=uuid.uuid4(), tenant_id="t", status=st, template_id=tpl, device_id=dev) for st in ("revoked", "superseded", "active", "revoked"))
    # Group Policy's certificate replaced b on that PC (another template), and another PC's user certificate replaced c:
    # neither is a renewal of b with its key, so neither is revoked with it.
    gpo = SimpleNamespace(id=uuid.uuid4(), tenant_id="t", status="active", template_id=uuid.uuid4(), device_id=dev)
    other_pc = SimpleNamespace(id=uuid.uuid4(), tenant_id="t", status="active", template_id=tpl, device_id=uuid.uuid4())
    children = {a.id: [b], b.id: [c, d, gpo], c.id: [other_pc], d.id: []}
    for parent, kids in list(children.items()):
        for k in kids:
            k.renewal_of = parent

    class S:
        def scalars(self, stmt):
            parents = next(v for k, v in stmt.compile().params.items() if k.startswith("renewal_of"))
            return SimpleNamespace(all=lambda: [x for p in parents for x in children[p]])

    assert renewal.successors(S(), a) == [b, c]  # d is revoked already


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


def test_a_conflict_is_its_own_event(monkeypatch):
    cert = SimpleNamespace(id=uuid.uuid4(), tenant_id=uuid.uuid4(), common_name="nina", serial="0A", purpose="user")
    audits, queried = [], []

    class S:
        def rollback(self):
            pass

        def commit(self):
            pass

        def scalar(self, stmt):
            queried.append(str(stmt.compile(compile_kwargs={"literal_binds": True})))
            return 0

    monkeypatch.setattr(ep, "set_platform", lambda s: None)
    monkeypatch.setattr(ep, "client_ip", lambda r: "192.0.2.1")
    monkeypatch.setattr(ep.audit, "record", lambda s, actor, action, **kw: audits.append(action))
    ep._refused(S(), ep.enr.RenewalRefused("in use", cert, "conflict"), None)
    assert audits == ["certificate.renewal_conflict"] and "certificate.renewal_conflict" in queried[0]


def test_a_refused_v2_renewal_keeps_its_check_in(monkeypatch):
    """Refused daily, a v2 renewer is overdue (alive, refused), not silent: its signed check-in survives the rollback."""
    cert = SimpleNamespace(id=uuid.uuid4(), tenant_id=uuid.uuid4(), common_name="nina", serial="0A", purpose="user")
    done = {"updates": [], "commits": 0, "scope": None}

    class S:
        def rollback(self):
            pass

        def commit(self):
            done["commits"] += 1

        def execute(self, stmt):
            done["updates"].append(stmt.compile().params)

        def scalar(self, stmt):
            return 1  # audited today already

    monkeypatch.setattr(ep, "set_tenant", lambda s, t: done.update(scope=t))
    monkeypatch.setattr(ep.audit, "record", lambda *a, **kw: pytest.fail("audited twice in a day"))
    info = ep.enr.parse_client('{"kind": "linux", "version": "2.0"}')
    ep._refused(S(), ep.enr.RenewalRefused("disabled", cert, "account", (info, NOW)), None)
    (params,) = done["updates"]
    assert params["renewal_checked_at"] == NOW and params["renewer"] == "linux" and done["scope"] == cert.tenant_id and done["commits"] == 1


def _check_in_world(monkeypatch, status="active"):
    old = SimpleNamespace(id=uuid.uuid4(), tenant_id=uuid.uuid4(), status=status, purpose="device",
                          not_before=NOW - timedelta(days=100), not_after=NOW + timedelta(days=265))
    monkeypatch.setattr(ep.limiter, "hit", lambda *a: True)
    monkeypatch.setattr(ep, "set_platform", lambda s: None)
    monkeypatch.setattr(ep, "client_ip", lambda r: "192.0.2.1")
    monkeypatch.setattr(ep, "OpenBao", lambda: None)
    monkeypatch.setattr(ep.enr, "renew", lambda *a, **kw: (old, None))
    monkeypatch.setattr(ep.renewal, "settings", lambda s, t: ON)
    monkeypatch.setattr(ep, "trust_block", lambda s, t: {"roots": [{"sha256": "ab" * 32, "pem": "PEM"}], "cross": []})
    body = ep.RenewIn(certificate="Yw" * 60, signed_at=0, signature="cw" * 30, client='{"kind": "linux"}')
    return old, body


def test_a_check_in_answer_says_when_to_renew_and_what_to_trust(monkeypatch):
    old, body = _check_in_world(monkeypatch)
    r = ep.renew(body, None, SimpleNamespace())
    assert r["renewed"] is False and r["superseded"] is False and r["renewal_enabled"] is True
    assert r["renew_from"] == renewal.renew_from(old, 80).isoformat() and r["trust"]["roots"][0]["sha256"] == "ab" * 32


def test_a_superseded_certificate_is_told_to_finish_now(monkeypatch):
    _, body = _check_in_world(monkeypatch, status="superseded")
    r = ep.renew(body, None, SimpleNamespace())
    assert r["superseded"] is True and datetime.fromisoformat(r["renew_from"]) <= datetime.now(UTC)


def test_trust_block_lists_active_roots():
    root = SimpleNamespace(fingerprint_sha256="AB" * 32, certificate_pem="-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----")

    class S:
        def scalars(self, stmt):
            sql = str(stmt.compile(compile_kwargs={"literal_binds": True}))
            assert "'root'" in sql and "'active'" in sql
            return SimpleNamespace(all=lambda: [root])

    assert ep.trust_block(S(), uuid.uuid4()) == {"roots": [{"sha256": "ab" * 32, "pem": root.certificate_pem + "\n"}], "cross": []}


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
