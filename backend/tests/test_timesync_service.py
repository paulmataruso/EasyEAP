"""The time service against a stand-in chronyd that behaves as chronyd 4.8 did in docs/plans/ntp.md's tests: reload
reads *.sources, selectopts takes an IP and changes the configured options, sources -N gives configured names."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.routers.system import check_time
from app.timesync import chrony, config, service, sntp

TRACKING = "C0000201,192.0.2.1,2,1794264832.0,-0.000250000,0.0,0.0001,-27.75,0.0,0.009,0.06,0.001,520.0,Normal\n"


class FakeChronyd:
    """Host config: two Ubuntu-style pools (prefer). sourcedir: whatever easyeap.sources says. `answers`: the addresses
    that reply; `resolved`: what names resolve to (unknown names stay unresolved, as ID# rows)."""

    def __init__(self, sources_dir: Path):
        self.dir = sources_dir
        self.host = [("203.0.113.1", "1.ntp.ubuntu.com", "prefer"), ("203.0.113.2", "2.ntp.ubuntu.com", "prefer")]
        self.resolved = {"ntp.example.net": ["198.51.100.10", "198.51.100.11"], "time.example.org": ["198.51.100.20"]}
        self.answers = {"203.0.113.1", "203.0.113.2", "198.51.100.10", "198.51.100.11", "198.51.100.20", "192.0.2.50"}
        self.noselect: set[str] = set()
        self.extra: list[tuple[str, str, str]] = []
        self.calls: list[tuple[str, ...]] = []
        self.reads_sourcedir = True
        self.reload()

    def reload(self):
        self.extra = []
        f = self.dir / "easyeap.sources"
        if not self.reads_sourcedir or not f.exists():
            return
        for line in f.read_text().splitlines():
            if line.startswith("#") or not line.strip():
                continue
            _kind, name, *opts = line.split()
            addrs = [name] if chrony.is_address(name) else self.resolved.get(name, [])
            if not addrs:
                self.extra += [(f"ID#{i:010d}", name, " ".join(opts)) for i in range(1, 3)]
            self.extra += [(a, name, " ".join(opts)) for a in addrs]

    def rows(self):
        return [*self.host, *self.extra]

    def __call__(self, *args: str, named: bool = False, timeout: float = 10) -> str:
        self.calls.append(args)
        cmd = args[0]
        if cmd == "tracking":
            return TRACKING
        if cmd == "reload":
            self.reload()
            return "200 OK\n"
        if cmd == "sources":
            out = []
            for addr, name, _opts in self.rows():
                reach = "377" if addr in self.answers else "0"
                out.append(f"^,{'+' if reach != '0' else '?'},{name if named else addr},2,6,{reach},12,0.001,0.001,0.02")
            return "\n".join(out) + "\n"
        if cmd == "selectdata":
            out = []
            for addr, _name, opts in self.rows():
                n = "N" if addr in self.noselect else "-"
                p = "P" if "prefer" in opts else "-"
                out.append(f"{n if n == 'N' else '+'},{addr},N,{n},{p},-,-,-,{n},{p},-,-,-,10,1.0,-0.01,0.01,Normal")
            return "\n".join(out) + "\n"
        if cmd == "authdata":
            return "".join(f"{a},{'NTS' if 'nts' in o else '-'},1,30,128,10,0,0,8,64\n" for a, _n, o in self.rows())
        if cmd == "reselect":
            return "200 OK\n"
        if cmd == "selectopts":
            addr, change = args[1], args[2]
            if not chrony.is_address(addr):
                raise chrony.ChronyError("Invalid syntax for selectopts command")
            if addr not in {a for a, _n, _o in self.rows()}:
                raise chrony.ChronyError("503 No such source")
            (self.noselect.add if change == "+noselect" else self.noselect.discard)(addr)
            return "200 OK\n"
        raise AssertionError(f"unexpected chronyc {args}")


def settings(*servers: dict, only_these: bool = False, revision: int = 1) -> config.TimeSettings:
    return config.TimeSettings(servers=[config.Server(**s) for s in servers], only_these=only_these, revision=revision)


@pytest.fixture
def host(tmp_path):
    d = tmp_path / "sources.d"
    d.mkdir()
    return FakeChronyd(d)


def manager(host: FakeChronyd, switched=None) -> service.Manager:
    return service.Manager(run=host, sources_dir=host.dir, switched=switched)


def test_servers_go_to_easyeap_sources_and_chronyd_reloads_once(host):
    m = manager(host)
    s = settings({"address": "ntp.example.net", "kind": "pool"}, {"address": "192.0.2.50", "nts": True, "prefer": True})
    assert m.apply(s) is True
    text = (host.dir / "easyeap.sources").read_text()
    assert text.splitlines()[2:] == ["pool ntp.example.net iburst", "server 192.0.2.50 iburst nts prefer"]
    assert text.endswith("\n") and text.startswith("# ")
    assert not list(host.dir.glob(".*"))   # the temporary file was renamed into place
    assert m.apply(s) is False             # unchanged: no second reload
    assert host.calls.count(("reload", "sources")) == 1
    assert m.applied_revision == 1 and m.apply_error is None
    # No servers: the file goes, and chronyd drops them.
    assert m.apply(settings(revision=2)) is True
    assert not (host.dir / "easyeap.sources").exists() and host.extra == []


def test_status_marks_easyeaps_sources_by_their_configured_name(host):
    m = manager(host)
    s = settings({"address": "ntp.example.net", "kind": "pool"}, {"address": "unresolvable.example", "kind": "pool"})
    m.apply(s)
    st = m.observe(s)
    by = {(x["address"], x["name"]): x for x in st["sources"]}
    assert by[("198.51.100.10", "ntp.example.net")]["ours"] is True
    assert by[("203.0.113.1", "1.ntp.ubuntu.com")]["ours"] is False
    # A name chronyd hasn't resolved is one row, not one per spare slot.
    pending = [x for x in st["sources"] if not x["resolved"]]
    assert [(x["name"], x["ours"]) for x in pending] == [("unresolvable.example", True)]
    assert st["synchronised"] is True and st["offset"] == pytest.approx(0.00025)
    assert m.apply_error is None


def test_chronyd_that_ignores_sources_d_is_reported(host):
    host.reads_sourcedir = False
    m = manager(host)
    s = settings({"address": "time.example.org"})
    m.apply(s)
    m.observe(s)
    assert "sourcedir" in (m.apply_error or "")


def test_only_these_switches_the_host_servers_off_and_back_on(host):
    m = manager(host)
    s = settings({"address": "time.example.org"}, only_these=True)
    m.apply(s)
    assert m.reconcile(s, m.observe(s)["sources"]) is True
    assert host.noselect == {"203.0.113.1", "203.0.113.2"} and set(m.switched) == host.noselect
    assert m.switched["203.0.113.1"] == "1.ntp.ubuntu.com"
    assert m.reconcile(s, m.observe(s)["sources"]) is False   # nothing more to do
    # chronyd restarted: it forgot, so the service applies it again.
    host.noselect.clear()
    assert m.reconcile(s, m.observe(s)["sources"]) is True and host.noselect == {"203.0.113.1", "203.0.113.2"}
    # Turned off in the console: exactly those come back.
    off = settings({"address": "time.example.org"}, only_these=False, revision=2)
    assert m.reconcile(off, m.observe(off)["sources"]) is True
    assert host.noselect == set() and m.switched == {}


def test_only_these_never_leaves_the_clock_without_a_server(host):
    m = manager(host)
    s = settings({"address": "time.example.org"}, only_these=True)
    m.apply(s)
    m.reconcile(s, m.observe(s)["sources"])
    assert host.noselect
    host.answers.discard("198.51.100.20")   # EasyEAP's only server stops answering
    assert m.reconcile(s, m.observe(s)["sources"]) is True
    assert host.noselect == set()           # the host's servers keep the clock meanwhile
    host.answers.add("198.51.100.20")
    m.reconcile(s, m.observe(s)["sources"])
    assert host.noselect == {"203.0.113.1", "203.0.113.2"}


def test_servers_that_answer_but_never_become_usable_give_the_clock_back(host):
    """chrony's default authselectmode: a listed NTS server nobody can reach holds back the plain ones."""
    clock = [0.0]
    m = service.Manager(run=host, sources_dir=host.dir, now=lambda: clock[0])
    s = settings({"address": "time.example.org"}, only_these=True)
    m.apply(s)

    def stuck(sources):
        for x in sources:
            if x["ours"]:
                x["select"] = "waits_for_others"
        return sources
    m.reconcile(s, stuck(m.observe(s)["sources"]))
    assert host.noselect == {"203.0.113.1", "203.0.113.2"}
    clock[0] = 10                      # the grace period starts once the host's servers are off
    m.reconcile(s, stuck(m.observe(s)["sources"]))
    clock[0] = 10 + service.GRACE - 1
    m.reconcile(s, stuck(m.observe(s)["sources"]))
    assert host.noselect and m.select_error is None
    clock[0] = 10 + service.GRACE
    assert m.reconcile(s, stuck(m.observe(s)["sources"])) is True
    assert host.noselect == set() and "tries its servers alone again" in (m.select_error or "")
    assert config.assess({**service.empty_status(), "mode": "chrony", "synchronised": True, "select_error": m.select_error}, s)[0] == "warn"
    # An hour later EasyEAP's are tried alone again.
    clock[0] = 10 + service.GRACE + service.RETRY
    m.reconcile(s, m.observe(s)["sources"])
    assert host.noselect == {"203.0.113.1", "203.0.113.2"} and m.select_error is None


def test_a_source_switched_off_by_someone_else_stays_off(host):
    host.noselect.add("203.0.113.2")        # noselect in the host's own configuration
    m = manager(host)
    s = settings({"address": "time.example.org"}, only_these=True)
    m.apply(s)
    m.reconcile(s, m.observe(s)["sources"])
    assert set(m.switched) == {"203.0.113.1"}
    off = settings({"address": "time.example.org"}, revision=2)
    m.reconcile(off, m.observe(off)["sources"])
    assert host.noselect == {"203.0.113.2"}


def test_an_old_chronyd_without_selectopts_is_explained(host):
    def old(*args, **kw):
        if args[0] == "selectopts":
            raise chrony.ChronyError("Unrecognised command")
        return host(*args, **kw)
    m = service.Manager(run=old, sources_dir=host.dir)
    s = settings({"address": "time.example.org"}, only_these=True)
    m.apply(s)
    assert m.reconcile(s, m.observe(s)["sources"]) is False
    assert "4.4" in (m.select_error or "")


def test_server_validation_keeps_the_sources_file_safe():
    for bad in ("ntp.example.net iburst", "ntp.example.net\nserver evil", "", "::", "127.0.0.1", "http://ntp.example.net"):
        with pytest.raises(ValidationError):
            config.Server(address=bad)
    with pytest.raises(ValidationError, match="pool is a name"):
        config.Server(address="192.0.2.1", kind="pool")
    with pytest.raises(ValidationError, match="listed twice"):
        config.TimeSettings(servers=[config.Server(address="A.example"), config.Server(address="a.example")])
    with pytest.raises(ValidationError, match="at least one server"):
        config.TimeSettings(only_these=True)
    assert config.Server(address=" [2001:db8::1] ").directive() == "server 2001:db8::1 iburst"


def test_without_chronyd_the_clock_is_measured(monkeypatch):
    monkeypatch.setattr(chrony, "available", lambda: False)
    monkeypatch.setattr(service.kernel, "read", lambda: service.kernel.KernelClock(0.2, 0.001))
    asked = []

    def query(host):
        asked.append(host)
        if host == "down.example":
            raise sntp.SntpError("192.0.2.9 didn't answer within 2 seconds")
        return sntp.Sample("192.0.2.8", -0.004, 0.02, 2, 0, "")   # this clock 4 ms ahead
    monkeypatch.setattr(service.sntp, "query", query)
    clock = [0.0]
    svc = service.Service(manager=service.Manager(run=lambda *a, **k: "", sources_dir=Path("/nonexistent")), now=lambda: clock[0])
    s = settings({"address": "up.example"}, {"address": "down.example"})
    st, due = svc.tick(s)
    assert due and st["mode"] == "sntp" and st["synchronised"] is True and st["kernel_synchronised"] is True
    assert st["offset"] == pytest.approx(0.004)
    assert [c["error"] is None for c in st["checks"]] == [True, False]
    assert config.assess(st, s)[0] == "warn"   # servers set, but nothing to apply them to
    # Not again within five minutes, unless the servers change.
    clock[0] = 60
    svc.tick(s)
    assert asked == ["up.example", "down.example"]
    svc.tick(settings({"address": "up.example"}, revision=2))
    assert asked[-1] == "up.example" and len(asked) == 3
    # Never had chronyd: restarts hourly to find one installed later.
    assert svc.should_exit() is None
    clock[0] = service.RECHECK_EXIT
    assert svc.should_exit() == 0


def test_chronyd_not_answering_once_is_not_no_chrony(monkeypatch, host):
    monkeypatch.setattr(chrony, "available", lambda: True)
    monkeypatch.setattr(service.kernel, "read", lambda: service.kernel.KernelClock(0.2, 0.001))

    def busy(*a, **k):
        raise chrony.ChronyError("chronyd didn't answer tracking within 10 seconds")
    svc = service.Service(manager=service.Manager(run=busy, sources_dir=host.dir), now=lambda: 0.0)
    asked = []
    monkeypatch.setattr(service, "measure", lambda *a, **k: asked.append(1) or [])
    st, _ = svc.tick(settings({"address": "time.example.org"}))
    assert st["mode"] == "chrony" and "didn't answer" in st["problem"] and not asked
    assert config.assess(st, settings())[0] == "warn"
    st["kernel_synchronised"] = False
    assert config.assess(st, settings())[0] == "crit"


def test_losing_chronyds_socket_restarts_the_service(monkeypatch, host):
    up = [True]
    monkeypatch.setattr(chrony, "available", lambda: up[0])
    monkeypatch.setattr(service.kernel, "read", lambda: None)
    clock = [0.0]
    svc = service.Service(manager=manager(host), now=lambda: clock[0])
    s = settings({"address": "time.example.org"})
    st, _ = svc.tick(s)
    assert st["mode"] == "chrony"
    up[0] = False
    clock[0] = 10
    svc.tick(s)
    clock[0] = 10 + service.LOST_SOCKET_EXIT
    assert svc.should_exit() == 1


def test_assessment_thresholds():
    s = settings()
    base = {**service.empty_status(), "mode": "chrony", "synchronised": True}
    assert config.assess({**base, "offset": 0.002}, s)[0] == "valid"
    assert config.assess({**base, "offset": -0.25}, s) == ("warn", "the clock is 250 ms slow")
    assert config.assess({**base, "offset": 1.5}, s) == ("crit", "the clock is 1.50 s fast")
    assert config.assess({**base, "synchronised": False}, s)[0] == "crit"
    assert config.assess({**base, "apply_error": "x"}, s)[0] == "warn"


class _Session:
    def __init__(self, values: dict):
        self.values = values

    def get(self, _model, key):
        return SimpleNamespace(value=self.values[key]) if key in self.values else None


def test_health_check():
    now = datetime.now(UTC)
    out = []

    def check(service_, ok, tone, label, detail, **kw):
        out.append((service_, ok, tone, label, detail))
    check_time(_Session({}), check, now)
    assert out[-1][:4] == ("time", False, "warn", "Not reporting")
    good = {**service.empty_status(), "mode": "chrony", "synchronised": True, "offset": 0.0012, "reference": "192.0.2.1",
            "stratum": 2, "at": now.isoformat()}
    check_time(_Session({"time_status": good}), check, now)
    assert out[-1][:4] == ("time", True, "valid", "Synchronised") and "192.0.2.1 (stratum 2), 1.2 ms fast" in out[-1][4]
    check_time(_Session({"time_status": {**good, "synchronised": False}}), check, now)
    assert out[-1][2:4] == ("crit", "Not synchronised")
    stale = {**good, "at": (now - timedelta(minutes=10)).isoformat()}
    check_time(_Session({"time_status": stale}), check, now)
    assert out[-1][3] == "Not reporting"


# ── Critic findings ──────────────────────────────────────────────────────────


def test_source_offsets_keep_chronycs_sign(host):
    """chronyc sources: positive when this clock is ahead of the source. Captured on chrony 4.8 next to EasyEAP's own
    SNTP query of the same server: chronyc -0.753 ms, SNTP server-minus-client +0.75 ms (this clock behind)."""
    rows = chrony.parse_sources("^,+,198.51.100.112,2,10,377,80,-0.000753000,-0.000753000,0.035148341\n")
    assert rows[0]["offset"] == pytest.approx(-0.000753)
    m = manager(host)
    s = settings()
    st = m.observe(s)
    assert all(x["offset"] == pytest.approx(0.001) for x in st["sources"])   # the stand-in prints +0.001: passed through


def test_a_failed_reload_is_tried_again(host):
    m = manager(host)
    s = settings({"address": "time.example.org"})
    real = host.__call__
    fail = [True]

    def flaky(*args, **kw):
        if args[0] == "reload" and fail[0]:
            raise chrony.ChronyError("chronyd didn't answer reload sources within 10 seconds")
        return real(*args, **kw)
    m.run = flaky
    with pytest.raises(chrony.ChronyError):
        m.apply(s)
    assert (host.dir / "easyeap.sources").exists() and host.extra == []   # written, not yet loaded
    fail[0] = False
    assert m.apply(s) is True and [a for a, _n, _o in host.extra] == ["198.51.100.20"]


def test_a_new_run_reloads_once_even_if_the_file_is_unchanged(host):
    s = settings({"address": "time.example.org"})
    manager(host).apply(s)
    calls = len(host.calls)
    m2 = manager(host)
    assert m2.apply(s) is False   # nothing new to log
    assert host.calls[calls:] == [("reload", "sources"), ("reselect",)]
    assert m2.apply(s) is False and len(host.calls) == calls + 2


def test_new_settings_end_a_fallback_at_once(host):
    clock = [0.0]
    m = service.Manager(run=host, sources_dir=host.dir, now=lambda: clock[0])
    s = settings({"address": "time.example.org"}, only_these=True)
    m.apply(s)
    m.reconcile(s, m.observe(s)["sources"])
    m.fallback_until, m.fallback_revision = 10_000.0, s.revision   # falling back
    m.reconcile(s, m.observe(s)["sources"])
    assert host.noselect == set()
    fixed = settings({"address": "time.example.org"}, only_these=True, revision=2)
    m.reconcile(fixed, m.observe(fixed)["sources"])
    assert host.noselect == {"203.0.113.1", "203.0.113.2"} and m.select_error is None


def test_a_replaced_pool_address_keeps_noselect_and_is_switched_back_on(host):
    m = manager(host)
    s = settings({"address": "time.example.org"}, only_these=True)
    m.apply(s)
    m.reconcile(s, m.observe(s)["sources"])
    # The pool replaces 203.0.113.2; chronyd keeps the record's options, so the new address arrives switched off.
    host.host[1] = ("203.0.113.9", "2.ntp.ubuntu.com", "prefer")
    host.noselect = {"203.0.113.1", "203.0.113.9"}
    m.reconcile(s, m.observe(s)["sources"])
    assert set(m.switched) == {"203.0.113.1", "203.0.113.9"}
    off = settings({"address": "time.example.org"}, revision=2)
    m.reconcile(off, m.observe(off)["sources"])
    assert host.noselect == set() and m.switched == {}


def test_a_restarted_service_switches_back_on_what_the_last_run_switched_off(host):
    host.noselect = {"203.0.113.1"}
    svc = service.Service(manager=manager(host), now=lambda: 0.0)
    svc.restore({"switched_off": [{"address": "203.0.113.1", "name": "1.ntp.ubuntu.com"}, "junk"]})
    m = svc.m
    off = settings({"address": "time.example.org"})
    m.apply(off)
    m.reconcile(off, m.observe(off)["sources"])
    assert host.noselect == set()


def test_stopping_gives_the_clock_back_to_the_host(monkeypatch, host):
    monkeypatch.setattr(chrony, "available", lambda: True)
    svc = service.Service(manager=manager(host), now=lambda: 0.0)
    s = settings({"address": "time.example.org"}, only_these=True)
    svc.m.apply(s)
    svc.m.reconcile(s, svc.m.observe(s)["sources"])
    assert host.noselect
    assert svc.stop() == {"switched_off": []}
    assert host.noselect == set()


def test_a_mismatched_listing_decides_nothing(host):
    m = manager(host)
    s = settings({"address": "ntp.example.net", "kind": "pool"}, only_these=True)
    m.apply(s)
    real = host.__call__

    def racing(*args, named=False, **kw):
        out = real(*args, named=named, **kw)
        return out + "^,?,192.0.2.99,0,6,0,4294967295,0,0,0\n" if args[0] == "sources" and named else out
    m.run = racing
    st = m.observe(s)
    assert st["names_ok"] is False and m.apply_error is None
    assert m.reconcile(s, st["sources"], st["names_ok"]) is False and host.noselect == set()


@pytest.mark.parametrize("bad", ["fe80::1%x offset 3600 trust", "fe80::1%eth0", "fe80::1%x\nserver 192.0.2.66 prefer trust",
                                 "ntp.example.net\n]", "[ntp.example.net", "ntp.example.net trust",
                                 "ntp\texample.net", "fe80::1"])
def test_addresses_that_would_change_the_chrony_line_are_refused(bad):
    with pytest.raises(ValidationError):
        config.Server(address=bad)


def test_surrounding_whitespace_is_trimmed_not_kept():
    assert config.Server(address="  ntp.example.net\n").address == "ntp.example.net"
    assert config.Server(address="[2001:db8::7]").address == "2001:db8::7"


def test_an_invalid_saved_setting_doesnt_read_as_no_servers():
    sess = _Session({"time": {"servers": [{"address": "bad address"}]}})
    with pytest.raises(ValidationError):
        config.load(sess)
    assert config.load_for_display(sess).servers == []


# ── The API ──────────────────────────────────────────────────────────────────


class _ApiSession(_Session):
    def __init__(self, values):
        super().__init__(values)
        self.info = {}

    def in_transaction(self):
        return False

    def add(self, row):
        self.values[row.key] = row.value

    def get(self, _model, key):
        return SimpleNamespace(key=key, value=self.values[key]) if key in self.values else None


@pytest.fixture
def api(monkeypatch):
    from fastapi.testclient import TestClient

    from app import models as m
    from app.deps import Principal, db, principal
    from app.main import app
    from app.routers import timesync as r
    from app.security.ratelimit import limiter

    limiter._hits.clear()
    state = SimpleNamespace(role="platform_owner", audits=[], session=_ApiSession({}))
    monkeypatch.setattr(m, "PlatformSetting", lambda key, value: SimpleNamespace(key=key, value=value))
    monkeypatch.setattr(r.audit, "record", lambda _s, actor, action, **kw: state.audits.append((action, kw)))
    monkeypatch.setattr(r.sntp, "query", lambda addr, timeout=2.0: sntp.Sample("192.0.2.8", 0.012, 0.03, 2, 0, ""))

    def who():
        admin = SimpleNamespace(id="a1", email="owner@example.com", platform_role=state.role, grants=[])
        return Principal(admin=admin, session=None, ip="192.0.2.200")
    app.dependency_overrides[db] = lambda: state.session
    app.dependency_overrides[principal] = who
    state.client = TestClient(app)
    yield state
    app.dependency_overrides.pop(db, None)
    app.dependency_overrides.pop(principal, None)


def test_api_saves_audits_and_reads_back(api):
    body = {"servers": [{"address": "Time.Example.org", "kind": "server", "iburst": True, "nts": True, "prefer": False}], "only_these": True}
    r = api.client.put("/api/system/time", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["settings"]["servers"][0]["address"] == "time.example.org" and r.json()["settings"]["revision"] == 1
    assert api.audits == [("system.time_updated", {"target_type": "time", "target_label": "NTP servers",
                                                    "detail": {"servers": ["server time.example.org iburst nts"], "only_these": True, "revision": 1}})]
    g = api.client.get("/api/system/time").json()
    assert g["stale"] is True and g["assessment"] is None and g["settings"]["only_these"] is True


@pytest.mark.parametrize(("body", "msg"), [
    ({"servers": [{"address": "a.example"}, {"address": "A.example"}]}, "listed twice"),
    ({"servers": [], "only_these": True}, "at least one server"),
    ({"servers": [{"address": "fe80::1%x trust"}]}, "host name or IP address"),
])
def test_api_explains_a_bad_list(api, body, msg):
    r = api.client.put("/api/system/time", json=body)
    assert r.status_code == 422 and msg in r.text and "errors.pydantic.dev" not in r.text
    assert api.audits == []


def test_api_test_reports_this_clocks_offset_and_is_rate_limited(api):
    r = api.client.post("/api/system/time/test", json={"address": "time.example.org"})
    assert r.status_code == 200 and r.json()["offset"] == pytest.approx(-0.012)   # the server is 12 ms ahead: this clock behind
    bad = api.client.post("/api/system/time/test", json={"address": "x y"})
    assert bad.status_code == 422 and "host name or IP address" in bad.json()["detail"]
    codes = [api.client.post("/api/system/time/test", json={"address": "time.example.org"}).status_code for _ in range(25)]
    assert 429 in codes


def test_api_auditors_read_but_dont_change(api):
    api.role = "platform_auditor"
    assert api.client.get("/api/system/time").status_code == 200
    assert api.client.put("/api/system/time", json={"servers": []}).status_code == 403
    assert api.client.post("/api/system/time/test", json={"address": "time.example.org"}).status_code == 403


def test_chronyd_chooses_again_at_once_after_a_change(host):
    """Without reselect, changed options apply only at the next measurement (up to a poll interval, 17 minutes on a
    settled host): the console would show the old reference until then."""
    m = manager(host)
    s = settings({"address": "time.example.org"}, only_these=True)
    m.apply(s)
    assert host.calls[-1] == ("reselect",)
    n = len(host.calls)
    m.reconcile(s, m.observe(s)["sources"])
    assert host.calls[-1] == ("reselect",) and host.calls.count(("reselect",)) == 2
    n = len(host.calls)
    m.reconcile(s, m.observe(s)["sources"])   # nothing to change: no reselect
    assert ("reselect",) not in host.calls[n:]
    m.release()
    assert host.calls[-1] == ("reselect",) and host.noselect == set()
