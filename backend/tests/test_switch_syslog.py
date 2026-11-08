"""Switch audit syslog: parsing Cisco messages, the allow-list, redaction, quotas, coalescing, the source map and the
receiver thread (docs/plans/switch-audit.md §0a)."""
from __future__ import annotations

import socket
import time
import uuid
from datetime import UTC, datetime, timedelta

from app.switchaudit import service, syslog
from app.switchaudit.syslog import Coalescer, Switch, parse

NOW = datetime(2026, 11, 7, 12, 0, 5, tzinfo=UTC)
SW = Switch(uuid.uuid4(), uuid.uuid4())

DOT1X_FAIL = (b"<189>1234: Nov  7 22:39:22.522 UTC: %DOT1X-5-FAIL: Switch 1 R0/0: sessmgrd: Authentication failed for client "
              b"(0200.0000.1103) on Interface Gi1/0/5 AuditSessionID 0A0A0A0B0000001200ABCDEF")
ERR_DISABLE = b"<188>55: lab-sw1: *Nov  7 22:39:22: %PM-4-ERR_DISABLE: bpduguard error detected on Gi1/0/10, putting Gi1/0/10 in err-disable state"
RADIUS_DEAD = b"<188>12: %RADIUS-4-RADIUS_DEAD: RADIUS server 172.16.0.45:1812,1813 is not responding."


def test_parse_ios_xe_messages():
    m = parse(DOT1X_FAIL)
    assert (m.facility, m.severity, m.mnemonic, m.tag) == ("DOT1X", 5, "FAIL", "DOT1X-5-FAIL")
    assert m.port == "GigabitEthernet1/0/5" and m.mac == "020000001103" and m.session_id == "0A0A0A0B0000001200ABCDEF"
    assert m.text.startswith("Authentication failed for client")  # IOS-XE's "Switch 1 R0/0: sessmgrd:" removed
    e = parse(ERR_DISABLE)
    assert e.tag == "PM-4-ERR_DISABLE" and e.port == "GigabitEthernet1/0/10" and e.mac == ""
    r = parse(RADIUS_DEAD)
    assert r.tag == "RADIUS-4-RADIUS_DEAD" and r.port == "" and "172.16.0.45" in r.text
    v = parse(b"<189>%AUTHMGR-5-SECURITY_VIOLATION: Security violation on the interface GigabitEthernet1/0/7, new MAC address "
              b"(02:00:00:00:99:05) is seen.AuditSessionID 0A0A0A0B0000001300ABCDEF")
    assert v.port == "GigabitEthernet1/0/7" and v.mac == "020000009905" and v.session_id == "0A0A0A0B0000001300ABCDEF"
    assert parse(b"<13>Nov  7 12:00:00 host sshd[1]: Accepted publickey for root") is None
    assert parse(b"\x00\xff%SYS-5-CONFIG_I: Configured from\x07 console by admin on vty0 (10.1.2.3)").text == \
        "Configured from console by admin on vty0 (10.1.2.3)"  # control characters out, the administrator kept
    assert len(parse(b"%DOT1X-5-FAIL: " + b"x" * 5000).text) == syslog.MAX_TEXT


def test_allow_list():
    for fac, mn in [("SESSION_MGR", "FAIL"), ("AUTHMGR", "SECURITY_VIOLATION"), ("DOT1X", "FAIL"), ("MAB", "FAIL"),
                    ("DOT1X_SWITCH", "ERR_VLAN_NOT_FOUND"), ("PM", "ERR_RECOVER"), ("RADIUS", "ALLDEADSERVER"),
                    ("RADIUS_AUDIT_MESSAGE", "RADIUS_DEAD"), ("SYS", "CONFIG_I")]:
        assert syslog.kept(fac, mn), (fac, mn)
    # Successful authentications (and the VLAN assignment logged with each) are in EasyEAP's own event log.
    for fac, mn in [("SESSION_MGR", "START"), ("DOT1X", "SUCCESS"), ("AUTHMGR", "VLANASSIGN"), ("SYS", "RESTART"),
                    ("SEC_LOGIN", "LOGIN_SUCCESS"), ("LINK", "UPDOWN")]:
        assert not syslog.kept(fac, mn), (fac, mn)


def test_variants_seen_in_the_field():
    assert parse(b"<188>%PM-SP-4-ERR_DISABLE: udld error detected on Gi4/1, putting Gi4/1 in err-disable state").tag == "PM-4-ERR_DISABLE"
    r = parse(b"<190>%RADIUS_AUDIT_MESSAGE-6-RADIUS_DEAD: R0/0: sessmgrd: RADIUS server 10.127.197.164:1812,1813 is not responding.")
    assert r.tag == "RADIUS_AUDIT_MESSAGE-6-RADIUS_DEAD" and r.subject == "10.127.197.164" and r.text.startswith("RADIUS server")
    assert parse(b"%RADIUS-4-RADIUS_ALIVE: RADIUS server 10.1.1.1:1812,1813 has returned.").subject == "10.1.1.1"
    assert parse(b"%RADIUS-3-ALLDEADSERVER: Group ISE: No active radius servers found. Id 57.").subject == "all"
    v = parse(b"%DOT1X_SWITCH-5-ERR_VLAN_NOT_FOUND: Attempt to assign non-existent or shutdown VLAN TEST to 802.1x port GigabitEthernet0/2 AuditSessionID 0A0A")
    assert v.port == "GigabitEthernet0/2"
    assert parse(b"%SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.31.0.24)").subject == "console by admin on vty0 (10.31.0.24)"
    assert parse(ERR_DISABLE).subject == "bpduguard"


def test_redaction():
    assert syslog.redact("Login failed [user: alice] [Source: 10.0.0.1]") == "Login failed [user: <redacted>] [Source: 10.0.0.1]"
    assert syslog.redact("user alice password=hunter2 key: abc, secret s3cr3t") == \
        "user <redacted> password=<redacted> key: <redacted>, secret <redacted>"
    assert "hunter2" not in parse(b"%AUTHMGR-5-FAIL: Authorization failed for client (0200.0000.1103) username=bob password hunter2").text


def test_port_and_mac_notations():
    assert syslog.port_of("on Interface Te2/1/1 now") == "TenGigabitEthernet2/1/1"
    assert syslog.port_of("VLAN 220 assigned to Interface GigabitEthernet1/0/5") == "GigabitEthernet1/0/5"
    assert syslog.port_of("RADIUS server 10.0.0.1:1812 is dead") == ""
    assert syslog.mac_of("client (0011.2233.44aa)") == "0011223344AA" and syslog.mac_of("mac 00-11-22-33-44-55") == "001122334455"


def test_coalescing_per_minute():
    co = Coalescer()
    msg = parse(DOT1X_FAIL)
    for i in range(5):
        assert co.add("192.0.2.10", SW, msg, NOW + timedelta(seconds=i), mono=float(i)) == "kept"
    dirty = co.take_dirty(NOW + timedelta(seconds=5))
    assert len(dirty) == 1 and dirty[0].count == 5 and dirty[0].first_at == NOW and dirty[0].last_at == NOW + timedelta(seconds=4)
    assert co.take_dirty(NOW + timedelta(seconds=6)) == []
    co.add("192.0.2.10", SW, msg, NOW + timedelta(seconds=7), mono=7.0)  # same minute: the same row, updated
    again = co.take_dirty(NOW + timedelta(seconds=8))
    assert again[0].id == dirty[0].id and again[0].count == 6
    co.add("192.0.2.10", SW, msg, NOW + timedelta(minutes=1), mono=60.0)  # the next minute: a new row
    nxt = co.take_dirty(NOW + timedelta(minutes=1, seconds=1))
    assert len(nxt) == 1 and nxt[0].id != dirty[0].id and nxt[0].count == 1
    co.take_dirty(NOW + timedelta(minutes=1, seconds=3))
    assert len(co.entries) == 1  # the first minute's row, written and clean, is forgotten
    st = co.take_stats()[SW]
    assert (st.received, st.kept, st.last_tag) == (7, 7, "DOT1X-5-FAIL")


def fail_on(n: int) -> syslog.Message:
    return parse(f"%DOT1X-5-FAIL: Authentication failed for client (0200.0000.{n:04d}) on Interface Gi1/0/{n % 48 + 1}".encode())


def test_filtered_and_quotas():
    co = Coalescer(max_entries=2, tenant_bytes=10_000)
    assert co.add("192.0.2.10", SW, parse(b"%SESSION_MGR-5-START: Starting 'dot1x'"), NOW, mono=0.0) == "filtered"
    assert co.add("192.0.2.10", SW, None, NOW, mono=0.0) == "filtered"
    # Per source: a burst of 200 new messages, then 100 a second; repeats of a kept one only count.
    co2 = Coalescer()
    results = [co2.add("192.0.2.10", SW, fail_on(i), NOW, mono=0.0) for i in range(250)]
    assert results.count("kept") == 200 and results.count("quota") == 50
    assert co2.add("192.0.2.10", SW, fail_on(0), NOW, mono=0.0) == "kept"  # a repeat, even with the bucket empty
    assert co2.add("192.0.2.10", SW, fail_on(300), NOW, mono=1.0) == "kept"  # refilled
    # The coalescing table overall and per switch, and the tenant's bytes.
    for i in (1, 2, 3):
        res = co.add("192.0.2.10", SW, fail_on(i), NOW, mono=float(i))
    assert res == "quota" and len(co.entries) == 2
    per = Coalescer(per_switch=2)
    other = Switch(uuid.uuid4(), SW.tenant_id)
    assert [per.add("192.0.2.10", SW, fail_on(i), NOW, mono=float(i)) for i in range(3)] == ["kept", "kept", "quota"]
    assert per.add("192.0.2.11", other, fail_on(9), NOW, mono=0.0) == "kept"  # another switch has its own share
    small = Coalescer(tenant_bytes=500)
    assert small.add("192.0.2.10", SW, fail_on(1), NOW, mono=0.0) == "kept"
    assert small.add("192.0.2.10", SW, fail_on(2), NOW, mono=0.0) == "quota"
    assert small.add("192.0.2.10", SW, parse(ERR_DISABLE), NOW, mono=0.0) == "kept"  # err-disable and RADIUS always kept
    assert small.add("192.0.2.10", SW, fail_on(2), NOW + timedelta(days=1), mono=1.0) == "kept"  # a new day
    restarted = Coalescer(tenant_bytes=500)
    restarted.set_usage(NOW.date(), {SW.tenant_id: 400})  # what's already stored today counts after a restart
    assert restarted.add("192.0.2.10", SW, fail_on(1), NOW, mono=0.0) == "quota"


def test_messages_about_different_servers_or_people_stay_apart():
    co = Coalescer()
    for raw in (b"%RADIUS-4-RADIUS_DEAD: RADIUS server 10.0.0.1:1812,1813 is not responding.",
                b"%RADIUS-4-RADIUS_DEAD: RADIUS server 10.0.0.2:1812,1813 is not responding.",
                b"%SYS-5-CONFIG_I: Configured from console by alice on vty0 (10.1.1.1)",
                b"%SYS-5-CONFIG_I: Configured from console by bob on vty1 (10.1.1.2)"):
        co.add("192.0.2.10", SW, parse(raw), NOW, mono=0.0)
    assert len(co.entries) == 4


def test_failed_writes_are_retried_then_dropped_and_a_restore_starts_over():
    co = Coalescer()
    co.add("192.0.2.10", SW, fail_on(1), NOW, mono=0.0)
    e = co.take_dirty(NOW)[0]
    for _ in range(syslog.MAX_WRITE_FAILURES - 1):
        co.failed(e)
        assert co.take_dirty(NOW) == [e]
    co.failed(e)
    assert co.entries == {} and co.per_switch == {}
    co.add("192.0.2.10", SW, fail_on(2), NOW, mono=0.0)
    co.reset()
    assert co.entries == {} and co.buckets == {} and co.used == {} and co.take_stats() == {}


def test_some_messages_hint_at_an_earlier_poll():
    co = Coalescer()
    co.add("192.0.2.10", SW, parse(DOT1X_FAIL), NOW, mono=0.0)
    assert co.take_hints() == {}
    co.add("192.0.2.10", SW, parse(ERR_DISABLE), NOW, mono=0.0)
    assert co.take_hints() == {SW: NOW} and co.take_hints() == {}


def test_source_map_only_verified_and_unshared_addresses():
    a, b, c = (Switch(uuid.uuid4(), uuid.uuid4()) for _ in range(3))
    got = syslog.source_map([(a, {"192.0.2.10", "192.0.2.11", ""}, True), (b, {"192.0.2.11", "2001:db8::0010"}, True),
                             (c, {"192.0.2.12"}, False)])
    assert got == {"192.0.2.10": a, "2001:db8::10": b}  # .11 claimed twice; .12 never answered a poll
    # Another tenant claiming a verified switch's address (without polling it) makes it ambiguous, not theirs.
    assert syslog.source_map([(a, {"192.0.2.10"}, True), (c, {"192.0.2.10"}, False)]) == {}
    assert syslog.normalize_ip("::ffff:192.0.2.10") == "192.0.2.10"


def test_receiver_thread(monkeypatch):
    monkeypatch.setattr(syslog, "FLUSH_SECONDS", 0.2)
    stored: dict = {}  # row id → (tag, count) as last written

    def store(co, now):
        stored.update({e.id: (e.msg.tag, e.count) for e in co.take_dirty(now)})
        co.take_stats()

    r = syslog.Receiver(lambda: {"127.0.0.1": SW}, store, port=0)
    r.start()
    try:
        port = r._sock.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as out:
            for data in (DOT1X_FAIL, DOT1X_FAIL, b"not syslog at all"):
                out.sendto(data, ("127.0.0.1", port))
        deadline = time.monotonic() + 5
        while ("DOT1X-5-FAIL", 2) not in stored.values() and time.monotonic() < deadline:
            time.sleep(0.05)
    finally:
        r.stop()
    assert list(stored.values()) == [("DOT1X-5-FAIL", 2)] and r.received == 3 and not r.unknown


def test_receiver_drops_unknown_sources():
    r = syslog.Receiver(lambda: {}, lambda co, now: None)
    r.sources = {"192.0.2.10": SW}
    assert r.handle(DOT1X_FAIL, "198.51.100.1", NOW) == "unknown"
    assert r.handle(DOT1X_FAIL, "::ffff:192.0.2.10", NOW) == "kept"
    assert r.health()["unknown_top"] == [{"address": "198.51.100.1", "count": 1}] and r.health()["unknown_source"] == 1


def test_config_block_with_syslog():
    block = service.config_block({"version": "v2c", "host": "192.0.2.10"}, "192.0.2.1", ("198.51.100.5", 5514))
    assert "logging discriminator EASYEAP facility includes SESSION_MGR|AUTHMGR|DOT1X|DOT1X_SWITCH|MAB|PM|RADIUS|SYS rate-limit 100" in block
    assert "\nlogging host 198.51.100.5 transport udp port 5514 discriminator EASYEAP\n" in block  # IOS-XE 16.6: discriminator last
    assert "logging host 198.51.100.5 vrf Mgmt-vrf transport udp port 5514 discriminator EASYEAP" in block
    assert "discriminator EASYEAP transport" not in block, "nothing may follow the discriminator name"
    assert "only keeps messages sent from 192.0.2.10" in block
    assert "logging trap" not in block and "service timestamps" not in block
    assert "logging" not in service.config_block({"version": "v2c", "host": "192.0.2.10"}, "192.0.2.1")
    rm = service.removal_block({"version": "v2c"}, syslog=("198.51.100.5", 5514))
    assert rm.startswith("no logging host 198.51.100.5 transport udp port 5514 discriminator EASYEAP\n")  # exactly as added
    assert "no logging discriminator EASYEAP" in rm
    assert "logging" not in service.removal_block({"version": "v2c"})


def row(fac, mn, subject, at=NOW):
    from types import SimpleNamespace
    return SimpleNamespace(id=uuid.uuid4(), first_at=at, last_at=at, count=1, facility=fac, severity=4, mnemonic=mn, port="", mac="",
                           session_id="", subject=subject, text="x")


def test_radius_down_per_server():
    ours, other = "192.0.2.1", "10.0.0.2"
    t1, t2 = NOW - timedelta(minutes=5), NOW
    # Newest first, as the API reads them.
    assert [d["server"] for d in service.radius_down([row("RADIUS", "RADIUS_DEAD", ours)], ours)] == [ours]
    assert service.radius_down([row("RADIUS", "RADIUS_DEAD", ours)], ours)[0]["ours"]
    assert service.radius_down([row("RADIUS", "RADIUS_ALIVE", ours, t2), row("RADIUS", "RADIUS_DEAD", ours, t1)], ours) == []
    # Another server coming back doesn't clear ours, and isn't ours.
    got = service.radius_down([row("RADIUS", "RADIUS_ALIVE", other, t2), row("RADIUS_AUDIT_MESSAGE", "RADIUS_DEAD", ours, t1),
                               row("RADIUS", "RADIUS_DEAD", "10.0.0.3", t1)], ours)
    assert {(d["server"], d["ours"]) for d in got} == {(ours, True), ("10.0.0.3", False)}
    # EasyEAP has heard from the switch since: its server is evidently reachable, even without an ALIVE message.
    assert service.radius_down([row("RADIUS", "RADIUS_DEAD", ours, t1)], ours, heard_since=lambda at: True) == []
    assert service.radius_down([row("RADIUS", "ALLDEADSERVER", "all")], ours)[0]["server"] is None
    assert service.radius_down([row("DOT1X", "FAIL", "")], ours) == []
