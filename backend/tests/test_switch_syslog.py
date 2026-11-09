"""Device syslog: parsing (Cisco IOS/IOS-XE/NX-OS, Catalyst 9800, AireOS, UniFi hostapd and CEF), redaction, quotas,
coalescing, attribution and the receiver threads (docs/plans/syslog-full.md)."""
from __future__ import annotations

import socket
import time
import uuid
from datetime import UTC, datetime, timedelta

from app.switchaudit import service, syslog
from app.switchaudit.syslog import Claims, Coalescer, Device, parse

NOW = datetime(2026, 11, 7, 12, 0, 5, tzinfo=UTC)
SW = Device(uuid.uuid4(), uuid.uuid4())

DOT1X_FAIL = (b"<189>1234: Nov  7 22:39:22.522 UTC: %DOT1X-5-FAIL: Switch 1 R0/0: sessmgrd: Authentication failed for client "
              b"(0200.0000.1103) on Interface Gi1/0/5 AuditSessionID 0A0A0A0B0000001200ABCDEF")
ERR_DISABLE = b"<188>55: lab-sw1: *Nov  7 22:39:22: %PM-4-ERR_DISABLE: bpduguard error detected on Gi1/0/10, putting Gi1/0/10 in err-disable state"
RADIUS_DEAD = b"<188>12: %RADIUS-4-RADIUS_DEAD: RADIUS server 192.0.2.45:1812,1813 is not responding."
LINK_UP = b"<187>%LINK-3-UPDOWN: Interface GigabitEthernet1/0/5, changed state to up"
LINK_DOWN = b"<187>%LINK-3-UPDOWN: Interface GigabitEthernet1/0/5, changed state to down"


def test_parse_ios_xe_messages():
    m = parse(DOT1X_FAIL)
    assert (m.facility, m.severity, m.mnemonic, m.tag) == ("DOT1X", 5, "FAIL", "DOT1X-5-FAIL")
    assert m.port == "GigabitEthernet1/0/5" and m.mac == "020000001103" and m.session_id == "0A0A0A0B0000001200ABCDEF"
    assert m.text.startswith("Authentication failed for client")  # IOS-XE's "Switch 1 R0/0: sessmgrd:" removed
    e = parse(ERR_DISABLE)
    assert e.tag == "PM-4-ERR_DISABLE" and e.port == "GigabitEthernet1/0/10" and e.mac == ""
    r = parse(RADIUS_DEAD)
    assert r.tag == "RADIUS-4-RADIUS_DEAD" and r.port == "" and "192.0.2.45" in r.text
    v = parse(b"<189>%AUTHMGR-5-SECURITY_VIOLATION: Security violation on the interface GigabitEthernet1/0/7, new MAC address "
              b"(02:00:00:00:99:05) is seen.AuditSessionID 0A0A0A0B0000001300ABCDEF")
    assert v.port == "GigabitEthernet1/0/7" and v.mac == "020000009905" and v.session_id == "0A0A0A0B0000001300ABCDEF"
    assert parse(b"\x00\xff%SYS-5-CONFIG_I: Configured from\x07 console by admin on vty0 (10.1.2.3)").text == \
        "Configured from console by admin on vty0 (10.1.2.3)"  # control characters out, the administrator kept
    assert len(parse(b"%DOT1X-5-FAIL: " + b"x" * 5000).text) == syslog.MAX_TEXT
    assert parse(b"   ") is None and parse(b"<13>") is None


def test_everything_else_is_kept_as_it_came():
    # Not a Cisco tag: RFC 3164, the program as the facility and the host as the subject.
    m = parse(b"<13>Nov  7 12:00:00 host sshd[1]: Accepted publickey for root")
    assert (m.facility, m.severity, m.mnemonic, m.subject, m.text, m.tag) == ("sshd", 5, "", "host", "Accepted publickey for root", "sshd")
    assert parse(b"something without a header").text == "something without a header"
    up = parse(LINK_UP)
    assert up.tag == "LINK-3-UPDOWN" and up.port == "GigabitEthernet1/0/5" and not syslog.notable(up)
    assert syslog.notable(parse(DOT1X_FAIL)) and syslog.notable(parse(ERR_DISABLE))


def test_the_session_story_is_notable():
    for raw in (b"%SESSION_MGR-5-START: R0/0: sessmgrd: Starting 'dot1x' for client (0200.0000.1103) on Interface Gi1/0/5 AuditSessionID 0A",
                b"%AUTHMGR-5-START: Starting 'mab' for client (28d2.4496.5376) on Interface Gi3/0/48 AuditSessionID 0A6A258E0000003300C586C2",
                b"%MAB-5-SUCCESS: Authentication successful for client (28d2.4496.5376) on Interface Gi3/0/48 AuditSessionID 0A6A",
                b"%SESSION_MGR-5-VLANASSIGN: VLAN 20 assigned to Interface Gi1/0/5 AuditSessionID 0A0A0A0B0000001200ABCDEF",
                b"%EPM-6-POLICY_REQ: IP 10.1.1.20| MAC 0200.0000.1103| AuditSessionID 0A0A| EVENT IP-ASSIGNMENT"):
        assert syslog.notable(parse(raw)), raw
    assert not syslog.notable(parse(b"%ILPOWER-5-POWER_GRANTED: Interface Gi1/0/5: Power granted"))


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
    # A 2960-X with a discriminator prefixes "[syslog@9 …]:" (Cisco Community report).
    assert parse(b'<189>[syslog@9 s_sn="375" s_tc="4979"]: %DOT1X-5-FAIL: Authentication failed for client (0200.0000.1103) on '
                 b'Interface Gi1/0/5').tag == "DOT1X-5-FAIL"
    # Cisco Business: a letter for the severity.
    assert parse(b"<190>%LINK-W-Down:  gi1/0/3").severity == 4


def test_catalyst_9800_messages():
    m = parse(b"<189>%DOT1X-5-FAIL: R0/0: wncd: Authentication failed for client (ec2e.9835.cc35) with reason (Cred Fail) on Interface "
              b"capwap_9000000d AuditSessionID 320A16AC0000007EFC256556 Username: marco", "cisco-9800")
    assert m.tag == "DOT1X-5-FAIL" and m.mac == "EC2E9835CC35" and m.port == "" and m.session_id == "320A16AC0000007EFC256556"
    assert "marco" not in m.text and m.text.startswith("Authentication failed")
    x = parse(b"%CLIENT_EXCLUSION_SERVER-5-ADD_TO_EXCLUSIONLIST_REASON_DYNAMIC: R0/0: wncmgrd: Client MAC: ec2e.9835.cc35 was added to "
              b"exclusion list associated with AP Name:AP_REUNIONES, BSSID:MAC: 00d7.8f2f.6c24, reason:802.1X authentication credential failure")
    assert x.mac == "EC2E9835CC35" and x.subject == "AP_REUNIONES" and syslog.notable(x)
    d = parse(b"%RADIUS_AUDIT_MESSAGE-6-RADIUS_DEAD: Chassis 1 R0/0: wncd: RADIUS server 10.9.9.9:1812,1813 is not responding.")
    assert d.subject == "10.9.9.9" and d.text.startswith("RADIUS server")


def test_aireos_messages():
    a = parse(b"<131>WLC001: *Dot1x_NW_MsgTask_2: Feb 08 14:38:49.791: #APF-3-AUTHENTICATION_TRAP: apf_80211.c:15520 Client "
              b"Authenticated: MACAddress:18:65:90:48:e0:3a Base Radio MAC:0c:68:03:2c:fc:d0 Slot:1 User Name:MYUSERNAME "
              b"Ip Address:192.168.237.101 SSID:MYSSID", "cisco-aireos")
    assert a.tag == "APF-3-AUTHENTICATION_TRAP" and a.mac == "18659048E03A" and a.text.startswith("Client Authenticated")
    assert "MYUSERNAME" not in a.text and "SSID:MYSSID" in a.text and syslog.notable(a)
    f = parse(b"*radiusTransportThread: Jun 06 17:20:28.517: %AAA-4-RADIUS_RESPONSE_FAILED: [PA]radius_db.c:658 RADIUS server "
              b"10.245.64.196:1812 failed to respond to request(ID 208) for STA 00:11:22:33:44:55 / user 'bob'", "cisco-aireos")
    assert f.text.startswith("RADIUS server 10.245.64.196") and f.subject == "10.245.64.196" and f.mac == "001122334455"
    t = parse(b"<134>WLC001: *SISF BT Process: Aug 20 11:25:50.157: %SISF-6-ENTRY_DELETED: Entry deleted", "cisco-aireos")
    assert t.tag == "SISF-6-ENTRY_DELETED"   # a task name with spaces before the tag


def test_unifi_messages():
    h = parse(b"<30>Jun 21 22:42:22 RoomA 023c8af144b7,UAP-AC-Lite-6.7.5+14823: hostapd[32723]: wifi0ap1: STA 02:5f:3a:9c:11:e4 "
              b"IEEE 802.11: associated", "unifi")
    assert (h.facility, h.severity, h.subject, h.mac) == ("hostapd", 6, "RoomA", "025F3A9C11E4")
    assert h.text == "wifi0ap1: STA 02:5f:3a:9c:11:e4 IEEE 802.11: associated" and syslog.notable(h)
    c = parse(b"<134>Dec  3 15:59:50 UDM CEF:0|Ubiquiti|UniFi Network|9.3.33|401|WiFi Client Disconnected|2|UNIFIcategory=Monitoring "
              b"UNIFIhost=Office UDM Pro UNIFIlastConnectedToDeviceName=Lobby AP UNIFIclientMac=0a:be:db:c8:0d:81 UNIFIwifiName=Employee "
              b"WiFi suser=John Smith msg=Apple Watch 0d:87 disconnected from Employee WiFi.", "unifi")
    assert (c.facility, c.mnemonic, c.mac, c.subject) == ("UNIFI", "WiFi Client Disconnected", "0ABEDBC80D81", "Lobby AP")
    assert c.text == "Apple Watch 0d:87 disconnected from Employee WiFi." and syslog.notable(c)
    # A UniFi line can't pass for a Cisco message, whatever an SSID or a host name says.
    fake = parse(b"<30>Jun 21 22:42:22 %RADIUS-4-RADIUS_DEAD: RADIUS server 10.0.0.1 is not responding", "unifi")
    assert fake.facility != "RADIUS" and (fake.facility, fake.mnemonic) not in syslog.PRIORITY


def test_a_cisco_tag_far_into_a_message_is_text():
    raw = b"<13>Nov  7 12:00:00 host app: " + b"x" * 200 + b" %RADIUS-4-RADIUS_DEAD: RADIUS server 10.0.0.1 is not responding"
    assert parse(raw).facility == "app"
    assert parse(b"<13>user said:%RADIUS-4-RADIUS_DEAD: x").facility == "RADIUS"   # at a token boundary, near the start
    assert parse(b"<13>abc%RADIUS-4-RADIUS_DEAD: x").facility != "RADIUS"           # inside a word


def test_redaction():
    assert syslog.redact("Login failed [user: alice] [Source: 10.0.0.1]") == "Login failed [user: <redacted>] [Source: 10.0.0.1]"
    assert syslog.redact("user alice password=hunter2 key: abc, secret s3cr3t") == \
        "user <redacted> password=<redacted> key: <redacted>, secret <redacted>"
    assert "hunter2" not in parse(b"%AUTHMGR-5-FAIL: Authorization failed for client (0200.0000.1103) username=bob password hunter2").text
    for raw, secret in (("secret 5 Hunter2pass", "Hunter2pass"), ("tacacs key 7 RadKey123", "RadKey123"),
                        ("snmp-server user G v3 auth sha AuthPass1 priv aes 128 PrivPass1", "AuthPass1"),
                        ("snmp-server user G v3 auth sha AuthPass1 priv aes 128 PrivPass1", "PrivPass1"),
                        ("wpa-psk ascii 0 WifiPass", "WifiPass"), ("set-key 0 WifiPass", "WifiPass"),
                        ("key-string 7 ABCDEF", "ABCDEF"), ("suser=John Smith UNIFIclientMac=aa", "John Smith"),
                        ("IEEE 802.1X: identity received from STA: 'bob@example'", "bob@example"),
                        ("User Name:MYUSERNAME Ip Address:1.2.3.4", "MYUSERNAME"),
                        ("akm psk set-key ascii WifiPw 1", "WifiPw"), ("ntp authentication-key 1 md5 NtpSecret 7", "NtpSecret"),
                        ("snmp-server host 1.2.3.4 version 2c MyCommunity", "MyCommunity"),
                        ("snmp-server host 1.2.3.4 informs MyCommunity", "MyCommunity"),
                        ("config radius auth add 1 10.0.0.1 1812 ascii SharedSecret", "SharedSecret"),
                        ("config mgmtuser add u Pa55word read-write", "Pa55word"),
                        ("passphrase=Secret1 sae_password=Secret2", "Secret1"), ("passphrase=Secret1 sae_password=Secret2", "Secret2")):
        assert secret not in syslog.redact(raw), raw
    # A logged configuration command keeps its first two words only.
    m = parse(b"%PARSER-5-CFGLOG_LOGGEDCMD: User:admin  logged command:snmp-server host 10.1.1.1 version 2c MyTrapCommunity")
    assert "MyTrapCommunity" not in m.text and "snmp-server host" in m.text and "admin" not in m.text


def test_hostile_text_parses_quickly():
    # A long run of hyphenated words once made the port pattern backtrack quadratically (57 ms a datagram).
    start = time.perf_counter()
    for _ in range(20):
        parse(b"%LINK-3-UPDOWN: " + b"a-" * 1000)
    assert (time.perf_counter() - start) / 20 < 0.02


def test_port_and_mac_notations():
    assert syslog.port_of("on Interface Te2/1/1 now") == "TenGigabitEthernet2/1/1"
    assert syslog.port_of("VLAN 220 assigned to Interface GigabitEthernet1/0/5") == "GigabitEthernet1/0/5"
    assert syslog.port_of("RADIUS server 10.0.0.1:1812 is dead") == ""
    assert syslog.mac_of("client (0011.2233.44aa)") == "0011223344AA" and syslog.mac_of("mac 00-11-22-33-44-55") == "001122334455"


def test_coalescing_per_minute_and_text():
    co = Coalescer()
    msg = parse(DOT1X_FAIL)
    for i in range(5):
        assert co.add(SW, msg, NOW + timedelta(seconds=i), "192.0.2.10", mono=float(i)) == "kept"
    new = co.take(NOW + timedelta(seconds=5), mono=5.0)
    assert len(new) == 1 and new[0].count == 5 and new[0].first_at == NOW and new[0].last_at == NOW + timedelta(seconds=4)
    assert new[0].source == "192.0.2.10" and new[0].notable
    assert co.take(NOW + timedelta(seconds=6), mono=6.0) == []
    co.add(SW, msg, NOW + timedelta(seconds=7), mono=7.0)   # the same row, updated: its count waits COUNT_SECONDS
    assert co.take(NOW + timedelta(seconds=8), mono=8.0) == []
    again = co.take(NOW + timedelta(seconds=11), mono=5.0 + syslog.COUNT_SECONDS)
    assert again[0].id == new[0].id and again[0].count == 6
    co.add(SW, msg, NOW + timedelta(minutes=1), mono=60.0)  # the next minute: a new row, written at once
    nxt = co.take(NOW + timedelta(minutes=1, seconds=1), mono=61.0)
    assert len(nxt) == 1 and nxt[0].id != new[0].id and nxt[0].count == 1
    co.take(NOW + timedelta(minutes=1, seconds=3), mono=63.0)
    assert len(co.entries) == 1  # the first minute's row, written and clean, is forgotten
    st = co.take_stats()[SW]
    assert (st.received, st.kept, st.last_tag) == (7, 7, "DOT1X-5-FAIL")
    # Up and down within a minute are two rows.
    co.add(SW, parse(LINK_UP), NOW, mono=70.0)
    co.add(SW, parse(LINK_DOWN), NOW, mono=70.0)
    assert len([e for e in co.entries.values() if e.msg.facility == "LINK"]) == 2


def test_a_repeat_whose_minute_ended_is_written_without_waiting():
    co = Coalescer()
    co.add(SW, parse(DOT1X_FAIL), NOW, mono=0.0)
    co.take(NOW, mono=0.0)
    co.add(SW, parse(DOT1X_FAIL), NOW + timedelta(seconds=10), mono=1.0)
    assert [e.count for e in co.take(NOW + timedelta(minutes=1), mono=2.0)] == [2]


def fail_on(n: int) -> syslog.Message:
    return parse(f"%DOT1X-5-FAIL: Authentication failed for client (0200.0000.{n:04d}) on Interface Gi1/0/{n % 48 + 1}".encode())


def link_on(n: int) -> syslog.Message:
    return parse(f"%LINK-3-UPDOWN: Interface GigabitEthernet1/0/{n % 48 + 1}, changed state to up {n}".encode())


def test_quotas():
    co = Coalescer()
    assert co.add(SW, None, NOW, mono=0.0) == "empty"
    # Per device: a burst of 200 new rows, then 100 a second; repeats only count.
    results = [co.add(SW, fail_on(i), NOW, mono=0.0) for i in range(250)]
    assert results.count("kept") == 200 and results.count("quota") == 50
    assert co.add(SW, fail_on(0), NOW, mono=0.0) == "kept"  # a repeat, even with the bucket empty
    assert co.add(SW, fail_on(300), NOW, mono=1.0) == "kept"  # refilled
    # The bucket is the device's, whatever address it sends from.
    other_addr = Coalescer()
    assert [other_addr.add(SW, fail_on(i), NOW, f"10.0.{i}.1", mono=0.0) for i in range(201)].count("quota") == 1
    # The coalescing table overall, per tenant and per device.
    capped = Coalescer(max_entries=2)
    assert [capped.add(SW, fail_on(i), NOW, mono=float(i)) for i in range(3)] == ["kept", "kept", "quota"]
    per = Coalescer(per_device=2)
    other = Device(uuid.uuid4(), SW.tenant_id)
    assert [per.add(SW, fail_on(i), NOW, mono=float(i)) for i in range(3)] == ["kept", "kept", "quota"]
    assert per.add(other, fail_on(9), NOW, mono=0.0) == "kept"  # another device has its own share
    tenant = Coalescer(per_tenant=2)
    assert [tenant.add(d, fail_on(i), NOW, mono=0.0) for i, d in enumerate((SW, other, Device(uuid.uuid4(), SW.tenant_id)))] == ["kept", "kept", "quota"]
    assert tenant.add(Device(uuid.uuid4(), uuid.uuid4()), fail_on(1), NOW, mono=0.0) == "kept"  # another tenant isn't held up


def test_the_daily_bytes_go_to_notable_messages_last():
    sl, sf = len(link_on(1).text) + 200, len(fail_on(1).text) + 200
    # 80 %: room for three ordinary rows, and all of it for one notable row more.
    co = Coalescer(tenant_bytes=int(max(sl * 3 / syslog.NOTABLE_SHARE, sl * 3 + sf)) + 1)
    assert [co.add(SW, link_on(i), NOW, mono=0.0) for i in range(4)] == ["kept", "kept", "kept", "quota"]
    assert co.add(SW, fail_on(1), NOW, mono=0.0) == "kept"     # a notable one still fits in the last 20 %
    small = Coalescer(tenant_bytes=500)
    assert small.add(SW, fail_on(1), NOW, mono=0.0) == "kept"
    assert small.add(SW, fail_on(2), NOW, mono=0.0) == "quota"
    assert small.add(SW, parse(ERR_DISABLE), NOW, mono=0.0) == "kept"  # err-disable and RADIUS always kept
    assert small.add(SW, parse(b"%FOO-4-ERR_DISABLE: not the one"), NOW, mono=0.0) == "quota"  # the (facility, mnemonic) pair
    assert small.add(SW, fail_on(2), NOW + timedelta(days=1), mono=1.0) == "kept"  # a new day
    restarted = Coalescer(tenant_bytes=500)
    restarted.set_usage(NOW.date(), {SW.tenant_id: 400})  # what's already stored today counts after a restart
    assert restarted.add(SW, fail_on(1), NOW, mono=0.0) == "quota"
    assert small.take_stats()[SW].bytes > 0


def test_messages_about_different_servers_or_people_stay_apart():
    co = Coalescer()
    for raw in (b"%RADIUS-4-RADIUS_DEAD: RADIUS server 10.0.0.1:1812,1813 is not responding.",
                b"%RADIUS-4-RADIUS_DEAD: RADIUS server 10.0.0.2:1812,1813 is not responding.",
                b"%SYS-5-CONFIG_I: Configured from console by alice on vty0 (10.1.1.1)",
                b"%SYS-5-CONFIG_I: Configured from console by bob on vty1 (10.1.1.2)"):
        co.add(SW, parse(raw), NOW, mono=0.0)
    assert len(co.entries) == 4


def test_failed_writes_are_retried_then_dropped_and_a_restore_starts_over():
    co = Coalescer()
    co.add(SW, fail_on(1), NOW, mono=0.0)
    e = co.take(NOW, mono=0.0)[0]
    for _ in range(syslog.MAX_WRITE_FAILURES - 1):
        co.failed(e)
        assert co.take(NOW, mono=0.0) == [e]
    co.failed(e)
    assert co.entries == {} and co.per_device == {} and co.per_tenant == {}
    co.add(SW, fail_on(2), NOW, mono=0.0)
    co.reset()
    assert co.entries == {} and co.buckets == {} and co.used == {} and co.take_stats() == {}


def test_some_switch_messages_hint_at_an_earlier_poll():
    co = Coalescer()
    # A failed authentication or an err-disabled port: the SNMP view should catch up within seconds, not an interval.
    co.add(SW, parse(DOT1X_FAIL), NOW, mono=0.0)
    assert co.take_hints() == {SW: NOW} and co.take_hints() == {}
    co.add(SW, parse(ERR_DISABLE), NOW, mono=0.0)
    assert co.take_hints() == {SW: NOW}
    co.add(SW, parse(b"%ILPOWER-3-CONTROLLER_PORT_ERR: FAIL"), NOW, mono=0.0)   # a FAIL mnemonic? no: not the evidence
    co.add(SW, parse(b"%FOO-5-FAIL: something else failed"), NOW, mono=0.0)
    assert co.take_hints() == {}
    wlc = Device(uuid.uuid4(), SW.tenant_id, "cisco-9800")
    co.add(wlc, parse(DOT1X_FAIL), NOW, mono=0.0)
    assert co.take_hints() == {}   # controllers aren't polled
    assert syslog.HINT_MIN_GAP.total_seconds() == 30 and syslog.HINT_DELAY.total_seconds() == 10


def test_claims():
    t1, t2 = uuid.uuid4(), uuid.uuid4()
    sw = Device(uuid.uuid4(), t1)
    unifi = Device(uuid.uuid4(), t1, "unifi")
    quiet = Device(uuid.uuid4(), t1)
    other = Device(uuid.uuid4(), t2)
    c = Claims([("10.0.0.3", sw, False), ("10.0.0.3", sw, True),         # its RADIUS address (no switch) and its verified SNMP address
                ("10.0.0.0/24", unifi, True), ("10.0.0.7", quiet, False),
                ("10.1.0.0/16", other, True), ("2001:db8::10", sw, True)])
    assert c.lookup("10.0.0.3") == (sw, "ok")          # longest prefix
    assert c.lookup("10.0.0.50") == (unifi, "ok")      # an access point in the UniFi range
    assert c.lookup("10.0.0.7") == (None, "disabled")  # a device inside the range that hasn't syslog on: not the UniFi's
    assert c.lookup("10.1.2.3") == (other, "ok")
    assert c.lookup("2001:db8::10") == (sw, "ok") and c.lookup("192.0.2.1") == (None, "unknown")
    assert c.enabled == {sw, unifi, other}
    # Another tenant's device inside a range: neither tenant gets its messages.
    inside = Claims([("10.1.0.0/16", other, True), ("10.1.2.3", Device(uuid.uuid4(), t1), False)])
    assert inside.lookup("10.1.2.3") == (None, "ambiguous") and inside.lookup("10.1.2.4") == (other, "ok")
    # Two devices claiming the same address.
    assert Claims([("10.0.0.3", sw, True), ("10.0.0.3", quiet, True)]).lookup("10.0.0.3") == (None, "ambiguous")
    # IPv4-mapped claims mean the IPv4 range; compatible and NAT64 ones, and anything wider than 65,536, aren't claims.
    assert Claims([("::ffff:10.9.0.0/112", other, True)]).lookup("10.9.1.1") == (other, "ok")
    assert Claims([("::ffff:10.9.0.0/112", other, True), ("10.9.1.1", sw, False)]).lookup("10.9.1.1") == (None, "ambiguous")
    assert syslog.claim_network("::10.9.0.0/112") is None and syslog.claim_network("64:ff9b::a09:0/120") is None
    assert syslog.claim_network("10.0.0.0/15") is None and syslog.claim_network("nonsense") is None
    assert syslog.normalize_ip("::ffff:192.0.2.10") == "192.0.2.10"
    # Two tenants claim one address: the one whose SNMP credentials the device answers controls it.
    mine, theirs = Device(uuid.uuid4(), t1), Device(uuid.uuid4(), t2)
    assert Claims([("10.5.0.9", mine, True, True), ("10.5.0.9", theirs, True)]).lookup("10.5.0.9") == (mine, "ok")
    assert Claims([("10.5.0.9", mine, False, True), ("10.5.0.9", theirs, True)]).lookup("10.5.0.9") == (None, "ambiguous")
    inside = Claims([("10.5.0.0/24", theirs, True), ("10.5.0.9", mine, True, True)])   # a proven switch inside their range
    assert inside.lookup("10.5.0.9") == (mine, "ok") and inside.lookup("10.5.0.10") == (theirs, "ok")


def test_own_gateways(tmp_path):
    route = tmp_path / "route"
    route.write_text("Iface\tDestination\tGateway \tFlags\n"
                     "eth0\t00000000\t010012AC\t0003\n"     # default via 172.18.0.1
                     "eth0\t000012AC\t00000000\t0001\n")   # 172.18.0.0/16, connected
    route6 = tmp_path / "route6"
    route6.write_text("00000000000000000000000000000000 00 00000000000000000000000000000000 00 fd000000000000000000000000000001 "
                      "00000400 00000001 00000000 00000003 eth0\n"
                      "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 "
                      "00000400 00000001 00000000 00000003 eth1\n")
    assert syslog.own_gateways(str(route), str(route6)) == {"172.18.0.1", "fd00::1"}
    assert syslog.own_gateways(str(tmp_path / "missing"), str(tmp_path / "missing6")) == set()


def test_receiver_threads(monkeypatch):
    monkeypatch.setattr(syslog, "FLUSH_SECONDS", 0.1)
    monkeypatch.setattr(syslog, "COUNT_SECONDS", 0.2)
    stored: dict = {}  # row id → (tag, count) as last written

    def store(batch):
        stored.update({e.id: (e.msg.tag, e.count) for e in batch.entries})

    r = syslog.Receiver(lambda: Claims([("127.0.0.1", SW, True)]), store, port=0)
    r.start()
    try:
        port = r._sock.getsockname()[1]
        deadline = time.monotonic() + 5
        while not r.claims.enabled and time.monotonic() < deadline:
            time.sleep(0.02)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as out:
            for data in (DOT1X_FAIL, DOT1X_FAIL, b"not syslog at all"):
                out.sendto(data, ("127.0.0.1", port))
        while ("DOT1X-5-FAIL", 2) not in stored.values() and time.monotonic() < deadline:
            time.sleep(0.05)
    finally:
        r.stop()
    assert sorted(stored.values()) == [("DOT1X-5-FAIL", 2), ("syslog", 1)] and r.received == 3 and not r.unknown


def test_a_failed_store_is_retried():
    calls = []

    def store(batch):
        calls.append(len(batch.entries))
        if len(calls) == 1:
            batch.failed += batch.entries

    r = syslog.Receiver(lambda: Claims(), store)
    r.claims = Claims([("192.0.2.10", SW, True)])
    r.handle(DOT1X_FAIL, "192.0.2.10", NOW)
    r.flush()
    r.flush()
    assert calls == [1, 1]


def test_receiver_survives_and_bounds_a_flood(monkeypatch):
    r = syslog.Receiver(lambda: Claims(), lambda batch: None)
    r.claims = Claims([("192.0.2.10", SW, True), ("172.18.0.1", SW, True)])
    r.rewritten = {"172.18.0.1"}
    assert r.handle(DOT1X_FAIL, "172.18.0.1", NOW) == "rewritten"   # Docker's gateway: never the device
    monkeypatch.setattr(syslog, "RAW_BURST", 3.0)
    monkeypatch.setattr(syslog, "RAW_RATE", 0.0)
    r.raw.clear()
    got = [r.handle(DOT1X_FAIL, "192.0.2.10", NOW) for _ in range(5)]
    assert got[:3] == ["kept"] * 3 and got[3:] == ["quota", "quota"]
    assert r.coalescer.stats[SW].quota == 2 and r.health()["rewritten"] == 1


def test_a_bad_datagram_doesnt_stop_the_socket_thread(monkeypatch):
    r = syslog.Receiver(lambda: Claims(), lambda batch: None, port=0)
    seen = []

    def handle(data, addr, now=None):
        seen.append(data)
        if data == b"boom":
            raise RuntimeError("bad datagram")
        return "kept"
    monkeypatch.setattr(r, "handle", handle)
    r.start()
    try:
        port = r._sock.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as out:
            out.sendto(b"boom", ("127.0.0.1", port))
            out.sendto(b"fine", ("127.0.0.1", port))
        deadline = time.monotonic() + 5
        while len(seen) < 2 and time.monotonic() < deadline:
            time.sleep(0.02)
        assert seen == [b"boom", b"fine"] and r.alive()
    finally:
        r.stop()
    assert not r.alive()


def test_usage_is_loaded_before_any_claim():
    calls = []
    r = syslog.Receiver(lambda: calls.append("claims") or Claims(), lambda batch: None,
                        usage=lambda: calls.append("usage") or {SW.tenant_id: 1234})
    r._reload()
    r._reload()
    assert calls == ["usage", "claims", "claims"] and r.coalescer.used == {SW.tenant_id: 1234}
    failing = syslog.Receiver(lambda: calls.append("claims2") or Claims([("192.0.2.10", SW, True)]), lambda batch: None,
                              usage=lambda: (_ for _ in ()).throw(RuntimeError("db down")))
    failing._reload()
    assert "claims2" not in calls and not failing.claims.enabled   # no quota, no claims: nothing stored against zero


def test_receiver_counts_what_it_drops():
    r = syslog.Receiver(lambda: Claims(), lambda batch: None)
    r.claims = Claims([("192.0.2.10", SW, True), ("192.0.2.11", Device(uuid.uuid4(), SW.tenant_id), False)])
    assert r.handle(DOT1X_FAIL, "198.51.100.1", NOW) == "unknown"
    assert r.handle(DOT1X_FAIL, "192.0.2.11", NOW) == "disabled"
    assert r.handle(DOT1X_FAIL, "::ffff:192.0.2.10", NOW) == "kept"
    h = r.health()
    assert h["unknown_source"] == 1 and h["disabled"] == 1 and h["ambiguous"] == 0
    top = {t["address"]: t for t in h["unknown_top"]}
    assert top["198.51.100.1"]["why"] == "unknown" and top["198.51.100.1"]["sample"].startswith("<189>1234")
    assert len(top["198.51.100.1"]["sample"]) <= syslog.SAMPLE_CHARS


def test_config_block_with_syslog():
    block = service.config_block({"version": "v2c", "host": "192.0.2.10"}, "192.0.2.1", ("198.51.100.5", 5514))
    assert not [ln for ln in block.splitlines() if "discriminator" in ln and not ln.startswith("!")]
    assert "\nauthentication logging verbose\ndot1x logging verbose\nmab logging verbose\n" in block
    assert "\nlogging host 198.51.100.5 transport udp port 5514\n" in block
    assert "!   logging host 198.51.100.5 vrf Mgmt-vrf transport udp port 5514\n" in block
    assert "only keeps messages sent from 192.0.2.10" in block
    assert "\nlogging trap" not in block and "service timestamps" not in block
    assert "!   no logging discriminator EASYEAP" in block and "\nno logging discriminator EASYEAP" not in block  # a new switch
    legacy = service.config_block({"version": "v2c", "host": "192.0.2.10", "credentials_set_at": "2026-11-08T08:24:32Z"}, "192.0.2.1",
                                  ("198.51.100.5", 5514))
    assert "\nno logging discriminator EASYEAP\n" in legacy   # set up with the earlier block: the filter comes off
    assert "logging" not in service.config_block({"version": "v2c", "host": "192.0.2.10"}, "192.0.2.1")
    rm = service.removal_block({"version": "v2c"}, syslog=("198.51.100.5", 5514))
    assert rm.startswith("no logging host 198.51.100.5 transport udp port 5514\n")
    assert "!   no logging discriminator EASYEAP" in rm and "!   no dot1x logging verbose" in rm
    assert "logging" not in service.removal_block({"version": "v2c"})


def row(fac, mn, subject, at=NOW):
    from types import SimpleNamespace
    return SimpleNamespace(id=uuid.uuid4(), seq=1, first_at=at, last_at=at, count=1, facility=fac, severity=4, mnemonic=mn, port="", mac="",
                           session_id="", subject=subject, text="x", notable=True, source="")


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
