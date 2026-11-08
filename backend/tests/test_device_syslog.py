"""Device syslog, read side: sessions and clients decoded from what devices logged, the guidance per vendor, and the
cross-tenant check on a device's syslog addresses (docs/plans/syslog-full.md §4–§6, §9)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.switchaudit import devicelog
from app.switchaudit.syslog import notable, parse

T0 = datetime(2026, 11, 8, 12, 0, 0, tzinfo=UTC)


def rows(*lines: tuple[int, bytes], vendor: str = "cisco-switch", count: dict[int, tuple[int, int]] | None = None):
    """(seconds after T0, datagram) → rows as the receiver stores them; count: index → (count, last seconds)."""
    out = []
    for i, (sec, raw) in enumerate(lines):
        msg = parse(raw, vendor)
        n, last = (count or {}).get(i, (1, sec))
        out.append(SimpleNamespace(id=uuid.uuid4(), first_at=T0 + timedelta(seconds=sec), last_at=T0 + timedelta(seconds=last), count=n,
                                   facility=msg.facility, severity=msg.severity, mnemonic=msg.mnemonic, port=msg.port, mac=msg.mac,
                                   session_id=msg.session_id, subject=msg.subject, text=msg.text, notable=notable(msg)))
    return out


SID = b"0A0A0A0B0000001200ABCDEF"


def test_a_wired_session_from_start_to_link_down():
    got = devicelog.syslog_sessions(rows(
        (0, b"%SESSION_MGR-5-START: Switch 1 R0/0: sessmgrd: Starting 'dot1x' for client (0200.0000.1103) on Interface Gi1/0/5 AuditSessionID " + SID),
        (2, b"%DOT1X-5-SUCCESS: Switch 1 R0/0: sessmgrd: Authentication successful for client (0200.0000.1103) on Interface Gi1/0/5 AuditSessionID " + SID),
        (2, b"%SESSION_MGR-5-VLANASSIGN: VLAN 20 assigned to Interface Gi1/0/5 AuditSessionID " + SID),
        (3, b"%SESSION_MGR-5-SUCCESS: Authorization succeeded for client (0200.0000.1103) on Interface Gi1/0/5 AuditSessionID " + SID),
        (4, b"%EPM-6-POLICY_REQ: IP 10.1.20.7| MAC 0200.0000.1103| AuditSessionID " + SID + b"| EVENT IP-ASSIGNMENT"),
    ))
    assert len(got) == 1
    s = got[0]
    assert (s["port"], s["mac"], s["state"], s["method"], s["vlan"], s["ip"], s["session_id"], s["active"]) == \
        ("GigabitEthernet1/0/5", "020000001103", "authorized", "dot1x", 20, "10.1.20.7", SID.decode(), True)
    ended = devicelog.syslog_sessions(rows(
        (0, b"%SESSION_MGR-5-START: Starting 'mab' for client (0200.0000.1103) on Interface Gi1/0/5 AuditSessionID " + SID),
        (5, b"%LINK-3-UPDOWN: Interface GigabitEthernet1/0/5, changed state to down"),
        (6, b"%LINK-3-UPDOWN: Interface GigabitEthernet1/0/6, changed state to down"),
    ))[0]
    assert ended["ended"] == "link down" and not ended["active"] and ended["method"] == "mab"


def test_failures_carry_their_reason():
    s = devicelog.syslog_sessions(rows(
        (0, b"%DOT1X-5-FAIL: Authentication failed for client (aaaa.bbbb.cccc) with reason (No Response from Client) on Interface "
            b"Gi6/0/32 AuditSessionID CBFF0000"),
        (1, b"%SESSION_MGR-5-FAIL: Authorization failed or unapplied for client (aaaa.bbbb.cccc) on Interface Gi6/0/32 AuditSessionID "
            b"CBFF0000. Failure reason: Authc fail. Authc failure reason: Cred Fail."),
    ))[0]
    assert (s["state"], s["reason"], s["method"]) == ("unauthorized", "Cred Fail", "dot1x")
    office = devicelog.syslog_sessions(rows(   # what office-sx logged (IOS-XE 16.6.1)
        (0, b"%SESSION_MGR-5-FAIL: Switch 1 R0/0: sessmgrd: Authorization failed or unapplied for client (0005.1b31.576e) on Interface "
            b"GigabitEthernet1/0/24 AuditSessionID AC1000030000000BBA220E17"),
        (0, b"%DOT1X-5-FAIL: Switch 1 R0/0: sessmgrd: Authentication failed for client (0005.1B31.576E) on Interface Gi1/0/24 "
            b"AuditSessionID AC1000030000000BBA220E17"),
    ))[0]
    assert (office["port"], office["mac"], office["state"]) == ("GigabitEthernet1/0/24", "00051B31576E", "failed")


def test_a_repeated_row_counts_at_its_first_and_last_time():
    # Link down at :05 and again at :40 within one minute: one row (count 2). A session that started at :10 ended at :40.
    got = devicelog.syslog_sessions(rows(
        (5, b"%LINK-3-UPDOWN: Interface GigabitEthernet1/0/5, changed state to down"),
        (10, b"%SESSION_MGR-5-START: Starting 'dot1x' for client (0200.0000.1103) on Interface Gi1/0/5 AuditSessionID " + SID),
        (12, b"%SESSION_MGR-5-SUCCESS: Authorization succeeded for client (0200.0000.1103) on Interface Gi1/0/5 AuditSessionID " + SID),
        count={0: (2, 40)}))
    assert got[0]["ended"] == "link down"


def test_mac_move_and_a_new_session_after_the_end():
    got = devicelog.syslog_sessions(rows(
        (0, b"%SESSION_MGR-5-START: Starting 'dot1x' for client (0200.0000.1103) on Interface Gi1/0/5 AuditSessionID 01"),
        (5, b"%SESSION_MGR-5-MACMOVE: MAC address (0200.0000.1103) moved from Interface Gi1/0/5 to Interface Gi1/0/9 AuditSessionID 02"),
        (6, b"%SESSION_MGR-5-START: Starting 'dot1x' for client (0200.0000.1103) on Interface Gi1/0/9 AuditSessionID 02"),
    ))
    by_port = {s["port"]: s for s in got}
    assert by_port["GigabitEthernet1/0/5"]["ended"].startswith("moved to") and by_port["GigabitEthernet1/0/9"]["active"]
    # No MACMOVE (the old port went down before the switch logged to EasyEAP): starting elsewhere ends the old one.
    got = devicelog.syslog_sessions(rows(
        (0, b"%SESSION_MGR-5-FAIL: Authorization failed or unapplied for client (0005.1b31.576e) on Interface GigabitEthernet1/0/24 AuditSessionID 01"),
        (600, b"%SESSION_MGR-5-START: Starting 'dot1x' for client (0005.1B31.576E) on Interface GigabitEthernet1/0/23 AuditSessionID 02"),
    ))
    by_port = {s["port"]: s for s in got}
    assert by_port["GigabitEthernet1/0/24"]["ended"] == "started on GigabitEthernet1/0/23" and by_port["GigabitEthernet1/0/23"]["active"]


def test_nexus_sessions_name_a_port():
    got = devicelog.syslog_sessions(rows(
        (0, b"%DOT1X-5-SESSION_CREATION: Dot1x authentication session initiated in interface Ethernet1/5 using authentication method MAB"),
        (9, b"%DOT1X-5-SESSION_TERMINATION: Dot1x authentication session initiated in interface Ethernet1/5 using authentication method "
            b"MAB is terminated because of Link Down and port moved to Unauthorized state"),
    ))
    assert got[0]["port"] == "Ethernet1/5" and got[0]["mac"] is None and got[0]["ended"] == "Link Down (port Unauthorized)"


def test_wireless_clients():
    c9800 = devicelog.syslog_sessions(rows(
        (0, b"%CLIENT_ORCH_LOG-6-CLIENT_ADDED_TO_RUN_STATE: R0/0: wncd: Username entry (3423.874C.6BF7) joined with ssid (EWA-Guest) "
            b"for device with MAC: 3423.874c.6bf7"),
        (5, b"%CLIENT_EXCLUSION_SERVER-5-ADD_TO_EXCLUSIONLIST_REASON_DYNAMIC: R0/0: wncmgrd: Client MAC: ec2e.9835.cc35 was added to "
            b"exclusion list associated with AP Name:AP_REUNIONES, BSSID:MAC: 00d7.8f2f.6c24, reason:802.1X authentication credential failure"),
        vendor="cisco-9800"))
    by_mac = {s["mac"]: s for s in c9800}
    assert by_mac["3423874C6BF7"]["state"] == "connected" and by_mac["3423874C6BF7"]["ssid"] == "EWA-Guest"
    ex = by_mac["EC2E9835CC35"]
    assert (ex["state"], ex["ap"], ex["reason"]) == ("excluded", "AP_REUNIONES", "802.1X authentication credential failure")
    aireos = devicelog.syslog_sessions(rows(
        (0, b"WLC: *apfMsConnTask_3: Jan 05 13:48:49.758: %APF-3-ASSOC_TRAP: apf_80211.c:19384 Client Association: "
            b"MACAddress:aa:aa:aa:aa:aa:01 Base Radio MAC:00:00:00:00:00:01 Slot:1 User Name:unknown Ip Address:10.0.0.9"),
        (3, b"WLC: *Dot1x_NW_MsgTask_2: Feb 08 14:38:49.791: #APF-3-AUTHENTICATION_TRAP: apf_80211.c:15520 Client Authenticated: "
            b"MACAddress:aa:aa:aa:aa:aa:01 Base Radio MAC:00:00:00:00:00:01 Slot:1 User Name:bob Ip Address:10.0.0.9 SSID:CORP"),
        (9, b"WLC: *apfReceiveTask: Jan 05 13:54:14.418: %APF-3-DISASSOC_TRAP: apf_80211.c:19394 Client Disassociated: "
            b"MACAddress:aa:aa:aa:aa:aa:01 Base Radio MAC:00:00:00:00:00:01 Slot:1 User Name:unknown Ip Address:10.0.0.9 "
            b"Reason:Disassociated due to inactivity ReasonCode:4"),
        vendor="cisco-aireos"))[0]
    assert (aireos["ssid"], aireos["ip"], aireos["ended"]) == ("CORP", "10.0.0.9", "Disassociated due to inactivity")
    unifi = devicelog.syslog_sessions(rows(
        (0, b"<30>Jun 21 22:42:22 RoomA 023c8af144b7,UAP-AC-Lite-6.7.5+14823: hostapd[32723]: wifi0ap1: STA 02:5f:3a:9c:11:e4 IEEE 802.11: associated"),
        (1, b"<30>Jun 21 22:42:23 RoomA 023c8af144b7,UAP-AC-Lite-6.7.5+14823: hostapd[32723]: wifi0ap1: STA 02:5f:3a:9c:11:e4 IEEE 802.1X: "
            b"authenticated - EAP type: 13 (TLS)"),
        vendor="unifi"))[0]
    assert (unifi["state"], unifi["method"], unifi["ap"]) == ("authenticated", "EAP-TLS", "RoomA")


def test_guides():
    target = ("172.16.0.45", 5514)
    g = devicelog.guide("cisco-9800", "10.0.0.5", [], target, False)
    assert "logging host 172.16.0.45 transport udp port 5514" in g["config"] and g["removal"].startswith("no logging host 172.16.0.45")
    assert "10.0.0.5" in g["config"] and g["can_send"]
    a = devicelog.guide("cisco-aireos", "10.0.0.6", [], target, False)
    assert not a["can_send"] and "UDP 514 only" in a["notes"][0]
    a514 = devicelog.guide("cisco-aireos", "10.0.0.6", [], target, True)
    assert a514["can_send"] and a514["port"] == 514 and "config logging syslog facility client authfail enable" in a514["config"]
    assert "config logging syslog host 172.16.0.45 delete" in a514["removal"]
    u = devicelog.guide("unifi", "10.0.10.0/24", ["10.0.0.2"], target, False)
    assert any("SIEM Server" in s for s in u["steps"]) and any("10.0.10.0/24, 10.0.0.2" in n for n in u["notes"])
    assert not devicelog.guide("other", "10.0.0.7", [], None, False)["can_send"]


def test_syslog_conflicts(monkeypatch):
    from app.routers import device_syslog as r
    from app.switchaudit.syslog import claim_network
    me, them = uuid.uuid4(), uuid.uuid4()

    def client(tid, address, name="x", addresses=(), host=""):
        return SimpleNamespace(id=uuid.uuid4(), tenant_id=tid, name=name, address=address, syslog={"addresses": list(addresses)},
                               monitoring={"host": host} if host else {})

    others = [client(me, "10.0.0.0/24", "UniFi"), client(them, "10.9.0.0/16"), client(them, "172.16.5.5", host="172.16.6.6"),
              client(them, "172.20.0.1", addresses=["172.21.0.9"]),                                   # syslog off: claims nothing extra
              SimpleNamespace(**{**vars(client(them, "172.22.0.1")), "syslog": {"enabled": True, "addresses": ["172.23.0.9"]}})]
    s = SimpleNamespace(scalars=lambda q: others, info={"tenant_id": me})
    monkeypatch.setattr(r, "set_platform", lambda s: None)
    monkeypatch.setattr(r, "set_tenant", lambda s, t: None)
    mine = uuid.uuid4()
    assert r.syslog_conflict(s, me, [claim_network("10.0.0.5")], mine) is None          # inside my own range: longest prefix
    assert "already has" in r.syslog_conflict(s, me, [claim_network("10.0.0.0/24")], mine)
    assert "another tenant" in r.syslog_conflict(s, me, [claim_network("10.9.3.0/24")], mine)
    assert "another tenant" in r.syslog_conflict(s, me, [claim_network("172.16.6.6")], mine)   # their switch's SNMP address
    assert "another tenant" in r.syslog_conflict(s, me, [claim_network("::ffff:10.9.0.1")], mine)   # mapped: the same address
    assert r.syslog_conflict(s, me, [claim_network("2001:db8::1")], mine) is None
    assert r.syslog_conflict(s, me, [claim_network("172.21.0.9")], mine) is None        # their switched-off extra address
    assert "another tenant" in r.syslog_conflict(s, me, [claim_network("172.23.0.9")], mine)


@pytest.mark.parametrize("bad", ["nonsense", "10.0.0.0/8", "10.0.0.0/23", "::10.0.0.1", "64:ff9b::a00:1", "127.0.0.1", "169.254.1.1",
                                 "fe80::1", "224.0.0.5"])
def test_syslog_addresses_are_checked(monkeypatch, bad):
    from fastapi import HTTPException

    from app import models as m
    from app.routers import device_syslog as r
    tid = uuid.uuid4()
    c = SimpleNamespace(id=uuid.uuid4(), tenant_id=tid, name="wlc", address="10.0.0.5", vendor="cisco-9800", syslog={}, monitoring={})
    ctx = SimpleNamespace(session=SimpleNamespace(get=lambda model, _k: c if model is m.RadiusClient else None), id=tid,
                          actor=SimpleNamespace(label="admin"))
    with pytest.raises(HTTPException) as e:
        r.set_device_syslog(c.id, r.SyslogSettingsIn(enabled=True, addresses=[bad]), ctx)
    assert e.value.status_code == 422 and e.value.detail["field"] == "addresses"


def test_turning_syslog_on_is_audited(monkeypatch):
    from app import models as m
    from app.routers import device_syslog as r
    tid = uuid.uuid4()
    c = SimpleNamespace(id=uuid.uuid4(), tenant_id=tid, name="wlc", address="10.0.0.5", vendor="cisco-9800", syslog={}, monitoring={})
    ctx = SimpleNamespace(session=SimpleNamespace(get=lambda model, _k: c if model is m.RadiusClient else None), id=tid,
                          actor=SimpleNamespace(label="admin"))
    recorded = []
    monkeypatch.setattr(r, "syslog_conflict", lambda *a: None)
    monkeypatch.setattr(r.audit, "record", lambda *a, **k: recorded.append(k["detail"]))
    out = r.set_device_syslog(c.id, r.SyslogSettingsIn(enabled=True, addresses=["10.0.0.9", "10.0.0.9", "::ffff:10.0.0.10"]), ctx)
    assert out["settings"] == {"enabled": True, "addresses": ["10.0.0.9", "10.0.0.10"]} and c.syslog == out["settings"]
    assert recorded == [{"enabled": True, "addresses": ["10.0.0.9", "10.0.0.10"]}]
    r.set_device_syslog(c.id, r.SyslogSettingsIn(enabled=True, addresses=["10.0.0.9", "10.0.0.10"]), ctx)
    assert len(recorded) == 1   # nothing changed: nothing recorded
    # Extra addresses saved with syslog off are checked too (they'd claim the moment it's turned on).
    checked = []
    monkeypatch.setattr(r, "syslog_conflict", lambda s, t, nets, cid: checked.append([str(n) for n in nets]))
    r.set_device_syslog(c.id, r.SyslogSettingsIn(enabled=False, addresses=["10.0.0.11"]), ctx)
    r.set_device_syslog(c.id, r.SyslogSettingsIn(enabled=False), ctx)
    assert checked == [["10.0.0.11/32"]]
    monkeypatch.setattr(r, "syslog_conflict", lambda *a: "This address overlaps a device of another tenant")
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as e:
        r.set_device_syslog(c.id, r.SyslogSettingsIn(enabled=True), ctx)
    assert e.value.status_code == 409
