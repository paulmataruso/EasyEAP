"""The time service's parsers: chronyc's CSV (saved from chrony 4.8, addresses replaced) and NTP replies."""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from app.timesync import chrony, sntp

FIX = Path(__file__).parent / "fixtures" / "chrony"


def test_tracking_reads_chronyc_csv_with_the_offset_the_way_people_say_it():
    t = chrony.parse_tracking((FIX / "tracking.csv").read_text())
    assert t["synchronised"] is True
    assert t["stratum"] == 3
    assert t["reference"] == "2001:db8:4002::3123"
    assert t["leap"] == "normal"
    # chronyc tracking said "0.000250776 seconds fast of NTP time": ahead is positive here.
    assert t["offset"] == pytest.approx(0.000250776)
    assert t["frequency_ppm"] == pytest.approx(-27.75)
    assert t["reference_time"].startswith("2026-11-09T22:53:52")


def test_tracking_before_chronyd_has_a_source_is_not_synchronised():
    # chronyd 4.8 with no reachable source, as chronyc 4.6.1 printed it
    t = chrony.parse_tracking("00000000,,0,0.000000000,0.000000000,0.000000000,0.000000000,0.000,0.000,0.000,1.000000000,1.000000000,0.0,Not synchronised\n")
    assert t["synchronised"] is False
    assert t["leap"] == "unsynchronised"
    assert t["reference_time"] is None


def test_tracking_refuses_output_it_doesnt_know():
    with pytest.raises(chrony.ChronyError):
        chrony.parse_tracking("506 Cannot talk to daemon\n")


def test_sources_and_selection():
    src = chrony.parse_sources((FIX / "sources.csv").read_text())
    assert [s["address"] for s in src][:2] == ["2001:db8:4000::2123", "192.0.2.123"]
    best = next(s for s in src if s["state"] == "selected")
    assert best["address"] == "2001:db8:4002::3123" and best["reach"] == 0o377 and best["reachable"]
    assert best["mode"] == "server" and best["poll"] == 9
    sel = chrony.parse_selectdata((FIX / "selectdata.csv").read_text())
    assert sel["2001:db8:4002::3123"]["select"] == "best"
    assert sel["2001:db8:4002::3123"]["prefer"] is True and sel["2001:db8:4002::3123"]["authenticated"] is True
    assert sel["2001:db8:4000::1123"]["select"] == "not_preferred" and sel["2001:db8:4000::1123"]["prefer"] is False


def _reply(cookie: int, rx: float, tx: float, *, mode: int = 4, stratum: int = 2, leap: int = 0, ref: bytes = b"\xc0\x00\x02\x01") -> bytes:
    def ntp(t: float) -> int:
        t += sntp.NTP_EPOCH
        return (int(t) << 32) | int((t % 1) * (1 << 32))
    return struct.pack("!BBbbII4sQQQQ", (leap << 6) | (4 << 3) | mode, stratum, 6, -20, 0, 0, ref, 0, cookie, ntp(rx), ntp(tx))


def test_an_ntp_reply_gives_the_offset_and_delay():
    packet, cookie = sntp.request()
    assert len(packet) == 48 and packet[0] == 0x23
    # Sent at 1000.0 by this clock, answered at 1000.6/1000.61 by the server, received at 1000.11: this clock is 0.55 s behind.
    s = sntp.parse(_reply(cookie, 1_800_000_000.6, 1_800_000_000.61), cookie, 1_800_000_000.0, 1_800_000_000.11, "192.0.2.1", 0.11)
    assert s.offset == pytest.approx(0.55, abs=1e-6)
    assert s.delay == pytest.approx(0.10, abs=1e-6)
    assert s.stratum == 2 and s.reference == "192.0.2.1"


@pytest.mark.parametrize(("kw", "why"), [
    ({"mode": 3}, "isn't from an NTP server"),
    ({"stratum": 0, "ref": b"RATE"}, "refused the request (RATE)"),
    ({"leap": 3}, "isn't synchronised"),
])
def test_an_ntp_reply_a_client_must_not_use_is_refused(kw, why):
    _packet, cookie = sntp.request()
    with pytest.raises(sntp.SntpError, match=why.replace("(", r"\(").replace(")", r"\)")):
        sntp.parse(_reply(cookie, 1_800_000_000.0, 1_800_000_000.0, **kw), cookie, 1_800_000_000.0, 1_800_000_000.0, "192.0.2.1", 0.0)


def test_a_reply_to_another_request_is_refused():
    _packet, cookie = sntp.request()
    with pytest.raises(sntp.SntpError, match="doesn't answer this request"):
        sntp.parse(_reply(cookie ^ 1, 1_800_000_000.0, 1_800_000_000.0), cookie, 1_800_000_000.0, 1_800_000_000.0, "192.0.2.1", 0.0)


def test_ntp_timestamps_after_2036_roll_into_the_next_era():
    # 2036-02-07T06:28:16Z is NTP era 1, second 0.
    assert sntp._ntp_to_unix(0x0000_0010 << 32) == pytest.approx(2_085_978_496 + 16)
