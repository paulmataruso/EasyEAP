"""Remote syslog: message format and framing, destination validation, real UDP/TCP/TLS delivery, and the forwarder's
cursor semantics against the database (integration)."""
from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import os
import socket
import ssl
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from app.logs import dbhandler, syslog
from app.logs.syslog import Destination, Message, Sender, frame, render

AT = datetime(2026, 11, 6, 9, 5, 7, 123000, tzinfo=UTC)


def _dest(**kw) -> Destination:
    return Destination(**{"name": "SIEM", "host": "siem.example", "port": 6514, **kw})


def _msg() -> Message:
    return Message("audit", 42, AT, syslog.SEVERITY["notice"], {"tenant": "Harborview Logistics", "actor": "alice@msp.example",
                                                                 "action": "certificate.revoked", "detail": {"reason": "keyCompromise"}})


# ── Format ───────────────────────────────────────────────────────────────────

def test_rfc5424_text():
    out = render(_dest(facility="local0"), _msg(), "easyeap.msp.example").decode()
    assert out == ('<133>1 2026-11-06T09:05:07.123Z easyeap.msp.example easyeap - audit - audit seq=42 tenant="Harborview Logistics" '
                   'actor=alice@msp.example action=certificate.revoked detail="{\\"reason\\":\\"keyCompromise\\"}"')


def test_rfc3164_json():
    out = render(_dest(format="rfc3164", body="json", facility="auth"), _msg(), "easyeap.msp.example").decode()
    head, body = out.split(": ", 1)
    assert head == "<37>Nov  6 09:05:07 easyeap.msp.example easyeap-audit"
    assert body.startswith('{"category":"audit","seq":42,"at":"2026-11-06T09:05:07.123Z","tenant":"Harborview Logistics"')


def test_text_body_keeps_one_line():
    m = Message("system", 7, AT, 3, {"level": "error", "message": 'boom "quoted"\nTraceback line'})
    body = syslog.text_body(m)
    assert "\n" not in body and body.endswith('message="boom \\"quoted\\"\\nTraceback line"')


def test_framing():
    assert frame(_dest(), b"<13>1 hello") == b"11 <13>1 hello"
    assert frame(_dest(framing="newline"), b"a\nb") == b"a b\n"


def test_severity_follows_the_event():
    assert syslog.SEVERITY["warning"] == 4
    assert syslog._audit_alarm("auth.login_failed") and not syslog._audit_alarm("certificate.issued")


# ── Validation ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("host", ["http://siem.example", "siem.example:514", "bad host", "-x.example", ""])
def test_host_must_be_a_bare_name_or_address(host):
    with pytest.raises(ValidationError):
        _dest(host=host)


def test_host_normalised():
    assert _dest(host="SIEM.Example").host == "siem.example"
    assert _dest(host="[2001:db8::1]").host == "2001:db8::1"


def test_ca_bundle_must_be_certificates():
    with pytest.raises(ValidationError, match="PEM certificates"):
        _dest(ca_pem="-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----")
    assert _dest(transport="udp", ca_pem=None).ca_pem is None


def test_categories_are_canonical_and_required():
    assert _dest(categories=["system", "audit"]).categories == ["audit", "system"]
    with pytest.raises(ValidationError):
        _dest(categories=[])
    with pytest.raises(ValidationError):
        _dest(facility="local9")


# ── Transport, with real sockets ─────────────────────────────────────────────

class Receiver:
    """A minimal syslog receiver on 127.0.0.1 (TCP, optionally TLS)."""

    def __init__(self, tls: ssl.SSLContext | None = None, close_after_first: bool = False):
        self.srv = socket.create_server(("127.0.0.1", 0))
        self.port = self.srv.getsockname()[1]
        self.tls, self.close_after_first = tls, close_after_first
        self.data = b""
        self.connections = 0
        self.got = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            self.connections += 1
            if self.tls:
                try:
                    conn = self.tls.wrap_socket(conn, server_side=True)
                except (ssl.SSLError, OSError):
                    conn.close()
                    continue
            with conn:
                try:
                    while chunk := conn.recv(65536):
                        self.data += chunk
                        self.got.set()
                        if self.close_after_first:
                            self.close_after_first = False
                            break
                except OSError:  # TLS peers that hang up without close_notify
                    pass

    def close(self):
        self.srv.close()


def _pki(tmp_path: Path) -> tuple[str, ssl.SSLContext]:
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Syslog CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])).issuer_name(ca_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    (tmp_path / "srv.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "srv.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "srv.pem", tmp_path / "srv.key")
    return ca.public_bytes(serialization.Encoding.PEM).decode(), ctx


def _wait(rx: Receiver, n: int) -> None:
    for _ in range(100):
        if rx.data.count(b"<133>1") >= n:
            return
        time.sleep(0.05)
    raise AssertionError(f"received {rx.data!r}")


def test_tcp_octet_counting():
    rx = Receiver()
    s = Sender(_dest(host="127.0.0.1", port=rx.port, transport="tcp"))
    msgs = [render(_dest(), _msg(), "h") for _ in range(3)]
    s.send(msgs)
    _wait(rx, 3)
    s.close()
    rx.close()
    first = rx.data.split(b" ", 1)
    assert int(first[0]) == len(msgs[0]) and rx.data == b"".join(frame(_dest(), m) for m in msgs)


def test_udp_one_datagram_per_message():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(2)
    s = Sender(_dest(host="127.0.0.1", port=srv.getsockname()[1], transport="udp"))
    s.send([b"<13>1 one", b"<13>1 two"])
    assert [srv.recv(9000), srv.recv(9000)] == [b"<13>1 one", b"<13>1 two"]
    s.close()
    srv.close()


def test_tls_verifies_against_the_pasted_ca(tmp_path):
    ca_pem, server_ctx = _pki(tmp_path)
    rx = Receiver(tls=server_ctx)
    good = Sender(_dest(host="localhost", port=rx.port, transport="tls", ca_pem=ca_pem))
    good.send([render(_dest(), _msg(), "h")])
    _wait(rx, 1)
    good.close()
    # Without the CA (system trust only) the self-made certificate is refused, with a plain explanation.
    bad = Sender(_dest(host="localhost", port=rx.port, transport="tls"))
    with pytest.raises(ssl.SSLCertVerificationError) as err:
        bad.send([b"x"])
    assert "isn't trusted" in syslog.describe_error(err.value)
    rx.close()


def test_reconnects_when_the_receiver_closed_the_connection():
    rx = Receiver(close_after_first=True)
    s = Sender(_dest(host="127.0.0.1", port=rx.port, transport="tcp"))
    s.send([render(_dest(), _msg(), "h")])
    _wait(rx, 1)
    for _ in range(50):  # let the receiver close its end
        if s.sock is not None and not s._alive():
            break
        time.sleep(0.05)
    s.send([render(_dest(), _msg(), "h")])
    _wait(rx, 2)
    assert rx.connections == 2
    s.close()
    rx.close()


def test_connection_refused_is_explained():
    port = socket.create_server(("127.0.0.1", 0)).getsockname()[1]  # closed again at once
    with pytest.raises(OSError) as err:
        Sender(_dest(host="127.0.0.1", port=port, transport="tcp"), timeout=2).send([b"x"])
    assert "refused" in syslog.describe_error(err.value).lower()


# ── Database log handler ─────────────────────────────────────────────────────

def test_handler_keeps_easyeap_info_and_library_warnings():
    rec = lambda name, lvl: logging.LogRecord(name, lvl, __file__, 1, "m", None, None)  # noqa: E731
    assert dbhandler.wanted(rec("easyeap.worker", logging.INFO))
    assert not dbhandler.wanted(rec("easyeap.worker", logging.DEBUG))
    assert not dbhandler.wanted(rec("httpx", logging.INFO))
    assert dbhandler.wanted(rec("sqlalchemy.pool", logging.WARNING))


def test_handler_redacts_and_never_blocks(monkeypatch):
    written: list[list[dict]] = []
    monkeypatch.setattr(dbhandler, "write_rows", lambda rows: written.append(rows))
    h = dbhandler.DatabaseLogHandler("api", interval=3600)
    lg = logging.getLogger(f"easyeap.test.{uuid.uuid4().hex}")
    lg.addHandler(h)
    lg.setLevel(logging.INFO)
    lg.propagate = False
    lg.warning("bind failed password=hunter2 for %s", "cn=svc")
    for i in range(dbhandler.MAX_QUEUE + 10):
        lg.info("line %d", i)
    assert h.dropped == 11
    h.flush()
    rows = [r for batch in written for r in batch]
    assert len(rows) == dbhandler.MAX_QUEUE
    assert all("hunter2" not in r["message"] for r in rows)
    assert rows[-1]["message"] == f"line {dbhandler.MAX_QUEUE + 9}" and rows[0]["source"] == "api"
    h._stop.set()


# ── Forwarder against the database ───────────────────────────────────────────

integration = pytest.mark.skipif(os.environ.get("EASYEAP_TEST_INTEGRATION") != "1", reason="integration stack not enabled")


@integration
def test_forwarder_delivers_and_catches_up_after_an_outage():
    from sqlalchemy import text

    from app import models as m
    from app.db import platform_session

    with platform_session() as s:
        saved = {k: (s.get(m.PlatformSetting, k).value if s.get(m.PlatformSetting, k) else None) for k in (syslog.CONFIG_KEY, syslog.STATE_KEY)}
        start = syslog.newest_ids(s.connection())
    rx = Receiver()
    dest = _dest(host="127.0.0.1", port=rx.port, transport="tcp", categories=["system"], system_level="warning",
                 start_after=start, id=uuid.uuid4().hex[:12])
    marker = uuid.uuid4().hex
    try:
        with platform_session() as s:
            syslog.save_destinations(s, [dest])
            s.execute(m.SystemLog.__table__.insert(), [
                {"level": "info", "source": "api", "logger": "easyeap.test", "message": f"{marker} skipped (below warning)"},
                {"level": "warning", "source": "api", "logger": "easyeap.test", "message": f"{marker} first"},
            ])
        fw = syslog.Forwarder()
        fw.cycle()
        for _ in range(100):
            if marker.encode() + b" first" in rx.data:
                break
            time.sleep(0.05)
        assert marker.encode() + b" first" in rx.data and b"skipped" not in rx.data
        with platform_session() as s:
            st = syslog.load_state(s)[dest.id]
        assert st["sent"] == 1 and not st.get("error") and st["cursors"]["system"] > start["system"]

        # The receiver goes away: the error is recorded and the cursor stays put.
        rx.close()
        fw._close_all()
        with platform_session() as s:
            s.execute(m.SystemLog.__table__.insert(), [{"level": "error", "source": "worker", "logger": "easyeap.test", "message": f"{marker} during outage"}])
        cursor_before = st["cursors"]["system"]
        fw.cycle()
        with platform_session() as s:
            st = syslog.load_state(s)[dest.id]
        assert st.get("error") and st["cursors"]["system"] == cursor_before

        # It comes back on another port (the operator fixed the destination): the missed message is delivered.
        rx2 = Receiver()
        with platform_session() as s:
            syslog.save_destinations(s, [dest.model_copy(update={"port": rx2.port})])
        fw.retry_at.clear()
        fw.cycle()
        for _ in range(100):
            if b"during outage" in rx2.data:
                break
            time.sleep(0.05)
        assert marker.encode() + b" during outage" in rx2.data
        with platform_session() as s:
            st = syslog.load_state(s)[dest.id]
        assert not st.get("error") and st["sent"] == 2

        # start_after moves past the saved cursor (a category added while editing starts from now): older messages stay put.
        with platform_session() as s:
            s.execute(m.SystemLog.__table__.insert(), [{"level": "error", "source": "worker", "logger": "easyeap.test", "message": f"{marker} before the edit"}])
            moved = syslog.newest_ids(s.connection())
            syslog.save_destinations(s, [dest.model_copy(update={"port": rx2.port, "start_after": moved})])
            s.execute(m.SystemLog.__table__.insert(), [{"level": "error", "source": "worker", "logger": "easyeap.test", "message": f"{marker} after the edit"}])
        fw.cycle()
        for _ in range(100):
            if b"after the edit" in rx2.data:
                break
            time.sleep(0.05)
        assert b"after the edit" in rx2.data and b"before the edit" not in rx2.data
        rx2.close()
        fw._close_all()
    finally:
        with platform_session() as s:
            s.execute(text("DELETE FROM system_logs WHERE message LIKE :m"), {"m": f"{marker}%"})
            for k, v in saved.items():
                row = s.get(m.PlatformSetting, k)
                if v is None and row is not None:
                    s.delete(row)
                elif v is not None:
                    (row or s.merge(m.PlatformSetting(key=k, value={}))).value = v
