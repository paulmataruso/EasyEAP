"""Switch audit: the SNMP client (BER, v2c, USM), reading a switch's tables, the finding rules and their hysteresis,
the generated switch configuration and the monitoring settings (docs/plans/switch-audit.md)."""
from __future__ import annotations

import hashlib
import hmac
import socket
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.radius.wired import canonical_port, planned_ports
from app.switchaudit import collect, findings, service, snmp
from app.switchaudit.findings import Context, Found, Seen, evaluate
from app.switchaudit.snmp import CFB, Cipher, algorithms

# ── BER ──────────────────────────────────────────────────────────────────────


def test_oid_round_trip_with_large_arcs():
    for text in ("1.3.6.1.2.1.1.5.0", "1.3.6.1.4.1.9.9.656.1.4.1.1.2.8.48.65", "1.3.6.1.4.1.2147483647.0", "2.999.1"):
        o = snmp.oid(text)
        node, end = snmp.read(snmp.enc_oid(o))
        assert snmp.dec_oid(node) == o and end == len(snmp.enc_oid(o))


@pytest.mark.parametrize("v", [0, 1, 127, 128, 255, 256, 65535, 2_147_483_647, -1, -128, -129])
def test_integer_round_trip(v):
    node, _ = snmp.read(snmp.enc_int(v))
    assert snmp.dec_int(node) == v


def test_unsigned_types_keep_the_top_bit_clear():
    node, _ = snmp.read(snmp.enc_int(0xFFFFFFFF, snmp.GAUGE32))
    assert node.value[0] == 0 and snmp.dec_value(node) == 0xFFFFFFFF


def test_long_lengths_and_truncation():
    body = b"x" * 300
    node, _ = snmp.read(snmp.tlv(snmp.OCTET_STRING, body))
    assert node.value == body
    with pytest.raises(snmp.SnmpError):
        snmp.read(snmp.tlv(snmp.OCTET_STRING, body)[:-1])
    with pytest.raises(snmp.SnmpError):
        snmp.read(b"\x04\x85\x00\x00\x00\x00\x01")  # a five-byte length
    with pytest.raises(snmp.SnmpError):
        snmp.read(b"\x04")


def test_varbind_exceptions_are_falsy_and_recognised():
    for tag, obj in ((0x80, snmp.NoSuchObject), (0x81, snmp.NoSuchInstance), (0x82, snmp.EndOfMibView)):
        node, _ = snmp.read(bytes([tag, 0]))
        v = snmp.dec_value(node)
        assert v is obj and not v and snmp.is_missing(v)


def test_text_and_mac_helpers():
    assert snmp.text(b"Gi1/0/1\x00\x07") == "Gi1/0/1"
    assert snmp.text(snmp.NoSuchObject) == ""
    assert snmp.mac(b"\x00\x11\x22\x33\x44\x55") == "001122334455"
    assert snmp.mac(b"\x00\x11") == ""


# ── USM keys (RFC 3414 appendix A.3.2) ──────────────────────────────────────


def test_rfc3414_sha1_key_localization_vector():
    ku = snmp.password_to_key(b"maplesyrup", "sha1")
    assert ku.hex() == "9fb5cc0381497b3793528939ff788d5d79145211"
    kul = snmp.localize(ku, bytes.fromhex("000000000000000000000002"), "sha1")
    assert kul.hex() == "6695febc9288e36282235fc7151f128497b38f3f"


def test_v3_protocol_combinations():
    snmp.V3("u", "authkey12", "privkey12", "sha256", "aes256").check()
    with pytest.raises(snmp.SnmpError):
        snmp.V3("u", "authkey12", "privkey12", "sha", "aes256").check()  # would need key extension
    with pytest.raises(snmp.SnmpError):
        snmp.V3("u", "short", "privkey12").check()


# ── A fake agent on localhost ────────────────────────────────────────────────


class Agent:
    """Answers GET/GETNEXT/GETBULK from a sorted table, over v2c and USM (SHA-256 or SHA-1, AES), with knobs to
    misbehave: drop requests, refuse big responses, return OIDs out of order, start with a stale clock."""

    def __init__(self, table: dict[str, object], community="public", user="easyeap", auth_key="authkey123", priv_key="privkey123",
                 auth="sha256", priv="aes128"):
        self.rows = sorted((snmp.oid(k), v) for k, v in table.items())
        self.community, self.user = community, user
        self.engine_id = bytes.fromhex("80001f8804") + b"fake-switch"
        self.boots, self.started = 7, time.monotonic() - 1000
        h = snmp.AUTH[auth][0]
        self.hash, self.mac_len = h, snmp.AUTH[auth][1]
        self.auth_key = snmp.localize(snmp.password_to_key(auth_key.encode(), h), self.engine_id, h)
        self.priv_key = snmp.localize(snmp.password_to_key(priv_key.encode(), h), self.engine_id, h)[:snmp.PRIV[priv]]
        self.drop_first, self.max_varbinds, self.disorder, self.report_time_once = 0, None, False, False
        self.response_time_offset, self.no_priv = 0, False  # replayed-looking clock; authenticated but unencrypted answers
        self.requests = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.2)
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def close(self):
        self._stop = True
        self.thread.join(2)
        self.sock.close()

    def _serve(self):
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError:
                return
            self.requests += 1
            if self.drop_first > 0:
                self.drop_first -= 1
                continue
            try:
                out = self._handle(data)
            except Exception:  # noqa: BLE001 — a broken request gets no answer, like a real agent
                out = None
            if out:
                self.sock.sendto(out, addr)

    def _answer(self, pdu: snmp.Pdu) -> list[tuple[tuple, object]]:
        out = []
        if pdu.kind == snmp.GET:
            for o, _ in pdu.varbinds:
                out.append((o, next((v for k, v in self.rows if k == o), snmp.NoSuchObject)))
        elif pdu.kind == snmp.GETNEXT:
            for o, _ in pdu.varbinds:
                nxt = next(((k, v) for k, v in self.rows if k > o), None)
                out.append(nxt or (o, snmp.EndOfMibView))
        else:
            o = pdu.varbinds[0][0]
            for _ in range(pdu.error_index):
                nxt = next(((k, v) for k, v in self.rows if k > o), None)
                if nxt is None:
                    out.append((o, snmp.EndOfMibView))
                    break
                out.append(nxt)
                o = nxt[0]
            if self.disorder and len(out) > 1:
                out[1] = out[0]  # the same OID again: an agent looping
        return out

    def _encode_value(self, v) -> bytes:
        if v is snmp.NoSuchObject:
            return bytes([0x80, 0])
        if v is snmp.EndOfMibView:
            return bytes([0x82, 0])
        if isinstance(v, int):
            return snmp.enc_int(v)
        if isinstance(v, tuple):
            return snmp.enc_oid(v)
        return snmp.tlv(snmp.OCTET_STRING, v if isinstance(v, bytes) else str(v).encode())

    def _response(self, rid: int, vbs, kind=snmp.RESPONSE, status=0) -> bytes:
        body = snmp.seq(*(snmp.seq(snmp.enc_oid(o), self._encode_value(v)) for o, v in vbs))
        return snmp.seq(snmp.enc_int(rid), snmp.enc_int(status), snmp.enc_int(0), body, tag=kind)

    def _result(self, pdu: snmp.Pdu) -> bytes:
        if self.max_varbinds and pdu.kind == snmp.GETBULK and pdu.error_index > self.max_varbinds:
            return self._response(pdu.request_id, [], status=1)  # tooBig
        return self._response(pdu.request_id, self._answer(pdu))

    def _handle(self, data: bytes) -> bytes | None:
        top, _ = snmp.read(data)
        parts = snmp.children(top)
        version = snmp.dec_int(parts[0])
        if version == 1:
            if parts[1].value.decode() != self.community:
                return None
            pdu = snmp.dec_pdu(parts[2])
            return snmp.seq(snmp.enc_int(1), snmp.tlv(snmp.OCTET_STRING, parts[1].value), self._result(pdu))
        g = snmp.children(parts[1])
        mid, flags = snmp.dec_int(g[0]), g[2].value[0]
        sec_top, _ = snmp.read(data, parts[2].start, parts[2].end)
        sp = snmp.children(sec_top)
        now = int(time.monotonic() - self.started)
        if not sp[0].value:  # discovery
            report = self._response(0, [(snmp.oid("1.3.6.1.6.3.15.1.1.4.0"), 1)], kind=snmp.REPORT)
            return self._v3(mid, 0x00, report, now, encrypt=False, authenticate=False)
        if sp[3].value.decode() != self.user:
            report = self._response(0, [(snmp.oid("1.3.6.1.6.3.15.1.1.3.0"), 1)], kind=snmp.REPORT)
            return self._v3(mid, 0x00, report, now, encrypt=False, authenticate=False)
        auth = sp[4]
        check = hmac.new(self.auth_key, data[:auth.start] + b"\x00" * self.mac_len + data[auth.end:], self.hash).digest()[:self.mac_len]
        if check != data[auth.start:auth.end]:
            report = self._response(0, [(snmp.oid("1.3.6.1.6.3.15.1.1.5.0"), 1)], kind=snmp.REPORT)
            return self._v3(mid, 0x00, report, now, encrypt=False, authenticate=False)
        if self.report_time_once or abs(snmp.dec_int(sp[2]) - now) > 150:
            self.report_time_once = False
            report = self._response(0, [(snmp.oid("1.3.6.1.6.3.15.1.1.2.0"), 1)], kind=snmp.REPORT)
            return self._v3(mid, 0x01, report, now, encrypt=False, authenticate=True)
        iv = snmp.dec_int(sp[1]).to_bytes(4, "big") + snmp.dec_int(sp[2]).to_bytes(4, "big") + sp[5].value
        dec = Cipher(algorithms.AES(self.priv_key), CFB(iv)).decryptor()
        plain = dec.update(parts[3].value) + dec.finalize()
        scoped, _ = snmp.read(plain)
        pdu = snmp.dec_pdu(snmp.children(scoped)[2])
        if self.no_priv:
            return self._v3(mid, 0x01, self._result(pdu), now, encrypt=False, authenticate=True)
        return self._v3(mid, flags & 0x03, self._result(pdu), now + self.response_time_offset, encrypt=True, authenticate=True)

    def _v3(self, mid: int, flags: int, pdu: bytes, now: int, encrypt: bool, authenticate: bool) -> bytes:
        scoped = snmp.seq(snmp.tlv(snmp.OCTET_STRING, self.engine_id), snmp.tlv(snmp.OCTET_STRING, b""), pdu)
        salt = b"\x00\x00\x00\x00\x00\x00\x00\x09"
        if encrypt:
            iv = self.boots.to_bytes(4, "big") + now.to_bytes(4, "big") + salt
            enc = Cipher(algorithms.AES(self.priv_key), CFB(iv)).encryptor()
            data = snmp.tlv(snmp.OCTET_STRING, enc.update(scoped) + enc.finalize())
        else:
            data = scoped
        marker = b"\xab" * self.mac_len if authenticate else b""
        sec = snmp.seq(snmp.tlv(snmp.OCTET_STRING, self.engine_id), snmp.enc_int(self.boots), snmp.enc_int(now),
                       snmp.tlv(snmp.OCTET_STRING, self.user.encode() if authenticate else b""), snmp.tlv(snmp.OCTET_STRING, marker),
                       snmp.tlv(snmp.OCTET_STRING, salt if encrypt else b""))
        msg = snmp.seq(snmp.enc_int(3), snmp.seq(snmp.enc_int(mid), snmp.enc_int(65507), snmp.tlv(snmp.OCTET_STRING, bytes([flags])), snmp.enc_int(3)),
                       snmp.tlv(snmp.OCTET_STRING, sec), data)
        if authenticate:
            at = msg.index(marker)
            blank = msg[:at] + b"\x00" * self.mac_len + msg[at + self.mac_len:]
            digest = hmac.new(self.auth_key, blank, self.hash).digest()[:self.mac_len]
            msg = msg[:at] + digest + msg[at + self.mac_len:]
        return msg


TABLE = {"1.3.6.1.2.1.1.5.0": b"sw1", **{f"1.3.6.1.2.1.31.1.1.1.1.{i}": f"Gi1/0/{i}".encode() for i in range(1, 50)},
         "1.3.6.1.2.1.31.1.1.1.18.1": b"desk"}


@pytest.fixture
def agent():
    a = Agent(TABLE)
    yield a
    a.close()


def test_v2c_get_and_walk(agent):
    with snmp.Session("127.0.0.1", snmp.V2c("public"), port=agent.port, timeout=1, retries=0) as s:
        got = s.get(["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.6.0"])
        assert got[snmp.oid("1.3.6.1.2.1.1.5.0")] == b"sw1" and got[snmp.oid("1.3.6.1.2.1.1.6.0")] is snmp.NoSuchObject
        rows = s.walk("1.3.6.1.2.1.31.1.1.1.1")
        assert len(rows) == 49 and rows[0][1] == b"Gi1/0/1" and rows[-1][1] == b"Gi1/0/49"
        assert s.requests == 1 + 3  # 49 rows at 20 per GETBULK


def test_v2c_wrong_community_times_out(agent):
    with snmp.Session("127.0.0.1", snmp.V2c("nope"), port=agent.port, timeout=0.3, retries=1) as s, pytest.raises(snmp.SnmpTimeout):
        s.get(["1.3.6.1.2.1.1.5.0"])


def test_retry_after_a_lost_request(agent):
    agent.drop_first = 1
    with snmp.Session("127.0.0.1", snmp.V2c("public"), port=agent.port, timeout=0.3, retries=2) as s:
        assert s.get(["1.3.6.1.2.1.1.5.0"])[snmp.oid("1.3.6.1.2.1.1.5.0")] == b"sw1"


def test_too_big_halves_the_repetitions(agent):
    agent.max_varbinds = 5
    with snmp.Session("127.0.0.1", snmp.V2c("public"), port=agent.port, timeout=1, retries=0) as s:
        assert len(s.walk("1.3.6.1.2.1.31.1.1.1.1")) == 49


def test_walk_refuses_oids_out_of_order(agent):
    agent.disorder = True
    with snmp.Session("127.0.0.1", snmp.V2c("public"), port=agent.port, timeout=1, retries=0) as s, pytest.raises(snmp.SnmpError):
        s.walk("1.3.6.1.2.1.31.1.1.1.1")


def test_walk_row_limit(agent):
    with snmp.Session("127.0.0.1", snmp.V2c("public"), port=agent.port, timeout=1, retries=0) as s, pytest.raises(snmp.SnmpError) as e:
        s.walk("1.3.6.1.2.1.31.1.1.1.1", max_rows=10)
    assert e.value.kind == "too_big"


def test_deadline_bounds_the_session():
    quiet = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    quiet.bind(("127.0.0.1", 0))
    try:
        t = time.monotonic()
        with snmp.Session("127.0.0.1", snmp.V2c("x"), port=quiet.getsockname()[1], timeout=5, retries=5, deadline=time.monotonic() + 0.5) as s, \
                pytest.raises(snmp.SnmpTimeout):
            s.get(["1.3.6.1.2.1.1.5.0"])
        assert time.monotonic() - t < 2
    finally:
        quiet.close()


@pytest.mark.parametrize(("auth", "priv"), [("sha256", "aes128"), ("sha256", "aes256"), ("sha", "aes128")])
def test_v3_auth_priv(auth, priv):
    a = Agent(TABLE, auth=auth, priv=priv)
    try:
        with snmp.Session("127.0.0.1", snmp.V3("easyeap", "authkey123", "privkey123", auth, priv), port=a.port, timeout=1, retries=0) as s:
            assert s.get(["1.3.6.1.2.1.1.5.0"])[snmp.oid("1.3.6.1.2.1.1.5.0")] == b"sw1"
            assert len(s.walk("1.3.6.1.2.1.31.1.1.1.1")) == 49
            assert s.engine_id == a.engine_id
    finally:
        a.close()


def test_v3_clock_window_report_is_retried_once(agent):
    agent.report_time_once = True
    with snmp.Session("127.0.0.1", snmp.V3("easyeap", "authkey123", "privkey123"), port=agent.port, timeout=1, retries=0) as s:
        assert s.get(["1.3.6.1.2.1.1.5.0"])[snmp.oid("1.3.6.1.2.1.1.5.0")] == b"sw1"


@pytest.mark.parametrize(("creds", "words"), [
    (snmp.V3("easyeap", "wrongkey123", "privkey123"), "authentication key"),
    (snmp.V3("someone", "authkey123", "privkey123"), "doesn't know this SNMPv3 user"),
    (snmp.V3("easyeap", "authkey123", "privkey123", "sha", "aes128"), "authentication key"),
])
def test_v3_refusals_are_auth_errors(agent, creds, words):
    with snmp.Session("127.0.0.1", creds, port=agent.port, timeout=0.5, retries=0) as s, pytest.raises(snmp.SnmpAuthError) as e:
        s.get(["1.3.6.1.2.1.1.5.0"])
    assert words in str(e.value)


def test_v3_wrong_privacy_key_is_reported_as_such(agent):
    with snmp.Session("127.0.0.1", snmp.V3("easyeap", "authkey123", "wrongpriv12"), port=agent.port, timeout=0.3, retries=0) as s, \
            pytest.raises(snmp.SnmpAuthError) as e:
        s.get(["1.3.6.1.2.1.1.5.0"])
    assert "privacy key" in str(e.value)


def test_v3_forged_response_is_refused(agent):
    """A response whose HMAC doesn't verify is never believed."""
    real = agent.auth_key
    agent.auth_key = hashlib.sha256(b"someone else").digest()
    try:
        # The agent now rejects our digest too, so make it verify ours but sign with the wrong key.
        orig = agent._handle

        def forge(data):
            agent.auth_key = real
            try:
                top, _ = snmp.read(data)
                parts = snmp.children(top)
                sec_top, _ = snmp.read(data, parts[2].start, parts[2].end)
                if not snmp.children(sec_top)[0].value:
                    return orig(data)
                out = orig(data)
            finally:
                agent.auth_key = real
            return out[:-1] + bytes([out[-1] ^ 1])  # flip a bit in the encrypted payload after signing
        agent._handle = forge
        with snmp.Session("127.0.0.1", snmp.V3("easyeap", "authkey123", "privkey123"), port=agent.port, timeout=0.5, retries=0) as s, \
                pytest.raises(snmp.SnmpAuthError):
            s.get(["1.3.6.1.2.1.1.5.0"])
    finally:
        agent.auth_key = real


# ── Reading a switch ─────────────────────────────────────────────────────────


class FakeSession:
    """collect.poll's view of a switch: a dict of OID → value."""

    def __init__(self, table: dict[str, object], engine_id: bytes = b""):
        self.rows = sorted((snmp.oid(k), v) for k, v in table.items())
        self.engine_id = engine_id

    def get(self, oids):
        found = dict(self.rows)
        return {snmp.oid(o): found.get(snmp.oid(o), snmp.NoSuchObject) for o in oids}

    def walk(self, base, max_rows=20_000, truncate=False):
        root = snmp.oid(base)
        out = [(o, v) for o, v in self.rows if o[:len(root)] == root and len(o) > len(root)]
        if len(out) > max_rows:
            if not truncate:
                raise snmp.SnmpError("too many", "too_big")
            return out[:max_rows + 1]
        return out

    def first(self, base):
        rows = self.walk(base)
        return rows[0] if rows else None


def catalyst(sessions: list[tuple[int, str, str, int, dict]] | None = None, errdis: dict[int, int] | None = None, caf: bool = True,
             ports: dict[int, tuple[str, int, int]] | None = None, serial: str = "FOC1234X0AB") -> dict:
    """A Catalyst-like table. ports: ifIndex → (ifName, control, open); sessions: (ifIndex, session id, MAC hex, status, extra)."""
    t: dict[str, object] = {
        collect.SYS_DESCR: b"Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE",
        collect.SYS_OBJECT_ID: snmp.oid("1.3.6.1.4.1.9.1.2494"), collect.SYS_UPTIME: 123400, collect.SYS_NAME: b"lab-sw1",
        f"{collect.ENT_CLASS}.1": 3, f"{collect.ENT_CLASS}.1000": 3, f"{collect.ENT_CLASS}.1001": 10,
        f"{collect.ENT_SERIAL}.1": serial.encode(), f"{collect.ENT_MODEL}.1": b"C9300-48P",
        f"{collect.ENT_SERIAL}.1000": b"OTHER", collect.ERRDIS_INTERVAL: 300,
    }
    ports = ports if ports is not None else {8: ("Gi1/0/1", 2, 2), 9: ("Gi1/0/2", 2, 2), 10: ("Gi1/0/3", 3, 2), 60: ("Te1/1/1", 3, 2)}
    for idx, (name, control, open_) in ports.items():
        t[f"{collect.IF_TYPE}.{idx}"] = 6
        t[f"{collect.IF_NAME}.{idx}"] = name.encode()
        t[f"{collect.IF_ALIAS}.{idx}"] = b""
        t[f"{collect.IF_ADMIN}.{idx}"] = 1
        t[f"{collect.IF_OPER}.{idx}"] = 1
        if caf:
            t[f"{collect.CAF_PORT}.3.{idx}"] = 3
            t[f"{collect.CAF_PORT}.4.{idx}"] = open_
            t[f"{collect.CAF_PORT}.5.{idx}"] = control
    t[f"{collect.IF_TYPE}.200"] = 53  # a VLAN interface: not a port
    t[f"{collect.IF_NAME}.200"] = b"Vl1"
    if caf:
        t[f"{collect.CAF_REG}.1.2"] = 2
    for idx, sid, mac, status, extra in sessions or []:
        sub = ".".join(str(b) for b in sid.encode())
        t[f"{collect.CAF_SESSION}.2.{idx}.{sub}"] = bytes.fromhex(mac)
        t[f"{collect.CAF_SESSION}.5.{idx}.{sub}"] = status
        t[f"{collect.CAF_SESSION}.6.{idx}.{sub}"] = extra.get("domain", 2)
        t[f"{collect.CAF_SESSION}.10.{idx}.{sub}"] = extra.get("user", b"")
        t[f"{collect.CAF_SESSION}.12.{idx}.{sub}"] = extra.get("by", b"Authentication Server")
        t[f"{collect.CAF_SESSION}.13.{idx}.{sub}"] = extra.get("critical", 0)
        t[f"{collect.CAF_SESSION}.14.{idx}.{sub}"] = extra.get("vlan", 0)
        method = extra.get("method", 2)
        t[f"{collect.CAF_METHOD_STATE}.{idx}.{len(sid)}.{sub}.{method}"] = extra.get("state", 4)
        if method == 3:
            t[f"{collect.CAF_METHOD_STATE}.{idx}.{len(sid)}.{sub}.2"] = 3  # dot1x failed over to MAB
    for idx, cause in (errdis or {}).items():
        t[f"{collect.ERRDIS_CAUSE}.{idx}.0"] = cause
    return t


def test_poll_decodes_ports_sessions_and_methods():
    data = collect.poll(FakeSession(catalyst(
        sessions=[(8, "0A0B0C0D0000001200ABCDEF", "001122334455", 6, {"user": b"alice", "vlan": 20}),
                  (9, "0A0B0C0D0000001300ABCDEF", "66778899AABB", 6, {"method": 3, "domain": 3})],
        errdis={10: 2}), engine_id=b"\x80\x00\x1f\x88\x04x"))
    f = data["facts"]
    assert f["name"] == "lab-sw1" and f["version"] == "17.9.4a" and f["model"] == "C9300-48P" and f["serial"] == "FOC1234X0AB"
    assert f["uptime_s"] == 1234 and f["engine_id"] == "80001f880478"
    assert data["capabilities"] == {"caf": True, "errdisable": True}
    names = [p["name"] for p in data["ports"]]
    assert names == ["GigabitEthernet1/0/1", "GigabitEthernet1/0/2", "GigabitEthernet1/0/3", "TenGigabitEthernet1/1/1"]  # no Vlan1
    p3 = data["ports"][2]
    assert p3["auth"] == {"control": "force-authorized", "host_mode": "multi-auth", "open": False} and p3["err_disabled"] == "BPDU guard"
    s1, s2 = data["sessions"]
    assert s1 == {**s1, "port": "GigabitEthernet1/0/1", "mac": "001122334455", "authorized": True, "status": "authorized", "user": "alice",
                  "vlan": 20, "method": "dot1x", "domain": "data", "critical": False, "id": "0A0B0C0D0000001200ABCDEF"}
    assert s2["method"] == "mab" and s2["methods"] == {"dot1x": "failed-over", "mab": "success"} and s2["domain"] == "voice"


def test_poll_without_caf_reads_no_sessions():
    data = collect.poll(FakeSession(catalyst(caf=False)))
    assert data["capabilities"]["caf"] is False and data["sessions"] == []
    assert all(p["auth"] is None for p in data["ports"])


def test_canonical_port_names():
    assert canonical_port("Gi1/0/5") == "GigabitEthernet1/0/5"
    assert canonical_port("gigabitethernet1/0/5") == "GigabitEthernet1/0/5"
    assert canonical_port("Te1/1/1") == "TenGigabitEthernet1/1/1"
    assert canonical_port("Tw2/0/12") == "TwoGigabitEthernet2/0/12"
    assert canonical_port("Vl10") == "Vl10" and canonical_port("") == ""
    assert planned_ports({"interfaces": "GigabitEthernet1/0/1 - 3", "exclude": "GigabitEthernet1/0/2"}) == {"GigabitEthernet1/0/1", "GigabitEthernet1/0/3"}
    assert planned_ports({}) == set()


# ── Findings ─────────────────────────────────────────────────────────────────

NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)


def dx(mac: str) -> tuple[str, str]:
    return (mac, "dot1x")

PLAN = {"GigabitEthernet1/0/1", "GigabitEthernet1/0/2", "GigabitEthernet1/0/3"}
COVERED = {"GigabitEthernet1/0/1", "GigabitEthernet1/0/2"}  # the planned ports the default table covers


def state(sessions=(), ports=None, errdis=None, caf=True, serial="FOC1234X0AB"):
    return collect.poll(FakeSession(catalyst(sessions=list(sessions), ports=ports, errdis=errdis, caf=caf, serial=serial)))


def kinds(found):
    return sorted((f.kind, f.port, f.mac, f.severity) for f in found)


def test_port_rules_monitor_and_enforce():
    st = state(ports={8: ("Gi1/0/1", 2, 1), 9: ("Gi1/0/2", 2, 2), 10: ("Gi1/0/3", 3, 2)})
    mon, _ = evaluate(st, Context("monitor", PLAN, False))
    assert kinds(mon) == [("port_not_covered", "GigabitEthernet1/0/3", "", "warning")]  # open access is monitor mode working
    enf, _ = evaluate(st, Context("enforce", PLAN, False))
    assert kinds(enf) == [("open_access_in_enforce", "GigabitEthernet1/0/1", "", "critical"),
                          ("port_not_covered", "GigabitEthernet1/0/3", "", "critical")]


def test_a_port_not_on_the_switch_is_not_a_finding():
    found, _ = evaluate(state(), Context("enforce", {"GigabitEthernet3/0/1"}, False))
    assert found == []


def test_session_rules():
    sessions = [
        (8, "S1", "001122334455", 6, {"vlan": 20}),            # accepted by EasyEAP with VLAN 20: fine
        (8, "S2", "0011223344AA", 6, {}),                      # never seen by EasyEAP
        (8, "S3", "0011223344BB", 6, {}),                      # EasyEAP's latest answer is a reject
        (9, "S4", "0011223344CC", 6, {"vlan": 30}),            # accepted with VLAN 20, sits in 30
        (9, "S5", "0011223344DD", 6, {"method": 3}),           # MAB while EasyEAP has MAB off
        (9, "S6", "0011223344EE", 6, {"critical": 60, "by": b"Critical Auth"}),
        (9, "S7", "0011223344FF", 6, {}),                      # accepted, certificate revoked since
        (9, "S8", "001122334400", 5, {}),                      # failed: not authorized, never a finding
    ]
    acc = Seen("accept", NOW - timedelta(hours=1), vlan_id=20)
    ctx = Context("enforce", COVERED, False,
                  latest_accept={dx("001122334455"): acc, dx("0011223344CC"): acc, dx("0011223344FF"): acc,
                                 dx("0011223344BB"): Seen("accept", NOW - timedelta(days=2))},
                  latest_reject={dx("0011223344BB"): Seen("reject", NOW - timedelta(hours=2), reason_code="cert_revoked")},
                  denied_now={dx("0011223344FF"): "its certificate was revoked"})
    found, _ = evaluate(state(sessions), ctx)
    assert kinds(found) == [
        ("authorized_after_deny", "GigabitEthernet1/0/2", "0011223344FF", "warning"),
        ("authorized_despite_reject", "GigabitEthernet1/0/1", "0011223344BB", "critical"),
        ("authorized_without_easyeap", "GigabitEthernet1/0/1", "0011223344AA", "warning"),
        ("critical_auth", "GigabitEthernet1/0/2", "0011223344EE", "warning"),
        ("mab_not_expected", "GigabitEthernet1/0/2", "0011223344DD", "warning"),
        ("vlan_mismatch", "GigabitEthernet1/0/2", "0011223344CC", "warning"),
    ]
    assert next(f for f in found if f.kind == "vlan_mismatch").detail["sent"] == 20


def test_monitor_mode_skips_vlan_and_reject_rules():
    sessions = [(8, "S3", "0011223344BB", 6, {}), (9, "S4", "0011223344CC", 6, {"vlan": 30})]
    acc = Seen("accept", NOW - timedelta(hours=1), vlan_id=20)
    ctx = Context("monitor", COVERED, True, latest_accept={dx("0011223344CC"): acc},
                  latest_reject={dx("0011223344BB"): Seen("reject", NOW - timedelta(hours=2))})
    found, _ = evaluate(state(sessions), ctx)
    assert kinds(found) == [("authorized_without_easyeap", "GigabitEthernet1/0/1", "0011223344BB", "warning")]


def test_an_accept_after_the_reject_wins():
    sessions = [(8, "S3", "0011223344BB", 6, {})]
    ctx = Context("enforce", COVERED, False, latest_accept={dx("0011223344BB"): Seen("accept", NOW)},
                  latest_reject={dx("0011223344BB"): Seen("reject", NOW - timedelta(minutes=5))})
    assert evaluate(state(sessions), ctx)[0] == []


def test_mab_and_dot1x_answers_are_compared_separately():
    """A device admitted by MAB whose later 802.1X attempt was refused: the MAB session is the one EasyEAP accepted."""
    sessions = [(8, "S3", "0011223344BB", 6, {"method": 3, "vlan": 30})]
    ctx = Context("enforce", COVERED, True, latest_accept={("0011223344BB", "mab"): Seen("accept", NOW - timedelta(hours=1), vlan_id=30, method="mab")},
                  latest_reject={dx("0011223344BB"): Seen("reject", NOW - timedelta(minutes=5), method="eap-tls")},
                  denied_now={dx("0011223344BB"): "its certificate was revoked"})
    assert evaluate(state(sessions), ctx)[0] == []
    # The same answers against an 802.1X session: refused after the (MAB) accept, and nothing EasyEAP accepted by 802.1X.
    found, _ = evaluate(state([(8, "S3", "0011223344BB", 6, {})]), ctx)
    assert kinds(found) == [("authorized_despite_reject", "GigabitEthernet1/0/1", "0011223344BB", "critical")]
    assert findings.family("mab-eap") == "mab" and findings.family("eap-tls") == "dot1x" and findings.family(None) == "dot1x"


def test_err_disabled_and_capability_gating():
    found, evaluated = evaluate(state(errdis={10: 2, 60: 9}), Context("monitor", {"GigabitEthernet1/0/1", "GigabitEthernet1/0/2"}, False))
    # Gi1/0/3 (BPDU guard) isn't planned; Te1/1/1's security violation is reported on any port.
    assert kinds(found) == [("err_disabled", "TenGigabitEthernet1/1/1", "", "warning")]
    nocaf, evaluated = evaluate(state(caf=False), Context("enforce", PLAN, False))
    assert kinds(nocaf) == [("caf_missing", "", "", "warning")]
    assert "port_not_covered" not in evaluated and "err_disabled" in evaluated and "snmp_unreachable" in evaluated


def test_switch_changed():
    ctx = Context("monitor", set(), False, pinned={"serial": "FOC1234X0AB", "engine_id": "aa"}, version="v2c")
    assert evaluate(state(), ctx)[0] == []
    found, _ = evaluate(state(serial="FOC9999"), ctx)
    assert [(f.kind, f.detail) for f in found] == [("switch_changed", {"serial": {"was": "FOC1234X0AB", "now": "FOC9999"}})]


def test_failures():
    assert [f.kind for f in findings.failure("auth", "x")] == ["snmp_auth"]
    assert [f.kind for f in findings.failure("timeout", "x")] == ["snmp_unreachable"]
    assert set(findings.TEXT) == set(findings.KINDS)


# ── Hysteresis ───────────────────────────────────────────────────────────────


def row(kind="port_not_covered", port="Gi1", mac=""):
    return SimpleNamespace(kind=kind, port=port, mac=mac, seen_count=0, missing_count=0, opened_at=None, resolved_at=None, ack_hash=None,
                           acknowledged_at=None, acknowledged_by=None, ack_note=None, detail_hash="", severity="", detail={}, last_seen_at=None)


def run(rows, found, evaluated=None, now=NOW):
    evaluated = evaluated if evaluated is not None else set(findings.KINDS)
    added, gone = service.transition({(r.kind, r.port, r.mac): r for r in rows if r.resolved_at is None}, found, evaluated, now,
                                     lambda f: row(f.kind, f.port, f.mac))
    out = [r for r in rows if r not in gone] + added
    return out


def test_opens_after_two_polls_and_resolves_after_two():
    f = Found("port_not_covered", "warning", port="Gi1")
    rows = run([], [f])
    assert len(rows) == 1 and rows[0].opened_at is None  # seen once: not shown yet
    rows = run(rows, [f])
    assert rows[0].opened_at == NOW
    rows = run(rows, [])
    assert rows[0].resolved_at is None and rows[0].missing_count == 1
    rows = run(rows, [f])  # back again: the missing count restarts
    assert rows[0].missing_count == 0
    rows = run(run(rows, []), [])
    assert rows[0].resolved_at == NOW


def test_a_finding_seen_once_is_forgotten():
    rows = run([], [Found("vlan_mismatch", "warning", port="Gi1", mac="AA")])
    assert run(rows, []) == []


def test_snmp_failures_open_and_resolve_at_once():
    rows = run([], findings.failure("timeout", "no answer"), {"snmp_unreachable", "snmp_auth"})
    assert rows[0].opened_at == NOW
    rows = run(rows, [])
    assert rows[0].resolved_at == NOW


def test_unevaluated_kinds_are_left_alone():
    rows = run(run([], [Found("port_not_covered", "warning", port="Gi1")]), [Found("port_not_covered", "warning", port="Gi1")])
    rows = run(rows, findings.failure("timeout", "x"), {"snmp_unreachable", "snmp_auth"})
    pnc = next(r for r in rows if r.kind == "port_not_covered")
    assert pnc.resolved_at is None and pnc.missing_count == 0


def test_switch_changed_is_sticky_and_ack_resets_on_change():
    f = Found("switch_changed", "warning", detail={"serial": {"was": "A", "now": "B"}})
    rows = run([], [f])
    assert rows[0].opened_at == NOW
    rows = run(rows, [])
    assert rows[0].resolved_at is None  # only an acknowledgement closes it
    r = run([], [Found("authorized_without_easyeap", "warning", port="Gi1", mac="AA", detail={"vlan": 10})])[0]
    r.ack_hash, r.acknowledged_at = r.detail_hash, NOW
    run([r], [Found("authorized_without_easyeap", "warning", port="Gi1", mac="AA", detail={"vlan": 10})])
    assert r.acknowledged_at == NOW
    run([r], [Found("authorized_without_easyeap", "warning", port="Gi1", mac="AA", detail={"vlan": 30})])
    assert r.acknowledged_at is None  # its detail changed: shown again


# ── Settings and configuration ───────────────────────────────────────────────


def test_monitoring_settings_validation():
    ok = service.MonitoringIn(host=" 10.0.0.5 ")
    assert ok.host == "10.0.0.5" and ok.version == "v2c" and ok.interval_minutes == 15
    for bad in ("127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "switch.example.com", "10.0.0.0/24"):  # noqa: S104 — refused, never bound
        with pytest.raises(ValueError):
            service.MonitoringIn(host=bad)
    with pytest.raises(service.MonitoringError):
        service.MonitoringIn(host="10.0.0.5", version="v3", auth="sha", priv="aes256").check()
    with pytest.raises(ValueError):
        service.MonitoringIn(host="10.0.0.5", interval_minutes=1)


def test_default_host_only_for_a_single_address():
    assert service.default_host(SimpleNamespace(address="10.0.0.5")) == "10.0.0.5"
    assert service.default_host(SimpleNamespace(address="10.0.0.5/32")) == "10.0.0.5"
    assert service.default_host(SimpleNamespace(address="10.0.0.0/24")) == ""


def test_credentials_are_generated_fresh():
    a, b = service.new_credentials("v2c"), service.new_credentials("v2c")
    assert len(a["community"]) == 24 and a["community"].isalnum() and a != b
    v3 = service.new_credentials("v3")
    assert len(v3["auth_key"]) == 24 and len(v3["priv_key"]) == 24 and v3["auth_key"] != v3["priv_key"]


def test_config_block_v2c_and_v3_carry_no_secrets():
    v2 = service.config_block({"version": "v2c"}, "192.0.2.10")
    assert "ip access-list standard EASYEAP-SNMP\n permit host 192.0.2.10\n deny any" in v2
    assert "snmp-server community <community> view EASYEAP-RO RO EASYEAP-SNMP" in v2
    assert v2.count("snmp-server view EASYEAP-RO") == 6 and "1.3.6.1.4.1.9.9.656 included" in v2
    assert "logging" not in v2 and "aaa" not in v2
    v3 = service.config_block({"version": "v3", "user": "audit", "auth": "sha256", "priv": "aes256"}, "192.0.2.10")
    assert "snmp-server group EASYEAP v3 priv read EASYEAP-RO access EASYEAP-SNMP" in v3
    assert "snmp-server user audit EASYEAP v3 auth sha-2 256 <authentication key> priv aes 256 <privacy key>" in v3
    v6 = service.config_block({"version": "v2c"}, "2001:db8::10")
    assert "ipv6 access-list EASYEAP-SNMP6" in v6 and "RO ipv6 EASYEAP-SNMP6" in v6
    assert "IOS XE 17.10.1a" in v3  # sha-2 isn't on 3.x, 16.x or early 17.x
    # SHA-1 by default: the one every IOS-XE Catalyst has.
    assert service.MonitoringIn(host="192.0.2.10", version="v3").auth == "sha"
    assert "v3 auth sha <authentication key> priv aes 128 <privacy key>" in service.config_block({"version": "v3", "auth": "sha"}, "192.0.2.10")
    rm = service.removal_block({"version": "v3", "user": "audit"}, source="192.0.2.10")
    assert "no snmp-server user audit EASYEAP v3" in rm
    # Each subtree as it was added (17.12 and 17.15 accept only that), and only the ACL that was made.
    assert rm.count("no snmp-server view EASYEAP-RO 1.3.6.1.") == 6 and "no snmp-server view EASYEAP-RO\n" not in rm
    assert "no ip access-list standard EASYEAP-SNMP" in rm and "ipv6" not in rm
    assert "no ipv6 access-list EASYEAP-SNMP6" in service.removal_block({"version": "v2c"}, source="2001:db8::10")


def test_polled_sessions_for_readiness():
    st = SimpleNamespace(ok=True, last_ok_at=datetime.now(UTC), capabilities={"caf": True},
                         sessions=[{"port": "GigabitEthernet1/0/1", "mac": "001122334455", "method": "dot1x", "domain": "data", "status": "authorized", "authorized": True},
                                   {"port": "GigabitEthernet1/0/2", "mac": "001122334466", "method": "mab", "domain": "data", "status": "running", "authorized": False}])
    out = service.polled_sessions(st, 15)
    assert out["sessions"] == 2 and out["authorized"] == 1 and [r["interface"] for r in out["would_lose_access"]] == ["GigabitEthernet1/0/2"]
    st.last_ok_at = datetime.now(UTC) - timedelta(hours=2)
    assert service.polled_sessions(st, 15) is None  # stale: ask for the paste instead


def test_state_is_capped():
    big = {"facts": {}, "capabilities": {}, "ports": [], "sessions": [{"x": "y" * 1000}] * 3000, "truncated": False}
    out = service._fit(big)
    assert out["truncated"] and len(out["sessions"]) < 3000


# ── Critique fixes (docs/plans/switch-audit.md §12, revision 3) ──────────────


def test_v3_invalid_engine_boots_is_a_protocol_error():
    a = Agent(TABLE)
    a.boots = 1 << 32  # what `int.to_bytes(4)` can't hold: must surface as an SnmpError, not an OverflowError
    try:
        t = service.Target(uuid.uuid4(), uuid.uuid4(), "127.0.0.1", a.port, snmp.V3("easyeap", "authkey123", "privkey123"))
        res = service.run_poll(t, budget=3, probe_only=True, timeout=0.3, retries=0)
        assert res["ok"] is False and res["error_kind"] == "protocol" and "boots" in res["error"]
    finally:
        a.close()


def test_a_poll_ends_with_a_result_whatever_goes_wrong(agent, monkeypatch):
    def boom(_s):
        raise ValueError("unexpected index")
    monkeypatch.setattr(service.collect, "probe", boom)
    res = service.run_poll(service.Target(uuid.uuid4(), uuid.uuid4(), "127.0.0.1", agent.port, snmp.V2c("public")), budget=3, probe_only=True)
    assert res["ok"] is False and res["error_kind"] == "protocol" and "ValueError" in res["error"]


def test_v3_response_outside_the_time_window_is_ignored(agent):
    """An authentic response whose engine time is far behind ours is a replay: dropped, never believed."""
    agent.response_time_offset = -1000
    with snmp.Session("127.0.0.1", snmp.V3("easyeap", "authkey123", "privkey123"), port=agent.port, timeout=0.4, retries=0) as s, \
            pytest.raises(snmp.SnmpError):
        s.get(["1.3.6.1.2.1.1.5.0"])


def test_v3_response_without_encryption_is_refused(agent):
    agent.no_priv = True
    with snmp.Session("127.0.0.1", snmp.V3("easyeap", "authkey123", "privkey123"), port=agent.port, timeout=0.4, retries=0) as s, \
            pytest.raises(snmp.SnmpError) as e:
        s.get(["1.3.6.1.2.1.1.5.0"])
    assert "without encryption" in str(e.value)


def test_request_ids_are_independent(agent):
    with snmp.Session("127.0.0.1", snmp.V2c("public"), port=agent.port, timeout=1, retries=0) as s:
        ids = [s._next_id() for _ in range(50)]
    assert len(set(ids)) == 50 and sorted(ids) != ids  # not a counter


def test_secrets_stay_out_of_reprs():
    v2, v3 = snmp.V2c("community-secret"), snmp.V3("easyeap", "auth-secret-1", "priv-secret-1")
    t = service.Target(uuid.uuid4(), uuid.uuid4(), "192.0.2.10", 161, v3)
    text = repr(v2) + repr(v3) + repr(t) + repr(snmp.Session("192.0.2.10", v2))
    assert "secret" not in text


def test_identity_fields_are_pinned_one_by_one():
    assert service.pin_missing({}, {"serial": "FOC1", "engine_id": ""}) == {"serial": "FOC1", "engine_id": ""}
    # A switch moved from v2c to v3 keeps its serial and gains its engine ID.
    assert service.pin_missing({"serial": "FOC1", "engine_id": ""}, {"serial": "FOC1", "engine_id": "80001f88"}) == {"serial": "FOC1", "engine_id": "80001f88"}
    assert service.pin_missing({"serial": "FOC1", "engine_id": "aa"}, {"serial": "FOC2", "engine_id": "bb"}) == {"serial": "FOC1", "engine_id": "aa"}


def test_findings_past_a_cut_list_are_left_alone():
    pnc = row("port_not_covered", "GigabitEthernet1/0/9")
    wo = row("authorized_without_easyeap", "GigabitEthernet1/0/1", "0011223344AA")
    for r in (pnc, wo):
        r.opened_at, r.seen_count = NOW, 2
    result = {"ports": [{"name": "GigabitEthernet1/0/1"}], "sessions": [{"mac": "001122334455"}], "partial": {"ports": True, "sessions": True}}
    skip = service._past_the_cut(result)
    service.transition({(r.kind, r.port, r.mac): r for r in (pnc, wo)}, [], set(findings.KINDS), NOW, lambda f: None, skip)
    service.transition({(r.kind, r.port, r.mac): r for r in (pnc, wo)}, [], set(findings.KINDS), NOW, lambda f: None, skip)
    assert pnc.resolved_at is None and wo.resolved_at is None and pnc.missing_count == 0
    assert service._past_the_cut({"partial": {"ports": False, "sessions": False}}) is None


def test_poll_ignores_odd_indexes_and_cuts_sessions_short(monkeypatch):
    t = catalyst(sessions=[(8, "S1", "001122334455", 6, {}), (9, "S2", "0011223344AA", 6, {})])
    t[f"{collect.IF_NAME}.300.1"] = b"odd"  # an ifName row with a two-arc index
    monkeypatch.setattr(collect, "MAX_SESSIONS", 1)
    data = collect.poll(FakeSession(t))
    assert "odd" not in [p["short"] for p in data["ports"]]
    assert len(data["sessions"]) == 1 and data["partial"] == {"ports": False, "sessions": True} and data["truncated"]


def test_changing_the_address_needs_the_secrets_permission(monkeypatch):
    from fastapi import HTTPException

    from app import models as m
    from app.routers import switch_audit as r
    tid = uuid.uuid4()
    c = SimpleNamespace(id=uuid.uuid4(), tenant_id=tid, vendor="cisco-switch", name="sw1", snmp_secret_ct="vault:v1:x",
                        monitoring={"host": "192.0.2.10", "port": 161, "version": "v2c", "enabled": True, "interval_minutes": 15})
    ctx = SimpleNamespace(session=SimpleNamespace(get=lambda model, _k: c if model is m.RadiusClient else None), id=tid,
                          perms={"radius:read", "radius:write"}, actor=SimpleNamespace(label="Wi-Fi admin"))
    monkeypatch.setattr(r.audit, "record", lambda *a, **k: None)
    for change in ({"host": "198.51.100.7"}, {"port": 1161}):
        with pytest.raises(HTTPException) as e:
            r.update_monitoring(c.id, r.MonitoringUpdate(**change), ctx)
        assert e.value.status_code == 403
    assert r.update_monitoring(c.id, r.MonitoringUpdate(interval_minutes=30), ctx)["monitoring"]["interval_minutes"] == 30
    ctx.perms.add("radius:secrets")
    assert r.update_monitoring(c.id, r.MonitoringUpdate(host="198.51.100.7"), ctx)["monitoring"]["host"] == "198.51.100.7"
