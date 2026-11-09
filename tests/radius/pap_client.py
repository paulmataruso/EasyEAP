"""A PAP Access-Request built by hand, for tests/radius/run.sh: what Nexus and Meraki send for MAC authentication (no
Service-Type Call-Check), with or without Message-Authenticator and Proxy-State. radclient always adds
Message-Authenticator, so it can't send these. Stdlib only; runs in the lab client image (python3 - < this file).

    python3 - SERVER SECRET USER PASSWORD [--service N] [--port-type N] [--csid MAC] [--ma] [--proxy-state]

Prints "accept <vlan|none> <session-timeout|->", "reject" or "none" (no answer).
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import socket
import struct


def attr(t: int, v: bytes) -> bytes:
    return struct.pack("BB", t, len(v) + 2) + v


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("server")
    ap.add_argument("secret")
    ap.add_argument("user")
    ap.add_argument("password")
    ap.add_argument("--service", type=int)
    ap.add_argument("--port-type", type=int, default=15, help="NAS-Port-Type; -1 leaves it out")
    ap.add_argument("--csid")
    ap.add_argument("--ma", action="store_true")
    ap.add_argument("--proxy-state", action="store_true")
    a = ap.parse_args()
    secret = a.secret.encode()
    auth = os.urandom(16)
    pw = a.password.encode().ljust(16, b"\0")
    enc = bytes(x ^ y for x, y in zip(pw, hashlib.md5(secret + auth).digest(), strict=True))  # noqa: S324 — RADIUS PAP
    attrs = attr(1, a.user.encode()) + attr(2, enc) + attr(5, struct.pack("!I", 50107))
    if a.port_type >= 0:
        attrs += attr(61, struct.pack("!I", a.port_type))
    if a.service is not None:
        attrs += attr(6, struct.pack("!I", a.service))
    if a.csid:
        attrs += attr(31, a.csid.encode())
    if a.proxy_state:
        attrs += attr(33, b"proxied-by-someone")
    ma_at = None
    if a.ma:
        ma_at = 20 + len(attrs)
        attrs += attr(80, b"\0" * 16)
    pkt = bytearray(struct.pack("!BBH", 1, 91, 20 + len(attrs)) + auth + attrs)
    if ma_at is not None:
        pkt[ma_at + 2:ma_at + 18] = hmac.new(secret, bytes(pkt), "md5").digest()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(bytes(pkt), (a.server, 1812))
    try:
        reply = s.recv(4096)
    except TimeoutError:
        print("none")
        return
    if reply[0] != 2:
        print("reject")
        return
    vlan, st, i = "none", "-", 20
    while i + 2 <= len(reply):
        t, ln = reply[i], reply[i + 1]
        if ln < 2:
            break
        v = reply[i + 2:i + ln]
        if t == 81:
            vlan = (v[1:] if v and v[0] < 0x20 else v).decode(errors="replace") or "none"
        elif t == 27 and len(v) == 4:
            st = str(struct.unpack("!I", v)[0])
        i += ln
    print(f"accept {vlan} {st}")


main()
