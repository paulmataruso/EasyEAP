#!/usr/bin/env python3
"""A TACACS+ client (RFC 8907) for EasyEAP's tests, written independently of services/radius/agent/tacacs.py.

It speaks like IOS: an SSH login sends START with the username and gets GETPASS; a telnet login sends START without
one and gets GETUSER first; PAP sends both in START. Prints one line: the statuses received, e.g. "GETPASS PASS".
Standard library only; runs on the lab client image's Python 3.10.

  tacacs_client.py --host H --port 4949 --key K login USER PASSWORD [--telnet] [--rem 10.0.0.9]
  tacacs_client.py ... enable USER PASSWORD [--priv 15]
  tacacs_client.py ... pap USER PASSWORD
  tacacs_client.py ... chap USER
  tacacs_client.py ... abort USER
  tacacs_client.py ... plain USER                    # the unencrypted flag: the server must drop the connection
  tacacs_client.py ... author USER [--cmd show --arg running-config]
  tacacs_client.py ... acct USER start|stop|watchdog [--cmd "configure terminal <cr>"]
"""
from __future__ import annotations

import argparse
import hashlib
import os
import socket
import struct
import sys

AUTHEN, AUTHOR, ACCT = 1, 2, 3
STATUS = {1: "PASS", 2: "FAIL", 3: "GETDATA", 4: "GETUSER", 5: "GETPASS", 6: "RESTART", 7: "ERROR", 0x21: "FOLLOW"}
AUTHOR_STATUS = {1: "PASS_ADD", 2: "PASS_REPL", 0x10: "FAIL", 0x11: "ERROR", 0x21: "FOLLOW"}
ACCT_STATUS = {1: "SUCCESS", 2: "ERROR", 0x21: "FOLLOW"}


def _pad(sid: int, key: bytes, ver: int, seq: int, n: int) -> bytes:
    out, prev = b"", b""
    while len(out) < n:
        prev = hashlib.md5(struct.pack("!I", sid) + key + bytes([ver, seq]) + prev).digest()  # noqa: S324 — the protocol's pad
        out += prev
    return out[:n]


class Client:
    def __init__(self, host: str, port: int, key: str, timeout: float = 10.0) -> None:
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.key = key.encode()
        self.sid = struct.unpack("!I", os.urandom(4))[0]
        self.seq = 1

    def send(self, ptype: int, body: bytes, minor: int = 0, flags: int = 0) -> None:
        ver = 0xC0 | minor
        data = body if flags & 0x01 else bytes(a ^ b for a, b in zip(body, _pad(self.sid, self.key, ver, self.seq, len(body)), strict=True))
        self.sock.sendall(struct.pack("!BBBBII", ver, ptype, self.seq, flags, self.sid, len(body)) + data)
        self.ver = ver

    def recv(self) -> bytes | None:
        head = self._exact(12)
        if head is None:
            return None
        ver, _t, seq, _f, sid, n = struct.unpack("!BBBBII", head)
        body = self._exact(n) or b""
        if seq != self.seq + 1 or sid != self.sid:
            raise RuntimeError(f"bad reply sequence {seq} (sent {self.seq})")
        self.seq += 2
        return bytes(a ^ b for a, b in zip(body, _pad(sid, self.key, ver, seq, n), strict=False))

    def _exact(self, n: int) -> bytes | None:
        buf = b""
        while len(buf) < n:
            try:
                chunk = self.sock.recv(n - len(buf))
            except (ConnectionResetError, TimeoutError):
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    def close(self) -> None:
        self.sock.close()


def start_body(user: str, data: bytes = b"", atype: int = 1, service: int = 1, priv: int = 1, port: str = "tty2",
               rem: str = "10.0.0.9") -> bytes:
    u, p, r = user.encode(), port.encode(), rem.encode()
    return struct.pack("!BBBBBBBB", 1, priv, atype, service, len(u), len(p), len(r), len(data)) + u + p + r + data


def continue_body(msg: str, abort: bool = False) -> bytes:
    m = msg.encode()
    return struct.pack("!HHB", len(m), 0, 1 if abort else 0) + m


def args_body(user: str, args: list[str], acct_flags: int | None = None, priv: int = 1, port: str = "tty2", rem: str = "10.0.0.9",
              method: int = 6) -> bytes:
    """method: authen_method, how the device authenticated the session (6 TACACS+, 5 local, 0 not set)."""
    u, p, r = user.encode(), port.encode(), rem.encode()
    a = [x.encode() for x in args]
    head = (bytes([acct_flags]) if acct_flags is not None else b"") + struct.pack("!BBBBBBBB", method, priv, 1, 1, len(u), len(p), len(r), len(a))
    return head + bytes(len(x) for x in a) + u + p + r + b"".join(a)


def authen_status(body: bytes) -> tuple[str, str]:
    status, _flags, ml, _dl = struct.unpack("!BBHH", body[:6])
    return STATUS.get(status, str(status)), body[6:6 + ml].decode("utf-8", "replace")


def login(c: Client, user: str, password: str, *, telnet: bool = False, service: int = 1, priv: int = 1, rem: str = "10.0.0.9") -> list[str]:
    seen = []
    c.send(AUTHEN, start_body("" if telnet else user, service=service, priv=priv, rem=rem))
    for _ in range(5):
        r = c.recv()
        if r is None:
            seen.append("CLOSED")
            return seen
        st, _msg = authen_status(r)
        seen.append(st)
        if st == "GETUSER":
            c.send(AUTHEN, continue_body(user))
        elif st in ("GETPASS", "GETDATA"):
            c.send(AUTHEN, continue_body(password))
        else:
            return seen
    return seen


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=4949)
    ap.add_argument("--key", required=True)
    ap.add_argument("--telnet", action="store_true")
    ap.add_argument("--priv", type=int, default=15)
    ap.add_argument("--rem", default="10.0.0.9")
    ap.add_argument("--cmd", default="")
    ap.add_argument("--method", type=int, default=6, help="authen_method for author: 6 TACACS+, 5 local")
    ap.add_argument("--arg", action="append", default=[])
    ap.add_argument("what")
    ap.add_argument("rest", nargs="*")
    a = ap.parse_args()
    try:
        c = Client(a.host, a.port, a.key)
    except OSError as exc:
        print(f"CONNECT-FAILED {exc}")
        return 1
    try:
        out = run(c, a)
    except OSError:
        out = ["CLOSED"]  # the server closed the connection before or while we wrote
    finally:
        c.close()
    if out is None:
        print(f"unknown command {a.what}")
        return 2
    print(" ".join(out))
    return 0


def run(c: Client, a: argparse.Namespace) -> list[str] | None:
    if a.what == "login":
        out = login(c, a.rest[0], a.rest[1] if len(a.rest) > 1 else "", telnet=a.telnet, rem=a.rem)
    elif a.what == "enable":
        out = login(c, a.rest[0], a.rest[1], service=2, priv=a.priv, rem=a.rem)
    elif a.what == "pap":
        c.send(AUTHEN, start_body(a.rest[0], a.rest[1].encode(), atype=2, rem=a.rem), minor=1)
        r = c.recv()
        out = [authen_status(r)[0] if r else "CLOSED"]
    elif a.what == "chap":
        c.send(AUTHEN, start_body(a.rest[0], os.urandom(17), atype=3, rem=a.rem), minor=1)
        r = c.recv()
        out = [authen_status(r)[0] if r else "CLOSED"]
    elif a.what == "abort":
        c.send(AUTHEN, start_body(a.rest[0], rem=a.rem))
        r = c.recv()
        out = [authen_status(r)[0] if r else "CLOSED"]
        c.send(AUTHEN, continue_body("user gave up", abort=True))
        out.append("REPLY" if c.recv() else "CLOSED")
    elif a.what == "plain":
        c.send(AUTHEN, start_body(a.rest[0], rem=a.rem), flags=0x01)
        out = ["REPLY" if c.recv() else "CLOSED"]
    elif a.what == "author":
        args = ["service=shell", f"cmd={a.cmd}" if a.cmd else "cmd*", *[f"cmd-arg={x}" for x in a.arg]]
        c.send(AUTHOR, args_body(a.rest[0], args, rem=a.rem, method=a.method))
        r = c.recv()
        if r is None:
            out = ["CLOSED"]
        else:
            st, n, ml, dl = struct.unpack("!BBHH", r[:6])
            lens = list(r[6:6 + n])
            pos = 6 + n + ml + dl
            pairs = []
            for ln in lens:
                pairs.append(r[pos:pos + ln].decode())
                pos += ln
            out = [AUTHOR_STATUS.get(st, str(st)), *pairs]
    elif a.what == "acct":
        flags = {"start": 0x02, "stop": 0x04, "watchdog": 0x08, "bad": 0x06}[a.rest[1]]
        args = ["task_id=42", "service=shell", f"priv-lvl={a.priv}", *([f"cmd={a.cmd}"] if a.cmd else [])]
        c.send(ACCT, args_body(a.rest[0], args, acct_flags=flags, rem=a.rem))
        r = c.recv()
        out = [ACCT_STATUS.get(r[4], str(r[4])) if r else "CLOSED"]
    else:
        return None
    return out


if __name__ == "__main__":
    sys.exit(main())
