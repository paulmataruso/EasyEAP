"""One NTP client exchange (SNTP, RFC 4330 and RFC 5905 §8): how far this server's clock is from a time server.

Used when the host has no chrony EasyEAP can manage: EasyEAP can't set the clock then, but it still measures it against
the servers configured in the console and warns when it drifts. The request's transmit timestamp is random: the reply
must echo it, which ties the reply to this request, and it tells the server nothing about this clock. The offset itself
uses this host's wall clock at send and receive.
"""
from __future__ import annotations

import os
import socket
import struct
import time
from dataclasses import dataclass

PORT = 123
NTP_EPOCH = 2_208_988_800  # 1900-01-01 to 1970-01-01, in seconds
_ERA = 1 << 32
_PACKET = struct.Struct("!BBbbII4sQQQQ")  # 48 bytes: RFC 5905 figure 8, without extensions or MAC


class SntpError(Exception):
    pass


@dataclass(frozen=True)
class Sample:
    address: str     # the address that answered
    offset: float    # seconds: positive when this host's clock is behind the server
    delay: float     # round trip, seconds
    stratum: int
    leap: int        # 0 none, 1 +1 s, 2 -1 s (3, unsynchronised, is refused)
    reference: str   # the server's reference ID: an IPv4 address, or a refclock code like "GPS"


def _ntp_to_unix(ts: int) -> float:
    secs, frac = ts >> 32, ts & 0xFFFFFFFF
    if secs < (1 << 31):  # era 1: 7 February 2036 onwards
        secs += _ERA
    return secs - NTP_EPOCH + frac / _ERA


def _reference(stratum: int, ref: bytes) -> str:
    if stratum <= 1:
        return ref.rstrip(b"\0").decode("ascii", "replace")
    return socket.inet_ntoa(ref) if any(ref) else ""


def request() -> tuple[bytes, int]:
    """A client request (LI 0, version 4, mode 3) and the cookie its reply must echo."""
    cookie = struct.unpack("!Q", os.urandom(8))[0] or 1
    return _PACKET.pack(0x23, 0, 0, 0, 0, 0, b"\0" * 4, 0, 0, 0, cookie), cookie


def parse(data: bytes, cookie: int, sent: float, received: float, address: str, rtt: float) -> Sample:
    """The reply as a Sample, or SntpError for anything a client must not use (RFC 4330 §5)."""
    if len(data) < _PACKET.size:
        raise SntpError("the reply is too short")
    first, stratum, _poll, _prec, _root_delay, _root_disp, ref, _reft, origin, rx, tx = _PACKET.unpack(data[:_PACKET.size])
    leap, version, mode = first >> 6, (first >> 3) & 7, first & 7
    if origin != cookie:
        raise SntpError("the reply doesn't answer this request")
    if mode != 4 or version not in (3, 4):
        raise SntpError("the reply isn't from an NTP server")
    if stratum == 0:
        code = ref.rstrip(b"\0").decode("ascii", "replace")
        raise SntpError(f"the server refused the request ({code or 'kiss-o’-death'})")
    if leap == 3 or stratum > 15:
        raise SntpError("the server isn't synchronised itself")
    if not tx or not rx:
        raise SntpError("the reply carries no time")
    t2, t3 = _ntp_to_unix(rx), _ntp_to_unix(tx)
    offset = ((t2 - sent) + (t3 - received)) / 2
    delay = max(0.0, rtt - (t3 - t2))
    return Sample(address, offset, delay, stratum, leap, _reference(stratum, ref))


def query(host: str, timeout: float = 2.0) -> Sample:
    """Ask `host` (a name or address) once, trying each address it resolves to until one answers."""
    try:
        infos = socket.getaddrinfo(host, PORT, type=socket.SOCK_DGRAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise SntpError(f"{host} couldn't be resolved") from exc
    last: Exception | None = None
    for family, kind, proto, _canon, sockaddr in infos[:4]:
        packet, cookie = request()
        try:
            with socket.socket(family, kind, proto) as sock:
                sock.settimeout(timeout)
                sock.connect(sockaddr)
                mono = time.monotonic()
                sent = time.time()
                sock.send(packet)
                data = sock.recv(512)
                received = time.time()
                rtt = time.monotonic() - mono
            return parse(data, cookie, sent, received, sockaddr[0], rtt)
        except TimeoutError as exc:
            last = SntpError(f"{sockaddr[0]} didn't answer within {timeout:g} seconds")
            last.__cause__ = exc
        except OSError as exc:
            last = SntpError(f"{sockaddr[0]}: {exc.strerror or exc}")
        except SntpError as exc:
            last = SntpError(f"{sockaddr[0]}: {exc}")
    raise last or SntpError(f"{host} has no address")
