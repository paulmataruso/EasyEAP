"""The kernel's own view of the clock: adjtimex(2) with modes 0 reads it and needs no privilege.

systemd (timedated's ntp_synced) calls the clock synchronised when the kernel's maximum error is under 16 seconds,
whichever daemon keeps it: chronyd, systemd-timesyncd or ntpd all update it, and the kernel grows it by 500 µs a second
when nobody does. EasyEAP uses the same test, so a host with another time daemon still reads as synchronised.
"""
from __future__ import annotations

import ctypes
import ctypes.util
from dataclasses import dataclass

SYNC_LIMIT_US = 16_000_000


class _Timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _Timex(ctypes.Structure):
    # struct timex (include/uapi/linux/timex.h), natural alignment as on every 64-bit Linux ABI
    _fields_ = [
        ("modes", ctypes.c_uint), ("offset", ctypes.c_long), ("freq", ctypes.c_long), ("maxerror", ctypes.c_long),
        ("esterror", ctypes.c_long), ("status", ctypes.c_int), ("constant", ctypes.c_long), ("precision", ctypes.c_long),
        ("tolerance", ctypes.c_long), ("time", _Timeval), ("tick", ctypes.c_long), ("ppsfreq", ctypes.c_long),
        ("jitter", ctypes.c_long), ("shift", ctypes.c_int), ("stabil", ctypes.c_long), ("jitcnt", ctypes.c_long),
        ("calcnt", ctypes.c_long), ("errcnt", ctypes.c_long), ("stbcnt", ctypes.c_long), ("tai", ctypes.c_int),
        ("_reserved", ctypes.c_int * 11),
    ]


@dataclass(frozen=True)
class KernelClock:
    maxerror: float   # seconds
    esterror: float   # seconds

    @property
    def synchronised(self) -> bool:
        return self.maxerror * 1e6 < SYNC_LIMIT_US


def read() -> KernelClock | None:
    """None where adjtimex isn't available (not Linux, or a sandbox that blocks it)."""
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        tx = _Timex()
        if libc.adjtimex(ctypes.byref(tx)) < 0:
            return None
    except (OSError, AttributeError):
        return None
    return KernelClock(tx.maxerror / 1e6, tx.esterror / 1e6)
