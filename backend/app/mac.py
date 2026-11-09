"""MAC addresses: one canonical form (12 uppercase hex digits) for storage, lookups and the RADIUS snapshot.

Switches send MACs in many shapes: Cisco MAB's User-Name is `b496912267d1`, its Calling-Station-Id `B4-96-91-22-67-D1`,
UniFi sends `B496912267D1` without separators, and admins paste `b4:96:91:22:67:d1` or `b496.9122.67d1`. Everything is
normalised here, and the RADIUS renderer uses the same rules (services/radius/agent/render.py, MAC_RE).
"""
from __future__ import annotations

import re

_SEPARATED = re.compile(r"^[0-9A-Fa-f]{2}([-:])[0-9A-Fa-f]{2}(\1[0-9A-Fa-f]{2}){4}$")  # AA-BB-.. or aa:bb:..
_DOTTED = re.compile(r"^[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}$")             # aabb.ccdd.eeff (Cisco)
_BARE = re.compile(r"^[0-9A-Fa-f]{12}$")


class MacError(ValueError):
    pass


def normalize_mac(value: str) -> str:
    """`AABBCCDDEEFF` from any common notation, or MacError. Refuses group (multicast/broadcast) and all-zero addresses:
    no device authenticates with one, and an all-zero Calling-Station-Id is what some NASes send when they don't know."""
    v = (value or "").strip()
    if not (_SEPARATED.match(v) or _DOTTED.match(v) or _BARE.match(v)):
        raise MacError("Enter a MAC address such as AA:BB:CC:DD:EE:FF.")
    mac = re.sub(r"[^0-9A-Fa-f]", "", v).upper()
    if mac == "000000000000":
        raise MacError("00:00:00:00:00:00 isn't a device's address.")
    if int(mac[1], 16) & 1:
        raise MacError("That's a multicast or broadcast address, not a device's.")
    return mac


def try_mac(value: str | None) -> str | None:
    """The canonical MAC, or None when `value` isn't one (for log fields such as Calling-Station-Id)."""
    try:
        return normalize_mac(value or "")
    except MacError:
        return None


def format_mac(mac: str) -> str:
    """`AA:BB:CC:DD:EE:FF` for display."""
    return ":".join(mac[i:i + 2] for i in range(0, 12, 2))
