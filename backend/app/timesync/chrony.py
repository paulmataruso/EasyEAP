"""chronyc's CSV reports (chronyc -c -n), parsed into plain dicts for the console.

Field order is chronyc's own (client.c in chrony 4.x; checked against chrony 4.8's output): tracking prints 14 fields,
sources 10, selectdata 18. Signs follow chronyc's text output: tracking's "System time" field is the correction chronyd
is still applying, so a negative value means this clock is fast; the console shows `offset` the other way round
(positive: this clock is ahead of true time), which is what "fast" and "slow" mean to a reader.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

CHRONYC = "chronyc"
SOCKET = Path("/run/chrony/chronyd.sock")
TIMEOUT = 10
NEVER = "4294967295"   # chronyc's LastRx (and authdata's last key exchange) for "never"

LEAP = {"Normal": "normal", "Insert second": "insert", "Delete second": "delete", "Not synchronised": "unsynchronised"}
MODES = {"^": "server", "=": "peer", "#": "refclock"}
# chronyc sources' state column
STATES = {"*": "selected", "+": "combined", "-": "not_combined", "?": "unusable", "x": "falseticker", "~": "jittery"}
# chronyc selectdata's state column (chronyc help: "selectdata -v")
SELECT = {
    "N": "noselect", "s": "unsynchronised", "M": "missing_samples", "d": "large_distance", "D": "large_distance",
    "~": "jittery", "w": "waits_for_others", "W": "waits_for_others", "S": "stale", "O": "orphan", "T": "not_trusted",
    "P": "not_preferred", "U": "waits_for_update", "x": "falseticker", "+": "combined", "*": "best",
}


class ChronyError(Exception):
    pass


def _rows(text: str) -> list[list[str]]:
    return [r for r in csv.reader(io.StringIO(text)) if r]


def _float(v: str) -> float | None:
    try:
        return float(v)
    except ValueError:
        return None


def _int(v: str) -> int | None:
    try:
        return int(v)
    except ValueError:
        return None


def parse_tracking(text: str) -> dict[str, Any]:
    rows = _rows(text)
    if not rows or len(rows[0]) < 14:
        raise ChronyError("chronyc tracking printed something unexpected")
    r = rows[0]
    ref_time = _float(r[3])
    leap = LEAP.get(r[13], r[13].lower())
    correction = _float(r[4])
    stratum = _int(r[2]) or 0
    return {
        "reference_id": r[0],
        "reference": r[1] if r[1] not in ("", "0.0.0.0") else None,  # noqa: S104 — chronyc's "no reference"
        "stratum": stratum,
        "reference_time": datetime.fromtimestamp(ref_time, UTC).isoformat() if ref_time else None,
        "offset": -correction if correction is not None else None,   # positive: this clock is ahead
        "last_offset": _float(r[5]),
        "rms_offset": _float(r[6]),
        "frequency_ppm": _float(r[7]),
        "skew_ppm": _float(r[9]),
        "root_delay": _float(r[10]),
        "root_dispersion": _float(r[11]),
        "update_interval": _float(r[12]),
        "leap": leap,
        # chronyd reports stratum 0 (and "Not synchronised") until it has selected a source.
        "synchronised": leap != "unsynchronised" and 0 < stratum < 16 and bool(ref_time),
    }


def parse_sources(text: str) -> list[dict[str, Any]]:
    out = []
    for r in _rows(text):
        if len(r) < 10:
            continue
        reach = _int_base(r[5], 8)
        out.append({
            "mode": MODES.get(r[0], r[0]),
            "state": STATES.get(r[1], r[1]),
            "address": r[2],
            "stratum": _int(r[3]),
            "poll": _int(r[4]),
            "reach": reach,
            "reachable": bool(reach),
            "last_rx": None if r[6] == NEVER else _int(r[6]),   # seconds since the last good sample
            "offset": _float(r[7]),           # positive: this clock is ahead of the source (chronyc(1), sources)
            "measured_offset": _float(r[8]),
            "error": _float(r[9]),
        })
    return out


def _int_base(v: str, base: int) -> int:
    try:
        return int(v, base)
    except ValueError:
        return 0


def parse_selectdata(text: str) -> dict[str, dict[str, Any]]:
    """Address → why chronyd does or doesn't use the source, and its options as configured and as in effect."""
    out: dict[str, dict[str, Any]] = {}
    for r in _rows(text):
        if len(r) < 18:
            continue
        configured = "".join(r[3:8])
        effective = "".join(r[8:13])
        out[r[1]] = {
            "select": SELECT.get(r[0], r[0]),
            "authenticated": r[2] == "Y",
            "noselect": "N" in effective,
            "prefer": "P" in effective,
            "configured_noselect": "N" in configured,
        }
    return out


def parse_authdata(text: str) -> dict[str, str]:
    """Address → how its packets are authenticated: "NTS", "SK" (symmetric key) or "" (not at all)."""
    return {r[0]: ("" if r[1] == "-" else r[1]) for r in _rows(text) if len(r) >= 2}


def run(*args: str, named: bool = False, timeout: float = TIMEOUT) -> str:
    """One chronyc command over chronyd's Unix socket: -h with the socket's path, the only way chronyd accepts commands
    that change it, and no fallback to UDP (which in a container would be the container itself). -c: CSV. -n: addresses
    not names, or with `named` -N: each source's name as configured (a pool's name for each of its servers)."""
    cmd = [CHRONYC, "-h", str(SOCKET), "-N" if named else "-n", "-c", *args]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603 — argv list, no shell
    except FileNotFoundError as exc:
        raise ChronyError("chronyc isn't installed in this image") from exc
    except subprocess.TimeoutExpired as exc:
        raise ChronyError(f"chronyd didn't answer {' '.join(args)} within {timeout:g} seconds") from exc
    if p.returncode != 0:
        raise ChronyError(_explain((p.stderr or "").strip() or (p.stdout or "").strip() or f"chronyc exited with {p.returncode}"))
    return p.stdout


def _explain(msg: str) -> str:
    msg = msg.splitlines()[0] if msg else msg
    if "Could not open connection" in msg or "Connection refused" in msg or "No such file" in msg or "506 " in msg:
        return "chronyd isn't answering on its control socket (is it running on the host?)"
    if "Permission denied" in msg or "Could not create" in msg:
        return "the time service can't use chronyd's control socket (permission denied)"
    if "501 " in msg:
        return "chronyd refused the command (not authorised)"
    return msg[:200]


def available() -> bool:
    return SOCKET.exists()


def is_address(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False

