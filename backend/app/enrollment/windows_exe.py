"""The Windows setup as a program users double-click (backend/winlauncher/Launcher.cs).

The launcher is built once, with the API image; each download is the launcher followed by that user's setup script and
a trailer the launcher finds it by: [launcher][script][script length, 8 bytes little-endian][MAGIC]. The script is the
same .cmd setup file or portal helper as before, run the same way, so nothing about what it does changes.

It isn't code-signed: SmartScreen asks once (More info, then Run anyway) until a signing certificate is set up
(docs/windows-setup.md). Appended data would invalidate a signature, so signing will need the script carried another way.
"""
from __future__ import annotations

import logging
import os
import struct
from pathlib import Path

log = logging.getLogger(__name__)

MAGIC = b"EASYEAP-SETUP-PAYLOAD-1"
MAX_SCRIPT = 16 * 1024 * 1024  # the launcher refuses more
LAUNCHER = Path(os.environ.get("EASYEAP_WINDOWS_LAUNCHER", "/usr/local/share/easyeap/EasyEAP-Setup.exe"))


def available() -> bool:
    return LAUNCHER.is_file()


def wrap(script: bytes, launcher: Path | None = None) -> bytes:
    """The launcher carrying this script. Raises FileNotFoundError when the image has no launcher (a development stack
    built without it): callers then offer the script itself."""
    if not 0 < len(script) <= MAX_SCRIPT:
        raise ValueError("the setup script is empty or too large for the launcher")
    exe = (launcher or LAUNCHER).read_bytes()
    if exe[:2] != b"MZ":
        raise ValueError("the Windows launcher isn't a Windows program")
    return exe + script + struct.pack("<Q", len(script)) + MAGIC


def wrap_or_none(script: bytes) -> bytes | None:
    """wrap(), or None when this image has no usable launcher (none built, unreadable, damaged) or the script doesn't
    fit: callers then offer the script itself instead of failing the download."""
    if not available():
        return None
    try:
        return wrap(script)
    except (OSError, ValueError) as exc:
        log.warning("Windows setup program not made, offering the script instead: %s", exc)
        return None


def unwrap(exe: bytes) -> bytes | None:
    """The script a wrapped launcher carries, as the launcher reads it (tests)."""
    trailer = len(MAGIC) + 8
    if len(exe) < trailer or exe[-len(MAGIC):] != MAGIC:
        return None
    (length,) = struct.unpack("<Q", exe[-trailer:-len(MAGIC)])
    if not 0 < length <= min(MAX_SCRIPT, len(exe) - trailer):
        return None
    return exe[-(trailer + length):-trailer]


def exe_name(name: str) -> str:
    """EasyEAP-Setup-nina.cmd → EasyEAP-Setup-nina.exe."""
    stem = name.rsplit(".", 1)[0] if "." in name else name
    return stem + ".exe"
