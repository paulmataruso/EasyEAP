"""The Windows setup program (backend/winlauncher, enrollment/windows_exe.py) without Windows: run.sh builds the
launcher with the API image's compiler, `wrap` puts the generated setup file and portal helper inside it and checks it
is a Windows console program for any CPU that runs as the user, run.sh runs each under Mono with the extract hook, and
`check` compares what came out with what went in, byte for byte."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

from app.enrollment import windows_exe

OUT = Path(sys.argv[2] if len(sys.argv) > 2 else "/out")
CASES = {"full": "full.cmd", "helper": "helper.ps1"}


def _pe(exe: bytes) -> dict:
    pe = struct.unpack_from("<I", exe, 0x3C)[0]
    assert exe[pe:pe + 4] == b"PE\0\0", "no PE header"
    sections, opt_size = struct.unpack_from("<H", exe, pe + 6)[0], struct.unpack_from("<H", exe, pe + 20)[0]
    opt = pe + 24
    magic, subsystem = struct.unpack_from("<H", exe, opt)[0], struct.unpack_from("<H", exe, opt + 68)[0]
    assert magic == 0x10B, "not PE32"
    clr_rva = struct.unpack_from("<I", exe, opt + 96 + 14 * 8)[0]
    for i in range(sections):
        _, vsize, va, raw_size, raw = struct.unpack_from("<8sIIII", exe, opt + opt_size + 40 * i)
        if va <= clr_rva < va + max(vsize, raw_size):
            flags = struct.unpack_from("<I", exe, raw + clr_rva - va + 16)[0]
            return {"subsystem": subsystem, "cor_flags": flags}
    raise AssertionError("no .NET header")


def wrap() -> None:
    launcher = OUT / "launcher.exe"
    pe = _pe(launcher.read_bytes())
    # 3: console (the setup's own window). ILONLY without 32BITREQUIRED/32BITPREFERRED: 64-bit on x64 and ARM64, so
    # it starts the 64-bit Windows PowerShell and sees the real System32.
    good = pe["subsystem"] == 3 and pe["cor_flags"] & 0x1 and not pe["cor_flags"] & (0x2 | 0x20000)
    good = good and b"asInvoker" in launcher.read_bytes()
    print(f"  {'PASS' if good else 'FAIL'} launcher: {launcher.stat().st_size} bytes, subsystem {pe['subsystem']}, "
          f"COR flags {pe['cor_flags']:#x}, asInvoker manifest={b'asInvoker' in launcher.read_bytes()}")
    for case, src in CASES.items():
        script = (OUT / src).read_bytes()
        if case == "helper":
            script = "﻿".encode() + script   # as the portal serves it
        (OUT / f"{case}.in").write_bytes(script)
        (OUT / f"{case}.exe").write_bytes(windows_exe.wrap(script, launcher))
    sys.exit(0 if good else 1)


def check() -> None:
    bad = 0
    for case in CASES:
        want, got = (OUT / f"{case}.in").read_bytes(), OUT / f"{case}.extracted"
        good = got.is_file() and got.read_bytes() == want
        bad += not good
        print(f"  {'PASS' if good else 'FAIL'} {case}.exe gives back its script ({len(want)} bytes)")
    sys.exit(bad)


if __name__ == "__main__":
    {"wrap": wrap, "check": check}[sys.argv[1]]()
