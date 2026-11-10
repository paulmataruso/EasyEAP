"""The Windows setup as a program users double-click (enrollment/windows_exe.py): the launcher with the setup script
after it, from the portal (routers/enroll_public.py windows_program) and the console (routers/enrollments.py
_setup_file). The launcher itself runs on Windows; tests/windows/run.sh builds it and checks what it extracts."""
from __future__ import annotations

import base64
import hashlib
import struct
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.enrollment import windows_exe as wx
from app.routers import enroll_public as ep

PROGRAM = b"MZ\x90\x00" + bytes(range(256)) * 4   # stands in for the launcher: only the MZ matters here


def _cert(cn: str, key) -> str:
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture()
def launcher(tmp_path, monkeypatch):
    f = tmp_path / "EasyEAP-Setup.exe"
    f.write_bytes(PROGRAM)
    monkeypatch.setattr(wx, "LAUNCHER", f)
    return f


@pytest.mark.parametrize("script", [b"x", "﻿<# : batch\r\nWi-Fi 'Café'\r\n".encode(), bytes(range(256)) * 100])
def test_the_script_comes_back_byte_for_byte(launcher, script):
    exe = wx.wrap(script)
    assert exe.startswith(PROGRAM) and exe.endswith(wx.MAGIC)
    assert exe[len(PROGRAM) + len(script):-len(wx.MAGIC)] == struct.pack("<Q", len(script))
    assert wx.unwrap(exe) == script


def test_a_damaged_program_carries_no_script(launcher):
    exe = wx.wrap(b"Write-Host hi")
    assert wx.unwrap(PROGRAM) is None                                # the launcher alone
    assert wx.unwrap(exe[:-1]) is None                               # cut short
    assert wx.unwrap(exe[:5] + exe[-31:]) is None                    # length longer than what's there
    zero = PROGRAM + struct.pack("<Q", 0) + wx.MAGIC
    assert wx.unwrap(zero) is None
    huge = PROGRAM + struct.pack("<Q", wx.MAX_SCRIPT + 1) + wx.MAGIC
    assert wx.unwrap(huge) is None


def test_what_wrap_refuses(launcher, tmp_path):
    with pytest.raises(ValueError):
        wx.wrap(b"")
    with pytest.raises(ValueError):
        wx.wrap(b"x" * (wx.MAX_SCRIPT + 1))
    not_a_program = tmp_path / "x.exe"
    not_a_program.write_bytes(b"#!/bin/sh\n")
    with pytest.raises(ValueError):
        wx.wrap(b"x", not_a_program)


def test_available_and_names(launcher, tmp_path, monkeypatch):
    assert wx.available()
    monkeypatch.setattr(wx, "LAUNCHER", tmp_path / "missing.exe")
    assert not wx.available()
    assert wx.exe_name("EasyEAP-Setup-nina.cmd") == "EasyEAP-Setup-nina.exe"
    assert wx.exe_name("EasyEAP-Setup-j.doe.cmd") == "EasyEAP-Setup-j.doe.exe"
    assert wx.exe_name("setup") == "setup.exe"


def test_a_damaged_launcher_gives_the_script_instead_of_failing(tmp_path, monkeypatch):
    bad = tmp_path / "EasyEAP-Setup.exe"
    bad.write_bytes(b"not a program")
    monkeypatch.setattr(wx, "LAUNCHER", bad)
    assert wx.available() and wx.wrap_or_none(b"x") is None
    monkeypatch.setattr(wx, "LAUNCHER", tmp_path / "missing.exe")
    assert wx.wrap_or_none(b"x") is None


def test_wrap_or_none_wraps(launcher):
    assert wx.unwrap(wx.wrap_or_none(b"Write-Host hi")) == b"Write-Host hi"
    assert wx.wrap_or_none(b"") is None


# ── The portal ────────────────────────────────────────────────────────────


@pytest.fixture()
def link(monkeypatch, tmp_path):
    e = SimpleNamespace(method="link", template_id=None, status="pending")
    tenant = SimpleNamespace(id="t1", name="Café Corp", slug="corp")
    ident = SimpleNamespace(upn="nina@corp.example", username="nina", id="i1")
    root = _cert("Test Root", ec.generate_private_key(ec.SECP256R1()))
    key = ec.generate_private_key(ec.SECP256R1())
    tls = tmp_path / "proxy-tls.crt"
    tls.write_text(_cert("easyeap.example", key))
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    monkeypatch.setattr(ep, "PROXY_CERT", tls)
    monkeypatch.setattr(ep, "_load", lambda token, request, s, pending=False: (e, tenant, ident))
    monkeypatch.setattr(ep, "_net", lambda s, t: ("Caf\u00e9 Wi-Fi", "radius.corp.example", False))
    monkeypatch.setattr(ep.pki, "chain_pem", lambda s, t: (root, root))
    monkeypatch.setattr(ep, "get_settings", lambda: SimpleNamespace(public_url="https://easyeap.example"))
    return SimpleNamespace(e=e, s=SimpleNamespace(get=lambda *a: None), pin=base64.b64encode(hashlib.sha256(spki).digest()).decode())


def test_the_portal_program_carries_the_powershell_helper(link, launcher):
    script = ep.windows_script("tok-123", None, link.s)
    exe = ep.windows_program("tok-123", None, link.s)
    assert exe.media_type == "application/vnd.microsoft.portable-executable" and exe.headers["cache-control"] == "no-store"
    assert exe.headers["content-disposition"] == 'attachment; filename="EasyEAP-WiFi-Setup.exe"'
    inside = wx.unwrap(exe.body)
    assert inside == script.body                                     # the very same helper, BOM and all
    text = inside.decode("utf-8")
    assert text.startswith("﻿") and "Caf\u00e9 Wi-Fi" in text and "tok-123" in text
    assert f"$TlsPin = '{link.pin}'" in text


def test_the_portal_program_says_501_without_a_launcher(link, tmp_path, monkeypatch):
    """Not 404: the portal reads 404 as an unknown or used link. 501 sends it to the .ps1 instead."""
    monkeypatch.setattr(wx, "LAUNCHER", tmp_path / "missing.exe")
    with pytest.raises(ep.HTTPException) as exc:
        ep.windows_program("tok", None, link.s)
    assert exc.value.status_code == 501


def test_the_portal_program_says_501_with_a_damaged_launcher(link, tmp_path, monkeypatch):
    bad = tmp_path / "EasyEAP-Setup.exe"
    bad.write_bytes(b"#!/bin/sh\n")
    monkeypatch.setattr(wx, "LAUNCHER", bad)
    with pytest.raises(ep.HTTPException) as exc:
        ep.windows_program("tok", None, link.s)
    assert exc.value.status_code == 501


def test_the_portal_program_refuses_a_package_link_like_the_script(link, launcher):
    link.e.method = "server"
    for route in (ep.windows_script, ep.windows_program):
        with pytest.raises(ep.HTTPException) as exc:
            route("tok", None, link.s)
        assert exc.value.status_code == 400
