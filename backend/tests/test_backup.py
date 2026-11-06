"""Backup file format and the restore safety checks that don't need a running stack."""
from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from app.backup import engine
from app.backup.bundle import HEADER, PARTS, BundleError, BundleReader, BundleWriter, passphrase_problem, read_header

PASS = "correct-horse-battery-staple"


def _make(tmp_path: Path, passphrase: str = PASS, db: bytes = b"PGDMP" + bytes(range(256)) * 400) -> Path:
    w = BundleWriter(tmp_path / "work", passphrase)
    w.add_bytes("database.dump", db)
    w.add_bytes("pki.tar", b"pki-data")
    w.add_bytes("secrets.tar", b"secrets")
    w.add_bytes("manifest.json", json.dumps({"parts": dict(w.parts), "schema_revision": "x"}).encode())
    out = tmp_path / "b.easyeap"
    info = w.finish(out, {"product_version": "1.0.0", "created_at": "2026-11-06T00:00:00+00:00"})
    assert info["size"] == out.stat().st_size and len(info["sha256"]) == 64
    assert not (tmp_path / "work").exists(), "the work directory with encrypted parts is removed"
    return out


def test_round_trip_streams_and_verifies(tmp_path):
    db = bytes(range(256)) * 5000
    path = _make(tmp_path, db=db)
    header = read_header(path)
    assert header["format"] == "easyeap-backup" and header["product_version"] == "1.0.0"
    assert "tenants" not in json.dumps(header), "the plain header says nothing about the contents"
    with BundleReader(path) as r:
        mf = r.unlock(PASS)
        assert set(mf["parts"]) == {"database.dump", "pki.tar", "secrets.tar"}
        out = io.BytesIO()
        r.stream_to("database.dump", out)
        assert out.getvalue() == db
        assert r.read_bytes("pki.tar") == b"pki-data"
        r.verify("secrets.tar")


def test_wrong_passphrase_is_a_plain_error(tmp_path):
    path = _make(tmp_path)
    with BundleReader(path) as r, pytest.raises(BundleError, match="passphrase doesn't open"):
        r.unlock("not-the-passphrase")


def test_tampering_is_detected(tmp_path):
    path = _make(tmp_path)
    data = bytearray(path.read_bytes())
    with tarfile.open(path) as t:
        m = t.getmember("database.dump.age")
        offset = m.offset_data + m.size // 2
    data[offset] ^= 0x01
    path.write_bytes(bytes(data))
    with BundleReader(path) as r:
        r.unlock(PASS)
        with pytest.raises(BundleError, match="damaged"):
            r.verify("database.dump")


def test_checksum_mismatch_is_detected(tmp_path):
    w = BundleWriter(tmp_path / "work", PASS)
    for p in ("database.dump", "pki.tar", "secrets.tar"):
        w.add_bytes(p, p.encode())
    parts = dict(w.parts)
    parts["pki.tar"] = {"sha256": "0" * 64, "size": 7}
    w.add_bytes("manifest.json", json.dumps({"parts": parts}).encode())
    out = tmp_path / "b.easyeap"
    w.finish(out, {})
    with BundleReader(out) as r:
        r.unlock(PASS)
        with pytest.raises(BundleError, match="checksum"):
            r.read_bytes("pki.tar")


def test_layout_is_strict(tmp_path):
    good = _make(tmp_path)
    # Another tar entirely.
    other = tmp_path / "other.tar"
    with tarfile.open(other, "w") as t:
        info = tarfile.TarInfo("hello.txt")
        info.size = 2
        t.addfile(info, io.BytesIO(b"hi"))
    with pytest.raises(BundleError, match="isn't an EasyEAP backup"):
        read_header(other)
    # An extra member (or a link) is refused, so nothing unexpected is ever read.
    extra = tmp_path / "extra.easyeap"
    with tarfile.open(good) as src, tarfile.open(extra, "w") as dst:
        for m in src.getmembers():
            dst.addfile(m, src.extractfile(m))
        link = tarfile.TarInfo("evil")
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        dst.addfile(link)
    with pytest.raises(BundleError, match="unexpected layout"):
        read_header(extra)
    # Not a tar at all.
    junk = tmp_path / "junk.easyeap"
    junk.write_bytes(b"\x00" * 10 + b"nonsense" * 100)
    with pytest.raises(BundleError):
        read_header(junk)


def test_newer_format_is_refused(tmp_path):
    path = _make(tmp_path)
    rewritten = tmp_path / "newer.easyeap"
    with tarfile.open(path) as src, tarfile.open(rewritten, "w") as dst:
        for m in src.getmembers():
            if m.name == HEADER:
                data = json.dumps({"format": "easyeap-backup", "format_version": 99}).encode()
                m.size = len(data)
                dst.addfile(m, io.BytesIO(data))
            else:
                dst.addfile(m, src.extractfile(m))
    with pytest.raises(BundleError, match="newer version"):
        read_header(rewritten)


def test_passphrase_floor():
    assert passphrase_problem("short") is not None
    assert passphrase_problem("aaaaaaaaaaaaaaaa") is not None
    assert passphrase_problem(PASS) is None
    with pytest.raises(BundleError):
        BundleWriter(Path("/nonexistent/never-created"), "short")


def test_all_parts_required(tmp_path):
    w = BundleWriter(tmp_path / "work", PASS)
    w.add_bytes("database.dump", b"x")
    with pytest.raises(BundleError, match="missing"):
        w.finish(tmp_path / "x.easyeap", {})
    assert set(PARTS) == {"manifest.json", "secrets.tar", "pki.tar", "database.dump"}


def test_secrets_tar_only_known_files():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in (("openbao-api-token", b"tok"), ("../../etc/cron.d/x", b"evil"), ("openbao-init.json", b"{}")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    out = engine._parse_secrets(buf.getvalue())
    assert out == {"openbao-api-token": b"tok", "openbao-init.json": b"{}"}


def test_secrets_tar_without_token_is_refused():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w"):
        pass
    with pytest.raises(engine.RestoreError):
        engine._parse_secrets(buf.getvalue())


def test_maintenance_reads_the_state_file(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "state_file", lambda: tmp_path / "restore-state.json")
    assert engine.maintenance() is None
    engine._write_json(tmp_path / "restore-state.json", {"id": "a", "status": "running", "step": "database", "done": ["verify", "pki"]})
    st = engine.maintenance()
    assert st and st["step"] == "database"
    assert [s["done"] for s in st["steps"]][:3] == [True, True, False]
    assert "actor" not in st and "flags" not in st, "the public view leaves out who and how"
    engine._write_json(tmp_path / "restore-state.json", {"id": "a", "status": "done"})
    assert engine.maintenance() is None


def test_version_tuple():
    assert engine._version_tuple("2.4.1") == (2, 4, 1)
    assert engine._version_tuple("v2.5.0-beta") == (0, 5, 0) or engine._version_tuple("2.5.0-beta") == (2, 5, 0)
    assert engine._version_tuple(None) == (0,)
