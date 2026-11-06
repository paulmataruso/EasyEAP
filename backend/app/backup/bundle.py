"""The EasyEAP backup file (.easyeap): an uncompressed tar of separately encrypted parts.

    easyeap-backup.json   plain header: format, versions and creation time. No secrets, nothing about the tenants.
    key.age               a one-off X25519 age identity, encrypted with the backup passphrase (age scrypt recipient)
    manifest.json.age     what the backup holds, with the SHA-256 of every part
    secrets.tar.age       the API's OpenBao credentials (token, recovery keys)
    pki.tar.age           OpenBao storage and its seal key: every CA key, protected by the parts above
    database.dump.age     pg_dump custom-format archive

Every part is encrypted to the one-off identity with age (pyrage, a binding to the maintained rage implementation):
authenticated, streamed in 64 KiB chunks, so a damaged or altered file is detected and a multi-gigabyte database never
sits in memory. The passphrase only unlocks the identity. There is no EasyEAP-specific cryptography here.

By hand, without EasyEAP:  tar -xf backup.easyeap;  age -d key.age > id.txt  (enter the passphrase);
                           age -d -i id.txt database.dump.age > database.dump   (likewise for the other parts)
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import tarfile
import time
from pathlib import Path
from typing import IO, Any

import pyrage
from pyrage import passphrase as age_passphrase
from pyrage import x25519

FORMAT = "easyeap-backup"
FORMAT_VERSION = 1
HEADER = "easyeap-backup.json"
KEY = "key.age"
PARTS = ("manifest.json", "secrets.tar", "pki.tar", "database.dump")
MIN_PASSPHRASE = 12
_MAX_HEADER = 64 * 1024
_MAX_SMALL_PART = 64 * 1024 * 1024  # manifest and secrets are read into memory


class BundleError(Exception):
    """A problem with a backup file, phrased for the administrator."""


def passphrase_problem(p: str) -> str | None:
    if len(p) < MIN_PASSPHRASE:
        return f"Use a passphrase of at least {MIN_PASSPHRASE} characters."
    if len(set(p)) < 5:
        return "That passphrase is too repetitive. Use the generated one or a longer phrase."
    return None


class _HashReader:
    def __init__(self, raw: IO[bytes]):
        self.raw, self.h, self.n = raw, hashlib.sha256(), 0

    def read(self, size: int = -1) -> bytes:
        b = self.raw.read(size)
        self.h.update(b)
        self.n += len(b)
        return b


class _HashWriter:
    """Hashes what passes through and forwards it (to a file, a pipe, or nowhere)."""

    def __init__(self, raw: IO[bytes] | None = None):
        self.raw, self.h, self.n = raw, hashlib.sha256(), 0

    def write(self, b: bytes) -> int:
        self.h.update(b)
        self.n += len(b)
        if self.raw is not None:
            self.raw.write(b)
        return len(b)

    def flush(self) -> None:
        if self.raw is not None:
            self.raw.flush()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class BundleWriter:
    """Encrypts parts into `workdir` as they stream in, then packs them into one file."""

    def __init__(self, workdir: Path, passphrase: str):
        problem = passphrase_problem(passphrase)
        if problem:
            raise BundleError(problem)
        self.workdir = workdir
        workdir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._identity = x25519.Identity.generate()
        self._recipient = self._identity.to_public()
        (workdir / KEY).write_bytes(age_passphrase.encrypt(str(self._identity).encode(), passphrase))
        self.parts: dict[str, dict[str, Any]] = {}

    def add_stream(self, name: str, reader: IO[bytes]) -> dict[str, Any]:
        hr = _HashReader(reader)
        with open(self.workdir / f"{name}.age", "wb") as out:
            pyrage.encrypt_io(hr, out, [self._recipient])
        self.parts[name] = {"sha256": hr.h.hexdigest(), "size": hr.n}
        return self.parts[name]

    def add_bytes(self, name: str, data: bytes) -> dict[str, Any]:
        return self.add_stream(name, io.BytesIO(data))

    def add_file(self, name: str, path: Path) -> dict[str, Any]:
        with open(path, "rb") as f:
            return self.add_stream(name, f)

    def finish(self, out: Path, header: dict[str, Any]) -> dict[str, Any]:
        missing = [p for p in PARTS if p not in self.parts]
        if missing:
            raise BundleError(f"Internal error: the backup is missing {', '.join(missing)}.")
        tmp = out.with_name(out.name + ".partial")
        now = time.time()
        with tarfile.open(tmp, "w", format=tarfile.PAX_FORMAT) as t:
            data = json.dumps({"format": FORMAT, "format_version": FORMAT_VERSION, **header}, indent=2).encode()
            info = tarfile.TarInfo(HEADER)
            info.size, info.mode, info.mtime = len(data), 0o600, int(now)
            t.addfile(info, io.BytesIO(data))
            for name in (KEY, *(f"{p}.age" for p in PARTS)):
                info = t.gettarinfo(str(self.workdir / name), arcname=name)
                info.mode, info.uid, info.gid, info.uname, info.gname = 0o600, 0, 0, "", ""
                with open(self.workdir / name, "rb") as f:
                    t.addfile(info, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, out)
        shutil.rmtree(self.workdir, ignore_errors=True)
        return {"size": out.stat().st_size, "sha256": _sha256_file(out)}

    def abort(self) -> None:
        shutil.rmtree(self.workdir, ignore_errors=True)


def read_header(path: Path) -> dict[str, Any]:
    """Validate the outer layout and return the plain header. Raises BundleError for anything else."""
    try:
        with tarfile.open(path, "r:") as t:
            members = t.getmembers()
            names = [m.name for m in members]
            expected = {HEADER, KEY, *(f"{p}.age" for p in PARTS)}
            if HEADER not in names:
                raise BundleError("This isn't an EasyEAP backup file.")
            if len(names) != len(set(names)) or set(names) != expected or any(not m.isreg() for m in members):
                raise BundleError("This backup file has an unexpected layout. It may be damaged or from another product.")
            hm = t.getmember(HEADER)
            if hm.size > _MAX_HEADER:
                raise BundleError("This backup file has an unexpected layout.")
            header = json.loads(t.extractfile(hm).read())  # type: ignore[union-attr]
    except tarfile.TarError as exc:
        raise BundleError("This isn't an EasyEAP backup file (or it is incomplete).") from exc
    except (ValueError, UnicodeDecodeError) as exc:
        raise BundleError("This backup file's header is unreadable.") from exc
    if header.get("format") != FORMAT:
        raise BundleError("This isn't an EasyEAP backup file.")
    if int(header.get("format_version", 0)) > FORMAT_VERSION:
        raise BundleError("This backup was made by a newer version of EasyEAP. Update EasyEAP first, then restore it.")
    return header


class BundleReader:
    def __init__(self, path: Path):
        self.path = path
        self.header = read_header(path)
        self._tar = tarfile.open(path, "r:")
        self._identity: x25519.Identity | None = None
        self.manifest: dict[str, Any] = {}

    def close(self) -> None:
        self._tar.close()

    def __enter__(self) -> BundleReader:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _member(self, name: str) -> IO[bytes]:
        f = self._tar.extractfile(self._tar.getmember(name))
        if f is None:
            raise BundleError("This backup file has an unexpected layout.")
        return f

    def unlock(self, passphrase: str) -> dict[str, Any]:
        """Decrypt the identity and the manifest. Wrong passphrase → BundleError."""
        try:
            raw = age_passphrase.decrypt(self._member(KEY).read(_MAX_HEADER), passphrase)
            self._identity = x25519.Identity.from_str(raw.decode())
        except (pyrage.DecryptError, ValueError, UnicodeDecodeError) as exc:
            raise BundleError("That passphrase doesn't open this backup.") from exc
        out = io.BytesIO()
        self._decrypt("manifest.json", out, limit=_MAX_SMALL_PART)
        try:
            self.manifest = json.loads(out.getvalue())
        except ValueError as exc:
            raise BundleError("The backup's contents list is unreadable. The file may be damaged.") from exc
        if not isinstance(self.manifest.get("parts"), dict):
            raise BundleError("The backup's contents list is incomplete.")
        return self.manifest

    def _decrypt(self, part: str, writer: IO[bytes] | _HashWriter | Any, limit: int | None = None) -> _HashWriter:
        if self._identity is None:
            raise BundleError("Internal error: the backup is still locked.")
        member = self._tar.getmember(f"{part}.age")
        if limit is not None and member.size > limit + 4096:
            raise BundleError("This backup file has an unexpected layout.")
        hw = writer if isinstance(writer, _HashWriter) else _HashWriter(writer)
        try:
            pyrage.decrypt_io(self._member(f"{part}.age"), hw, [self._identity])
        except (pyrage.DecryptError, OSError) as exc:
            raise BundleError(f"The backup is damaged: its {_label(part)} can't be decrypted.") from exc
        return hw

    def _check(self, part: str, hw: _HashWriter) -> None:
        if part == "manifest.json":
            return
        want = (self.manifest.get("parts") or {}).get(part, {}).get("sha256")
        if not want or want != hw.h.hexdigest():
            raise BundleError(f"The backup is damaged: its {_label(part)} doesn't match its checksum.")

    def read_bytes(self, part: str) -> bytes:
        out = io.BytesIO()
        hw = self._decrypt(part, out, limit=_MAX_SMALL_PART)
        self._check(part, hw)
        return out.getvalue()

    def stream_to(self, part: str, writer: IO[bytes] | Any) -> None:
        """Decrypt a part into `writer` (a file or a pipe) and verify its checksum. The writer has already received the
        data when a checksum mismatch is raised, so callers verify() first before doing anything irreversible."""
        hw = self._decrypt(part, _HashWriter(writer))
        self._check(part, hw)

    def verify(self, part: str) -> None:
        self.stream_to(part, None)


def _label(part: str) -> str:
    return {"manifest.json": "contents list", "secrets.tar": "PKI credentials", "pki.tar": "certificate authority data",
            "database.dump": "database"}.get(part, part)
