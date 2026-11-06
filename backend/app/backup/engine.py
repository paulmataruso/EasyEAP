"""Full backup and restore, driven from the console (or `easyeap backup …`).

Backup: renew the PKI token, stream `pg_dump` through age into the work directory, ask the PKI supervisor for a copy
of OpenBao's storage and seal key (OpenBao pauses for a few seconds; RADIUS is unaffected), add the API's OpenBao
credentials and a manifest, and pack it all into one .easyeap file (see bundle.py). The database is dumped before the
PKI is copied, so a certificate issued in between can only exist in the PKI without a database row, which RADIUS
treats as unknown; never the reverse.

Restore: everything is checked before anything changes, then each step is recorded in restore-state.json so that a
failure, or an API restart in the middle, rolls back to exactly what was there before:

  verify    decrypt every part and compare it with the manifest's checksums
  pki       the supervisor installs the backup's OpenBao storage and seal key (keeping the current ones)
  database  the current database is renamed aside, a new one is created and pg_restore'd from the decrypting stream
  migrate   alembic upgrade head (backups from older versions)
  secrets   the backup's OpenBao credentials replace the current ones (kept aside)
  access    the PKI token is checked; if it expired while the backup sat on a shelf, the recovery keys mint a new one
  finish    audit chain check, RADIUS versions moved past anything an agent could hold, sessions cleared, decisions
            recomputed; then commit: drop the old database and the PKI rollback copy

While a restore runs the API answers 503 with its progress, the worker pauses and RADIUS keeps authenticating from
its local data.
"""
from __future__ import annotations

import base64
import io
import json
import logging
import os
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import psycopg
from psycopg import sql
from sqlalchemy import func, select, text
from sqlalchemy.engine import make_url

from app import __version__, audit
from app import models as m
from app.backup import pkictl
from app.backup.bundle import PARTS, BundleError, BundleReader, BundleWriter, passphrase_problem, read_header
from app.config import get_settings
from app.db import platform_session, reset_engine
from app.security.redact import redact

log = logging.getLogger("easyeap.backup")
_lock = threading.Lock()  # one backup or restore at a time in this process
SECRET_FILES = ("openbao-api-token", "openbao-init.json")
RESTORE_STEPS = [
    ("verify", "Checking the backup"),
    ("pki", "Restoring the certificate authorities"),
    ("database", "Restoring the database"),
    ("migrate", "Updating the database schema"),
    ("secrets", "Restoring PKI credentials"),
    ("access", "Checking PKI access"),
    ("finish", "Finishing up"),
]
BACKUP_STEPS = [
    ("prepare", "Preparing"),
    ("database", "Exporting the database"),
    ("pki", "Copying the certificate authorities"),
    ("package", "Encrypting and packaging"),
]
MAX_UPLOAD = 64 * 1024**3


class RestoreError(Exception):
    """A restore problem, phrased for the administrator."""


# ── Paths and small helpers ──────────────────────────────────────────────────

def backups_dir() -> Path:
    d = Path(get_settings().backup_dir)
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d


def secrets_dir() -> Path:
    return Path(get_settings().openbao_init_file).parent


def state_file() -> Path:
    return secrets_dir() / "restore-state.json"


def _now() -> datetime:
    return datetime.now(UTC)


def _write_json(path: Path, data: dict[str, Any]) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2, default=str)
    os.replace(tmp, path)


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, ValueError):
        return None


def _valid_id(value: str) -> bool:
    return 8 <= len(value) <= 64 and all(c in "0123456789abcdef" for c in value)


def _tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise RestoreError(f"{name} is not installed in the API image.")
    return path


def _owner_url() -> Any:
    return make_url(get_settings().database_owner_url)


def _pg_env() -> dict[str, str]:
    u = _owner_url()
    return {**os.environ, "PGPASSWORD": get_settings().db_owner_password, "PGHOST": u.host or "localhost",
            "PGPORT": str(u.port or 5432), "PGUSER": u.username or "easyeap", "PGCONNECT_TIMEOUT": "10"}


def _db_name() -> str:
    return _owner_url().database or "easyeap"


def _admin_conn() -> psycopg.Connection:
    """Owner connection to the maintenance database, for renaming/creating the EasyEAP database."""
    u = _owner_url()
    return psycopg.connect(host=u.host, port=u.port or 5432, user=u.username, password=get_settings().db_owner_password,
                           dbname="postgres", autocommit=True, connect_timeout=10)


# ── Maintenance state ────────────────────────────────────────────────────────

def recovery_keys_present() -> bool:
    init = _read_json(Path(get_settings().openbao_init_file)) or {}
    return bool(init.get("recovery_keys_b64"))


def restore_state() -> dict[str, Any] | None:
    return _read_json(state_file())


_maint_cache: tuple[float, dict[str, Any] | None] = (-1.0, None)


def maintenance() -> dict[str, Any] | None:
    """Progress of the restore that is running right now (in any process), else None. Called on every API request:
    one stat, and the file is parsed only when it changes."""
    global _maint_cache
    try:
        mtime = state_file().stat().st_mtime
    except FileNotFoundError:
        return None
    if mtime != _maint_cache[0]:
        st = _read_json(state_file())
        _maint_cache = (mtime, public_state(st) if st and st.get("status") in ("running", "rolling_back") else None)
    return _maint_cache[1]


def public_state(st: dict[str, Any]) -> dict[str, Any]:
    """What anyone may see about a restore (shown on the maintenance page before sign-in)."""
    steps = [{"key": k, "label": label, "done": k in st.get("done", []), "current": st.get("step") == k} for k, label in RESTORE_STEPS]
    return {"id": st.get("id"), "status": st.get("status"), "step": st.get("step"), "steps": steps, "error": st.get("error"),
            "started_at": st.get("started_at"), "finished_at": st.get("finished_at"), "source": st.get("source"),
            "backup_created_at": (st.get("backup") or {}).get("created_at"), "warnings": st.get("warnings", [])}


def _save_state(st: dict[str, Any]) -> None:
    _write_json(state_file(), st)


# ── Backup records ───────────────────────────────────────────────────────────

def _record_path(rid: str) -> Path:
    return backups_dir() / f"{rid}.json"


def _file_path(rid: str) -> Path:
    return backups_dir() / f"{rid}.easyeap"


def purge_expired() -> None:
    """Server copies are temporary: the backup belongs off this host. Also clears abandoned uploads and work dirs."""
    now = _now()
    d = backups_dir()
    for rec_path in d.glob("*.json"):
        rec = _read_json(rec_path) or {}
        exp = rec.get("expires_at")
        stale_running = rec.get("status") == "running" and not _alive(rec)
        if (exp and datetime.fromisoformat(exp) < now) or stale_running:
            rid = rec_path.stem
            if stale_running:
                rec.update(status="failed", error="Interrupted: the API restarted while the backup was being made.",
                           expires_at=(now + timedelta(hours=get_settings().backup_retention_hours)).isoformat())
                _write_json(rec_path, rec)
                shutil.rmtree(d / f".work-{rid}", ignore_errors=True)
                _file_path(rid).with_name(_file_path(rid).name + ".partial").unlink(missing_ok=True)
                continue
            _file_path(rid).unlink(missing_ok=True)
            rec_path.unlink(missing_ok=True)
    running = {p.stem for p in d.glob("*.json") if (_read_json(p) or {}).get("status") == "running"}
    for work in d.glob(".work-*"):
        if work.name.removeprefix(".work-") not in running:
            shutil.rmtree(work, ignore_errors=True)
    for partial in d.glob("*.partial"):
        if partial.name.split(".")[0] not in running and time.time() - partial.stat().st_mtime > 6 * 3600:
            partial.unlink(missing_ok=True)


def _alive(rec: dict[str, Any]) -> bool:
    """A running backup belongs to a live process in this container (the API, or `easyeap backup` via exec)."""
    if rec.get("host") != socket.gethostname():
        return False
    try:
        os.kill(int(rec.get("pid") or 0), 0)
        return int(rec.get("pid") or 0) > 0
    except (OSError, ValueError):
        return False


def public_record(rec: dict[str, Any]) -> dict[str, Any]:
    keys = ("id", "kind", "status", "step", "steps", "error", "created_at", "finished_at", "created_by", "file_name", "size",
            "sha256", "expires_at", "downloaded_at", "downloads", "summary", "pki_access")
    return {k: rec.get(k) for k in keys if k in rec}


def list_backups() -> list[dict[str, Any]]:
    purge_expired()
    out = [_read_json(p) for p in backups_dir().glob("*.json")]
    out = [r for r in out if r and r.get("kind") == "backup"]
    return [public_record(r) for r in sorted(out, key=lambda r: r.get("created_at", ""), reverse=True)]


def get_backup(rid: str) -> tuple[dict[str, Any], Path]:
    rec = _read_json(_record_path(rid)) if _valid_id(rid) else None
    if not rec or rec.get("kind") != "backup":
        raise BundleError("That backup no longer exists on the server.")
    return rec, _file_path(rid)


def delete_backup(rid: str) -> None:
    rec, path = get_backup(rid)
    if rec.get("status") == "running":
        raise BundleError("This backup is still being made.")
    path.unlink(missing_ok=True)
    _record_path(rid).unlink(missing_ok=True)


def mark_downloaded(rid: str, actor: audit.Actor) -> None:
    rec, _ = get_backup(rid)
    now = _now()
    first = not rec.get("downloaded_at")
    rec["downloaded_at"] = rec.get("downloaded_at") or now.isoformat()
    rec["downloads"] = int(rec.get("downloads") or 0) + 1
    _write_json(_record_path(rid), rec)
    with platform_session() as s:
        if first:
            row = s.get(m.PlatformSetting, "last_backup") or m.PlatformSetting(key="last_backup", value={})
            row.value = {"at": rec["created_at"], "file": rec["file_name"], "size": rec["size"], "encrypted": True,
                         "downloaded_at": rec["downloaded_at"], "sha256": rec["sha256"]}
            s.add(row)
        audit.record(s, actor, "system.backup_downloaded", target_type="backup", target_label=rec["file_name"],
                     detail={"sha256": rec["sha256"], "size": rec["size"]})


# ── Create ───────────────────────────────────────────────────────────────────

def _progress(rec: dict[str, Any], step: str, steps: list[tuple[str, str]]) -> None:
    keys = [k for k, _ in steps]
    rec["step"] = step
    rec["steps"] = [{"key": k, "label": label, "done": keys.index(k) < keys.index(step), "current": k == step} for k, label in steps]
    _write_json(_record_path(rec["id"]), rec)


def start_backup(actor: audit.Actor, passphrase: str, *, wait: bool = False) -> dict[str, Any]:
    problem = passphrase_problem(passphrase)
    if problem:
        raise BundleError(problem)
    if maintenance():
        raise BundleError("A restore is running. Try again when it has finished.")
    if not pkictl.available():
        raise BundleError("The PKI service is not running the EasyEAP supervisor yet. Update the installation (docker compose up -d) and try again.")
    if not _lock.acquire(blocking=False):
        raise BundleError("A backup or restore is already running.")
    purge_expired()
    rid = uuid.uuid4().hex
    rec: dict[str, Any] = {"id": rid, "kind": "backup", "status": "running", "created_at": _now().isoformat(), "created_by": actor.label,
                           "pid": os.getpid(), "host": socket.gethostname()}
    _progress(rec, "prepare", BACKUP_STEPS)

    def run() -> None:
        try:
            _create(rec, passphrase, actor)
        except Exception as exc:  # noqa: BLE001 — reported to the administrator
            log.error("Backup %s failed: %s", rid, exc)
            rec.update(status="failed", error=str(exc) if isinstance(exc, (BundleError, RestoreError, pkictl.PkiControlError)) else
                       f"The backup failed: {redact(str(exc))[:300]}", finished_at=_now().isoformat(),
                       expires_at=(_now() + timedelta(hours=get_settings().backup_retention_hours)).isoformat())
            _write_json(_record_path(rid), rec)
            shutil.rmtree(backups_dir() / f".work-{rid}", ignore_errors=True)
        finally:
            _lock.release()

    if wait:
        run()
    else:
        threading.Thread(target=run, name=f"backup-{rid}", daemon=True).start()
    return public_record(rec)


def _inventory() -> dict[str, Any]:
    with platform_session() as s:
        tenants = [{"name": t.name, "slug": t.slug, "status": t.status} for t in s.scalars(select(m.Tenant).order_by(m.Tenant.name))]
        count = lambda model, *where: s.scalar(select(func.count()).select_from(model).where(*where)) or 0  # noqa: E731
        counts = {"tenants": len(tenants), "administrators": count(m.Admin), "identities": count(m.Identity),
                  "certificates": count(m.Certificate), "active_certificates": count(m.Certificate, m.Certificate.status == "active"),
                  "radius_clients": count(m.RadiusClient), "audit_events": count(m.AuditEvent)}
    return {"tenants": tenants, "counts": counts, "schema_revision": _schema_revision()}


def _schema_revision() -> str | None:
    """alembic_version belongs to the schema owner (the application role can't read it)."""
    u = _owner_url()
    with psycopg.connect(host=u.host, port=u.port or 5432, user=u.username, password=get_settings().db_owner_password,
                         dbname=_db_name(), connect_timeout=10) as c:
        row = c.execute("SELECT version_num FROM alembic_version").fetchone()
    return row[0] if row else None


def _pki_access() -> dict[str, Any]:
    from app.pki.openbao import OpenBao
    bao = OpenBao()
    try:
        bao.write("auth/token/renew-self")  # restart the 32-day clock so a restore has the longest window
    except Exception as exc:  # noqa: BLE001
        log.warning("OpenBao token renewal before backup failed: %s", exc)
    info = (bao.request("GET", "auth/token/lookup-self") or {}).get("data", {})
    init = _read_json(Path(get_settings().openbao_init_file)) or {}
    keys = len(init.get("recovery_keys_b64") or [])
    return {"recovery_keys": keys > 0, "token_expires_at": info.get("expire_time"),
            "openbao_version": OpenBao(token="").health().get("version")}


def _secrets_tar() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name in SECRET_FILES:
            p = secrets_dir() / name
            if p.is_file():
                data = p.read_bytes()
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(data), 0o600, int(time.time())
                t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _create(rec: dict[str, Any], passphrase: str, actor: audit.Actor) -> None:
    rid = rec["id"]
    settings = get_settings()
    host = urlparse(settings.public_url).hostname or "easyeap"
    stamp = _now().strftime("%Y%m%dT%H%M%SZ")
    writer = BundleWriter(backups_dir() / f".work-{rid}", passphrase)
    try:
        inventory = _inventory()
        access = _pki_access()

        _progress(rec, "database", BACKUP_STEPS)
        with tempfile.TemporaryFile() as err:
            proc = subprocess.Popen([_tool("pg_dump"), "--format=custom", "--no-password", "--dbname", _db_name()],  # noqa: S603 — fixed argv, no shell
                                    stdout=subprocess.PIPE, stderr=err, env=_pg_env())
            if proc.stdout is None:
                raise BundleError("The database export could not start.")
            writer.add_stream("database.dump", proc.stdout)
            code = proc.wait()
            if code != 0:
                err.seek(0)
                raise BundleError(f"The database export failed: {redact(err.read().decode(errors='replace'))[-400:].strip()}")

        _progress(rec, "pki", BACKUP_STEPS)
        snap = pkictl.snapshot()
        try:
            writer.add_file("pki.tar", snap)
        finally:
            pkictl.discard(snap)

        _progress(rec, "package", BACKUP_STEPS)
        writer.add_bytes("secrets.tar", _secrets_tar())
        restore_before = None if access["recovery_keys"] else access.get("token_expires_at")
        manifest = {
            "format_version": 1, "product_version": __version__, "created_at": rec["created_at"], "created_by": actor.label,
            "source": {"public_url": settings.public_url, "hostname": host}, "schema_revision": inventory["schema_revision"],
            "openbao_version": access.get("openbao_version"), "tenants": inventory["tenants"], "counts": inventory["counts"],
            "pki_access": {"recovery_keys": access["recovery_keys"], "restore_before": restore_before},
            "parts": dict(writer.parts),
        }
        writer.add_bytes("manifest.json", json.dumps(manifest, indent=2).encode())
        file_name = f"easyeap-backup-{host}-{stamp}.easyeap"
        result = writer.finish(_file_path(rid), {"product_version": __version__, "created_at": rec["created_at"]})
    except BaseException:
        writer.abort()
        raise
    finished = _now()
    rec.update(status="done", step=None, steps=None, finished_at=finished.isoformat(), file_name=file_name, size=result["size"],
               sha256=result["sha256"], expires_at=(finished + timedelta(hours=settings.backup_retention_hours)).isoformat(),
               summary={"tenants": [t["name"] for t in inventory["tenants"]], "counts": inventory["counts"]},
               pki_access={"recovery_keys": access["recovery_keys"], "restore_before": restore_before})
    _write_json(_record_path(rid), rec)
    with platform_session() as s:
        audit.record(s, actor, "system.backup_created", target_type="backup", target_label=file_name,
                     detail={"size": result["size"], "sha256": result["sha256"], "tenants": len(inventory["tenants"])})
    log.info("Backup %s written (%d bytes)", file_name, result["size"])


# ── Upload and inspect ───────────────────────────────────────────────────────

def new_upload_path() -> tuple[str, Path]:
    purge_expired()
    rid = uuid.uuid4().hex
    return rid, backups_dir() / f"{rid}.easyeap.partial"


def check_space(size: int | None) -> None:
    free = shutil.disk_usage(backups_dir()).free
    if size and size > MAX_UPLOAD:
        raise BundleError("That file is too large to be an EasyEAP backup.")
    if size and free < size * 2 + 512 * 1024**2:
        raise BundleError("There isn't enough free disk space on the server to receive and restore this backup.")


def finish_upload(rid: str, partial: Path, source: str) -> dict[str, Any]:
    final = _file_path(rid)
    os.replace(partial, final)
    try:
        header = read_header(final)
    except BundleError:
        final.unlink(missing_ok=True)
        raise
    rec = {"id": rid, "kind": "upload", "status": "uploaded", "created_at": _now().isoformat(), "source": source,
           "size": final.stat().st_size, "header": header,
           "expires_at": (_now() + timedelta(hours=get_settings().backup_retention_hours)).isoformat()}
    _write_json(_record_path(rid), rec)
    return {"id": rid, "size": rec["size"], "created_at": header.get("created_at"), "product_version": header.get("product_version")}


def _upload(rid: str) -> Path:
    rec = _read_json(_record_path(rid)) if _valid_id(rid) else None
    if not rec or rec.get("kind") not in ("upload", "backup") or not _file_path(rid).is_file():
        raise BundleError("That uploaded backup is no longer on the server. Upload it again.")
    return _file_path(rid)


def discard_upload(rid: str) -> None:
    rec = _read_json(_record_path(rid)) if _valid_id(rid) else None
    if rec and rec.get("kind") == "upload":
        _file_path(rid).unlink(missing_ok=True)
        _record_path(rid).unlink(missing_ok=True)


def _known_revisions() -> set[str]:
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    root = Path(__file__).resolve().parents[2]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "alembic"))
    return {r.revision for r in ScriptDirectory.from_config(cfg).walk_revisions()}


def _version_tuple(v: str | None) -> tuple[int, ...]:
    out = []
    for part in (v or "0").split("+")[0].split("-")[0].split("."):
        out.append(int(part) if part.isdigit() else 0)
    return tuple(out[:3])


def inspect(rid: str, passphrase: str) -> dict[str, Any]:
    """Unlock the backup and say what it holds and whether it can be restored here."""
    with BundleReader(_upload(rid)) as r:
        mf = r.unlock(passphrase)
    problems, warnings = [], []
    if set(PARTS) - {"manifest.json"} - set(mf.get("parts", {})):
        problems.append("The backup is incomplete.")
    if mf.get("schema_revision") not in _known_revisions():
        problems.append(f"This backup comes from a newer EasyEAP ({mf.get('product_version')}). Update EasyEAP to that version or later first.")
    from app.pki.openbao import OpenBao
    try:
        running_bao = OpenBao(token="").health().get("version")
    except Exception:  # noqa: BLE001
        running_bao = None
    if running_bao and _version_tuple(mf.get("openbao_version"))[:2] > _version_tuple(running_bao)[:2]:
        problems.append(f"This backup's PKI data comes from OpenBao {mf.get('openbao_version')}, newer than this server's {running_bao}.")
    access = mf.get("pki_access") or {}
    before = access.get("restore_before")
    if not access.get("recovery_keys") and before:
        if datetime.fromisoformat(before) < _now():
            problems.append("This backup's PKI credentials expired on "
                            f"{before[:10]} and it has no recovery keys, so EasyEAP couldn't use its certificate authorities after a restore.")
        else:
            warnings.append(f"Restore it before {before[:10]}: this installation predates PKI recovery keys, so its credentials expire then.")
    src = (mf.get("source") or {}).get("hostname")
    here = urlparse(get_settings().public_url).hostname
    if src and here and src != here:
        warnings.append(f"The backup comes from {src}. This server is {here}. Certificates point at {src} for revocation lists: "
                        f"point that name at this server, or re-issue certificates over time.")
    return {"created_at": mf.get("created_at"), "created_by": mf.get("created_by"), "product_version": mf.get("product_version"),
            "source_host": src, "tenants": mf.get("tenants", []), "counts": mf.get("counts", {}),
            "size": _upload(rid).stat().st_size, "restorable": not problems, "problems": problems, "warnings": warnings}


# ── Restore ──────────────────────────────────────────────────────────────────

def start_restore(rid: str, passphrase: str, *, actor_label: str, source: str, wait: bool = False) -> dict[str, Any]:
    path = _upload(rid)
    summary = inspect(rid, passphrase)
    if not summary["restorable"]:
        raise BundleError(" ".join(summary["problems"]))
    if not pkictl.available():
        raise BundleError("The PKI service is not running the EasyEAP supervisor yet. Update the installation (docker compose up -d) and try again.")
    if not _lock.acquire(blocking=False):
        raise BundleError("A backup or restore is already running.")
    st: dict[str, Any] = {"id": uuid.uuid4().hex, "status": "running", "step": "verify", "done": [], "started_at": _now().isoformat(),
                          "actor": actor_label, "source": source, "upload_id": rid,
                          "backup": {"created_at": summary["created_at"], "host": summary["source_host"], "tenants": len(summary["tenants"])},
                          "flags": {}, "warnings": [w for w in summary["warnings"] if not w.startswith("Restore it before")]}
    _save_state(st)

    def run() -> None:
        try:
            _restore(st, path, passphrase)
        except Exception as exc:  # noqa: BLE001 — reported to the administrator, then rolled back
            message = str(exc) if isinstance(exc, (RestoreError, BundleError, pkictl.PkiControlError)) else f"Unexpected error: {redact(str(exc))[:300]}"
            log.error("Restore %s failed at %s: %s", st["id"], st.get("step"), message)
            st["error"] = message
            _rollback(st)
        finally:
            _lock.release()

    if wait:
        run()
    else:
        threading.Thread(target=run, name=f"restore-{st['id']}", daemon=True).start()
    return public_state(st)


def _step(st: dict[str, Any], key: str) -> None:
    if st.get("step") and st["step"] != key and st["step"] not in st["done"]:
        st["done"].append(st["step"])
    st["step"] = key
    _save_state(st)
    log.info("Restore %s: %s", st["id"], dict(RESTORE_STEPS)[key])


class _PipeWriter:
    def __init__(self, pipe: Any):
        self.pipe = pipe

    def write(self, b: bytes) -> int:
        self.pipe.write(b)
        return len(b)

    def flush(self) -> None:
        self.pipe.flush()


def _max_radius_version() -> int:
    try:
        with platform_session() as s:
            return int(s.scalar(text("SELECT coalesce(max(greatest(snapshot_version, config_version)), 0) FROM radius_settings")) or 0)
    except Exception:  # noqa: BLE001 — an empty first-run database
        return 0


def _restore(st: dict[str, Any], path: Path, passphrase: str) -> None:
    db = _db_name()
    flags = st["flags"]
    with BundleReader(path) as r:
        r.unlock(passphrase)
        # verify: every byte decrypts and matches its checksum before anything changes.
        for part in ("secrets.tar", "pki.tar", "database.dump"):
            r.verify(part)
        secrets_blob = r.read_bytes("secrets.tar")
        secrets_files = _parse_secrets(secrets_blob)
        st["max_version"] = _max_radius_version()
        _save_state(st)

        _step(st, "pki")
        req_id = pkictl.new_id()
        flags["pki_req"] = req_id
        with open(pkictl.staging_path(req_id), "wb") as f:
            r.stream_to("pki.tar", f)
        flags["pki_pending"] = True
        _save_state(st)
        pkictl.restore(req_id)
        flags["pki_restored"] = True
        _save_state(st)

        _step(st, "database")
        old = f"{db}_pre_restore_{int(time.time())}"
        with _admin_conn() as c:
            c.execute(sql.SQL("ALTER DATABASE {} WITH ALLOW_CONNECTIONS false").format(sql.Identifier(db)))
            flags["db_locked"] = True
            _save_state(st)
            for attempt in range(10):
                c.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s AND pid <> pg_backend_pid()", (db,))
                try:
                    c.execute(sql.SQL("ALTER DATABASE {} RENAME TO {}").format(sql.Identifier(db), sql.Identifier(old)))
                    break
                except psycopg.errors.ObjectInUse:
                    if attempt == 9:
                        raise RestoreError("The database stayed in use. Try the restore again.") from None
                    time.sleep(1)
            flags.update(db_swapped=True, old_db=old)
            _save_state(st)
            owner = _owner_url().username or "easyeap"
            c.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(db), sql.Identifier(owner)))
            c.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(db)))
            c.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO easyeap_app").format(sql.Identifier(db)))
        reset_engine()
        with tempfile.TemporaryFile() as err:
            proc = subprocess.Popen([_tool("pg_restore"), "--exit-on-error", "--no-password", "--dbname", db],  # noqa: S603 — fixed argv, no shell
                                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=err, env=_pg_env())
            if proc.stdin is None:
                raise RestoreError("The database restore could not start.")
            try:
                r.stream_to("database.dump", _PipeWriter(proc.stdin))
                proc.stdin.close()
            except (BundleError, OSError) as exc:
                proc.kill()
                proc.wait()
                err.seek(0)
                detail = redact(err.read().decode(errors="replace"))[-400:].strip()
                raise RestoreError(f"The database restore failed: {detail or exc}") from exc
            if proc.wait() != 0:
                err.seek(0)
                raise RestoreError(f"The database restore failed: {redact(err.read().decode(errors='replace'))[-400:].strip()}")

    _step(st, "migrate")
    app_root = Path(__file__).resolve().parents[2]
    res = subprocess.run([_tool("alembic"), "upgrade", "head"], cwd=app_root, capture_output=True, text=True, timeout=1800)  # noqa: S603
    if res.returncode != 0:
        raise RestoreError(f"Updating the restored database failed: {redact(res.stderr)[-400:].strip()}")

    _step(st, "secrets")
    pre = secrets_dir() / ".pre-restore"
    shutil.rmtree(pre, ignore_errors=True)
    pre.mkdir(mode=0o700)
    for name in SECRET_FILES:
        if (secrets_dir() / name).is_file():
            shutil.copy2(secrets_dir() / name, pre / name)
    flags["secrets_replaced"] = True
    _save_state(st)
    for name, data in secrets_files.items():
        _write_private(secrets_dir() / name, data)
    if "openbao-init.json" not in secrets_files:
        (secrets_dir() / "openbao-init.json").unlink(missing_ok=True)

    _step(st, "access")
    how = _ensure_pki_access()
    if how == "recovered":
        st["warnings"].append("The backup's PKI token had expired; EasyEAP issued a new one with the recovery keys.")

    _step(st, "finish")
    _finish(st)
    _commit(st)


def _parse_secrets(blob: bytes) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:") as t:
        for member in t.getmembers():
            if member.name in SECRET_FILES and member.isreg() and member.size < 1024 * 1024:
                f = t.extractfile(member)
                if f:
                    out[member.name] = f.read()
    if "openbao-api-token" not in out:
        raise RestoreError("The backup has no PKI credentials.")
    return out


def _write_private(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def _ensure_pki_access() -> str:
    """Make sure the restored token works. If it expired, use the recovery keys to mint a new one."""
    from app.pki.openbao import API_POLICY, OpenBao, OpenBaoError
    try:
        OpenBao().request("GET", "auth/token/lookup-self")
        OpenBao().write("auth/token/renew-self")
        return "token"
    except OpenBaoError as exc:
        if exc.status not in (400, 401, 403):
            raise RestoreError(f"The restored PKI service answered unexpectedly: {exc}") from exc
    init = _read_json(secrets_dir() / "openbao-init.json") or {}
    keys = init.get("recovery_keys_b64") or []
    if not keys:
        raise RestoreError("The backup's PKI token has expired and the backup holds no recovery keys, so its certificate authorities can't be used.")
    anon = OpenBao(token="")
    anon.request("DELETE", "sys/generate-root/attempt")
    attempt = anon.request("PUT", "sys/generate-root/attempt", {}) or {}
    otp, nonce, result = attempt["otp"], attempt["nonce"], {}
    for key in keys:
        result = anon.request("PUT", "sys/generate-root/update", {"key": key, "nonce": nonce}) or {}
        if result.get("complete"):
            break
    if not result.get("complete"):
        anon.request("DELETE", "sys/generate-root/attempt")
        raise RestoreError("The backup's recovery keys were not accepted by its PKI service.")
    enc = result["encoded_token"]
    raw = base64.b64decode(enc + "=" * (-len(enc) % 4))
    root_token = bytes(a ^ b for a, b in zip(raw, otp.encode(), strict=False)).decode()
    root = OpenBao(token=root_token)
    try:
        root.request("PUT", "sys/policies/acl/easyeap-api", {"policy": API_POLICY})
        tok = root.write("auth/token/create-orphan", {"policies": ["easyeap-api"], "period": "768h", "display_name": "easyeap-api"})
        _write_private(secrets_dir() / "openbao-api-token", tok["auth"]["client_token"].encode())
    finally:
        root.write("auth/token/revoke-self")
    return "recovered"


def _finish(st: dict[str, Any]) -> None:
    from app.policy.service import recompute_tenant
    from app.radius.state import bump
    reset_engine()
    with platform_session() as s:
        ok, bad, n = audit.verify_chain(s)
        if not ok:
            st["warnings"].append(f"The restored audit trail fails verification at entry #{bad}. It was restored as it was in the backup.")
        # Agents compare snapshot versions for equality: move every version past anything the replaced database issued.
        floor = int(st.get("max_version") or 0) + 1
        s.execute(text("UPDATE radius_settings SET snapshot_version = greatest(snapshot_version, :f) + 1, "
                       "config_version = greatest(config_version, :f) + 1"), {"f": floor})
        # Sessions from the backup would bring back sign-ins that ended after it was made.
        s.execute(text("DELETE FROM admin_sessions"))
        tenants = [t.id for t in s.scalars(select(m.Tenant).where(m.Tenant.status == "active"))]
    for tid in tenants:
        try:
            with platform_session() as s:
                recompute_tenant(s, tid)
                bump(s, tid)
        except Exception as exc:  # noqa: BLE001 — the worker's hourly refresh will retry
            st["warnings"].append(f"Access decisions for one tenant will be rebuilt by the next refresh ({redact(str(exc))[:120]}).")
    with platform_session() as s:
        audit.record(s, audit.Actor("system", f"Restore by {st.get('actor')}"), "system.backup_restored", target_type="backup",
                     target_label=(st.get("backup") or {}).get("created_at") or "",
                     detail={"backup_created_at": (st.get("backup") or {}).get("created_at"), "source_host": (st.get("backup") or {}).get("host"),
                             "restored_by": st.get("actor"), "via": st.get("source"), "audit_chain_ok": ok, "audit_rows": n})
        row = s.get(m.PlatformSetting, "last_restore") or m.PlatformSetting(key="last_restore", value={})
        row.value = {"at": _now().isoformat(), "backup_created_at": (st.get("backup") or {}).get("created_at"), "by": st.get("actor")}
        s.add(row)
        if (s.scalar(select(func.count()).select_from(m.Admin)) or 0) > 0:
            from app.secrets_store import consume_setup_token
            consume_setup_token()


def _commit(st: dict[str, Any]) -> None:
    flags = st["flags"]
    flags["committed"] = True
    _save_state(st)
    if flags.get("pki_restored"):
        try:
            pkictl.commit()
        except Exception as exc:  # noqa: BLE001 — harmless: the rollback copy is cleared on the next restore
            log.warning("PKI commit after restore: %s", exc)
    if flags.get("old_db"):
        try:
            with _admin_conn() as c:
                c.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(flags["old_db"])))
        except Exception as exc:  # noqa: BLE001
            log.warning("Dropping the pre-restore database %s failed: %s", flags["old_db"], exc)
    shutil.rmtree(secrets_dir() / ".pre-restore", ignore_errors=True)
    if st.get("upload_id"):
        discard_upload(st["upload_id"])
    st["done"] = [k for k, _ in RESTORE_STEPS]
    st.update(status="done", step=None, finished_at=_now().isoformat())
    _save_state(st)
    reset_engine()
    log.info("Restore %s complete", st["id"])


def _rollback(st: dict[str, Any]) -> None:
    """Undo whatever the restore changed, newest first. Each part is attempted even if another fails."""
    flags = st.get("flags", {})
    st["status"] = "rolling_back"
    _save_state(st)
    db = _db_name()
    notes = []
    if flags.get("secrets_replaced"):
        pre = secrets_dir() / ".pre-restore"
        try:
            for name in SECRET_FILES:
                if (pre / name).is_file():
                    shutil.copy2(pre / name, secrets_dir() / name)
                else:
                    (secrets_dir() / name).unlink(missing_ok=True)
            shutil.rmtree(pre, ignore_errors=True)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"PKI credentials: {exc}")
    if flags.get("db_swapped") or flags.get("db_locked"):
        try:
            with _admin_conn() as c:
                if flags.get("db_swapped"):
                    c.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(db)))
                    c.execute(sql.SQL("ALTER DATABASE {} RENAME TO {}").format(sql.Identifier(flags["old_db"]), sql.Identifier(db)))
                c.execute(sql.SQL("ALTER DATABASE {} WITH ALLOW_CONNECTIONS true").format(sql.Identifier(db)))
        except Exception as exc:  # noqa: BLE001
            notes.append(f"database: {exc}")
    if flags.get("pki_req"):
        pkictl.discard(pkictl.staging_path(flags["pki_req"]))
    if flags.get("pki_restored") or flags.get("pki_pending"):
        try:
            pkictl.rollback()
        except Exception as exc:  # noqa: BLE001
            notes.append(f"PKI: {exc}")
    reset_engine()
    if notes:
        log.error("Restore rollback incomplete: %s", "; ".join(notes))
        st["error"] = f"{st.get('error') or 'The restore failed.'} Putting things back also failed ({'; '.join(notes)[:300]}). See the troubleshooting guide."
    st.update(status="failed", finished_at=_now().isoformat())
    _save_state(st)  # the upload is kept, so the administrator can retry


def recover() -> str | None:
    """Called at API start: finish or undo a restore that was interrupted by a restart."""
    st = restore_state()
    if not st or st.get("status") not in ("running", "rolling_back"):
        return None
    for _ in range(120):  # the PKI container may still be starting
        if pkictl.available():
            break
        time.sleep(1)
    if st.get("flags", {}).get("committed"):
        _commit(st)
        return "completed"
    st["error"] = "The restore was interrupted because EasyEAP restarted. Everything was put back as it was before the restore."
    _rollback(st)
    return "rolled back"
