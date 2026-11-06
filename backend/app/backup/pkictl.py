"""Client for the PKI supervisor (deploy/openbao/supervisor.sh).

The API never controls Docker. It asks the supervisor in the PKI container to snapshot or replace OpenBao's storage by
dropping request files on the private control volume (tmpfs, mounted only in the API and PKI containers).
"""
from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path

from app.config import get_settings


class PkiControlError(RuntimeError):
    pass


def _root() -> Path:
    return Path(get_settings().control_dir)


def available() -> bool:
    """True when the PKI container runs the supervisor (an install updated to this version)."""
    return (_root() / "supervisor.json").is_file()


def new_id() -> str:
    return secrets.token_hex(12)


def _wait(req_id: str, timeout: float) -> dict:
    res = _root() / "res" / f"{req_id}.json"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if res.is_file():
            try:
                data = json.loads(res.read_text())
            finally:
                res.unlink(missing_ok=True)
            return data
        time.sleep(0.5)
    raise PkiControlError("The PKI service did not answer in time. Check that the easyeap-pki container is running.")


def _request(req_id: str, op: str, timeout: float) -> dict:
    if not available():
        raise PkiControlError("The PKI service is not running the EasyEAP supervisor. Update the installation (docker compose up -d) and try again.")
    req = _root() / "req" / f"{req_id}.{op}"
    req.touch()
    return _wait(req_id, timeout)


def snapshot(timeout: float = 300) -> Path:
    """Stop OpenBao briefly and return the path of a tar with its storage and seal key (on the tmpfs control volume).
    The caller must delete it as soon as it is encrypted."""
    req_id = new_id()
    res = _request(req_id, "snapshot", timeout)
    out = _root() / "out" / f"{req_id}.tar"
    if not res.get("ok") or not out.is_file():
        out.unlink(missing_ok=True)
        raise PkiControlError(res.get("error") or "The PKI snapshot failed.")
    return out


def staging_path(req_id: str) -> Path:
    """Where to write the PKI tar for restore(req_id)."""
    return _root() / "in" / f"{req_id}.tar"


def restore(req_id: str, timeout: float = 400) -> None:
    """Install staging_path(req_id). The supervisor keeps the replaced data until commit() or rollback()."""
    res = _request(req_id, "restore", timeout)
    if not res.get("ok"):
        raise PkiControlError(res.get("error") or "The PKI restore failed.")


def rollback(timeout: float = 400) -> None:
    res = _request(new_id(), "rollback", timeout)
    if not res.get("ok"):
        raise PkiControlError(res.get("error") or "The PKI rollback failed.")


def commit(timeout: float = 60) -> None:
    _request(new_id(), "commit", timeout)


def discard(path: Path) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
