"""Server-side secrets kept on the API's private volume (mode 0600). Generated on first use."""
from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

from app.config import get_settings


def _dir() -> Path:
    return Path(get_settings().openbao_init_file).parent


def _write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w") as f:
        f.write(value)


def get_or_create(name: str, nbytes: int = 32) -> str:
    path = _dir() / name
    if path.exists():
        return path.read_text().strip()
    value = secrets.token_urlsafe(nbytes)
    _write(path, value)
    return value


def session_secret() -> str:
    return get_settings().session_secret or get_or_create("session-secret")


def setup_token_path() -> Path:
    return Path(get_settings().setup_token_file)


def ensure_setup_token() -> str:
    p = setup_token_path()
    if p.exists():
        return p.read_text().strip()
    token = secrets.token_urlsafe(24)
    _write(p, token)
    return token


def consume_setup_token() -> None:
    setup_token_path().unlink(missing_ok=True)
