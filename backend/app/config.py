"""Runtime settings. Every value comes from the environment (EASYEAP_*) or a Docker secret file."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _read_secret(value: str | None) -> str | None:
    """Values of the form file:///run/secrets/x are read from that file (Docker secrets)."""
    if value and value.startswith("file://"):
        return Path(value.removeprefix("file://")).read_text().strip()
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="EASYEAP_", env_file=None, extra="ignore")

    environment: str = "production"  # production | development | test
    # Application role (subject to row-level security) and owner role (migrations only).
    database_url: str = "postgresql+psycopg://easyeap_app:easyeap@db:5432/easyeap"
    database_owner_url: str = "postgresql+psycopg://easyeap:easyeap@db:5432/easyeap"
    # In Docker the passwords come from secret files; the URLs are then built here, for every process
    # (api, worker, and `docker compose exec easyeap-api easyeap …`), so they never appear in the environment.
    db_app_password_file: str | None = None
    db_owner_password_file: str | None = None
    db_host: str = "easyeap-db"
    db_name: str = "easyeap"

    openbao_addr: str = "http://pki:8200"
    openbao_token: str | None = None  # file:// path to the API's OpenBao token
    openbao_init_file: str = "/var/lib/easyeap/secrets/openbao-init.json"

    agent_token: str | None = None  # bearer token for radius-agent (file://)
    setup_token_file: str = "/var/lib/easyeap/secrets/setup-token"  # noqa: S105 — a file path, not a secret
    backup_dir: str = "/var/lib/easyeap/backups"  # encrypted backups made or uploaded in the console
    control_dir: str = "/var/lib/easyeap/control"  # hand-off with the PKI supervisor (tmpfs)
    backup_retention_hours: int = 24
    session_secret: str | None = None  # HMAC key for CSRF tokens (file://)

    public_url: str = "https://easyeap.localhost"  # console/enrollment base URL
    pki_public_url: str = "http://easyeap.localhost"  # CRL/OCSP base URL (plain HTTP)
    radius_public_address: str = ""  # address controllers use to reach RADIUS (shown in guides)
    syslog_bind: str = ""  # where easyeap-syslog's port is published (empty or loopback: not reachable by switches)
    syslog_port: int = 5514

    @property
    def syslog_receiving(self) -> bool:
        """Switches can reach the collector's syslog port (docs/switch-audit.md)."""
        return self.syslog_bind.strip() not in ("", "127.0.0.1", "::1", "localhost")

    session_ttl_minutes: int = 12 * 60
    session_idle_minutes: int = 60
    cookie_secure: bool = True
    login_rate_limit_per_minute: int = 10
    enrollment_link_ttl_hours: int = 72
    lab_mode: bool = False  # enables the lab-only "keep root CA online" option and test endpoints

    @field_validator("openbao_token", "agent_token", "session_secret", mode="after")
    @classmethod
    def _secrets(cls, v: str | None) -> str | None:
        return _read_secret(v)

    @model_validator(mode="after")
    def _database_urls_from_secrets(self) -> Settings:
        for attr, user, f in (("database_url", "easyeap_app", self.db_app_password_file),
                              ("database_owner_url", "easyeap", self.db_owner_password_file)):
            if f and Path(f).is_file():
                pw = quote(Path(f).read_text().strip(), safe="")
                setattr(self, attr, f"postgresql+psycopg://{user}:{pw}@{self.db_host}:5432/{self.db_name}")
        return self

    @property
    def db_owner_password(self) -> str:
        """The schema owner's password, for pg_dump/pg_restore during backup and restore."""
        if self.db_owner_password_file and Path(self.db_owner_password_file).is_file():
            return Path(self.db_owner_password_file).read_text().strip()
        from sqlalchemy.engine import make_url
        return make_url(self.database_owner_url).password or ""

    @property
    def is_dev(self) -> bool:
        return self.environment in ("development", "test")


@lru_cache
def get_settings() -> Settings:
    return Settings()


