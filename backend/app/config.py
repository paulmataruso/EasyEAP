"""Runtime settings. Every value comes from the environment (EASYEAP_*) or a Docker secret file."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
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

    openbao_addr: str = "http://pki:8200"
    openbao_token: str | None = None  # file:// path to the API's OpenBao token
    openbao_init_file: str = "/var/lib/easyeap/secrets/openbao-init.json"

    agent_token: str | None = None  # bearer token for radius-agent (file://)
    setup_token_file: str = "/var/lib/easyeap/secrets/setup-token"
    session_secret: str | None = None  # HMAC key for CSRF tokens (file://)

    public_url: str = "https://easyeap.localhost"  # console/enrollment base URL
    pki_public_url: str = "http://easyeap.localhost"  # CRL/OCSP base URL (plain HTTP)
    radius_public_address: str = ""  # address controllers use to reach RADIUS (shown in guides)

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

    @property
    def is_dev(self) -> bool:
        return self.environment in ("development", "test")


@lru_cache
def get_settings() -> Settings:
    return Settings()


