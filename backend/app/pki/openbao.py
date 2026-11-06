"""Minimal OpenBao (Vault-compatible) HTTP client and the one-time bootstrap.

The API holds a non-root, policy-limited token. The root token produced at initialisation is used once to
configure policies and is then revoked. The recovery keys are kept on the API's secrets volume (and in every encrypted
backup): with them EasyEAP can regenerate an admin token if the API token is ever lost or expires.
"""
from __future__ import annotations

import json
import logging
import os
import stat
from pathlib import Path
from typing import Any

import httpx

from app.config import get_settings

log = logging.getLogger("easyeap.openbao")
RECOVERY_SHARES, RECOVERY_THRESHOLD = 5, 3

API_POLICY = """
# EasyEAP API — least privilege for tenant PKI + Transit.
# Note: in OpenBao policies '*' is only a trailing prefix glob, so "pki-t-*" covers every path inside those mounts.
path "sys/mounts" { capabilities = ["read"] }
path "sys/mounts/pki-t-*" { capabilities = ["create", "read", "update", "delete"] }
path "sys/mounts/pki-root-*" { capabilities = ["create", "read", "update", "delete"] }
path "pki-t-*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "pki-root-*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "transit/keys/*" { capabilities = ["create", "read", "update", "delete"] }
path "transit/encrypt/*" { capabilities = ["update"] }
path "transit/decrypt/*" { capabilities = ["update"] }
path "transit/rewrap/*" { capabilities = ["update"] }
path "sys/health" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
"""


class OpenBaoError(RuntimeError):
    def __init__(self, status: int, errors: list[str], path: str):
        super().__init__(f"OpenBao {status} on {path}: {'; '.join(errors)}")
        self.status = status
        self.errors = errors


class OpenBao:
    def __init__(self, addr: str | None = None, token: str | None = None, timeout: float = 15.0):
        settings = get_settings()
        self.addr = (addr or settings.openbao_addr).rstrip("/")
        self.token = token if token is not None else _load_api_token()
        self._client = httpx.Client(base_url=self.addr, timeout=timeout)

    def request(self, method: str, path: str, json_body: dict | None = None, *, allow_404: bool = False) -> dict[str, Any] | None:
        headers = {"X-Vault-Token": self.token} if self.token else {}
        r = self._client.request(method, f"/v1/{path.lstrip('/')}", json=json_body, headers=headers)
        if r.status_code == 404 and allow_404:
            return None
        if r.status_code >= 400:
            try:
                errors = r.json().get("errors", [])
            except ValueError:
                errors = [r.text[:200]]
            raise OpenBaoError(r.status_code, errors, path)
        if r.status_code == 204 or not r.content:
            return {}
        try:
            return r.json()
        except ValueError:
            return {"raw": r.text}

    def get_text(self, path: str) -> str:
        r = self._client.get(f"/v1/{path.lstrip('/')}")
        r.raise_for_status()
        return r.text

    def get_bytes(self, path: str) -> bytes:
        r = self._client.get(f"/v1/{path.lstrip('/')}")
        r.raise_for_status()
        return r.content

    def post_raw(self, path: str, body: bytes, content_type: str) -> httpx.Response:
        return self._client.post(f"/v1/{path.lstrip('/')}", content=body, headers={"Content-Type": content_type})

    # Convenience
    def write(self, path: str, data: dict | None = None) -> dict[str, Any]:
        return self.request("POST", path, data or {}) or {}

    def read(self, path: str) -> dict[str, Any] | None:
        return self.request("GET", path, allow_404=True)

    def delete(self, path: str) -> None:
        self.request("DELETE", path, allow_404=True)

    def health(self) -> dict[str, Any]:
        r = self._client.get("/v1/sys/health", params={"standbyok": "true", "sealedcode": "200", "uninitcode": "200"})
        return r.json()

    def mount_exists(self, name: str) -> bool:
        mounts = self.request("GET", "sys/mounts") or {}
        data = mounts.get("data", mounts)
        return f"{name}/" in data


def _load_api_token() -> str | None:
    settings = get_settings()
    if settings.openbao_token:
        return settings.openbao_token
    path = Path(settings.openbao_init_file).with_name("openbao-api-token")
    return path.read_text().strip() if path.exists() else None


def _write_private(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w") as f:
        f.write(content)


def bootstrap() -> str:
    """Initialise and configure OpenBao if needed. Returns the API token. Idempotent."""
    settings = get_settings()
    init_file = Path(settings.openbao_init_file)
    token_file = init_file.with_name("openbao-api-token")
    anon = OpenBao(token="")
    health = anon.health()
    if health.get("initialized") and token_file.exists():
        return token_file.read_text().strip()
    if health.get("initialized") and not token_file.exists():
        raise RuntimeError(
            "OpenBao is initialised but the EasyEAP API token is missing from the secrets volume. "
            "Restore the secrets volume from backup (see DEPLOYMENT.md, Disaster recovery)."
        )
    log.info("Initialising OpenBao (static seal, recovery keys 3 of 5)")
    init = anon.write("sys/init", {"recovery_shares": RECOVERY_SHARES, "recovery_threshold": RECOVERY_THRESHOLD})
    root_token = init["root_token"]
    # OpenBao names the field recovery_keys_base64. These keys are the only way to mint a new admin token later (for
    # example when a restored backup's API token has expired), so they travel inside encrypted backups.
    _write_private(init_file, json.dumps({"recovery_keys_b64": init.get("recovery_keys_base64") or [],
                                          "recovery_threshold": RECOVERY_THRESHOLD}, indent=2))
    root = OpenBao(token=root_token)
    root.write("sys/mounts/transit", {"type": "transit", "description": "EasyEAP envelope encryption"})
    root.write("transit/keys/platform", {"type": "aes256-gcm96"})
    root.request("PUT", "sys/policies/acl/easyeap-api", {"policy": API_POLICY})
    tok = root.write("auth/token/create-orphan", {"policies": ["easyeap-api"], "period": "768h", "display_name": "easyeap-api", "no_default_policy": False})
    api_token = tok["auth"]["client_token"]
    _write_private(token_file, api_token)
    root.write("auth/token/revoke-self")
    log.info("OpenBao configured; root token revoked")
    return api_token


def renew_token() -> None:
    try:
        OpenBao().write("auth/token/renew-self")
    except Exception as exc:  # noqa: BLE001
        log.warning("OpenBao token renewal failed: %s", exc)
