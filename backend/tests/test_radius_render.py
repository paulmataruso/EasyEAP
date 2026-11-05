"""The FreeRADIUS renderer (services/radius/agent/render.py)."""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec_path = ROOT / "services" / "radius" / "agent" / "render.py"
if not spec_path.exists():
    pytest.skip("services/radius not available in this checkout", allow_module_level=True)
spec = importlib.util.spec_from_file_location("render", spec_path)
render = importlib.util.module_from_spec(spec)
sys.modules["render"] = render
spec.loader.exec_module(render)

TENANT = {"id": "11111111-2222-3333-4444-555555555555", "slug": "corp", "name": "Corp", "auth_port": 1812, "acct_port": 1813, "dedicated_ports": False,
          "tls_min_version": "1.2", "tls_session_cache": False, "session_timeout": 28800, "server_cert_pem": "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----",
          "server_key_pem": "-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----", "ca_pem": "-----BEGIN CERTIFICATE-----\nBB\n-----END CERTIFICATE-----\n",
          "crl_pem": "-----BEGIN X509 CRL-----\nCC\n-----END X509 CRL-----\n",
          "clients": [{"id": "aaaaaaaa-0000-0000-0000-000000000001", "name": "WLC 1", "vendor": "cisco-9800", "address": "10.0.0.0/24", "secret": "s3cret", "coa": True, "coa_port": 1700}]}


def test_render_tree(tmp_path):
    render.render({"version": "x", "tenants": [TENANT]}, tmp_path, "/state")
    s = render.short(TENANT["id"])
    clients = (tmp_path / "clients.conf").read_text()
    assert "require_message_authenticator = yes" in clients and "limit_proxy_state = yes" in clients and f"virtual_server = t_{s}" in clients
    assert oct((tmp_path / "clients.conf").stat().st_mode)[-3:] == "600"
    assert oct((tmp_path / "tenants" / s / "server.key").stat().st_mode)[-3:] == "600"
    eap = (tmp_path / "mods-enabled" / f"eap_{s}").read_text()
    assert "default_eap_type = tls" in eap and "check_crl = yes" in eap and "enable = no" in eap and f'virtual_server = "t_{s}_check"' in eap
    for banned in ("peap", "ttls", "md5", "mschap"):
        assert banned not in eap.lower()
    check = (tmp_path / "sites-enabled" / f"t_{s}_check").read_text()
    assert "snapshot_stale" in check and "cert_unknown" in check and "Tunnel-Private-Group-Id" in check
    assert "valid_until > %l" in check, "freshness is enforced by RADIUS itself"
    ca = (tmp_path / "tenants" / s / "ca.pem").read_text()
    assert "X509 CRL" in ca
    # Events carry the address the packet came from, so EasyEAP can tell which controller sent it even when the
    # controller reports a different NAS-IP-Address.
    main = (tmp_path / "sites-enabled" / f"t_{s}").read_text()
    assert main.count('&EasyEAP-Source := "%{%{Packet-Src-IP-Address}:-%{Packet-Src-IPv6-Address}}"') == 4
    assert "&control:EasyEAP-Source" in render.AUTH_ATTRS and "&control:EasyEAP-Source" in render.ACCT_ATTRS


def test_dedicated_ports_scope_clients(tmp_path):
    t = dict(TENANT, dedicated_ports=True, auth_port=1820, acct_port=1821)
    render.render({"version": "x", "tenants": [t]}, tmp_path, "/state")
    s = render.short(t["id"])
    assert f"clients clients_{s}" in (tmp_path / "clients.conf").read_text()
    assert "port = 1820" in (tmp_path / "sites-enabled" / f"t_{s}").read_text()


def test_unsafe_secret_rejected():
    with pytest.raises(ValueError):
        render.q('bad"secret')
