"""A pending enrollment link can be shown again (app/enrollment/service.py link_token): only while it's a pending,
unexpired link whose token EasyEAP kept. No database or OpenBao."""
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from app.enrollment import service as enr


def _e(**kw):
    base = {"method": "link", "status": "pending", "token_ct": "vault:v1:abc", "expires_at": datetime.now(UTC) + timedelta(hours=1),
            "tenant_id": "t"}
    return SimpleNamespace(**{**base, **kw})


def test_link_token_only_for_a_pending_kept_link(monkeypatch):
    monkeypatch.setattr(enr.crypto, "decrypt_str", lambda tid, ct, bao=None: f"token-for-{tid}-{ct}")
    assert enr.link_token(_e()) == "token-for-t-vault:v1:abc"
    assert enr.link_token(_e(status="completed")) is None
    assert enr.link_token(_e(status="cancelled")) is None
    assert enr.link_token(_e(expires_at=datetime.now(UTC) - timedelta(seconds=1))) is None
    assert enr.link_token(_e(token_ct=None)) is None, "a link created before EasyEAP kept them"
    assert enr.link_token(_e(method="server")) is None and enr.link_token(_e(method="windows-setup")) is None
