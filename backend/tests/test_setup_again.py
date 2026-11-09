"""A waiting link or Windows setup file can be given again without making a new one (routers/enrollments.py
windows_setup_again and show_link, routers/identities.py _waiting, enrollment/service.py kept): only the codes not
used yet, the sign-in mode the file was made with, today's network settings. No database: a small fake session."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import HTTPException

from app import models as m
from app.enrollment import service as enr
from app.routers import enrollments as router
from app.routers import identities

NOW = datetime.now(UTC)


def _ca_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Acme Root")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


CA = _ca_pem()


class FakeSession:
    def __init__(self, rows):
        self.objs, self.rows = {}, rows

    def put(self, model, obj, key=None):
        self.objs[(model, key if key is not None else obj.id)] = obj
        return obj

    def get(self, model, ident):
        return self.objs.get((model, ident))

    def scalars(self, _stmt):
        return iter(self.rows)


@pytest.fixture()
def world(monkeypatch):
    tid, iid, did = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    s = FakeSession([])
    tenant = SimpleNamespace(id=tid, name="Acme", slug="acme")
    ident = s.put(m.Identity, SimpleNamespace(id=iid, tenant_id=tid, username="nina", upn="nina@acme.example", display_name="Nina Patel", account_state="enabled"))
    rs = s.put(m.RadiusSettings, SimpleNamespace(server_hostname="radius.acme.example", ssid="Acme-Secure", wpa3=False, wired_enabled=True), tid)
    tpl = {p: s.put(m.CertificateTemplate, SimpleNamespace(id=uuid.uuid4(), purpose=p, renew_before_days=d)) for p, d in (("user", 30), ("device", 45))}
    opts = {"wifi": True, "wired": True, "shared_pc": False, "user": True, "computer": True}

    def part(purpose, **kw):
        base = dict(id=uuid.uuid4(), tenant_id=tid, identity_id=iid, device_id=did, device_name="Windows PC", platform="windows", method=enr.WINDOWS_SETUP,
                    template_id=tpl[purpose].id, status="pending", token_ct=f"ct-{purpose}", expires_at=NOW + timedelta(hours=48),
                    setup_options=dict(opts), created_at=NOW, created_by="admin@acme.example", completed_at=None, certificate_id=None)
        return s.put(m.Enrollment, SimpleNamespace(**{**base, **kw}))

    audits = []
    monkeypatch.setattr(enr.crypto, "decrypt_str", lambda t, ct, bao=None: f"CODE-{ct}")
    monkeypatch.setattr(router.audit, "record", lambda *a, **kw: audits.append((a[2], kw)))
    monkeypatch.setattr("app.pki.service.chain_pem", lambda session, t: (CA, CA))
    ctx = SimpleNamespace(session=s, id=tid, tenant=tenant, actor=None, principal=SimpleNamespace(admin=SimpleNamespace(email="admin@acme.example")), perms=set())
    return SimpleNamespace(s=s, ctx=ctx, part=part, audits=audits, rs=rs, ident=ident, tpl=tpl)


def test_both_codes_again(world):
    u, c = world.part("user"), world.part("device")
    world.s.rows = [u, c]
    out = router.windows_setup_again(c.id, world.ctx)
    assert out["filename"] == "EasyEAP-Setup-nina.cmd" and out["sign_in_mode"] == "machineOrUser"
    assert "$UserCode = 'CODE-ct-user'" in out["content"] and "$ComputerCode = 'CODE-ct-device'" in out["content"]
    assert "$Ssid = 'Acme-Secure'" in out["content"] and "$Wired = $true" in out["content"]
    action, kw = world.audits[-1]
    assert action == "enrollment.windows_setup_downloaded_again" and sorted(kw["detail"]["enrollments"]) == sorted([str(u.id), str(c.id)])


def test_the_setup_file_comes_as_a_program_too(world, tmp_path, monkeypatch):
    """With the launcher in the image, the same file inside the program users double-click (enrollment/windows_exe.py),
    and the server certificate's pin in both. Without one (a development build), the .cmd alone."""
    import base64

    from app.enrollment import linux_setup, windows_exe
    c = world.part("device")
    world.s.rows = [c]
    out = router.windows_setup_again(c.id, world.ctx)
    assert out["exe_filename"] is None and out["exe_b64"] is None and "$TlsPin = ''" in out["content"]

    exe, tls = tmp_path / "EasyEAP-Setup.exe", tmp_path / "proxy-tls.crt"
    exe.write_bytes(b"MZ" + bytes(500))
    tls.write_text(CA)
    monkeypatch.setattr(windows_exe, "LAUNCHER", exe)
    monkeypatch.setattr("app.autoenroll.kerberos.PROXY_CERT", tls)
    out = router.windows_setup_again(c.id, world.ctx)
    assert out["filename"] == "EasyEAP-Setup-nina.cmd" and out["exe_filename"] == "EasyEAP-Setup-nina.exe"
    assert windows_exe.unwrap(base64.b64decode(out["exe_b64"])) == out["content"].encode()
    pin = linux_setup.tls_pin(tls)
    assert pin and f"$TlsPin = '{pin}'" in out["content"]


def test_only_the_codes_not_used_yet_and_the_same_sign_in_mode(world):
    u, c = world.part("user", status="completed", token_ct=None), world.part("device")
    world.s.rows = [u, c]
    out = router.windows_setup_again(u.id, world.ctx)   # either code of the file finds it
    assert "$UserCode = ''" in out["content"] and "$ComputerCode = 'CODE-ct-device'" in out["content"]
    assert out["sign_in_mode"] == "machineOrUser" and "$Mode = 'machineOrUser'" in out["content"], "not 'machine' just because the user's code was used"


def test_only_the_user_code_left_still_runs_the_computer_part(world):
    """Wi-Fi only, the computer's code used (say the file was run with "Run as administrator", so the user part was
    skipped): the file made again has only the user's code, keeps machineOrUser, and still runs the computer part,
    which puts back the shared profile and renewal instead of a per-user profile in user mode."""
    o = {"wifi": True, "wired": False, "shared_pc": False, "user": True, "computer": True}
    u, c = world.part("user", setup_options=o), world.part("device", setup_options=o, status="completed", token_ct=None)
    world.s.rows = [u, c]
    out = router.windows_setup_again(u.id, world.ctx)
    assert "$ComputerCode = ''" in out["content"] and "$Wired = $false" in out["content"]
    assert "$Mode = 'machineOrUser'" in out["content"] and "machineOrUser</authMode>" in out["content"]
    assert "$needComputer = [bool]$ComputerCode -or $Wired -or $Mode -ne 'user'" in out["content"]


def test_shared_pc_and_wired_only_choices_are_kept(world):
    o = {"wifi": False, "wired": True, "shared_pc": True, "user": False, "computer": True}
    c = world.part("device", setup_options=o)
    world.s.rows = [c]
    out = router.windows_setup_again(c.id, world.ctx)
    assert out["sign_in_mode"] == "machine" and "$Ssid = ''" in out["content"]


@pytest.mark.parametrize("change, message", [
    ({"status": "completed", "token_ct": None}, "used, cancelled or have expired"),
    ({"status": "cancelled", "token_ct": None}, "used, cancelled or have expired"),
    ({"expires_at": NOW - timedelta(minutes=1)}, "used, cancelled or have expired"),
    ({"token_ct": None}, "made before EasyEAP kept its codes"),
])
def test_refused_when_nothing_can_be_given(world, change, message):
    c = world.part("device", **change)
    world.s.rows = [c]
    with pytest.raises(HTTPException) as exc:
        router.windows_setup_again(c.id, world.ctx)
    assert exc.value.status_code == 409 and message in exc.value.detail
    assert world.audits == []


def test_refused_when_the_wifi_name_was_removed(world):
    c = world.part("device")
    world.s.rows = [c]
    world.rs.ssid = ""
    with pytest.raises(HTTPException) as exc:
        router.windows_setup_again(c.id, world.ctx)
    assert exc.value.status_code == 409 and "Wi-Fi network name was removed" in exc.value.detail


def test_refused_for_a_disabled_account_and_other_tenants_and_links(world):
    c = world.part("device")
    world.s.rows = [c]
    world.ident.account_state = "disabled"
    with pytest.raises(HTTPException) as exc:
        router.windows_setup_again(c.id, world.ctx)
    assert exc.value.status_code == 409
    other = world.part("device", tenant_id=uuid.uuid4())
    link = world.part("user", method="link")
    for e in (other, link):
        with pytest.raises(HTTPException) as exc:
            router.windows_setup_again(e.id, world.ctx)
        assert exc.value.status_code == 404


def test_show_link_sends_a_setup_code_to_the_file(world):
    c = world.part("device")
    with pytest.raises(HTTPException) as exc:
        router.show_link(c.id, world.ctx)
    assert exc.value.status_code == 409 and "download the file again" in exc.value.detail


def test_show_link_waits_for_a_disabled_account(world):
    link = world.part("user", method="link", device_id=None)
    assert router.show_link(link.id, world.ctx)["link"].endswith("/enroll.html#/t/CODE-ct-user")
    assert world.audits[-1][0] == "enrollment.link_shown"
    world.ident.account_state = "disabled"
    with pytest.raises(HTTPException) as exc:
        router.show_link(link.id, world.ctx)
    assert exc.value.status_code == 409 and "until it's enabled again" in exc.value.detail


def test_linux_link_script_for_the_admin(world):
    link = world.part("user", method="link", platform="linux", device_id=None, device_name="Nina’s Ubuntu")
    out = router.linux_script_again(link.id, world.ctx)
    assert out["filename"] == "EasyEAP-WiFi-Setup.sh" and out["content"].startswith("#!")
    assert "TOKEN='CODE-ct-user'" in out["content"] and "SSID='Acme-Secure'" in out["content"]
    assert world.audits[-1][0] == "enrollment.linux_script_downloaded"
    assert "CODE-ct-user" not in repr(world.audits), "the code isn't in the audit log"


@pytest.mark.parametrize("change, code, message", [
    ({"platform": "windows"}, 409, "for another platform"),
    ({"status": "completed", "token_ct": None}, 409, "used, cancelled or has expired"),
    ({"token_ct": None}, 409, "before EasyEAP kept links"),
    ({"method": enr.WINDOWS_SETUP}, 404, "not found"),
])
def test_linux_script_refusals(world, change, code, message):
    link = world.part("user", **{"method": "link", "platform": "linux", "device_id": None, **change})
    with pytest.raises(HTTPException) as exc:
        router.linux_script_again(link.id, world.ctx)
    assert exc.value.status_code == code and message in exc.value.detail


def test_linux_script_needs_the_wifi_name_and_an_enabled_account(world):
    link = world.part("user", method="link", platform="linux", device_id=None)
    world.rs.ssid = ""
    with pytest.raises(HTTPException) as exc:
        router.linux_script_again(link.id, world.ctx)
    assert exc.value.status_code == 409 and "Wi-Fi network name" in exc.value.detail
    world.rs.ssid, world.ident.account_state = "Acme-Secure", "locked"
    with pytest.raises(HTTPException) as exc:
        router.linux_script_again(link.id, world.ctx)
    assert exc.value.status_code == 409 and "locked" in exc.value.detail


def test_kept_codes():
    e = SimpleNamespace(method=enr.WINDOWS_SETUP, status="pending", token_ct="ct", expires_at=NOW + timedelta(hours=1), tenant_id="t")
    assert enr.kept(e) and enr.link_token(e) is None, "a setup code isn't a browser link"
    for change in ({"status": "completed"}, {"token_ct": None}, {"expires_at": NOW - timedelta(seconds=1)}, {"method": "server"}):
        assert not enr.kept(SimpleNamespace(**{**vars(e), **change}))


def test_create_keeps_each_code_encrypted_with_the_choices(monkeypatch):
    added = []
    tpl = SimpleNamespace(id=uuid.uuid4())
    s = SimpleNamespace(add=added.append, flush=lambda: None, scalars=lambda stmt: SimpleNamespace(first=lambda: tpl))
    monkeypatch.setattr(enr.pki, "issuing_ca", lambda session, t: None)
    monkeypatch.setattr(enr.crypto, "encrypt", lambda t, token, bao=None: f"enc({token})")
    tenant = SimpleNamespace(id=uuid.uuid4())
    ident = SimpleNamespace(id=uuid.uuid4(), account_state="enabled")
    _, made = enr.create_windows_setup(s, tenant, ident, user=True, computer=False, created_by="a", options={"wifi": True, "wired": False, "shared_pc": False})
    e, code, _ = made["user"]
    assert e.token_ct == f"enc({code})" and e.token_hash != code
    assert e.setup_options == {"wifi": True, "wired": False, "shared_pc": False, "user": True, "computer": False}


def test_users_list_shows_a_setup_file_once(world):
    u, c = world.part("user", token_ct=None), world.part("device")
    link = world.part("user", method="link", device_id=None, device_name="Nina’s phone", created_at=NOW + timedelta(seconds=1))
    world.s.rows = [link, u, c]
    out = identities._waiting(world.s, [world.ident.id], NOW)[world.ident.id]
    assert [(w["method"], w["available"]) for w in out] == [("link", True), (enr.WINDOWS_SETUP, True)], "one entry per file; a kept code makes it available"
    assert out[1]["id"] == str(u.id)
