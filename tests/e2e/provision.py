"""EasyEAP end-to-end driver. Runs inside the api container (`python - <cmd> < provision.py`) against the real API.

Commands (credentials come from E2E_EMAIL / E2E_PASSWORD; optional E2E_SETUP_TOKEN creates the first admin):
  provision <client-subnet>   build a lab tenant from the Samba AD (E2E_AD_CA = DC CA PEM) and issue test certificates
  revoke <device-name>        revoke the certificate issued for that device
  sync                        re-run directory sync and recompute decisions
  wait                        wait until the RADIUS agent has applied this tenant's latest snapshot
  events                      print recent authentication events as JSON
  call <METHOD> <path> [json] call /api/tenants/<e2e tenant><path>; prints {"status": …, "body": …} whatever the status
  enroll <user> <platform>    enroll a new device for that user from an on-device key; prints the CSR response
  winsetup <user>             the Windows setup for that user, run by a simulated PC (certreq-style requests), then
                              renewal; prints checks and the renewed computer certificate for the lab client
All output is JSON on stdout. Private keys are generated here (the RA never sees them) and returned for the lab client.
"""
import json
import os
import sys
import time
from datetime import datetime

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

SLUG = "e2e-lab"
API = "http://127.0.0.1:8000"


def fail(msg, r=None):
    detail = f" [{r.status_code} {r.request.method} {r.request.url.path}: {r.text[:400]}]" if r is not None else ""
    print(json.dumps({"error": msg + detail}))
    sys.exit(1)


SESSION_CACHE = "/tmp/easyeap-e2e-session.json"  # inside the api container; reused so the login rate limit isn't hit


class Api:
    def __init__(self):
        self.c = httpx.Client(base_url=API, timeout=120)
        if self._resume():
            return
        email, password = os.environ["E2E_EMAIL"], os.environ["E2E_PASSWORD"]
        token = os.environ.get("E2E_SETUP_TOKEN", "").strip()
        if token:
            r = self.c.post("/api/setup/admin", json={"setup_token": token, "email": email, "display_name": "E2E Owner", "password": password})
        else:
            r = self.c.post("/api/auth/login", json={"email": email, "password": password})
        if r.status_code >= 400:
            fail("sign-in failed", r)
        # The session cookie is Secure (HTTPS-only); inside the container we talk plain HTTP, so send it explicitly.
        self._use(r.cookies.get("easyeap_session"), r.json()["csrf_token"])
        fd = os.open(SESSION_CACHE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"session": r.cookies.get("easyeap_session"), "csrf": r.json()["csrf_token"]}, f)

    def _use(self, session, csrf):
        self.c.headers["Cookie"] = f"easyeap_session={session}"
        self.c.headers["X-CSRF-Token"] = csrf

    def _resume(self):
        try:
            with open(SESSION_CACHE) as f:
                saved = json.load(f)
        except (OSError, ValueError):
            return False
        self._use(saved["session"], saved["csrf"])
        if self.c.get("/api/auth/me").status_code == 200:
            return True
        del self.c.headers["Cookie"], self.c.headers["X-CSRF-Token"]
        return False

    def __call__(self, method, path, ok=(200, 201, 204), **kw):
        r = self.c.request(method, path, **kw)
        if r.status_code not in ok:
            fail("request failed", r)
        return r.json() if r.content and r.headers.get("content-type", "").startswith("application/json") else r

    def tenant(self):
        for t in self("GET", "/api/tenants")["tenants"]:
            if t["slug"] == SLUG:
                return t["id"]
        fail("e2e tenant not found; run provision first")


def csr_for(name):
    key = ec.generate_private_key(ec.SECP256R1())
    # The subject below is deliberately wrong: EasyEAP (the RA) must replace it with directory data.
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{name}-claimed-admin")])).sign(key, hashes.SHA256())
    return key, csr.public_bytes(serialization.Encoding.PEM).decode()


def provision(api, subnet):
    for t in api("GET", "/api/tenants")["tenants"]:
        if t["slug"] == SLUG:
            api("DELETE", f"/api/tenants/{t['id']}", json={"confirm_slug": SLUG})
    T = api("POST", "/api/tenants", json={"name": "E2E Lab", "slug": SLUG, "domain": "lab.easyeap.test"})["id"]
    cer = api("POST", f"/api/tenants/{T}/pki/initialize", json={"organization": "EasyEAP Lab", "country": "US", "root_common_name": "E2E Lab Root CA",
                                                                 "issuing_common_name": "E2E Lab Issuing CA 1", "root_passphrase": "e2e-offline-root-passphrase"})
    assert cer["root"]["offline"], "root CA must be offline after the ceremony"
    d = {"hosts": ["dc1.lab.easyeap.test"], "port": 636, "transport": "ldaps", "verify_certificate": True, "ca_bundle_pem": os.environ["E2E_AD_CA"],
         "domain": "lab.easyeap.test", "base_dn": "DC=lab,DC=easyeap,DC=test", "bind_dn": "svc-easyeap@lab.easyeap.test", "bind_password": "Svc-Read-0nly-Lab!"}
    test = api("POST", f"/api/tenants/{T}/directory/test", json=d)
    if not test.get("ok"):
        fail(f"directory test failed: {json.dumps(test)[:400]}")
    api("PUT", f"/api/tenants/{T}/directory", json=d)
    sync = api("POST", f"/api/tenants/{T}/directory/sync", json={})
    groups = {g["name"]: g["id"] for g in api("GET", f"/api/tenants/{T}/directory/groups")["groups"]}
    v120 = api("POST", f"/api/tenants/{T}/policy/vlans", json={"vlan_id": 120, "name": "IT"})["id"]
    v100 = api("POST", f"/api/tenants/{T}/policy/vlans", json={"vlan_id": 100, "name": "Staff"})["id"]
    api("POST", f"/api/tenants/{T}/policy/rules", json={"name": "Block contractors", "action": "deny", "group_ids": [groups["Contractors"]]})
    api("POST", f"/api/tenants/{T}/policy/rules", json={"name": "IT staff", "action": "allow", "vlan_ref": v120, "group_ids": [groups["IT Dept"]]})
    api("POST", f"/api/tenants/{T}/policy/rules", json={"name": "Staff", "action": "allow", "vlan_ref": v100, "group_ids": [groups["Staff"]]})
    rs = api("PUT", f"/api/tenants/{T}/radius", json={"server_hostname": "radius.lab.easyeap.test", "ssid": "EasyEAP-Lab"})
    cl = api("POST", f"/api/tenants/{T}/radius/clients", json={"name": "lab-controller", "vendor": "other", "address": subnet, "coa_enabled": False})
    api("PATCH", f"/api/tenants/{T}", json={"status": "active"})

    users = {i["username"]: i for i in api("GET", f"/api/tenants/{T}/identities", params={"page_size": 100})["items"] if i["source"] == "ad"}
    out = {"tenant": T, "secret": cl["shared_secret"], "server_name": rs["settings"]["server_hostname"], "sync": sync, "certs": {}}
    for user in ("nina", "alice", "bob", "carol"):
        en = api("POST", f"/api/tenants/{T}/enrollments", json={"identity_id": users[user]["id"], "device_name": f"{user}-laptop", "platform": "linux"})
        token = en["link"].split("/t/")[1]
        key, csr = csr_for(user)
        res = api("POST", f"/api/enroll/{token}/csr", json={"csr": csr, "key_origin": "csr"})
        issued = x509.load_pem_x509_certificate(res["certificate_pem"].encode())
        cn = issued.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert "claimed-admin" not in cn, f"RA accepted the CSR subject: {cn}"
        out["ca_pem"] = res["issuing_ca_pem"] + res["root_ca_pem"]
        out["certs"][user] = {"serial": res["serial"], "cn": cn, "cert_pem": res["certificate_pem"],
                              "key_pem": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()}
        reuse = api.c.post(f"/api/enroll/{token}/csr", json={"csr": csr, "key_origin": "csr"})
        assert reuse.status_code == 410, f"an enrollment link must work only once (got {reuse.status_code})"
        assert api.c.get(f"/api/enroll/{token}").json().get("status") == "completed", "a used link must say it was used"
    r = api.c.post(f"/api/tenants/{T}/enrollments", json={"identity_id": users["dave"]["id"], "device_name": "dave-laptop", "platform": "linux"})
    if r.status_code < 400:
        fail("a disabled directory account was allowed to enroll")
    out["dave_enrollment_refused"] = r.json().get("detail")
    print(json.dumps(out))


def wait(api, fresh=False):
    """Until the agent reports the tenant's latest snapshot and configuration applied. fresh: only a report made after
    this call started counts (after an upgrade, the last report in the database is the old agent's)."""
    T = api.tenant()
    started = time.time()
    deadline = started + 120
    while time.time() < deadline:
        r = api("GET", f"/api/tenants/{T}/radius")
        a = r.get("agent") or {}
        seen = a.get("last_seen_at")
        recent = not fresh or (seen and datetime.fromisoformat(seen).timestamp() > started)
        # tenant_config_in_sync: configuration-only changes (a switch's monitor/enforce) don't change the snapshot.
        if (recent and a.get("tenant_in_sync") and a.get("tenant_config_in_sync") is not False and a.get("tenant_mac_in_sync") is not False
                and a.get("config_ok") and a.get("radius_running")):
            print(json.dumps({"in_sync": True, "snapshot": a.get("tenant_snapshot_applied")}))
            return
        time.sleep(2)
    fail(f"RADIUS agent did not apply the latest snapshot: {json.dumps(r.get('agent'))[:400]}")


def wait_admin(api):
    """Until the agent has the tenant's latest device-admin data and, when a device has admin logins on, TACACS+ runs."""
    T = api.tenant()
    deadline = time.time() + 120
    while time.time() < deadline:
        r = api("GET", f"/api/tenants/{T}/device-admin")
        a = r["agent"]
        on = any(d["admin_enabled"] for d in r["devices"])
        if a["supported"] and a["online"] and a["in_sync"] and (a["running"] or not on):
            print(json.dumps({"in_sync": True, "running": a["running"]}))
            return
        time.sleep(2)
    fail(f"RADIUS agent did not apply the latest device-admin data: {json.dumps(r['agent'])}")


def _renewal(cert_pem, key, new_csr_pem, signed_at=None):
    """What the setup's renew.ps1 sends (New-RenewalBody), with an EC key signing in P1363 form like .NET does."""
    import base64
    import hashlib
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    der = x509.load_pem_x509_certificate(cert_pem.encode()).public_bytes(serialization.Encoding.DER)
    csr_der = x509.load_pem_x509_csr(new_csr_pem.encode()).public_bytes(serialization.Encoding.DER)
    signed_at = int(time.time()) if signed_at is None else signed_at
    msg = f"easyeap-renew-v1|{hashlib.sha256(der).hexdigest()}|{signed_at}|{hashlib.sha256(csr_der).hexdigest()}".encode()
    r, s = decode_dss_signature(key.sign(msg, ec.ECDSA(hashes.SHA256())))
    return {"certificate": base64.b64encode(der).decode(), "csr": new_csr_pem, "signed_at": signed_at,
            "signature": base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode(), "key_storage": "software"}


def _certreq(name):
    """A key and request as certreq writes them: `NEW CERTIFICATE REQUEST`, subject CN=EasyEAP."""
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EasyEAP")])).sign(key, hashes.SHA256())
    return key, csr.public_bytes(serialization.Encoding.PEM).decode().replace("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST")


def _codes(content):
    import re
    found = dict(re.findall(r"^\$(UserCode|ComputerCode) = '([^']*)'", content, re.M))
    return found.get("UserCode") or None, found.get("ComputerCode") or None


def winsetup(api, user):
    """docs/plans/windows-setup.md §6: the setup a console admin downloads, run by a simulated Windows PC."""
    T = api.tenant()
    users = {i["username"]: i for i in api("GET", f"/api/tenants/{T}/identities", params={"page_size": 100})["items"]}
    checks = {}
    pc = "PC-" + user.upper() + "01"
    setup = api("POST", f"/api/tenants/{T}/enrollments/windows-setup", json={"identity_id": users[user]["id"], "wired": True})
    content = setup["content"]
    ucode, ccode = _codes(content)
    checks["file"] = (setup["filename"].endswith(".cmd") and content.startswith("<# :") and "\r\n" in content and "PRIVATE KEY" not in content
                      and bool(ucode) and bool(ccode) and setup["sign_in_mode"] == "machineOrUser")
    issued = {}
    for kind, code, storage in (("user", ucode, "tpm"), ("computer", ccode, "software")):
        key, csr = _certreq(pc)
        res = api("POST", f"/api/enroll/{code}/csr", json={"csr": csr, "key_origin": "device", "device_hint": pc, "key_storage": storage})
        issued[kind] = (key, res)
        again = api.c.post(f"/api/enroll/{code}/csr", json={"csr": csr, "key_origin": "device", "device_hint": pc})
        checks[f"{kind}_code_once"] = again.status_code == 410
    certs = {c["serial"]: c for c in api("GET", f"/api/tenants/{T}/certificates", params={"page_size": 200})["items"]}
    u, c = certs[issued["user"][1]["serial"]], certs[issued["computer"][1]["serial"]]
    checks["purposes"] = u["purpose"] == "user" and c["purpose"] == "device"
    checks["pc_named"] = c["device"]["name"] == pc and u["device"]["id"] == c["device"]["id"] and c["common_name"].lower().startswith(pc.lower())
    checks["key_storage"] = u["key_storage"] == "tpm" and c["key_storage"] == "software"

    # Renewal: nothing before the window; inside it a new certificate, the old one superseded and never renewed twice.
    ckey, cres = issued["computer"]
    nkey, ncsr = _certreq(pc)
    early = api("POST", "/api/enroll/renew", json=_renewal(cres["certificate_pem"], ckey, ncsr))
    checks["not_yet"] = early["renewed"] is False and bool(early["renew_from"])
    tpl = next(t for t in api("GET", f"/api/tenants/{T}/pki")["templates"] if t["purpose"] == "device")
    keep = {k: tpl[k] for k in ("name", "purpose", "key_algorithm", "validity_days", "renew_before_days", "subject_pattern", "san_patterns",
                                "allow_client_keygen", "allow_server_keygen")}
    api("PUT", f"/api/tenants/{T}/pki/templates/{tpl['id']}", json={**keep, "validity_days": 30, "renew_before_days": 180})
    try:
        setup2 = api("POST", f"/api/tenants/{T}/enrollments/windows-setup", json={"identity_id": users[user]["id"], "user_certificate": False})
        _, ccode2 = _codes(setup2["content"])
        checks["computer_only_mode"] = setup2["sign_in_mode"] == "machine" and _codes(setup2["content"])[0] is None
        okey, ocsr = _certreq(pc)
        old = api("POST", f"/api/enroll/{ccode2}/csr", json={"csr": ocsr, "key_origin": "device", "device_hint": pc, "key_storage": "tpm"})
        nkey, ncsr = _certreq(pc)
        bad_sig = _renewal(old["certificate_pem"], nkey, ncsr)  # signed by the wrong key
        checks["wrong_key_refused"] = api.c.post("/api/enroll/renew", json=bad_sig).status_code == 400
        stale = _renewal(old["certificate_pem"], okey, ncsr, signed_at=int(time.time()) - 3600)
        checks["stale_refused"] = api.c.post("/api/enroll/renew", json=stale).status_code == 400
        same_key = _renewal(old["certificate_pem"], okey, ocsr)
        checks["same_key_refused"] = api.c.post("/api/enroll/renew", json=same_key).status_code == 400
        new = api("POST", "/api/enroll/renew", json=_renewal(old["certificate_pem"], okey, ncsr))
        certs = {c["serial"]: c for c in api("GET", f"/api/tenants/{T}/certificates", params={"page_size": 200})["items"]}
        checks["renewed"] = (new["renewed"] is True and certs[old["serial"]]["stored_status"] == "superseded"
                             and certs[new["serial"]]["renewal_of"] == certs[old["serial"]]["id"] and certs[new["serial"]]["key_storage"] == "software"
                             and certs[new["serial"]]["device"]["name"] == pc)
        n2key, n2csr = _certreq(pc)
        checks["renews_once"] = api.c.post("/api/enroll/renew", json=_renewal(old["certificate_pem"], okey, n2csr)).status_code == 400
    finally:
        api("PUT", f"/api/tenants/{T}/pki/templates/{tpl['id']}", json=keep)
    print(json.dumps({"checks": checks, "pc": pc, "cert_pem": new["certificate_pem"],
                      "key_pem": nkey.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()}))


def main():
    cmd = sys.argv[1]
    if cmd == "provision":
        provision(Api(), sys.argv[2])
    elif cmd == "wait":
        wait(Api(), fresh=sys.argv[2:3] == ["fresh"])
    elif cmd == "wait-admin":
        wait_admin(Api())
    elif cmd == "revoke":  # revoke <serial as printed by openssl, e.g. 1A2B…>
        api = Api()
        T = api.tenant()
        want = sys.argv[2].replace(":", "").upper().lstrip("0")
        items = api("GET", f"/api/tenants/{T}/certificates", params={"page_size": 200})["items"]
        match = [c for c in items if c["serial"].replace(":", "").upper().lstrip("0") == want]
        if not match:
            fail(f"no certificate with serial {want} among {len(items)}")
        r = api("POST", f"/api/tenants/{T}/certificates/{match[0]['id']}/revoke", json={"reason": "keyCompromise"})
        print(json.dumps({"revoked": match[0]["serial"], "note": r.get("note")}))
    elif cmd == "sync":
        api = Api()
        T = api.tenant()
        print(json.dumps(api("POST", f"/api/tenants/{T}/directory/sync", json={})))
    elif cmd == "events":
        api = Api()
        T = api.tenant()
        ev = api("GET", f"/api/tenants/{T}/events", params={"hours": 2, "page_size": 50})["items"]
        print(json.dumps([{"at": e["at"], "result": e["result"], "reason": e["reason_code"], "vlan": e["vlan_id"], "user": e.get("username"),
                           "title": (e.get("explanation") or {}).get("title"), "network": e.get("network"), "port": e.get("nas_port_id"),
                           "monitor": e.get("monitor"), "mac": e.get("calling_station_id"), "client": e.get("nas_client_id"),
                           "method": e.get("method"), "device_mac": e.get("mac"), "mac_device": e.get("mac_device_id")} for e in ev]))
    elif cmd == "call":
        api = Api()
        T = api.tenant()
        body = json.loads(sys.argv[4]) if len(sys.argv) > 4 else None
        r = api.c.request(sys.argv[2], f"/api/tenants/{T}{sys.argv[3]}", json=body)
        print(json.dumps({"status": r.status_code, "body": r.json() if r.content and r.headers.get("content-type", "").startswith("application/json") else r.text}))
    elif cmd == "enroll":
        api = Api()
        T = api.tenant()
        users = {i["username"]: i for i in api("GET", f"/api/tenants/{T}/identities", params={"page_size": 100})["items"]}
        en = api("POST", f"/api/tenants/{T}/enrollments", json={"identity_id": users[sys.argv[2]]["id"], "device_name": f"{sys.argv[2]}-{sys.argv[3]}", "platform": sys.argv[3]})
        token = en["link"].split("/t/")[1]
        _, csr = csr_for(sys.argv[2])
        info = api("GET", f"/api/enroll/{token}")
        res = api("POST", f"/api/enroll/{token}/csr", json={"csr": csr, "key_origin": "csr"})
        print(json.dumps({"info": info, "csr": res}))
    elif cmd == "winsetup":
        winsetup(Api(), sys.argv[2])
    else:
        fail(f"unknown command {cmd}")


if __name__ == "__main__":
    main()
