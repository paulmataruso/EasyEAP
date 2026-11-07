"""The console's keytab **Test** (docs/plans/gpo-autoenrollment.md §2.2): get a ticket for HTTP/<console host> from the
domain controller with the directory's bind account, as a PC would, and open it with the uploaded keytab.

Run as a separate process (`python -m app.autoenroll.keytab_test`, JSON on stdin and stdout) because MIT Kerberos
reads its configuration (the tenant's realm and KDC) from the environment once per process.
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

TIMEOUT = 25
_REALM = re.compile(r"^[A-Z0-9](?:[A-Z0-9.-]{0,250}[A-Z0-9])?$")
_KDC = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")  # a host name or IPv4 address: nothing krb5.conf would read as syntax


def run(*, realm: str, kdcs: list[str], user: str, password: str, host: str, keytab: bytes) -> dict:
    """Called by the API. Returns {"ok": bool, "step": str, "message": str}."""
    from app.autoenroll.kerberos import clean_text

    r = _run(realm=realm, kdcs=kdcs, user=user, password=password, host=host, keytab=keytab)
    return {"ok": r.get("ok") is True, "step": clean_text(str(r.get("step", "")), 32), "message": clean_text(str(r.get("message", "")))}


def _run(*, realm: str, kdcs: list[str], user: str, password: str, host: str, keytab: bytes) -> dict:
    kdcs = [k for k in kdcs if _KDC.match(k)][:4]
    if not _REALM.match(realm) or not kdcs:
        return {"ok": False, "step": "directory", "message": "The directory's domain or server names can't be used for Kerberos "
                                                             "(use DNS names or IPv4 addresses)."}
    # On tmpfs where there is one: the keytab is written there for the test.
    shm = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else None  # noqa: S108
    with tempfile.TemporaryDirectory(prefix="easyeap-kt-", dir=shm) as d:
        conf = Path(d) / "krb5.conf"
        kdc_lines = "\n".join(f"        kdc = {k}" for k in kdcs)
        conf.write_text(f"""[libdefaults]
    default_realm = {realm}
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    dns_canonicalize_hostname = false
    udp_preference_limit = 0
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128
[realms]
    {realm} = {{
{kdc_lines}
    }}
""")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": os.environ.get("PYTHONPATH", ""), "KRB5_CONFIG": str(conf),
               "KRB5CCNAME": "MEMORY:easyeap-test", "EASYEAP_KRB_DIR": str(Path(d) / "rt"), "HOME": d}
        payload = json.dumps({"realm": realm, "user": user, "password": password, "host": host,
                              "keytab": base64.b64encode(keytab).decode()})
        try:
            p = subprocess.run([sys.executable, "-m", "app.autoenroll.keytab_test"], input=payload, capture_output=True,
                               text=True, timeout=TIMEOUT, env=env, cwd=str(Path(__file__).resolve().parents[2]))
        except subprocess.TimeoutExpired:
            return {"ok": False, "step": "kdc", "message": f"The domain controller didn't answer Kerberos (88/tcp) within {TIMEOUT} seconds."}
        try:
            return json.loads(p.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError):
            return {"ok": False, "step": "internal", "message": (p.stderr or "The test didn't run.").strip()[-500:]}


def _explain(step: str, text: str, host: str, realm: str) -> str:
    t = text.lower()
    if step == "login":
        if "cannot contact any kdc" in t or "cannot find kdc" in t or "connection refused" in t or "timed out" in t:
            return f"EasyEAP can't reach Kerberos (88/tcp) on the directory's domain controllers. Enrollment doesn't need it, only this test. ({text})"
        if "preauthentication failed" in t or "password incorrect" in t:
            return f"The directory's bind account couldn't sign in with Kerberos. ({text})"
        return f"The directory's bind account couldn't get a Kerberos ticket. ({text})"
    if step == "ticket":
        if "encryption type" in t or "enctype" in t:
            return (f"The domain controller has no AES key for HTTP/{host}, and EasyEAP accepts AES tickets only. Allow AES on "
                    f"the service account and make the keytab again (the service-account script does both). ({text})")
        if "not found in kerberos database" in t or "server not found" in t:
            return (f"The domain has no account with the SPN HTTP/{host}. Run the service-account script, or check for a typo in "
                    f"the console's host name. ({text})")
        return f"The domain controller wouldn't issue a ticket for HTTP/{host}@{realm}. ({text})"
    return text


def _child() -> None:
    import gssapi

    from app.autoenroll import kerberos

    SPNEGO, KRB5 = gssapi.OID.from_int_seq("1.3.6.1.5.5.2"), gssapi.OID.from_int_seq("1.2.840.113554.1.2.2")
    req = json.loads(sys.stdin.read())
    realm, host = req["realm"], req["host"]
    step = "login"
    try:
        name = gssapi.Name(f"{req['user']}@{realm}", gssapi.NameType.kerberos_principal)
        # Acquired for SPNEGO, which Windows uses (Kerberos-only credentials can't be used through SPNEGO), and Kerberos.
        creds = gssapi.raw.acquire_cred_with_password(name, req["password"].encode(), usage="initiate", mechs=[SPNEGO, KRB5]).creds
        step = "ticket"
        target = gssapi.Name(f"HTTP/{host}@{realm}", gssapi.NameType.kerberos_principal)
        ctx = gssapi.SecurityContext(name=target, creds=creds, usage="initiate", mech=SPNEGO)
        token = ctx.step()
    except gssapi.exceptions.GSSError as exc:
        text = kerberos._gss_text(exc)
        if step == "ticket":  # SPNEGO hides why ("cannot find mechanisms to negotiate"): ask Kerberos itself
            text = _krb5_reason(target, creds) or text
        print(json.dumps({"ok": False, "step": step, "message": _explain(step, text, host, realm)}))
        return
    try:
        caller = kerberos.accept(token, base64.b64decode(req["keytab"]), [realm])
    except kerberos.KerberosError as exc:
        print(json.dumps({"ok": False, "step": "keytab", "message": str(exc)}))
        return
    print(json.dumps({"ok": True, "step": "done",
                      "message": f"The domain controller issued a ticket for HTTP/{host} to {caller.principal}, and the keytab opened it."}))


def _krb5_reason(target, creds) -> str | None:
    import gssapi

    from app.autoenroll import kerberos
    try:
        gssapi.SecurityContext(name=target, creds=creds, usage="initiate", mech=gssapi.OID.from_int_seq("1.2.840.113554.1.2.2")).step()
    except gssapi.exceptions.GSSError as exc:
        return kerberos._gss_text(exc)
    return None


if __name__ == "__main__":
    _child()
