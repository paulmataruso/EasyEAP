"""Run by tests/autoenroll/kerberos.sh inside a container with an MIT KDC for TEST.EXAMPLE."""
import os
import subprocess
import sys

import gssapi

from app.autoenroll import kerberos as k

SPNEGO = gssapi.OID.from_int_seq("1.3.6.1.5.5.2")
fails = 0


def check(name, ok, detail=""):
    global fails
    fails += 0 if ok else 1
    print(f"  {'PASS' if ok else 'FAIL'} {name}{'' if ok else ' -- ' + str(detail)}")


BINDING = b"tls-server-end-point:" + bytes(range(32))


def token_as(principal, password, service="HTTP@easyeap.test", binding=None, mech=SPNEGO):
    cache = f"/tmp/cc-{principal.replace('$', '')}"
    r = subprocess.run(["kinit", "-c", cache, principal], input=f"{password}\n", text=True, capture_output=True)
    if r.returncode:
        raise SystemExit(f"kinit {principal}: {r.stderr.strip()}")
    os.environ["KRB5CCNAME"] = cache
    cb = gssapi.raw.ChannelBindings(application_data=binding) if binding else None
    ctx = gssapi.SecurityContext(name=gssapi.Name(service, gssapi.NameType.hostbased_service), usage="initiate", mech=mech,
                                 flags=gssapi.RequirementFlag.mutual_authentication, channel_bindings=cb)
    return ctx.step()


keytab = open("/tmp/http.keytab", "rb").read()
entries = k.parse_keytab(keytab)
s = k.summarize(entries, "easyeap.test")
check("keytab read: principal, realm, AES", s["principal"] == "HTTP/easyeap.test@TEST.EXAMPLE" and not s["problems"] and
      "aes256-cts-hmac-sha1-96" in s["enctypes"], s)
check("a keytab for another name is flagged", k.summarize(entries, "wrong.test")["problems"] != [])

pc = token_as("PC01$", "pc01pass")
c = k.accept(pc, keytab, ["TEST.EXAMPLE"])
check("computer ticket accepted through SPNEGO", c.name == "PC01$" and c.realm == "TEST.EXAMPLE" and c.claims_computer and c.reply, c)

u = k.accept(token_as("nina", "ninapass"), keytab, ["test.example"])
check("user ticket accepted (realm compared case-insensitively)", u.name == "nina" and not u.claims_computer, u)

try:
    k.accept(pc, keytab, ["TEST.EXAMPLE"])
    check("the same token twice is refused (replay cache)", False, "accepted")
except k.KerberosError as e:
    check("the same token twice is refused (replay cache)", e.code == "invalid", e)

try:
    k.accept(token_as("PC01$", "pc01pass"), keytab, ["CORP.EXAMPLE"])
    check("a realm that isn't the tenant's is refused", False, "accepted")
except k.KerberosError as e:
    check("a realm that isn't the tenant's is refused", e.code == "realm", e)

try:
    k.accept(token_as("PC01$", "pc01pass"), open("/tmp/wrong.keytab", "rb").read(), ["TEST.EXAMPLE"])
    check("another tenant's keytab can't read the ticket", False, "accepted")
except k.KerberosError as e:
    check("another tenant's keytab can't read the ticket", e.code in ("keytab", "invalid"), e)

b = k.accept(token_as("PC01$", "pc01pass", binding=BINDING), keytab, ["TEST.EXAMPLE"], binding=BINDING)
check("a ticket bound to this TLS channel is accepted as bound", b.channel_bound, b)
nb = k.accept(token_as("PC01$", "pc01pass"), keytab, ["TEST.EXAMPLE"], binding=BINDING)
check("a ticket without a channel binding is accepted, reported unbound", not nb.channel_bound, nb)
try:
    k.accept(token_as("PC01$", "pc01pass", binding=b"tls-server-end-point:" + bytes(32)), keytab, ["TEST.EXAMPLE"], binding=BINDING)
    check("a ticket bound to another TLS channel is refused", False, "accepted")
except k.KerberosError as e:
    check("a ticket bound to another TLS channel is refused", e.code == "binding", e)
# What Windows sends: SPNEGO NegTokenInit whose mechTypes list Microsoft's Kerberos OID first, then the standard one,
# with the Kerberos AP-REQ as the optimistic mechToken. MIT can't initiate that itself, so it's assembled here.
from app.autoenroll.cms import explicit, octets, oid, seq, tlv  # noqa: E402

raw = token_as("PC01$", "pc01pass", mech=gssapi.MechType.kerberos)
neg = explicit(0, seq(explicit(0, seq(oid("1.2.840.48018.1.2.2"), oid("1.2.840.113554.1.2.2"))), explicit(2, octets(raw))))
windows_like = tlv(0x60, oid("1.3.6.1.5.5.2") + neg)
ms = k.accept(windows_like, keytab, ["TEST.EXAMPLE"])
check("Windows-style SPNEGO (Microsoft's Kerberos OID first) is accepted", ms.name == "PC01$", ms)

ntlm = b"NTLMSSP\x00\x01\x00\x00\x00" + b"\x00" * 24
try:
    k.accept(ntlm, keytab, ["TEST.EXAMPLE"])
    check("NTLM is refused with a reason", False, "accepted")
except k.KerberosError as e:
    check("NTLM is refused with a reason", e.code == "ntlm" and "SPN" in str(e), e)

files = os.listdir(os.environ["EASYEAP_KRB_DIR"])
mode = oct(os.stat(os.path.join(os.environ["EASYEAP_KRB_DIR"], [f for f in files if f.endswith(".keytab")][0])).st_mode & 0o777)
check("keytab written 0600 to the runtime directory", mode == "0o600", mode)
print(f"kerberos checks: {fails} failure(s)")
sys.exit(1 if fails else 0)
