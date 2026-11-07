"""Group Policy autoenrollment as a Windows PC does it, against the lab: Kerberos (SPNEGO, bound to the TLS
connection) from the Samba AD KDC, MS-XCEP GetPolicies, then MS-WSTEP certificate requests, through the proxy.

Independent of EasyEAP's own code: the SOAP, DER and CMC here are written from the specifications, so a mistake on
EasyEAP's side isn't mirrored here.

    python3 autoenroll_client.py <scenario> <principal> <password> [options as JSON]

Prints one JSON object: {"checks": {name: bool}, "notes": {...}, ...}.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import ssl
import sys
import uuid
import xml.etree.ElementTree as ET

import gssapi
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID

HOST = os.environ.get("AE_HOST", "easyeap.lab.easyeap.test")
REALM = os.environ.get("AE_REALM", "LAB.EASYEAP.TEST")
SLUG = os.environ.get("AE_SLUG", "e2e-lab")
CA_FILE = os.environ.get("AE_TLS_CA", "/t/tls.crt")
SPNEGO = gssapi.OID.from_int_seq("1.3.6.1.5.5.2")
NS = {"s": "http://www.w3.org/2003/05/soap-envelope", "a": "http://www.w3.org/2005/08/addressing",
      "x": "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy", "t": "http://docs.oasis-open.org/ws-sx/ws-trust/200512",
      "w": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
      "e": "http://schemas.microsoft.com/windows/pki/2009/01/enrollment", "xsi": "http://www.w3.org/2001/XMLSchema-instance"}

# ── DER, by hand ─────────────────────────────────────────────────────────────


def tlv(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    ln = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(ln)]) + ln + body


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def der_int(v: int) -> bytes:
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True)
    return tlv(0x02, b)


def der_oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    out = bytes([40 * arcs[0] + arcs[1]])
    for a in arcs[2:]:
        chunk = [a & 0x7F]
        a >>= 7
        while a:
            chunk.append(0x80 | (a & 0x7F))
            a >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, out)


def template_ext(oid: str, major: int, minor: int) -> bytes:
    """CertificateTemplate ::= SEQUENCE { templateID OID, templateMajorVersion INTEGER, templateMinorVersion INTEGER }"""
    return seq(der_oid(oid), der_int(major), der_int(minor))


def read(buf: bytes, i: int = 0) -> tuple[int, int, int]:
    """(tag, content start, content end) of the TLV at i."""
    tag, ln = buf[i], buf[i + 1]
    i += 2
    if ln & 0x80:
        k = ln & 0x7F
        ln = int.from_bytes(buf[i:i + k], "big")
        i += k
    return tag, i, i + ln


def kids(buf: bytes, s: int, e: int):
    while s < e:
        tag, cs, ce = read(buf, s)
        yield tag, s, cs, ce
        s = ce


# ── A PC's requests ──────────────────────────────────────────────────────────


def csr(key, *, template: tuple[str, int, int] | None, machine: str | None = None) -> bytes:
    b = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
    if template:
        b = b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.311.21.7"), template_ext(*template)), critical=False)
    b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    req = b.sign(key, hashes.SHA256())
    return req.public_bytes(serialization.Encoding.DER)


def cmc(csr_der: bytes, body_part: int = 7) -> bytes:
    """A CMC full PKI request as Windows sends it for a user: ContentInfo(SignedData(PKIData{tcr [0] {id, csr}})),
    eContentType id-cct-PKIData. (Windows signs the SignedData with the request key; the PKCS#10 inside carries
    the proof of possession that matters, so this one has no signer.)"""
    tcr = tlv(0xA0, der_int(body_part) + csr_der)
    pki_data = seq(seq(), seq(tcr), seq(), seq())
    encap = seq(der_oid("1.3.6.1.5.5.7.12.2"), tlv(0xA0, tlv(0x04, pki_data)))
    signed = seq(der_int(3), tlv(0x31, b""), encap, tlv(0x31, b""))
    return seq(der_oid("1.2.840.113549.1.7.2"), tlv(0xA0, signed))


def get_policies() -> bytes:
    return f"""<s:Envelope xmlns:s="{NS['s']}" xmlns:a="{NS['a']}"><s:Header>
<a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies</a:Action>
<a:MessageID>urn:uuid:{uuid.uuid4()}</a:MessageID><a:To s:mustUnderstand="1">https://{HOST}/cep/{SLUG}</a:To></s:Header>
<s:Body xmlns:xsi="{NS['xsi']}"><GetPolicies xmlns="{NS['x']}"><client><lastUpdate>0001-01-01T00:00:00</lastUpdate>
<preferredLanguage xsi:nil="true"/></client><requestFilter xsi:nil="true"/></GetPolicies></s:Body></s:Envelope>""".encode()


def rst(token: bytes, context: dict[str, str]) -> tuple[bytes, str]:
    mid = f"urn:uuid:{uuid.uuid4()}"
    b64 = base64.b64encode(token).decode()
    wrapped = "\r\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    items = "".join(f'<ContextItem Name="{k}"><Value>{v}</Value></ContextItem>' for k, v in context.items())
    body = f"""<s:Envelope xmlns:a="{NS['a']}" xmlns:s="{NS['s']}"><s:Header>
<a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
<a:MessageID>{mid}</a:MessageID></s:Header><s:Body xmlns:xsi="{NS['xsi']}">
<RequestSecurityToken PreferredLanguage="en-US" xmlns="{NS['t']}">
<TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</TokenType>
<RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</RequestType>
<BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
 EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary" xmlns="{NS['w']}">{wrapped}</BinarySecurityToken>
<AdditionalContext xmlns="http://schemas.xmlsoap.org/ws/2006/12/authorization">{items}</AdditionalContext>
</RequestSecurityToken></s:Body></s:Envelope>"""
    return body.encode(), mid


# ── HTTP Negotiate over one TLS connection ───────────────────────────────────


class Pc:
    def __init__(self, principal: str, password: str):
        name = gssapi.Name(f"{principal}@{REALM}", gssapi.NameType.kerberos_principal)
        # For SPNEGO, as Windows uses: credentials acquired for Kerberos alone can't be used through SPNEGO.
        self.creds = gssapi.raw.acquire_cred_with_password(name, password.encode(), usage="initiate",
                                                           mechs=[SPNEGO, gssapi.OID.from_int_seq("1.2.840.113554.1.2.2")]).creds
        self.tls = ssl.create_default_context(cafile=CA_FILE)
        self.conn = http.client.HTTPSConnection(HOST, int(os.environ.get("AE_PORT", "443")), context=self.tls, timeout=30)
        self.conn.connect()
        peer = self.conn.sock.getpeercert(binary_form=True)
        # RFC 5929 tls-server-end-point: SHA-256 for a certificate signed with SHA-256.
        self.binding = b"tls-server-end-point:" + hashlib.sha256(peer).digest()

    def token(self, binding: bytes | None | str = "conn") -> tuple[bytes, gssapi.SecurityContext]:
        target = gssapi.Name(f"HTTP/{HOST}@{REALM}", gssapi.NameType.kerberos_principal)
        cb = self.binding if binding == "conn" else binding
        ctx = gssapi.SecurityContext(name=target, creds=self.creds, usage="initiate", mech=SPNEGO,
                                     flags=gssapi.RequirementFlag.mutual_authentication | gssapi.RequirementFlag.out_of_sequence_detection,
                                     channel_bindings=gssapi.raw.ChannelBindings(application_data=cb) if cb else None)
        return ctx.step(), ctx

    def post(self, path: str, body: bytes, *, auth: bool = True, binding: bytes | None | str = "conn") -> tuple[int, dict, bytes, object]:
        headers = {"Content-Type": "application/soap+xml; charset=utf-8"}
        ctx = None
        if auth:
            tok, ctx = self.token(binding)
            headers["Authorization"] = "Negotiate " + base64.b64encode(tok).decode()
        self.conn.request("POST", path, body=body, headers=headers)
        r = self.conn.getresponse()
        data = r.read()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data, ctx


def fault(data: bytes) -> dict:
    root = ET.fromstring(data)
    f = root.find("s:Body/s:Fault", NS)
    if f is None:
        return {}
    d = f.find("s:Detail/e:CertificateEnrollmentWSDetail", NS)
    return {"reason": (f.findtext("s:Reason/s:Text", "", NS) or "").strip(), "action": root.findtext("s:Header/a:Action", "", NS),
            "code": int(d.findtext("e:ErrorCode", "0", NS)) & 0xFFFFFFFF if d is not None else None,
            "invalid": d.findtext("e:InvalidRequest", "", NS) if d is not None else None,
            "request_id": d.findtext("e:RequestID", "", NS) if d is not None else None}


def policies(data: bytes) -> dict:
    resp = ET.fromstring(data).find("s:Body/x:GetPoliciesResponse", NS)
    oids = {o.findtext("x:oIDReferenceID", "", NS): (o.findtext("x:value", "", NS), o.findtext("x:group", "", NS)) for o in resp.findall("x:oIDs/x:oID", NS)}
    out = {"policy_id": resp.findtext("x:response/x:policyID", "", NS), "templates": [], "cas": []}
    for p in resp.findall("x:response/x:policies/x:policy", NS):
        a = p.find("x:attributes", NS)
        exts = {oids[e.findtext("x:oIDReference", "", NS)][0]: base64.b64decode(e.findtext("x:value", "", NS)) for e in a.findall("x:extensions/x:extension", NS)}
        out["templates"].append({
            "cn": a.findtext("x:commonName", "", NS), "oid": oids[p.findtext("x:policyOIDReference", "", NS)][0],
            "oid_group": oids[p.findtext("x:policyOIDReference", "", NS)][1],
            "major": int(a.findtext("x:revision/x:majorRevision", "0", NS)), "minor": int(a.findtext("x:revision/x:minorRevision", "0", NS)),
            "general": int(a.findtext("x:generalFlags", "0", NS)), "enroll": int(a.findtext("x:enrollmentFlags", "0", NS)),
            "subject": int(a.findtext("x:subjectNameFlags", "0", NS)), "min_key": int(a.findtext("x:privateKeyAttributes/x:minimalKeyLength", "0", NS)),
            "validity": int(a.findtext("x:certificateValidity/x:validityPeriodSeconds", "0", NS)),
            "providers": [x.text for x in a.findall("x:privateKeyAttributes/x:cryptoProviders/x:provider", NS)],
            "template_ext": exts.get("1.3.6.1.4.1.311.21.7"),
        })
    for ca in resp.findall("x:cAs/x:cA", NS):
        out["cas"].append({"uri": ca.findtext("x:uris/x:cAURI/x:uri", "", NS), "auth": ca.findtext("x:uris/x:cAURI/x:clientAuthentication", "", NS),
                           "cert": base64.b64decode(ca.findtext("x:certificate", "", NS))})
    return out


def issued(data: bytes) -> dict:
    root = ET.fromstring(data)
    r = root.find("s:Body/t:RequestSecurityTokenResponseCollection/t:RequestSecurityTokenResponse", NS)
    pkcs7_der = base64.b64decode(r.findtext("w:BinarySecurityToken", "", NS))
    leaf = base64.b64decode(r.findtext("t:RequestedSecurityToken/w:BinarySecurityToken", "", NS))
    return {"disposition": r.findtext("e:DispositionMessage", "", NS), "request_id": r.findtext("e:RequestID", "", NS),
            "relates_to": root.findtext("s:Header/a:RelatesTo", "", NS), "pkcs7": pkcs7_der, "leaf": leaf}


def cmc_status(pkcs7_der: bytes) -> tuple[int | None, int | None]:
    """(status, bodyPartID) from the PKIResponse in the response's SignedData (id-cct-PKIResponse)."""
    _, s, e = read(pkcs7_der)
    it = kids(pkcs7_der, s, e)
    next(it)  # contentType
    _, _, cs, _ce = next(it)  # [0]
    _, ss, se = read(pkcs7_der, cs)  # SignedData
    parts = list(kids(pkcs7_der, ss, se))
    encap = parts[2]
    ep = list(kids(pkcs7_der, encap[2], encap[3]))
    if pkcs7_der[ep[0][2]:ep[0][3]] != der_oid("1.3.6.1.5.5.7.12.3")[2:]:
        return None, None
    _, os_, oe = read(pkcs7_der, ep[1][2])  # OCTET STRING
    _, rs, re_ = read(pkcs7_der, os_)       # PKIResponse
    controls = next(kids(pkcs7_der, rs, re_))
    for _, _, ts, te in kids(pkcs7_der, controls[2], controls[3]):  # TaggedAttribute
        f = list(kids(pkcs7_der, ts, te))
        if pkcs7_der[f[1][2]:f[1][3]] == der_oid("1.3.6.1.5.5.7.7.1")[2:]:  # id-cmc-statusInfo
            _, vs, ve = f[2][0], f[2][2], f[2][3]
            si = next(kids(pkcs7_der, vs, ve))
            sf = list(kids(pkcs7_der, si[2], si[3]))
            status = int.from_bytes(pkcs7_der[sf[0][2]:sf[0][3]], "big")
            ids = next(kids(pkcs7_der, sf[1][2], sf[1][3]))
            return status, int.from_bytes(pkcs7_der[ids[2]:ids[3]], "big")
    return None, None


# ── Scenarios ────────────────────────────────────────────────────────────────


def enroll_flow(pc: Pc, kind: str, opts: dict) -> dict:
    checks, notes = {}, {}
    st, h, data, _ = pc.post(f"/cep/{SLUG}", get_policies(), auth=False)
    checks["challenge"] = st == 401 and h.get("www-authenticate", "").strip() == "Negotiate"
    st, h, data, ctx = pc.post(f"/cep/{SLUG}", get_policies())
    notes["cep_status"] = st
    if st != 200:
        notes["cep_body"] = data.decode(errors="replace")[:600]
        return {"checks": checks, "notes": notes}
    reply = h.get("www-authenticate", "")
    try:
        ctx.step(base64.b64decode(reply.split(" ", 1)[1]))
        checks["mutual_auth"] = ctx.complete
    except Exception as exc:  # noqa: BLE001
        checks["mutual_auth"], notes["mutual_auth"] = False, str(exc)
    pol = policies(data)
    want = "EasyEAP-Computer" if kind == "computer" else "EasyEAP-User"
    tpls = [t for t in pol["templates"] if t["cn"] == want]
    checks["one_template"] = [t["cn"] for t in pol["templates"]] == [want]
    if not tpls:
        notes["templates"] = [t["cn"] for t in pol["templates"]]
        return {"checks": checks, "notes": notes}
    t = tpls[0]
    notes["template"] = {k: v for k, v in t.items() if k not in ("template_ext",)}
    checks["template_flags"] = (t["general"] == (0x40 if kind == "computer" else 0) and t["enroll"] & 0x20 and t["min_key"] == 2048
                                and t["subject"] == (0x18000000 if kind == "computer" else 0x82000000) and t["oid_group"] == "9"
                                and "Microsoft Platform Crypto Provider" in t["providers"])
    checks["template_ext"] = t["template_ext"] == template_ext(t["oid"], t["major"], t["minor"])
    checks["ca"] = len(pol["cas"]) == 1 and pol["cas"][0]["auth"] == "2" and pol["cas"][0]["uri"] == f"https://{HOST}/ces/{SLUG}"
    ca = x509.load_der_x509_certificate(pol["cas"][0]["cert"])
    ces = "/ces/" + SLUG

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    req = csr(key, template=(t["oid"], t["major"], t["minor"]))
    machine = opts.get("machine", "")
    token = cmc(req) if kind == "user" else req
    body, mid = rst(token, {"ccm": machine} if machine else {})
    st, h, data, _ = pc.post(ces, body)
    notes["ces_status"] = st
    if st != 200:
        notes["ces_fault"] = fault(data) if data.startswith(b"<") else data.decode(errors="replace")[:400]
        return {"checks": checks, "notes": notes}
    got = issued(data)
    leaf = x509.load_der_x509_certificate(got["leaf"])
    checks["issued"] = got["disposition"] == "Issued" and got["relates_to"] == mid and got["request_id"].isdigit()
    checks["same_key"] = leaf.public_key().public_numbers() == key.public_key().public_numbers()
    try:
        leaf.verify_directly_issued_by(ca)  # the CA in the policy signed it
        checks["issuer"] = True
    except (ValueError, TypeError, Exception) as exc:  # noqa: BLE001
        checks["issuer"], notes["issuer"] = False, str(exc)
    ku = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    checks["key_usage"] = ku.digital_signature and not ku.key_encipherment and not ku.key_cert_sign
    checks["eku"] = list(leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    checks["not_ca"] = not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    # DER of the extension value, whether cryptography decodes it (MSCertificateTemplate) or not
    tx = leaf.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.311.21.7")).value.public_bytes()
    checks["cert_template_ext"] = tx == template_ext(t["oid"], t["major"], t["minor"])
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    cn = leaf.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    if kind == "computer":
        checks["names"] = cn == opts["dns"] and san.get_values_for_type(x509.DNSName) == [opts["dns"]]
    else:
        upns = [o.value for o in san.get_values_for_type(x509.OtherName) if o.type_id.dotted_string == "1.3.6.1.4.1.311.20.2.3"]
        checks["names"] = cn == opts["upn"] and len(upns) == 1 and opts["upn"].encode() in upns[0]
    certs = pkcs7.load_der_pkcs7_certificates(got["pkcs7"])
    checks["chain"] = got["leaf"] in [c.public_bytes(serialization.Encoding.DER) for c in certs] and any(c.subject == ca.subject for c in certs)
    status, part = cmc_status(got["pkcs7"])
    notes["cmc"] = {"status": status, "body_part": part}
    checks["cmc_success"] = status == 0 and part == (7 if kind == "user" else 1)
    notes["serial"] = format(leaf.serial_number, "x")
    if opts.get("save"):
        with open(opts["save"] + ".pem", "w") as f:
            f.write(leaf.public_bytes(serialization.Encoding.PEM).decode())
        with open(opts["save"] + ".key", "w") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
        os.chmod(opts["save"] + ".key", 0o644)
    notes["template_oid"], notes["template_rev"] = t["oid"], [t["major"], t["minor"]]
    return {"checks": checks, "notes": notes}


def refusals(pc: Pc, opts: dict) -> dict:
    """With the computer's own credentials: what EasyEAP must refuse."""
    checks, notes = {}, {}
    st, _, data, _ = pc.post(f"/cep/{SLUG}", get_policies(), binding=None)
    notes["unbound"] = (st, fault(data).get("reason") if data.startswith(b"<") else None)
    checks["unbound_refused"] = st == 500 and "bound" in (notes["unbound"][1] or "")
    st, _, data, _ = pc.post(f"/cep/{SLUG}", get_policies(), binding=b"tls-server-end-point:" + bytes(32))
    notes["wrong_binding"] = (st, fault(data).get("reason") if data.startswith(b"<") else None)
    checks["wrong_binding_refused"] = st in (401, 500) and st != 200
    # The user template's OID in a computer's request.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    body, _ = rst(csr(key, template=(opts["user_oid"], 100, 0)), {})
    st, _, data, _ = pc.post(f"/ces/{SLUG}", body)
    f = fault(data) if data.startswith(b"<") else {}
    notes["other_template"] = (st, f)
    checks["other_template_refused"] = st == 500 and f.get("code") == 0x80094012 and f.get("invalid") == "false"
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505 — must be refused
    body, _ = rst(csr(weak, template=None), {})
    st, _, data, _ = pc.post(f"/ces/{SLUG}", body)
    f = fault(data) if data.startswith(b"<") else {}
    notes["weak_key"] = (st, f)
    checks["weak_key_refused"] = st == 500 and f.get("code") == 0x80094811 and f.get("invalid") == "true"
    st, _, data, _ = pc.post(f"/ces/{SLUG}", b"<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'><s:Body><x/></s:Body></s:Envelope>")
    checks["garbage_refused"] = st == 400
    return {"checks": checks, "notes": notes}


def cep_only(pc: Pc) -> dict:
    st, _, data, _ = pc.post(f"/cep/{SLUG}", get_policies())
    out = {"status": st}
    if data.startswith(b"<"):
        out["fault"] = fault(data)
        if st == 200:
            out["templates"] = [t["cn"] for t in policies(data)["templates"]]
    return {"checks": {}, "notes": out}


def main() -> None:
    scenario, principal, password = sys.argv[1:4]
    opts = json.loads(sys.argv[4]) if len(sys.argv) > 4 else {}
    try:
        pc = Pc(principal, password)
    except gssapi.exceptions.GSSError as exc:
        print(json.dumps({"checks": {"kinit": False}, "notes": {"kinit": exc.gen_message()}}))
        return
    if scenario == "computer":
        out = enroll_flow(pc, "computer", opts)
    elif scenario == "user":
        out = enroll_flow(pc, "user", opts)
    elif scenario == "refusals":
        out = refusals(pc, opts)
    else:
        out = cep_only(pc)
    print(json.dumps(out, default=str))


if __name__ == "__main__":
    main()
