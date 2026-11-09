"""Group Policy autoenrollment: SOAP messages (MS-XCEP, MS-WSTEP), keytabs, the service's rules and the /cep and /ces
flows (Kerberos and the database mocked; the lab test in tests/e2e covers them for real)."""
from __future__ import annotations

import base64
import struct
import uuid
import xml.etree.ElementTree as ET
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.autoenroll import cms, kerberos, soap
from app.autoenroll import service as svc

FIXTURES = Path(__file__).parent / "fixtures"
NS = {"s": soap.NS_S, "a": soap.NS_A, "x": soap.NS_XCEP, "t": soap.NS_WST, "w": soap.NS_WSSE, "e": soap.NS_ENROLL,
      "xsi": "http://www.w3.org/2001/XMLSchema-instance"}

# MS-XCEP 4.1.1.1, with the spec's line wrapping undone.
GET_POLICIES = b"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
  <s:Header>
    <a:Action s:mustUnderstand="1">
      http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies
    </a:Action>
    <a:MessageID>
      urn:uuid:5fb5f6fd-4709-414b-8afa-0c05f6686d1c
    </a:MessageID>
    <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
  </s:Header>
  <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema">
    <GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
      <client><lastUpdate>0001-01-01T00:00:00</lastUpdate><preferredLanguage xsi:nil="true"></preferredLanguage></client>
      <requestFilter xsi:nil="true"></requestFilter>
    </GetPolicies>
  </s:Body>
</s:Envelope>"""


def rst(token: bytes, *, context: dict[str, str] | None = None, request_type: str = soap.REQUEST_ISSUE, wrap: int = 64) -> bytes:
    """MS-WSTEP 4.1.1.1 with the token wrapped as Windows wraps it, plus AdditionalContext as autoenrollment sends it."""
    b64 = base64.b64encode(token).decode()
    wrapped = "\n".join(b64[i:i + wrap] for i in range(0, len(b64), wrap))
    items = "".join(f'<ContextItem Name="{k}"><Value>{v}</Value></ContextItem>' for k, v in (context or {}).items())
    ctx = f'<AdditionalContext xmlns="{soap.NS_AUTH}">{items}</AdditionalContext>' if items else ""
    return f"""<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
<s:Header><a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
<a:MessageID>urn:uuid:b5d1a601-5091-4a7d-b34b-5204c18b5919</a:MessageID></s:Header>
<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<RequestSecurityToken xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
<TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</TokenType>
<RequestType>{request_type}</RequestType>
<BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"
 ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7"
 xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">{wrapped}</BinarySecurityToken>
{ctx}<RequestID xsi:nil="true" xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment"/>
</RequestSecurityToken></s:Body></s:Envelope>""".encode()


# ── SOAP parsing ─────────────────────────────────────────────────────────────


def test_get_policies_from_the_spec():
    gp = soap.parse_get_policies(GET_POLICIES)
    assert gp.message_id == "urn:uuid:5fb5f6fd-4709-414b-8afa-0c05f6686d1c"
    assert gp.policy_oids == []


def test_get_policies_filter():
    body = GET_POLICIES.replace(b'<requestFilter xsi:nil="true"></requestFilter>',
                                b"<requestFilter><policyOIDs><oid>1.3.6.1.4.1.311.21.8.1.2</oid><oid> 1.2.3 </oid></policyOIDs></requestFilter>")
    assert soap.parse_get_policies(body).policy_oids == ["1.3.6.1.4.1.311.21.8.1.2", "1.2.3"]


@pytest.mark.parametrize(("body", "message"), [
    (b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>', "Document type"),
    (b"<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'><s:Body>" + b" " * 70000 + b"</s:Body></s:Envelope>", "64 KiB"),
    (b"<Envelope><Body/></Envelope>", "SOAP 1.2"),
    (b"<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'><s:Body>", "well-formed"),
    (b"<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'><s:Body><Other/></s:Body></s:Envelope>", "GetPolicies"),
])
def test_get_policies_refusals(body, message):
    with pytest.raises(soap.SoapError, match=message):
        soap.parse_get_policies(body)


def test_rst_with_wrapped_token_and_context():
    token = (FIXTURES / "wstep-spec-request.der").read_bytes()
    req = soap.parse_rst(rst(token, context={"ccm": "pc01.corp.example", "rmd": "PC01"}))
    assert req.token == token
    assert req.request_type == soap.REQUEST_ISSUE
    assert req.message_id == "urn:uuid:b5d1a601-5091-4a7d-b34b-5204c18b5919"
    assert req.context == {"ccm": "pc01.corp.example", "rmd": "PC01"}
    assert cms.parse_request(req.token).form == "pkcs10"


def test_rst_refusals():
    with pytest.raises(soap.SoapError, match="base64"):
        soap.parse_rst(rst(b"x").replace(b"eA==", b"e!A=="))
    with pytest.raises(soap.SoapError, match="RequestSecurityToken"):
        soap.parse_rst(GET_POLICIES)


# ── SOAP responses ───────────────────────────────────────────────────────────


def _ca() -> tuple[bytes, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuing CA")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(7)
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=900))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER), key


def _tpl(kind: str, **kw) -> SimpleNamespace:
    base = {"id": uuid.uuid4(), "autoenroll_kind": kind, "name": svc.TEMPLATE_NAMES[kind],
            "template_oid": f"1.3.6.1.4.1.311.21.8.1.2.3.4.5.6.{100 if kind == 'computer' else 200}.1", "revision_major": 100,
            "revision_minor": 0, "validity_days": 365, "renew_before_days": 42}
    return SimpleNamespace(**{**base, **kw})


def test_policies_response_shape():
    ca_der, _ = _ca()
    tpls = [svc.template_policy(_tpl("computer")), svc.template_policy(_tpl("user", revision_major=101, revision_minor=3))]
    xml = soap.get_policies_response(relates_to="urn:uuid:1", policy_id="{ABC}", friendly_name="EasyEAP (Corp)",
                                     ces_uri="https://easyeap.corp.example/ces/corp", ca_der=ca_der, templates=tpls)
    root = ET.fromstring(xml)
    assert root.find("s:Header/a:Action", NS).text == soap.ACTION_GET_POLICIES_RESPONSE
    assert root.find("s:Header/a:RelatesTo", NS).text == "urn:uuid:1"
    resp = root.find("s:Body/x:GetPoliciesResponse", NS)
    assert resp.find("x:response/x:policyID", NS).text == "{ABC}"
    policies = resp.findall("x:response/x:policies/x:policy", NS)
    assert len(policies) == 2

    oids = {o.find("x:oIDReferenceID", NS).text: (o.find("x:value", NS).text, int(o.find("x:group", NS).text))
            for o in resp.findall("x:oIDs/x:oID", NS)}
    computer, user = (p.find("x:attributes", NS) for p in policies)
    assert computer.find("x:commonName", NS).text == "EasyEAP-Computer"
    assert computer.find("x:policySchema", NS).text == "3"
    assert int(computer.find("x:generalFlags", NS).text) == soap.GENERAL_MACHINE
    assert int(user.find("x:generalFlags", NS).text) == 0
    assert int(computer.find("x:subjectNameFlags", NS).text) == 0x18000000
    assert int(user.find("x:subjectNameFlags", NS).text) == 0x82000000
    assert int(computer.find("x:enrollmentFlags", NS).text) == 0x420
    assert computer.find("x:certificateValidity/x:validityPeriodSeconds", NS).text == str(365 * 86400)
    assert computer.find("x:certificateValidity/x:renewalPeriodSeconds", NS).text == str(42 * 86400)
    assert user.find("x:revision/x:majorRevision", NS).text == "101" and user.find("x:revision/x:minorRevision", NS).text == "3"
    assert [p.text for p in computer.findall("x:privateKeyAttributes/x:cryptoProviders/x:provider", NS)] == list(soap.PROVIDERS)
    assert computer.find("x:privateKeyAttributes/x:minimalKeyLength", NS).text == "2048"
    # Every reference resolves, in the right group: template 9, algorithm 3, hash 1, extensions 6.
    assert oids[policies[0].find("x:policyOIDReference", NS).text] == ("1.3.6.1.4.1.311.21.8.1.2.3.4.5.6.100.1", 9)
    assert oids[computer.find("x:privateKeyAttributes/x:algorithmOIDReference", NS).text] == (soap.OID_RSA, 3)
    assert oids[computer.find("x:hashAlgorithmOIDReference", NS).text] == (soap.OID_SHA256, 1)
    exts = {oids[e.find("x:oIDReference", NS).text][0]: (e.find("x:critical", NS).text, base64.b64decode(e.find("x:value", NS).text))
            for e in computer.findall("x:extensions/x:extension", NS)}
    assert all(oids[e.find("x:oIDReference", NS).text][1] == 6 for e in computer.findall("x:extensions/x:extension", NS))
    assert exts[soap.OID_KEY_USAGE] == ("true", bytes.fromhex("03020780"))
    assert exts[soap.OID_TEMPLATE_EXT] == ("false", cms.template_extension("1.3.6.1.4.1.311.21.8.1.2.3.4.5.6.100.1", 100, 0))
    assert exts[soap.OID_EKU][1] == cms.seq(cms.oid("1.3.6.1.5.5.7.3.2"))
    # One CA: Kerberos (2), the enrollment URL, its certificate.
    ca = resp.find("x:cAs/x:cA", NS)
    assert ca.find("x:uris/x:cAURI/x:clientAuthentication", NS).text == "2"
    assert ca.find("x:uris/x:cAURI/x:uri", NS).text == "https://easyeap.corp.example/ces/corp"
    assert base64.b64decode(ca.find("x:certificate", NS).text) == ca_der
    assert {p.find("x:cAs/x:cAReference", NS).text for p in policies} == {ca.find("x:cAReferenceID", NS).text}


def test_policies_response_with_nothing_offered():
    xml = soap.get_policies_response(relates_to="", policy_id="{ABC}", friendly_name="x", ces_uri="https://h/ces/x", ca_der=b"\x30\x00",
                                     templates=[])
    resp = ET.fromstring(xml).find("s:Body/x:GetPoliciesResponse", NS)
    for path in ("x:response/x:policies", "x:cAs", "x:oIDs"):
        assert resp.find(path, NS).get(f"{{{NS['xsi']}}}nil") == "true"


def test_names_are_escaped():
    xml = soap.get_policies_response(relates_to="urn:<x>&", policy_id="{A}", friendly_name="R&D <lab>", ces_uri="https://h/ces/x",
                                     ca_der=b"\x30\x00", templates=[])
    root = ET.fromstring(xml)
    assert root.find("s:Body/x:GetPoliciesResponse/x:response/x:policyFriendlyName", NS).text == "R&D <lab>"
    assert root.find("s:Header/a:RelatesTo", NS).text == "urn:<x>&"


def test_issued_response_and_fault():
    xml = soap.issued_response(relates_to="urn:uuid:9", request_id=42, response_der=b"\x30\x03\x02\x01\x01", certificate_der=b"\x30\x00")
    root = ET.fromstring(xml)
    assert root.find("s:Header/a:Action", NS).text == soap.ACTION_RSTRC
    r = root.find("s:Body/t:RequestSecurityTokenResponseCollection/t:RequestSecurityTokenResponse", NS)
    assert r.find("e:DispositionMessage", NS).text == "Issued"
    assert r.find("e:RequestID", NS).text == "42"
    assert base64.b64decode(r.find("w:BinarySecurityToken", NS).text) == b"\x30\x03\x02\x01\x01"
    assert base64.b64decode(r.find("t:RequestedSecurityToken/w:BinarySecurityToken", NS).text) == b"\x30\x00"

    f = ET.fromstring(soap.wstep_fault(relates_to="urn:uuid:9", reason="No <way>", error_code=soap.CERTSRV_E_TEMPLATE_DENIED,
                                       invalid_request=True, request_id=43))
    assert f.find("s:Header/a:Action", NS).text == soap.ACTION_WSTEP_FAULT
    fault = f.find("s:Body/s:Fault", NS)
    assert fault.find("s:Reason/s:Text", NS).text == "No <way>"
    detail = fault.find("s:Detail/e:CertificateEnrollmentWSDetail", NS)
    assert int(detail.find("e:ErrorCode", NS).text) == 0x80094012 - (1 << 32)  # signed, as Windows reads it
    assert detail.find("e:InvalidRequest", NS).text == "true"
    assert detail.find("e:RequestID", NS).text == "43"


# ── Keytabs ──────────────────────────────────────────────────────────────────


def keytab(*entries: tuple[str, str, int, int]) -> bytes:
    """An MIT keytab (0x0502) with (principal, realm, kvno, enctype) entries and random keys."""
    out = b"\x05\x02"
    for principal, realm, kvno, enctype in entries:
        comps = principal.split("/")
        e = struct.pack(">H", len(comps)) + struct.pack(">H", len(realm)) + realm.encode()
        e += b"".join(struct.pack(">H", len(c)) + c.encode() for c in comps)
        e += struct.pack(">IIB", 1, 1700000000, kvno & 0xFF) + struct.pack(">HH", enctype, 32) + bytes(32) + struct.pack(">I", kvno)
        out += struct.pack(">i", len(e)) + e
    return out


def test_keytab_summary():
    data = keytab(("HTTP/easyeap.corp.example", "CORP.EXAMPLE", 3, 18), ("HTTP/easyeap.corp.example", "CORP.EXAMPLE", 3, 17),
                  ("HTTP/easyeap.corp.example", "CORP.EXAMPLE", 2, 18))
    s = kerberos.summarize(kerberos.parse_keytab(data), "easyeap.corp.example")
    assert s["principal"] == "HTTP/easyeap.corp.example@CORP.EXAMPLE" and s["kvno"] == 3 and not s["problems"]
    assert s["enctypes"] == ["aes128-cts-hmac-sha1-96", "aes256-cts-hmac-sha1-96"]


def test_keytab_problems():
    wrong_host = kerberos.summarize(kerberos.parse_keytab(keytab(("HTTP/other.corp.example", "CORP.EXAMPLE", 1, 18))), "easyeap.corp.example")
    assert "no key for HTTP/easyeap.corp.example" in wrong_host["problems"][0]
    rc4 = kerberos.summarize(kerberos.parse_keytab(keytab(("HTTP/easyeap.corp.example", "CORP.EXAMPLE", 1, 23))), "easyeap.corp.example")
    assert "no AES key" in rc4["problems"][0]
    with pytest.raises(ValueError, match="keytab"):
        kerberos.parse_keytab(b"\x05\x03nope")
    with pytest.raises(ValueError, match="truncated"):
        kerberos.parse_keytab(keytab(("HTTP/a.b", "B", 1, 18))[:-20])


def test_ntlm_is_named():
    with pytest.raises(kerberos.KerberosError) as e:
        kerberos.accept(b"NTLMSSP\x00\x01\x00\x00\x00", b"", ["CORP.EXAMPLE"])
    assert e.value.code == "ntlm"
    assert kerberos.negotiate_token(None) is None and kerberos.negotiate_token("Basic abc") is None
    assert kerberos.negotiate_token("Negotiate YWJj") == b"abc"
    with pytest.raises(kerberos.KerberosError):
        kerberos.negotiate_token("Negotiate !!!")


# ── Service rules ────────────────────────────────────────────────────────────


def test_oid_root_fits_32_bit_arcs():
    for _ in range(50):
        root = svc._random_oid_root()
        assert root.startswith("1.3.6.1.4.1.311.21.8.")
        arcs = [int(a) for a in root.split(".")[9:]]
        assert len(arcs) == 6 and all(0 < a < 1 << 24 for a in arcs)
        cms.oid(root)  # encodes


def test_offered():
    tpls = {"computer": _tpl("computer"), "user": _tpl("user")}
    cfg = SimpleNamespace(enabled=True, computers=True, users=False)
    pc, nina = SimpleNamespace(kind="computer"), SimpleNamespace(kind="user")
    assert svc.offered(cfg, tpls, pc) == [tpls["computer"]]
    assert svc.offered(cfg, tpls, nina) == []
    cfg.users = True
    assert svc.offered(cfg, tpls, nina) == [tpls["user"]]
    cfg.enabled = False
    assert svc.offered(cfg, tpls, pc) == []


def _csr(template_oid: str | None = None, *, name: str | None = None) -> x509.CertificateSigningRequest:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    b = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
    if template_oid:
        b = b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.311.21.7"),
                                                       cms.template_extension(template_oid, 100, 0)), critical=False)
    if name:
        b = b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2"),
                                                       b"\x1e" + bytes([len(name) * 2]) + name.encode("utf-16-be")), critical=False)
    return b.sign(key, hashes.SHA256())


def test_choose_template():
    pc, user = _tpl("computer"), _tpl("user")
    assert svc._choose_template(_csr(pc.template_oid), [pc], "computer") is pc
    assert svc._choose_template(_csr(), [pc], "computer") is pc  # no template named: the one on offer
    with pytest.raises(svc.Denied) as e:
        svc._choose_template(_csr(user.template_oid), [pc], "computer")
    assert e.value.code == "template" and e.value.hresult == soap.CERTSRV_E_TEMPLATE_DENIED
    with pytest.raises(svc.Denied):
        svc._choose_template(_csr(), [], "user")


def test_ttl_is_cut_to_the_ca_or_refused(monkeypatch):
    now = datetime.now(UTC)
    tpl = _tpl("computer")
    monkeypatch.setattr(svc.pki, "issuing_ca", lambda s, t: SimpleNamespace(not_after=now + timedelta(days=1000)))
    assert svc._ttl(None, uuid.uuid4(), tpl, now) == timedelta(days=365)
    monkeypatch.setattr(svc.pki, "issuing_ca", lambda s, t: SimpleNamespace(not_after=now + timedelta(days=100)))
    assert timedelta(days=98) < svc._ttl(None, uuid.uuid4(), tpl, now) < timedelta(days=100)
    monkeypatch.setattr(svc.pki, "issuing_ca", lambda s, t: SimpleNamespace(not_after=now + timedelta(days=40)))
    with pytest.raises(svc.Denied) as e:
        svc._ttl(None, uuid.uuid4(), tpl, now)
    assert e.value.code == "ca_expiring"


def test_key_storage_from_the_provider_attribute():
    token = (FIXTURES / "wstep-spec-request.der").read_bytes()
    # The spec's request names "Microsoft Enhanced Cryptographic Provider v1.0" (a CSP, neither TPM nor KSP).
    assert svc._storage(token) is None
    marker = cms.oid("1.3.6.1.4.1.311.13.2.2")
    for provider, storage in (("Microsoft Platform Crypto Provider", "tpm"), ("Microsoft Software Key Storage Provider", "software")):
        name = provider.encode("utf-16-be")
        attr = marker + b"\x31\x00" + b"\x02\x01\x01" + b"\x1e" + bytes([len(name)]) + name
        assert svc._storage(b"\x30\x00" + attr) == storage


def test_template_policy_matches_what_issuing_writes():
    t = _tpl("computer", revision_major=104, revision_minor=2, validity_days=200, renew_before_days=30)
    p = svc.template_policy(t)
    assert p.machine and p.major == 104 and p.minor == 2 and p.validity_seconds == 200 * 86400 and p.renewal_seconds == 30 * 86400
    ext = dict((o, v) for o, _, v in p.extensions)
    assert ext[soap.OID_TEMPLATE_EXT] == cms.template_extension(t.template_oid, 104, 2)


# ── /cep and /ces ────────────────────────────────────────────────────────────


class FakeSession:
    def __init__(self, tenant, cfg):
        self.tenant, self.cfg, self.info, self.commits = tenant, cfg, {}, 0

    def in_transaction(self):
        return False

    def scalars(self, q):
        wanted = str(q.compile(compile_kwargs={"literal_binds": True}))
        return SimpleNamespace(first=lambda: self.tenant if self.tenant is not None and f"'{self.tenant.slug}'" in wanted else None)

    def get(self, model, _key):
        return {"AutoenrollConfig": self.cfg}.get(model.__name__)

    def begin_nested(self):
        return nullcontext()

    def commit(self):
        self.commits += 1


@pytest.fixture()
def flow(monkeypatch):
    from fastapi.testclient import TestClient

    from app.deps import db
    from app.main import app
    from app.routers import autoenroll as r
    from app.security.ratelimit import limiter

    limiter._hits.clear()
    r._tenants.clear()
    tenant = SimpleNamespace(id=uuid.uuid4(), slug="corp", name="Corp", status="active")
    cfg = SimpleNamespace(enabled=True, computers=True, users=True, keytab_ct="vault:v1:x", keytab_info={"realm": "CORP.EXAMPLE"},
                          require_channel_binding=True, policy_id="{P}", response_format="unsigned", last_success_at=None)
    s = FakeSession(tenant, cfg)
    events: list[dict] = []
    state = SimpleNamespace(session=s, cfg=cfg, tenant=tenant, events=events, bound=True, binding=b"tls-server-end-point:x",
                            caller="PC01$@CORP.EXAMPLE", kerberos_error=None, denied=None, enroll_denied=None, boom=False)

    def record_event(_s, _t, **kw):
        events.append(kw)
        return SimpleNamespace(id=len(events))

    def accept(token, keytab_bytes, realms, *, binding=None):
        assert keytab_bytes == b"keytab" and realms == ["CORP.EXAMPLE"]
        state.got_binding = binding
        if state.kerberos_error:
            raise kerberos.KerberosError(*state.kerberos_error)
        name, _, realm = state.caller.partition("@")
        return kerberos.Caller(principal=state.caller, name=name, realm=realm, reply="cmVwbHk=", channel_bound=state.bound)

    def identify(_s, _t, _cfg, caller):
        if state.denied:
            raise svc.Denied(*state.denied)
        return SimpleNamespace(kind="computer" if caller.claims_computer else "user", username=caller.name)

    ca_der, _ = _ca()

    def enroll(_s, _bao, _tenant, _cfg, ident, req):
        if state.boom:
            raise RuntimeError("OpenBao is sealed")
        if state.enroll_denied:
            raise svc.Denied(*state.enroll_denied)
        cert = SimpleNamespace(id=uuid.uuid4(), common_name="pc01.corp.example", serial="01", key_storage="tpm", device_id=None,
                               template_id=None)
        return svc.Issued(certificate=cert, response_der=b"\x30\x01\x01", certificate_der=b"\x30\x00"), SimpleNamespace(form="pkcs10")

    monkeypatch.setattr(r.svc, "record_event", record_event)
    monkeypatch.setattr(r.svc, "realm", lambda _s, _t: "CORP.EXAMPLE")
    monkeypatch.setattr(r.svc, "identify", identify)
    monkeypatch.setattr(r.svc, "enroll", enroll)
    monkeypatch.setattr(r.svc, "templates", lambda _s, _t: {"computer": _tpl("computer"), "user": _tpl("user")})
    monkeypatch.setattr(r, "_keytab", lambda _t, _c: b"keytab")
    monkeypatch.setattr(r, "_ca_der", lambda _s, _t: ca_der)
    monkeypatch.setattr(r, "OpenBao", lambda: None)
    monkeypatch.setattr(r.kerberos, "accept", accept)
    monkeypatch.setattr(r.kerberos, "proxy_binding", lambda: state.binding)
    app.dependency_overrides[db] = lambda: s
    state.client = TestClient(app)
    yield state
    app.dependency_overrides.pop(db, None)


NEGOTIATE = {"Authorization": "Negotiate " + base64.b64encode(b"\x60\x10kerberos-token").decode()}


def test_cep_asks_for_kerberos_first(flow):
    r = flow.client.post("/cep/corp", content=GET_POLICIES)
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Negotiate"
    assert flow.events == []


def test_unknown_or_disabled_tenant(flow):
    assert flow.client.post("/cep/nope", content=GET_POLICIES, headers=NEGOTIATE).status_code == 404
    flow.cfg.enabled = False
    assert flow.client.post("/cep/corp", content=GET_POLICIES, headers=NEGOTIATE).status_code == 404
    flow.session.tenant = None
    assert flow.client.post("/ces/corp", content=b"", headers=NEGOTIATE).status_code == 404


def test_cep_policies(flow):
    r = flow.client.post("/cep/corp", content=GET_POLICIES, headers=NEGOTIATE)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/soap+xml")
    assert r.headers["www-authenticate"] == "Negotiate cmVwbHk="  # mutual authentication
    resp = ET.fromstring(r.content).find("s:Body/x:GetPoliciesResponse", NS)
    names = [p.find("x:attributes/x:commonName", NS).text for p in resp.findall("x:response/x:policies/x:policy", NS)]
    assert names == ["EasyEAP-Computer"]
    assert resp.find("x:cAs/x:cA/x:uris/x:cAURI/x:uri", NS).text.endswith("/ces/corp")
    assert flow.events[-1]["outcome"] == "ok" and flow.events[-1]["service"] == "cep"
    # The same caller's routine refresh isn't logged again.
    flow.client.post("/cep/corp", content=GET_POLICIES, headers=NEGOTIATE)
    assert len(flow.events) == 1


def test_cep_user_when_users_are_off(flow):
    flow.caller, flow.cfg.users = "nina@CORP.EXAMPLE", False
    r = flow.client.post("/cep/corp", content=GET_POLICIES, headers=NEGOTIATE)
    resp = ET.fromstring(r.content).find("s:Body/x:GetPoliciesResponse", NS)
    assert resp.find("x:response/x:policies", NS).get(f"{{{NS['xsi']}}}nil") == "true"
    assert flow.events[-1]["code"] == "none" and "off for users" in flow.events[-1]["message"]


def test_unbound_ticket_is_refused_when_binding_is_required(flow):
    flow.bound = False
    r = flow.client.post("/ces/corp", content=rst(b"\x30\x00"), headers=NEGOTIATE)
    assert r.status_code == 500 and b"Extended Protection" in r.content
    assert flow.events[-1]["code"] == "binding" and flow.events[-1]["outcome"] == "denied"
    assert flow.got_binding == flow.binding
    # Not required: no bindings go to the acceptor, since MIT refuses a ticket whose bindings differ from them (a
    # TLS-inspecting proxy, the reason to turn it off).
    flow.cfg.require_channel_binding = False
    assert flow.client.post("/ces/corp", content=rst(b"\x30\x00"), headers=NEGOTIATE).status_code == 200
    assert flow.got_binding is None


def test_binding_without_the_proxy_certificate(flow):
    flow.binding, flow.bound = None, False
    r = flow.client.post("/cep/corp", content=GET_POLICIES, headers=NEGOTIATE)
    assert r.status_code == 500 and b"proxy" in r.content
    assert flow.events[-1]["outcome"] == "error"


@pytest.mark.parametrize(("code", "status"), [("ntlm", 401), ("invalid", 401), ("keytab", 500), ("realm", 500)])
def test_kerberos_failures(flow, code, status):
    flow.kerberos_error = (code, f"{code} problem")
    r = flow.client.post("/cep/corp", content=GET_POLICIES, headers=NEGOTIATE)
    assert r.status_code == status
    assert flow.events[-1]["code"] == code and flow.events[-1]["outcome"] == ("error" if code == "keytab" else "denied")


def test_failures_without_a_caller_dont_flood_the_log(flow):
    flow.kerberos_error = ("invalid", "nope")
    for _ in range(40):
        flow.client.post("/cep/corp", content=GET_POLICIES, headers=NEGOTIATE)
    assert len(flow.events) == 20


def test_no_keytab(flow):
    flow.cfg.keytab_ct = None
    r = flow.client.post("/cep/corp", content=GET_POLICIES, headers=NEGOTIATE)
    assert r.status_code == 500 and flow.events[-1]["code"] == "keytab"


def test_ces_issues(flow):
    r = flow.client.post("/ces/corp", content=rst(b"\x30\x00", context={"ccm": "pc01.corp.example"}), headers=NEGOTIATE)
    assert r.status_code == 200, r.text
    resp = ET.fromstring(r.content).find("s:Body/t:RequestSecurityTokenResponseCollection/t:RequestSecurityTokenResponse", NS)
    assert resp.find("e:DispositionMessage", NS).text == "Issued"
    assert resp.find("e:RequestID", NS).text == str(len(flow.events))
    assert ET.fromstring(r.content).find("s:Header/a:RelatesTo", NS).text == "urn:uuid:b5d1a601-5091-4a7d-b34b-5204c18b5919"
    assert flow.events[-1]["outcome"] == "ok" and flow.events[-1]["machine"] == "pc01.corp.example"


@pytest.mark.parametrize(("code", "hresult", "invalid"), [("key", soap.CERTSRV_E_KEY_LENGTH, "true"),
                                                          ("limit", soap.CERTSRV_E_ENROLL_DENIED, "false")])
def test_ces_denied(flow, code, hresult, invalid):
    flow.enroll_denied = (code, f"{code} says no", hresult)
    resp = flow.client.post("/ces/corp", content=rst(b"\x30\x00"), headers=NEGOTIATE)
    assert resp.status_code == 500
    detail = ET.fromstring(resp.content).find("s:Body/s:Fault/s:Detail/e:CertificateEnrollmentWSDetail", NS)
    assert int(detail.find("e:ErrorCode", NS).text) == hresult
    assert detail.find("e:InvalidRequest", NS).text == invalid
    assert detail.find("e:RequestID", NS).text == str(len(flow.events))
    assert flow.events[-1]["code"] == code


def test_identity_refused(flow):
    flow.denied = ("not_in_group", "PC01$ isn't in Laptops", soap.CERTSRV_E_TEMPLATE_DENIED)
    # A caller autoenrollment isn't for gets an empty policy, as from AD CS: no fault for Windows to log at every refresh.
    r = flow.client.post("/cep/corp", content=GET_POLICIES, headers=NEGOTIATE)
    assert r.status_code == 200 and b"Laptops" not in r.content and b"EasyEAP-Computer" not in r.content
    assert flow.events[-1]["caller"] == "PC01$@CORP.EXAMPLE" and flow.events[-1]["kind"] == "computer"
    assert flow.events[-1]["code"] == "not_in_group" and len(flow.events) == 1
    # The same refusal at the next refresh isn't logged again (REPEAT_LOG_EVERY).
    assert flow.client.post("/cep/corp", content=GET_POLICIES, headers=NEGOTIATE).status_code == 200 and len(flow.events) == 1
    # Enrolling is refused with the reason.
    r = flow.client.post("/ces/corp", content=rst(b"\x30\x00"), headers=NEGOTIATE)
    assert r.status_code == 500 and b"Laptops" in r.content
    # A directory failure is a fault on /cep too: it's not an answer about the caller.
    flow.denied = ("directory", "AD unreachable", soap.E_FAIL)
    assert flow.client.post("/cep/corp", content=GET_POLICIES, headers=NEGOTIATE).status_code == 500


def test_identify_crash_is_a_fault(flow, monkeypatch):
    from app.routers import autoenroll as r

    def boom(*_a, **_k):
        raise RuntimeError("duplicate key value violates unique constraint")
    monkeypatch.setattr(r.svc, "identify", boom)
    resp = flow.client.post("/cep/corp", content=GET_POLICIES, headers=NEGOTIATE)
    assert resp.status_code == 500 and b"request log" in resp.content
    assert flow.events[-1]["code"] == "internal" and flow.events[-1]["outcome"] == "error"


def test_first_leg_needs_no_database(flow):
    assert flow.client.post("/cep/corp", content=GET_POLICIES).status_code == 401
    flow.session.scalars = None  # the second credential-less request is answered from the cache
    assert flow.client.post("/cep/corp", content=GET_POLICIES).status_code == 401


def test_ces_internal_error_is_a_fault(flow):
    flow.boom = True
    r = flow.client.post("/ces/corp", content=rst(b"\x30\x00"), headers=NEGOTIATE)
    assert r.status_code == 500 and b"request log" in r.content
    assert flow.events[-1]["outcome"] == "error" and "sealed" in flow.events[-1]["message"]


def test_bad_soap(flow):
    r = flow.client.post("/ces/corp", content=b"<x/>", headers=NEGOTIATE)
    assert r.status_code == 400 and flow.events[-1]["code"] == "bad_request"
    assert flow.client.post("/cep/corp", content=b"x" * (soap.MAX_BODY + 1), headers=NEGOTIATE).status_code == 413


def test_per_caller_limit(flow):
    codes = [flow.client.post("/cep/corp", content=GET_POLICIES, headers=NEGOTIATE).status_code for _ in range(62)]
    assert codes[:60] == [200] * 60 and codes[60:] == [503, 503]


# ── Console helpers ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(("host", "ok"), [("easyeap.corp.example", True), ("10.0.0.5", False), ("localhost", False),
                                          ("easyeap.localhost", False), ("easyeap", False), ("", False)])
def test_host_problem(host, ok):
    from app.routers.autoenroll import _host_problem
    assert (_host_problem(host) is None) is ok


def test_scripts():
    from app.routers.autoenroll import samba_script, windows_script
    ps = windows_script(host="easyeap.corp.example", realm="CORP.EXAMPLE", account="easyeap-cep", tenant="Corp")
    assert '$ServiceHost = "easyeap.corp.example"' in ps and '$Realm = "CORP.EXAMPLE"' in ps
    assert "-crypto AES256-SHA1" in ps and "-ptype KRB5_NT_PRINCIPAL" in ps and "-mapop set" in ps
    assert "KerberosEncryptionType AES128,AES256" in ps and "3268" in ps  # AES tickets; SPN checked forest-wide
    sh = samba_script(host="easyeap.corp.example", realm="CORP.EXAMPLE", account="easyeap-cep", tenant="Corp")
    assert "samba-tool domain exportkeytab easyeap-cep.keytab --principal=\"$SPN\"" in sh and "SPN='HTTP/easyeap.corp.example'" in sh
    # Samba gives a user account's SPN RC4 tickets and keys unless AES is allowed on it; EasyEAP accepts AES only.
    assert sh.index("msDS-SupportedEncryptionTypes: 24") < sh.index("samba-tool domain exportkeytab")
    assert "${PRIVATE:-/var/lib/samba/private}/sam.ldb" in sh


def test_clean_text():
    from app.autoenroll.kerberos import clean_text
    # MIT's SPNEGO minor-status text ends in NUL, which Postgres refuses in text and JSON (a 500 in the lab).
    assert clean_text("SPNEGO cannot find mechanisms to negotiate\x00 ") == "SPNEGO cannot find mechanisms to negotiate"
    assert clean_text("a\tb\nc\x07\x7f") == "a\tb\nc" and len(clean_text("x" * 5000)) == 2000


def test_keytab_test_result_is_clean(monkeypatch):
    from app.autoenroll import keytab_test
    monkeypatch.setattr(keytab_test, "_run", lambda **_: {"ok": "yes", "step": "ticket\x00", "message": "bad\x00", "extra": 1})
    r = keytab_test.run(realm="R", kdcs=[], user="u", password="p", host="h", keytab=b"")
    assert r == {"ok": False, "step": "ticket", "message": "bad"}


def test_keytab_test_explains_rc4_only():
    from app.autoenroll.keytab_test import _explain
    msg = _explain("ticket", "KDC has no support for encryption type", "easyeap.corp.example", "CORP.EXAMPLE")
    assert "no AES key for HTTP/easyeap.corp.example" in msg and "script" in msg


def test_keytab_rc4_only_problem():
    from app.autoenroll import kerberos
    info = kerberos.summarize(kerberos.parse_keytab(keytab(("HTTP/easyeap.corp.example", "CORP.EXAMPLE", 2, 23))), "easyeap.corp.example")
    assert info["enctypes"] == ["rc4-hmac"] and "AES tickets only" in info["problems"][0] and "msDS-SupportedEncryptionTypes" in info["problems"][0]


# ── Review fixes: keytab scope, XML, directory, computers ───────────────────


def test_keytab_is_cut_to_the_service():
    data = keytab(("HTTP/easyeap.corp.example", "CORP.EXAMPLE", 3, 18), ("HTTP/other.corp.example", "CORP.EXAMPLE", 1, 18),
                  ("easyeap-cep", "CORP.EXAMPLE", 3, 18))
    kept = kerberos.parse_keytab(kerberos.for_host(data, "EasyEAP.corp.example"))
    assert [(e.principal, e.kvno) for e in kept] == [("HTTP/easyeap.corp.example", 3)]
    assert kerberos.upload_problem(kerberos.parse_keytab(data)) is None
    full = keytab(("HTTP/easyeap.corp.example", "CORP.EXAMPLE", 3, 18), ("krbtgt/CORP.EXAMPLE", "CORP.EXAMPLE", 2, 18))
    assert "krbtgt" in (kerberos.upload_problem(kerberos.parse_keytab(full)) or "")


@pytest.mark.parametrize("body", [
    '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>'.encode("utf-16"),
    b"<!--" + b"x" * 5000 + b"--><!DOCTYPE x [<!ENTITY a 'b'>]><x>&a;</x>",
    b'<!DOCTYPE x SYSTEM "http://example.invalid/x.dtd"><x/>',
])
def test_dtds_are_refused_wherever_they_are(body):
    with pytest.raises(soap.SoapError, match="Document type"):
        soap.parse_get_policies(body)


def test_users_never_include_computers():
    from app.directory import ldap
    assert ldap._users_only("(objectClass=user)") == "(&(objectClass=user)(!(objectClass=computer)))"


class _Conn:
    def __init__(self, response, result=None):
        self.response, self.result, self.searches = response, result or {"result": 0}, []

    def search(self, base, flt, **kw):
        self.searches.append((base, flt))
        return bool(self.response)


def _computer_entry(uac: int, name: str = "PC01") -> dict:
    return {"type": "searchResEntry", "dn": f"CN={name},CN=Computers,DC=corp,DC=example",
            "attributes": {"sAMAccountName": f"{name}$", "cn": name, "dNSHostName": f"{name.lower()}.corp.example", "userAccountControl": uac},
            "raw_attributes": {"objectGUID": [uuid.UUID(int=1).bytes_le], "objectSid": [], "ms-DS-CreatorSID": []}}


def test_directory_failures_aren_t_answers():
    from app.directory import ldap
    p = SimpleNamespace(base_dn="DC=corp,DC=example")
    with pytest.raises(ldap.DirectoryError, match="refused"):
        ldap.lookup_computer(_Conn([], {"result": 50, "description": "insufficientAccessRights"}), p, "PC01$")
    assert ldap.lookup_computer(_Conn([]), p, "PC01$") is None  # nothing found is an answer
    # tokenGroups that can't be read: None (keep what's known), not "no groups"
    assert ldap.token_group_sids(_Conn([]), "CN=x", strict=True) is None
    assert ldap.token_group_sids(_Conn([]), "CN=x") == []


def test_lookup_by_guid_filter():
    from app.directory import ldap
    guid = "01020304-0506-0708-090a-0b0c0d0e0f10"
    entry = _computer_entry(0x1000)
    entry["raw_attributes"]["objectGUID"] = [uuid.UUID(guid).bytes_le]
    conn = _Conn([entry])
    c = ldap.lookup_computer_by_guid(conn, SimpleNamespace(base_dn="DC=x"), guid)
    assert c is not None and c.username == "PC01$" and c.object_guid == guid
    # AD's objectGUID is the little-endian byte form: the first three fields reversed
    assert "(objectGUID=\\04\\03\\02\\01\\06\\05\\08\\07\\09\\0a\\0b\\0c\\0d\\0e\\0f\\10)" in conn.searches[0][1]


def test_read_only_domain_controller_isn_t_a_workstation():
    from app.directory import ldap
    assert ldap._to_computer(_computer_entry(0x1000)).workstation
    assert not ldap._to_computer(_computer_entry(0x05001000)).workstation  # RODC: partial secrets + workstation


class _Rows:
    def __init__(self, rows):
        self.rows = rows

    def first(self):
        return self.rows[0] if self.rows else None

    def __iter__(self):
        return iter(self.rows)


@pytest.mark.parametrize(("username", "dns", "other", "ok"), [
    ("PC01$", "pc01.corp.example", None, True),
    ("PC01$", "pc01.emea.corp.example", None, True),            # a child DNS zone of the domain
    ("PC01$", "dc1.corp.example", None, False),                 # another host's name (the Certifried class)
    ("PC01$", "pc01.evil.example", None, False),                # outside the domain
    ("PC01$", "pc01.corp.example", "PC01-OLD$", False),         # another enabled computer has it
    ("LONGCOMPUTERNAM$", "longcomputername01.corp.example", None, True),  # NetBIOS name cut to 15
    ("LONGCOMPUTERNAM$", "longcomputerx.corp.example", None, False),
])
def test_dns_name_must_be_the_computer_s_own(username, dns, other, ok):
    session = SimpleNamespace(scalars=lambda _q: _Rows([other] if other else []))
    ident = SimpleNamespace(id=uuid.uuid4(), username=username, dns_name=dns)
    assert (svc.dns_name_problem(session, uuid.uuid4(), ident, "CORP.EXAMPLE") is None) is ok


def test_confirm_computer_reads_ad_by_guid(monkeypatch):
    from app.directory import ldap
    guid = str(uuid.UUID(int=1))
    found = {"c": ldap._to_computer(_computer_entry(0x1000))}
    found["c"].group_sids = []
    monkeypatch.setattr(svc.ldap, "connect", lambda _p: SimpleNamespace(unbind=lambda: None))
    monkeypatch.setattr(svc.dsync, "params", lambda _d: SimpleNamespace(base_dn="DC=x"))
    monkeypatch.setattr(svc.ldap, "lookup_computer_by_guid", lambda _c, _p, g: found["c"] if g == guid else None)
    session = SimpleNamespace(get=lambda _m, _k: SimpleNamespace(enabled=True), scalars=lambda _q: _Rows([]), flush=lambda: None)
    cfg = SimpleNamespace(computer_group_id=None)
    ident = SimpleNamespace(id=uuid.uuid4(), username="PC01$", object_guid=guid, groups=[], account_state="enabled", kind="computer")
    assert svc.confirm_computer(session, uuid.uuid4(), cfg, ident, datetime.now(UTC)).username == "PC01$"
    assert ident.dns_name == "pc01.corp.example"
    # The account EasyEAP knows was renamed: a new account with the old name gets nothing on its behalf.
    found["c"] = ldap._to_computer(_computer_entry(0x1000, "FIN-PC01"))
    with pytest.raises(svc.Denied, match="is now FIN-PC01"):
        svc.confirm_computer(session, uuid.uuid4(), cfg, ident, datetime.now(UTC))
    found["c"] = None
    with pytest.raises(svc.Denied, match="was deleted"):
        svc.confirm_computer(session, uuid.uuid4(), cfg, ident, datetime.now(UTC))


def test_limiter_forgets_idle_keys(monkeypatch):
    from app.security import ratelimit
    clock = {"t": 1000.0}
    monkeypatch.setattr(ratelimit.time, "monotonic", lambda: clock["t"])
    lim = ratelimit.RateLimiter()
    for i in range(100):
        lim.hit(f"ip-{i}", 5, 60)
    clock["t"] += ratelimit.SWEEP_EVERY + 1
    lim.hit("ip-new", 5, 60)
    assert set(lim._hits) == {"ip-new"}
