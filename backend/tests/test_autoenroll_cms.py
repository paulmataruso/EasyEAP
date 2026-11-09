"""app/autoenroll/cms.py: reading every request form Windows sends, the extensions EasyEAP adds, and the CMC full PKI
response (docs/plans/gpo-autoenrollment.md §2.6)."""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from app.autoenroll import cms

SPEC_REQUEST = Path(__file__).parent / "fixtures" / "wstep-spec-request.der"  # MS-WSTEP 4.1.1.1's BinarySecurityToken
NOW = datetime.now(UTC)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(cn, key, issuer_cn, issuer_key, ca=False):
    return (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(issuer_cn)).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(NOW - timedelta(minutes=1)).not_valid_after(NOW + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True).sign(issuer_key, hashes.SHA256()))


def _csr(key=None):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(key, hashes.SHA256())


def _cmc(*requests: bytes, content_type: str = "1.3.6.1.5.5.7.12.2", nested: bytes | None = None) -> bytes:
    """A CMC request as Windows sends it: PKIData in a SignedData (unsigned here; EasyEAP relies on Kerberos and the
    PKCS#10's own signature)."""
    tagged = [cms.tlv(0xA0, cms.integer(bp) + der) for bp, der in requests]
    cms_seq = cms.seq(cms.seq(cms.integer(9), nested)) if nested else cms.seq()
    pki_data = cms.seq(cms.seq(), cms.seq(*tagged), cms_seq, cms.seq())
    return cms.seq(cms.oid(cms.OID_SIGNED_DATA), cms.explicit(0, cms.seq(
        cms.integer(3), cms.set_of(cms.seq(cms.oid(cms.OID_SHA256))),
        cms.seq(cms.oid(content_type), cms.explicit(0, cms.octets(pki_data))), cms.set_of())))


def _der(csr):
    return csr.public_bytes(serialization.Encoding.DER)


def test_spec_request_is_read_with_its_machine_and_template():
    req = cms.parse_request(SPEC_REQUEST.read_bytes())  # signed with SHA-1, which cryptography's own check refuses
    assert req.form == "pkcs10" and req.body_part_id == 1
    assert req.csr.signature_hash_algorithm.name == "sha1" and not req.csr.is_signature_valid and cms.signature_ok(req.csr)
    assert req.machine == "9-1351c0405a.d9-1351c0406a.nttest.microsoft.com"  # client information, 1.3.6.1.4.1.311.21.20
    tpl_oid, name = cms.template_of(req.csr)
    assert tpl_oid is None and name  # a v1 template: by name (1.3.6.1.4.1.311.20.2)


def test_pkcs10_inside_a_pkcs7_renewal():
    old_key = ec.generate_private_key(ec.SECP256R1())
    old = _cert("pc01.corp.example", old_key, "pc01.corp.example", old_key)
    csr = _csr()
    p7 = pkcs7.PKCS7SignatureBuilder().set_data(_der(csr)).add_signer(old, old_key, hashes.SHA256()) \
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
    req = cms.parse_request(p7)
    assert req.form == "pkcs7" and req.body_part_id == 1 and req.csr.public_key().public_numbers() == csr.public_key().public_numbers()


def test_cmc_request_keeps_its_body_part_id():
    csr = _csr()
    req = cms.parse_request(_cmc((7, _der(csr))))
    assert req.form == "cmc" and req.body_part_id == 7 and req.csr.public_key().public_numbers() == csr.public_key().public_numbers()


def test_cmc_request_nested_in_cms_sequence():
    csr = _csr()
    inner = _cmc((3, _der(csr)))
    req = cms.parse_request(_cmc(nested=inner))
    assert req.body_part_id == 3


def test_two_requests_are_refused():
    with pytest.raises(ValueError, match="more than one"):
        cms.parse_request(_cmc((1, _der(_csr())), (2, _der(_csr()))))


def test_crmf_is_refused():
    pki_data = cms.seq(cms.seq(), cms.seq(cms.tlv(0xA1, cms.seq())), cms.seq(), cms.seq())
    signed = cms.seq(cms.oid(cms.OID_SIGNED_DATA), cms.explicit(0, cms.seq(cms.integer(3), cms.set_of(),
                     cms.seq(cms.oid("1.3.6.1.5.5.7.12.2"), cms.explicit(0, cms.octets(pki_data))), cms.set_of())))
    with pytest.raises(ValueError, match="CRMF"):
        cms.parse_request(signed)


@pytest.mark.parametrize("data", [b"", b"\x30\x03\x02\x01\x00", b"garbage" * 20, b"\x30\x84\xff\xff\xff\xff", b"\x30\x00" * 40000])
def test_no_request(data):
    with pytest.raises(ValueError):
        cms.parse_request(data)


def test_tampered_csr_is_refused():
    der = bytearray(_der(_csr()))
    der[-5] ^= 0xFF  # the signature
    with pytest.raises(ValueError):
        cms.parse_request(bytes(der))


def test_deep_nesting_stops():
    inner = _cmc((1, _der(_csr())))
    for _ in range(6):
        inner = _cmc(nested=inner)
    with pytest.raises(ValueError, match="nested"):
        cms.parse_request(inner)


def test_key_checks():
    assert cms.key_problem(_csr()) is None
    assert cms.key_problem(_csr(ec.generate_private_key(ec.SECP256R1()))) is None
    assert "2048" in cms.key_problem(_csr(rsa.generate_private_key(public_exponent=65537, key_size=1024)))  # noqa: S505 — the weak key is the point
    assert "curve" in cms.key_problem(_csr(ec.generate_private_key(ec.SECP521R1())))


def test_roca_fingerprint():
    """A modulus built like an Infineon key (p, q ≡ 65537^k mod M, M the product of the small primes) is caught;
    ordinary keys aren't."""
    import math
    m = math.prod(cms._ROCA_PRIMES)
    p = 7919 * m + pow(65537, 1234, m)
    q = 104729 * m + pow(65537, 777, m)

    class Weak:  # roca_weak only reads public_numbers().n
        def public_numbers(self):
            return type("N", (), {"n": p * q})()

    rsa.RSAPublicKey.register(Weak)
    assert cms.roca_weak(Weak())
    for _ in range(5):
        assert not cms.roca_weak(rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key())


def test_extensions_parse_as_microsofts():
    key = ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder().subject_name(_name("x")).issuer_name(_name("x")).public_key(key.public_key()).serial_number(1)
         .not_valid_before(NOW).not_valid_after(NOW + timedelta(days=1))
         .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.311.21.7"), cms.template_extension("2.25.12345", 100, 3)), critical=False)
         .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("2.5.29.17"), cms.san_extension(dns=["pc01.corp.example"], upn="PC01$@corp.example")), critical=False))
    c = x509.load_der_x509_certificate(b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
    t = c.extensions.get_extension_for_oid(x509.ObjectIdentifier("1.3.6.1.4.1.311.21.7")).value
    assert (t.template_id.dotted_string, t.major_version, t.minor_version) == ("2.25.12345", 100, 3)
    san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["pc01.corp.example"]
    other = san.get_values_for_type(x509.OtherName)[0]
    assert other.type_id.dotted_string == "1.3.6.1.4.1.311.20.2.3" and other.value == b"\x0c\x12PC01$@corp.example"


@pytest.mark.parametrize("kind", ["ec", "rsa"])
def test_signed_response_verifies(kind):
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _cert("Test Issuing", ca_key, "Test Issuing", ca_key, ca=True)
    signer_key = ec.generate_private_key(ec.SECP256R1()) if kind == "ec" else rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer = _cert("EasyEAP enrollment service", signer_key, "Test Issuing", ca_key)
    leaf = _cert("pc01.corp.example", ec.generate_private_key(ec.SECP256R1()), "Test Issuing", ca_key)
    der = lambda c: c.public_bytes(serialization.Encoding.DER)  # noqa: E731
    content = cms.pki_response(issued_der=der(leaf))
    out = cms.signed_response(content, [der(leaf), der(ca)], signer, signer_key)

    # Walk it back: ContentInfo → SignedData → (eContentType, eContent, certificates, signerInfo)
    _, cs, ce = cms.read_tlv(out)
    els = list(cms.children(out, cs, ce))
    assert out[els[0][1]:els[0][3]] == cms.oid(cms.OID_SIGNED_DATA)
    _, _, sd_cs, sd_ce = next(cms.children(out, els[1][2], els[1][3]))
    sd = list(cms.children(out, sd_cs, sd_ce))
    encap = list(cms.children(out, sd[2][2], sd[2][3]))
    assert out[encap[0][1]:encap[0][3]] == cms.oid(cms.OID_PKI_RESPONSE)
    certs = [out[s:e] for _, s, _, e in cms.children(out, sd[3][2], sd[3][3])]
    assert certs[0] == der(signer) and der(leaf) in certs and der(ca) in certs
    si = list(cms.children(out, *next(cms.children(out, sd[4][2], sd[4][3]))[2:]))
    attrs_content = out[si[3][2]:si[3][3]]
    sig = out[si[5][2]:si[5][3]]
    signed = cms.tlv(0x31, attrs_content)
    pub = signer.public_key()
    if kind == "ec":
        pub.verify(sig, signed, ec.ECDSA(hashes.SHA256()))
    else:
        from cryptography.hazmat.primitives.asymmetric import padding
        pub.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
    assert hashlib.sha256(content).digest() in attrs_content
    assert hashlib.sha1(der(leaf)).digest() in content  # noqa: S324 — Microsoft's issued-certificate hash


def test_failure_response_has_no_certificate_hash():
    content = cms.pki_response(issued_der=None, status=cms.CMC_FAILED, text="Denied")
    assert b"Denied" in content and cms.oid(cms.OID_MS_CMC_ADD_ATTRIBUTES) not in content


def test_unsigned_response_carries_the_status_and_chain():
    key = ec.generate_private_key(ec.SECP256R1())
    ca, leaf = _cert("ca", key, "ca", key, ca=True), _cert("leaf", key, "ca", key)
    der = lambda c: c.public_bytes(serialization.Encoding.DER)  # noqa: E731
    content = cms.pki_response(issued_der=der(leaf), body_part=7)
    out = cms.unsigned_response(content, [der(leaf), der(ca)])
    assert {c.subject for c in pkcs7.load_der_pkcs7_certificates(out)} == {leaf.subject, ca.subject}
    assert cms.oid(cms.OID_PKI_RESPONSE) in out and content in out
    # statusInfo for body part 7 (the request's), success
    assert cms.seq(cms.integer(0), cms.seq(cms.integer(7)), cms.utf8("Issued")) in content


def test_failure_status_has_fail_info():
    content = cms.pki_response(issued_der=None, status=cms.CMC_FAILED, text="Denied", body_part=2, fail_info=cms.CMC_BAD_REQUEST)
    assert cms.seq(cms.integer(2), cms.seq(cms.integer(2)), cms.utf8("Denied"), cms.integer(2)) in content


def test_response_matches_the_spec_example_shape():
    """MS-WSTEP 4.1.1.2's response (AD CS): the PKIResponse for a bare PKCS#10 is status success for body part 1 plus
    the add-attributes control with the issued certificate's SHA-1 hash. Ours is the same bytes, but for the hash."""
    spec = (Path(__file__).parent / "fixtures" / "wstep-spec-response.der").read_bytes()
    i = spec.index(bytes.fromhex("306D3067"))
    theirs = spec[i:i + 0x6F]
    h = theirs.index(bytes.fromhex("0414")) + 2
    ours = cms.pki_response(issued_der=b"x")
    assert ours.replace(hashlib.sha1(b"x").digest(), theirs[h:h + 20]) == theirs  # noqa: S324


def test_chain_pkcs7_loads():
    key = ec.generate_private_key(ec.SECP256R1())
    a, b = _cert("a", key, "a", key, ca=True), _cert("b", key, "a", key)
    loaded = pkcs7.load_der_pkcs7_certificates(cms.chain_pkcs7([a.public_bytes(serialization.Encoding.DER), b.public_bytes(serialization.Encoding.DER)]))
    assert {c.subject for c in loaded} == {a.subject, b.subject}
