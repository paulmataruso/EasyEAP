"""DER and CMS for Group Policy autoenrollment (docs/plans/gpo-autoenrollment.md §2.6).

Requests: Windows sends a PKCS#10, a CMC request (PKIData in a CMS SignedData) or a renewal (a PKCS#10 inside a
SignedData signed by the old certificate), and labels them all #PKCS7. `parse_request` reads the structure: exactly one
request, its CMC body part ID (the response refers to it), and the PC's name from the client information.

Responses: MS-WSTEP 3.1.4.1.3.3 requires a CMC full PKI response. Like AD CS's (MS-WSTEP 4.1.1.2) it carries a success
status for body part 1, the issued certificate's SHA-1 hash (Microsoft's CMC attribute), and the certificate with its
chain, in a SignedData whose content type is id-cct-PKIResponse. AD CS signs it with the CA key; EasyEAP's CA key
stays in OpenBao, so it's signed by the tenant's enrollment-service certificate, issued by the same CA.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

# ── DER ──────────────────────────────────────────────────────────────────────


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def set_of(*items: bytes) -> bytes:
    return tlv(0x31, b"".join(sorted(items)))  # DER: SET OF sorted by encoding


def integer(v: int) -> bytes:
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True)
    return tlv(0x02, b)


def oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    body = bytearray([40 * arcs[0] + arcs[1]])
    for v in arcs[2:]:
        enc = [v & 0x7F]
        v >>= 7
        while v:
            enc.insert(0, 0x80 | (v & 0x7F))
            v >>= 7
        body += bytes(enc)
    return tlv(0x06, bytes(body))


def octets(b: bytes) -> bytes:
    return tlv(0x04, b)


def utf8(s: str) -> bytes:
    return tlv(0x0C, s.encode())


def explicit(n: int, content: bytes) -> bytes:
    return tlv(0xA0 + n, content)


def read_tlv(data: bytes, pos: int = 0) -> tuple[int, int, int]:
    """(tag, content start, content end) of the element at `pos`. Raises ValueError on bad DER."""
    if pos + 2 > len(data):
        raise ValueError("truncated")
    tag, first = data[pos], data[pos + 1]
    if tag & 0x1F == 0x1F:
        raise ValueError("high tag numbers aren't used here")
    i = pos + 2
    if first < 0x80:
        n = first
    else:
        k = first & 0x7F
        if k == 0 or k > 4 or i + k > len(data):
            raise ValueError("bad length")
        n = int.from_bytes(data[i:i + k], "big")
        i += k
    if i + n > len(data):
        raise ValueError("truncated")
    return tag, i, i + n


def children(data: bytes, start: int, end: int) -> Iterator[tuple[int, int, int, int]]:
    """(tag, element start, content start, content end) for each element in data[start:end]."""
    pos = start
    while pos < end:
        tag, cs, ce = read_tlv(data, pos)
        yield tag, pos, cs, ce
        pos = ce


# ── Reading a request ────────────────────────────────────────────────────────

MAX_DEPTH = 12
OID_DATA = "1.2.840.113549.1.7.1"
OID_PKI_DATA = "1.3.6.1.5.5.7.12.2"
OID_CLIENT_INFO = "1.3.6.1.4.1.311.21.20"


@dataclass(frozen=True)
class ParsedRequest:
    csr: x509.CertificateSigningRequest
    body_part_id: int        # echoed in the response's status (1 for a bare PKCS#10, as AD CS does)
    form: str                # pkcs10 | cmc | pkcs7 (a PKCS#10 in a SignedData: a renewal)
    machine: str | None      # the PC's DNS name from the request's client information, if any


def parse_request(token: bytes) -> ParsedRequest:
    """The one certificate request in a WSTEP BinarySecurityToken: a PKCS#10, a CMC PKIData (in a SignedData, as
    Windows sends it), or a PKCS#10 in a SignedData (a renewal signed by the old certificate). Windows labels them all
    #PKCS7, so the structure decides. Raises ValueError when there's no request, more than one, or the PKCS#10's own
    signature (proof of possession of the key) doesn't verify."""
    if len(token) > 65536:
        raise ValueError("The request is too large.")
    csr_der, body_part, form = _request_in(token, 0)
    try:
        csr = x509.load_der_x509_csr(csr_der)
    except ValueError as exc:
        raise ValueError("The certificate request (PKCS#10) can't be read.") from exc
    if not signature_ok(csr):
        raise ValueError("The certificate request's signature doesn't verify.")
    return ParsedRequest(csr=csr, body_part_id=body_part, form=form, machine=client_machine(token))


def _request_in(der: bytes, depth: int) -> tuple[bytes, int, str]:
    if depth > 3:
        raise ValueError("The request is nested too deeply.")
    try:
        tag, cs, ce = read_tlv(der)
        if tag != 0x30 or ce != len(der):
            raise ValueError("not one DER element")
        first = list(children(der, cs, ce))
    except ValueError as exc:
        raise ValueError("The request isn't DER.") from exc
    if _looks_like_csr(der):
        return der, 1, "pkcs10"
    # ContentInfo ::= SEQUENCE { contentType OID, [0] EXPLICIT content }
    if len(first) == 2 and first[0][0] == 0x06 and _oid_at(der, first[0]) == OID_SIGNED_DATA and first[1][0] == 0xA0:
        econtent_type, econtent = _encapsulated(der, first[1][2], first[1][3])
        if econtent_type == OID_PKI_DATA:
            return _pki_data(econtent, depth)
        if econtent_type == OID_DATA:
            if _looks_like_csr(econtent):
                return econtent, 1, "pkcs7"
            return _pki_data(econtent, depth)
        raise ValueError(f"The SignedData carries {econtent_type}, not a certificate request.")
    raise ValueError("The request is neither a PKCS#10 nor a CMC request.")


def _oid_at(der: bytes, el: tuple[int, int, int, int]) -> str:
    return _decode_oid(der[el[2]:el[3]])


def _decode_oid(body: bytes) -> str:
    if not body:
        raise ValueError("empty OID")
    first = body[0]
    arcs = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    v = 0
    for b in body[1:]:
        v = (v << 7) | (b & 0x7F)
        if not b & 0x80:
            arcs.append(v)
            v = 0
    return ".".join(map(str, arcs))


def _encapsulated(der: bytes, start: int, end: int) -> tuple[str, bytes]:
    """SignedData's encapContentInfo: (eContentType, eContent)."""
    sd = list(children(der, start, end))
    if len(sd) != 1 or sd[0][0] != 0x30:
        raise ValueError("The SignedData is malformed.")
    parts = list(children(der, sd[0][2], sd[0][3]))
    # SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo SEQUENCE, [0] certs, [1] crls, signerInfos }
    if len(parts) < 3 or parts[2][0] != 0x30:
        raise ValueError("The SignedData is malformed.")
    eci = list(children(der, parts[2][2], parts[2][3]))
    if not eci or eci[0][0] != 0x06:
        raise ValueError("The SignedData has no content type.")
    ctype = _oid_at(der, eci[0])
    if len(eci) < 2 or eci[1][0] != 0xA0:
        raise ValueError("The SignedData has no content.")
    inner = list(children(der, eci[1][2], eci[1][3]))
    if len(inner) != 1 or inner[0][0] != 0x04:
        raise ValueError("The SignedData's content isn't an OCTET STRING.")
    return ctype, der[inner[0][2]:inner[0][3]]


def _pki_data(der: bytes, depth: int) -> tuple[bytes, int, str]:
    """PKIData ::= SEQUENCE { controlSequence, reqSequence, cmsSequence, otherMsgSequence }; exactly one
    TaggedCertificationRequest ([0] IMPLICIT SEQUENCE { bodyPartID, CertificationRequest }), or none and one nested
    ContentInfo in cmsSequence."""
    try:
        _, cs, ce = read_tlv(der)
        parts = list(children(der, cs, ce))
        if len(parts) != 4 or any(p[0] != 0x30 for p in parts):
            raise ValueError("PKIData has four sequences")
        reqs = list(children(der, parts[1][2], parts[1][3]))
        nested = list(children(der, parts[2][2], parts[2][3]))
    except ValueError as exc:
        raise ValueError("The CMC request (PKIData) is malformed.") from exc
    if len(reqs) > 1:
        raise ValueError("The CMC request has more than one certificate request; send one at a time.")
    if len(reqs) == 1:
        tag, _, rcs, rce = reqs[0]
        if tag != 0xA0:
            raise ValueError("Only PKCS#10 requests are accepted in a CMC request (not CRMF).")
        fields = list(children(der, rcs, rce))
        if len(fields) != 2 or fields[0][0] != 0x02 or fields[1][0] != 0x30:
            raise ValueError("The CMC request's certificate request is malformed.")
        body_part = int.from_bytes(der[fields[0][2]:fields[0][3]], "big", signed=True)
        if not 0 <= body_part <= 4294967295:
            raise ValueError("The CMC request's body part ID is out of range.")
        return der[fields[1][1]:fields[1][3]], body_part, "cmc"
    if len(nested) == 1:
        # TaggedContentInfo ::= SEQUENCE { bodyPartID, ContentInfo }
        tci = list(children(der, nested[0][2], nested[0][3]))
        if len(tci) == 2 and tci[1][0] == 0x30:
            return _request_in(der[tci[1][1]:tci[1][3]], depth + 1)
    raise ValueError("The CMC request has no certificate request.")


def client_machine(token: bytes) -> str | None:
    """The PC's DNS name from Microsoft's client information attribute (1.3.6.1.4.1.311.21.20: SEQUENCE { clientId,
    machine name, user name, process name }), wherever the request carries it."""
    want = oid(OID_CLIENT_INFO)
    for start, end in _sequences(token, 0, len(token), 0):
        el = token[start:end]
        if want not in el[:len(want) + 6]:
            continue
        try:
            _, cs, ce = read_tlv(el)
            kids = list(children(el, cs, ce))
            if len(kids) != 2 or el[kids[0][1]:kids[0][3]] != want or kids[1][0] != 0x31:
                continue
            seq_ = list(children(el, kids[1][2], kids[1][3]))
            info = list(children(el, seq_[0][2], seq_[0][3])) if seq_ and seq_[0][0] == 0x30 else []
            if len(info) >= 2 and info[1][0] in (0x0C, 0x16, 0x13):
                name = el[info[1][2]:info[1][3]].decode("utf-8", "replace").strip().lower()
                return name[:253] or None
        except (ValueError, IndexError):
            continue
    return None


def signature_ok(csr: x509.CertificateSigningRequest) -> bool:
    """Proof of possession. Unlike cryptography's is_signature_valid this accepts SHA-1, which Windows uses when the
    policy names no hash (MS-WSTEP 4.1.1.1's own request is SHA-1); OpenBao (Go's CheckSignature) accepts it too."""
    alg = csr.signature_hash_algorithm
    if alg is None or alg.name not in ("sha1", "sha256", "sha384", "sha512"):
        return False
    key, sig, data = csr.public_key(), csr.signature, csr.tbs_certrequest_bytes
    try:
        if isinstance(key, rsa.RSAPublicKey):
            params = csr.signature_algorithm_parameters
            pad = params if isinstance(params, padding.PSS) else padding.PKCS1v15()
            key.verify(sig, data, pad, alg)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(sig, data, ec.ECDSA(alg))
        else:
            return False
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


# ROCA (CVE-2017-15361): Infineon TPMs before 2017 made RSA keys whose modulus N, for every small prime r up to 167,
# lies in the subgroup generated by 65537 mod r. A random modulus fails that test almost surely.
_ROCA_PRIMES = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
                109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167)


def _subgroup_65537(r: int) -> frozenset[int]:
    out, v = set(), 1
    while v not in out:
        out.add(v)
        v = v * 65537 % r
    return frozenset(out)


_ROCA_SETS = tuple((r, _subgroup_65537(r)) for r in _ROCA_PRIMES)


def roca_weak(public_key) -> bool:
    if not isinstance(public_key, rsa.RSAPublicKey):
        return False
    n = public_key.public_numbers().n
    return all(n % r in subgroup for r, subgroup in _ROCA_SETS)


def key_problem(csr: x509.CertificateSigningRequest) -> str | None:
    """Why the request's key isn't accepted, or None: RSA of 2048 bits or more (not ROCA), or EC P-256/P-384."""
    key = csr.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size < 2048:
            return f"The key is RSA {key.key_size}; at least 2048 bits are needed."
        if roca_weak(key):
            return ("The key has the ROCA weakness (CVE-2017-15361) of Infineon TPMs with old firmware. Update the TPM's "
                    "firmware (from the PC maker), clear the TPM, and enroll again.")
        return None
    if isinstance(key, ec.EllipticCurvePublicKey):
        return None if key.curve.name in ("secp256r1", "secp384r1") else f"The EC curve {key.curve.name} isn't accepted (P-256 or P-384)."
    return "Only RSA and EC keys are accepted."


def _looks_like_csr(der: bytes) -> bool:
    # CertificationRequest ::= SEQUENCE { SEQUENCE { INTEGER 0, Name, SubjectPublicKeyInfo, [0] attributes }, alg, sig }
    try:
        _, cs, ce = read_tlv(der)
        tag, _info_s, info_cs, info_ce = next(children(der, cs, ce))
        if tag != 0x30:
            return False
        vtag, _, vcs, vce = next(children(der, info_cs, info_ce))
        return vtag == 0x02 and der[vcs:vce] == b"\x00"
    except (ValueError, StopIteration):
        return False


def _sequences(data: bytes, start: int, end: int, depth: int) -> Iterator[tuple[int, int]]:
    """Every SEQUENCE in data[start:end], outermost first, looking inside constructed elements and OCTET STRINGs."""
    if depth > MAX_DEPTH:
        return
    try:
        elements = list(children(data, start, end))
    except ValueError:
        return
    for tag, el_start, cs, ce in elements:
        if tag == 0x30:
            yield el_start, ce
        if tag & 0x20 or tag == 0x04:  # constructed, or an OCTET STRING that may wrap DER (encapsulated content)
            yield from _sequences(data, cs, ce, depth + 1)


def template_of(csr: x509.CertificateSigningRequest) -> tuple[str | None, str | None]:
    """(template OID, template name) the request names, from Microsoft's template extensions, if any."""
    tpl_oid = name = None
    for ext in csr.extensions:
        if ext.oid.dotted_string == "1.3.6.1.4.1.311.21.7":
            v = ext.value
            tpl_oid = v.template_id.dotted_string if hasattr(v, "template_id") else None
        elif ext.oid.dotted_string == "1.3.6.1.4.1.311.20.2":
            raw = ext.value.value if hasattr(ext.value, "value") else b""
            try:
                tag, cs, ce = read_tlv(raw)
                name = raw[cs:ce].decode("utf-16-be") if tag == 0x1E else raw[cs:ce].decode("utf-8", "replace")
            except ValueError:
                name = None
    return tpl_oid, name


# ── Extensions EasyEAP puts in certificates ─────────────────────────────────

def template_extension(template_oid: str, major: int, minor: int = 0) -> bytes:
    """szOID_CERTIFICATE_TEMPLATE (1.3.6.1.4.1.311.21.7): SEQUENCE { templateID, majorVersion, minorVersion }."""
    return seq(oid(template_oid), integer(major), integer(minor))


def san_extension(*, dns: list[str] | None = None, upn: str | None = None) -> bytes:
    """subjectAltName with dNSName and/or the Microsoft UPN otherName (1.3.6.1.4.1.311.20.2.3)."""
    names = [tlv(0x82, d.encode("ascii")) for d in dns or []]
    if upn:
        names.append(tlv(0xA0, oid("1.3.6.1.4.1.311.20.2.3") + explicit(0, utf8(upn))))
    if not names:
        raise ValueError("A subject alternative name needs a DNS name or a UPN.")
    return seq(*names)


# ── The CMC full PKI response ────────────────────────────────────────────────

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_PKI_RESPONSE = "1.3.6.1.5.5.7.12.3"
OID_STATUS_INFO = "1.3.6.1.5.5.7.7.1"
OID_MS_CMC_ADD_ATTRIBUTES = "1.3.6.1.4.1.311.10.10.1"
OID_MS_ISSUED_CERT_HASH = "1.3.6.1.4.1.311.21.17"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_RSA_SHA256 = "1.2.840.113549.1.1.11"
CMC_SUCCESS, CMC_FAILED = 0, 2


CMC_BAD_REQUEST = 2  # CMCFailInfo badRequest


def pki_response(*, issued_der: bytes | None, status: int = CMC_SUCCESS, text: str = "Issued", body_part: int = 1,
                 fail_info: int | None = None) -> bytes:
    """PKIResponse ::= SEQUENCE { controlSequence, cmsSequence, otherMsgSequence }, shaped like AD CS's (MS-WCCE
    3.2.1.4.2.1.4.8.2): the status for the request's body part and, when issued, Microsoft's issued-certificate hash."""
    status_info = seq(integer(status), seq(integer(body_part)), utf8(text), *([integer(fail_info)] if fail_info is not None else []))
    controls = [seq(integer(1), oid(OID_STATUS_INFO), set_of(status_info))]
    if issued_der is not None:
        cert_hash = seq(oid(OID_MS_ISSUED_CERT_HASH), set_of(octets(hashlib.sha1(issued_der).digest())))  # noqa: S324 — the format
        add_attrs = seq(integer(0), seq(integer(body_part)), set_of(cert_hash))
        controls.append(seq(integer(2), oid(OID_MS_CMC_ADD_ATTRIBUTES), set_of(add_attrs)))
    return seq(seq(*controls), seq(), seq())


def signed_response(content: bytes, certificates: list[bytes], signer_cert: x509.Certificate, signer_key) -> bytes:
    """ContentInfo(SignedData) with eContentType id-cct-PKIResponse, signed (SHA-256) by the enrollment-service key."""
    digest = hashlib.sha256(content).digest()
    attrs = [seq(oid(OID_CONTENT_TYPE), set_of(oid(OID_PKI_RESPONSE))), seq(oid(OID_MESSAGE_DIGEST), set_of(octets(digest)))]
    attrs_content = b"".join(sorted(attrs))
    signed_attrs_set = tlv(0x31, attrs_content)  # signed as a SET OF (RFC 5652 5.4), carried as [0] IMPLICIT
    if isinstance(signer_key, ec.EllipticCurvePrivateKey):
        sig_alg, sig = seq(oid(OID_ECDSA_SHA256)), signer_key.sign(signed_attrs_set, ec.ECDSA(hashes.SHA256()))
    elif isinstance(signer_key, rsa.RSAPrivateKey):
        sig_alg, sig = seq(oid(OID_RSA_SHA256), tlv(0x05, b"")), signer_key.sign(signed_attrs_set, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise ValueError("The enrollment-service key must be ECDSA or RSA.")
    issuer_serial = seq(signer_cert.issuer.public_bytes(), integer(signer_cert.serial_number))
    signer_info = seq(integer(1), issuer_serial, seq(oid(OID_SHA256)),
                      tlv(0xA0, attrs_content), sig_alg, octets(sig))
    signer_der = signer_cert.public_bytes(serialization.Encoding.DER)
    certs = [signer_der] + [c for c in certificates if c != signer_der]
    signed_data = seq(integer(3), set_of(seq(oid(OID_SHA256))), seq(oid(OID_PKI_RESPONSE), explicit(0, octets(content))),
                      tlv(0xA0, b"".join(certs)), set_of(signer_info))
    return seq(oid(OID_SIGNED_DATA), explicit(0, signed_data))


def unsigned_response(content: bytes, certificates: list[bytes]) -> bytes:
    """The same SignedData as `signed_response`, with no signer: AD CS's shape for a CA whose key EasyEAP can't use
    (tranquilit/adcs_python answers Windows this way when it fronts another PKI)."""
    signed_data = seq(integer(3), set_of(seq(oid(OID_SHA256))), seq(oid(OID_PKI_RESPONSE), explicit(0, octets(content))),
                      tlv(0xA0, b"".join(certificates)), set_of())
    return seq(oid(OID_SIGNED_DATA), explicit(0, signed_data))


def chain_pkcs7(certificates: list[bytes]) -> bytes:
    """A degenerate PKCS#7 (certificates only), for clients that read the chain from it."""
    signed_data = seq(integer(1), set_of(), seq(oid("1.2.840.113549.1.7.1")), tlv(0xA0, b"".join(certificates)), set_of())
    return seq(oid(OID_SIGNED_DATA), explicit(0, signed_data))
