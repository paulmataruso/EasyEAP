"""SOAP for Group Policy autoenrollment: MS-XCEP GetPolicies and MS-WSTEP RequestSecurityToken (docs/plans/
gpo-autoenrollment.md §2.1, §2.4, §2.6).

Requests are parsed with the standard library after refusing any DTD (no entity can be declared, so none can be
expanded) and anything over 64 KiB. Responses are written as text, element for element in the order and namespaces of
the specs' own examples (MS-XCEP 4.1.1.2, MS-WSTEP 4.1.1.2) and of tranquilit/adcs_python, which Windows accepts.
"""
from __future__ import annotations

import base64
import binascii
import uuid
import xml.etree.ElementTree as ET  # DTDs are refused before parsing (see _parse)
from dataclasses import dataclass, field
from xml.parsers import expat
from xml.sax.saxutils import escape, quoteattr

MAX_BODY = 65536

NS_S = "http://www.w3.org/2003/05/soap-envelope"
NS_A = "http://www.w3.org/2005/08/addressing"
NS_XCEP = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"
NS_WST = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
NS_WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
NS_ENROLL = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment"
NS_AUTH = "http://schemas.xmlsoap.org/ws/2006/12/authorization"
NS_DIAG = "http://schemas.microsoft.com/2004/09/ServiceModel/Diagnostics"

ACTION_GET_POLICIES = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"
ACTION_GET_POLICIES_RESPONSE = ACTION_GET_POLICIES + "Response"
ACTION_RST = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep"
ACTION_RSTRC = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep"
ACTION_WSTEP_FAULT = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RequestSecurityTokenCertificateEnrollmentWSDetailFault"
ACTION_FAULT = "http://www.w3.org/2005/08/addressing/soap/fault"
REQUEST_ISSUE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"
TOKEN_X509 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"  # noqa: S105 — a URI
VALUE_PKCS7 = NS_WSSE + "#PKCS7"
ENCODING_B64 = NS_WSSE + "#base64binary"
CONTENT_TYPE = "application/soap+xml; charset=utf-8"

# HRESULTs Windows writes to its event log (winerror.h), as the signed 32-bit ints the WSDL types ErrorCode as.
def _hr(v: int) -> int:
    return v - (1 << 32) if v & 0x80000000 else v


CERTSRV_E_BAD_REQUESTSUBJECT = _hr(0x80094001)
CERTSRV_E_ENROLL_DENIED = _hr(0x80094011)
CERTSRV_E_TEMPLATE_DENIED = _hr(0x80094012)
CERTSRV_E_UNSUPPORTED_CERT_TYPE = _hr(0x80094800)
CERTSRV_E_KEY_LENGTH = _hr(0x80094811)
E_INVALIDARG = _hr(0x80070057)
E_FAIL = _hr(0x80004005)


class SoapError(ValueError):
    """A request that isn't the SOAP message it should be."""


# ── Parsing ──────────────────────────────────────────────────────────────────


def _refuse_dtd(*_args: object) -> None:
    raise SoapError("Document type declarations aren't accepted.")


def _parse(body: bytes) -> ET.Element:
    if len(body) > MAX_BODY:
        raise SoapError("The message is larger than 64 KiB.")
    # Expat itself refuses any DOCTYPE or entity declaration, in whatever encoding and wherever it is, before
    # ElementTree parses the message.
    guard = expat.ParserCreate()
    guard.StartDoctypeDeclHandler = _refuse_dtd
    guard.EntityDeclHandler = _refuse_dtd
    try:
        guard.Parse(body, True)
        return ET.fromstring(body)  # noqa: S314 — no DTD (refused above), so no entities to expand
    except (expat.ExpatError, ET.ParseError) as exc:
        raise SoapError(f"The message isn't well-formed XML ({exc}).") from None


def _text(el: ET.Element | None) -> str:
    return (el.text or "").strip() if el is not None else ""


def _header(root: ET.Element) -> tuple[str, str]:
    """(Action, MessageID) from the SOAP header."""
    if root.tag != f"{{{NS_S}}}Envelope":
        raise SoapError("This isn't a SOAP 1.2 envelope.")
    hdr = root.find(f"{{{NS_S}}}Header")
    return _text(hdr.find(f"{{{NS_A}}}Action") if hdr is not None else None), _text(hdr.find(f"{{{NS_A}}}MessageID") if hdr is not None else None)


@dataclass(frozen=True)
class GetPolicies:
    message_id: str
    policy_oids: list[str] = field(default_factory=list)  # requestFilter/policyOIDs: answer only these, when given


def parse_get_policies(body: bytes) -> GetPolicies:
    root = _parse(body)
    action, message_id = _header(root)
    gp = root.find(f"{{{NS_S}}}Body/{{{NS_XCEP}}}GetPolicies")
    if gp is None:
        raise SoapError(f"This isn't a GetPolicies request (action {action or 'none'}).")
    oids = [_text(o) for o in gp.findall(f"{{{NS_XCEP}}}requestFilter/{{{NS_XCEP}}}policyOIDs/{{{NS_XCEP}}}oid") if _text(o)]
    return GetPolicies(message_id=message_id, policy_oids=oids)


@dataclass(frozen=True)
class RequestSecurityToken:
    message_id: str
    request_type: str
    token: bytes                     # the BinarySecurityToken, decoded
    context: dict[str, str]          # auth:AdditionalContext items (Windows sends ccm, the client's machine name, etc.)


def parse_rst(body: bytes) -> RequestSecurityToken:
    root = _parse(body)
    _action, message_id = _header(root)
    rst = root.find(f"{{{NS_S}}}Body/{{{NS_WST}}}RequestSecurityToken")
    if rst is None:
        raise SoapError("This isn't a RequestSecurityToken.")
    request_type = _text(rst.find(f"{{{NS_WST}}}RequestType"))
    bst = rst.find(f"{{{NS_WSSE}}}BinarySecurityToken")
    token = b""
    if bst is not None:
        raw = "".join((bst.text or "").split())
        try:
            token = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError):
            raise SoapError("The BinarySecurityToken isn't valid base64.") from None
    context = {}
    for item in rst.findall(f"{{{NS_AUTH}}}AdditionalContext/{{{NS_AUTH}}}ContextItem"):
        name = item.get("Name") or ""
        if name:
            context[name[:64]] = _text(item.find(f"{{{NS_AUTH}}}Value"))[:256]
    return RequestSecurityToken(message_id=message_id, request_type=request_type, token=token, context=context)


# ── XCEP GetPoliciesResponse ─────────────────────────────────────────────────

OID_RSA = "1.2.840.113549.1.1.1"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_TEMPLATE_EXT = "1.3.6.1.4.1.311.21.7"
OID_EKU = "2.5.29.37"
OID_KEY_USAGE = "2.5.29.15"
OID_APP_POLICIES = "1.3.6.1.4.1.311.21.10"

# Flags pinned from MS-XCEP 3.1.4.1.3.1 (docs/plans/gpo-autoenrollment.md §2.4).
ENROLL_AUTOENROLLMENT = 0x20
ENROLL_REMOVE_INVALID = 0x400       # delete expired, revoked or renewed certificates of this template
GENERAL_MACHINE = 0x40
SUBJECT_DNS_AS_CN_AND_DNS_SAN = 0x10000000 | 0x08000000   # computer: built from dNSHostName
SUBJECT_DN_AND_UPN_SAN = 0x80000000 | 0x02000000          # user: built from the directory
PROVIDERS = ("Microsoft Platform Crypto Provider", "Microsoft Software Key Storage Provider")


@dataclass(frozen=True)
class TemplatePolicy:
    common_name: str          # unique in the response: EasyEAP-Computer / EasyEAP-User
    display_name: str         # the OID's defaultName, shown in certmgr
    oid: str                  # the template OID (AD CS style)
    major: int
    minor: int
    validity_seconds: int
    renewal_seconds: int
    machine: bool
    extensions: tuple[tuple[str, bool, bytes], ...]  # (OID, critical, DER value) Windows puts in the request


class _Oids:
    """The response's OID table: one oIDReferenceID per (value, group)."""

    def __init__(self) -> None:
        self.rows: list[tuple[str, int, int, str]] = []

    def ref(self, value: str, group: int, name: str) -> int:
        for v, g, r, _ in self.rows:
            if v == value and g == group:
                return r
        r = len(self.rows) + 1
        self.rows.append((value, group, r, name))
        return r


def _nil(tag: str) -> str:
    return f'<{tag} xsi:nil="true"/>'


def _el(tag: str, value: object) -> str:
    return f"<{tag}>{escape(str(value))}</{tag}>"


def get_policies_response(*, relates_to: str, policy_id: str, friendly_name: str, ces_uri: str, ca_der: bytes,
                          templates: list[TemplatePolicy], next_update_hours: int = 8) -> str:
    oids = _Oids()
    names = {OID_TEMPLATE_EXT: "Certificate Template Information", OID_EKU: "Enhanced Key Usage", OID_KEY_USAGE: "Key Usage",
             OID_APP_POLICIES: "Application Policies"}
    policies = []
    for t in templates:
        policy_ref = oids.ref(t.oid, 9, t.display_name)
        alg_ref = oids.ref(OID_RSA, 3, "RSA")
        hash_ref = oids.ref(OID_SHA256, 1, "sha256")
        exts = "".join(
            f"<extension>{_el('oIDReference', oids.ref(o, 6, names.get(o, o)))}{_el('critical', 'true' if crit else 'false')}"
            f"{_el('value', base64.b64encode(v).decode())}</extension>" for o, crit, v in t.extensions)
        policies.append(
            "<policy>"
            f"{_el('policyOIDReference', policy_ref)}<cAs>{_el('cAReference', 0)}</cAs>"
            "<attributes>"
            f"{_el('commonName', t.common_name)}{_el('policySchema', 3)}"
            f"<certificateValidity>{_el('validityPeriodSeconds', t.validity_seconds)}{_el('renewalPeriodSeconds', t.renewal_seconds)}</certificateValidity>"
            f"<permission>{_el('enroll', 'true')}{_el('autoEnroll', 'true')}</permission>"
            "<privateKeyAttributes>"
            f"{_el('minimalKeyLength', 2048)}{_el('keySpec', 1)}{_nil('keyUsageProperty')}{_nil('permissions')}"
            f"{_el('algorithmOIDReference', alg_ref)}"
            f"<cryptoProviders>{''.join(_el('provider', p) for p in PROVIDERS)}</cryptoProviders>"
            "</privateKeyAttributes>"
            f"<revision>{_el('majorRevision', t.major)}{_el('minorRevision', t.minor)}</revision>"
            f"{_nil('supersededPolicies')}"
            f"{_el('privateKeyFlags', 0)}"
            f"{_el('subjectNameFlags', SUBJECT_DNS_AS_CN_AND_DNS_SAN if t.machine else SUBJECT_DN_AND_UPN_SAN)}"
            f"{_el('enrollmentFlags', ENROLL_AUTOENROLLMENT | ENROLL_REMOVE_INVALID)}"
            f"{_el('generalFlags', GENERAL_MACHINE if t.machine else 0)}"
            f"{_el('hashAlgorithmOIDReference', hash_ref)}"
            f"{_nil('rARequirements')}{_nil('keyArchivalAttributes')}"
            f"<extensions>{exts}</extensions>"
            "</attributes></policy>")
    if policies:
        body_policies = f"<policies>{''.join(policies)}</policies>"
        cas = ("<cAs><cA><uris><cAURI>"
               f"{_el('clientAuthentication', 2)}{_el('uri', ces_uri)}{_el('priority', 1)}{_el('renewalOnly', 'false')}"
               f"</cAURI></uris>{_el('certificate', base64.b64encode(ca_der).decode())}{_el('enrollPermission', 'true')}"
               f"{_el('cAReferenceID', 0)}</cA></cAs>")
        oid_xml = "<oIDs>" + "".join(
            f"<oID>{_el('value', v)}{_el('group', g)}{_el('oIDReferenceID', r)}{_el('defaultName', n)}</oID>" for v, g, r, n in oids.rows
        ) + "</oIDs>"
    else:  # PolicyCollection, CACollection and OIDCollection need at least one member: nil when empty
        body_policies, cas, oid_xml = _nil("policies"), _nil("cAs"), _nil("oIDs")
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<s:Envelope xmlns:s="{NS_S}" xmlns:a="{NS_A}">'
        "<s:Header>"
        f'<a:Action s:mustUnderstand="1">{ACTION_GET_POLICIES_RESPONSE}</a:Action>'
        f"{_relates(relates_to)}{_activity()}"
        "</s:Header>"
        '<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">'
        f'<GetPoliciesResponse xmlns="{NS_XCEP}">'
        f"<response>{_el('policyID', policy_id)}{_el('policyFriendlyName', friendly_name)}{_el('nextUpdateHours', next_update_hours)}"
        f"{_nil('policiesNotChanged')}{body_policies}</response>"
        f"{cas}{oid_xml}"
        "</GetPoliciesResponse></s:Body></s:Envelope>"
    )


# ── WSTEP RequestSecurityTokenResponseCollection and faults ─────────────────


def _relates(message_id: str) -> str:
    return f"<a:RelatesTo>{escape(message_id)}</a:RelatesTo>" if message_id else ""


def _activity() -> str:
    return f'<ActivityId CorrelationId="{uuid.uuid4()}" xmlns="{NS_DIAG}">{uuid.uuid4()}</ActivityId>'


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def issued_response(*, relates_to: str, request_id: int, response_der: bytes, certificate_der: bytes) -> str:
    """MS-WSTEP 4.1.1.2: the CMC full PKI response in BinarySecurityToken, the certificate in RequestedSecurityToken."""
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<s:Envelope xmlns:s="{NS_S}" xmlns:a="{NS_A}">'
        f'<s:Header><a:Action s:mustUnderstand="1">{ACTION_RSTRC}</a:Action>{_relates(relates_to)}{_activity()}</s:Header>'
        "<s:Body>"
        f'<RequestSecurityTokenResponseCollection xmlns="{NS_WST}"><RequestSecurityTokenResponse>'
        f"<TokenType>{TOKEN_X509}</TokenType>"
        f'<DispositionMessage xml:lang="en-US" xmlns="{NS_ENROLL}">Issued</DispositionMessage>'
        f'<BinarySecurityToken ValueType={quoteattr(VALUE_PKCS7)} EncodingType={quoteattr(ENCODING_B64)} xmlns="{NS_WSSE}">'
        f"{_b64(response_der)}</BinarySecurityToken>"
        "<RequestedSecurityToken>"
        f'<BinarySecurityToken ValueType={quoteattr(TOKEN_X509)} EncodingType={quoteattr(ENCODING_B64)} xmlns="{NS_WSSE}">'
        f"{_b64(certificate_der)}</BinarySecurityToken>"
        "</RequestedSecurityToken>"
        f'<RequestID xmlns="{NS_ENROLL}">{int(request_id)}</RequestID>'
        "</RequestSecurityTokenResponse></RequestSecurityTokenResponseCollection>"
        "</s:Body></s:Envelope>"
    )


def wstep_fault(*, relates_to: str, reason: str, error_code: int, invalid_request: bool, request_id: int | None,
                binary_response: bytes | None = None) -> str:
    """MS-WSTEP 3.1.4.1.2.1: a SOAP fault whose CertificateEnrollmentWSDetail carries the HRESULT Windows logs."""
    detail = (f'<CertificateEnrollmentWSDetail xmlns="{NS_ENROLL}" xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
              'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
              + (f"<BinaryResponse>{_b64(binary_response)}</BinaryResponse>" if binary_response else '<BinaryResponse xsi:nil="true"/>')
              + f"<ErrorCode>{int(error_code)}</ErrorCode><InvalidRequest>{'true' if invalid_request else 'false'}</InvalidRequest>"
              + (f"<RequestID>{int(request_id)}</RequestID>" if request_id is not None else '<RequestID xsi:nil="true"/>')
              + "</CertificateEnrollmentWSDetail>")
    return _fault(ACTION_WSTEP_FAULT, relates_to, reason, detail)


def soap_fault(*, relates_to: str, reason: str) -> str:
    """A plain SOAP fault (for XCEP, and for a WSTEP message that can't be read at all)."""
    return _fault(ACTION_FAULT, relates_to, reason, "")


def _fault(action: str, relates_to: str, reason: str, detail: str) -> str:
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<s:Envelope xmlns:s="{NS_S}" xmlns:a="{NS_A}">'
        f'<s:Header><a:Action s:mustUnderstand="1">{action}</a:Action>{_relates(relates_to)}{_activity()}</s:Header>'
        "<s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code>"
        f'<s:Reason><s:Text xml:lang="en-US">{escape(reason)}</s:Text></s:Reason>'
        + (f"<s:Detail>{detail}</s:Detail>" if detail else "")
        + "</s:Fault></s:Body></s:Envelope>"
    )
