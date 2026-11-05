"""Plain-language explanations of RADIUS/TLS failures. Mirrors frontend/src/domain/explain.ts."""
from __future__ import annotations

import re

EXPLANATIONS: dict[str, dict[str, str]] = {
    "unknown_ca": {"title": "Certificate from an untrusted authority",
                   "explanation": "The device presented a certificate issued by an authority that this RADIUS server does not trust.",
                   "fix": "Re-enroll the device so it receives a certificate from this tenant's issuing CA, or remove a stale certificate the device chose instead."},
    "cert_expired": {"title": "Certificate has expired",
                     "explanation": "The device's certificate is past its expiry date, so the server refused it.",
                     "fix": "Renew the certificate from the user's enrollment page and install the new package on the device."},
    "cert_revoked": {"title": "Certificate was revoked",
                     "explanation": "This certificate was revoked by an administrator and can no longer be used to connect.",
                     "fix": "If the device should still have access, issue it a new certificate. Revocation cannot be undone."},
    "cert_unknown": {"title": "Certificate not issued by EasyEAP",
                     "explanation": "The certificate chains to a trusted CA but EasyEAP has no record of issuing it, so it is treated as untrusted.",
                     "fix": "Check for certificates issued outside EasyEAP from the same CA, then re-enroll the device."},
    "identity_unauthorized": {"title": "User is not authorized for Wi-Fi",
                              "explanation": "The certificate is valid, but none of the user's directory groups grant Wi-Fi access.",
                              "fix": "Add the user to a group with an Allow rule, or add a rule for one of their groups."},
    "account_disabled": {"title": "Directory account is disabled or locked",
                         "explanation": "Active Directory reports this account as disabled, locked out or deleted, so access is denied.",
                         "fix": "Re-enable or unlock the account in Active Directory, then run a directory sync."},
    "policy_deny": {"title": "Denied by an access rule",
                    "explanation": "An explicit Deny rule matched one of the user's groups. Deny rules always take precedence.",
                    "fix": "Review the rule that denied access, or remove the user from the denied group."},
    "vlan_assignment": {"title": "VLAN could not be applied",
                        "explanation": "Authentication succeeded but the controller did not place the client on the assigned VLAN (it may not exist on the controller or interface group).",
                        "fix": "Confirm the VLAN exists on the controller and that AAA override / RADIUS VLAN assignment is enabled on the SSID."},
    "snapshot_stale": {"title": "Authorization data is out of date",
                       "explanation": "The RADIUS server's copy of authorization data is older than the allowed maximum, so it failed safe and denied access.",
                       "fix": "Check that the EasyEAP API and worker are running and that directory sync is succeeding."},
    "tls_handshake": {"title": "Secure handshake failed",
                      "explanation": "The device and server could not complete the TLS handshake, often because the device does not trust the server certificate.",
                      "fix": "Install the Root CA on the device and make sure its Wi-Fi profile names the RADIUS server certificate's hostname."},
    "client_timeout": {"title": "Device stopped responding",
                       "explanation": "The device stopped answering midway through authentication. This often means it rejected the server certificate silently.",
                       "fix": "Check the device trusts the Root CA and the server name in its Wi-Fi profile matches."},
}

# FreeRADIUS / OpenSSL messages → failure codes (first match wins).
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"certificate has expired|cert(ificate)? expired", re.I), "cert_expired"),
    (re.compile(r"certificate revoked|revoked", re.I), "cert_revoked"),
    (re.compile(r"unable to get (local )?issuer|unknown ca|self.signed certificate in certificate chain|unable to verify the first certificate", re.I), "unknown_ca"),
    (re.compile(r"no eap.?start|no response|timed? ?out|client didn't|expired session|did not finish", re.I), "client_timeout"),
    (re.compile(r"tls alert|ssl3?_|handshake|tls_|eap-tls", re.I), "tls_handshake"),
]


def classify(message: str | None) -> str | None:
    if not message:
        return None
    for pattern, code in _PATTERNS:
        if pattern.search(message):
            return code
    return None


def explain(code: str | None) -> dict[str, str] | None:
    return EXPLANATIONS.get(code or "")
