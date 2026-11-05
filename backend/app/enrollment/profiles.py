"""Platform Wi-Fi profiles for EAP-TLS. Every profile pins the RADIUS server name and the tenant Root CA so devices
do not trust an impostor access point."""
from __future__ import annotations

import base64
import plistlib
import uuid
from xml.sax.saxutils import escape

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

PKCS12_MARKER = "EASYEAP-PKCS12-BASE64"


def _thumbprint(pem: str) -> str:
    cert = x509.load_pem_x509_certificate(pem.encode())
    h = cert.fingerprint(hashes.SHA1()).hex()  # Windows WLAN profiles identify trusted roots by SHA-1 thumbprint
    return " ".join(h[i:i + 2] for i in range(0, len(h), 2))


def _der(pem: str) -> bytes:
    return x509.load_pem_x509_certificate(pem.encode()).public_bytes(Encoding.DER)


def windows_wlan_xml(ssid: str, server_name: str, root_pem: str, wpa3: bool = False) -> str:
    auth = "WPA3ENT" if wpa3 else "WPA2"
    hex_ssid = ssid.encode().hex().upper()
    return f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{escape(ssid)}</name>
  <SSIDConfig><SSID><hex>{hex_ssid}</hex><name>{escape(ssid)}</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM><security>
    <authEncryption><authentication>{auth}</authentication><encryption>AES</encryption><useOneX>true</useOneX></authEncryption>
    <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
      <authMode>user</authMode>
      <EAPConfig><EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
        <EapMethod><Type xmlns="http://www.microsoft.com/provisioning/EapCommon">13</Type><VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId><VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType><AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId></EapMethod>
        <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
          <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>13</Type>
            <EapType xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1">
              <CredentialsSource><CertificateStore><SimpleCertSelection>true</SimpleCertSelection></CertificateStore></CredentialsSource>
              <ServerValidation>
                <DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation>
                <ServerNames>{escape(server_name)}</ServerNames>
                <TrustedRootCA>{_thumbprint(root_pem)}</TrustedRootCA>
              </ServerValidation>
              <DifferentUsername>false</DifferentUsername>
            </EapType>
          </Eap>
        </Config>
      </EapHostConfig></EAPConfig>
    </OneX>
  </security></MSM>
</WLANProfile>
"""


def windows_powershell(api_base: str, token: str, ssid: str, server_name: str, root_pem: str, issuing_pem: str, wpa3: bool = False) -> str:
    """Enrollment helper: TPM-backed key via certreq when available, CSR to EasyEAP, install cert + CA + Wi-Fi profile."""
    xml = windows_wlan_xml(ssid, server_name, root_pem, wpa3).replace("'", "''")
    return f"""# EasyEAP Wi-Fi enrollment for Windows. Run in PowerShell as the user who will connect (no admin rights needed).
# The private key is created on this computer (in the TPM when available) and never leaves it.
$ErrorActionPreference = 'Stop'
$Api = '{api_base.rstrip('/')}'
$Token = '{token}'
$Work = Join-Path $env:TEMP ('easyeap-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $Work | Out-Null
try {{
  $Provider = 'Microsoft Software Key Storage Provider'
  try {{ if ((Get-Tpm -ErrorAction Stop).TpmReady) {{ $Provider = 'Microsoft Platform Crypto Provider' }} }} catch {{ }}
  Write-Host "Creating key with: $Provider"
@"
[Version]
Signature="`$Windows NT`$"
[NewRequest]
Subject = "CN=EasyEAP enrollment"
KeyAlgorithm = ECDSA_P256
KeyLength = 256
HashAlgorithm = SHA256
Exportable = FALSE
MachineKeySet = FALSE
ProviderName = "$Provider"
RequestType = PKCS10
"@ | Set-Content -Path "$Work\\req.inf" -Encoding ASCII
  certreq.exe -q -new "$Work\\req.inf" "$Work\\req.csr" | Out-Null
  $Csr = Get-Content "$Work\\req.csr" -Raw
  $Body = @{{ csr = $Csr; key_origin = 'device'; device_hint = $env:COMPUTERNAME }} | ConvertTo-Json
  $Resp = Invoke-RestMethod -Method Post -Uri "$Api/api/enroll/$Token/csr" -ContentType 'application/json' -Body $Body
  Set-Content -Path "$Work\\cert.pem" -Value $Resp.certificate_pem -Encoding ASCII
  certreq.exe -q -accept -user "$Work\\cert.pem" | Out-Null
@'
{root_pem.strip()}
'@ | Set-Content -Path "$Work\\root.pem" -Encoding ASCII
@'
{issuing_pem.strip()}
'@ | Set-Content -Path "$Work\\issuing.pem" -Encoding ASCII
  Import-Certificate -FilePath "$Work\\root.pem" -CertStoreLocation Cert:\\CurrentUser\\Root | Out-Null
  Import-Certificate -FilePath "$Work\\issuing.pem" -CertStoreLocation Cert:\\CurrentUser\\CA | Out-Null
@'
{xml}
'@ | Set-Content -Path "$Work\\wifi.xml" -Encoding UTF8
  netsh wlan add profile filename="$Work\\wifi.xml" user=current | Out-Null
  Write-Host "Done. Connect to '{ssid}' — no password needed." -ForegroundColor Green
}} finally {{
  Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
}}
"""


def apple_mobileconfig(*, ssid: str, server_name: str, root_pem: str, issuing_pem: str, org: str, tenant_slug: str,
                       identity_label: str, wpa3: bool = False, pkcs12_b64: str | None = None) -> bytes:
    """Unsigned configuration profile. Without `pkcs12_b64` the identity payload carries PKCS12_MARKER for the
    enrollment page to replace with the PKCS#12 it assembled locally."""
    root_uuid, iss_uuid, p12_uuid, wifi_uuid = (str(uuid.uuid4()).upper() for _ in range(4))
    ident = f"com.easyeap.{tenant_slug}.wifi"
    p12_data = base64.b64decode(pkcs12_b64) if pkcs12_b64 else PKCS12_MARKER.encode()
    payloads = [
        {"PayloadType": "com.apple.security.root", "PayloadVersion": 1, "PayloadIdentifier": f"{ident}.root", "PayloadUUID": root_uuid,
         "PayloadDisplayName": f"{org} Root CA", "PayloadContent": _der(root_pem)},
        {"PayloadType": "com.apple.security.pkcs1", "PayloadVersion": 1, "PayloadIdentifier": f"{ident}.issuing", "PayloadUUID": iss_uuid,
         "PayloadDisplayName": f"{org} Issuing CA", "PayloadContent": _der(issuing_pem)},
        {"PayloadType": "com.apple.security.pkcs12", "PayloadVersion": 1, "PayloadIdentifier": f"{ident}.identity", "PayloadUUID": p12_uuid,
         "PayloadDisplayName": f"Wi-Fi certificate ({identity_label})", "PayloadContent": p12_data},
        {"PayloadType": "com.apple.wifi.managed", "PayloadVersion": 1, "PayloadIdentifier": f"{ident}.network", "PayloadUUID": wifi_uuid,
         "PayloadDisplayName": ssid, "SSID_STR": ssid, "HIDDEN_NETWORK": False, "AutoJoin": True,
         "EncryptionType": "WPA3" if wpa3 else "WPA2", "PayloadCertificateUUID": p12_uuid,
         "EAPClientConfiguration": {"AcceptEAPTypes": [13], "TLSTrustedServerNames": [server_name],
                                    "PayloadCertificateAnchorUUID": [root_uuid, iss_uuid], "TLSAllowTrustExceptions": False}},
    ]
    profile = {"PayloadType": "Configuration", "PayloadVersion": 1, "PayloadIdentifier": ident, "PayloadUUID": str(uuid.uuid4()).upper(),
               "PayloadDisplayName": f"{org} Wi-Fi ({ssid})", "PayloadOrganization": org,
               "PayloadDescription": "Installs your Wi-Fi certificate and connects you to the network. Created by EasyEAP.",
               "PayloadRemovalDisallowed": False, "PayloadContent": payloads}
    out = plistlib.dumps(profile, fmt=plistlib.FMT_XML)
    if not pkcs12_b64:
        out = out.replace(base64.b64encode(PKCS12_MARKER.encode()), PKCS12_MARKER.encode())
    return out


def networkmanager(ssid: str, server_name: str, identity: str, wpa3: bool = False) -> str:
    return f"""# Save as /etc/NetworkManager/system-connections/{ssid}.nmconnection (mode 600), then: nmcli connection reload
[connection]
id={ssid}
type=wifi

[wifi]
mode=infrastructure
ssid={ssid}

[wifi-security]
key-mgmt=wpa-eap
pmf={3 if wpa3 else 2}

[802-1x]
eap=tls;
identity={identity}
ca-cert=/etc/easyeap/ca-chain.pem
client-cert=/etc/easyeap/client.pem
private-key=/etc/easyeap/client.key
private-key-password-flags=4
domain-suffix-match={server_name}

[ipv4]
method=auto

[ipv6]
method=auto
"""


def wpa_supplicant(ssid: str, server_name: str, identity: str) -> str:
    return f"""network={{
    ssid="{ssid}"
    key_mgmt=WPA-EAP
    eap=TLS
    identity="{identity}"
    ca_cert="/etc/easyeap/ca-chain.pem"
    client_cert="/etc/easyeap/client.pem"
    private_key="/etc/easyeap/client.key"
    domain_suffix_match="{server_name}"
}}
"""


def instructions(platform: str, ssid: str, server_name: str) -> list[str]:
    if platform == "windows":
        return ["Download the enrollment helper and run it in PowerShell (right-click → Run with PowerShell).",
                "Approve the prompt to trust your organization's Root CA.",
                f"Connect to “{ssid}”. No password is needed."]
    if platform in ("macos", "ios"):
        return ["Download the profile on this device.",
                "iPhone/iPad: open Settings → Profile Downloaded → Install. Mac: open System Settings → Privacy & Security → Profiles.",
                "When asked for the certificate password, enter the one shown on this page.",
                f"Join “{ssid}”."]
    if platform == "android":
        return ["Download the certificate file on this device.",
                "Open Settings → Security → More security settings → Install from device storage → Wi-Fi certificate, and pick the file.",
                f"Open Wi-Fi → “{ssid}”: EAP method TLS, CA certificate = the one you installed, Domain = {server_name}, Identity = your email.",
                "Save and connect."]
    return ["Save the certificate, key and CA chain under /etc/easyeap/ (key mode 600).",
            "Install the NetworkManager profile or add the wpa_supplicant block.",
            f"Connect to “{ssid}”. The profile checks that the server name is {server_name}."]
