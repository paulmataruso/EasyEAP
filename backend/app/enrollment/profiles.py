"""Platform Wi-Fi and wired 802.1X profiles for EAP-TLS. Every profile pins the RADIUS server name and the tenant Root CA
so devices do not trust an impostor access point or switch."""
from __future__ import annotations

import base64
import plistlib
import re
import uuid
from xml.sax.saxutils import escape

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

PKCS12_MARKER = "EASYEAP-PKCS12-BASE64"


def _thumbprint(pem: str) -> str:
    cert = x509.load_pem_x509_certificate(pem.encode())
    h = cert.fingerprint(hashes.SHA1()).hex()  # noqa: S303 — Windows WLAN profiles identify trusted roots by SHA-1 thumbprint
    return " ".join(h[i:i + 2] for i in range(0, len(h), 2))


# PowerShell reads ‘ ’ ‚ ‛ as single quotes too (about_Quoting_Rules), so each is doubled like ' to stay literal.
_PS_QUOTES = re.compile("(['\u2018\u2019\u201a\u201b])")


def ps_quote(value: str) -> str:
    """A PowerShell single-quoted string literal."""
    return "'" + _PS_QUOTES.sub(r"\1\1", value) + "'"


def ps_here_ok(text: str) -> bool:
    """Whether text can sit in a single-quoted here-string: no line may start with a quote and @ (which ends it)."""
    return not re.search("^['\u2018\u2019\u201a\u201b]@", text, re.MULTILINE)


def _der(pem: str) -> bytes:
    return x509.load_pem_x509_certificate(pem.encode()).public_bytes(Encoding.DER)


def _eap_config(server_name: str, root_pem: str, issuers: list[str] | None = None) -> str:
    """The EAP-TLS method configuration shared by the Wi-Fi (WLAN) and wired (LAN) profiles. `issuers` (CA certificates,
    PEM) adds Windows' certificate filter, so a PC with other client certificates (an AD CS machine certificate, a VPN
    certificate) picks one issued by EasyEAP; it's what Group Policy's "Advanced → Certificate Issuer" writes."""
    extensions = ""
    if issuers:
        hashes = "".join(f"<IssuerHash>{_thumbprint(pem)}</IssuerHash>" for pem in issuers)
        extensions = ("""              <PerformServerValidation xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</PerformServerValidation>
              <AcceptServerName xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">true</AcceptServerName>
              <TLSExtensions xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV2">
                <FilteringInfo xmlns="http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV3"><CAHashList Enabled="true">"""
                      + hashes + """</CAHashList></FilteringInfo>
              </TLSExtensions>
""")
    return f"""      <EAPConfig><EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
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
{extensions}            </EapType>
          </Eap>
        </Config>
      </EapHostConfig></EAPConfig>
"""


AUTH_MODES = ("user", "machine", "machineOrUser")


def windows_wlan_xml(ssid: str, server_name: str, root_pem: str, wpa3: bool = False, *, auth_mode: str = "user",
                     issuers: list[str] | None = None) -> str:
    """`auth_mode`: user (the user's certificate, after sign-in), machine (the computer's, always) or machineOrUser
    (the computer's at the sign-in screen, the user's after). machine and machineOrUser need an all-users profile."""
    if auth_mode not in AUTH_MODES:
        raise ValueError(f"auth_mode must be one of {AUTH_MODES}")
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
      <authMode>{auth_mode}</authMode>
{_eap_config(server_name, root_pem, issuers)}    </OneX>
  </security></MSM>
</WLANProfile>
"""


def windows_lan_xml(server_name: str, root_pem: str, *, auth_mode: str = "user", issuers: list[str] | None = None) -> str:
    """Windows wired (LAN) profile: 802.1X with EAP-TLS and the user's certificate (or the computer's: `auth_mode`, as
    for Wi-Fi). OneXEnforced=false: on a port without 802.1X the computer still connects normally."""
    if auth_mode not in AUTH_MODES:
        raise ValueError(f"auth_mode must be one of {AUTH_MODES}")
    return f"""<?xml version="1.0"?>
<LANProfile xmlns="http://www.microsoft.com/networking/LAN/profile/v1">
  <MSM><security>
    <OneXEnforced>false</OneXEnforced>
    <OneXEnabled>true</OneXEnabled>
    <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
      <cacheUserData>true</cacheUserData>
      <authMode>{auth_mode}</authMode>
{_eap_config(server_name, root_pem, issuers)}    </OneX>
  </security></MSM>
</LANProfile>
"""


def windows_wired_script(server_name: str, root_pem: str, issuing_pem: str, org: str) -> str:
    """IT-deployed wired setup for Windows (docs/plans/wired-8021x.md §7): needs administrator rights (the Wired
    AutoConfig service and `netsh lan`), so it runs from an admin prompt, Intune, an RMM or a startup script as SYSTEM.
    Uses each user's existing EasyEAP certificate; contains nothing secret."""
    xml = windows_lan_xml(server_name, root_pem).replace("'", "''")
    return f"""# EasyEAP wired 802.1X for Windows ({org}). Run as administrator or SYSTEM (Intune, RMM, startup script).
# Uses the EasyEAP certificate each user already has from Wi-Fi enrollment; this script contains nothing secret.
# Note: the profile signs in with the user's certificate, so wired 802.1X starts after a user signs in. At the sign-in
# screen the port has no access unless the PC has a computer certificate (the Windows setup file installs one).
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$Work = Join-Path $env:TEMP ('easyeap-wired-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $Work | Out-Null
try {{
  # Wired AutoConfig is off by default on Windows.
  Set-Service -Name dot3svc -StartupType Automatic
  Start-Service -Name dot3svc
@'
{root_pem.strip()}
'@ | Set-Content -Path "$Work\\root.pem" -Encoding ASCII
@'
{issuing_pem.strip()}
'@ | Set-Content -Path "$Work\\issuing.pem" -Encoding ASCII
  Import-Certificate -FilePath "$Work\\root.pem" -CertStoreLocation Cert:\\LocalMachine\\Root | Out-Null
  Import-Certificate -FilePath "$Work\\issuing.pem" -CertStoreLocation Cert:\\LocalMachine\\CA | Out-Null
@'
{xml}
'@ | Set-Content -Path "$Work\\lan.xml" -Encoding UTF8
  $Adapters = Get-NetAdapter -Physical | Where-Object {{ $_.MediaType -eq '802.3' }}
  if (-not $Adapters) {{ Write-Host 'No wired network adapter found; nothing to configure.'; return }}
  foreach ($A in $Adapters) {{
    netsh lan add profile filename="$Work\\lan.xml" interface="$($A.Name)" | Out-Null
    Write-Host "Configured 802.1X on $($A.Name)"
  }}
  Write-Host 'Done. Users with an EasyEAP certificate connect on 802.1X ports after signing in.' -ForegroundColor Green
}} catch {{
  Write-Host "Setup did not finish: $($_.Exception.Message)" -ForegroundColor Red
  exit 1
}} finally {{
  Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
}}
"""


def _cn(pem: str) -> str:
    cert = x509.load_pem_x509_certificate(pem.encode())
    names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return str(names[0].value) if names else cert.subject.rfc4514_string()


def group_policy_guide(*, server_name: str, ssid: str, wpa3: bool, root_pem: str, issuing_pem: str, slug: str) -> dict:
    """Group Policy for domain PCs (docs/windows-group-policy.md, which mirrors this): trust, services, Wi-Fi and wired
    802.1X policies, filled with the tenant's values. Windows can't enroll from EasyEAP by itself (no Group Policy setting
    talks to a non-Microsoft CA), so users enroll through the portal; Group Policy sets up everything around it."""
    root_cn, issuing_cn, thumb = _cn(root_pem), _cn(issuing_pem), _thumbprint(root_pem).upper()
    eap = [
        "Network authentication method: Microsoft: Smart Card or other certificate → Properties.",
        "When connecting: Use a certificate on this computer, with Use simple certificate selection on. Advanced: Certificate "
        f"Issuer → tick {root_cn} (it lists roots installed on the PC you run Group Policy Management on, so import "
        f"{slug}-root.cer there first) and Extended Key Usage → Client Authentication.",
        f"Verify the server's identity by validating the certificate: on. Connect to these servers: {server_name}.",
        f"Trusted Root Certification Authorities: tick {root_cn} only.",
        "Don't prompt user to authorize new servers or trusted CAs: on (newer Group Policy Management: Notifications before "
        "connecting → Don't ask user). Without it, a user can accept an impostor's certificate.",
    ]
    return {
        "server_name": server_name, "ssid": ssid, "wpa3": wpa3, "root_cn": root_cn, "issuing_cn": issuing_cn, "root_thumbprint": thumb,
        "files": [
            {"name": f"{slug}-root.cer", "type": "application/x-x509-ca-cert", "content": root_pem},
            {"name": f"{slug}-issuing.cer", "type": "application/x-x509-ca-cert", "content": issuing_pem},
            {"name": f"{slug}-wifi.xml", "type": "application/xml", "content": windows_wlan_xml(ssid, server_name, root_pem, wpa3)},
            {"name": f"{slug}-wired.xml", "type": "application/xml", "content": windows_lan_xml(server_name, root_pem)},
        ],
        "sections": [
            {"title": "Before you start", "steps": [
                "Certificates come from the Windows setup file (a user's page → Windows setup: the user's and the computer's "
                "certificates, renewed automatically) or the EasyEAP portal. Group Policy sets up trust and the network policies "
                "around them. Group Policy autoenrollment from EasyEAP is planned.",
                "Create one GPO for the network (for example “EasyEAP 802.1X”) and link it to the OUs that hold the computers. "
                "Everything below is under Computer Configuration → Policies → Windows Settings → Security Settings.",
                "Download the files on this page. None of them is secret.",
            ]},
            {"title": "1. Trust the EasyEAP CA", "steps": [
                f"Public Key Policies → Trusted Root Certification Authorities → Import → {slug}-root.cer ({root_cn}, SHA-1 thumbprint "
                f"{thumb}). Every computer in the GPO's scope then trusts certificates from this CA.",
                f"Public Key Policies → Intermediate Certification Authorities → Import → {slug}-issuing.cer ({issuing_cn}).",
                "Don't add either to NTAuth (Enterprise NTAuth store): that would let this CA's certificates sign in to the domain "
                "with smart-card logon.",
            ]},
            {"title": "2. Start the 802.1X services", "steps": [
                "System Services → WLAN AutoConfig → Define this policy setting → Automatic (Wi-Fi).",
                "System Services → Wired AutoConfig → Define this policy setting → Automatic (it's off by default; wired 802.1X "
                "never starts without it).",
            ]},
            {"title": "3. Wi-Fi policy", "steps": [
                "Wireless Network (IEEE 802.11) Policies → Create A New Wireless Network Policy for Windows Vista and Later Releases.",
                f"General → Import… → {slug}-wifi.xml. That adds the {ssid} network with every setting below already made "
                + ("(and WPA3-Enterprise, which the Group Policy editor can't select)." if wpa3 else "(skip the next steps if you import it)."),
                f"Or Add → Infrastructure: Network name {ssid}; Security: {'WPA3-Enterprise' if wpa3 else 'WPA2-Enterprise'}, AES.",
                *eap,
                "Advanced → Specify authentication mode: User or computer authentication on PCs with a computer certificate, "
                "otherwise User authentication (see “Sign-in and machine certificates”).",
            ]},
            {"title": "4. Wired policy", "steps": [
                "Wired Network (IEEE 802.3) Policies → Create A New Wired Network Policy for Windows Vista and Later Releases.",
                "Security: Enable use of IEEE 802.1X authentication for network access.",
                *eap,
                "Advanced → Specify authentication mode: as for Wi-Fi. Cache user information for subsequent connections: on. "
                "Enforce use of IEEE 802.1X authentication: off, so the PC still works on ports without 802.1X.",
                f"Or deploy {slug}-wired.xml with the Windows wired kit's script instead of this policy, but never both on the same PCs.",
            ]},
            {"title": "Sign-in and machine certificates", "steps": [
                "With only user certificates the network starts after sign-in: on an enforcing switch port the sign-in screen has "
                "no network, a user who never signed in on that PC can't, and computer policy doesn't refresh before sign-in.",
                "A computer certificate fixes that. The Windows setup file installs one (a device certificate of that user, so the "
                "PC gets the user's access) and uses User or computer authentication: the computer's certificate at the sign-in "
                "screen, the user's after.",
                "In Group Policy profiles, choose User or computer authentication only for PCs with a computer certificate: "
                "without one, the sign-in screen still has no network. A Group Policy profile replaces the setup file's profile "
                "with the same name.",
            ]},
            {"title": "Check it", "steps": [
                "On a PC: gpupdate /force, then netsh wlan show profiles (the network is listed with “Group policy profiles”) and "
                "netsh lan show profiles.",
                f"certlm.msc → Trusted Root Certification Authorities shows {root_cn}.",
                "Run the Windows setup file on the PC (or the user enrolls from the portal), then connect. EasyEAP's Authentication log shows the result and, if it "
                "fails, why.",
                "A Group Policy profile wins over a profile with the same name installed by the EasyEAP helper; remove one of "
                "them so users see one network.",
                "Several client certificates on one PC: the issuer filter in step 3 makes Windows pick the EasyEAP one.",
            ]},
        ],
    }


WINDOWS_GPO_STEPS = [
    "Group Policy Management → a GPO linked to the computers → Computer Configuration → Policies → Windows Settings → "
    "Security Settings → System Services → Wired AutoConfig: Automatic.",
    "Same GPO → Security Settings → Wired Network (IEEE 802.3) Policies → Create A New Wired Network Policy for Windows Vista and Later Releases.",
    "Security tab: Enable IEEE 802.1X authentication; method Microsoft: Smart Card or other certificate; Authentication Mode: User authentication; "
    "Cache user information: on; Enforce use of IEEE 802.1X authentication: off.",
    "Properties of the method: Verify the server's identity, connect to these servers: the RADIUS server name below; trusted root: the "
    "tenant Root CA (deploy it under Trusted Root Certification Authorities in the same GPO).",
]


def windows_powershell(api_base: str, token: str, ssid: str, server_name: str, root_pem: str, issuing_pem: str, wpa3: bool = False,
                       renew_ps1: str | None = None, pin: str = "") -> str:
    """Enrollment helper: non-exportable key in the TPM when Windows can create one there (the software key store
    otherwise), CSR to EasyEAP, then the certificate, the CA chain and the Wi-Fi profile. Runs as a standard user.
    `renew_ps1` (windows_setup.renew_ps1, kind windows-helper): a per-user task renews the certificate, as the setup
    file's does when no administrator ran it (docs/plans/cert-renewal.md §15c item 8). `pin`: the server certificate's
    public key, accepted when the PC doesn't trust the certificate (windows_setup.tls_pin_ps)."""
    from app.enrollment.windows_setup import tls_pin_ps  # windows_setup imports this module
    xml = windows_wlan_xml(ssid, server_name, root_pem, wpa3)  # in a here-string: quotes stay as they are
    if renew_ps1 is not None and not ps_here_ok(renew_ps1):
        raise ValueError("the renewal script can't start a line with '@")
    root_b64 = base64.b64encode(_der(root_pem)).decode()
    script = f"""# EasyEAP Wi-Fi enrollment for Windows. Run in PowerShell as the user who will connect (no admin rights needed).
# The private key is created on this computer (in the TPM when available) and never leaves it.
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
{tls_pin_ps(pin)}
$Api = '{api_base.rstrip('/')}'
$Token = '{token}'
$Work = Join-Path $env:TEMP ('easyeap-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $Work | Out-Null

function New-EasyEapRequest([string]$Provider) {{
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
  Remove-Item "$Work\\req.csr" -ErrorAction SilentlyContinue
  # Windows PowerShell turns a native command's error output into a stopping error under 'Stop': not here.
  & {{ $ErrorActionPreference = 'Continue'; certreq.exe -q -new "$Work\\req.inf" "$Work\\req.csr" 2>&1 | Out-Null }}
  return ($LASTEXITCODE -eq 0) -and (Test-Path "$Work\\req.csr")
}}

$RenewPs1 = __RENEW_PS1__

function Install-Renewal {{
  # A daily and sign-in task for this user renews the certificate before it expires. Not when the EasyEAP setup file
  # already installed the shared one for everyone on this PC.
  if (-not $RenewPs1) {{ return $false }}
  # The setup file's shared task, when its script is for this EasyEAP (it renews only certificates under its own root).
  # The setup file leaves a note when it adds that task: a standard user can't always list it.
  $shared = Join-Path $env:ProgramFiles 'EasyEAP'
  # It must also reach EasyEAP the way this helper does: one from before the server-certificate pin can't, where Windows
  # doesn't trust EasyEAP's web certificate.
  $ours = $false
  try {{
    $text = Get-Content (Join-Path $shared 'renew.ps1') -Raw -ErrorAction Stop
    $ours = $text.Contains('{root_b64}') -and (-not $TlsPin -or $text.Contains("`$TlsPin = '$TlsPin'"))
  }} catch {{ }}
  if ($ours) {{
    if (Test-Path (Join-Path $shared 'renews-users.txt')) {{ return $true }}
    try {{
      if (Get-ScheduledTask -TaskPath '\\EasyEAP\\' -TaskName 'Renew user certificate' -ErrorAction SilentlyContinue) {{ return $true }}
    }} catch {{ }}
  }}
  $dir = Join-Path $env:LOCALAPPDATA 'EasyEAP'
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $renew = Join-Path $dir 'renew.ps1'
  Set-Content -Path $renew -Value $RenewPs1 -Encoding UTF8
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$renew`" -Scope User"
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
  $triggers = @((New-ScheduledTaskTrigger -Daily -At '10:00' -RandomDelay (New-TimeSpan -Hours 6)))
  $name = "EasyEAP renew certificate ($env:USERNAME)"
  try {{
    $logon = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\\$env:USERNAME"
    Register-ScheduledTask -TaskName $name -Action $action -Trigger ($triggers + $logon) -Settings $settings -Force | Out-Null
  }} catch {{
    # Some PCs don't let a standard user add a sign-in trigger: the daily one is enough.
    Register-ScheduledTask -TaskName $name -Action $action -Trigger $triggers -Settings $settings -Force | Out-Null
  }}
  $true
}}

try {{
  $Renewer = $null
  try {{ if (Install-Renewal) {{ $Renewer = 'windows-helper' }} }} catch {{
    Write-Host "Automatic renewal wasn't set up ($($_.Exception.Message)). Ask your IT team for a new link before the certificate expires." -ForegroundColor Yellow
  }}
  # Try the TPM first (no admin rights needed to create a key there); fall back to the software key store.
  $Provider = 'Microsoft Platform Crypto Provider'
  if (-not (New-EasyEapRequest $Provider)) {{
    $Provider = 'Microsoft Software Key Storage Provider'
    if (-not (New-EasyEapRequest $Provider)) {{ throw 'Windows could not create a key for the certificate request.' }}
  }}
  Write-Host "Key created with: $Provider"
  # ReadAllText, not Get-Content: Windows PowerShell's ConvertTo-Json writes a Get-Content string as an object.
  $Csr = [IO.File]::ReadAllText("$Work\\req.csr")
  $Body = @{{ csr = $Csr; key_origin = 'device'; device_hint = $env:COMPUTERNAME; renewer = $Renewer }} | ConvertTo-Json
  Use-EasyEapPin
  try {{
    $Resp = Invoke-RestMethod -Method Post -Uri "$Api/api/enroll/$Token/csr" -ContentType 'application/json' -Body $Body
  }} catch {{
    $hint = Get-EasyEapPinHint $_
    if ($hint) {{ throw ($_.Exception.Message + $hint) }}
    throw
  }}
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
  if ($Renewer) {{ Write-Host 'Your certificate renews itself before it expires.' }}
  Write-Host ('Done. Connect to "' + {ps_quote(ssid)} + '". No password is needed.') -ForegroundColor Green
}} catch {{
  $Err = $_
  $Msg = $Err.Exception.Message
  if ($Err.ErrorDetails -and $Err.ErrorDetails.Message) {{
    try {{ $Msg = ($Err.ErrorDetails.Message | ConvertFrom-Json).detail }} catch {{ $Msg = $Err.ErrorDetails.Message }}
  }}
  Write-Host "Setup did not finish: $Msg" -ForegroundColor Red
  Write-Host 'Nothing else was changed. Ask your IT team for help, and include this message.'
}} finally {{
  Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
}}
Read-Host 'Press Enter to close' | Out-Null
"""
    return script.replace("__RENEW_PS1__", "@'\n" + renew_ps1.rstrip("\n") + "\n'@" if renew_ps1 else "''", 1)


def apple_mobileconfig(*, ssid: str, server_name: str, root_pem: str, issuing_pem: str, org: str, tenant_slug: str,
                       identity_label: str, wpa3: bool = False, pkcs12_b64: str | None = None, wired: bool = False) -> bytes:
    """Unsigned configuration profile. Without `pkcs12_b64` the identity payload carries PKCS12_MARKER for the
    enrollment page to replace with the PKCS#12 it assembled locally. `wired` (Macs only) adds an Ethernet payload
    with the same identity and trust, so 802.1X switch ports work too."""
    root_uuid, iss_uuid, p12_uuid, wifi_uuid, eth_uuid = (str(uuid.uuid4()).upper() for _ in range(5))
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
    if wired:
        payloads.append({
            "PayloadType": "com.apple.globalethernet.managed", "PayloadVersion": 1, "PayloadIdentifier": f"{ident}.ethernet", "PayloadUUID": eth_uuid,
            "PayloadDisplayName": "Wired 802.1X", "PayloadCertificateUUID": p12_uuid,
            "EAPClientConfiguration": {"AcceptEAPTypes": [13], "TLSTrustedServerNames": [server_name],
                                       "PayloadCertificateAnchorUUID": [root_uuid, iss_uuid], "TLSAllowTrustExceptions": False}})
    profile = {"PayloadType": "Configuration", "PayloadVersion": 1, "PayloadIdentifier": ident, "PayloadUUID": str(uuid.uuid4()).upper(),
               "PayloadDisplayName": f"{org} Wi-Fi ({ssid})" + (" and wired" if wired else ""), "PayloadOrganization": org,
               "PayloadDescription": "Installs your network certificate and connects you to " + ("Wi-Fi and wired network ports" if wired else "the network")
               + ". Created by EasyEAP.",
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


def networkmanager_wired(server_name: str, identity: str) -> str:
    """Wired 802.1X for NetworkManager. optional=true: on a port without 802.1X the connection still comes up."""
    return f"""# Save as /etc/NetworkManager/system-connections/wired-8021x.nmconnection (mode 600), then: nmcli connection reload
[connection]
id=Wired 802.1X
type=ethernet
autoconnect-priority=10

[ethernet]

[802-1x]
eap=tls;
identity={identity}
ca-cert=/etc/easyeap/ca-chain.pem
client-cert=/etc/easyeap/client.pem
private-key=/etc/easyeap/client.key
private-key-password-flags=4
domain-suffix-match={server_name}
optional=true

[ipv4]
method=auto

[ipv6]
method=auto
"""


def wpa_supplicant_wired(server_name: str, identity: str) -> str:
    return f"""# Wired 802.1X: wpa_supplicant -D wired -i <interface> -c /etc/wpa_supplicant/wired.conf
ctrl_interface=/run/wpa_supplicant
ap_scan=0
network={{
    key_mgmt=IEEE8021X
    eap=TLS
    eapol_flags=0
    identity="{identity}"
    ca_cert="/etc/easyeap/ca-chain.pem"
    client_cert="/etc/easyeap/client.pem"
    private_key="/etc/easyeap/client.key"
    domain_suffix_match="{server_name}"
}}
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


def instructions(platform: str, ssid: str, server_name: str, wired: bool = False) -> list[str]:
    if platform == "windows":
        out = ["Download the enrollment helper and run it in PowerShell (right-click → Run with PowerShell).",
               "Approve the prompt to trust your organization's Root CA.",
               f"Connect to “{ssid}”. No password is needed."]
        if wired:
            out.append("Network ports with 802.1X: your IT team sets those up on this computer (it needs administrator rights). "
                       "The certificate you get here is the one they use.")
        return out
    if platform in ("macos", "ios"):
        out = ["Download the profile on this device.",
               "iPhone/iPad: open Settings → Profile Downloaded → Install. "
               "Mac: open System Settings → General → Device Management (Privacy & Security → Profiles before macOS 15).",
               "When asked for the certificate password, enter the one shown on this page.",
               f"Join “{ssid}”."]
        if wired and platform == "macos":
            out.append("Network ports with 802.1X work too: plug in, and the Mac uses the same certificate.")
        return out
    if platform == "android":
        return ["Download the certificate file on this device.",
                "Open Settings → Security → More security settings → Install from device storage → Wi-Fi certificate, and pick the file.",
                f"Open Wi-Fi → “{ssid}”: EAP method TLS, CA certificate = the one you installed, Domain = {server_name}, "
                "Identity = your sign-in name (shown on this page).",
                "Save and connect."]
    out = ["Download the setup script (EasyEAP-WiFi-Setup.sh) on this computer.",
           "Open Terminal and run: bash ~/Downloads/EasyEAP-WiFi-Setup.sh. It asks for your password once.",
           f"It finds NetworkManager, iwd or wpa_supplicant, creates the key on this computer, saves the certificate "
           f"under /etc/easyeap/ and adds “{ssid}”, trusting only the server {server_name}. "
           "It renews the certificate by itself."]
    if wired:
        out.append("Network ports with 802.1X: on computers with NetworkManager, the script sets those up too.")
    return out
