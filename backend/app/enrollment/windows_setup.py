"""The Windows 11 setup file (docs/plans/windows-setup.md): one download per user that sets up a PC for EasyEAP.

A batch/PowerShell polyglot (`.cmd`): double-clicking it runs Windows PowerShell 5.1 for that process only with
`-ExecutionPolicy Bypass`, and PowerShell skips the batch part as a block comment. The computer part runs elevated
(UAC); the user part runs as the signed-in user, so the user's certificate lands in their own store.

Nothing secret is inside: the enrollment codes work once and expire, and every key is created on the PC (TPM first;
a non-exportable software key on PCs without one, such as Windows 11 installed with the TPM bypass).
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from app.enrollment.profiles import windows_lan_xml, windows_wlan_xml

SCRIPT_VERSION = "1"


@dataclass
class SetupOptions:
    api: str                  # the console's public URL
    org: str                  # tenant name, shown in messages
    user_label: str           # the person the setup is for (display name and user name)
    user_code: str | None     # one-time code for the user's certificate
    computer_code: str | None  # one-time code for the computer's certificate
    server_name: str          # RADIUS server name the profiles pin
    root_pem: str
    issuing_pem: str
    ssid: str | None          # Wi-Fi profile when set
    wpa3: bool
    wired: bool               # wired 802.1X profile and the Wired AutoConfig service
    shared_pc: bool           # computer certificate only on the network (several people use the PC)
    user_renew_days: int      # renewal windows of the templates (the server decides; this avoids signing daily)
    computer_renew_days: int
    expires: str              # when the codes stop working (for the message), ISO 8601
    mode: str | None = None   # the profiles' sign-in mode when the file is made again with only the codes not used yet


def mode_for(user: bool, computer: bool, shared_pc: bool) -> str:
    """The profiles' authentication mode: the computer's certificate at the sign-in screen and the user's after
    (machineOrUser), the computer's always (a shared PC, or no user certificate), or the user's only."""
    if computer and (shared_pc or not user):
        return "machine"
    return "machineOrUser" if computer else "user"


def auth_mode(o: SetupOptions) -> str:
    return o.mode or mode_for(bool(o.user_code), bool(o.computer_code), o.shared_pc)


def _ps(value: str) -> str:
    """A PowerShell single-quoted string literal."""
    return "'" + value.replace("'", "''") + "'"


def _here(text: str) -> str:
    """A PowerShell single-quoted here-string. The content must not have a line starting with '@."""
    if re.search(r"^'@", text, re.MULTILINE):
        raise ValueError("here-string content can't start a line with '@")
    return "@'\n" + text.rstrip("\n") + "\n'@"


def _comment(text: str) -> str:
    """Text safe inside a PowerShell line comment: one line, and no `<#`/`#>` that would open or close a block comment."""
    return re.sub(r"[\r\n<>#]+", " ", text)[:120]


def _der_b64(pem: str) -> str:
    return base64.b64encode(x509.load_pem_x509_certificate(pem.encode()).public_bytes(Encoding.DER)).decode()


def filename(username: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", username.split("@", 1)[0]).strip("-.")[:40] or "user"
    return f"EasyEAP-Setup-{safe}.cmd"


RENEW = r"""# EasyEAP certificate renewal, installed by the EasyEAP setup. Runs as SYSTEM for the computer's certificate (daily
# and at startup) and as each user for theirs (at sign-in and unlock). Inside the renewal window it makes a new key,
# signs the request with the current certificate's key, installs the new certificate and removes the old one.
param([ValidateSet('Computer', 'User')][string]$Scope = 'Computer')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Api = __API__
$IssuingDer = __ISSUING__
$RenewDays = @{ Computer = __COMPUTER_DAYS__; User = __USER_DAYS__ }[$Scope]
$Machine = $Scope -eq 'Computer'
$Dir = if ($Machine) { Join-Path $env:ProgramFiles 'EasyEAP' } else { Join-Path $env:LOCALAPPDATA 'EasyEAP' }
$LogFile = Join-Path $Dir 'renew.log'

function Write-Log([string]$Text, [string]$Level = 'Information') {
  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
  $line = '{0:u} {1} {2}' -f (Get-Date), $Scope, $Text
  Add-Content -Path $LogFile -Value $line -Encoding UTF8
  try { Write-EventLog -LogName Application -Source 'EasyEAP' -EventId 100 -EntryType $Level -Message $Text } catch { }
}

function New-EasyEapRequest([string]$Work) {
  $tries = @(
    @{ Provider = 'Microsoft Platform Crypto Provider'; Alg = 'ECDSA_P256'; Len = 256; Storage = 'tpm' },
    @{ Provider = 'Microsoft Platform Crypto Provider'; Alg = 'RSA'; Len = 2048; Storage = 'tpm' },
    @{ Provider = 'Microsoft Software Key Storage Provider'; Alg = 'ECDSA_P256'; Len = 256; Storage = 'software' }
  )
  foreach ($t in $tries) {
    $inf = Join-Path $Work 'renew.inf'; $csr = Join-Path $Work 'renew.csr'
    Remove-Item $csr -ErrorAction SilentlyContinue
    $set = if ($Machine) { 'TRUE' } else { 'FALSE' }
    @(
      '[Version]', 'Signature="$Windows NT$"', '[NewRequest]', 'Subject = "CN=EasyEAP"', "KeyAlgorithm = $($t.Alg)",
      "KeyLength = $($t.Len)", 'HashAlgorithm = SHA256', 'Exportable = FALSE', "MachineKeySet = $set",
      ('ProviderName = "' + $t.Provider + '"'), 'KeyUsage = 0x80', 'RequestType = PKCS10'
    ) | Set-Content -Path $inf -Encoding ASCII
    & certreq.exe -q -new $inf $csr 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0 -and (Test-Path $csr)) { return @{ Pem = (Get-Content $csr -Raw); Storage = $t.Storage } }
  }
  throw 'Windows could not create a key for the new certificate.'
}

function Get-Hex([byte[]]$Bytes) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  (($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
}

function New-RenewalBody($Current, [string]$CsrPem, [string]$Storage) {
  # The current key signs the current certificate, the time and the new request (app/enrollment/service.py
  # renewal_message): ECDSA keys sign in IEEE P1363 form, RSA keys with PKCS#1 v1.5; TPM keys work for both.
  $csrDer = [Convert]::FromBase64String(($CsrPem -replace '-----[^-]+-----', '' -replace '\s', ''))
  $signedAt = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $message = [Text.Encoding]::ASCII.GetBytes('easyeap-renew-v1|' + (Get-Hex $Current.RawData) + '|' + $signedAt + '|' + (Get-Hex $csrDer))
  $ecKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Current)
  if ($ecKey) {
    $sig = $ecKey.SignData($message, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
  } else {
    $rsaKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Current)
    $sig = $rsaKey.SignData($message, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
  }
  @{ certificate = [Convert]::ToBase64String($Current.RawData); csr = $CsrPem; signed_at = $signedAt
     signature = [Convert]::ToBase64String($sig); key_storage = $Storage }
}

function Remove-PendingRequests {
  $req = if ($Machine) { 'Cert:\LocalMachine\REQUEST' } else { 'Cert:\CurrentUser\REQUEST' }
  Get-ChildItem $req -ErrorAction SilentlyContinue | Where-Object { $_.Subject -eq 'CN=EasyEAP' } |
    ForEach-Object { Remove-Item -Path $_.PSPath -DeleteKey -ErrorAction SilentlyContinue }
}

$Work = Join-Path $env:TEMP ('easyeap-renew-' + [guid]::NewGuid())
try {
  $Ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, [Convert]::FromBase64String($IssuingDer))
  $Store = if ($Machine) { 'Cert:\LocalMachine\My' } else { 'Cert:\CurrentUser\My' }
  $Mine = @(Get-ChildItem $Store | Where-Object { $_.Issuer -eq $Ca.Subject -and $_.HasPrivateKey } | Sort-Object NotAfter -Descending)
  if ($Mine.Count -eq 0) { exit 0 }
  $Current = $Mine[0]
  # Older EasyEAP certificates left behind (a renewal that was interrupted): the newest one is the one in use.
  foreach ($old in ($Mine | Select-Object -Skip 1)) { Remove-Item -Path $old.PSPath -DeleteKey -ErrorAction SilentlyContinue }
  if ($Current.NotAfter -le (Get-Date)) { Write-Log 'The certificate has expired. Run the EasyEAP setup again.' 'Warning'; exit 1 }
  if ($Current.NotAfter -gt (Get-Date).AddDays($RenewDays)) { exit 0 }

  New-Item -ItemType Directory -Path $Work | Out-Null
  $req = New-EasyEapRequest $Work
  $body = New-RenewalBody $Current $req.Pem $req.Storage | ConvertTo-Json
  $resp = Invoke-RestMethod -Method Post -Uri "$Api/api/enroll/renew" -ContentType 'application/json' -Body $body -UseBasicParsing
  if (-not $resp.renewed) { Remove-PendingRequests; exit 0 }
  $pem = Join-Path $Work 'new.pem'
  Set-Content -Path $pem -Value $resp.certificate_pem -Encoding ASCII
  if ($Machine) { & certreq.exe -q -accept -machine $pem | Out-Null } else { & certreq.exe -q -accept -user $pem | Out-Null }
  if ($LASTEXITCODE -ne 0) { throw "certreq couldn't install the new certificate ($LASTEXITCODE)." }
  if ($resp.issuing_ca_pem) {
    $caPem = Join-Path $Work 'issuing.pem'
    Set-Content -Path $caPem -Value $resp.issuing_ca_pem -Encoding ASCII
    $caStore = if ($Machine) { 'Cert:\LocalMachine\CA' } else { 'Cert:\CurrentUser\CA' }
    try { Import-Certificate -FilePath $caPem -CertStoreLocation $caStore | Out-Null } catch { }
  }
  Remove-Item -Path $Current.PSPath -DeleteKey -ErrorAction SilentlyContinue
  Write-Log ("Renewed the EasyEAP certificate: new serial {0}, valid until {1} ({2} key)." -f $resp.serial, $resp.not_after, $req.Storage)
} catch {
  $msg = $_.Exception.Message
  if ($_.ErrorDetails -and $_.ErrorDetails.Message) { try { $msg = ($_.ErrorDetails.Message | ConvertFrom-Json).detail } catch { $msg = $_.ErrorDetails.Message } }
  Remove-PendingRequests
  Write-Log "Renewal failed: $msg" 'Warning'
  exit 1
} finally {
  Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
  if ((Get-Item $LogFile -ErrorAction SilentlyContinue).Length -gt 256KB) {
    Get-Content $LogFile -Tail 500 | Set-Content "$LogFile.tmp" -Encoding UTF8; Move-Item -Force "$LogFile.tmp" $LogFile
  }
}
"""

MAIN = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Api = __API__
$Org = __ORG__
$ForUser = __USER__
$UserCode = __USER_CODE__
$ComputerCode = __COMPUTER_CODE__
$Ssid = __SSID__
$Wired = __WIRED__
$Mode = __MODE__
$Expires = __EXPIRES__
$Version = __VERSION__
$RootPem = __ROOT__
$IssuingPem = __ISSUING_PEM__
$IssuingDer = __ISSUING__
$WlanXml = __WLAN__
$WlanUserXml = __WLAN_USER__
$LanXml = __LAN__
$RenewPs1 = __RENEW__

$Part = $env:EASYEAP_PART
$Self = $env:EASYEAP_SETUP
$RunId = $env:EASYEAP_RUN
# Program Files, not ProgramData: only administrators can create folders there, so nobody can plant or swap the
# renewal script that runs as SYSTEM.
$ProgramDir = Join-Path $env:ProgramFiles 'EasyEAP'
$ResultFile = Join-Path $ProgramDir 'setup-result.json'

function Test-Admin { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }

function Get-ErrorText($Err) {
  $msg = $Err.Exception.Message
  if ($Err.ErrorDetails -and $Err.ErrorDetails.Message) { try { $msg = ($Err.ErrorDetails.Message | ConvertFrom-Json).detail } catch { $msg = $Err.ErrorDetails.Message } }
  $msg
}

function New-EasyEapRequest([string]$Work, [bool]$Machine) {
  # The TPM first (ECDSA, then RSA for TPMs without ECC), then a non-exportable software key: Windows 11 installed
  # with the TPM bypass has no TPM.
  $tries = @(
    @{ Provider = 'Microsoft Platform Crypto Provider'; Alg = 'ECDSA_P256'; Len = 256; Storage = 'tpm' },
    @{ Provider = 'Microsoft Platform Crypto Provider'; Alg = 'RSA'; Len = 2048; Storage = 'tpm' },
    @{ Provider = 'Microsoft Software Key Storage Provider'; Alg = 'ECDSA_P256'; Len = 256; Storage = 'software' }
  )
  foreach ($t in $tries) {
    $inf = Join-Path $Work 'req.inf'; $csr = Join-Path $Work 'req.csr'
    Remove-Item $csr -ErrorAction SilentlyContinue
    $set = if ($Machine) { 'TRUE' } else { 'FALSE' }
    @(
      '[Version]', 'Signature="$Windows NT$"', '[NewRequest]', 'Subject = "CN=EasyEAP"', "KeyAlgorithm = $($t.Alg)",
      "KeyLength = $($t.Len)", 'HashAlgorithm = SHA256', 'Exportable = FALSE', "MachineKeySet = $set",
      ('ProviderName = "' + $t.Provider + '"'), 'KeyUsage = 0x80', 'RequestType = PKCS10'
    ) | Set-Content -Path $inf -Encoding ASCII
    & certreq.exe -q -new $inf $csr 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0 -and (Test-Path $csr)) { return @{ Pem = (Get-Content $csr -Raw); Storage = $t.Storage } }
  }
  throw 'Windows could not create a key for the certificate.'
}

function Install-EasyEapCertificate([string]$Code, [bool]$Machine, [string]$Work) {
  $req = New-EasyEapRequest $Work $Machine
  $body = @{ csr = $req.Pem; key_origin = 'device'; device_hint = $env:COMPUTERNAME; key_storage = $req.Storage } | ConvertTo-Json
  try {
    $resp = Invoke-RestMethod -Method Post -Uri "$Api/api/enroll/$Code/csr" -ContentType 'application/json' -Body $body -UseBasicParsing
  } catch {
    $pending = if ($Machine) { 'Cert:\LocalMachine\REQUEST' } else { 'Cert:\CurrentUser\REQUEST' }
    Get-ChildItem $pending -ErrorAction SilentlyContinue | Where-Object { $_.Subject -eq 'CN=EasyEAP' } |
      ForEach-Object { Remove-Item -Path $_.PSPath -DeleteKey -ErrorAction SilentlyContinue }
    throw
  }
  $pem = Join-Path $Work 'cert.pem'
  Set-Content -Path $pem -Value $resp.certificate_pem -Encoding ASCII
  if ($Machine) { & certreq.exe -q -accept -machine $pem | Out-Null } else { & certreq.exe -q -accept -user $pem | Out-Null }
  if ($LASTEXITCODE -ne 0) { throw "certreq couldn't install the certificate ($LASTEXITCODE)." }
  # Older EasyEAP certificates in the same store: the new one replaces them (they stay valid in EasyEAP until they expire).
  $newDer = [Convert]::FromBase64String(($resp.certificate_pem -replace '-----[^-]+-----', '' -replace '\s', ''))
  $new = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $newDer)
  $ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, [Convert]::FromBase64String($IssuingDer))
  $store = if ($Machine) { 'Cert:\LocalMachine\My' } else { 'Cert:\CurrentUser\My' }
  Get-ChildItem $store | Where-Object { $_.Issuer -eq $ca.Subject -and $_.Thumbprint -ne $new.Thumbprint } |
    ForEach-Object { Remove-Item -Path $_.PSPath -DeleteKey -ErrorAction SilentlyContinue }
  @{ Serial = $resp.serial; NotAfter = $resp.not_after; Storage = $req.Storage }
}

function Save-Text([string]$Path, [string]$Text, [string]$Encoding = 'ASCII') { Set-Content -Path $Path -Value $Text -Encoding $Encoding }

# ── The computer part (administrator) ────────────────────────────────────────
# Each step stands alone: one that fails (no Wi-Fi service, a wired adapter Windows refuses) doesn't stop the others,
# because the one-time codes can't be used twice.
function Invoke-ComputerPart {
  $r = [ordered]@{ ok = $false; steps = @(); errors = @(); run = $null; trusted = $false; wifi = $false; renewal = $false }
  $work = Join-Path $env:TEMP ('easyeap-' + [guid]::NewGuid())
  New-Item -ItemType Directory -Path $work | Out-Null
  try {
    New-Item -ItemType Directory -Force -Path $ProgramDir | Out-Null
    try { if (-not [Diagnostics.EventLog]::SourceExists('EasyEAP')) { New-EventLog -LogName Application -Source 'EasyEAP' } } catch { }

    try {
      Save-Text (Join-Path $work 'root.pem') $RootPem
      Save-Text (Join-Path $work 'issuing.pem') $IssuingPem
      Import-Certificate -FilePath (Join-Path $work 'root.pem') -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
      Import-Certificate -FilePath (Join-Path $work 'issuing.pem') -CertStoreLocation Cert:\LocalMachine\CA | Out-Null
      $r.steps += "Trusted the $Org certificate authority"
      $r.trusted = $true
    } catch { $r.errors += "Trusting the certificate authority: $(Get-ErrorText $_)" }

    if ($ComputerCode) {
      try {
        $c = Install-EasyEapCertificate $ComputerCode $true $work
        $r.steps += ("Computer certificate installed ({0} key, valid until {1})" -f $(if ($c.Storage -eq 'tpm') { 'TPM' } else { 'software' }), ([datetime]$c.NotAfter).ToString('d'))
        $r.computer_storage = $c.Storage
      } catch { $r.errors += "The computer certificate: $(Get-ErrorText $_)" }
    }

    if ($Wired) {
      try {
        Set-Service -Name dot3svc -StartupType Automatic
        Start-Service -Name dot3svc
        Save-Text (Join-Path $work 'lan.xml') $LanXml 'UTF8'
        $adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.MediaType -eq '802.3' })
        $failed = @()
        foreach ($a in $adapters) {
          & netsh.exe lan add profile filename="$(Join-Path $work 'lan.xml')" interface="$($a.Name)" | Out-Null
          if ($LASTEXITCODE -ne 0) { $failed += $a.Name }
        }
        if (-not $adapters.Count) { $r.steps += 'No wired network adapter found; wired 802.1X skipped' }
        elseif ($failed.Count -lt $adapters.Count) { $r.steps += "Wired 802.1X on $($adapters.Count - $failed.Count) network adapter(s)" }
        if ($failed.Count) { $r.errors += "Windows didn't accept the wired profile on: $($failed -join ', ')" }
      } catch { $r.errors += "Wired 802.1X: $(Get-ErrorText $_)" }
    }

    if ($Ssid) {
      try {
        $wlan = Get-Service -Name WlanSvc -ErrorAction SilentlyContinue
        if ($wlan -and $wlan.Status -eq 'Running') {
          Save-Text (Join-Path $work 'wlan.xml') $WlanXml 'UTF8'
          & netsh.exe wlan add profile filename="$(Join-Path $work 'wlan.xml')" user=all | Out-Null
          if ($LASTEXITCODE -ne 0) { throw "Windows didn't accept the Wi-Fi profile ($LASTEXITCODE)." }
          $r.steps += "Wi-Fi network '$Ssid' added for everyone on this PC"
          $r.wifi = $true
        } else {
          $r.steps += 'No Wi-Fi on this PC; Wi-Fi skipped'
        }
      } catch { $r.errors += "Wi-Fi: $(Get-ErrorText $_)" }
    }

    # Renewal: a daily task as SYSTEM for the computer's certificate, and one at sign-in and unlock for each user's.
    try {
      $renew = Join-Path $ProgramDir 'renew.ps1'
      Save-Text $renew $RenewPs1 'UTF8'
      $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
      if ($ComputerCode) {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$renew`" -Scope Computer"
        $triggers = @((New-ScheduledTaskTrigger -Daily -At '09:00' -RandomDelay (New-TimeSpan -Hours 8)), (New-ScheduledTaskTrigger -AtStartup))
        $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskPath '\EasyEAP\' -TaskName 'Renew computer certificate' -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
      }
      if ($UserCode) {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$renew`" -Scope User"
        $class = Get-CimClass -Namespace 'ROOT\Microsoft\Windows\TaskScheduler' -ClassName 'MSFT_TaskSessionStateChangeTrigger'
        $unlock = New-CimInstance -CimClass $class -ClientOnly
        $unlock.StateChange = 8
        $triggers = @((New-ScheduledTaskTrigger -AtLogOn), $unlock)
        $principal = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited
        Register-ScheduledTask -TaskPath '\EasyEAP\' -TaskName 'Renew user certificate' -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
      }
      $r.steps += 'Certificates renew themselves before they expire'
      $r.renewal = $true
    } catch { $r.errors += "Automatic renewal: $(Get-ErrorText $_)" }
    $r.ok = $r.errors.Count -eq 0
  } catch {
    $r.errors += Get-ErrorText $_
  } finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
  }
  $r
}

# ── The user part (the signed-in user) ───────────────────────────────────────
function Invoke-UserPart($Computer) {
  # What the computer part did for everyone on the PC ($null when it didn't run); the user part covers the rest.
  $r = [ordered]@{ ok = $false; steps = @(); errors = @() }
  $work = Join-Path $env:TEMP ('easyeap-' + [guid]::NewGuid())
  New-Item -ItemType Directory -Path $work | Out-Null
  try {
    if (-not $Computer.trusted) {
      # The computer part didn't trust the CA: trust it for this user (Windows asks to confirm).
      try {
        Save-Text (Join-Path $work 'root.pem') $RootPem
        Save-Text (Join-Path $work 'issuing.pem') $IssuingPem
        Import-Certificate -FilePath (Join-Path $work 'root.pem') -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
        Import-Certificate -FilePath (Join-Path $work 'issuing.pem') -CertStoreLocation Cert:\CurrentUser\CA | Out-Null
        $r.steps += "Trusted the $Org certificate authority (for you)"
      } catch { $r.errors += "Trusting the certificate authority: $(Get-ErrorText $_)" }
    }
    $c = Install-EasyEapCertificate $UserCode $false $work
    $r.steps += ("Your certificate installed ({0} key, valid until {1})" -f $(if ($c.Storage -eq 'tpm') { 'TPM' } else { 'software' }), ([datetime]$c.NotAfter).ToString('d'))
    if ($Ssid -and -not $Computer.wifi) {
      try {
        $wlan = Get-Service -Name WlanSvc -ErrorAction SilentlyContinue
        if ($wlan -and $wlan.Status -eq 'Running') {
          Save-Text (Join-Path $work 'wlan.xml') $WlanUserXml 'UTF8'
          & netsh.exe wlan add profile filename="$(Join-Path $work 'wlan.xml')" user=current | Out-Null
          if ($LASTEXITCODE -ne 0) { throw "Windows didn't accept the Wi-Fi profile ($LASTEXITCODE)." }
          $r.steps += "Wi-Fi network '$Ssid' added for you"
        }
      } catch { $r.errors += "Wi-Fi: $(Get-ErrorText $_)" }
    }
    if (-not $Computer.renewal) {
      # No administrator, so no shared renewal task: one for this user only, with the script in their own folder (it
      # runs as them, so a folder they can write is fine).
      try {
        $dir = Join-Path $env:LOCALAPPDATA 'EasyEAP'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $renew = Join-Path $dir 'renew.ps1'
        Save-Text $renew $RenewPs1 'UTF8'
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$renew`" -Scope User"
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
        $triggers = @((New-ScheduledTaskTrigger -Daily -At '10:00' -RandomDelay (New-TimeSpan -Hours 6)))
        try { $triggers += New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME" } catch { }
        Register-ScheduledTask -TaskName "EasyEAP renew certificate ($env:USERNAME)" -Action $action -Trigger $triggers -Settings $settings -Force | Out-Null
        $r.steps += 'Your certificate renews itself before it expires'
      } catch { $r.errors += "Automatic renewal: $(Get-ErrorText $_)" }
    } else {
      # The shared task (\EasyEAP\Renew user certificate) renews it now; drop a per-user one from an earlier run.
      Get-ScheduledTask -TaskName "EasyEAP renew certificate ($env:USERNAME)" -ErrorAction SilentlyContinue |
        Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
    }
    $r.ok = $r.errors.Count -eq 0
  } catch {
    $r.errors += "Your certificate: $(Get-ErrorText $_)"
  } finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
  }
  $r
}

if ($Part -eq 'computer') {
  # The elevated copy: do the computer part and leave the result for the copy that started it.
  $res = Invoke-ComputerPart
  $res.run = $RunId
  try { $res | ConvertTo-Json | Set-Content -Path $ResultFile -Encoding UTF8 } catch { }
  if ($res.ok) { exit 0 } else { exit 1 }
}

Write-Host ''
Write-Host "EasyEAP setup for $ForUser ($Org)" -ForegroundColor Cyan
Write-Host 'This connects the PC to the network with certificates. Keys are created on this PC and never leave it.'
Write-Host ''
if ([Environment]::OSVersion.Version.Build -lt 22000) { Write-Host 'This PC runs Windows 10. The setup is made for Windows 11; it usually works, but check the result.' -ForegroundColor Yellow }

$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$isSystem = $me.User.Value -eq 'S-1-5-18'
$console = $null
try {
  $explorer = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Select-Object -First 1
  if ($explorer) { $console = (Invoke-CimMethod -InputObject $explorer -MethodName GetOwnerSid).Sid }
} catch { }
# Started with "Run as administrator" by someone else (or as SYSTEM): the user's certificate would land in the wrong store.
$userHere = $UserCode -and -not $isSystem -and (-not $console -or $console -eq $me.User.Value)

$computer = $null
# A file made again with only the user's code still runs the computer part when the first file had one (sign-in mode
# machine or machineOrUser): it puts back the shared Wi-Fi profile, trust and renewal, and every step is safe to repeat.
$needComputer = [bool]$ComputerCode -or $Wired -or $Mode -ne 'user'
if ($needComputer) {
  if (Test-Admin) {
    $computer = Invoke-ComputerPart
  } else {
    Write-Host 'Windows will ask for administrator approval to set up the computer part.'
    $run = [guid]::NewGuid().ToString()
    $cmd = "`$env:EASYEAP_PART='computer'; `$env:EASYEAP_RUN='$run'; `$env:EASYEAP_SETUP='" + $Self.Replace("'", "''") + "'; Invoke-Expression ([IO.File]::ReadAllText(`$env:EASYEAP_SETUP))"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
    try {
      $p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded"
      if (Test-Path $ResultFile) {
        $found = Get-Content $ResultFile -Raw | ConvertFrom-Json
        if ($found.run -eq $run) { $computer = $found }  # never a result left by an earlier run
      }
      if (-not $computer) { $computer = [pscustomobject]@{ ok = $false; steps = @(); errors = @("The administrator part stopped (exit code $($p.ExitCode)).") } }
    } catch {
      $computer = [pscustomobject]@{ ok = $false; steps = @(); errors = @('Administrator approval was declined, so the computer part was skipped.') }
    }
  }
}

$user = $null
if ($UserCode -and $userHere) { $user = Invoke-UserPart $computer }

Write-Host ''
foreach ($res in @($computer, $user)) {
  if (-not $res) { continue }
  foreach ($s in $res.steps) { Write-Host "  [ok] $s" -ForegroundColor Green }
  foreach ($e in @($res.errors)) { if ($e) { Write-Host "  [!!] $e" -ForegroundColor Red } }
}
if ($UserCode -and -not $userHere) {
  Write-Host "  [!!] Your certificate wasn't installed: run this file again signed in as $ForUser, without 'Run as administrator'." -ForegroundColor Yellow
}
$allOk = (-not $computer -or $computer.ok) -and (-not $UserCode -or ($user -and $user.ok))
Write-Host ''
if ($allOk) {
  Write-Host 'Done. The PC connects automatically, including at the sign-in screen when a computer certificate was installed.' -ForegroundColor Green
} else {
  Write-Host "Setup didn't finish. Ask your IT team for help and include the lines above. The codes in this file work once and expire $Expires; after a code was used, IT makes a new setup file." -ForegroundColor Red
}
Write-Host ''
Read-Host 'Press Enter to close' | Out-Null
if ($allOk) { exit 0 } else { exit 1 }
"""

LAUNCHER = (
    "<# : EasyEAP setup for Windows 11. Double-click to run. The PowerShell part below does the work.\r\n"
    "@echo off\r\n"
    "setlocal\r\n"
    "set \"EASYEAP_SETUP=%~f0\"\r\n"
    "set \"EASYEAP_PART=\"\r\n"
    "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Invoke-Expression ([IO.File]::ReadAllText($env:EASYEAP_SETUP))\"\r\n"
    "exit /b %errorlevel%\r\n"
    "#>\r\n"
)


def renew_script(o: SetupOptions) -> str:
    return (RENEW.replace("__API__", _ps(o.api.rstrip("/"))).replace("__ISSUING__", _ps(_der_b64(o.issuing_pem)))
            .replace("__COMPUTER_DAYS__", str(int(o.computer_renew_days))).replace("__USER_DAYS__", str(int(o.user_renew_days))))


def build(o: SetupOptions) -> str:
    """The .cmd file. ASCII batch header, CRLF line endings (cmd needs them), UTF-8 PowerShell body without a BOM."""
    mode = auth_mode(o)
    issuers = [o.root_pem, o.issuing_pem]
    wlan = windows_wlan_xml(o.ssid, o.server_name, o.root_pem, o.wpa3, auth_mode=mode, issuers=issuers) if o.ssid else ""
    wlan_user = windows_wlan_xml(o.ssid, o.server_name, o.root_pem, o.wpa3, auth_mode="user", issuers=issuers) if o.ssid else ""
    lan = windows_lan_xml(o.server_name, o.root_pem, auth_mode=mode, issuers=issuers) if o.wired else ""
    values = {
        "__API__": _ps(o.api.rstrip("/")), "__ORG__": _ps(o.org), "__USER__": _ps(o.user_label),
        "__USER_CODE__": _ps(o.user_code or ""), "__COMPUTER_CODE__": _ps(o.computer_code or ""), "__SSID__": _ps(o.ssid or ""),
        "__WIRED__": "$true" if o.wired else "$false", "__MODE__": _ps(mode), "__EXPIRES__": _ps(o.expires), "__VERSION__": _ps(SCRIPT_VERSION),
        "__ROOT__": _here(o.root_pem.strip()), "__ISSUING_PEM__": _here(o.issuing_pem.strip()), "__ISSUING__": _ps(_der_b64(o.issuing_pem)),
        "__WLAN__": _here(wlan) if wlan else "''", "__WLAN_USER__": _here(wlan_user) if wlan_user else "''", "__LAN__": _here(lan) if lan else "''",
        "__RENEW__": _here(renew_script(o)),
    }
    body = MAIN
    # One pass, longest names first, so a value is never substituted into again.
    pattern = re.compile("|".join(re.escape(k) for k in sorted(values, key=len, reverse=True)))
    body = pattern.sub(lambda mt: values[mt.group(0)], body)
    header = f"# EasyEAP setup v{SCRIPT_VERSION} for {_comment(o.user_label)} ({_comment(o.org)}). Codes expire {o.expires}.\n"
    text = header + body.lstrip("\n")
    return LAUNCHER + text.replace("\r\n", "\n").replace("\n", "\r\n")
