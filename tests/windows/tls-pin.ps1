# tests/windows/run.sh: the server-certificate pin exactly as the setup file carries it (taken from the generated
# full.cmd by its syntax tree), against an HTTPS server with a self-signed certificate under another name, as a PC sees
# EasyEAP's temporary certificate. HttpWebRequest, as Windows PowerShell's Invoke-RestMethod uses; both ask
# ServicePointManager. Usage: tls-pin.ps1 <https url>
param([string]$Url)
$ErrorActionPreference = 'Stop'
$fail = 0
function Check([bool]$Ok, [string]$What) {
  if ($Ok) { Write-Host "  PASS $What" } else { $script:fail++; Write-Host "  FAIL $What" }
}
function Test-Get {
  $req = [System.Net.HttpWebRequest]::Create($Url)
  $req.KeepAlive = $false   # a new TLS handshake every time
  $req.Timeout = 10000
  try { $r = $req.GetResponse(); $r.Close(); return $true } catch { return $false }
}

$main = [System.Management.Automation.Language.Parser]::ParseFile('/out/full.cmd', [ref]$null, [ref]$null)
foreach ($st in $main.EndBlock.Statements) {
  if ($st -is [System.Management.Automation.Language.AssignmentStatementAst] -and $st.Left.Extent.Text -in '$TlsPin', '$TlsPinSource') {
    . ([scriptblock]::Create($st.Extent.Text))
  }
}
foreach ($fn in $main.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Use-EasyEapPin' }, $true)) {
  . ([scriptblock]::Create($fn.Extent.Text))
}
$pins = Get-Content /out/pins.json -Raw | ConvertFrom-Json
Check ($TlsPin -eq $pins.tls) 'the setup file carries the server certificate''s pin'

# Reachable at all (so a refusal below is the certificate, not the network).
$u = [uri]$Url
$up = $false
foreach ($i in 1..20) {
  try { $tcp = [System.Net.Sockets.TcpClient]::new($u.Host, $u.Port); $tcp.Close(); $up = $true; break } catch { Start-Sleep -Milliseconds 500 }
}
Check $up 'the test server answers'

Check (-not (Test-Get)) 'without the pin, the self-signed certificate is refused'
Use-EasyEapPin
Check ([bool]('EasyEapTlsPin' -as [type])) 'the pin check compiles (C#)'
Check (Test-Get) 'with the pin, the certificate with that public key is accepted (self-signed, another name)'
Use-EasyEapPin   # a second call changes nothing
Check (Test-Get) 'Use-EasyEapPin twice: still accepted'

# The parser on its own: the SubjectPublicKeyInfo of an ECDSA and an RSA certificate hash to the pins EasyEAP made.
foreach ($name in 'tls', 'tls-rsa') {
  $der = [IO.File]::ReadAllBytes("/out/$name.cer")
  Check ([EasyEapTlsPin]::Matches($der, $pins.$name)) "$name certificate: its public key matches EasyEAP's pin"
}
Check (-not [EasyEapTlsPin]::Matches([IO.File]::ReadAllBytes('/out/tls-rsa.cer'), $pins.tls)) 'another certificate''s key doesn''t match'
Check (-not [EasyEapTlsPin]::Matches([byte[]](0x30, 0x82, 0xFF), $pins.tls)) 'truncated bytes: no match, no exception'
Check (-not [EasyEapTlsPin]::Matches([byte[]]@(), $pins.tls)) 'no bytes: no match, no exception'

# Another pin: the same certificate is refused again.
[EasyEapTlsPin]::Use('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')
Check (-not (Test-Get)) 'with a different pin, the certificate is refused'
exit $fail
