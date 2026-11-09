# Dot-sourced by check.ps1 (tests/windows/run.sh): the generated renew.ps1's own decision code (Invoke-Renewal,
# Complete-Renewal, Get-Pending, Invoke-Warning...) taken from its syntax tree, run against a stand-in certificate store,
# certreq and EasyEAP. What the real store, certreq and TPM do is for the Windows 11 test (TODO.md).
param([string]$RenewFile = '/out/full-renew.ps1')

$ast = [System.Management.Automation.Language.Parser]::ParseFile($RenewFile, [ref]$null, [ref]$null)
foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { . ([scriptblock]::Create($fn.Extent.Text)) }
foreach ($st in $ast.EndBlock.Statements) {
  if ($st -is [System.Management.Automation.Language.AssignmentStatementAst] -and $st.Left.Extent.Text -in '$FinalCodes', '$QuietHours', '$WarnDays', '$TemplateExt', '$ClientAuth') {
    . ([scriptblock]::Create($st.Extent.Text))
  }
}
$RealGetCertificates = ${function:Get-EasyEapCertificates}

# ── Before the stand-ins: the real selection and the real HTTP client ─────────
# Which certificates are EasyEAP's (X509Chain here is .NET on Linux, not CryptoAPI: the Windows 11 test repeats it).
function Cer([string]$Name) { [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([IO.File]::ReadAllBytes("/out/$Name")) }
$script:Roots = @(Cer 'root.cer')
$script:RootHashes = @($script:Roots | ForEach-Object { Get-Hex $_.RawData })
$script:Cas = @($script:Roots) + @(Cer 'issuing.cer') + @(Cer 'other-issuing.cer')
$pick = @{}
foreach ($n in 'sel-ok', 'sel-gpo', 'sel-server', 'sel-foreign') {
  $pick[$n] = Test-EasyEapCertificate ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new("/out/$n.pfx", 'test'))
}
$pick['sel-nokey'] = Test-EasyEapCertificate (Cer 'sel-nokey.cer')
Check 'renewal: its own certificate only (not Group Policy''s, a server one, another CA''s, or one without its key)' (
  $pick['sel-ok'] -and -not $pick['sel-gpo'] -and -not $pick['sel-server'] -and -not $pick['sel-foreign'] -and -not $pick['sel-nokey']) (($pick.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ' ')

# Invoke-EasyEap against a real HTTP server: a refusal's code, an answer, an error without a code, a gateway error,
# and nothing listening.
$port = 18000 + (Get-Random -Maximum 2000)
$job = Start-ThreadJob -ArgumentList $port -ScriptBlock {
  param($port)
  $l = [System.Net.HttpListener]::new(); $l.Prefixes.Add("http://127.0.0.1:$port/"); $l.Start()
  $answers = @(@(400, '{"detail":"This certificate was already renewed. Use the newer one.","code":"renewed"}'),
               @(200, '{"renewed":false,"superseded":false,"renew_from":"2026-11-10T09:00:00+00:00","renewal_enabled":true}'),
               @(400, '{"detail":"EasyEAP didn''t issue this certificate."}'),
               @(502, 'Bad Gateway'))
  foreach ($a in $answers) {
    $c = $l.GetContext(); $null = [IO.StreamReader]::new($c.Request.InputStream).ReadToEnd()
    $bytes = [Text.Encoding]::UTF8.GetBytes($a[1])
    $c.Response.StatusCode = $a[0]; $c.Response.ContentType = $(if ($a[0] -eq 502) { 'text/plain' } else { 'application/json' })
    $c.Response.OutputStream.Write($bytes, 0, $bytes.Length); $c.Response.Close()
  }
  $l.Stop()
}
Start-Sleep -Milliseconds 700
$Api = "http://127.0.0.1:$port"
$h = @((Invoke-EasyEap @{ a = 1 }), (Invoke-EasyEap @{ a = 2 }), (Invoke-EasyEap @{ a = 3 }), (Invoke-EasyEap @{ a = 4 }))
$Api = 'http://127.0.0.1:9'
$h += Invoke-EasyEap @{ a = 5 }
$job | Wait-Job -Timeout 5 | Out-Null; $job | Remove-Job -Force
Check 'renewal: the HTTP client reads statuses, details and codes' (
  $h[0].Status -eq 400 -and $h[0].Code -eq 'renewed' -and $h[0].Detail -like '*already renewed*' -and
  $h[1].Status -eq 200 -and $h[1].Data.renewal_enabled -eq $true -and $null -ne (ConvertTo-Instant $h[1].Data.renew_from) -and
  $h[2].Status -eq 400 -and $h[2].Code -eq '' -and $h[2].Detail -like '*didn''t issue*' -and
  $h[3].Status -eq 502 -and $h[4].Status -eq 0) (($h | ForEach-Object { "$($_.Status) $($_.Code) $($_.Detail)" }) -join ' | ')

$Scope = 'User'; $Machine = $false; $Kind = 'windows-setup'; $RenewerVersion = '2.0'; $RenewDays = 30; $Org = 'Corp'
$Base = '/tmp/renew-decisions'
$StoreRoot = "$Base/store"; $Dir = "$Base/dir"; $LogFile = "$Dir/renew.log"
$StateFile = "$Dir/renew-state-user.json"; $PendingFile = "$Dir/renew-pending-user.json"; $Work = "$Base/work"

# ── Stand-ins ────────────────────────────────────────────────────────────────
function Get-Now { $script:now }
function Write-Log([string]$Text, [string]$Level = 'Information') { $script:dlog.Add("log $Text") }
function Show-Notice([string]$Text) { $script:dlog.Add("notice $Text") }
function Get-TrustedRoots { @('cd' * 32) }
function Get-EasyEapCertificates { @($script:store | Sort-Object NotAfter -Descending) }
function Remove-Certificate($Cert) { $script:dlog.Add("remove-cert $($Cert.Thumbprint)"); $script:store = @($script:store | Where-Object { $_.Thumbprint -ne $Cert.Thumbprint }) }
function Get-Item { [CmdletBinding()] param([Parameter(Position = 0)][string]$Path)
  $leaf = Split-Path -Leaf ($Path -replace '\\', '/'); $script:store | Where-Object { $_.Thumbprint -eq $leaf } }
function Remove-Item { [CmdletBinding()] param([Parameter(Position = 0)][string[]]$Path, [switch]$DeleteKey, [switch]$Recurse, [switch]$Force)
  foreach ($p in $Path) {
    if ($DeleteKey) { $script:dlog.Add("delete-key $(Split-Path -Leaf ($p -replace '\\', '/'))") }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath ($p -replace '\\', '/') -Recurse:$Recurse -Force:$Force -ErrorAction SilentlyContinue
  } }
function New-EasyEapRequest([string]$Work) {
  if ($script:failRequest) { throw 'Windows could not create a key for the new certificate.' }
  $script:requests++
  $id = "REQ$($script:requests)"
  New-Item -ItemType File -Force -Path "$StoreRoot/REQUEST/$id" | Out-Null
  $script:dlog.Add("request $id")
  @{ Pem = "CSR$($script:requests)"; Storage = 'tpm'; Request = $id }
}
function ConvertFrom-Pem([string]$Pem) { [pscustomobject]@{ Thumbprint = $Pem } }   # an answer's "PEM" is the new thumbprint here
function Install-Answer($Answer, [string]$Work) {
  $script:dlog.Add("install $($Answer.certificate_pem)")
  if ($script:failInstall) { throw 'certreq could not install the new certificate (-2146885628).' }
  $new = [pscustomobject]@{ Thumbprint = $Answer.certificate_pem; NotAfter = $script:now.UtcDateTime.AddDays($script:newDays); NotBefore = $script:now.UtcDateTime }
  $script:store += $new
  $new
}
function New-CheckInBody($Cert, [string]$Client) {
  if ($script:badKeys -contains $Cert.Thumbprint) { throw 'Keyset does not exist' }
  @{ kind = 'check'; cert = $Cert.Thumbprint; client = $Client }
}
function New-RenewalBody($Cert, [string]$CsrPem, [string]$Storage, [string]$Client) { @{ kind = 'renew'; cert = $Cert.Thumbprint; csr = $CsrPem; client = $Client } }
function Invoke-EasyEap($Body) {
  $script:dlog.Add(("{0} {1}{2}" -f $Body.kind, $Body.cert, $(if ($Body.csr) { " $($Body.csr)" } else { '' })))
  if (-not ($Body.client | ConvertFrom-Json).kind) { throw 'no client block' }
  if ($script:answers.Count -eq 0) { throw "unexpected call to EasyEAP: $($Body.kind) $($Body.cert)" }
  $a = $script:answers[0]; $script:answers = @($script:answers | Select-Object -Skip 1)
  $a
}

# EasyEAP's answers.
function NotDue([int]$Days = 5) { @{ Status = 200; Data = [pscustomobject]@{ renewed = $false; superseded = $false; renewal_enabled = $true; renew_from = $script:now.AddDays($Days).ToString('o') } } }
function Due { @{ Status = 200; Data = [pscustomobject]@{ renewed = $false; superseded = $false; renewal_enabled = $true; renew_from = $script:now.AddDays(-1).ToString('o') } } }
function Superseded { @{ Status = 200; Data = [pscustomobject]@{ renewed = $false; superseded = $true; renewal_enabled = $true; renew_from = $script:now.ToString('o') } } }
function Renewed([string]$Thumb) { @{ Status = 200; Data = [pscustomobject]@{ renewed = $true; certificate_pem = $Thumb; serial = '0B'; not_after = '2027-11-09T00:00:00+00:00' } } }
function Refused([string]$Code) { @{ Status = 400; Data = $null; Detail = "refused ($Code)"; Code = $Code } }
function Unreachable { @{ Status = 0; Data = $null; Detail = 'The operation has timed out. (no proxy)'; Code = '' } }

function Reset([int]$DaysLeft = 20) {
  Microsoft.PowerShell.Management\Remove-Item -Recurse -Force $Base -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path "$StoreRoot/REQUEST", $Dir, $Work | Out-Null
  $script:now = [DateTimeOffset]::new(2026, 11, 9, 9, 0, 0, [TimeSpan]::Zero)
  $script:store = @([pscustomobject]@{ Thumbprint = 'OLD'; NotAfter = $script:now.UtcDateTime.AddDays($DaysLeft); NotBefore = $script:now.UtcDateTime.AddDays($DaysLeft - 365) })
  $script:dlog = [System.Collections.Generic.List[string]]::new()
  $script:answers = @(); $script:requests = 0; $script:failInstall = $false; $script:failRequest = $false; $script:badKeys = @(); $script:newDays = 365
}
function Run([double]$AfterHours = 0) {
  $script:now = $script:now.AddHours($AfterHours)
  $script:dlog.Add('--')
  # renew.ps1's own run section catches what Invoke-Renewal throws; here it's a failure of the scenario, with the reason.
  try { Invoke-Renewal $Work } catch { $script:dlog.Add("threw $($_.Exception.Message)"); 'threw' }
}
function Answer { $script:answers = @($args) }
function Logged([string]$Pattern) { @($script:dlog | Where-Object { $_ -like $Pattern }).Count }
function State { Get-Content $StateFile -Raw | ConvertFrom-Json }
function Thumbs { (@($script:store | ForEach-Object Thumbprint) | Sort-Object) -join ',' }
function DCheck([string]$Name, [bool]$Ok) { Check "renewal: $Name" $Ok ($script:dlog -join ' | ') }

# ── Scenarios ────────────────────────────────────────────────────────────────
Reset; Answer (NotDue)
$a = Run; $b = Run 1
Answer (NotDue)
$c = Run 20
DCheck 'not due: one check-in a day, nothing else' ($a -eq 0 -and $b -eq 0 -and $c -eq 0 -and (Logged 'check OLD') -eq 2 -and -not (Logged 'request*') -and
  (State).thumbprint -eq 'OLD' -and (State).renewal_enabled)

Reset; Answer (Due) (Renewed 'NEW1') (NotDue 300)
# Another valid EasyEAP certificate in the same store (the portal helper's, a PKCS#12 from the console): not this
# renewal's to remove.
$script:store += [pscustomobject]@{ Thumbprint = 'OTHER'; NotAfter = $script:now.UtcDateTime.AddDays(15); NotBefore = $script:now.UtcDateTime.AddDays(-300) }
$a = Run
$steps = @($script:dlog | Where-Object { $_ -notlike 'log *' }) -join ' | '
DCheck 'due: request, renewal, install, a check-in with the new key, then the old goes' ($a -eq 0 -and
  $steps -eq '-- | check OLD | request REQ1 | renew OLD CSR1 | install NEW1 | check NEW1 | remove-cert OLD' -and
  (Thumbs) -eq 'NEW1,OTHER' -and -not (Test-Path $PendingFile) -and (State).thumbprint -eq 'NEW1' -and (State).checked_at)

Reset; Answer (Due) (Unreachable)
$a = Run
$kept = Test-Path $PendingFile
Answer (Renewed 'NEW1') (NotDue 300)
$b = Run 1
DCheck 'a lost answer: the same request again at once, no new key' ($a -eq 1 -and $kept -and $b -eq 0 -and (Logged 'renew OLD CSR1') -eq 2 -and
  (Logged 'request*') -eq 1 -and (Logged 'check OLD') -eq 1 -and (Thumbs) -eq 'NEW1')

Reset; Answer (Due) (Refused 'renewed')
$a = Run
$st = State
$b = Run 1
Answer (Superseded)
$c = Run 20
DCheck 'a final refusal: the request and its key go, and it isn''t asked again' ($a -eq 1 -and $st.final -eq 'renewed' -and (Logged 'delete-key REQ1') -and
  -not (Test-Path $PendingFile) -and $b -eq 1 -and $c -eq 1 -and (Logged 'request*') -eq 1 -and (Logged 'renew*') -eq 1)

Reset; Answer (Due) (Refused 'clock')
$a = Run
$kept = Test-Path $PendingFile
$b = Run 1
Answer (Renewed 'NEW1') (NotDue 300)
$c = Run 20
DCheck 'a refusal that isn''t final keeps the key: quiet for the day, then the same request' ($a -eq 1 -and $kept -and -not (Logged 'delete-key*') -and
  $b -eq 1 -and $c -eq 0 -and (Logged 'request*') -eq 1 -and (Logged 'renew OLD CSR1') -eq 2 -and (Thumbs) -eq 'NEW1')

Reset 200; Answer (Superseded) (Renewed 'NEW1') (NotDue 300)
$a = Run
DCheck 'superseded with nothing waiting: a new key, and EasyEAP replaces the lost certificate' ($a -eq 0 -and (Logged 'log*never arrived*') -and
  (Logged 'renew OLD CSR1') -and (Thumbs) -eq 'NEW1')

Reset; Answer @{ Status = 200; Data = [pscustomobject]@{ renewed = $false; superseded = $false; renewal_enabled = $false; renew_from = $script:now.AddDays(-1).ToString('o') } }
$a = Run
$b = Run 2
DCheck 'renewal turned off: said, no key made, not asked again today' ($a -eq 1 -and $b -eq 1 -and -not (Logged 'request*') -and (Logged 'log*turned off*') -eq 1)

Reset 200; Answer (Unreachable)
$a = Run
Reset 10; Answer (Unreachable) (Renewed 'NEW1') (NotDue 300)
$b = Run
DCheck 'EasyEAP unreachable: the template''s days decide' ($a -eq 0 -and $b -eq 0 -and (Logged 'renew OLD CSR1') -and (Thumbs) -eq 'NEW1')

Reset; Answer (Due) (Renewed 'NEW1') (Unreachable)
$a = Run
$both = Thumbs
Answer (NotDue 300)
$b = Run 1
DCheck 'installed but not confirmed: both kept, the next run finishes' ($a -eq 1 -and $both -eq 'NEW1,OLD' -and $b -eq 0 -and (Thumbs) -eq 'NEW1' -and
  (Logged 'check NEW1') -eq 2 -and -not (Test-Path $PendingFile))

Reset; $script:badKeys = @('NEW1'); Answer (Due) (Renewed 'NEW1')
$a = Run
DCheck 'the new key can''t sign: the new certificate goes, the old stays' ($a -eq 1 -and (Thumbs) -eq 'OLD' -and (Logged 'remove-cert NEW1') -and
  -not (Test-Path $PendingFile))

Reset; $script:failInstall = $true; Answer (Due) (Renewed 'NEW1')
$a = Run
DCheck 'certreq can''t install it: the request goes, the next run asks again' ($a -eq 1 -and (Thumbs) -eq 'OLD' -and (Logged 'delete-key REQ1') -and -not (Test-Path $PendingFile))

Reset; Answer (Due) (NotDue 3)
$a = Run
$b = Run 1
DCheck 'the renewal says not yet: the request goes, the window is kept' ($a -eq 0 -and $b -eq 0 -and (Logged 'delete-key REQ1') -and -not (Test-Path $PendingFile) -and
  (Logged 'renew*') -eq 1 -and (Logged 'check*') -eq 1)

Reset; New-Item -ItemType File -Force -Path "$StoreRoot/REQUEST/REQ9" | Out-Null
'{"csr":"CSR9","request":"REQ9","storage":"tpm","for":"GONE","made":"2026-10-01T00:00:00+00:00"}' | Set-Content $PendingFile
Answer (NotDue)
$a = Run
DCheck 'a request for another certificate is dropped' ($a -eq 0 -and (Logged 'delete-key REQ9') -and -not (Test-Path $PendingFile) -and -not (Logged 'renew*'))

Reset; Answer (Due) (Unreachable)
$a = Run
(Get-Content $PendingFile -Raw | ConvertFrom-Json | Add-Member -PassThru made '2026-01-01T00:00:00+00:00' -Force) | ConvertTo-Json | Set-Content $PendingFile
Answer (Renewed 'NEW1') (NotDue 300)
$b = Run 1
DCheck 'an old request is still sent again: a certificate may be waiting for its key' ($b -eq 0 -and (Logged 'renew OLD CSR1') -eq 2 -and (Thumbs) -eq 'NEW1')

Reset; $script:newDays = 10; Answer (Due) (Renewed 'NEW1') (Unreachable)
$a = Run
Answer (NotDue 3)
$b = Run 1
DCheck 'an unconfirmed new certificate that ends first is still finished, not renewed over' ($a -eq 1 -and $b -eq 0 -and (Thumbs) -eq 'NEW1' -and
  (Logged 'request*') -eq 1 -and -not (Test-Path $PendingFile))

Reset; Answer (Due) (Renewed 'NEW1') (Refused 'revoked')
$a = Run
Answer (Superseded) (Refused 'renewed')
$b = Run 1
DCheck 'EasyEAP refuses the new certificate: it goes, and the next run starts from a fresh check-in' ($a -eq 1 -and (Logged 'remove-cert NEW1') -and
  -not (Logged 'remove-cert OLD') -and $b -eq 1 -and (Logged 'check OLD') -eq 2 -and (Thumbs) -eq 'OLD')

Reset; Answer (Due) (Refused 'off')
$a = Run
Answer (Refused 'off')
$b = Run 21
$c = Run 1
$d = Run 5
DCheck 'a request kept after a refusal: sent again once a day, not at every unlock' ($a -eq 1 -and $b -eq 1 -and $c -eq 1 -and $d -eq 1 -and
  (Logged 'renew OLD CSR1') -eq 2 -and (Logged 'request*') -eq 1)

Reset; $script:failRequest = $true; Answer (Due)
$a = Run
$b = Run 1
DCheck 'Windows can''t make a key: tried again tomorrow, not at every unlock' ($a -eq 'threw' -and $b -eq 1 -and (Logged 'check*') -eq 1 -and (State).refused)

# The certificate in use: newest expiry, then newest start (a renewal capped at the CA's expiry ties the old one).
$order = & {
  function Get-ChildItem { [CmdletBinding()] param([Parameter(Position = 0)]$Path)
    [pscustomobject]@{ Thumbprint = 'A'; NotAfter = [datetime]'2027-01-01'; NotBefore = [datetime]'2026-01-01' }
    [pscustomobject]@{ Thumbprint = 'B'; NotAfter = [datetime]'2027-01-01'; NotBefore = [datetime]'2026-11-01' }
    [pscustomobject]@{ Thumbprint = 'C'; NotAfter = [datetime]'2026-12-01'; NotBefore = [datetime]'2026-06-01' } }
  function Test-EasyEapCertificate($Cert) { $true }
  (& $RealGetCertificates | ForEach-Object Thumbprint) -join ','
}
DCheck 'newest certificate first, the later start breaking a tie' ($order -eq 'B,A,C')

# The user is told near expiry, once a day, by the user task only.
Reset 10
Invoke-Warning; Invoke-Warning
$script:now = $script:now.AddDays(1); Invoke-Warning
$Machine = $true; $script:now = $script:now.AddDays(1); Invoke-Warning; $Machine = $false
DCheck 'expiry notice: once a day, users only' ((Logged 'notice*') -eq 2)

# Times from EasyEAP and the saved files: text in Windows PowerShell, DateTime in PowerShell 7.
$t = [DateTimeOffset]::new(2026, 11, 9, 10, 0, 0, [TimeSpan]::Zero)
DCheck 'times read either way' ((ConvertTo-Instant '2026-11-09T10:00:00+00:00') -eq $t -and (ConvertTo-Instant '2026-11-09T12:00:00.0000000+02:00') -eq $t -and
  (ConvertTo-Instant $t.UtcDateTime) -eq $t -and $null -eq (ConvertTo-Instant '') -and $null -eq (ConvertTo-Instant $null) -and $null -eq (ConvertTo-Instant 'soon'))
