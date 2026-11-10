# tests/windows/run.sh: the certificate requests the setup file, its renew.ps1 and the portal helper send, built by
# their own code with certreq stood in for.
#
# Windows PowerShell 5.1's ConvertTo-Json writes a string that carries notes (Get-Content adds PSPath, PSParentPath and
# others) as an object, {"value": ..., "PSPath": ...}, and EasyEAP refuses that csr ("Input should be a valid string").
# PowerShell 7 writes it as a string, so the bug doesn't show here by itself: json51.ps1's ConvertTo-Json records it.
$ErrorActionPreference = 'Stop'
$fail = 0
function Check([string]$Name, [bool]$Ok, $Detail) {
  if (-not $Ok) { $script:fail++ }
  Write-Host ("  {0} {1}{2}" -f $(if ($Ok) { 'PASS' } else { 'FAIL' }), $Name, $(if ($Detail -and -not $Ok) { ": $Detail" } else { '' }))
}

. /t/json51.ps1

# certreq -q -new <inf> <csr>: writes a request file as certreq does, and remembers the request's subject.
$PemText = "-----BEGIN NEW CERTIFICATE REQUEST-----`r`nMIIBtest`r`n-----END NEW CERTIFICATE REQUEST-----`r`n"
function certreq.exe {
  $a = @($args)
  $i = [array]::IndexOf($a, '-new')
  if ($i -ge 0) {
    $script:subject = ((Get-Content $a[$i + 1]) | Where-Object { $_ -like 'Subject = *' }) -replace '^Subject = "(.*)"$', '$1'
    [IO.File]::WriteAllText($a[$i + 2], $PemText)
  }
  $global:LASTEXITCODE = 0
}
function Get-ChildItem { [CmdletBinding()] param([Parameter(Position = 0)]$Path) [pscustomobject]@{ Subject = $script:subject; Thumbprint = 'AB12'; PSPath = 'x' } }
function Remove-Item { [CmdletBinding()] param([Parameter(Position = 0)]$Path, [switch]$DeleteKey, [switch]$Recurse, [switch]$Force) }

function Import-Functions([string]$File, [string[]]$Names) {
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($File, [ref]$null, [ref]$null)
  foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $Names }, $true)) {
    . ([scriptblock]::Create($fn.Extent.Text))
    Set-Item -Path "function:script:$($fn.Name)" -Value (Get-Item "function:$($fn.Name)").ScriptBlock
  }
}

# The guard itself: a Get-Content string is caught, a ReadAllText one isn't.
$probe = Join-Path ([IO.Path]::GetTempPath()) 'easyeap-probe.csr'
[IO.File]::WriteAllText($probe, $PemText)
$script:Json51 = @(); $null = @{ csr = (Get-Content $probe -Raw) } | ConvertTo-Json
$caught = $script:Json51.Count -gt 0
$script:Json51 = @(); $null = @{ csr = [IO.File]::ReadAllText($probe) } | ConvertTo-Json
Check 'the check catches a Get-Content string in a JSON body, and only that' ($caught -and -not $script:Json51.Count)

$work = Join-Path ([IO.Path]::GetTempPath()) ('easyeap-bodies-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null

# renew.ps1 (setup file and helper): the request it keeps while it waits, and what it sends.
foreach ($file in '/out/full-renew.ps1', '/out/helper-renew.ps1') {
  Import-Functions $file @('New-EasyEapRequest')
  $Machine = $false; $StoreRoot = 'Cert:\CurrentUser'
  $script:Json51 = @()
  $req = New-EasyEapRequest $work
  $pending = [pscustomobject]@{ csr = $req.Pem; request = $req.Request; storage = $req.Storage; for = 'AB'; made = 'now' }
  $saved = $pending | ConvertTo-Json -Compress
  $sent = @{ csr = $req.Pem; key_storage = $req.Storage } | ConvertTo-Json -Compress
  $ok = -not $script:Json51.Count -and (($saved | ConvertFrom-Json).csr -eq $PemText) -and (($sent | ConvertFrom-Json).csr -is [string])
  Check "$(Split-Path $file -Leaf): the request it keeps and sends is a plain string" $ok ($script:Json51 -join '; ')
}

# The setup file: the body Install-EasyEapCertificate sends, from its own code up to Invoke-RestMethod.
Import-Functions '/out/full.cmd' @('New-EasyEapRequest', 'Install-EasyEapCertificate', 'Use-EasyEapPin', 'Get-EasyEapPinHint')
$Api = 'https://easyeap.example'; $TlsPin = ''; $env:COMPUTERNAME = 'PC-1'
$script:body = $null
function Invoke-RestMethod { [CmdletBinding()] param($Method, $Uri, $ContentType, $Body, [switch]$UseBasicParsing) $script:body = $Body; throw 'stop here' }
foreach ($machine in $false, $true) {
  $script:Json51 = @()
  try { Install-EasyEapCertificate 'CODE' $machine $work } catch { }
  $csr = if ($script:body) { ($script:body | ConvertFrom-Json).csr } else { $null }
  Check "full.cmd: the $(if ($machine) { 'computer' } else { 'user' }) certificate request sends csr as a string" (-not $script:Json51.Count -and $csr -is [string] -and $csr -eq $PemText) (($script:Json51 -join '; ') + " body: $script:body")
}

# The portal helper runs top to bottom: its own two statements that read the request and build the body.
$helper = [System.Management.Automation.Language.Parser]::ParseFile('/out/helper.ps1', [ref]$null, [ref]$null)
$steps = $helper.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -in '$Csr', '$Body' }, $true)
$Work = $work; $Renewer = 'windows-helper'
[IO.File]::WriteAllText("$Work\req.csr", $PemText)   # the path the helper reads, as written (a backslash on Linux)
$script:Json51 = @()
foreach ($s in $steps) { . ([scriptblock]::Create($s.Extent.Text)) }
Check 'helper.ps1: the certificate request sends csr as a string' ($steps.Count -eq 2 -and -not $script:Json51.Count -and ($Body | ConvertFrom-Json).csr -eq $PemText) (($script:Json51 -join '; ') + " ($($steps.Count) statements)")

[IO.File]::Delete("$work\req.csr")
Microsoft.PowerShell.Management\Remove-Item -Recurse -Force $work, $probe -ErrorAction SilentlyContinue
exit $fail
