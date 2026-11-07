# tests/windows/run.sh: PowerShell's own parser over every generated file, then the renewal script's real signing
# function (taken from the generated renew.ps1 by its syntax tree) run against software keys.
$ErrorActionPreference = 'Stop'
$fail = 0
foreach ($f in Get-ChildItem /out -File | Where-Object { $_.Extension -in '.cmd', '.ps1' }) {
  $tokens = $null; $errors = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
  if ($errors.Count) {
    $fail++
    Write-Host "  FAIL $($f.Name) parses: $($errors.Count) error(s)"
    $errors | Select-Object -First 5 | ForEach-Object { Write-Host "      line $($_.Extent.StartLineNumber): $($_.Message)" }
  } else { Write-Host "  PASS $($f.Name) parses" }
}

# Every embedded profile is well-formed XML with the expected authentication mode.
$expect = @{ 'full.cmd' = 'machineOrUser'; 'user-only.cmd' = 'user'; 'shared-pc.cmd' = 'machine' }
foreach ($name in $expect.Keys) {
  $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path /out $name), [ref]$null, [ref]$null)
  $assigns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -in '$WlanXml', '$LanXml' }, $false)
  foreach ($a in $assigns) {
    $text = $a.Right.Expression.Value
    if (-not $text) { continue }
    $xml = [xml]$text
    $mode = $xml.SelectSingleNode("//*[local-name()='authMode']").InnerText
    $hashes = $xml.SelectNodes("//*[local-name()='IssuerHash']").Count
    $ok = $mode -eq $expect[$name] -and $hashes -eq 2
    if (-not $ok) { $fail++ }
    Write-Host ("  {0} {1} {2}: authMode {3}, issuer filter {4} CA(s)" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $name, $a.Left.Extent.Text, $mode, $hashes)
  }
}

# The renewal signing code, exactly as generated.
$renew = [System.Management.Automation.Language.Parser]::ParseFile('/out/full-renew.ps1', [ref]$null, [ref]$null)
$funcs = $renew.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in 'Get-Hex', 'New-RenewalBody' }, $true)
foreach ($fn in $funcs) { . ([scriptblock]::Create($fn.Extent.Text)) }
foreach ($kind in 'ec', 'rsa') {
  $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("/out/$kind.pfx", 'test')
  $body = New-RenewalBody $cert (Get-Content "/out/$kind.csr" -Raw) 'software'
  $body | ConvertTo-Json | Set-Content "/out/$kind-body.json"
}

# The setup's own flow (the computer part, then the user part) with Windows' commands replaced by recorders: each step
# stands alone, and the user part covers exactly what the computer part didn't do.
$main = [System.Management.Automation.Language.Parser]::ParseFile('/out/full.cmd', [ref]$null, [ref]$null)
$config = '$Api', '$Org', '$ForUser', '$UserCode', '$ComputerCode', '$Ssid', '$Wired', '$Expires', '$RootPem', '$IssuingPem', '$IssuingDer',
  '$WlanXml', '$WlanUserXml', '$LanXml', '$RenewPs1'
foreach ($st in $main.EndBlock.Statements) {
  if ($st -is [System.Management.Automation.Language.AssignmentStatementAst] -and $st.Left.Extent.Text -in $config) { . ([scriptblock]::Create($st.Extent.Text)) }
}
foreach ($fn in $main.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { . ([scriptblock]::Create($fn.Extent.Text)) }

$env:TEMP = '/tmp'; $env:LOCALAPPDATA = '/tmp/lad'; $env:USERNAME = 'nina'; $env:USERDOMAIN = 'CORP'
$ProgramDir = '/tmp/pf/EasyEAP'
$script:log = [System.Collections.Generic.List[string]]::new()
$script:fail_netsh = @(); $script:fail_cert = $false
function Install-EasyEapCertificate($Code, $Machine, $Work) {
  $script:log.Add("cert $Code machine=$Machine")
  if ($Machine -and $script:fail_cert) { throw 'This code was already used.' }
  @{ Serial = '01'; NotAfter = '2027-01-01T00:00:00Z'; Storage = 'software' }
}
function Import-Certificate { [CmdletBinding()] param($FilePath, $CertStoreLocation) $script:log.Add("import $CertStoreLocation") }
function Set-Service { [CmdletBinding()] param($Name, $StartupType) }
function Start-Service { [CmdletBinding()] param($Name) }
function Get-Service { [CmdletBinding()] param($Name) [pscustomobject]@{ Name = $Name; Status = 'Running' } }
function Get-NetAdapter { [CmdletBinding()] param([switch]$Physical)
  @([pscustomobject]@{ Name = 'Ethernet'; MediaType = '802.3' }, [pscustomobject]@{ Name = 'Dock'; MediaType = '802.3' }, [pscustomobject]@{ Name = 'Wi-Fi'; MediaType = 'Native 802.11' }) }
function netsh.exe {
  $line = $args -join ' '
  $script:log.Add("netsh $line")
  $global:LASTEXITCODE = if (@($script:fail_netsh | Where-Object { $line -like $_ }).Count) { 1 } else { 0 }
}
function New-EventLog { [CmdletBinding()] param($LogName, $Source) }
function New-ScheduledTaskSettingsSet { [CmdletBinding()] param([Parameter(ValueFromRemainingArguments)]$Rest) 'settings' }
function New-ScheduledTaskAction { [CmdletBinding()] param($Execute, $Argument) $Argument }
function New-ScheduledTaskTrigger { [CmdletBinding()] param([Parameter(ValueFromRemainingArguments)]$Rest) 'trigger' }
function New-ScheduledTaskPrincipal { [CmdletBinding()] param($UserId, $GroupId, $LogonType, $RunLevel) "$UserId$GroupId" }
function Get-CimClass { [CmdletBinding()] param($Namespace, $ClassName) 'class' }
function New-CimInstance { [CmdletBinding()] param($CimClass, [switch]$ClientOnly) [pscustomobject]@{ StateChange = 0 } }
function Register-ScheduledTask { [CmdletBinding()] param($TaskPath = '\', $TaskName, $Action, $Trigger, $Principal, $Settings, [switch]$Force)
  $script:log.Add("task $TaskPath$TaskName as '$Principal' triggers=$(@($Trigger).Count)") }
function Get-ScheduledTask { [CmdletBinding()] param($TaskName) [pscustomobject]@{ TaskName = $TaskName } }
function Unregister-ScheduledTask { [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject, [switch]$Confirm) process { $script:log.Add("unregister $($InputObject.TaskName)") } }

function Check([string]$Name, [bool]$Ok, $Detail) {
  if (-not $Ok) { $script:fail++ }
  Write-Host ("  {0} flow: {1}{2}" -f $(if ($Ok) { 'PASS' } else { 'FAIL' }), $Name, $(if (-not $Ok -and $Detail) { " -- $Detail" } else { '' }))
}
function Has([string]$Pattern) { @($script:log | Where-Object { $_ -like $Pattern }).Count }

# 1. Everything works.
$script:log.Clear()
$c = Invoke-ComputerPart
Check 'computer part: all steps, both tasks' ($c.ok -and $c.trusted -and $c.wifi -and $c.renewal -and $c.steps.Count -eq 5 -and
  (Has 'import Cert:\LocalMachine\Root') -and (Has 'netsh lan add profile*interface=Ethernet') -and (Has 'netsh lan add profile*interface=Dock') -and
  -not (Has 'netsh lan*interface=Wi-Fi') -and (Has 'netsh wlan add profile*user=all') -and (Has "task \EasyEAP\Renew computer certificate as 'S-1-5-18' triggers=2") -and
  (Has "task \EasyEAP\Renew user certificate as 'S-1-5-32-545' triggers=2")) (($c.errors + $script:log) -join ' | ')
$back = $c | ConvertTo-Json | ConvertFrom-Json   # as the elevated copy hands it back
$script:log.Clear()
$u = Invoke-UserPart $back
Check 'user part after it: only the certificate' ($u.ok -and (Has 'cert UCODE machine=False') -and -not (Has 'import*') -and -not (Has 'netsh*') -and
  -not (Has 'task*') -and (Has 'unregister EasyEAP renew certificate (nina)')) (($u.errors + $script:log) -join ' | ')

# 2. Wi-Fi and one adapter refused: the rest still happens, and the user part adds Wi-Fi for the user.
$script:log.Clear(); $script:fail_netsh = @('wlan*', 'lan*interface=Dock')
$c = Invoke-ComputerPart
Check 'computer part: failures stay in their step' (-not $c.ok -and $c.trusted -and -not $c.wifi -and $c.renewal -and $c.errors.Count -eq 2 -and
  ($c.errors -join ' ') -like '*Dock*' -and ($c.errors -join ' ') -like '*Wi-Fi*' -and ($c.steps -join ' ') -like '*Wired 802.1X on 1 network adapter*' -and
  (Has 'cert CCODE machine=True')) (($c.errors + $c.steps) -join ' | ')
$script:log.Clear(); $script:fail_netsh = @()
$u = Invoke-UserPart ($c | ConvertTo-Json | ConvertFrom-Json)
Check 'user part covers the Wi-Fi' ($u.ok -and (Has 'netsh wlan add profile*user=current') -and -not (Has 'import*') -and -not (Has 'task*')) (($u.errors + $script:log) -join ' | ')

# 3. The computer certificate is refused (code already used): trust, networks and renewal still set up.
$script:log.Clear(); $script:fail_cert = $true
$c = Invoke-ComputerPart
Check 'computer part: refused certificate' (-not $c.ok -and $c.renewal -and $c.wifi -and ($c.errors -join ' ') -like 'The computer certificate: This code was already used.*') ($c.errors -join ' | ')
$script:fail_cert = $false

# 4. No computer part (approval declined): the user trusts the CA, gets Wi-Fi and their own renewal task.
$script:log.Clear()
$u = Invoke-UserPart $null
Check 'user part alone' ($u.ok -and (Has 'import Cert:\CurrentUser\Root') -and (Has 'netsh wlan add profile*user=current') -and
  (Has "task \EasyEAP renew certificate (nina) as '' triggers=2") -and (Test-Path '/tmp/lad/EasyEAP/renew.ps1')) (($u.errors + $script:log) -join ' | ')
exit $fail
