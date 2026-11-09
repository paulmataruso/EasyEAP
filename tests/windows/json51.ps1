# Dot-sourced by the Windows checks: ConvertTo-Json as Windows PowerShell 5.1 would treat what it's given. 5.1 writes a
# string that carries notes (Get-Content adds PSPath, PSParentPath and others) as an object, {"value": ..., "PSPath": ...},
# and a DateTimeOffset as an object too; PowerShell 7 writes both as text, so such bugs don't show here by themselves.
# Each value like that is recorded in $script:Json51 (where it was found), then the real ConvertTo-Json runs.
$script:Json51 = @()

function Find-Json51($Value, [string]$Path = 'value', [int]$Level = 0) {
  if ($null -eq $Value -or $Level -gt 8) { return }
  if ($Value -is [DateTimeOffset]) { "$Path is a DateTimeOffset"; return }
  if ($Value -is [string] -or $Value -is [ValueType]) {
    $notes = @($Value.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' })
    if ($notes) { "$Path carries $($notes.Name -join ', ')" }
    return
  }
  if ($Value -is [Collections.IDictionary]) { foreach ($k in @($Value.Keys)) { Find-Json51 $Value[$k] "$Path.$k" ($Level + 1) }; return }
  if ($Value -is [Collections.IEnumerable]) { $i = 0; foreach ($v in $Value) { Find-Json51 $v "$Path[$i]" ($Level + 1); $i++ }; return }
  foreach ($p in $Value.PSObject.Properties) { if ($p.MemberType -eq 'NoteProperty') { Find-Json51 $p.Value "$Path.$($p.Name)" ($Level + 1) } }
}

function ConvertTo-Json {
  [CmdletBinding()] param([Parameter(ValueFromPipeline, Position = 0)]$InputObject, [int]$Depth = 2, [switch]$Compress)
  begin { $all = @() }
  process { $script:Json51 += @(Find-Json51 $InputObject); $all += , $InputObject }
  end {
    $in = if ($all.Count -eq 1) { $all[0] } else { $all }
    Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $in -Depth $Depth -Compress:$Compress
  }
}
