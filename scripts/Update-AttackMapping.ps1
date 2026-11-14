<#
.SYNOPSIS
  Regenerates catalog/attack-enterprise.tsv from MITRE's official ATT&CK STIX bundle and validates every ATT&CK
  reference in the repository.

.DESCRIPTION
  1. Downloads (or reads) enterprise-attack-<version>.json from github.com/mitre-attack/attack-stix-data and writes
     one row per active (non-revoked, non-deprecated) Enterprise technique or sub-technique:

       technique_id  name  tactics  platforms  detection_strategies  mitigations

     detection_strategies = DET IDs linked by a "detects" relationship (ATT&CK v18+ data model)
     mitigations          = M IDs linked by a "mitigates" relationship

  2. ID check: every T1xxx / DETxxxx / M1xxx cited in catalog/, docs/, skills/, templates/, runbooks/ and root *.md
     must be active in the chosen version. Lines that deliberately cite revoked IDs carry "attack-lint: historical".

  3. Consistency check: every DET cited in a catalog entry (services.yaml / cloud-assets.yaml "- id:" block) or in a
     runbook (runbooks/RB-*.md) must detect at least one technique cited in that same entry or runbook.

  Exit code 1 if either check fails.

  Runs on Windows PowerShell 5.1 and PowerShell 7+.

.PARAMETER Version
  ATT&CK version, e.g. "20.1". Default: latest listed in the STIX index.

.PARAMETER StixPath
  Use a local STIX JSON instead of downloading.

.EXAMPLE
  ./scripts/Update-AttackMapping.ps1                 # latest
  ./scripts/Update-AttackMapping.ps1 -Version 20.1   # pinned
#>
[CmdletBinding()]
param(
  [string]$Version,
  [string]$StixPath
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$outFile = Join-Path $repo 'catalog/attack-enterprise.tsv'
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $outFile) | Out-Null

if (-not $StixPath) {
  $index = Invoke-RestMethod -UseBasicParsing 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json'
  $coll = $index.collections | Where-Object { $_.name -eq 'Enterprise ATT&CK' } | Select-Object -First 1
  $ver = if ($Version) { $coll.versions | Where-Object { $_.version -eq $Version } } else { $coll.versions | Select-Object -First 1 }
  if (-not $ver) { throw "ATT&CK version '$Version' not found in STIX index." }
  $Version = $ver.version
  $StixPath = Join-Path ([IO.Path]::GetTempPath()) "enterprise-attack-$Version.json"
  Write-Host "Downloading ATT&CK Enterprise $Version ..."
  Invoke-WebRequest -UseBasicParsing -Uri $ver.url -OutFile $StixPath
}
if (-not $Version) { $Version = 'local' }

# ---- load STIX as nested hashtables / arrays (PS 7+: ConvertFrom-Json -AsHashtable; PS 5.1: JavaScriptSerializer) ----
$json = [IO.File]::ReadAllText($StixPath)
if ($PSVersionTable.PSVersion.Major -ge 7) {
  $bundle = $json | ConvertFrom-Json -AsHashtable -Depth 100
} else {
  Add-Type -AssemblyName System.Web.Extensions
  $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
  $ser.MaxJsonLength = [int]::MaxValue
  $bundle = $ser.DeserializeObject($json)
}
$json = $null

# STIX id -> { ext, name, type, active, obj }
$byStixId = @{}
foreach ($o in $bundle['objects']) {
  if (-not $o['external_references']) { continue }
  $ref = $o['external_references'] | Where-Object { $_['source_name'] -eq 'mitre-attack' } | Select-Object -First 1
  if (-not $ref) { continue }
  $byStixId[$o['id']] = @{
    ext    = $ref['external_id']
    name   = $o['name']
    type   = $o['type']
    active = -not ($o['revoked'] -or $o['x_mitre_deprecated'])
    obj    = $o
  }
}

# technique -> DETs / Ms ; DET -> techniques
$det = @{}; $mit = @{}; $detToT = @{}
foreach ($o in $bundle['objects']) {
  if ($o['type'] -ne 'relationship' -or $o['revoked'] -or $o['x_mitre_deprecated']) { continue }
  $rt = $o['relationship_type']
  if ($rt -ne 'detects' -and $rt -ne 'mitigates') { continue }
  $s = $byStixId[$o['source_ref']]; $t = $byStixId[$o['target_ref']]
  if (-not $s -or -not $t -or -not $s.active -or -not $t.active) { continue }
  if ($s.ext -notmatch '^(DET|M)\d+$') { continue }
  $bucket = if ($rt -eq 'detects') { $det } else { $mit }
  if (-not $bucket.ContainsKey($t.ext)) { $bucket[$t.ext] = New-Object System.Collections.Generic.List[string] }
  if (-not $bucket[$t.ext].Contains($s.ext)) { $bucket[$t.ext].Add($s.ext) }
  if ($rt -eq 'detects') {
    if (-not $detToT.ContainsKey($s.ext)) { $detToT[$s.ext] = New-Object System.Collections.Generic.List[string] }
    if (-not $detToT[$s.ext].Contains($t.ext)) { $detToT[$s.ext].Add($t.ext) }
  }
}

$rows = foreach ($e in $byStixId.Values) {
  if ($e.type -ne 'attack-pattern' -or -not $e.active) { continue }
  $o = $e.obj
  $tactics = ($o['kill_chain_phases'] | ForEach-Object { $_['phase_name'] }) -join ','
  $plats   = ($o['x_mitre_platforms']) -join ','
  $d = if ($det[$e.ext]) { ($det[$e.ext] | Sort-Object) -join ',' } else { '' }
  $m = if ($mit[$e.ext]) { ($mit[$e.ext] | Sort-Object) -join ',' } else { '' }
  "{0}`t{1}`t{2}`t{3}`t{4}`t{5}" -f $e.ext, $e.name, $tactics, $plats, $d, $m
}
$header = "# ATT&CK Enterprise $Version - generated $(Get-Date -Format yyyy-MM-dd) by scripts/Update-AttackMapping.ps1 - (c) The MITRE Corporation, ATT&CK Terms of Use apply`n" +
          "technique_id`tname`ttactics`tplatforms`tdetection_strategies`tmitigations"
$body = ($rows | Sort-Object) -join "`n"
[IO.File]::WriteAllText($outFile, "$header`n$body`n", (New-Object Text.UTF8Encoding($false)))
Write-Host "Wrote $(@($rows).Count) techniques to $outFile"

# ---- check 1: every cited ID is active ----
$activeT = @{}; $activeDet = @{}; $activeM = @{}
foreach ($e in $byStixId.Values) {
  if (-not $e.active) { continue }
  switch -Regex ($e.ext) {
    '^T\d{4}(\.\d{3})?$' { if ($e.type -eq 'attack-pattern') { $activeT[$e.ext] = 1 } }
    '^DET\d+$'           { $activeDet[$e.ext] = 1 }
    '^M\d{4}$'           { if ($e.type -eq 'course-of-action') { $activeM[$e.ext] = 1 } }
  }
}
$idRegex = '\b(T1\d{3}(?:\.\d{3})?|DET\d{4}|M1\d{3})\b'   # Enterprise only; ATT&CK for ICS (T0xxx) is not checked
$scanDirs = @('catalog', 'docs', 'skills', 'templates', 'runbooks') | ForEach-Object { Join-Path $repo $_ } | Where-Object { Test-Path $_ }
$files = @(Get-ChildItem -Recurse -File -Path $scanDirs -Include *.yaml, *.md) +
         @(Get-ChildItem -File -Path $repo -Filter *.md)
$bad = @()
foreach ($f in $files) {
  $n = 0
  foreach ($line in [IO.File]::ReadAllLines($f.FullName)) {
    $n++
    if ($line -match 'attack-lint:\s*historical') { continue }
    foreach ($m in [regex]::Matches($line, $idRegex)) {
      $id = $m.Value
      $ok = switch -Regex ($id) { '^T' { $activeT.ContainsKey($id) } '^DET' { $activeDet.ContainsKey($id) } '^M' { $activeM.ContainsKey($id) } }
      if (-not $ok) { $bad += "$($f.Name):$n $id" }
    }
  }
}

# ---- check 2: each cited DET detects a technique cited in the same unit ----
function Test-DetConsistency([string]$unitName, [string[]]$lines) {
  $ts = @{}; $ds = @{}
  foreach ($l in $lines) {
    if ($l -match 'attack-lint:\s*historical') { continue }
    foreach ($m in [regex]::Matches($l, '\bT1\d{3}(?:\.\d{3})?\b')) { $ts[$m.Value] = 1 }
    foreach ($m in [regex]::Matches($l, '\bDET\d{4}\b')) { $ds[$m.Value] = 1 }
  }
  foreach ($d in $ds.Keys) {
    $hit = $false
    if ($detToT.ContainsKey($d)) { foreach ($t in $detToT[$d]) { if ($ts.ContainsKey($t)) { $hit = $true; break } } }
    if (-not $hit) { "$unitName -> $d (detects: $(@($detToT[$d]) -join ',')) has no matching technique cited alongside it" }
  }
}
$incons = @()
foreach ($cat in @('services.yaml', 'cloud-assets.yaml')) {
  $p = Join-Path $repo "catalog/$cat"
  if (-not (Test-Path $p)) { continue }
  $block = New-Object System.Collections.Generic.List[string]; $id = $null
  foreach ($line in [IO.File]::ReadAllLines($p)) {
    if ($line -match '^- id:\s*(\S+)') {
      if ($id) { $incons += Test-DetConsistency "$cat#$id" $block.ToArray() }
      $id = $Matches[1]; $block.Clear()
    } elseif ($id) { $block.Add($line) }
  }
  if ($id) { $incons += Test-DetConsistency "$cat#$id" $block.ToArray() }
}
$rbDir = Join-Path $repo 'runbooks'
if (Test-Path $rbDir) {
  foreach ($rb in Get-ChildItem -File -Path $rbDir -Filter 'RB-*.md') {
    $incons += Test-DetConsistency $rb.Name ([IO.File]::ReadAllLines($rb.FullName))
  }
}

# ---- report ----
$failed = $false
$bad = $bad | Sort-Object -Unique
if ($bad) {
  $failed = $true
  Write-Warning "IDs not active in ATT&CK $Version (revoked, deprecated or mistyped):"
  $bad | ForEach-Object { Write-Warning "  $_" }
}
if ($incons) {
  $failed = $true
  Write-Warning "Detection strategies cited without any technique they detect:"
  $incons | ForEach-Object { Write-Warning "  $_" }
}
if ($failed) { exit 1 }
Write-Host "Check 1: all ATT&CK IDs cited in catalog/, docs/, skills/, templates/, runbooks/ and root *.md are active in $Version."
Write-Host "Check 2: every DET in each catalog entry and runbook detects a technique cited alongside it."
