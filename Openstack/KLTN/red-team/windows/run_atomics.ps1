<#
  run_atomics.ps1 — orchestrate an Atomic Red Team sequence on kltn-windows-1 and
  write the red-team ground-truth log (UTC per technique) for SOC labeling.

  AUTHORIZED LAB ONLY. Run on the lab Windows VM after: Install-Module invoke-atomicredteam.
  The actual attack commands are ATT's maintained atomics — this script only sequences them,
  times them in UTC, and cleans up. Written, not executed by the author.

  Usage:
    powershell -ep bypass -f run_atomics.ps1 -Plan .\W1_baseline.txt -Attacker 203.0.113.66
    powershell -ep bypass -f run_atomics.ps1 -Plan .\W1_baseline.txt -WhatIf     # preview only
    powershell -ep bypass -f run_atomics.ps1 -Plan .\W1_baseline.txt -Cleanup    # revert atomics
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$Plan,
  [string]$Attacker = "203.0.113.66",
  [string]$LogDir   = "$env:TEMP\kltn-redteam",
  [switch]$WhatIf,
  [switch]$Cleanup,
  [switch]$DownloadPrereqs
)

if ($Attacker -notmatch '^(203\.0\.113\.|10\.30\.)') {
  throw "SAFETY BLOCK: Attacker IP '$Attacker' is outside authorized lab CIDRs (203.0.113.0/24 or 10.30.0.0/16)."
}

$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$log = Join-Path $LogDir ("redteam_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
"utc_start,utc_end,technique,test,tactic,note" | Out-File -Encoding utf8 $log

Import-Module invoke-atomicredteam -ErrorAction SilentlyContinue

# plan line: "<technique>[-<testNumber>]   # tactic | note"
foreach ($line in Get-Content $Plan) {
  $raw = $line.Trim()
  if (-not $raw -or $raw.StartsWith("#")) { continue }
  $spec, $comment = $raw -split "#", 2
  $tok  = ($spec.Trim() -split "\s+")[0]
  $tech, $testNum = $tok -split "-", 2
  $meta = if ($comment) { $comment.Trim() } else { "" }

  $start = (Get-Date).ToUniversalTime().ToString("o")
  $common = @{ AtomicTechnique = $tech; TimeoutSeconds = 120 }
  if ($testNum) { $common["TestNumbers"] = @($testNum) }

  if ($WhatIf) {
    Write-Host "[preview] $tech $testNum"
    Invoke-AtomicTest @common -ShowDetailsBrief
  } elseif ($Cleanup) {
    Write-Host "[cleanup] $tech $testNum"
    Invoke-AtomicTest @common -Cleanup
  } else {
    Write-Host "[run] $tech $testNum  ($meta)"
    if ($DownloadPrereqs) { Invoke-AtomicTest @common -GetPrereqs }
    Invoke-AtomicTest @common -InputArgs @{ server_ip = $Attacker }
  }

  $end = (Get-Date).ToUniversalTime().ToString("o")
  '"{0}","{1}","{2}","{3}","","{4}"' -f $start,$end,$tech,$testNum,$meta | Out-File -Append -Encoding utf8 $log
}

Write-Host "`nRed-team log: $log"
Write-Host "Use the utc_start/utc_end columns to bracket each technique when labeling on /soc."
