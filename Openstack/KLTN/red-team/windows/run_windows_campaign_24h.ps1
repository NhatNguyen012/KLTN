param(
  [int]$DurationSec = 86400,
  [string]$Dir = "C:\KLTN\redteam",
  [string]$Attacker = "203.0.113.66",
  [int]$InitialDelaySec = 60,
  [switch]$DryRun
)

if (-not ($Attacker -match '^(203\.0\.113\.|10\.30\.)')) {
  throw "SAFETY BLOCK: Attacker IP '$Attacker' outside authorized lab CIDRs (203.0.113.0/24 or 10.30.0.0/16)."
}

$Env:PSModulePath = 'C:\AtomicRedTeam\invoke-atomicredteam;' + $Env:PSModulePath
Import-Module invoke-atomicredteam -Force

$PauseFile = Join-Path $Dir "PAUSE"
$StopFile = Join-Path $Dir "STOP"
$GtFile = Join-Path $Dir "gt_win24h.jsonl"
$LogFile = Join-Path $Dir "win_24h.log"
$Atomics = "C:\AtomicRedTeam\atomics"

function Log-Msg([string]$msg) {
  $line = "$(Get-Date -Format o) $msg"
  Add-Content -Path $LogFile -Value $line -Encoding Utf8
}

function Load-Wave([string]$name, [string]$file) {
  $list = @()
  $path = Join-Path $Dir $file
  if (-not (Test-Path $path)) { return $list }
  Get-Content $path | ForEach-Object {
    $clean = ($_ -split '#')[0].Trim()
    if (-not $clean) { return }
    $parts = $clean -split '-'
    $list += [pscustomobject]@{
      Wave = $name
      Id = $clean
      Tech = $parts[0]
      Num = if ($parts.Count -gt 1) { [int]$parts[1] } else { 1 }
    }
  }
  return $list
}

$items = @()
$items += Load-Wave "W1_baseline" "W1_baseline.txt"
$items += Load-Wave "W2_obfuscated" "W2_obfuscated.txt"
$items += Load-Wave "W3_unseen" "W3_unseen.txt"

$count = [Math]::Max(1, $items.Count)
$span = [Math]::Max(60, ($DurationSec - 1800) - $InitialDelaySec)
$step = [int]($span / $count)
$t0 = [DateTimeOffset]::UtcNow

Log-Msg "START windows 24h campaign items=$count duration=${DurationSec}s step=${step}s dry=$DryRun"

for ($i = 0; $i -lt $items.Count; $i++) {
  if (Test-Path $StopFile) { Log-Msg "STOP file detected; exiting cleanly."; break }
  $item = $items[$i]
  $offset = $InitialDelaySec + ($i * $step)
  $targetTime = $t0.AddSeconds($offset)

  while ([DateTimeOffset]::UtcNow -lt $targetTime) {
    if (Test-Path $StopFile) { break }
    Start-Sleep -Seconds ([Math]::Min(30, [Math]::Max(1, [int](($targetTime - [DateTimeOffset]::UtcNow).TotalSeconds))))
  }
  while (Test-Path $PauseFile) {
    if (Test-Path $StopFile) { break }
    Log-Msg "PAUSED before $($item.Id); waiting 30s"
    Start-Sleep -Seconds 30
  }
  if (Test-Path $StopFile) { Log-Msg "STOP file detected; exiting cleanly."; break }

  $status = "ok"
  $detail = "executed offline"
  if ($DryRun) {
    $status = "dry"
    $detail = "dry-run skip"
  } else {
    try {
      Invoke-AtomicTest $item.Tech -TestNumbers $item.Num -PathToAtomicsFolder $Atomics -Confirm:$false -ErrorAction Stop 2>&1 | Out-Null
    } catch {
      $status = "warn"
      $detail = ($_.Exception.Message -replace '\s+', ' ').Trim()
    }
    try {
      Invoke-AtomicTest $item.Tech -TestNumbers $item.Num -PathToAtomicsFolder $Atomics -Cleanup -Confirm:$false 2>&1 | Out-Null
    } catch { }
  }

  $ev = [ordered]@{
    run = "WIN-24H"
    ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    wave = $item.Wave
    technique = $item.Id
    target = "10.30.3.159"
    status = $status
    evidence = $detail
  } | ConvertTo-Json -Compress
  Add-Content -Path $GtFile -Value $ev -Encoding Utf8
  Log-Msg "DONE $($item.Wave) $($item.Id) status=$status"
}

Log-Msg "END windows 24h campaign"
