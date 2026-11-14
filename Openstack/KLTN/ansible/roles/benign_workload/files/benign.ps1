# KLTN benign baseline activity (Windows): ordinary inventory and browsing, no system changes.
$n = Get-Random -Maximum 6
switch ($n) {
  0 { Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 | Out-Null }
  1 { Get-Service | Where-Object Status -eq 'Running' | Measure-Object | Out-Null }
  2 { Get-ChildItem C:\Windows\Logs -ErrorAction SilentlyContinue | Out-Null }
  3 { try { Invoke-WebRequest https://www.microsoft.com -UseBasicParsing -TimeoutSec 10 | Out-Null } catch {} }
  4 { Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version | Out-Null }
  5 { Add-Content -Path C:\KLTN\workload\notes.txt -Value (Get-Date) }
}
