# KLTN benign baseline activity (Windows): ordinary office/admin/browsing behaviour. No persistence, no privilege
# change, nothing an attack needs. Runs 2-4 varied actions per invocation so windows differ.
$ErrorActionPreference = 'SilentlyContinue'
$wd = 'C:\KLTN\workload'; New-Item -ItemType Directory -Force -Path "$wd\docs" | Out-Null
$sites = @('https://www.microsoft.com','https://en.wikipedia.org/wiki/Special:Random','https://www.bing.com','https://ubuntu.com')
$acts = 1..(Get-Random -Minimum 2 -Maximum 5)
foreach ($a in $acts) {
  switch (Get-Random -Maximum 11) {
    0 { Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 | Out-Null }
    1 { Get-Service | Where-Object Status -eq 'Running' | Measure-Object | Out-Null }
    2 { Get-ChildItem C:\Windows\Logs -Recurse -Depth 1 | Out-Null }
    3 { try { Invoke-WebRequest ($sites | Get-Random) -UseBasicParsing -TimeoutSec 10 | Out-Null } catch {} }
    4 { Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version | Out-Null; Get-CimInstance Win32_LogicalDisk | Out-Null }
    5 { $f="$wd\docs\memo_$(Get-Random -Maximum 6).txt"; Add-Content -Path $f -Value "edited $(Get-Date)"; Get-Content $f | Out-Null }
    6 { Get-WinEvent -LogName System -MaxEvents 20 | Out-Null }
    7 { Get-NetTCPConnection -State Established | Select-Object -First 10 | Out-Null; Test-Connection 10.30.3.1 -Count 1 | Out-Null }
    8 { Get-ChildItem Env: | Out-Null; whoami /all | Out-Null }
    9 { $z="$wd\docs_backup.zip"; Compress-Archive -Path "$wd\docs" -DestinationPath $z -Force; Remove-Item $z -Force }
    10 { Get-LocalUser | Out-Null; Get-ScheduledTask | Where-Object State -eq 'Ready' | Measure-Object | Out-Null }
  }
  Start-Sleep -Seconds (Get-Random -Minimum 2 -Maximum 20)
}
