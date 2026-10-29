#ps1_sysnative
$ErrorActionPreference = "Stop"

$terminalServerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
Set-ItemProperty -Path $terminalServerPath -Name "fDenyTSConnections" -Value 0
Set-Service -Name "TermService" -StartupType Automatic
Start-Service -Name "TermService"
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

$icmpRuleName = "OpenStack ICMPv4 Echo Request"
if (-not (Get-NetFirewallRule -DisplayName $icmpRuleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule `
        -DisplayName $icmpRuleName `
        -Direction Inbound `
        -Action Allow `
        -Protocol ICMPv4 `
        -IcmpType 8
}
