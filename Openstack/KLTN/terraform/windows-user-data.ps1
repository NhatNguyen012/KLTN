#ps1_sysnative
$ErrorActionPreference = "Stop"

# Disable sleep and hibernation; this is a lab VM that must stay accessible.
powercfg /change standby-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
powercfg /hibernate off

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


# Bootstrap Ansible over HTTPS. The controller retrieves this certificate via
# QEMU Guest Agent and validates it; no password is placed in user-data.
Set-Service WinRM -StartupType Automatic
Start-Service WinRM
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
Set-Item WSMan:\localhost\Service\Auth\Negotiate -Value $true
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -Type DWord -Value 1
$listener = Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTPS' }
if (-not $listener) {
    $cert = New-SelfSignedCertificate -Subject "CN=${management_ip}" -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm RSA -KeyLength 2048 -NotAfter (Get-Date).AddYears(1) -TextExtension @('2.5.29.17={text}IPAddress=${management_ip}')
    New-Item WSMan:\localhost\Listener -Transport HTTPS -Address '*' -CertificateThumbPrint $cert.Thumbprint -Force | Out-Null
}
if (-not (Get-NetFirewallRule -Name KLTN-WinRM-HTTPS -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name KLTN-WinRM-HTTPS -DisplayName 'KLTN WinRM HTTPS' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5986 -RemoteAddress '${management_cidr}' -Profile Any | Out-Null
}
