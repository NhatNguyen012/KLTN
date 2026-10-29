$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$logPath = "C:\Windows\Temp\openstack-image-build.log"
Start-Transcript -Path $logPath -Append

try {
    $mediaRoot = $PSScriptRoot
    $virtioTools = Join-Path $mediaRoot "virtio-win-guest-tools.exe"
    $cloudbaseMsi = Join-Path $mediaRoot "CloudbaseInitSetup_Stable_x64.msi"

    if (-not (Test-Path $virtioTools)) {
        throw "VirtIO guest tools installer is missing: $virtioTools"
    }
    if (-not (Test-Path $cloudbaseMsi)) {
        throw "Cloudbase-Init MSI is missing: $cloudbaseMsi"
    }

    function Install-Msi {
        param(
            [Parameter(Mandatory = $true)][string]$Path,
            [Parameter(Mandatory = $true)][string]$LogPath,
            [string[]]$Properties = @()
        )

        $arguments = @(
            "/i", "`"$Path`"", "/qn", "/norestart",
            "/l*v", "`"$LogPath`""
        ) + $Properties
        $process = Start-Process msiexec.exe -Wait -NoNewWindow -PassThru -ArgumentList $arguments
        if ($process.ExitCode -notin @(0, 1641, 3010)) {
            throw "MSI installation failed with exit code $($process.ExitCode): $Path"
        }
    }

    $virtioProcess = Start-Process -FilePath $virtioTools -Wait -PassThru -ArgumentList @(
        "/quiet", "/norestart", "/log", "C:\Windows\Temp\virtio-install.log"
    )
    if ($virtioProcess.ExitCode -notin @(0, 1641, 3010)) {
        throw "VirtIO guest tools installation failed with exit code $($virtioProcess.ExitCode)"
    }
    Install-Msi -Path $cloudbaseMsi -LogPath "C:\Windows\Temp\cloudbase-init-install.log" -Properties @(
        "USERNAME=Admin",
        "USERGROUPS=Administrators",
        "INJECTMETADATAPASSWORD=TRUE",
        "RUN_SERVICE_AS_LOCAL_SYSTEM=1",
        "LOGGINGSERIALPORTNAME=COM1"
    )

    $cloudbaseRoot = "C:\Program Files\Cloudbase Solutions\Cloudbase-Init"
    $cloudbaseConf = Join-Path $cloudbaseRoot "conf\cloudbase-init.conf"
    $cloudbaseUnattendConf = Join-Path $cloudbaseRoot "conf\cloudbase-init-unattend.conf"
    $cloudbaseUnattendXml = Join-Path $cloudbaseRoot "conf\Unattend.xml"

    $settings = @{
        "username" = "Admin"
        "groups" = "Administrators"
        "inject_user_password" = "true"
        "first_logon_behaviour" = "no"
        "netbios_host_name_compatibility" = "false"
        "allow_reboot" = "false"
        "metadata_services" = "cloudbaseinit.metadata.services.configdrive.ConfigDriveService,cloudbaseinit.metadata.services.httpservice.HttpService"
    }

    foreach ($configPath in @($cloudbaseConf, $cloudbaseUnattendConf)) {
        if (-not (Test-Path $configPath)) {
            throw "Cloudbase-Init configuration is missing: $configPath"
        }
        $content = Get-Content -Path $configPath
        foreach ($key in $settings.Keys) {
            $content = $content | Where-Object { $_ -notmatch ("^\s*" + [regex]::Escape($key) + "\s*=") }
        }
        $content += ""
        foreach ($key in ($settings.Keys | Sort-Object)) {
            $content += "$key=$($settings[$key])"
        }
        Set-Content -Path $configPath -Value $content -Encoding ASCII
    }

    Set-Service -Name cloudbase-init -StartupType Automatic
    Stop-Service -Name cloudbase-init -Force -ErrorAction SilentlyContinue
    Set-Service -Name QEMU-GA -StartupType Automatic
    Start-Service -Name QEMU-GA

    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    powercfg.exe /hibernate off

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -Value "0" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue

    Remove-Item "C:\Windows\Panther\Unattend.xml" -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\Panther\Unattend\Unattend.xml" -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $cloudbaseUnattendXml)) {
        throw "Cloudbase-Init Sysprep answer file is missing: $cloudbaseUnattendXml"
    }

    Stop-Transcript
    $sysprep = "C:\Windows\System32\Sysprep\Sysprep.exe"
    & $sysprep "/generalize" "/oobe" "/shutdown" "/unattend:$cloudbaseUnattendXml"
    if ($LASTEXITCODE -ne 0) {
        throw "Sysprep failed with exit code $LASTEXITCODE"
    }
}
catch {
    $_ | Out-String | Add-Content -Path $logPath
    Stop-Transcript -ErrorAction SilentlyContinue
    throw
}
