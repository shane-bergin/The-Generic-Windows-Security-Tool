#requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$KillAnomalyProcesses,
    [switch]$SkipServiceDisable,
    [switch]$SkipFirewallLogging,
    [switch]$SkipAllowRuleDisable,
    [string]$OutputPath,
    [switch]$OpenReport
)

$ErrorActionPreference = 'Continue'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$backupRoot = Join-Path $programData "TGWST\backups\windows11-barebones-lockdown-$timestamp"
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param(
        [string]$Area,
        [string]$Target,
        [string]$Status,
        [string]$Detail
    )

    $results.Add([pscustomobject]@{
        Area = $Area
        Target = $Target
        Status = $Status
        Detail = $Detail
    })
}

function Save-Json {
    param($Value, [string]$Path, [int]$Depth = 6)

    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $Value | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Save-RollbackSnapshot {
    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null

    try {
        Save-Json -Path (Join-Path $backupRoot 'services.json') -Value @(
            Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
                Select-Object Name, DisplayName, State, StartMode, PathName, StartName
        ) -Depth 5
        Add-Result 'Backup' 'Services' 'Saved' (Join-Path $backupRoot 'services.json')
    } catch {
        Add-Result 'Backup' 'Services' 'Failed' $_.Exception.Message
    }

    try {
        Save-Json -Path (Join-Path $backupRoot 'firewall-profiles.json') -Value @(
            Get-NetFirewallProfile -ErrorAction SilentlyContinue |
                Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogFileName, LogMaxSizeKilobytes
        ) -Depth 5
        Add-Result 'Backup' 'FirewallProfiles' 'Saved' (Join-Path $backupRoot 'firewall-profiles.json')
    } catch {
        Add-Result 'Backup' 'FirewallProfiles' 'Failed' $_.Exception.Message
    }

    try {
        Save-Json -Path (Join-Path $backupRoot 'enabled-inbound-allow-rules.json') -Value @(
            Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue |
                Select-Object Name, DisplayName, DisplayGroup, Profile, Direction, Action, Enabled
        ) -Depth 5
        Add-Result 'Backup' 'InboundAllowRules' 'Saved' (Join-Path $backupRoot 'enabled-inbound-allow-rules.json')
    } catch {
        Add-Result 'Backup' 'InboundAllowRules' 'Failed' $_.Exception.Message
    }

    try {
        Save-Json -Path (Join-Path $backupRoot 'processes.json') -Value @(
            Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
                Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
        ) -Depth 5
        Add-Result 'Backup' 'Processes' 'Saved' (Join-Path $backupRoot 'processes.json')
    } catch {
        Add-Result 'Backup' 'Processes' 'Failed' $_.Exception.Message
    }
}

function Stop-AndDisable-ServiceIfPresent {
    param([string]$Name, [string]$Reason)

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        Add-Result 'Service' $Name 'Missing' $Reason
        return
    }

    if (-not $PSCmdlet.ShouldProcess($Name, 'Stop and disable Windows 11 barebones lockdown service')) {
        Add-Result 'Service' $Name 'Skipped' 'ShouldProcess declined'
        return
    }

    try {
        if ($service.Status -ne 'Stopped') {
            Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        }

        Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop
        Add-Result 'Service' $Name 'Disabled' $Reason
    } catch {
        Add-Result 'Service' $Name 'Failed' $_.Exception.Message
    }
}

function Ensure-InboundBlockRule {
    param(
        [string]$Name,
        [string]$Protocol,
        [string]$LocalPort,
        [string]$Description
    )

    $existing = Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue
    if ($existing) {
        try {
            if ($PSCmdlet.ShouldProcess($Name, 'Enable existing inbound lockdown block rule')) {
                Set-NetFirewallRule -DisplayName $Name -Enabled True -Direction Inbound -Action Block -Profile Any -ErrorAction Stop
            }

            Add-Result 'FirewallBlockRule' $Name 'Present' "$Protocol $LocalPort"
        } catch {
            Add-Result 'FirewallBlockRule' $Name 'Failed' $_.Exception.Message
        }

        return
    }

    try {
        if ($PSCmdlet.ShouldProcess($Name, 'Create inbound lockdown block rule')) {
            New-NetFirewallRule `
                -DisplayName $Name `
                -Direction Inbound `
                -Action Block `
                -Protocol $Protocol `
                -LocalPort $LocalPort `
                -Profile Any `
                -Description $Description `
                -ErrorAction Stop | Out-Null
        }

        Add-Result 'FirewallBlockRule' $Name 'Created' "$Protocol $LocalPort"
    } catch {
        Add-Result 'FirewallBlockRule' $Name 'Failed' $_.Exception.Message
    }
}

function Disable-NonCoreInboundAllowRules {
    $coreGroups = @('Core Networking')
    $rules = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue |
        Where-Object {
            $group = $_.DisplayGroup
            [string]::IsNullOrWhiteSpace($group) -or
            $coreGroups -notcontains $group
        }

    foreach ($rule in $rules) {
        try {
            if ($PSCmdlet.ShouldProcess($rule.DisplayName, 'Disable non-core inbound allow rule')) {
                Disable-NetFirewallRule -Name $rule.Name -ErrorAction Stop
            }

            $detail = if ([string]::IsNullOrWhiteSpace($rule.DisplayGroup)) { 'No display group' } else { $rule.DisplayGroup }
            Add-Result 'FirewallAllowRule' $rule.DisplayName 'Disabled' $detail
        } catch {
            Add-Result 'FirewallAllowRule' $rule.DisplayName 'Failed' $_.Exception.Message
        }
    }
}

function Test-PrivateOrLocalAddress {
    param([string]$Address)

    if ([string]::IsNullOrWhiteSpace($Address)) { return $true }
    if ($Address -in @('0.0.0.0', '::', '::1', '127.0.0.1', 'localhost')) { return $true }
    if ($Address -like '127.*' -or $Address -like '169.254.*' -or $Address -like '10.*' -or $Address -like '192.168.*') { return $true }
    if ($Address -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return $true }
    if ($Address -like 'fe80:*' -or $Address -like 'fc*' -or $Address -like 'fd*') { return $true }

    return $false
}

function Test-UserWritablePath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }

    $roots = @(
        [Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData),
        [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData),
        [System.IO.Path]::GetTempPath(),
        (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)) 'Downloads'),
        (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)) 'Desktop')
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    foreach ($root in $roots) {
        if ($Path.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Test-ProtectedProcess {
    param($ProcessRow)

    $name = ([string]$ProcessRow.Name).ToLowerInvariant()
    $path = [string]$ProcessRow.ExecutablePath
    $protectedNames = @(
        'idle', 'system', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
        'lsass.exe', 'svchost.exe', 'fontdrvhost.exe', 'dwm.exe', 'explorer.exe', 'winlogon.exe',
        'conhost.exe', 'sihost.exe', 'taskhostw.exe', 'wudfhost.exe', 'wmiprvse.exe',
        'msmpeng.exe', 'nissrv.exe', 'securityhealthservice.exe', 'securityhealthsystray.exe',
        'mpdefendercoreservice.exe', 'sense.exe', 'powershell.exe'
    )

    if ($protectedNames -contains $name) { return $true }
    if (-not [string]::IsNullOrWhiteSpace($path) -and $path.StartsWith($env:windir, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    return $false
}

function Get-AnomalyProcessCandidates {
    $highRiskListeningPorts = @(21, 22, 23, 25, 110, 135, 139, 143, 445, 993, 995, 2177, 3240, 3306, 3389, 3702, 5040, 5353, 5355, 5357, 5358, 5900, 5985, 5986, 6379, 9200, 27017)
    $suspiciousNames = @('cmd.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'curl.exe', 'wget.exe', 'python.exe', 'pythonw.exe', 'node.exe', 'java.exe')
    $suspiciousCommand = '(?i)(-enc|encodedcommand|frombase64string|downloadstring|invoke-webrequest|\biwr\b|https?://|-nop\b|-w\s+hidden|executionpolicy\s+bypass|appdata|\\temp\\|startup|schtasks|reg\s+add|rundll32\s+javascript|mshta)'

    $processRows = @{}
    foreach ($process in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) {
        $processRows[[int]$process.ProcessId] = $process
    }

    $externalPids = @{}
    foreach ($connection in Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue) {
        if (-not (Test-PrivateOrLocalAddress $connection.RemoteAddress)) {
            $externalPids[[int]$connection.OwningProcess] = "External TCP connection to $($connection.RemoteAddress):$($connection.RemotePort)"
        }
    }

    $listenerPids = @{}
    foreach ($listener in Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue) {
        if ($highRiskListeningPorts -contains [int]$listener.LocalPort) {
            $listenerPids[[int]$listener.OwningProcess] = "High-risk listener on TCP $($listener.LocalPort)"
        }
    }

    $candidates = [System.Collections.Generic.List[object]]::new()
    $currentProcessId = $PID
    foreach ($processId in ($processRows.Keys | Sort-Object -Unique)) {
        $process = $processRows[$processId]
        if ($processId -eq $currentProcessId -or (Test-ProtectedProcess $process)) {
            continue
        }

        $name = ([string]$process.Name).ToLowerInvariant()
        $path = [string]$process.ExecutablePath
        $commandLine = [string]$process.CommandLine
        $userWritable = Test-UserWritablePath $path
        $hasExternal = $externalPids.ContainsKey($processId)
        $hasListener = $listenerPids.ContainsKey($processId)
        $suspiciousName = $suspiciousNames -contains $name
        $suspiciousCommandLine = $commandLine -match $suspiciousCommand

        $reasons = @()
        if ($userWritable -and $hasExternal) { $reasons += "User-writable process path with $($externalPids[$processId])" }
        if ($userWritable -and $hasListener) { $reasons += "User-writable process path with $($listenerPids[$processId])" }
        if ($suspiciousName -and $suspiciousCommandLine) { $reasons += 'Suspicious command-line pattern in a common abuse-capable process' }
        if ($userWritable -and $suspiciousCommandLine) { $reasons += 'User-writable process path with suspicious command-line pattern' }

        if ($reasons.Count -gt 0) {
            $candidates.Add([pscustomobject]@{
                ProcessId = $processId
                Name = $process.Name
                ExecutablePath = $path
                CommandLine = $commandLine
                Reasons = $reasons
            })
        }
    }

    return $candidates
}

function Stop-AnomalyProcesses {
    $candidates = @(Get-AnomalyProcessCandidates)
    if ($candidates.Count -eq 0) {
        Add-Result 'Process' 'AnomalyCandidates' 'None' 'No user-space anomaly process candidates matched the lockdown criteria.'
        return @()
    }

    foreach ($candidate in $candidates) {
        try {
            if ($PSCmdlet.ShouldProcess("$($candidate.Name) pid=$($candidate.ProcessId)", 'Terminate anomaly process')) {
                Stop-Process -Id $candidate.ProcessId -Force -ErrorAction Stop
            }

            Add-Result 'Process' "$($candidate.Name) pid=$($candidate.ProcessId)" 'Killed' ($candidate.Reasons -join '; ')
        } catch {
            Add-Result 'Process' "$($candidate.Name) pid=$($candidate.ProcessId)" 'Failed' $_.Exception.Message
        }
    }

    return $candidates
}

Save-RollbackSnapshot

if ($PSCmdlet.ShouldProcess('Windows Defender Firewall', 'Enable profiles, block default inbound traffic, and allow outbound')) {
    try {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop
        Add-Result 'FirewallProfile' 'Domain,Private,Public' 'Hardened' 'Profiles enabled; default inbound blocked; outbound allowed.'
    } catch {
        Add-Result 'FirewallProfile' 'Domain,Private,Public' 'Failed' $_.Exception.Message
    }
}

if (-not $SkipFirewallLogging) {
    try {
        if ($PSCmdlet.ShouldProcess('Windows Defender Firewall logging', 'Enable allowed and blocked packet logging')) {
            Set-NetFirewallProfile `
                -Profile Domain,Private,Public `
                -LogAllowed True `
                -LogBlocked True `
                -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log' `
                -LogMaxSizeKilobytes 32768 `
                -ErrorAction Stop
        }

        Add-Result 'FirewallLogging' 'pfirewall.log' 'Enabled' 'Allowed and blocked packet logging enabled; max 32768KB.'
    } catch {
        Add-Result 'FirewallLogging' 'pfirewall.log' 'Failed' $_.Exception.Message
    }
}

if (-not $SkipAllowRuleDisable) {
    Disable-NonCoreInboundAllowRules
}

$blockRules = @(
    @{ Name = 'TGWST Lockdown Block TCP 21 FTP'; Protocol = 'TCP'; Port = '21'; Detail = 'FTP listener' },
    @{ Name = 'TGWST Lockdown Block TCP 22 SSH'; Protocol = 'TCP'; Port = '22'; Detail = 'SSH listener' },
    @{ Name = 'TGWST Lockdown Block TCP 23 Telnet'; Protocol = 'TCP'; Port = '23'; Detail = 'Telnet listener' },
    @{ Name = 'TGWST Lockdown Block TCP 25 SMTP'; Protocol = 'TCP'; Port = '25'; Detail = 'SMTP listener' },
    @{ Name = 'TGWST Lockdown Block TCP 110 POP3'; Protocol = 'TCP'; Port = '110'; Detail = 'POP3 listener' },
    @{ Name = 'TGWST Lockdown Block TCP 135 RPC'; Protocol = 'TCP'; Port = '135'; Detail = 'RPC endpoint mapper' },
    @{ Name = 'TGWST Lockdown Block TCP 139 NetBIOS'; Protocol = 'TCP'; Port = '139'; Detail = 'NetBIOS session service' },
    @{ Name = 'TGWST Lockdown Block TCP 143 IMAP'; Protocol = 'TCP'; Port = '143'; Detail = 'IMAP listener' },
    @{ Name = 'TGWST Lockdown Block TCP 445 SMB'; Protocol = 'TCP'; Port = '445'; Detail = 'SMB direct hosting' },
    @{ Name = 'TGWST Lockdown Block TCP 3389 RDP'; Protocol = 'TCP'; Port = '3389'; Detail = 'Remote Desktop' },
    @{ Name = 'TGWST Lockdown Block TCP 5357 WSDAPI'; Protocol = 'TCP'; Port = '5357'; Detail = 'Web Services on Devices' },
    @{ Name = 'TGWST Lockdown Block TCP 5358 WSDAPI'; Protocol = 'TCP'; Port = '5358'; Detail = 'Web Services on Devices' },
    @{ Name = 'TGWST Lockdown Block TCP 5985 WinRM'; Protocol = 'TCP'; Port = '5985'; Detail = 'WinRM HTTP' },
    @{ Name = 'TGWST Lockdown Block TCP 5986 WinRM'; Protocol = 'TCP'; Port = '5986'; Detail = 'WinRM HTTPS' },
    @{ Name = 'TGWST Lockdown Block TCP 5900 VNC'; Protocol = 'TCP'; Port = '5900'; Detail = 'VNC listener' },
    @{ Name = 'TGWST Lockdown Block TCP 3240 USBIPD'; Protocol = 'TCP'; Port = '3240'; Detail = 'USB-over-IP daemon' },
    @{ Name = 'TGWST Lockdown Block TCP 5040 CDPSvc'; Protocol = 'TCP'; Port = '5040'; Detail = 'Connected Devices Platform' },
    @{ Name = 'TGWST Lockdown Block UDP 137 NetBIOS'; Protocol = 'UDP'; Port = '137'; Detail = 'NetBIOS name service' },
    @{ Name = 'TGWST Lockdown Block UDP 138 NetBIOS'; Protocol = 'UDP'; Port = '138'; Detail = 'NetBIOS datagram service' },
    @{ Name = 'TGWST Lockdown Block UDP 500 IKE'; Protocol = 'UDP'; Port = '500'; Detail = 'IKE/IPsec negotiation' },
    @{ Name = 'TGWST Lockdown Block UDP 4500 IPsec NAT-T'; Protocol = 'UDP'; Port = '4500'; Detail = 'IPsec NAT traversal' },
    @{ Name = 'TGWST Lockdown Block UDP 1900 SSDP'; Protocol = 'UDP'; Port = '1900'; Detail = 'SSDP discovery' },
    @{ Name = 'TGWST Lockdown Block UDP 2177 qWave'; Protocol = 'UDP'; Port = '2177'; Detail = 'qWave/cast quality signaling' },
    @{ Name = 'TGWST Lockdown Block UDP 3702 WSD'; Protocol = 'UDP'; Port = '3702'; Detail = 'Web Services Discovery' },
    @{ Name = 'TGWST Lockdown Block UDP 5050 CDPSvc'; Protocol = 'UDP'; Port = '5050'; Detail = 'Connected Devices Platform' },
    @{ Name = 'TGWST Lockdown Block UDP 5353 mDNS'; Protocol = 'UDP'; Port = '5353'; Detail = 'Multicast DNS' },
    @{ Name = 'TGWST Lockdown Block UDP 5355 LLMNR'; Protocol = 'UDP'; Port = '5355'; Detail = 'Link-local multicast name resolution' }
)

foreach ($rule in $blockRules) {
    Ensure-InboundBlockRule -Name $rule.Name -Protocol $rule.Protocol -LocalPort $rule.Port -Description "TGWST Windows 11 Barebones Lockdown: $($rule.Detail)"
}

if (-not $SkipServiceDisable) {
    $lockdownServices = @(
        @{ Name = 'LanmanServer'; Reason = 'SMB/file and printer sharing listener surface' },
        @{ Name = 'RemoteRegistry'; Reason = 'Remote registry management surface' },
        @{ Name = 'TermService'; Reason = 'Remote Desktop listener surface' },
        @{ Name = 'SessionEnv'; Reason = 'Remote Desktop configuration helper surface' },
        @{ Name = 'UmRdpService'; Reason = 'Remote Desktop user-mode port redirector surface' },
        @{ Name = 'WinRM'; Reason = 'Windows Remote Management listener surface' },
        @{ Name = 'SSDPSRV'; Reason = 'SSDP discovery listener surface' },
        @{ Name = 'upnphost'; Reason = 'UPnP device host listener surface' },
        @{ Name = 'fdPHost'; Reason = 'Function Discovery provider host listener surface' },
        @{ Name = 'FDResPub'; Reason = 'Function Discovery resource publication surface' },
        @{ Name = 'QWAVE'; Reason = 'qWave/cast quality listener surface' },
        @{ Name = 'CDPSvc'; Reason = 'Connected Devices Platform listener surface' },
        @{ Name = 'IKEEXT'; Reason = 'IKE/IPsec keying listener surface' },
        @{ Name = 'usbipd'; Reason = 'USB-over-IP listener surface' },
        @{ Name = 'Spooler'; Reason = 'Print Spooler remote attack surface; disables printing until restored' },
        @{ Name = 'WMPNetworkSvc'; Reason = 'Windows Media Player network sharing surface' },
        @{ Name = 'SharedAccess'; Reason = 'Internet Connection Sharing and hotspot sharing surface' },
        @{ Name = 'MapsBroker'; Reason = 'Downloaded maps broker not needed in lockdown' },
        @{ Name = 'lfsvc'; Reason = 'Geolocation service not needed in lockdown' },
        @{ Name = 'XblAuthManager'; Reason = 'Xbox Live auth service not needed in lockdown' },
        @{ Name = 'XblGameSave'; Reason = 'Xbox Live game save service not needed in lockdown' },
        @{ Name = 'XboxGipSvc'; Reason = 'Xbox accessory service not needed in lockdown' },
        @{ Name = 'XboxNetApiSvc'; Reason = 'Xbox networking service not needed in lockdown' },
        @{ Name = 'DiagTrack'; Reason = 'Connected user experiences telemetry not needed in lockdown' },
        @{ Name = 'dmwappushservice'; Reason = 'WAP push message routing telemetry not needed in lockdown' },
        @{ Name = 'WerSvc'; Reason = 'Windows Error Reporting not needed in lockdown' },
        @{ Name = 'PcaSvc'; Reason = 'Program Compatibility Assistant not needed in lockdown' },
        @{ Name = 'TrkWks'; Reason = 'Distributed Link Tracking Client not needed in lockdown' }
    )

    foreach ($entry in $lockdownServices) {
        Stop-AndDisable-ServiceIfPresent -Name $entry.Name -Reason $entry.Reason
    }
}

$killedCandidates = @()
if ($KillAnomalyProcesses) {
    $killedCandidates = @(Stop-AnomalyProcesses)
} else {
    Add-Result 'Process' 'AnomalyProcessKill' 'Skipped' 'Rerun with -KillAnomalyProcesses to terminate user-space anomaly candidates.'
}

$result = [pscustomobject]@{
    AppliedAt = (Get-Date).ToString('s')
    Summary = 'Windows 11 Barebones Lockdown requested'
    BackupRoot = $backupRoot
    OutputPath = $OutputPath
    KillAnomalyProcesses = [bool]$KillAnomalyProcesses
    RebootRecommended = $true
    KilledAnomalyCandidates = $killedCandidates
    Notes = @(
        'This is an emergency lockdown profile. It will disrupt SMB/file sharing, Remote Desktop, WinRM, discovery, casting, printing, device pairing, Xbox services, telemetry, VPN/IPsec, USB-over-IP, and similar convenience workflows.',
        'The process kill step intentionally avoids core Windows, Defender, Update, and Windows-directory processes. It targets user-space anomaly candidates with user-writable paths, high-risk listeners, external connections, or suspicious command-line patterns.',
        'Rollback snapshots are saved under BackupRoot, but automatic restore is not yet implemented.'
    )
    Results = $results
}

$json = $result | ConvertTo-Json -Depth 8

if ($OutputPath) {
    $parent = Split-Path -Parent $OutputPath
    if ($parent) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    Set-Content -LiteralPath $OutputPath -Value $json -Encoding UTF8
    if ($OpenReport) {
        Start-Process notepad.exe -ArgumentList $OutputPath
    }
}

$json
