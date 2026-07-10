[CmdletBinding()]
param(
    [int]$Days = 7,
    [int]$MaxSecurityEvents = 5000,
    [string]$OutputPath,
    [switch]$OpenReport
)

$ErrorActionPreference = 'Continue'
$start = (Get-Date).AddDays(-1 * [Math]::Max(1, $Days))
$watchedPorts = @(139,445,137,138,5353,5355,500,4500,3240,1900,2177,3702,5040,5050)

function Get-EventDataMap {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)

    $map = @{}
    try {
        [xml]$xml = $Event.ToXml()
        foreach ($data in $xml.Event.EventData.Data) {
            if ($data.Name) {
                $map[$data.Name] = [string]$data.'#text'
            }
        }
    } catch {
    }

    return $map
}

function Test-PrivateOrLocalIp {
    param([string]$Ip)

    if ([string]::IsNullOrWhiteSpace($Ip)) { return $true }
    if ($Ip -in @('-', '::', '::1', '0.0.0.0', '127.0.0.1')) { return $true }
    if ($Ip.StartsWith('10.') -or $Ip.StartsWith('192.168.') -or $Ip.StartsWith('169.254.')) { return $true }
    if ($Ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return $true }
    if ($Ip -match '^(fe80:|fd|fc|ff02:|ff05:|ff0e:)') { return $true }
    if ($Ip -match '^(224\.|239\.)') { return $true }
    return $false
}

function New-ErrorObject {
    param([string]$Area, [string]$Message)

    [pscustomobject]@{
        Area = $Area
        Error = $Message
    }
}

$firewallProfiles = @()
try {
    $firewallProfiles = Get-NetFirewallProfile -ErrorAction Stop |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogFileName, LogMaxSizeKilobytes
} catch {
    $firewallProfiles = @(New-ErrorObject 'FirewallProfiles' $_.Exception.Message)
}

$logFileStatus = [pscustomobject]@{
    Path = Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\pfirewall.log'
    Exists = $false
    LengthBytes = 0
    LastWriteTime = $null
}

try {
    $file = Get-Item -LiteralPath $logFileStatus.Path -ErrorAction SilentlyContinue
    if ($file) {
        $logFileStatus.Exists = $true
        $logFileStatus.LengthBytes = $file.Length
        $logFileStatus.LastWriteTime = $file.LastWriteTime
    }
} catch {
}

$wfpRows = @()
try {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5152,5156,5157,5158; StartTime = $start } -MaxEvents $MaxSecurityEvents -ErrorAction Stop
    foreach ($event in $events) {
        $map = Get-EventDataMap $event
        $destinationPort = $map['DestPort']
        if (-not $destinationPort) {
            $destinationPort = $map['DestinationPort']
        }

        if ($destinationPort -and ($watchedPorts -contains [int]$destinationPort)) {
            $source = $map['SourceAddress']
            $wfpRows += [pscustomobject]@{
                Time = $event.TimeCreated
                EventId = $event.Id
                Port = [int]$destinationPort
                Source = $source
                Destination = $map['DestAddress']
                Protocol = $map['Protocol']
                Application = $map['Application']
                Scope = $(if (Test-PrivateOrLocalIp $source) { 'local_private_or_multicast' } else { 'public' })
            }
        }
    }
} catch {
    $wfpRows = @(New-ErrorObject 'SecurityWfp' $_.Exception.Message)
}

$networkLogons = @()
try {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624,4625; StartTime = $start } -MaxEvents $MaxSecurityEvents -ErrorAction Stop
    foreach ($event in $events) {
        $map = Get-EventDataMap $event
        $logonType = $map['LogonType']
        $ip = $map['IpAddress']
        if ($logonType -in @('3', '10')) {
            $networkLogons += [pscustomobject]@{
                Time = $event.TimeCreated
                EventId = $event.Id
                LogonType = $logonType
                User = $map['TargetUserName']
                IpAddress = $ip
                Workstation = $map['WorkstationName']
                AuthPackage = $map['AuthenticationPackageName']
                Status = $map['Status']
                Scope = $(if (Test-PrivateOrLocalIp $ip) { 'local_private' } else { 'public' })
            }
        }
    }
} catch {
    $networkLogons = @(New-ErrorObject 'NetworkLogons' $_.Exception.Message)
}

$fileShareRows = @()
try {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5140,5145; StartTime = $start } -MaxEvents $MaxSecurityEvents -ErrorAction Stop
    foreach ($event in $events) {
        $map = Get-EventDataMap $event
        $ip = $map['IpAddress']
        $fileShareRows += [pscustomobject]@{
            Time = $event.TimeCreated
            EventId = $event.Id
            User = $map['SubjectUserName']
            IpAddress = $ip
            ShareName = $map['ShareName']
            Target = $map['RelativeTargetName']
            Scope = $(if (Test-PrivateOrLocalIp $ip) { 'local_private' } else { 'public' })
        }
    }
} catch {
    $fileShareRows = @(New-ErrorObject 'FileShareAudit' $_.Exception.Message)
}

$smbPublicRows = @()
foreach ($log in @('Microsoft-Windows-SMBServer/Operational', 'Microsoft-Windows-SMBServer/Connectivity', 'Microsoft-Windows-SMBServer/Security', 'Microsoft-Windows-SMBServer/Audit')) {
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $start } -MaxEvents $MaxSecurityEvents -ErrorAction Stop
        foreach ($event in $events) {
            $message = $event.Message
            $ips = [regex]::Matches($message, '(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)') |
                ForEach-Object { $_.Value } |
                Select-Object -Unique

            foreach ($ip in $ips) {
                if (-not (Test-PrivateOrLocalIp $ip)) {
                    $flat = $message -replace '\s+', ' '
                    $smbPublicRows += [pscustomobject]@{
                        Time = $event.TimeCreated
                        Log = $log
                        EventId = $event.Id
                        IpAddress = $ip
                        Message = $flat.Substring(0, [Math]::Min(300, $flat.Length))
                    }
                }
            }
        }
    } catch {
    }
}

$enabledInboundAllows = @()
try {
    $enabledInboundAllows = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop |
        Where-Object {
            $_.DisplayName -match 'mDNS|LLMNR|Network Discovery|qWave|SMB|NetBIOS|SSDP|WSD|usbip|IKE|IPsec|Connected Devices|Cast|Teams|Steam|Remote Assistance|Edge' -or
            $_.DisplayGroup -match 'Network Discovery|Cast|Connected Devices|Remote Assistance|Microsoft Edge|Teams|Steam'
        } |
        Select-Object DisplayName, DisplayGroup, Profile, EdgeTraversalPolicy
} catch {
    $enabledInboundAllows = @(New-ErrorObject 'InboundAllowRules' $_.Exception.Message)
}

$result = [pscustomobject]@{
    CollectedAt = (Get-Date).ToString('s')
    Days = $Days
    WatchedPorts = $watchedPorts
    FirewallProfiles = $firewallProfiles
    FirewallLogFile = $logFileStatus
    WfpWatchedPortCounts = @($wfpRows | Group-Object EventId,Port,Scope | Sort-Object Count -Descending | Select-Object Count,Name)
    WfpPublicWatchedPortEvents = @($wfpRows | Where-Object Scope -eq 'public' | Sort-Object Time -Descending | Select-Object -First 80)
    WfpTopLocalWatchedPortTalkers = @($wfpRows | Where-Object Scope -eq 'local_private_or_multicast' | Group-Object EventId,Port,Source,Destination,Application | Sort-Object Count -Descending | Select-Object -First 40 Count,Name)
    PublicNetworkLogons = @($networkLogons | Where-Object Scope -eq 'public' | Sort-Object Time -Descending | Select-Object -First 80)
    PrivateNetworkLogonSummary = @($networkLogons | Where-Object Scope -eq 'local_private' | Group-Object EventId,LogonType,User,IpAddress,Workstation,AuthPackage | Sort-Object Count -Descending | Select-Object -First 40 Count,Name)
    FileShareSummary = @($fileShareRows | Group-Object EventId,Scope,IpAddress,ShareName | Sort-Object Count -Descending | Select-Object -First 40 Count,Name)
    PublicFileShareEvents = @($fileShareRows | Where-Object Scope -eq 'public' | Sort-Object Time -Descending | Select-Object -First 80)
    SmbPublicIpEvents = @($smbPublicRows | Sort-Object Time -Descending | Select-Object -First 80)
    EnabledInboundAllowRulesOfInterest = $enabledInboundAllows
    Notes = @(
        'Security WFP events depend on local audit policy. Windows Firewall packet logs only exist after profile logging is enabled.',
        'Public hits are the strongest remote-access signal here. Local/private/multicast hits are commonly LAN discovery chatter, but should still be reviewed if unexpected.'
    )
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
