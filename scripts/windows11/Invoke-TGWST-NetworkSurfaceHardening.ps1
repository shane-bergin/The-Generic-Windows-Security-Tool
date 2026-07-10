#requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$SkipServiceDisable,
    [switch]$SkipDiscoveryRuleDisable,
    [switch]$SkipNetBiosDisable,
    [switch]$SkipFirewallLogging,
    [int]$FirewallLogSizeKilobytes = 16384
)

$ErrorActionPreference = 'Stop'

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

function Stop-AndDisable-ServiceIfPresent {
    param(
        [string]$Name,
        [string]$Reason
    )

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        Add-Result 'Service' $Name 'Missing' $Reason
        return
    }

    if (-not $PSCmdlet.ShouldProcess($Name, 'Stop and disable Windows service')) {
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
        if ($PSCmdlet.ShouldProcess($Name, 'Enable existing inbound block rule')) {
            Set-NetFirewallRule -DisplayName $Name -Enabled True -Direction Inbound -Action Block -Profile Any -ErrorAction Stop
        }

        Add-Result 'FirewallRule' $Name 'Present' "$Protocol $LocalPort"
        return
    }

    if (-not $PSCmdlet.ShouldProcess($Name, 'Create inbound firewall block rule')) {
        Add-Result 'FirewallRule' $Name 'Skipped' "$Protocol $LocalPort"
        return
    }

    New-NetFirewallRule `
        -DisplayName $Name `
        -Direction Inbound `
        -Action Block `
        -Protocol $Protocol `
        -LocalPort $LocalPort `
        -Profile Any `
        -Description $Description `
        -ErrorAction Stop | Out-Null

    Add-Result 'FirewallRule' $Name 'Created' "$Protocol $LocalPort"
}

if ($PSCmdlet.ShouldProcess('Windows Defender Firewall', 'Enable profiles and block default inbound traffic')) {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
    Add-Result 'FirewallProfile' 'Domain,Private,Public' 'Hardened' 'Profiles enabled; default inbound blocked; outbound allowed'
}

if (-not $SkipFirewallLogging) {
    if ($PSCmdlet.ShouldProcess('Windows Defender Firewall logging', 'Enable allowed and blocked packet logging')) {
        Set-NetFirewallProfile `
            -Profile Domain,Private,Public `
            -LogAllowed True `
            -LogBlocked True `
            -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log' `
            -LogMaxSizeKilobytes $FirewallLogSizeKilobytes
        Add-Result 'FirewallLogging' 'pfirewall.log' 'Enabled' "Allowed and blocked packet logging enabled; max ${FirewallLogSizeKilobytes}KB"
    }
}

if (-not $SkipServiceDisable) {
    $surfaceServices = @(
        @{ Name = 'usbipd'; Reason = 'USB-over-IP listener surface, commonly TCP 3240' },
        @{ Name = 'LanmanServer'; Reason = 'SMB/NetBIOS file and printer sharing listener surface' },
        @{ Name = 'SSDPSRV'; Reason = 'SSDP discovery listener surface, commonly UDP 1900' },
        @{ Name = 'upnphost'; Reason = 'UPnP device host listener surface' },
        @{ Name = 'fdPHost'; Reason = 'Function Discovery provider host listener surface' },
        @{ Name = 'FDResPub'; Reason = 'Function Discovery resource publication surface' },
        @{ Name = 'QWAVE'; Reason = 'qWave/cast quality listener surface, commonly TCP/UDP 2177' },
        @{ Name = 'CDPSvc'; Reason = 'Connected Devices Platform listener surface, commonly TCP 5040/UDP 5050' },
        @{ Name = 'IKEEXT'; Reason = 'IKE/IPsec keying listener surface, commonly UDP 500/4500' }
    )

    foreach ($entry in $surfaceServices) {
        Stop-AndDisable-ServiceIfPresent -Name $entry.Name -Reason $entry.Reason
    }
}

$blockRules = @(
    @{ Name = 'TGWST Block TCP 139 NetBIOS'; Protocol = 'TCP'; Port = '139'; Detail = 'NetBIOS session service' },
    @{ Name = 'TGWST Block TCP 445 SMB'; Protocol = 'TCP'; Port = '445'; Detail = 'SMB direct hosting' },
    @{ Name = 'TGWST Block TCP 3240 USBIPD'; Protocol = 'TCP'; Port = '3240'; Detail = 'USB-over-IP daemon' },
    @{ Name = 'TGWST Block TCP 5040 CDPSvc'; Protocol = 'TCP'; Port = '5040'; Detail = 'Connected Devices Platform' },
    @{ Name = 'TGWST Block UDP 137 NetBIOS'; Protocol = 'UDP'; Port = '137'; Detail = 'NetBIOS name service' },
    @{ Name = 'TGWST Block UDP 138 NetBIOS'; Protocol = 'UDP'; Port = '138'; Detail = 'NetBIOS datagram service' },
    @{ Name = 'TGWST Block UDP 5353 mDNS'; Protocol = 'UDP'; Port = '5353'; Detail = 'Multicast DNS' },
    @{ Name = 'TGWST Block UDP 5355 LLMNR'; Protocol = 'UDP'; Port = '5355'; Detail = 'Link-local multicast name resolution' },
    @{ Name = 'TGWST Block UDP 500 IKE'; Protocol = 'UDP'; Port = '500'; Detail = 'IKE/IPsec negotiation' },
    @{ Name = 'TGWST Block UDP 4500 IPsec NAT-T'; Protocol = 'UDP'; Port = '4500'; Detail = 'IPsec NAT traversal' },
    @{ Name = 'TGWST Block UDP 1900 SSDP'; Protocol = 'UDP'; Port = '1900'; Detail = 'SSDP discovery' },
    @{ Name = 'TGWST Block TCP 2177 qWave'; Protocol = 'TCP'; Port = '2177'; Detail = 'qWave/cast quality signaling' },
    @{ Name = 'TGWST Block UDP 2177 qWave'; Protocol = 'UDP'; Port = '2177'; Detail = 'qWave/cast quality signaling' },
    @{ Name = 'TGWST Block UDP 3702 WSD'; Protocol = 'UDP'; Port = '3702'; Detail = 'Web Services Discovery' },
    @{ Name = 'TGWST Block UDP 5050 CDPSvc'; Protocol = 'UDP'; Port = '5050'; Detail = 'Connected Devices Platform' }
)

foreach ($rule in $blockRules) {
    Ensure-InboundBlockRule -Name $rule.Name -Protocol $rule.Protocol -LocalPort $rule.Port -Description "TGWST network surface hardening: $($rule.Detail)"
}

if (-not $SkipDiscoveryRuleDisable) {
    $groupsToDisable = @(
        'Network Discovery',
        'Cast to Device functionality',
        'Connected Devices Platform',
        'Remote Assistance',
        'Wi-Fi Direct Network Discovery',
        'mDNS'
    )

    $rules = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue |
        Where-Object {
            $groupsToDisable -contains $_.DisplayGroup -or
            $_.DisplayName -match 'mDNS'
        }

    foreach ($rule in $rules) {
        if ($PSCmdlet.ShouldProcess($rule.DisplayName, 'Disable broad or stale inbound allow rule')) {
            Disable-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
            $detail = if ([string]::IsNullOrWhiteSpace($rule.DisplayGroup)) { 'stale browser mDNS rule' } else { $rule.DisplayGroup }
            Add-Result 'FirewallAllowRule' $rule.DisplayName 'Disabled' $detail
        }
    }
}

if ($PSCmdlet.ShouldProcess('LLMNR policy', 'Disable multicast name resolution')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null
    New-ItemProperty `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
        -Name 'EnableMulticast' `
        -Value 0 `
        -PropertyType DWord `
        -Force | Out-Null
    Add-Result 'Policy' 'LLMNR' 'Disabled' 'HKLM policy EnableMulticast=0'
}

if (-not $SkipNetBiosDisable) {
    $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue
    foreach ($adapter in $adapters) {
        if ($PSCmdlet.ShouldProcess($adapter.Description, 'Disable NetBIOS over TCP/IP')) {
            try {
                $result = Invoke-CimMethod -InputObject $adapter -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = 2 } -ErrorAction Stop
                Add-Result 'NetBIOS' $adapter.Description 'RequestedDisabled' "ReturnValue=$($result.ReturnValue)"
            } catch {
                Add-Result 'NetBIOS' $adapter.Description 'Failed' $_.Exception.Message
            }
        }
    }
}

[pscustomobject]@{
    AppliedAt = (Get-Date).ToString('s')
    Summary = 'Network surface hardening requested'
    RebootRecommended = $true
    Notes = @(
        'May disrupt SMB/file sharing, network discovery, casting, Remote Assistance, VPN/IPsec, USB-over-IP, and some device pairing flows.',
        'A reboot is recommended so disabled services and adapter-level NetBIOS changes settle fully.'
    )
    Results = $results
} | ConvertTo-Json -Depth 6
