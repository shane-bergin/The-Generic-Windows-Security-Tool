#requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$SkipQuickScan,
    [switch]$SkipWindowsUpdateScan,
    [switch]$SkipFirewallBaseline
)

$ErrorActionPreference = 'Continue'
$results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param([string]$Area, [string]$Status, [string]$Detail)

    $results.Add([pscustomobject]@{
        Area = $Area
        Status = $Status
        Detail = $Detail
    })
}

function Get-WinReInfo {
    $stdout = [System.IO.Path]::GetTempFileName()
    $stderr = [System.IO.Path]::GetTempFileName()

    try {
        $reagent = Join-Path $env:SystemRoot 'System32\reagentc.exe'
        $process = Start-Process -FilePath $reagent -ArgumentList '/info' -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr -ErrorAction Stop
        $output = @()
        if (Test-Path -LiteralPath $stdout) {
            $output += Get-Content -LiteralPath $stdout -ErrorAction SilentlyContinue
        }

        if ($process.ExitCode -ne 0 -and (Test-Path -LiteralPath $stderr)) {
            $output += Get-Content -LiteralPath $stderr -ErrorAction SilentlyContinue
        }

        return ($output -join [Environment]::NewLine).Trim()
    } catch {
        return ''
    } finally {
        Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
}

function Test-VersionAtLeast {
    param(
        [string]$Current,
        [string]$Minimum
    )

    try {
        if ([string]::IsNullOrWhiteSpace($Current)) { return $false }
        return ([version]$Current -ge [version]$Minimum)
    } catch {
        return $false
    }
}

function Start-DefenderService {
    foreach ($serviceName in @('WinDefend', 'WdNisSvc')) {
        try {
            Start-Service -Name $serviceName -ErrorAction Stop
            Add-Result 'DefenderService' 'Requested' "$serviceName start requested."
        } catch {
            Add-Result 'DefenderService' 'Warning' "${serviceName}: $($_.Exception.Message)"
        }
    }
}

function Set-DefenderPreferenceSafe {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowNull()][object]$Value
    )

    try {
        $parameters = @{ ErrorAction = 'Stop' }
        $parameters[$Name] = $Value
        Set-MpPreference @parameters
        Add-Result 'DefenderPreferences' 'Requested' "$Name=$Value"
        return $true
    } catch {
        Add-Result 'DefenderPreferences' 'Failed' "${Name}: $($_.Exception.Message)"
        return $false
    }
}

function Update-DefenderSignatureSafe {
    try {
        Update-MpSignature -ErrorAction Stop
        Add-Result 'DefenderSignatures' 'Requested' 'Update-MpSignature completed.'
        return
    } catch {
        Add-Result 'DefenderSignatures' 'Failed' "Update-MpSignature failed: $($_.Exception.Message)"
    }

    $candidates = New-Object System.Collections.Generic.List[string]
    $legacyPath = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
    if (Test-Path -LiteralPath $legacyPath) { $candidates.Add($legacyPath) }

    $platformRoot = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
    if (Test-Path -LiteralPath $platformRoot) {
        Get-ChildItem -LiteralPath $platformRoot -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending |
            ForEach-Object {
                $candidate = Join-Path $_.FullName 'MpCmdRun.exe'
                if (Test-Path -LiteralPath $candidate) { $candidates.Add($candidate) }
            }
    }

    foreach ($candidate in $candidates | Select-Object -Unique) {
        try {
            $process = Start-Process -FilePath $candidate -ArgumentList '-SignatureUpdate' -NoNewWindow -Wait -PassThru -ErrorAction Stop
            if ($process.ExitCode -eq 0) {
                Add-Result 'DefenderSignatures' 'Requested' "MpCmdRun signature update completed via $candidate."
                return
            }

            Add-Result 'DefenderSignatures' 'Failed' "MpCmdRun returned exit code $($process.ExitCode) via $candidate."
        } catch {
            Add-Result 'DefenderSignatures' 'Failed' "MpCmdRun failed via ${candidate}: $($_.Exception.Message)"
        }
    }
}

function Get-DefenderVerification {
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $preference = Get-MpPreference -ErrorAction SilentlyContinue
        $asrActions = @($preference.AttackSurfaceReductionRules_Actions)
        $asrBlockCount = @($asrActions | Where-Object { $_ -eq 1 -or $_ -eq 'Enabled' -or $_ -eq 'Block' -or $_ -eq 'BlockMode' }).Count

        return [pscustomobject]@{
            AntivirusEnabled = [bool]$status.AntivirusEnabled
            RealTimeProtectionEnabled = [bool]$status.RealTimeProtectionEnabled
            IoavProtectionEnabled = [bool]$status.IoavProtectionEnabled
            NISEnabled = [bool]$status.NISEnabled
            IsTamperProtected = $status.IsTamperProtected
            AMProductVersion = $status.AMProductVersion
            AMEngineVersion = $status.AMEngineVersion
            PlatformMeetsJune2026Baseline = (Test-VersionAtLeast $status.AMProductVersion '4.18.26050.15')
            EngineMeetsJune2026Baseline = (Test-VersionAtLeast $status.AMEngineVersion '1.1.26050.11')
            AsrBlockRuleCount = $asrBlockCount
            SignatureVersion = $status.AntivirusSignatureVersion
            QuickScanAge = $status.QuickScanAge
            FullScanAge = $status.FullScanAge
        }
    } catch {
        Add-Result 'DefenderVerification' 'Failed' $_.Exception.Message
        return $null
    }
}

Start-DefenderService

if ($PSCmdlet.ShouldProcess('Microsoft Defender signatures', 'Update malware intelligence')) {
    Update-DefenderSignatureSafe
}

if ($PSCmdlet.ShouldProcess('Microsoft Defender preferences', 'Enable core realtime, cloud, and scan protections')) {
    $requestedPreferenceCount = 0
    $requestedPreferences = @(
        @{ Name = 'DisableRealtimeMonitoring'; Value = $false },
        @{ Name = 'DisableIOAVProtection'; Value = $false },
        @{ Name = 'DisableBehaviorMonitoring'; Value = $false },
        @{ Name = 'DisableArchiveScanning'; Value = $false },
        @{ Name = 'DisableScriptScanning'; Value = $false },
        @{ Name = 'DisableEmailScanning'; Value = $false },
        @{ Name = 'DisableRemovableDriveScanning'; Value = $false },
        @{ Name = 'DisableScanningMappedNetworkDrivesForFullScan'; Value = $false },
        @{ Name = 'DisableScanningNetworkFiles'; Value = $false },
        @{ Name = 'DisableBlockAtFirstSeen'; Value = $false },
        @{ Name = 'CheckForSignaturesBeforeRunningScan'; Value = $true },
        @{ Name = 'MAPSReporting'; Value = 'Advanced' },
        @{ Name = 'SubmitSamplesConsent'; Value = 'SendSafeSamples' },
        @{ Name = 'PUAProtection'; Value = 'Enabled' },
        @{ Name = 'CloudBlockLevel'; Value = 'High' },
        @{ Name = 'CloudExtendedTimeout'; Value = 50 }
    )

    foreach ($preference in $requestedPreferences) {
        if (Set-DefenderPreferenceSafe -Name $preference.Name -Value $preference.Value) {
            $requestedPreferenceCount++
        }
    }

    Add-Result 'DefenderPreferences' 'Hardened' "$requestedPreferenceCount Defender preference(s) accepted. Verification follows; policy or Tamper Protection can still keep effective state disabled."
}

$asrRuleIds = @(
    '01443614-cd74-433a-b99e-2ecdc07bfc25',
    '26190899-1602-49e8-8b27-eb1d0a1ce869',
    '33ddedf1-c6e0-47cb-833e-de6133960387',
    '3b576869-a4ec-4529-8536-b80a7769e899',
    '56a863a9-875e-4185-98a7-b882c64b5ce5',
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc',
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84',
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c',
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b',
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2',
    'a8f5898e-1dc8-49a9-9878-85004b8a61e6',
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4',
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550',
    'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb',
    'c1db55ab-c21a-4637-bb3f-a12568109d35',
    'd1e49aac-8f56-4280-b9ba-993a6d77406c',
    'd3e037e1-3eb8-44c8-a917-57927947596d',
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a',
    'e6db77e5-3df2-4cf1-b95a-636979351e5b'
)

if ($PSCmdlet.ShouldProcess('Microsoft Defender ASR', 'Enable common workstation ASR block rules')) {
    $enabled = 0
    foreach ($ruleId in $asrRuleIds) {
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
            $enabled++
        } catch {
        }
    }

    Add-Result 'DefenderASR' 'Requested' "$enabled ASR block rule(s) requested."
}

$defenderVerification = Get-DefenderVerification
if ($defenderVerification) {
    if ($defenderVerification.AntivirusEnabled -and $defenderVerification.RealTimeProtectionEnabled -and $defenderVerification.IoavProtectionEnabled -and $defenderVerification.PlatformMeetsJune2026Baseline -and $defenderVerification.EngineMeetsJune2026Baseline) {
        Add-Result 'DefenderVerification' 'Verified' "Defender effective state is enabled and platform/engine meet June 2026 baseline ($($defenderVerification.AMProductVersion)/$($defenderVerification.AMEngineVersion))."
    } else {
        Add-Result 'DefenderVerification' 'Attention' "Effective state requires review: AV=$($defenderVerification.AntivirusEnabled), realtime=$($defenderVerification.RealTimeProtectionEnabled), IOAV=$($defenderVerification.IoavProtectionEnabled), platform=$($defenderVerification.AMProductVersion), engine=$($defenderVerification.AMEngineVersion), tamper=$($defenderVerification.IsTamperProtected)."
    }

    if (-not $defenderVerification.PlatformMeetsJune2026Baseline) {
        Add-Result 'DefenderPlatform' 'UpdateRequired' "Defender platform $($defenderVerification.AMProductVersion) is below 4.18.26050.15. Platform updates are serviced by Windows Update / Defender platform update, not by direct local policy alone."
    }

    if (-not $defenderVerification.EngineMeetsJune2026Baseline) {
        Add-Result 'DefenderEngine' 'UpdateRequired' "Defender engine $($defenderVerification.AMEngineVersion) is below 1.1.26050.11. Run malware intelligence update and Windows Update."
    }
}

if (-not $SkipFirewallBaseline) {
    if ($PSCmdlet.ShouldProcess('Windows Defender Firewall', 'Enable profiles and block default inbound traffic')) {
        try {
            Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop
            Add-Result 'Firewall' 'Hardened' 'Profiles enabled; default inbound blocked; outbound allowed.'
        } catch {
            Add-Result 'Firewall' 'Failed' $_.Exception.Message
        }
    }
}

$updateServices = @('wuauserv', 'bits', 'UsoSvc')
foreach ($serviceName in $updateServices) {
    if ($PSCmdlet.ShouldProcess($serviceName, 'Ensure Windows Update service can run')) {
        try {
            Set-Service -Name $serviceName -StartupType Manual -ErrorAction SilentlyContinue
            Start-Service -Name $serviceName -ErrorAction SilentlyContinue
            Add-Result 'WindowsUpdateService' 'Requested' "$serviceName is startable."
        } catch {
            Add-Result 'WindowsUpdateService' 'Failed' "${serviceName}: $($_.Exception.Message)"
        }
    }
}

if (-not $SkipWindowsUpdateScan) {
    if ($PSCmdlet.ShouldProcess('Windows Update', 'Start update scan')) {
        try {
            Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\UsoClient.exe') -ArgumentList 'StartScan' -WindowStyle Hidden -ErrorAction Stop
            Add-Result 'WindowsUpdateScan' 'Requested' 'UsoClient StartScan launched.'
        } catch {
            Add-Result 'WindowsUpdateScan' 'Failed' $_.Exception.Message
        }
    }
}

if (-not $SkipQuickScan) {
    if ($PSCmdlet.ShouldProcess('Microsoft Defender', 'Start quick scan')) {
        try {
            Start-MpScan -ScanType QuickScan -ErrorAction Stop
            Add-Result 'DefenderQuickScan' 'Requested' 'Quick scan requested.'
        } catch {
            Add-Result 'DefenderQuickScan' 'Failed' $_.Exception.Message
        }
    }
}

$bitlocker = @()
$winRe = ''
try { $bitlocker = @(Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object MountPoint, ProtectionStatus, VolumeStatus, EncryptionPercentage) } catch {}
try { $winRe = Get-WinReInfo } catch {}

Add-Result 'BitLockerWinRE' 'ManualReview' 'CVE-2026-45585 mitigation is intentionally not auto-applied. If BitLocker is enabled with WinRE, apply Microsoft mitigation or require a startup PIN.'

[pscustomobject]@{
    AppliedAt = (Get-Date).ToString('s')
    Summary = 'Windows CVE safeguards requested'
    Results = $results
    DefenderStatus = $defenderVerification
    BitLockerVolumes = $bitlocker
    WinRE = $winRe
    Notes = @(
        'This script does not apply exploit code or destructive changes.',
        'BitLocker/WinRE mitigation can involve recovery-image changes and is left as an explicit manual step using Microsoft guidance.',
        'Reboot if Windows Update, Defender platform update, or cumulative update installation requests it.'
    )
} | ConvertTo-Json -Depth 6
