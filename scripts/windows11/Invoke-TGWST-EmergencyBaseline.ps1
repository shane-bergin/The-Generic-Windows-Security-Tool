#requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$EnableAsrBlockRules
)

$ErrorActionPreference = 'Stop'

if ($PSCmdlet.ShouldProcess('Windows Defender Firewall', 'Enable all profiles and block default inbound traffic')) {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
}

if ($PSCmdlet.ShouldProcess('Microsoft Defender', 'Ensure realtime monitoring is enabled')) {
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -DisableIOAVProtection $false
    Set-MpPreference -MAPSReporting Advanced
    Set-MpPreference -SubmitSamplesConsent SendSafeSamples
}

if ($EnableAsrBlockRules) {
    $asrRuleIds = @(
        'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550',
        'D4F940AB-401B-4EFC-AADC-AD5F3C50688A',
        '3B576869-A4EC-4529-8536-B80A7769E899',
        '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84',
        'D3E037E1-3EB8-44C8-A917-57927947596D',
        '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC',
        '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B',
        '01443614-CD74-433A-B99E-2ECDC07BFC25'
    )

    if ($PSCmdlet.ShouldProcess('Microsoft Defender ASR', 'Enable common workstation block rules')) {
        Set-MpPreference -AttackSurfaceReductionRules_Ids $asrRuleIds -AttackSurfaceReductionRules_Actions Enabled
    }
}

if ($PSCmdlet.ShouldProcess('Microsoft Defender', 'Start quick scan')) {
    Start-MpScan -ScanType QuickScan
}

[pscustomobject]@{
    ActivatedAt = (Get-Date).ToString('s')
    Firewall = 'Enabled; default inbound blocked; default outbound allowed'
    DefenderRealtime = 'Requested enabled'
    QuickScan = 'Requested'
    AsrBlockRules = if ($EnableAsrBlockRules) { 'Requested common workstation rules' } else { 'Skipped; rerun with -EnableAsrBlockRules if desired' }
}
