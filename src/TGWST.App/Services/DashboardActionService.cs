using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.App.Services;

public sealed class DashboardActionService
{
    private const string AdvancedFirewallControlScript = """
$ErrorActionPreference = 'Continue'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportDir = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'TGWST\reports'
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
$reportPath = Join-Path $reportDir "advanced-firewall-controls-$timestamp.json"
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param([string]$Area, [string]$Target, [string]$Status, [string]$Detail)
    $results.Add([pscustomobject]@{
        Area = $Area
        Target = $Target
        Status = $Status
        Detail = $Detail
    })
}

try {
    Set-NetFirewallProfile `
        -Profile Domain,Private,Public `
        -Enabled True `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Allow `
        -LogAllowed True `
        -LogBlocked True `
        -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log' `
        -LogMaxSizeKilobytes 16384 `
        -ErrorAction Stop
    Add-Result 'FirewallProfile' 'Domain,Private,Public' 'Hardened' 'Profiles enabled, default inbound blocked, outbound allowed, allowed/blocked packet logging enabled.'
} catch {
    Add-Result 'FirewallProfile' 'Domain,Private,Public' 'Failed' $_.Exception.Message
}

$groupsToDisable = @(
    'Cast to Device functionality',
    'Connected Devices Platform',
    'File and Printer Sharing',
    'Network Discovery',
    'Remote Assistance',
    'Wi-Fi Direct Network Discovery',
    'mDNS'
)

try {
    $allowRules = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue |
        Where-Object { $groupsToDisable -contains $_.DisplayGroup -or $_.DisplayName -match 'mDNS|LLMNR|SSDP|UPnP' }

    foreach ($rule in $allowRules) {
        try {
            Disable-NetFirewallRule -Name $rule.Name -ErrorAction Stop
            $group = if ([string]::IsNullOrWhiteSpace($rule.DisplayGroup)) { 'ungrouped/high-discovery rule' } else { $rule.DisplayGroup }
            Add-Result 'InboundAllowRule' $rule.DisplayName 'Disabled' $group
        } catch {
            Add-Result 'InboundAllowRule' $rule.DisplayName 'Failed' $_.Exception.Message
        }
    }
} catch {
    Add-Result 'InboundAllowRule' 'Discovery/FileSharing groups' 'Failed' $_.Exception.Message
}

$blockRules = @(
    @{ Name = 'TGWST Block TCP 139 NetBIOS'; Protocol = 'TCP'; Port = '139'; Detail = 'NetBIOS session service' },
    @{ Name = 'TGWST Block TCP 445 SMB'; Protocol = 'TCP'; Port = '445'; Detail = 'SMB direct hosting' },
    @{ Name = 'TGWST Block UDP 137 NetBIOS'; Protocol = 'UDP'; Port = '137'; Detail = 'NetBIOS name service' },
    @{ Name = 'TGWST Block UDP 138 NetBIOS'; Protocol = 'UDP'; Port = '138'; Detail = 'NetBIOS datagram service' },
    @{ Name = 'TGWST Block UDP 5355 LLMNR'; Protocol = 'UDP'; Port = '5355'; Detail = 'Link-local multicast name resolution' },
    @{ Name = 'TGWST Block UDP 1900 SSDP'; Protocol = 'UDP'; Port = '1900'; Detail = 'SSDP discovery' },
    @{ Name = 'TGWST Block UDP 3702 WSD'; Protocol = 'UDP'; Port = '3702'; Detail = 'Web Services Discovery' }
)

foreach ($rule in $blockRules) {
    try {
        $existing = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
        if ($existing) {
            Set-NetFirewallRule -DisplayName $rule.Name -Enabled True -Direction Inbound -Action Block -Profile Any -ErrorAction Stop
            Add-Result 'InboundBlockRule' $rule.Name 'Present' "$($rule.Protocol) $($rule.Port)"
        } else {
            New-NetFirewallRule `
                -DisplayName $rule.Name `
                -Direction Inbound `
                -Action Block `
                -Protocol $rule.Protocol `
                -LocalPort $rule.Port `
                -Profile Any `
                -Description "TGWST advanced firewall controls: $($rule.Detail)" `
                -ErrorAction Stop | Out-Null
            Add-Result 'InboundBlockRule' $rule.Name 'Created' "$($rule.Protocol) $($rule.Port)"
        }
    } catch {
        Add-Result 'InboundBlockRule' $rule.Name 'Failed' $_.Exception.Message
    }
}

$profiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogFileName, LogMaxSizeKilobytes)
$report = [pscustomobject]@{
    AppliedAt = (Get-Date).ToString('s')
    Summary = 'Advanced firewall controls requested'
    ReportPath = $reportPath
    Profiles = $profiles
    Results = $results
}

$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportPath -Encoding UTF8
$report | ConvertTo-Json -Depth 6
""";

    private const string NetworkSettingsBaselineScript = """
$ErrorActionPreference = 'Continue'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportDir = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'TGWST\reports'
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
$reportPath = Join-Path $reportDir "network-privacy-baseline-$timestamp.json"
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param([string]$Area, [string]$Target, [string]$Status, [string]$Detail)
    $results.Add([pscustomobject]@{
        Area = $Area
        Target = $Target
        Status = $Status
        Detail = $Detail
    })
}

try {
    $profiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)
    foreach ($profile in $profiles) {
        if ($profile.NetworkCategory -eq 'DomainAuthenticated') {
            Add-Result 'NetworkProfile' $profile.Name 'Preserved' 'Domain-authenticated profile was not changed.'
            continue
        }

        try {
            Set-NetConnectionProfile -InterfaceIndex $profile.InterfaceIndex -NetworkCategory Public -ErrorAction Stop
            Add-Result 'NetworkProfile' $profile.Name 'Public' "InterfaceIndex=$($profile.InterfaceIndex)"
        } catch {
            Add-Result 'NetworkProfile' $profile.Name 'Failed' $_.Exception.Message
        }
    }
} catch {
    Add-Result 'NetworkProfile' 'Active profiles' 'Failed' $_.Exception.Message
}

try {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0 -PropertyType DWord -Force | Out-Null
    Add-Result 'NameResolution' 'LLMNR' 'Disabled' 'Policy EnableMulticast=0.'
} catch {
    Add-Result 'NameResolution' 'LLMNR' 'Failed' $_.Exception.Message
}

try {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DisableWpad' -Value 1 -PropertyType DWord -Force | Out-Null
    & netsh.exe winhttp reset proxy | Out-Null
    Add-Result 'NameResolution' 'WPAD/WinHTTP proxy discovery' 'Disabled' 'DisableWpad=1 and WinHTTP proxy reset requested.'
} catch {
    Add-Result 'NameResolution' 'WPAD/WinHTTP proxy discovery' 'Failed' $_.Exception.Message
}

try {
    $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue
    foreach ($adapter in $adapters) {
        try {
            $result = Invoke-CimMethod -InputObject $adapter -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = 2 } -ErrorAction Stop
            Add-Result 'NameResolution' $adapter.Description 'NetBIOSDisabled' "ReturnValue=$($result.ReturnValue)"
        } catch {
            Add-Result 'NameResolution' $adapter.Description 'Failed' $_.Exception.Message
        }
    }
} catch {
    Add-Result 'NameResolution' 'NetBIOS adapters' 'Failed' $_.Exception.Message
}

try {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop
    Add-Result 'FirewallProfile' 'Domain,Private,Public' 'Hardened' 'Profiles enabled; default inbound blocked.'
} catch {
    Add-Result 'FirewallProfile' 'Domain,Private,Public' 'Failed' $_.Exception.Message
}

$groupsToDisable = @(
    'File and Printer Sharing',
    'Network Discovery',
    'Remote Assistance',
    'Cast to Device functionality',
    'Connected Devices Platform',
    'Wi-Fi Direct Network Discovery'
)

try {
    $rules = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue |
        Where-Object { $groupsToDisable -contains $_.DisplayGroup }

    foreach ($rule in $rules) {
        try {
            Disable-NetFirewallRule -Name $rule.Name -ErrorAction Stop
            Add-Result 'InboundAllowRule' $rule.DisplayName 'Disabled' $rule.DisplayGroup
        } catch {
            Add-Result 'InboundAllowRule' $rule.DisplayName 'Failed' $_.Exception.Message
        }
    }
} catch {
    Add-Result 'InboundAllowRule' 'Network privacy groups' 'Failed' $_.Exception.Message
}

try {
    Set-SmbClientConfiguration -EnableInsecureGuestLogons $false -EnableSecuritySignature $true -RequireSecuritySignature $true -Confirm:$false -ErrorAction Stop
    Add-Result 'SMBClient' 'Signing/insecure guest' 'Hardened' 'Insecure guest disabled; SMB signing enabled and required.'
} catch {
    Add-Result 'SMBClient' 'Signing/insecure guest' 'Failed' $_.Exception.Message
}

$verification = [pscustomobject]@{
    NetworkProfiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity)
    FirewallProfiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)
    SmbClient = Get-SmbClientConfiguration -ErrorAction SilentlyContinue | Select-Object EnableInsecureGuestLogons, EnableSecuritySignature, RequireSecuritySignature
}

$report = [pscustomobject]@{
    AppliedAt = (Get-Date).ToString('s')
    Summary = 'Network privacy baseline requested'
    ReportPath = $reportPath
    RebootRecommended = $true
    Verification = $verification
    Results = $results
    Notes = @(
        'Non-domain networks are set to Public. Domain-authenticated profiles are preserved.',
        'This may affect local file sharing, device discovery, casting, and legacy SMB devices.',
        'A reboot or adapter reconnect may be required for NetBIOS/name-resolution changes to fully settle.'
    )
}

$report | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $reportPath -Encoding UTF8
$report | ConvertTo-Json -Depth 7
""";

    public Task<string> ApplyWindowsSecurityBaselineAsync(CancellationToken ct = default)
    {
        return Task.Run<string>(() =>
        {
            ct.ThrowIfCancellationRequested();
            RunElevatedPowerShellScript(
                "Invoke-TGWST-WindowsCveSafeguards.ps1",
                "-SkipWindowsUpdateScan",
                "-SkipQuickScan",
                "-SkipFirewallBaseline");
            return "Windows Security baseline requested: Defender signatures, realtime/IOAV, behavior/script/archive/email/removable/network scanning, cloud protection, PUA, ASR, and verification.";
        }, ct);
    }

    public Task<string> ApplyAdvancedFirewallControlsAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            RunElevatedPowerShellCommand(AdvancedFirewallControlScript);
            return "advanced firewall controls requested: profiles enabled, default inbound blocked, logging enabled, discovery/file-sharing inbound allows disabled, and high-risk inbound block rules enforced.";
        }, ct);
    }

    public Task<string> ApplyNetworkSettingsBaselineAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            RunElevatedPowerShellCommand(NetworkSettingsBaselineScript);
            return "network privacy baseline requested: non-domain networks set Public, LLMNR/WPAD/NetBIOS reduced, SMB client signing required, and discovery/file-sharing inbound allows disabled.";
        }, ct);
    }

    public Task<string> EnableFirewallProfilesAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            RunVerifiedFirewallBaseline(setDefaultInboundBlock: false);
            return "verified firewall enablement for all active profiles; existing default actions and rules were preserved";
        }, ct);
    }

    public Task<string> ApplyFirewallBaselineAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            RunVerifiedFirewallBaseline(setDefaultInboundBlock: true);
            return "verified firewall baseline: profiles on and default inbound blocked; stricter outbound policy and explicit rules were preserved";
        }, ct);
    }

    public Task<string> ApplyNetworkSurfaceHardeningAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            RunElevatedPowerShellScript("Invoke-TGWST-NetworkSurfaceHardening.ps1");
            return "applied network surface hardening: discovery/file-sharing services disabled, watched inbound ports blocked, LLMNR/NetBIOS reduced, firewall logging enabled";
        }, ct);
    }

    public Task<string> ApplyWindows11BarebonesLockdownAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            var reportPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "TGWST",
                "reports",
                $"windows11-barebones-lockdown-{DateTime.Now:yyyyMMdd-HHmmss}.json");

            RunElevatedPowerShellScript(
                "Invoke-TGWST-Windows11BarebonesLockdown.ps1",
                "-KillAnomalyProcesses",
                "-OutputPath",
                reportPath,
                "-OpenReport");

            return $"Windows 11 Barebones Lockdown complete: {reportPath}";
        }, ct);
    }

    public Task<string> RunInboundSurfaceAuditAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            var reportPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "TGWST",
                "reports",
                $"inbound-surface-audit-{DateTime.Now:yyyyMMdd-HHmmss}.json");

            RunElevatedPowerShellScript(
                "Get-TGWST-InboundSurfaceAudit.ps1",
                "-Days",
                "7",
                "-OutputPath",
                reportPath,
                "-OpenReport");

            return $"inbound surface audit complete: {reportPath}";
        }, ct);
    }

    public Task<string> RunWindowsCveExposureAuditAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            var reportPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "TGWST",
                "reports",
                $"windows-cve-exposure-{DateTime.Now:yyyyMMdd-HHmmss}.json");

            RunElevatedPowerShellScript(
                "Get-TGWST-WindowsCveExposure.ps1",
                "-OutputPath",
                reportPath,
                "-OpenReport");

            return $"Windows CVE exposure audit complete: {reportPath}";
        }, ct);
    }

    public Task<string> ApplyWindowsCveSafeguardsAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            RunElevatedPowerShellScript("Invoke-TGWST-WindowsCveSafeguards.ps1");
            return "Windows CVE safeguards requested: Defender updated/hardened, ASR requested, firewall baseline enforced, Windows Update scan requested";
        }, ct);
    }

    public Task<string> RunEicarDefenderTestAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            var reportPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "TGWST",
                "reports",
                $"eicar-defender-test-{DateTime.Now:yyyyMMdd-HHmmss}.json");

            RunElevatedPowerShellScript(
                "Test-TGWST-EicarDefender.ps1",
                "-OutputPath",
                reportPath,
                "-OpenReport");

            return $"EICAR Defender readiness test complete: {reportPath}";
        }, ct);
    }

    // === Windows Safeguards Defense additions (Req 1-3 primary) ===
    public Task<string> ApplyWindowsSafeguardsProfileAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            // Self-invoke CLI for consistency and to reuse the full engine
            var exe = Process.GetCurrentProcess().MainModule?.FileName ?? "TGWST.exe";
            var psi = new ProcessStartInfo(exe, "--apply-windows-safeguards")
            {
                UseShellExecute = true,
                Verb = "runas" // ensure elevation for hardening
            };
            using var p = Process.Start(psi) ?? throw new InvalidOperationException("Unable to launch the safeguards command.");
            p.WaitForExit();
            if (p.ExitCode != 0)
            {
                throw new InvalidOperationException($"Safeguards command is unavailable or failed (exit code {p.ExitCode}).");
            }
            return "Windows Safeguards Defense Profile apply launched (elevated CLI). Check console output / reports.";
        }, ct);
    }

    public Task<string> ApplyWdacContainmentProfileAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            var exe = Process.GetCurrentProcess().MainModule?.FileName ?? "TGWST.exe";
            var psi = new ProcessStartInfo(exe, "--apply-wdac-containment-profile")
            {
                UseShellExecute = true,
                Verb = "runas"
            };
            using var p = Process.Start(psi) ?? throw new InvalidOperationException("Unable to launch the WDAC command.");
            p.WaitForExit();
            if (p.ExitCode != 0)
            {
                throw new InvalidOperationException($"WDAC command is unavailable or failed (exit code {p.ExitCode}).");
            }
            return "WDAC Windows Safeguards Containment profile generation launched (see output / %ProgramData%\\TGWST\\wdac). Apply policy via ConfigCI after review.";
        }, ct);
    }

    public Task<string> ScanWindowsSafeguardsAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            var exe = Process.GetCurrentProcess().MainModule?.FileName ?? "TGWST.exe";
            var psi = new ProcessStartInfo(exe, "--scan-windows-safeguards --verbose")
            {
                UseShellExecute = true
            };
            using var p = Process.Start(psi) ?? throw new InvalidOperationException("Unable to launch the safeguards scan command.");
            p.WaitForExit();
            if (p.ExitCode != 0)
            {
                throw new InvalidOperationException($"Safeguards scan is unavailable or failed (exit code {p.ExitCode}).");
            }
            return "Windows Safeguards scan launched. Review console + %ProgramData%\\TGWST\\logs for JSON report and Event Log 'TGWST'.";
        }, ct);
    }

    public Task<string> EnableDefenderRealtimeAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            RunElevatedPowerShellScript(
                "Invoke-TGWST-WindowsCveSafeguards.ps1",
                "-SkipWindowsUpdateScan",
                "-SkipQuickScan",
                "-SkipFirewallBaseline");
            return "requested Defender realtime/IOAV, behavior, cloud, PUA, ASR, signature update, and verification safeguards";
        }, ct);
    }

    public Task<string> EnableDefenderCloudAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            RunElevatedPowerShellScript(
                "Invoke-TGWST-WindowsCveSafeguards.ps1",
                "-SkipWindowsUpdateScan",
                "-SkipQuickScan",
                "-SkipFirewallBaseline");
            return "requested Defender cloud protection, safe sample submission, block-at-first-sight, ASR, and verification safeguards";
        }, ct);
    }

    public Task<string> RunDefenderQuickScanAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            RunFixedElevatedPowerShell("$ErrorActionPreference='Stop'; $before=(Get-MpComputerStatus -ErrorAction Stop).QuickScanEndTime; Start-MpScan -ScanType QuickScan -ErrorAction Stop; $after=(Get-MpComputerStatus -ErrorAction Stop).QuickScanEndTime; if (-not $after -or ($before -and $after -le $before)) { throw 'Defender quick scan completion could not be verified.' }");
            return "verified Microsoft Defender quick scan completion";
        }, ct);
    }

    public Task<string> UpdateDefenderSignaturesAsync(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            RunFixedElevatedPowerShell("$ErrorActionPreference='Stop'; Update-MpSignature -ErrorAction Stop; $status=Get-MpComputerStatus -ErrorAction Stop; if (-not $status.AntivirusSignatureVersion -or -not $status.AntivirusSignatureLastUpdated) { throw 'Defender signature state could not be verified.' }");
            return "verified Defender signature update command and readable signature state";
        }, ct);
    }

    public Task<string> ActivateEmergencyBaselineAsync(CancellationToken ct = default)
    {
        if (ct.IsCancellationRequested)
        {
            return Task.FromCanceled<string>(ct);
        }

        return Task.FromException<string>(new NotSupportedException(
            "The emergency baseline is staged but unavailable until every control has independent verification and secured recovery data. No change was made."));
    }

    public Task<string> DisableSmb1Async(CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            RunFixedElevatedPowerShell("$ErrorActionPreference='Stop'; $before=Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop; if ($before.State -notin @('Disabled','DisablePending')) { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null }; $after=Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop; if ($after.State -notin @('Disabled','DisablePending')) { throw ('SMB1 verification failed; state=' + $after.State) }");
            return "verified SMBv1 is disabled or disable-pending; a reboot may be required";
        }, ct);
    }

    private static void RunVerifiedFirewallBaseline(bool setDefaultInboundBlock)
    {
        var setCommand = setDefaultInboundBlock
            ? "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -ErrorAction Stop"
            : "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction Stop";
        var inboundVerification = setDefaultInboundBlock
            ? " -or $_.DefaultInboundAction.ToString() -ne 'Block'"
            : string.Empty;
        var script = $$"""
$ErrorActionPreference = 'Stop'
{{setCommand}}
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
if ($profiles.Count -lt 3) { throw 'Firewall profile verification returned an incomplete profile set.' }
$failed = @($profiles | Where-Object { -not $_.Enabled{{inboundVerification}} })
if ($failed.Count -gt 0) { throw ('Firewall verification failed for: ' + (($failed | ForEach-Object Name) -join ', ')) }
""";
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        RunElevatedProcess(
            GetPowerShellPath(),
            $"-NoLogo -NoProfile -NonInteractive -EncodedCommand {encoded}");
    }

    private static void RunFixedElevatedPowerShell(string command)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(command));
        RunElevatedProcess(
            GetPowerShellPath(),
            $"-NoLogo -NoProfile -NonInteractive -EncodedCommand {encoded}");
    }

    private static void RunElevatedPowerShellCommand(string script)
    {
        throw new NotSupportedException(
            "Broad inline PowerShell remediation is disabled until TGWST provides typed preview, verification, and rollback. No change was made.");
    }

    private static void RunElevatedPowerShellScript(string scriptName, params string[] arguments)
    {
        throw new NotSupportedException(
            $"Packaged action '{scriptName}' is disabled until TGWST ships scripts through a signed or embedded trust boundary with verified results and rollback. No change was made.");
    }

    private static string GetPowerShellPath()
    {
        return Path.Combine(
            Environment.SystemDirectory,
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe");
    }

    private static void RunElevatedProcess(string fileName, string arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            UseShellExecute = true,
            Verb = "runas",
            Arguments = arguments
        };

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException($"Unable to launch {fileName}.");
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"{Path.GetFileName(fileName)} returned exit code {process.ExitCode}.");
        }
    }
}
