using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.Core.Hardening;

public class HardeningEngine
{
private static readonly AsrRule[] AllAsrRules = {
new() { Id = "56a863a9-875e-4185-98a7-b882c64b5ce5", Name = "Block abuse of exploited vulnerable signed drivers" },
new() { Id = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", Name = "Block Adobe Reader from creating child processes" },
new() { Id = "d4f940ab-401b-4efc-aadc-ad5f3c50688a", Name = "Block all Office applications from creating child processes" },
new() { Id = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", Name = "Block credential stealing from lsass.exe" },
new() { Id = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", Name = "Block executable content from email client and webmail" },
new() { Id = "01443614-cd74-433a-b99e-2ecdc07bfc25", Name = "Block executable files unless they meet prevalence/age/trusted list" },
new() { Id = "5beb7efe-fd9a-4556-801d-275e5ffc04cc", Name = "Block execution of potentially obfuscated scripts" },
new() { Id = "d3e037e1-3eb8-44c8-a917-57927947596d", Name = "Block JavaScript or VBScript from launching downloaded executables" },
new() { Id = "3b576869-a4ec-4529-8536-b80a7769e899", Name = "Block Office applications from creating executable content" },
new() { Id = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", Name = "Block Office applications from injecting code into other processes" },
new() { Id = "26190899-1602-49e8-8b27-eb1d0a1ce869", Name = "Block Office communication application from creating child processes" },
new() { Id = "e6db77e5-3df2-4cf1-b95a-636979351e5b", Name = "Block persistence through WMI event subscription" },
new() { Id = "d1e49aac-8f56-4280-b9ba-993a6d77406c", Name = "Block process creations originating from PSExec and WMI commands" },
new() { Id = "33ddedf1-c6e0-47cb-833e-de6133960387", Name = "Block rebooting machine in Safe Mode" },
new() { Id = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", Name = "Block untrusted and unsigned processes that run from USB" },
new() { Id = "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", Name = "Block use of copied or impersonated system tools" },
new() { Id = "a8f5898e-1dc8-49a9-9878-85004b8a61e6", Name = "Block Webshell creation for Servers" },
new() { Id = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", Name = "Block Win32 API calls from Office macros" },
new() { Id = "c1db55ab-c21a-4637-bb3f-a12568109d35", Name = "Use advanced protection against ransomware" }
};

private const string SnapshotPath = @"C:\ProgramData\TGWST\MpPoliciesBaseline.json";

public HardeningProfile GetProfile(HardeningProfileLevel level)
{
    HardeningProfile baseProfile = level switch
    {
        HardeningProfileLevel.Balanced   => new() { Level = level, DefenderRealtimeOn = true, NetworkProtectionOn = true, ControlledFolderAccessOn = false, SmartScreenOn = true },
        HardeningProfileLevel.Aggressive => new() { Level = level, DefenderRealtimeOn = true, NetworkProtectionOn = true, ControlledFolderAccessOn = true,  SmartScreenOn = true },
        HardeningProfileLevel.Audit      => new() { Level = level, DefenderRealtimeOn = true, NetworkProtectionOn = true, ControlledFolderAccessOn = false, SmartScreenOn = true },
        HardeningProfileLevel.Revert     => new() { Level = level, DefenderRealtimeOn = true, NetworkProtectionOn = false, ControlledFolderAccessOn = false, SmartScreenOn = true },
        _ => throw new ArgumentOutOfRangeException(nameof(level))
    };

    AsrAction action = level switch
    {
        HardeningProfileLevel.Audit  => AsrAction.Audit,
        HardeningProfileLevel.Revert => AsrAction.Off,
        _                            => AsrAction.Block
    };

    baseProfile.AsrRules = AllAsrRules
        .Select(r => new AsrRule { Id = r.Id, Name = r.Name, Action = action })
        .ToArray();

    return baseProfile;
}

public async Task<HardeningProfile> ApplyProfileAsync(
    HardeningProfile profile,
    IProgress<string>? log = null,
    CancellationToken ct = default)
{
    EnsureAdmin();
    Report(log, $"Starting profile '{profile.Level}'");

    if (profile.Level == HardeningProfileLevel.Revert)
    {
        if (!File.Exists(SnapshotPath))
            throw new InvalidOperationException("Baseline snapshot not found; cannot revert. Apply a profile first to create the baseline.");

        await ApplyBaselineAsync(log, ct);
        Report(log, "Reverted to baseline.");
        return profile;
    }

    await EnsureBaselineSnapshotAsync(log, ct);
    await SetDefenderOptionsAsync(profile, log, ct);
    await SetAsrRulesAsync(profile.AsrRules, log, ct);

    if (profile.Level is HardeningProfileLevel.Aggressive)
    {
        const string script = @"


bcdedit /set hypervisorlaunchtype auto
reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v LsaCfgFlags /t REG_DWORD /d 1 /f
";
Report(log, "Enabling HVCI/credential guard settings (requires reboot).");
await RunPowerShellAsync(script, log, ct, "Enable HVCI/CG");
profile.RebootRequired = true;
}

    Report(log, $"Profile '{profile.Level}' applied.");
    return profile;
}

private static async Task RunPowerShellAsync(string script, IProgress<string>? log, CancellationToken ct, string? label = null)
{
    if (!string.IsNullOrWhiteSpace(label))
        Report(log, $"Executing: {label}");

    var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

    var psi = new ProcessStartInfo
    {
        FileName = "powershell.exe",
        Arguments = $"-NoLogo -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}",
        UseShellExecute = false,
        CreateNoWindow = true,
        RedirectStandardError = true,
        RedirectStandardOutput = true
    };

    using var p = Process.Start(psi);
    if (p == null) throw new InvalidOperationException("Failed to start PowerShell");

    var stderrTask = p.StandardError.ReadToEndAsync();
    var stdoutTask = p.StandardOutput.ReadToEndAsync();
    await p.WaitForExitAsync(ct);
    var stderr = await stderrTask;
    var stdout = await stdoutTask;

    if (p.ExitCode != 0)
    {
        var sb = new StringBuilder();
        sb.Append($"PowerShell exited with code {p.ExitCode}.");
        if (!string.IsNullOrWhiteSpace(stdout))
            sb.Append($" Stdout: {Truncate(stdout)}");
        if (!string.IsNullOrWhiteSpace(stderr))
            sb.Append($" Stderr: {Truncate(stderr)}");
        throw new InvalidOperationException(sb.ToString());
    }
}

private async Task EnsureBaselineSnapshotAsync(IProgress<string>? log, CancellationToken ct)
{
    if (File.Exists(SnapshotPath)) return;

    var dir = Path.GetDirectoryName(SnapshotPath);
    if (!string.IsNullOrEmpty(dir))
        Directory.CreateDirectory(dir);

    var script = $@"
$p = Get-MpPreference
$baseline = [ordered]@{{
    DisableRealtimeMonitoring            = $p.DisableRealtimeMonitoring
    EnableNetworkProtection              = $p.EnableNetworkProtection
    EnableControlledFolderAccess         = $p.EnableControlledFolderAccess
    AttackSurfaceReductionRules_Ids      = $p.AttackSurfaceReductionRules_Ids
    AttackSurfaceReductionRules_Actions  = $p.AttackSurfaceReductionRules_Actions
}}
$baseline | ConvertTo-Json -Depth 5 | Set-Content -Path '{SnapshotPath}' -Encoding UTF8
";
    Report(log, $"Creating baseline snapshot at {SnapshotPath}");
    await RunPowerShellAsync(script, log, ct, "Export baseline (Get-MpPreference)");
}

private async Task SetDefenderOptionsAsync(HardeningProfile profile, IProgress<string>? log, CancellationToken ct)
{
    var commands = new List<string>
    {
        profile.DefenderRealtimeOn
            ? "Set-MpPreference -DisableRealtimeMonitoring $false"
            : "Set-MpPreference -DisableRealtimeMonitoring $true",
        profile.NetworkProtectionOn
            ? "Set-MpPreference -EnableNetworkProtection Enabled"
            : "Set-MpPreference -EnableNetworkProtection Disabled",
        profile.ControlledFolderAccessOn
            ? "Set-MpPreference -EnableControlledFolderAccess Enabled"
            : "Set-MpPreference -EnableControlledFolderAccess Disabled"
    };

    Report(log, $"Defender realtime: {(profile.DefenderRealtimeOn ? "On" : "Off")}");
    Report(log, $"Network protection: {(profile.NetworkProtectionOn ? "On" : "Off")}");
    Report(log, $"Controlled folder access: {(profile.ControlledFolderAccessOn ? "On" : "Off")}");

    var script = string.Join("; ", commands);
    Report(log, "Applying Defender options (Realtime/Network Protection/CFA)");
    await RunPowerShellAsync(script, log, ct, "Set Defender options");

    var verifyScript = $@"
$p = Get-MpPreference
$desiredRealtime = {(profile.DefenderRealtimeOn ? "$false" : "$true")}
$desiredNet = {(profile.NetworkProtectionOn ? "1" : "0")}
$desiredCfa = {(profile.ControlledFolderAccessOn ? "1" : "0")}
if ($p.DisableRealtimeMonitoring -ne $desiredRealtime) {{ Write-Output 'Realtime mismatch (policy may enforce).'; }}
if ($p.EnableNetworkProtection -ne $desiredNet) {{ Write-Output 'Network Protection mismatch (policy may enforce).'; }}
if ($p.EnableControlledFolderAccess -ne $desiredCfa) {{ Write-Output 'Controlled Folder Access mismatch (policy may enforce or Tamper Protection enabled).'; }}
Write-Output ""Realtime: $($p.DisableRealtimeMonitoring -eq $false)""
Write-Output ""NetworkProtection: $($p.EnableNetworkProtection)""
Write-Output ""ControlledFolderAccess: $($p.EnableControlledFolderAccess)""
";
    await RunPowerShellAsync(verifyScript, log, ct, "Verify Defender options");
}

private async Task SetAsrRulesAsync(IEnumerable<AsrRule> rules, IProgress<string>? log, CancellationToken ct)
{
    var ids = new List<string>();
    var actions = new List<string>();

    foreach (var rule in rules)
    {
        var value = rule.Action switch
        {
            AsrAction.Off   => "Disabled",
            AsrAction.Audit => "AuditMode",
            AsrAction.Block => "Enabled",
            _               => "Disabled"
        };

        ids.Add($"\"{rule.Id}\"");
        actions.Add($"\"{value}\"");
        Report(log, $"ASR: {rule.Id} -> {value} ({rule.Name})");
    }

    if (ids.Count == 0) return;

    var idsLiteral = $"@({string.Join(", ", ids)})";
    var actionsLiteral = $"@({string.Join(", ", actions)})";
    var script = $"Set-MpPreference -AttackSurfaceReductionRules_Ids {idsLiteral} -AttackSurfaceReductionRules_Actions {actionsLiteral}";
    Report(log, "Applying ASR rules set");
    await RunPowerShellAsync(script, log, ct, "Set ASR rules");
}

private async Task ApplyBaselineAsync(IProgress<string>? log, CancellationToken ct)
{
    if (!File.Exists(SnapshotPath))
        throw new InvalidOperationException("Baseline snapshot not found; cannot revert. Apply a profile first to create the baseline.");

    var script = $@"
$baseline = Get-Content -Path '{SnapshotPath}' -Raw | ConvertFrom-Json
if ($null -ne $baseline.DisableRealtimeMonitoring)    {{ Set-MpPreference -DisableRealtimeMonitoring $baseline.DisableRealtimeMonitoring }}
if ($null -ne $baseline.EnableNetworkProtection)      {{ Set-MpPreference -EnableNetworkProtection $baseline.EnableNetworkProtection }}
if ($null -ne $baseline.EnableControlledFolderAccess) {{ Set-MpPreference -EnableControlledFolderAccess $baseline.EnableControlledFolderAccess }}
if ($baseline.AttackSurfaceReductionRules_Ids -and $baseline.AttackSurfaceReductionRules_Actions) {{
    Set-MpPreference -AttackSurfaceReductionRules_Ids $baseline.AttackSurfaceReductionRules_Ids -AttackSurfaceReductionRules_Actions $baseline.AttackSurfaceReductionRules_Actions
}}
";
    Report(log, $"Restoring baseline from {SnapshotPath}");
    await RunPowerShellAsync(script, log, ct, "Restore baseline");
}

private static string Truncate(string value, int max = 400)
{
    var trimmed = value.Trim();
    return trimmed.Length <= max ? trimmed : trimmed[..max] + "...";
}

private static void EnsureAdmin()
{
    using var identity = WindowsIdentity.GetCurrent();
    var principal = new WindowsPrincipal(identity);
    if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
        throw new InvalidOperationException("Administrator rights are required to apply or revert hardening profiles.");
}

private static void Report(IProgress<string>? log, string message) => log?.Report(message);

}
