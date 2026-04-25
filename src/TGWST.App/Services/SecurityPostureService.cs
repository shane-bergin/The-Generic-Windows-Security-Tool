using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TGWST.App.ViewModels;
using TGWST.Core.Network;

namespace TGWST.App.Services;

public sealed class SecurityPostureService
{
    private readonly FirewallStatusService _firewallStatus;

    public SecurityPostureService(FirewallStatusService firewallStatus)
    {
        _firewallStatus = firewallStatus;
    }

    public async Task<SecurityPostureSnapshot> GetSnapshotAsync(
        NetworkTelemetrySnapshot? network,
        int recentCriticalTelemetry,
        CancellationToken ct = default)
    {
        var defenderTask = ReadDefenderAsync(ct);
        var firewallTask = _firewallStatus.GetStatusAsync();

        DefenderStatus defender;
        try
        {
            defender = await defenderTask.ConfigureAwait(false);
        }
        catch
        {
            defender = new DefenderStatus();
        }

        var vulnerableFirewallProfiles = 0;
        try
        {
            var profiles = await firewallTask.ConfigureAwait(false);
            vulnerableFirewallProfiles = profiles.Count(profile => profile.IsVulnerable);
        }
        catch
        {
            vulnerableFirewallProfiles = 1;
        }

        var blockedAsrControls = CountBlockedAsrControls(defender.AttackSurfaceReductionRules_Actions);

        var score = 100;
        if (defender.AntivirusEnabled == false) score -= 25;
        if (defender.RealTimeProtectionEnabled == false) score -= 25;
        if (defender.IoavProtectionEnabled == false) score -= 10;
        score -= Math.Min(30, vulnerableFirewallProfiles * 15);
        if (blockedAsrControls < 8) score -= 10;
        if (network != null) score -= Math.Min(25, network.HighestRiskScore / 4);
        score -= Math.Min(20, recentCriticalTelemetry * 10);
        score = Math.Clamp(score, 0, 100);

        var threatLevel = score < 60 || recentCriticalTelemetry > 0
            ? CyberThreatLevel.Critical
            : score < 82 || (network?.HighestRiskScore ?? 0) >= 60
                ? CyberThreatLevel.Elevated
                : CyberThreatLevel.Normal;

        var integrity = Math.Clamp(score + (defender.RealTimeProtectionEnabled == true ? 5 : -10), 0, 100);
        var exposure = network == null
            ? "UNKNOWN"
            : network.HighestRiskScore >= 70
                ? "HIGH"
                : network.HighestRiskScore >= 35
                    ? "ELEVATED"
                    : "LOW";
        var activeThreats = (network?.RiskyConnections.Count(row => row.RiskScore >= 70) ?? 0) + recentCriticalTelemetry;
        var lastFullScan = defender.FullScanEndTime?.ToLocalTime().ToString("yyyy-MM-dd HH:mm") ?? "unknown";

        return new SecurityPostureSnapshot(
            score,
            threatLevel,
            integrity,
            exposure,
            lastFullScan,
            activeThreats,
            defender.RealTimeProtectionEnabled == true ? "ON" : "ATTENTION",
            blockedAsrControls,
            vulnerableFirewallProfiles);
    }

    private static async Task<DefenderStatus> ReadDefenderAsync(CancellationToken ct)
    {
        var script = @"
$status = Get-MpComputerStatus
$preference = Get-MpPreference
[pscustomobject]@{
  AntivirusEnabled = $status.AntivirusEnabled
  RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
  IoavProtectionEnabled = $status.IoavProtectionEnabled
  NISEnabled = $status.NISEnabled
  FullScanEndTime = $status.FullScanEndTime
  QuickScanEndTime = $status.QuickScanEndTime
  AttackSurfaceReductionRules_Actions = @($preference.AttackSurfaceReductionRules_Actions)
} | ConvertTo-Json -Compress
";

        var output = await RunPowerShellAsync(script, ct).ConfigureAwait(false);
        return JsonSerializer.Deserialize<DefenderStatus>(output) ?? new DefenderStatus();
    }

    private static async Task<string> RunPowerShellAsync(string script, CancellationToken ct)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-EncodedCommand");
        startInfo.ArgumentList.Add(encoded);

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("PowerShell launch failed.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = process.StandardError.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct).ConfigureAwait(false);
        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);

        if (process.ExitCode != 0)
        {
            var detail = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
            throw new InvalidOperationException(Trim(detail));
        }

        return stdout;
    }

    private static int CountBlockedAsrControls(JsonElement actions)
    {
        if (actions.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
        {
            return 0;
        }

        if (actions.ValueKind == JsonValueKind.Array)
        {
            var count = 0;
            foreach (var action in actions.EnumerateArray())
            {
                if (IsBlockedAsrAction(action))
                {
                    count++;
                }
            }

            return count;
        }

        return IsBlockedAsrAction(actions) ? 1 : 0;
    }

    private static bool IsBlockedAsrAction(JsonElement action)
    {
        return action.ValueKind switch
        {
            JsonValueKind.Number => action.TryGetInt32(out var numeric) && numeric == 1,
            JsonValueKind.String => IsBlockedAsrAction(action.GetString()),
            _ => false
        };
    }

    private static bool IsBlockedAsrAction(string? action)
    {
        return action?.Trim() switch
        {
            "1" => true,
            "Enabled" => true,
            "Block" => true,
            "BlockMode" => true,
            _ => false
        };
    }

    private static string Trim(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "no detail";
        }

        var normalized = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return normalized.Length <= 180 ? normalized : normalized[..180];
    }

    private sealed class DefenderStatus
    {
        public bool? AntivirusEnabled { get; set; }
        public bool? RealTimeProtectionEnabled { get; set; }
        public bool? IoavProtectionEnabled { get; set; }
        public bool? NISEnabled { get; set; }
        public DateTime? FullScanEndTime { get; set; }
        public DateTime? QuickScanEndTime { get; set; }
        public JsonElement AttackSurfaceReductionRules_Actions { get; set; }
    }
}

public sealed record SecurityPostureSnapshot(
    int SecurityScore,
    CyberThreatLevel ThreatLevel,
    int SystemIntegrityPercent,
    string NetworkExposure,
    string LastFullScan,
    int ActiveThreats,
    string DefenderRealtime,
    int AsrBlockedControls,
    int VulnerableFirewallProfiles);
