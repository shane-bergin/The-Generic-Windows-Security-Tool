using System;
using System.Collections.Generic;
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
    private const string MinimumDefenderEngineVersion = "1.1.26050.11";
    private const string MinimumDefenderPlatformVersion = "4.18.26050.15";
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
        string? defenderReadError = null;
        try
        {
            defender = await defenderTask.ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            defender = new DefenderStatus();
            defenderReadError = Trim(ex.Message);
        }

        var vulnerableFirewallProfiles = 0;
        var firewallStatusAvailable = false;
        string? firewallReadError = null;
        try
        {
            var profiles = await firewallTask.ConfigureAwait(false);
            if (profiles.Count == 0)
            {
                firewallReadError = "no firewall profiles were returned";
            }
            else
            {
                vulnerableFirewallProfiles = profiles.Count(profile => profile.IsVulnerable);
                firewallStatusAvailable = true;
            }
        }
        catch (Exception ex)
        {
            firewallReadError = Trim(ex.Message);
        }

        var blockedAsrControls = CountBlockedAsrControls(defender.AttackSurfaceReductionRules_Actions);
        var defenderStatusAvailable = defender.HasAnyData;
        var defenderEvidenceComplete = defender.HasCoreData;
        var asrStatusAvailable = defender.AttackSurfaceReductionRules_Actions.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null);
        var findings = new List<DashboardFindingRow>();
        var deductions = new List<string>();

        var score = 100;
        DeductIf(
            !defenderStatusAvailable,
            5,
            "WARN",
            "Collection",
            "Microsoft Defender posture is unknown because status collection returned no usable data.",
            $"Refresh with sufficient permissions or inspect Windows Security directly. Missing evidence is not proof that Defender is disabled{(string.IsNullOrWhiteSpace(defenderReadError) ? "." : $" ({defenderReadError}).")}");
        DeductIf(
            defenderStatusAvailable && !defenderEvidenceComplete,
            3,
            "WARN",
            "Collection",
            "Microsoft Defender returned only partial posture evidence.",
            "Refresh with sufficient permissions and verify missing values directly. TGWST will not infer that an absent field is disabled.");
        DeductIf(
            !firewallStatusAvailable,
            5,
            "WARN",
            "Collection",
            "Windows Firewall posture is unknown because profile collection did not return a reliable profile set.",
            $"Refresh or inspect Windows Defender Firewall with Advanced Security{(string.IsNullOrWhiteSpace(firewallReadError) ? "." : $" ({firewallReadError}).")}");
        DeductIf(defender.AntivirusEnabled == false, 25, "CRITICAL", "Defender", "Microsoft Defender antivirus is not reporting enabled.", "Open Windows Security and restore antivirus protection.");
        DeductIf(defender.RealTimeProtectionEnabled == false, 25, "CRITICAL", "Defender", "Realtime protection is not reporting enabled.", "Open Windows Security or run a Defender quick scan.");
        DeductIf(defender.IoavProtectionEnabled == false, 10, "WARN", "Defender", "Internet/file download inspection is not reporting enabled.", "Review Microsoft Defender protection settings.");
        DeductIf(!string.IsNullOrWhiteSpace(defender.AMEngineVersion) && !VersionAtLeast(defender.AMEngineVersion, MinimumDefenderEngineVersion), 15, "CRITICAL", "Defender", $"Defender engine is below the configured baseline {MinimumDefenderEngineVersion}.", "Run Update-MpSignature or Windows Update.");
        DeductIf(!string.IsNullOrWhiteSpace(defender.AMProductVersion) && !VersionAtLeast(defender.AMProductVersion, MinimumDefenderPlatformVersion), 15, "CRITICAL", "Defender", $"Defender platform is below the configured baseline {MinimumDefenderPlatformVersion}.", "Run Windows Update or Defender platform update.");
        DeductIf(defender.IsTamperProtected == false, 10, "WARN", "Defender", "Defender Tamper Protection is not reporting enabled.", "Enable Tamper Protection in Windows Security where policy allows it.");
        DeductIf(firewallStatusAvailable && vulnerableFirewallProfiles > 0, Math.Min(30, vulnerableFirewallProfiles * 15), "CRITICAL", "Firewall", $"{vulnerableFirewallProfiles} firewall profile(s) need review.", "Use Enable Firewall or open Advanced Firewall.");
        DeductIf(asrStatusAvailable && blockedAsrControls < 8, 10, "WARN", "ASR", $"Only {blockedAsrControls} ASR rule(s) are in Block mode (baseline target is at least 8).", "Review ASR hardening in Windows Security.");
        if (network != null)
        {
            DeductIf(network.HighestRiskScore > 0, Math.Min(25, network.HighestRiskScore / 4), "WARN", "Network", $"Highest network risk score is {network.HighestRiskScore}/100.", "Open the Network tab, select the exact row, inspect it, then use Block process or Block remote if appropriate.");
        }

        DeductIf(recentCriticalTelemetry > 0, Math.Min(20, recentCriticalTelemetry * 10), "CRITICAL", "Telemetry", $"{recentCriticalTelemetry} critical telemetry signal(s) were seen in the last 10 minutes.", "Open Telemetry and inspect recent critical events.");
        score = Math.Clamp(score, 0, 100);

        var threatLevel = score < 60 || recentCriticalTelemetry > 0
            ? CyberThreatLevel.Critical
            : score < 82 || (network?.HighestRiskScore ?? 0) >= 60
                ? CyberThreatLevel.Elevated
                : CyberThreatLevel.Normal;

        var integrityAdjustment = defender.RealTimeProtectionEnabled switch
        {
            true => 5,
            false => -10,
            null => 0
        };
        var integrity = Math.Clamp(score + integrityAdjustment, 0, 100);
        var exposure = network == null
            ? "UNKNOWN"
            : network.HighestRiskScore >= 70
                ? "HIGH"
                : network.HighestRiskScore >= 35
                    ? "ELEVATED"
                    : "LOW";
        var activeThreats = (network?.RiskyConnections.Count(row => row.RiskScore >= 70) ?? 0) + recentCriticalTelemetry;
        var lastFullScan = defender.FullScanEndTime?.ToLocalTime().ToString("yyyy-MM-dd HH:mm") ?? "unknown";
        if (findings.Count == 0)
        {
            findings.Add(BuildFinding("INFO", "Posture", "No posture deductions are currently active.", "Continue monitoring and refresh after material system changes."));
        }

        return new SecurityPostureSnapshot(
            score,
            threatLevel,
            integrity,
            exposure,
            lastFullScan,
            activeThreats,
            defender.RealTimeProtectionEnabled switch
            {
                true => "ON",
                false => "OFF",
                null => "UNKNOWN"
            },
            blockedAsrControls,
            vulnerableFirewallProfiles,
            deductions.Count == 0
                ? "Score is at full strength. No posture deductions were applied."
                : $"Score starts at 100. Deductions applied: {string.Join("; ", deductions)}.",
            score < 60 || recentCriticalTelemetry > 0
                ? $"Critical because score is {score}/100 or recent critical telemetry is present ({recentCriticalTelemetry})."
                : $"Threat level follows score and network risk. Highest network risk is {network?.HighestRiskScore ?? 0}/100.",
            defender.RealTimeProtectionEnabled == true
                ? "Integrity is anchored by the score, with a small boost because realtime protection is on."
                : defender.RealTimeProtectionEnabled == false
                    ? "Integrity is below the score because Defender realtime protection is reporting off."
                    : "Integrity has no Defender adjustment because realtime protection state is unknown.",
            network == null
                ? "Network exposure is unknown until the network poller has a snapshot."
                : $"Exposure is based on highest network risk ({network.HighestRiskScore}/100), {network.InboundExposure} inbound exposure(s), and {network.OutboundConnections} outbound session(s).",
            !defenderStatusAvailable
                ? "Defender posture is unknown because TGWST could not collect usable status data. Missing evidence is not treated as a disabled control."
                : defender.RealTimeProtectionEnabled == true && VersionAtLeast(defender.AMEngineVersion, MinimumDefenderEngineVersion) && VersionAtLeast(defender.AMProductVersion, MinimumDefenderPlatformVersion)
                ? $"Defender realtime is on and platform/engine meet the June 2026 baseline ({defender.AMProductVersion}/{defender.AMEngineVersion})."
                : $"Defender needs review: realtime={defender.RealTimeProtectionEnabled}, platform={defender.AMProductVersion ?? "unknown"}, engine={defender.AMEngineVersion ?? "unknown"}.",
            !asrStatusAvailable
                ? "ASR posture is unknown because Defender did not return ASR action data."
                : blockedAsrControls >= 8
                ? $"{blockedAsrControls} ASR controls are blocked, meeting the dashboard hardening baseline."
                : $"{blockedAsrControls} ASR controls are blocked; dashboard expects at least 8 for a hardened baseline.",
            !firewallStatusAvailable
                ? "Firewall posture is unknown because TGWST could not collect a reliable effective profile set."
                : vulnerableFirewallProfiles == 0
                ? "Firewall profiles are reporting inbound blocking."
                : $"{vulnerableFirewallProfiles} firewall profile(s) need review or enablement.",
            findings);

        void DeductIf(bool condition, int amount, string severity, string area, string detail, string action)
        {
            if (!condition || amount <= 0)
            {
                return;
            }

            score -= amount;
            deductions.Add($"{area} -{amount}");
            findings.Add(BuildFinding(severity, area, detail, action));
        }
    }

    private static DashboardFindingRow BuildFinding(
        string severity,
        string area,
        string detail,
        string recommendedAction)
    {
        return area switch
        {
            "Collection" => new DashboardFindingRow(
                severity,
                area,
                detail,
                recommendedAction,
                "A required posture source returned no reliable effective-state evidence.",
                "TGWST coverage is degraded. The control may be healthy or unhealthy, so this row is not a failure verdict.",
                Verification: "Refresh after restoring permissions or inspect the named Windows control surface directly."),
            "Firewall" => new DashboardFindingRow(
                severity,
                area,
                detail,
                recommendedAction,
                "TGWST read the ActiveStore firewall profiles and found a disabled profile or a default inbound action other than Block.",
                "Unsolicited inbound traffic may reach a listening service. Existing explicit allow and block rules still affect effective exposure.",
                DashboardFindingAction.ApplyFirewallBaseline,
                "apply firewall baseline",
                "Enables all firewall profiles and sets default inbound blocking. It does not disable existing rules or weaken a stricter outbound-block policy.",
                "After UAC completion TGWST refreshes ActiveStore profile state. Review explicit inbound allow rules separately.",
                RequiresElevation: true),
            "Defender" => new DashboardFindingRow(
                severity,
                area,
                detail,
                recommendedAction,
                "TGWST compared Get-MpComputerStatus effective state with its configured posture expectations.",
                "Reduced or outdated Defender coverage can increase execution and persistence risk. Managed policy or Tamper Protection can affect remediation.",
                Verification: "Confirm the effective value in Windows Security or Get-MpComputerStatus after making a targeted change."),
            "ASR" => new DashboardFindingRow(
                severity,
                area,
                detail,
                recommendedAction,
                "TGWST counted ASR actions currently reported in block mode.",
                "Fewer block-mode rules can mean less preventive coverage, but applicability and business compatibility must be assessed per rule.",
                Verification: "Review each rule ID, policy source, and Defender Operational audit events before moving a rule to block mode."),
            "Network" => new DashboardFindingRow(
                severity,
                area,
                detail,
                recommendedAction,
                "This is a heuristic score based on socket ownership, ports, addressing, and listener state; it is not a malware verdict or confirmed traffic direction.",
                "Blocking a legitimate endpoint or process can interrupt applications, updates, VPNs, or Windows services.",
                Verification: "Select the exact Network row and validate process identity, endpoint ownership, and expected application behavior before containment."),
            "Telemetry" => new DashboardFindingRow(
                severity,
                area,
                detail,
                recommendedAction,
                "The count comes from recent in-session telemetry rows classified Critical by a heuristic rule.",
                "A true positive may indicate active execution or persistence; weak signals require corroboration before destructive response.",
                Verification: "Correlate process ancestry, signer/path, Defender history, and Windows event evidence."),
            _ => new DashboardFindingRow(
                severity,
                area,
                detail,
                recommendedAction,
                "This row summarizes the most recent TGWST posture snapshot.",
                "No single dashboard snapshot proves that a system is clean.",
                Verification: "Continue monitoring and refresh after security or policy changes.")
        };
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
  AMProductVersion = $status.AMProductVersion
  AMEngineVersion = $status.AMEngineVersion
  IsTamperProtected = $status.IsTamperProtected
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

    private static bool VersionAtLeast(string? current, string minimum)
    {
        return Version.TryParse(current, out var currentVersion) &&
               Version.TryParse(minimum, out var minimumVersion) &&
               currentVersion >= minimumVersion;
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
        public string? AMProductVersion { get; set; }
        public string? AMEngineVersion { get; set; }
        public bool? IsTamperProtected { get; set; }
        public DateTime? FullScanEndTime { get; set; }
        public DateTime? QuickScanEndTime { get; set; }
        public JsonElement AttackSurfaceReductionRules_Actions { get; set; }

        public bool HasAnyData =>
            AntivirusEnabled.HasValue ||
            RealTimeProtectionEnabled.HasValue ||
            IoavProtectionEnabled.HasValue ||
            NISEnabled.HasValue ||
            IsTamperProtected.HasValue ||
            !string.IsNullOrWhiteSpace(AMProductVersion) ||
            !string.IsNullOrWhiteSpace(AMEngineVersion) ||
            AttackSurfaceReductionRules_Actions.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null);

        public bool HasCoreData =>
            AntivirusEnabled.HasValue &&
            RealTimeProtectionEnabled.HasValue &&
            IoavProtectionEnabled.HasValue &&
            IsTamperProtected.HasValue &&
            !string.IsNullOrWhiteSpace(AMProductVersion) &&
            !string.IsNullOrWhiteSpace(AMEngineVersion) &&
            AttackSurfaceReductionRules_Actions.ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null);
    }

    // === Security Profile System (WDAC + ASR + Firewall) ===
    public enum SecurityProfile
    {
        Balanced,
        Hardened
    }

    public async Task<string> ApplySecurityProfileAsync(SecurityProfile profile, CancellationToken ct = default)
    {
        await Task.CompletedTask;
        ct.ThrowIfCancellationRequested();
        throw new NotSupportedException(
            $"The {profile} profile is staged but unavailable until TGWST can preview, apply, independently verify, and roll back each control.");
    }

    public string[] GetAvailableProfiles() => Enum.GetNames(typeof(SecurityProfile));

    private static string BuildSecurityProfileScript(string profileName, bool enforceStrictFirewall)
    {
        var firewallPolicy = enforceStrictFirewall
            ? "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound | Out-Null"
            : string.Empty;

        return $@"
$ErrorActionPreference = 'Continue'
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
Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableArchiveScanning $false -ErrorAction SilentlyContinue
Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction SilentlyContinue
Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
foreach ($ruleId in $asrRuleIds) {{
    Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled -ErrorAction SilentlyContinue
}}
netsh advfirewall set allprofiles state on | Out-Null
{firewallPolicy}
'{profileName} profile applied: Defender realtime/IOAV/cloud/PUA protections requested, 19 ASR rules requested, firewall profiles enabled{(enforceStrictFirewall ? ", default inbound blocked" : string.Empty)}.'";
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
    int VulnerableFirewallProfiles,
    string SecurityScoreExplanation,
    string ThreatExplanation,
    string IntegrityExplanation,
    string NetworkExposureExplanation,
    string DefenderExplanation,
    string AsrExplanation,
    string FirewallExplanation,
    IReadOnlyList<DashboardFindingRow> Findings);
