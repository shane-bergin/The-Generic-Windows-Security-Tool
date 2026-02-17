using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.Core.ServicesAnalysis
{
    public sealed class ServiceAnalyzerEngine
    {
        private static readonly HashSet<string> EssentialServiceNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "RpcSs", "EventLog", "WinDefend", "WdNisSvc", "Sense", "MpsSvc", "BFE",
            "Dhcp", "Dnscache", "NlaSvc", "Nsi", "PlugPlay", "DcomLaunch", "LSM",
            "SamSs", "Schedule", "Power", "LanmanWorkstation", "LanmanServer",
            "TermService", "TrustedInstaller", "W32Time", "ProfSvc", "CryptSvc",
            "Winmgmt", "WpnService", "CoreMessagingRegistrar"
        };

        private static readonly HashSet<string> CriticalCoreServiceNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "RpcSs", "EventLog", "WinDefend", "WdNisSvc", "Sense", "MpsSvc", "BFE",
            "Dhcp", "Dnscache", "NlaSvc", "DcomLaunch", "SamSs"
        };

        private static readonly IReadOnlyDictionary<string, ServiceGuidance> GuidanceByServiceName =
            new Dictionary<string, ServiceGuidance>(StringComparer.OrdinalIgnoreCase)
            {
                ["RpcSs"] = new(
                    HighImpact: true,
                    Purpose: "Remote Procedure Call fabric used by core Windows components.",
                    KeepEnabledReason: "Required by core OS service communication and component activation.",
                    DisableReason: "Do not disable during normal operation.",
                    Recommendation: "KEEP ENABLED: make/break core RPC dependency."),
                ["BFE"] = new(
                    HighImpact: true,
                    Purpose: "Base Filtering Engine for Windows firewall and IPSec policy.",
                    KeepEnabledReason: "Required for firewall enforcement and network security policy.",
                    DisableReason: "Disabling weakens or breaks firewall stack behavior.",
                    Recommendation: "KEEP ENABLED: make/break network security service."),
                ["MpsSvc"] = new(
                    HighImpact: true,
                    Purpose: "Windows Defender Firewall service.",
                    KeepEnabledReason: "Required to keep host firewall protection active.",
                    DisableReason: "Disable only in controlled test environments with alternate controls.",
                    Recommendation: "KEEP ENABLED: disabling reduces host security posture."),
                ["Dhcp"] = new(
                    HighImpact: true,
                    Purpose: "Dynamic address and network lease management.",
                    KeepEnabledReason: "Required for typical LAN/Wi-Fi IP configuration.",
                    DisableReason: "Disable only for fully static network setups.",
                    Recommendation: "KEEP ENABLED unless host is intentionally static-address only."),
                ["Dnscache"] = new(
                    HighImpact: true,
                    Purpose: "DNS Client resolver cache and name lookups.",
                    KeepEnabledReason: "Improves lookup performance and supports normal app resolution.",
                    DisableReason: "Disable only during specialized troubleshooting.",
                    Recommendation: "KEEP ENABLED: can impact network name resolution."),
                ["Wuauserv"] = new(
                    HighImpact: true,
                    Purpose: "Windows Update orchestration and patch servicing.",
                    KeepEnabledReason: "Required for OS security update cadence.",
                    DisableReason: "Disable only for controlled maintenance windows or offline images.",
                    Recommendation: "HIGH IMPACT: disabling blocks routine patching and can increase risk."),
                ["BITS"] = new(
                    HighImpact: true,
                    Purpose: "Background Intelligent Transfer Service for staged downloads.",
                    KeepEnabledReason: "Used by Windows Update and multiple enterprise agents.",
                    DisableReason: "Disable only if update/agent workflows are intentionally managed elsewhere.",
                    Recommendation: "HIGH IMPACT: can break update and management download pipelines."),
                ["DoSvc"] = new(
                    HighImpact: true,
                    Purpose: "Delivery Optimization for update/package download sharing.",
                    KeepEnabledReason: "Reduces update latency on managed or multi-device networks.",
                    DisableReason: "Can be disabled if bandwidth control policy requires strict direct download.",
                    Recommendation: "HIGH IMPACT: affects update behavior and bandwidth profile."),
                ["WSearch"] = new(
                    HighImpact: true,
                    Purpose: "Windows Search indexer for fast local and Outlook/mail search.",
                    KeepEnabledReason: "Keep enabled when fast start/menu/file/mail search is required.",
                    DisableReason: "Disable on low-resource systems where indexing overhead is measurable.",
                    Recommendation: "HIGH IMPACT: performance tradeoff service; disable only when search indexing is not needed."),
                ["SysMain"] = new(
                    HighImpact: true,
                    Purpose: "Memory and prefetch optimization based on app usage patterns.",
                    KeepEnabledReason: "Often helps launch latency on slower storage and mixed workloads.",
                    DisableReason: "Can be disabled if it causes disk churn/stutter on specific hardware profiles.",
                    Recommendation: "HIGH IMPACT: test before/after performance metrics before disabling."),
                ["Spooler"] = new(
                    HighImpact: true,
                    Purpose: "Print queue and print job broker service.",
                    KeepEnabledReason: "Required for local/network printing and print-to-PDF workflows.",
                    DisableReason: "Disable on machines that never print to reduce attack surface.",
                    Recommendation: "HIGH IMPACT: disable only when printing is not required."),
                ["DiagTrack"] = new(
                    HighImpact: true,
                    Purpose: "Connected User Experiences and diagnostics telemetry upload.",
                    KeepEnabledReason: "Supports diagnostic feedback and some support troubleshooting workflows.",
                    DisableReason: "Disable for privacy-hardening baselines where telemetry is minimized.",
                    Recommendation: "HIGH IMPACT: privacy/performance tradeoff; validate org policy before disabling."),
                ["TermService"] = new(
                    HighImpact: true,
                    Purpose: "Remote Desktop Services host/session broker.",
                    KeepEnabledReason: "Required for inbound RDP and remote admin workflows.",
                    DisableReason: "Disable on systems where remote desktop is prohibited.",
                    Recommendation: "HIGH IMPACT: disable only when remote desktop is intentionally unused."),
                ["LanmanServer"] = new(
                    HighImpact: true,
                    Purpose: "SMB server endpoint for file/print sharing.",
                    KeepEnabledReason: "Required for hosted SMB shares and remote management patterns.",
                    DisableReason: "Disable for hardened endpoints that do not host shares.",
                    Recommendation: "HIGH IMPACT: affects inbound file sharing and some admin tooling."),
                ["LanmanWorkstation"] = new(
                    HighImpact: true,
                    Purpose: "SMB client stack for network share access.",
                    KeepEnabledReason: "Required for normal domain/network share access.",
                    DisableReason: "Disable only on isolated systems with no SMB dependency.",
                    Recommendation: "HIGH IMPACT: can break mapped drives and enterprise workflows.")
            };

        private static readonly (string Prefix, ServiceGuidance Guidance)[] GuidanceByPrefix =
        {
            (
                "OneSyncSvc_",
                new ServiceGuidance(
                    HighImpact: false,
                    Purpose: "Per-user sync endpoint for mail/calendar/people data.",
                    KeepEnabledReason: "Keep enabled if built-in Mail/Calendar sync is used.",
                    DisableReason: "Disable on systems that do not use consumer sync features.",
                    Recommendation: "Optional service for consumer sync workloads.")),
            (
                "CDPUserSvc_",
                new ServiceGuidance(
                    HighImpact: false,
                    Purpose: "Connected Devices Platform per-user service for cross-device features.",
                    KeepEnabledReason: "Keep enabled for cross-device experiences and linked-device features.",
                    DisableReason: "Disable where cross-device features are intentionally not used.",
                    Recommendation: "Optional service tied to cross-device feature set."))
        };

        private readonly string _backupPath;
        private readonly object _backupSync = new();

        public ServiceAnalyzerEngine()
        {
            var basePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "TGWST",
                "Maintenance");
            Directory.CreateDirectory(basePath);
            _backupPath = Path.Combine(basePath, "ServiceStateBackup.json");
        }

        public Task<ServiceAnalysisSnapshot> AnalyzeAsync(CancellationToken ct = default)
        {
            return Task.Run(() =>
            {
                var items = new List<ServiceAnalysisItem>();
                using var searcher = new ManagementObjectSearcher(
                    "SELECT Name, DisplayName, State, StartMode, PathName FROM Win32_Service");
                foreach (ManagementObject svc in searcher.Get())
                {
                    ct.ThrowIfCancellationRequested();
                    using (svc)
                    {
                        var item = CreateAnalysisItem(svc);
                        items.Add(item);
                    }
                }

                var ordered = items
                    .OrderBy(x => x.Essential)
                    .ThenByDescending(x => x.HighImpact)
                    .ThenBy(x => x.DisplayName, StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                return new ServiceAnalysisSnapshot(ordered, DateTime.UtcNow);
            }, ct);
        }

        public async Task<ServiceActionResult> DisableAsync(string serviceName, CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(serviceName))
            {
                return new ServiceActionResult(false, "Service name is required.");
            }

            var normalized = serviceName.Trim();
            var service = await GetServiceAsync(normalized, ct).ConfigureAwait(false);
            if (service == null)
            {
                return new ServiceActionResult(false, $"Service '{normalized}' was not found.");
            }

            if (service.Essential)
            {
                return new ServiceActionResult(false, "This service is protected as essential and cannot be disabled.");
            }

            try
            {
                var startupType = await GetStartupTypeAsync(normalized, ct).ConfigureAwait(false);
                var wasRunning = IsRunning(normalized);

                SaveBackupRecord(new ServiceStateBackupRecord(
                    ServiceName: normalized,
                    StartupType: startupType,
                    WasRunning: wasRunning,
                    SavedAtUtc: DateTime.UtcNow));

                StopServiceBestEffort(normalized);
                ChangeStartMode(normalized, "Disabled");
                return new ServiceActionResult(true, $"Service '{normalized}' disabled successfully.");
            }
            catch (Exception ex)
            {
                return new ServiceActionResult(false, $"Failed to disable '{normalized}': {ex.Message}");
            }
        }

        public Task<ServiceActionResult> RestoreAsync(string serviceName, CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(serviceName))
            {
                return Task.FromResult(new ServiceActionResult(false, "Service name is required."));
            }

            var normalized = serviceName.Trim();
            var backup = GetBackupRecord(normalized);
            if (backup == null)
            {
                return Task.FromResult(new ServiceActionResult(
                    false,
                    $"No backup exists for service '{normalized}'."));
            }

            try
            {
                ct.ThrowIfCancellationRequested();
                ChangeStartMode(normalized, backup.StartupType);

                if (backup.WasRunning)
                {
                    StartServiceBestEffort(normalized);
                }

                return Task.FromResult(new ServiceActionResult(true, $"Service '{normalized}' restored."));
            }
            catch (OperationCanceledException)
            {
                return Task.FromResult(new ServiceActionResult(false, "Restore canceled."));
            }
            catch (Exception ex)
            {
                return Task.FromResult(new ServiceActionResult(
                    false,
                    $"Failed to restore '{normalized}': {ex.Message}"));
            }
        }

        private static ServiceAnalysisItem CreateAnalysisItem(ManagementObject svc)
        {
            var name = ReadString(svc, "Name");
            var displayName = ReadString(svc, "DisplayName");
            var status = NormalizeStatus(ReadString(svc, "State"));
            var startMode = NormalizeStartupMode(ReadString(svc, "StartMode"));
            var path = ReadString(svc, "PathName");
            var origin = DetectOrigin(path);
            var guidance = ResolveGuidance(name);

            var essential = IsEssential(name, origin);
            var highImpact = (guidance?.HighImpact ?? false) || CriticalCoreServiceNames.Contains(name);
            var reason = BuildReason(essential, highImpact, origin, status, startMode);
            var stateNote = BuildStateNote(essential, status, startMode);
            var purpose = BuildPurpose(guidance, origin, essential);
            var keepEnabledReason = BuildKeepEnabledReason(guidance, essential, origin);
            var disableReason = BuildDisableReason(guidance, essential, origin);
            var recommendation = BuildRecommendation(guidance, essential, highImpact, status, startMode);

            return new ServiceAnalysisItem(
                ServiceName: name,
                DisplayName: string.IsNullOrWhiteSpace(displayName) ? name : displayName,
                Status: status,
                StartupType: startMode,
                Origin: origin,
                Essential: essential,
                Reason: reason,
                StateNote: stateNote,
                HighImpact: highImpact,
                Purpose: purpose,
                KeepEnabledReason: keepEnabledReason,
                DisableReason: disableReason,
                Recommendation: recommendation);
        }

        private static string ReadString(ManagementBaseObject obj, string property)
        {
            try
            {
                var value = obj[property];
                return value?.ToString()?.Trim() ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        private static bool IsEssential(string serviceName, string origin)
        {
            if (EssentialServiceNames.Contains(serviceName))
            {
                return true;
            }

            if (origin.Equals("Microsoft/OS", StringComparison.OrdinalIgnoreCase) &&
                (serviceName.StartsWith("Wpn", StringComparison.OrdinalIgnoreCase) ||
                 serviceName.StartsWith("Win", StringComparison.OrdinalIgnoreCase) ||
                 serviceName.StartsWith("Security", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            return false;
        }

        private static string DetectOrigin(string imagePath)
        {
            if (string.IsNullOrWhiteSpace(imagePath))
            {
                return "Unknown";
            }

            var lower = imagePath.ToLowerInvariant();
            if (lower.Contains(@"\windows\system32\") ||
                lower.Contains(@"\windows\syswow64\") ||
                lower.Contains("microsoft"))
            {
                return "Microsoft/OS";
            }

            return "Third-Party";
        }

        private static string BuildReason(bool essential, bool highImpact, string origin, string status, string startupType)
        {
            if (essential)
            {
                return "Core OS/security/network dependency. Protected from disable.";
            }

            if (highImpact)
            {
                return "High-impact optional service; disabling can materially change performance or platform behavior.";
            }

            if (startupType.Equals("Disabled", StringComparison.OrdinalIgnoreCase))
            {
                return "Non-essential and startup is already disabled.";
            }

            if (origin.Equals("Third-Party", StringComparison.OrdinalIgnoreCase) &&
                startupType.Equals("Automatic", StringComparison.OrdinalIgnoreCase))
            {
                return "Third-party auto-start service; often non-essential for core OS operation.";
            }

            if (origin.Equals("Third-Party", StringComparison.OrdinalIgnoreCase))
            {
                return "Third-party service; typically optional depending on installed app usage.";
            }

            if (status.Equals("Running", StringComparison.OrdinalIgnoreCase))
            {
                return "Non-essential service is currently running; validate feature dependency before disabling.";
            }

            if (status.Equals("Stopped", StringComparison.OrdinalIgnoreCase))
            {
                return "Currently stopped and not required for active baseline behavior.";
            }

            return "Not in protected core set; validate before disabling.";
        }

        private static string BuildStateNote(bool essential, string status, string startupType)
        {
            if (startupType.Equals("Disabled", StringComparison.OrdinalIgnoreCase) &&
                status.Equals("Running", StringComparison.OrdinalIgnoreCase))
            {
                return "Startup disabled, currently active until restart.";
            }

            if (startupType.Equals("Disabled", StringComparison.OrdinalIgnoreCase))
            {
                return "Startup disabled.";
            }

            if (status.Equals("Running", StringComparison.OrdinalIgnoreCase))
            {
                return essential ? "Running (core)." : "Running (non-essential).";
            }

            if (status.Equals("Stopped", StringComparison.OrdinalIgnoreCase))
            {
                return essential ? "Stopped (core/on-demand)." : "Stopped.";
            }

            return status;
        }

        private static string BuildPurpose(ServiceGuidance? guidance, string origin, bool essential)
        {
            if (guidance != null)
            {
                return guidance.Purpose;
            }

            if (essential)
            {
                return "Supports core Windows platform behavior and service dependencies.";
            }

            if (origin.Equals("Third-Party", StringComparison.OrdinalIgnoreCase))
            {
                return "Provides feature support for an installed third-party application.";
            }

            return "Provides an optional Windows subsystem or feature capability.";
        }

        private static string BuildKeepEnabledReason(ServiceGuidance? guidance, bool essential, string origin)
        {
            if (guidance != null)
            {
                return guidance.KeepEnabledReason;
            }

            if (essential)
            {
                return "Keep enabled to preserve system stability and core security/network workflows.";
            }

            if (origin.Equals("Third-Party", StringComparison.OrdinalIgnoreCase))
            {
                return "Keep enabled while the owning application feature is in active use.";
            }

            return "Keep enabled when the related Windows feature is used in your workflow.";
        }

        private static string BuildDisableReason(ServiceGuidance? guidance, bool essential, string origin)
        {
            if (guidance != null)
            {
                return guidance.DisableReason;
            }

            if (essential)
            {
                return "Do not disable in normal operation.";
            }

            if (origin.Equals("Third-Party", StringComparison.OrdinalIgnoreCase))
            {
                return "Disable when the associated app or feature is not needed.";
            }

            return "Disable only after validating no dependency on the feature.";
        }

        private static string BuildRecommendation(
            ServiceGuidance? guidance,
            bool essential,
            bool highImpact,
            string status,
            string startupType)
        {
            if (guidance != null)
            {
                return guidance.Recommendation;
            }

            if (essential)
            {
                return "KEEP ENABLED: protected core service.";
            }

            if (highImpact)
            {
                return "HIGH IMPACT: review workload and dependency before disabling.";
            }

            if (startupType.Equals("Disabled", StringComparison.OrdinalIgnoreCase))
            {
                return "Already disabled at startup; keep disabled unless the feature is required.";
            }

            if (status.Equals("Running", StringComparison.OrdinalIgnoreCase))
            {
                return "Disable only if feature usage is confirmed unnecessary.";
            }

            return "Candidate for disable when unused.";
        }

        private static string NormalizeStartupMode(string startMode)
        {
            if (string.IsNullOrWhiteSpace(startMode))
            {
                return "Unknown";
            }

            return startMode.Trim() switch
            {
                "Auto" => "Automatic",
                "Manual" => "Manual",
                "Disabled" => "Disabled",
                _ => startMode.Trim()
            };
        }

        private static string NormalizeStatus(string state)
        {
            if (string.IsNullOrWhiteSpace(state))
            {
                return "Unknown";
            }

            var normalized = state.Trim();
            return normalized switch
            {
                "Start Pending" => "StartPending",
                "Stop Pending" => "StopPending",
                _ => normalized
            };
        }

        private static bool IsRunning(string serviceName)
        {
            using var controller = new ServiceController(serviceName);
            return controller.Status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending;
        }

        private static void StopServiceBestEffort(string serviceName)
        {
            using var controller = new ServiceController(serviceName);
            if (controller.Status == ServiceControllerStatus.Stopped ||
                controller.Status == ServiceControllerStatus.StopPending)
            {
                return;
            }

            controller.Stop();
            controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20));
        }

        private static void StartServiceBestEffort(string serviceName)
        {
            using var controller = new ServiceController(serviceName);
            if (controller.Status == ServiceControllerStatus.Running ||
                controller.Status == ServiceControllerStatus.StartPending)
            {
                return;
            }

            controller.Start();
            controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20));
        }

        private static void ChangeStartMode(string serviceName, string startupType)
        {
            var mode = startupType switch
            {
                "Automatic" => "Automatic",
                "Manual" => "Manual",
                "Disabled" => "Disabled",
                _ => startupType
            };

            using var service = new ManagementObject($"Win32_Service.Name='{EscapeWmiString(serviceName)}'");
            var result = service.InvokeMethod("ChangeStartMode", new object[] { mode });
            if (result != null)
            {
                var code = Convert.ToUInt32(result);
                if (code != 0)
                {
                    throw new InvalidOperationException($"ChangeStartMode returned code {code}.");
                }
            }
        }

        private async Task<ServiceAnalysisItem?> GetServiceAsync(string serviceName, CancellationToken ct)
        {
            var snapshot = await AnalyzeAsync(ct).ConfigureAwait(false);
            return snapshot.Services.FirstOrDefault(x =>
                string.Equals(x.ServiceName, serviceName, StringComparison.OrdinalIgnoreCase));
        }

        private static Task<string> GetStartupTypeAsync(string serviceName, CancellationToken ct)
        {
            return Task.Run(() =>
            {
                ct.ThrowIfCancellationRequested();
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT StartMode FROM Win32_Service WHERE Name='{EscapeWmiString(serviceName)}'");
                foreach (ManagementObject svc in searcher.Get())
                {
                    using (svc)
                    {
                        var mode = NormalizeStartupMode(ReadString(svc, "StartMode"));
                        if (!string.IsNullOrWhiteSpace(mode))
                        {
                            return mode;
                        }
                    }
                }

                return "Manual";
            }, ct);
        }

        private void SaveBackupRecord(ServiceStateBackupRecord record)
        {
            lock (_backupSync)
            {
                var all = LoadBackupState();
                all[record.ServiceName] = record;
                var json = JsonSerializer.Serialize(all, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_backupPath, json);
            }
        }

        private ServiceStateBackupRecord? GetBackupRecord(string serviceName)
        {
            lock (_backupSync)
            {
                var all = LoadBackupState();
                return all.TryGetValue(serviceName, out var record) ? record : null;
            }
        }

        private Dictionary<string, ServiceStateBackupRecord> LoadBackupState()
        {
            if (!File.Exists(_backupPath))
            {
                return new Dictionary<string, ServiceStateBackupRecord>(StringComparer.OrdinalIgnoreCase);
            }

            try
            {
                var json = File.ReadAllText(_backupPath);
                var parsed = JsonSerializer.Deserialize<Dictionary<string, ServiceStateBackupRecord>>(json);
                return parsed != null
                    ? new Dictionary<string, ServiceStateBackupRecord>(parsed, StringComparer.OrdinalIgnoreCase)
                    : new Dictionary<string, ServiceStateBackupRecord>(StringComparer.OrdinalIgnoreCase);
            }
            catch
            {
                return new Dictionary<string, ServiceStateBackupRecord>(StringComparer.OrdinalIgnoreCase);
            }
        }

        private static string EscapeWmiString(string value)
        {
            return (value ?? string.Empty).Replace("\\", "\\\\").Replace("'", "\\'");
        }

        private static ServiceGuidance? ResolveGuidance(string serviceName)
        {
            if (GuidanceByServiceName.TryGetValue(serviceName, out var guidance))
            {
                return guidance;
            }

            foreach (var item in GuidanceByPrefix)
            {
                if (serviceName.StartsWith(item.Prefix, StringComparison.OrdinalIgnoreCase))
                {
                    return item.Guidance;
                }
            }

            return null;
        }

        private sealed record ServiceGuidance(
            bool HighImpact,
            string Purpose,
            string KeepEnabledReason,
            string DisableReason,
            string Recommendation);
    }
}
