using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using TGWST.App.Services;
using TGWST.App.ViewModels;
using TGWST.App.Shell;
using TGWST.Core.Network;
using TGWST.Core.Network.Capture;
using TGWST.Core.Network.Hybrid;

namespace TGWST.App.Shell.Commands
{
    public sealed class NetworkCommand : ICommandHandler
    {
        private readonly TaskOutputService _outputService;
        private readonly IWslHybridAnalyzer _wslHybrid;
        private readonly HybridModeService _hybridMode;
        private readonly WslCredentialService _wslCredentials;
        private readonly PiHoleBridgeService _piHole;
        private readonly NetworkSecurityEngine _engine = new();
        private readonly FirewallStatusService _firewall = new();
        private readonly ConnectionMonitor _monitor = new();

        public NetworkCommand(
            TaskOutputService outputService,
            IWslHybridAnalyzer wslHybrid,
            HybridModeService hybridMode,
            WslCredentialService wslCredentials,
            PiHoleBridgeService piHole)
        {
            _outputService = outputService;
            _wslHybrid = wslHybrid;
            _hybridMode = hybridMode;
            _wslCredentials = wslCredentials;
            _piHole = piHole;
        }

        public string Name => "network";
        public string[] Aliases => Array.Empty<string>();

        public Task ExecuteAsync(string args, ShellViewModel vm)
        {
            var trimmed = (args ?? string.Empty).Trim();
            var sub = trimmed.ToLowerInvariant();

            if (sub == "board" || sub == "features")
            {
                return ShowFeatureBoardAsync(vm);
            }

            if (sub.StartsWith("feature", StringComparison.Ordinal))
            {
                var featureArgs = trimmed.Length <= "feature".Length
                    ? string.Empty
                    : trimmed["feature".Length..].Trim();
                return RunFeatureCommandAsync(featureArgs, vm);
            }

            if (sub == "quick" || sub == "start")
            {
                return RunQuickStartAsync(vm);
            }

            if (sub == "setup")
            {
                return RunSetupAsync(vm);
            }

            if (sub == "baseline")
            {
                return RunBaselineAsync(vm);
            }

            if (sub == "live")
            {
                return RunLiveEnhancedAsync(vm);
            }

            if (sub == "live-legacy")
            {
                return RunLiveLegacyAsync(vm);
            }

            if (sub == "stats")
            {
                return RunStatsAsync(vm);
            }

            if (sub.StartsWith("pihole", StringComparison.Ordinal))
            {
                var piHoleArgs = trimmed.Length <= "pihole".Length
                    ? string.Empty
                    : trimmed["pihole".Length..].Trim();
                return RunPiHoleCommandAsync(piHoleArgs, vm);
            }

            if (sub.StartsWith("hybrid", StringComparison.Ordinal))
            {
                var hybridArgs = trimmed.Length <= "hybrid".Length
                    ? string.Empty
                    : trimmed["hybrid".Length..].Trim();
                return RunHybridCommandAsync(hybridArgs, vm);
            }

            vm.AddOutput("Usage: network board | network feature | network quick | network setup | network baseline | network live | network stats | network pihole | network hybrid\n");
            vm.AddOutput("  board       - ASCII control board with status checkboxes\n");
            vm.AddOutput("  feature     - Toggle features: hybrid / pihole on/off\n");
            vm.AddOutput("  quick       - Recommended: show board and start live monitor\n");
            vm.AddOutput("  setup       - Full configuration/status check board\n");
            vm.AddOutput("  baseline    - Firewall and listening-port snapshot\n");
            vm.AddOutput("  live        - Live connection and bandwidth monitor\n");
            vm.AddOutput("  stats       - Historical network usage summary\n");
            vm.AddOutput("  pihole      - Pi-hole DNS controls (WSL)\n");
            vm.AddOutput("  hybrid      - Linux analytics controls (WSL)\n");
            return Task.CompletedTask;
        }

        private async Task RunFeatureCommandAsync(string args, ShellViewModel vm)
        {
            var tail = (args ?? string.Empty).Trim();
            if (tail.Length == 0 || string.Equals(tail, "status", StringComparison.OrdinalIgnoreCase))
            {
                await ShowFeatureBoardAsync(vm);
                return;
            }

            var actionSplit = tail.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            if (actionSplit.Length == 0)
            {
                await ShowFeatureBoardAsync(vm);
                return;
            }

            var action = actionSplit[0].ToLowerInvariant();
            var targetPart = actionSplit.Length > 1 ? actionSplit[1].Trim() : string.Empty;
            if (string.IsNullOrWhiteSpace(targetPart))
            {
                vm.AddOutput("Usage: network feature [status|enable|disable] [hybrid|pihole] [value]\n");
                return;
            }

            var targetSplit = targetPart.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            var target = targetSplit[0].ToLowerInvariant();
            var value = targetSplit.Length > 1 ? targetSplit[1].Trim() : string.Empty;

            switch (action)
            {
                case "enable":
                case "on":
                {
                    if (target == "hybrid")
                    {
                        var hybridArgs = string.IsNullOrWhiteSpace(value) ? "enable" : $"enable {value}";
                        await RunHybridCommandAsync(hybridArgs, vm);
                        await ShowFeatureBoardAsync(vm);
                        return;
                    }

                    if (target == "pihole")
                    {
                        await RunPiHoleCommandAsync("enable", vm);
                        await ShowFeatureBoardAsync(vm);
                        return;
                    }

                    break;
                }
                case "disable":
                case "off":
                {
                    if (target == "hybrid")
                    {
                        await RunHybridCommandAsync("disable", vm);
                        await ShowFeatureBoardAsync(vm);
                        return;
                    }

                    if (target == "pihole")
                    {
                        var piArgs = string.IsNullOrWhiteSpace(value) ? "disable" : $"disable {value}";
                        await RunPiHoleCommandAsync(piArgs, vm);
                        await ShowFeatureBoardAsync(vm);
                        return;
                    }

                    break;
                }
            }

            vm.AddOutput("Usage: network feature [status|enable|disable] [hybrid|pihole] [value]\n");
        }

        private async Task ShowFeatureBoardAsync(ShellViewModel vm)
        {
            var state = await CaptureFeatureStateAsync();

            vm.AddOutput("[>]  _______  _____ _       _______    _   ____  ____   ___   ____   ____  \n");
            vm.AddOutput("[>] |__   __|/ ____| |     |__   __|  | | |  _ \\|  _ \\ / _ \\ / ___| |  _ \\ \n");
            vm.AddOutput("[>]    | |  | |  __| |        | | __ | | | |_) | |_) | | | | |  _  | | | |\n");
            vm.AddOutput("[>]    | |  | | |_ | |        | |/ _` | | |  _ <|  _ <| |_| | |_| | | |_| |\n");
            vm.AddOutput("[>]    |_|   \\_____|_|        |_|\\__,_|_| |_| \\_\\_| \\_\\\\___/ \\____| |____/ \n");
            vm.AddOutput("[>]                               FEATURE CONTROL BOARD                      \n");
            vm.AddOutput("\n");

            vm.AddOutput("╔═══════════════════════════════════════════════════════════════════════════╗\n");
            vm.AddOutput("║ [i] BIOS-Style Feature Matrix                                             ║\n");
            vm.AddOutput("╠═══════════════════════════════════════════════════════════════════════════╣\n");

            WriteBoardStatus(vm, state.IsAdmin, "Full ETW Byte Tracking", state.IsAdmin ? "Ready" : "Run app as Admin");

            var hybridEnabled = _hybridMode.IsEnabled && state.HybridProbe.IsReady;
            var hybridDetail = hybridEnabled
                ? $"Enabled ({state.HybridProbe.SelectedDistro})"
                : BuildHybridBoardDetail(state);
            WriteBoardStatus(vm, hybridEnabled, "Linux Analytics Engine", hybridDetail);

            var credentialSnapshot = _wslCredentials.GetSnapshot();
            var credentialsReady = credentialSnapshot.IsEnabled &&
                                   credentialSnapshot.HasStoredPassword &&
                                   !string.IsNullOrWhiteSpace(credentialSnapshot.UserName);
            WriteBoardStatus(
                vm,
                credentialsReady,
                "WSL Sudo Credentials",
                BuildCredentialBoardDetail(credentialSnapshot));

            var piholeEnabled = state.PiHoleProbe.IsPiHoleInstalled && state.PiHoleProbe.IsBlockingEnabled;
            var piholeDetail = piholeEnabled
                ? $"Enabled ({state.PiHoleProbe.Distro})"
                : BuildPiHoleBoardDetail(state);
            WriteBoardStatus(vm, piholeEnabled, "Pi-hole DNS Filtering", piholeDetail);

            var ftlEnabled = state.PiHoleProbe.IsPiHoleInstalled && state.PiHoleProbe.IsFtlReachable;
            var ftlDetail = ftlEnabled ? "Socket 4711 reachable" : (state.PiHoleProbe.FailureReason ?? "Socket not reachable");
            WriteBoardStatus(vm, ftlEnabled, "Pi-hole FTL Telemetry", ftlDetail);

            vm.AddOutput("╠═══════════════════════════════════════════════════════════════════════════╣\n");
            vm.AddOutput("║ [i] Toggle Commands                                                       ║\n");
            vm.AddOutput("║  network feature enable hybrid                                            ║\n");
            vm.AddOutput("║  network feature disable hybrid                                           ║\n");
            vm.AddOutput("║  network feature enable pihole                                            ║\n");
            vm.AddOutput("║  network feature disable pihole [5m]                                      ║\n");
            vm.AddOutput("║  views -> WSL Credentials   (set username + sudo password)                ║\n");
            vm.AddOutput("║  network pihole sync-dns Ethernet                                         ║\n");
            vm.AddOutput("╚═══════════════════════════════════════════════════════════════════════════╝\n");
        }

        private async Task<FeatureStateSnapshot> CaptureFeatureStateAsync()
        {
            var isAdmin = IsAdministrator();
            var hybridProbe = await _wslHybrid.ProbeAsync(_hybridMode.PreferredDistro);
            _hybridMode.RecordProbe(hybridProbe);
            _hybridMode.RecordError(hybridProbe.IsReady ? null : hybridProbe.FailureReason);

            PiHoleProbeResult piHoleProbe;
            try
            {
                piHoleProbe = await _piHole.ProbeAsync(_hybridMode.PreferredDistro);
            }
            catch (Exception ex)
            {
                piHoleProbe = new PiHoleProbeResult
                {
                    FailureReason = ex.Message
                };
            }

            return new FeatureStateSnapshot(isAdmin, hybridProbe, piHoleProbe);
        }

        private static void WriteBoardStatus(
            ShellViewModel vm,
            bool enabled,
            string featureName,
            string detail)
        {
            var marker = enabled ? "[✓]" : "[X]";
            var safeFeature = Truncate(featureName, 28);
            var normalizedDetail = (detail ?? string.Empty)
                .Replace('\r', ' ')
                .Replace('\n', ' ');
            var safeDetail = Truncate(normalizedDetail, 38);
            vm.AddOutput($"{marker} {safeFeature,-28} : {safeDetail}\n");
        }

        private string BuildHybridBoardDetail(FeatureStateSnapshot state)
        {
            if (!_hybridMode.IsEnabled)
            {
                return "Toggle OFF";
            }

            if (!state.HybridProbe.IsWslInstalled)
            {
                return "WSL not installed";
            }

            if (!state.HybridProbe.HasAnyDistribution)
            {
                return "No Linux distro installed";
            }

            return state.HybridProbe.FailureReason ?? "Not ready";
        }

        private string BuildPiHoleBoardDetail(FeatureStateSnapshot state)
        {
            if (!state.PiHoleProbe.IsWslAvailable)
            {
                return "WSL not available";
            }

            if (!state.PiHoleProbe.IsPiHoleInstalled)
            {
                return "Pi-hole not installed";
            }

            if (!state.PiHoleProbe.IsBlockingEnabled)
            {
                return "Installed, toggle OFF";
            }

            return state.PiHoleProbe.StatusSummary ?? "Not ready";
        }

        private static string BuildCredentialBoardDetail(
            WslCredentialSnapshot snapshot)
        {
            if (!snapshot.IsEnabled)
            {
                return "Toggle OFF";
            }

            if (!snapshot.HasStoredPassword || string.IsNullOrWhiteSpace(snapshot.UserName))
            {
                return "Not configured";
            }

            return $"Configured ({snapshot.UserName})";
        }

        private sealed record FeatureStateSnapshot(
            bool IsAdmin,
            WslHybridProbeResult HybridProbe,
            PiHoleProbeResult PiHoleProbe);

        private async Task RunQuickStartAsync(ShellViewModel vm)
        {
            vm.AddOutput("[>] Opening feature control board...\n");
            await ShowFeatureBoardAsync(vm);
            vm.AddOutput("[>] Starting live monitor now...\n");
            await RunLiveEnhancedAsync(vm);
        }

        private async Task RunSetupAsync(ShellViewModel vm)
        {
            await ShowFeatureBoardAsync(vm);
            vm.AddOutput("\n");
            var credentialSnapshot = _wslCredentials.GetSnapshot();
            vm.AddOutput("[>] Setup policy: WSL sudo credentials can be stored encrypted (DPAPI).\n");
            vm.AddOutput("[>] Open Views -> WSL Credentials to set Linux username/password for sudo.\n");
            vm.AddOutput($"[>] Credential cache: {(credentialSnapshot.HasStoredPassword ? "present" : "missing")} | enabled={credentialSnapshot.IsEnabled}.\n");
            vm.AddOutput("[>] Privileged WSL actions try stored sudo credentials first, then `--user root` fallback.\n");
        }

        private async Task RunHybridCommandAsync(string args, ShellViewModel vm)
        {
            var tail = (args ?? string.Empty).Trim();
            if (tail.Length == 0 || string.Equals(tail, "status", StringComparison.OrdinalIgnoreCase))
            {
                await ShowHybridStatusAsync(vm);
                return;
            }

            var split = tail.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            var subCommand = split[0].ToLowerInvariant();
            var value = split.Length > 1 ? split[1].Trim() : string.Empty;

            switch (subCommand)
            {
                case "enable":
                {
                    _hybridMode.Enable(value);
                    _hybridMode.SetPreferredDistro(value);
                    vm.AddOutput("Linux analytics feature enabled.\n");
                    await ShowHybridStatusAsync(vm);
                    return;
                }
                case "disable":
                {
                    _hybridMode.Disable();
                    vm.AddOutput("Linux analytics feature disabled. `network live` will keep using Windows monitoring.\n");
                    return;
                }
                case "use":
                case "distro":
                {
                    if (string.IsNullOrWhiteSpace(value))
                    {
                        vm.AddOutput("Usage: network hybrid distro <WSL-Distro-Name>\n");
                        return;
                    }

                    _hybridMode.SetPreferredDistro(value);
                    vm.AddOutput($"Preferred Linux distro set to: {value}\n");
                    await ShowHybridStatusAsync(vm);
                    return;
                }
                default:
                {
                    vm.AddOutput("Usage: network hybrid [status|enable [distro]|disable|distro <name>]\n");
                    return;
                }
            }
        }

        private async Task ShowHybridStatusAsync(ShellViewModel vm)
        {
            var probe = await _wslHybrid.ProbeAsync(_hybridMode.PreferredDistro);
            _hybridMode.RecordProbe(probe);
            _hybridMode.RecordError(probe.IsReady ? null : probe.FailureReason);

            var state = _hybridMode.IsEnabled
                ? (probe.IsReady ? "ACTIVE" : "ENABLED (DEGRADED)")
                : "DISABLED";

            vm.AddOutput("╔═══════════════════════════════════════════════════════════════════════════╗\n");
            vm.AddOutput("║ Linux Analytics Feature                                                   ║\n");
            vm.AddOutput("╠═══════════════════════════════════════════════════════════════════════════╣\n");
            vm.AddOutput($"║ Mode: {state,-65} ║\n");
            vm.AddOutput($"║ WSL installed: {(probe.IsWslInstalled ? "Yes" : "No"),-56} ║\n");
            vm.AddOutput($"║ Distro selected: {(probe.SelectedDistro ?? "(none)"),-52} ║\n");
            vm.AddOutput($"║ Linux shell reachable: {(probe.BashReachable ? "Yes" : "No"),-50} ║\n");
            if (!string.IsNullOrWhiteSpace(probe.SelectedDistroUser))
                vm.AddOutput($"║ Distro user: {probe.SelectedDistroUser,-55} ║\n");
            var credentialSnapshot = _wslCredentials.GetSnapshot();
            var credentialState = credentialSnapshot.IsEnabled && credentialSnapshot.HasStoredPassword ? "Configured" : "Missing";
            vm.AddOutput($"║ Sudo credential cache: {credentialState,-45} ║\n");
            vm.AddOutput("╚═══════════════════════════════════════════════════════════════════════════╝\n");

            if (!probe.IsReady && !string.IsNullOrWhiteSpace(probe.FailureReason))
            {
                vm.AddOutput($"Reason: {probe.FailureReason}\n");
            }

            if (probe.AvailableDistros.Count > 0)
            {
                vm.AddOutput($"Available distros: {string.Join(", ", probe.AvailableDistros)}\n");
            }

            vm.AddOutput("Use `network feature enable hybrid` or `network feature disable hybrid` to toggle this feature.\n");
        }

        private async Task RunPiHoleCommandAsync(string args, ShellViewModel vm)
        {
            var tail = (args ?? string.Empty).Trim();
            if (tail.Length == 0 || string.Equals(tail, "status", StringComparison.OrdinalIgnoreCase))
            {
                await ShowPiHoleStatusAsync(vm);
                return;
            }

            var split = tail.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            var sub = split[0].ToLowerInvariant();
            var value = split.Length > 1 ? split[1].Trim() : string.Empty;

            try
            {
                switch (sub)
                {
                    case "enable":
                    case "on":
                    {
                        var message = await _piHole.EnableBlockingAsync(_hybridMode.PreferredDistro);
                        vm.AddOutput($"{message}\n");
                        return;
                    }
                    case "disable":
                    case "off":
                    {
                        var message = await _piHole.DisableBlockingAsync(
                            string.IsNullOrWhiteSpace(value) ? null : value,
                            _hybridMode.PreferredDistro);
                        vm.AddOutput($"{message}\n");
                        return;
                    }
                    case "update":
                    case "refresh":
                    {
                        var message = await _piHole.UpdateGravityAsync(_hybridMode.PreferredDistro);
                        vm.AddOutput($"{message}\n");
                        return;
                    }
                    case "allow":
                    case "whitelist":
                    {
                        if (string.IsNullOrWhiteSpace(value))
                        {
                            vm.AddOutput("Usage: network pihole allow <domain>\n");
                            return;
                        }

                        var message = await _piHole.AllowDomainAsync(value, _hybridMode.PreferredDistro);
                        vm.AddOutput($"{message}\n");
                        return;
                    }
                    case "top":
                    {
                        var count = 10;
                        if (!string.IsNullOrWhiteSpace(value) && !int.TryParse(value, out count))
                        {
                            vm.AddOutput("Usage: network pihole top [count]\n");
                            return;
                        }

                        await ShowPiHoleTopDomainsAsync(count, vm);
                        return;
                    }
                    case "wsl-ip":
                    case "ip":
                    {
                        var ip = await _piHole.GetWslIpAsync(_hybridMode.PreferredDistro);
                        vm.AddOutput($"WSL distro IP: {ip}\n");
                        return;
                    }
                    case "sync-dns":
                    {
                        if (string.IsNullOrWhiteSpace(value))
                        {
                            vm.AddOutput("Usage: network pihole sync-dns <Windows Interface Alias>\n");
                            vm.AddOutput("Example: network pihole sync-dns Ethernet\n");
                            return;
                        }

                        var probe = await _piHole.ProbeAsync(_hybridMode.PreferredDistro);
                        if (!probe.IsWslAvailable)
                        {
                            vm.AddOutput($"[error] WSL not available: {probe.FailureReason ?? "No distro detected."}\n");
                            return;
                        }

                        var ip = await _piHole.GetWslIpAsync(probe.Distro ?? _hybridMode.PreferredDistro);
                        var message = await _piHole.SyncWindowsDnsAsync(value, ip);
                        vm.AddOutput($"{message}\n");

                        if (probe.IsPiHoleInstalled)
                        {
                            vm.AddOutput("Windows DNS now points to your current WSL Pi-hole endpoint.\n");
                        }
                        else
                        {
                            vm.AddOutput("[warn] Pi-hole is not installed in the selected distro; DNS now points to WSL IP only.\n");
                        }

                        return;
                    }
                    default:
                    {
                        vm.AddOutput("Usage: network pihole [status|enable|disable [5m]|top [count]|update|allow <domain>|wsl-ip|sync-dns <interface>]\n");
                        return;
                    }
                }
            }
            catch (Exception ex)
            {
                vm.AddOutput($"[error] Pi-hole action failed: {ex.Message}\n");
            }
        }

        private async Task ShowPiHoleStatusAsync(ShellViewModel vm)
        {
            try
            {
                var probe = await _piHole.ProbeAsync(_hybridMode.PreferredDistro);

                vm.AddOutput("╔═══════════════════════════════════════════════════════════════════════════╗\n");
                vm.AddOutput("║ Pi-hole DNS Feature                                                       ║\n");
                vm.AddOutput("╠═══════════════════════════════════════════════════════════════════════════╣\n");
                vm.AddOutput($"║ WSL available: {(probe.IsWslAvailable ? "Yes" : "No"),-57} ║\n");
                vm.AddOutput($"║ Distro: {(probe.Distro ?? "(none)"),-64} ║\n");
                vm.AddOutput($"║ Pi-hole installed: {(probe.IsPiHoleInstalled ? "Yes" : "No"),-55} ║\n");
                vm.AddOutput($"║ Blocking active: {(probe.IsBlockingEnabled ? "Yes" : "No"),-56} ║\n");
                vm.AddOutput($"║ FTL socket (4711): {(probe.IsFtlReachable ? "Reachable" : "Not reachable"),-48} ║\n");
                if (!string.IsNullOrWhiteSpace(probe.StatusSummary))
                {
                    vm.AddOutput($"║ Status: {Truncate(probe.StatusSummary, 64),-64} ║\n");
                }
                vm.AddOutput("╚═══════════════════════════════════════════════════════════════════════════╝\n");

                if (!string.IsNullOrWhiteSpace(probe.FailureReason))
                {
                    vm.AddOutput($"Detail: {probe.FailureReason}\n");
                }

                vm.AddOutput("Use `network feature enable pihole` or `network feature disable pihole` to toggle blocking.\n");
            }
            catch (Exception ex)
            {
                vm.AddOutput($"[error] Failed to read Pi-hole status: {ex.Message}\n");
            }
        }

        private async Task ShowPiHoleTopDomainsAsync(int count, ShellViewModel vm)
        {
            try
            {
                var domains = await _piHole.GetTopBlockedDomainsAsync(count);
                if (domains.Count == 0)
                {
                    vm.AddOutput("No blocked domain data available yet.\n");
                    vm.AddOutput("Try again after Pi-hole has been active for a bit.\n");
                    return;
                }

                vm.AddOutput($"┌─ Top Blocked Domains (Pi-hole, top {domains.Count}) ─────────────────────┐\n");
                vm.AddOutput($"│ {"Domain",-48} {"Blocked",10} │\n");
                vm.AddOutput("├───────────────────────────────────────────────────────────────────────┤\n");
                foreach (var item in domains)
                {
                    vm.AddOutput($"│ {Truncate(item.Domain, 48),-48} {item.BlockedCount,10:N0} │\n");
                }
                vm.AddOutput("└───────────────────────────────────────────────────────────────────────┘\n");
            }
            catch (Exception ex)
            {
                vm.AddOutput($"[error] Failed to load top blocked domains: {ex.Message}\n");
            }
        }

        private Task RunStatsAsync(ShellViewModel vm)
        {
            try
            {
                using var store = new FlowRecordStore();
                var (count, bytes, oldest) = store.GetStats();

                vm.AddOutput("╔═══════════════════════════════════════════════════════════════════════════╗\n");
                vm.AddOutput("║ Network Flow Statistics                                                   ║\n");
                vm.AddOutput("╠═══════════════════════════════════════════════════════════════════════════╣\n");
                vm.AddOutput($"║ Total flows recorded:  {count:N0,-53} ║\n");
                vm.AddOutput($"║ Total bytes tracked:   {FlowRecord.FormatBytes(bytes),-53} ║\n");
                if (oldest.HasValue)
                    vm.AddOutput($"║ Oldest record:         {oldest.Value:g,-53} ║\n");
                vm.AddOutput("╚═══════════════════════════════════════════════════════════════════════════╝\n\n");

                var totals = store.GetHistoricalProcessTotals(DateTime.UtcNow.AddDays(-7)).Take(10).ToList();
                if (totals.Count > 0)
                {
                    vm.AddOutput("┌─ Top Processes (Last 7 Days) ─────────────────────────────────────────┐\n");
                    vm.AddOutput($"│ {"Process",-30} {"↓ In",13} {"↑ Out",13} │\n");
                    vm.AddOutput("├───────────────────────────────────────────────────────────────────────┤\n");
                    foreach (var p in totals)
                    {
                        vm.AddOutput($"│ {Truncate(p.ProcessName, 30),-30} {p.BytesReceivedDisplay,13} {p.BytesSentDisplay,13} │\n");
                    }
                    vm.AddOutput("└───────────────────────────────────────────────────────────────────────┘\n");
                }
            }
            catch (Exception ex)
            {
                vm.AddOutput("╔═══════════════════════════════════════════════════════════════════════════╗\n");
                vm.AddOutput("║ Network Flow Statistics                                                   ║\n");
                vm.AddOutput("╠═══════════════════════════════════════════════════════════════════════════╣\n");
                vm.AddOutput($"║ ✗ Error: {ex.Message,-65} ║\n");
                vm.AddOutput("╚═══════════════════════════════════════════════════════════════════════════╝\n");
            }

            return Task.CompletedTask;
        }

        private async Task RunBaselineAsync(ShellViewModel vm)
        {
            var session = _outputService.CreateSession("Network Baseline", vm.AcronymsExpanded);
            var progressVm = session.ViewModel;
            progressVm.Append("╔═══════════════════════════════════════════════════════════════════════════╗\n");
            progressVm.Append($"║ Network Baseline Scan                    Started: {DateTime.Now:T,-19} ║\n");
            progressVm.Append("╚═══════════════════════════════════════════════════════════════════════════╝\n\n");

            var profileCount = 0;
            var vulnerableCount = 0;
            try
            {
                progressVm.Append("┌─ Firewall Profile Status ─────────────────────────────────────────────┐\n");
                var profiles = await _firewall.GetStatusAsync();
                profileCount = profiles.Count;
                vulnerableCount = profiles.Count(p => p.IsVulnerable);
                foreach (var profile in profiles)
                {
                    var statusSymbol = profile.IsVulnerable ? "✗" : "✓";
                    var statusText = profile.IsVulnerable ? "VULNERABLE" : "OK";
                    progressVm.Append($"│ {statusSymbol} {profile.Profile,-15} {profile.State,-10} / {profile.Policy,-15} [{statusText,10}] │\n");
                }
                progressVm.Append("└───────────────────────────────────────────────────────────────────────┘\n\n");
            }
            catch (Exception ex)
            {
                progressVm.Append($"│ ✗ Error: {ex.Message,-64} │\n");
                progressVm.Append("└───────────────────────────────────────────────────────────────────────┘\n\n");
            }

            try
            {
                var ports = await _engine.GetListeningPortsAsync();
                var list = ports.Take(15).ToList();
                progressVm.Append($"┌─ Listening Ports ({ports.Count} total, showing top {list.Count}) ───────────────────────────┐\n");
                progressVm.Append($"│ {"Proto",6} {"Address",20} {"Port",6} {"Process",25} {"PID",8} │\n");
                progressVm.Append("├───────────────────────────────────────────────────────────────────────┤\n");
                foreach (var port in list)
                {
                    progressVm.Append($"│ {port.Protocol,6} {Truncate(port.Address, 20),20} {port.Port,6} {Truncate(port.ProcessName, 25),25} {port.Pid,8} │\n");
                }

                if (ports.Count > list.Count)
                    progressVm.Append($"│ ... and {ports.Count - list.Count} more ports                                                   │\n");
                progressVm.Append("└───────────────────────────────────────────────────────────────────────┘\n");
            }
            catch (Exception ex)
            {
                progressVm.Append($"┌─ Port Enumeration ────────────────────────────────────────────────────┐\n");
                progressVm.Append($"│ ✗ Error: {ex.Message,-64} │\n");
                progressVm.Append("└───────────────────────────────────────────────────────────────────────┘\n");
            }

            progressVm.Status = "Completed";
            vm.AddOutput($"✓ Network baseline completed: {profileCount} profiles checked, {vulnerableCount} vulnerable.\n");

            _ = session.View.Dispatcher.InvokeAsync(async () =>
            {
                await Task.Delay(TimeSpan.FromSeconds(2));
                session.View.Close();
            });
        }

        private async Task RunLiveEnhancedAsync(ShellViewModel vm)
        {
            var session = vm.OpenAttachedPane("Network Monitor (Enhanced)");
            var output = session.ViewModel;
            var ct = session.Cancellation.Token;

            output.Append("Enhanced network monitor starting...\n");
            output.Status = "Starting";

            FlowCapturePipeline? pipeline = null;
            FlowAggregator? aggregator = null;
            EnrichmentService? enrichment = null;
            FlowRecordStore? store = null;
            WslHybridProbeResult? hybridProbe = null;
            var hybridActive = false;
            var hybridDistro = string.Empty;
            var hybridLastError = string.Empty;
            var hybridConsecutiveErrors = 0;
            var nextHybridUpdateUtc = DateTime.UtcNow;
            var lastHybridFindings = new List<HybridRiskFinding>();
            var riskByFlow = new Dictionary<string, HybridRiskFinding>(StringComparer.OrdinalIgnoreCase);
            var endpointThroughputHistory = new Dictionary<string, Queue<long>>(StringComparer.OrdinalIgnoreCase);
            var endpointPreviousTotals = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);

            try
            {
                enrichment = new EnrichmentService();
                try
                {
                    store = new FlowRecordStore();
                }
                catch
                {
                    store = null;
                }
                aggregator = new FlowAggregator(enrichment, store);
                pipeline = new FlowCapturePipeline();

                pipeline.Start(TimeSpan.FromSeconds(2));
                aggregator.ConnectTo(pipeline);
                aggregator.Start();

                var modeText = pipeline.IsLimitedMode
                    ? "[Limited Mode - Run as Admin for bandwidth tracking]"
                    : "[Full Mode - ETW bandwidth tracking active]";

                if (_hybridMode.IsEnabled)
                {
                    output.Append("Checking Linux analytics engine...\n");
                    hybridProbe = await _wslHybrid.ProbeAsync(_hybridMode.PreferredDistro, ct);
                    _hybridMode.RecordProbe(hybridProbe);
                    _hybridMode.RecordError(hybridProbe.IsReady ? null : hybridProbe.FailureReason);

                    if (hybridProbe.IsReady && !string.IsNullOrWhiteSpace(hybridProbe.SelectedDistro))
                    {
                        hybridActive = true;
                        hybridDistro = hybridProbe.SelectedDistro!;
                    }
                    else
                    {
                        hybridLastError = hybridProbe.FailureReason ?? "Linux analytics engine is not ready.";
                    }
                }

                output.ClearOutput();
                output.ClearInteractiveEndpoints();
                output.Append($"Network Monitor {modeText}\n");
                output.Append(BuildHybridBanner(_hybridMode.IsEnabled, hybridActive, hybridDistro, hybridLastError));
                output.Append("Ctrl+P pauses updates (for scrolling). PgUp/PgDn scrolls. Ctrl+W closes pane.\n\n");
                output.Status = "Live";

                var paused = false;
                while (!ct.IsCancellationRequested)
                {
                    if (vm.IsAttachedPanePaused)
                    {
                        if (!paused)
                        {
                            output.Status = "Paused";
                            paused = true;
                        }

                        await Task.Delay(TimeSpan.FromMilliseconds(200), ct);
                        continue;
                    }

                    if (paused)
                    {
                        output.Status = "Live";
                        paused = false;
                    }

                    var (sent, received, flowCount, processCount) = aggregator.GetTotalStats();
                    var processTotals = aggregator.GetProcessTotals()
                        .Values
                        .OrderByDescending(p => p.TotalBytes)
                        .Take(10)
                        .ToList();
                    var activeFlows = aggregator.GetActiveFlows();

                    if (hybridActive && DateTime.UtcNow >= nextHybridUpdateUtc)
                    {
                        nextHybridUpdateUtc = DateTime.UtcNow.AddSeconds(5);

                        try
                        {
                            var findings = await _wslHybrid.AnalyzeFlowsAsync(
                                activeFlows.Take(120).ToList(),
                                hybridDistro,
                                ct);

                            hybridConsecutiveErrors = 0;
                            hybridLastError = string.Empty;
                            _hybridMode.RecordError(null);

                            lastHybridFindings = findings
                                .OrderByDescending(f => f.Score)
                                .Take(10)
                                .ToList();

                            riskByFlow = findings
                                .GroupBy(BuildRiskKey)
                                .Select(g => g.OrderByDescending(x => x.Score).First())
                                .ToDictionary(BuildRiskKey, x => x, StringComparer.OrdinalIgnoreCase);
                        }
                        catch (OperationCanceledException)
                        {
                            throw;
                        }
                        catch (Exception ex)
                        {
                            hybridConsecutiveErrors++;
                            hybridLastError = ex.Message;
                            _hybridMode.RecordError(hybridLastError);

                            if (hybridConsecutiveErrors >= 3)
                            {
                                hybridActive = false;
                                riskByFlow.Clear();
                                lastHybridFindings.Clear();
                            }
                        }
                    }

                    var focusSnapshots = BuildEndpointFocusSnapshots(
                        activeFlows,
                        riskByFlow,
                        endpointThroughputHistory,
                        endpointPreviousTotals);
                    output.SetInteractiveEndpoints(focusSnapshots);

                    output.ClearOutput();

                    // Header with stats
                    output.Append("╔═══════════════════════════════════════════════════════════════════════════╗\n");
                    output.Append($"║ Network Monitor                          Updated: {DateTime.Now:T,-19} ║\n");
                    output.Append("╠═══════════════════════════════════════════════════════════════════════════╣\n");
                    output.Append($"║ ↓ In: {FlowRecord.FormatBytes(received),12}  │  ↑ Out: {FlowRecord.FormatBytes(sent),12}  │  Flows: {flowCount,5}  │  Procs: {processCount,4} ║\n");
                    output.Append("╠═══════════════════════════════════════════════════════════════════════════╣\n");
                    output.Append($"║ {modeText,-73} ║\n");
                    output.Append($"║ {Truncate(BuildHybridStatusLine(_hybridMode.IsEnabled, hybridActive, hybridDistro, hybridLastError), 73),-73} ║\n");
                    output.Append("╚═══════════════════════════════════════════════════════════════════════════╝\n\n");

                    if (processTotals.Count > 0)
                    {
                        output.Append("┌─ Bandwidth by Process ────────────────────────────────────────────────┐\n");
                        output.Append($"│ {"Process",-30} {"↓ In",13} {"↑ Out",13} {"Conn",6} │\n");
                        output.Append("├───────────────────────────────────────────────────────────────────────┤\n");

                        var maxBytes = processTotals.Max(p => p.TotalBytes);
                        foreach (var p in processTotals)
                        {
                            var bar = CreateBandwidthBar(p.TotalBytes, maxBytes, 20);
                            output.Append($"│ {Truncate(p.ProcessName, 30),-30} {p.BytesReceivedDisplay,13} {p.BytesSentDisplay,13} {p.ConnectionCount,6} │\n");
                            output.Append($"│   {bar,-69} │\n");
                        }
                        output.Append("└───────────────────────────────────────────────────────────────────────┘\n\n");
                    }

                    if (activeFlows.Count > 0)
                    {
                        output.Append("┌─ Active Flows (top 20) ───────────────────────────────────────────────┐\n");
                        output.Append($"│ {"Process",-18} {"Remote",24} {"Geo",4} {"Act",3} {"Risk",5} {"Bytes",10} │\n");
                        output.Append("├───────────────────────────────────────────────────────────────────────┤\n");
                        foreach (var flow in activeFlows.Take(20))
                        {
                            var remote = !string.IsNullOrEmpty(flow.RemoteHostname)
                                ? flow.RemoteHostname
                                : $"{flow.RemoteAddress}:{flow.RemotePort}";
                            var country = string.IsNullOrEmpty(flow.RemoteCountry) ? "──" : flow.RemoteCountry;
                            var actionSymbol = flow.Action switch
                            {
                                FlowAction.Allow => "✓",
                                FlowAction.Block => "✗",
                                FlowAction.Drop => "!",
                                _ => "?"
                            };
                            var flowRiskKey = BuildRiskKey(flow);
                            var riskToken = riskByFlow.TryGetValue(flowRiskKey, out var risk)
                                ? RiskToken(risk)
                                : "──";
                            output.Append($"│ {Truncate(flow.ProcessName, 18),-18} {Truncate(remote, 24),-24} {country,4} {actionSymbol,3} {riskToken,5} {flow.TotalBytesDisplay,10} │\n");
                        }
                        output.Append("└───────────────────────────────────────────────────────────────────────┘\n");
                    }

                    if (_hybridMode.IsEnabled)
                    {
                        output.Append("\n");
                        if (lastHybridFindings.Count > 0)
                        {
                            output.Append("┌─ Extra Linux Risk Signals (top 8) ────────────────────────────────────┐\n");
                            output.Append($"│ {"Process",-16} {"Endpoint",24} {"Sev",6} {"Score",5} {"Signals",-14} │\n");
                            output.Append("├───────────────────────────────────────────────────────────────────────┤\n");
                            foreach (var finding in lastHybridFindings.Take(8))
                            {
                                var reasons = FormatReasonSummary(finding);
                                output.Append($"│ {Truncate(finding.ProcessName, 16),-16} {Truncate(finding.Endpoint, 24),-24} {finding.Severity,6} {finding.Score,5} {Truncate(reasons, 14),-14} │\n");
                            }
                            output.Append("└───────────────────────────────────────────────────────────────────────┘\n");
                        }
                        else if (!hybridActive && !string.IsNullOrWhiteSpace(hybridLastError))
                        {
                            output.Append($"Linux analytics unavailable: {hybridLastError}\n");
                            output.Append("Capture remains active using Windows native telemetry.\n");
                        }
                    }

                    await Task.Delay(TimeSpan.FromMilliseconds(500), ct);
                }
            }
            catch (OperationCanceledException)
            {
                output.Status = "Closed";
            }
            catch (Exception ex)
            {
                output.Append($"[error] Enhanced monitor failed: {ex.Message}\n");
                output.Append("Switching to basic monitor...\n");
                output.Status = "Fallback";
                // Fall back to legacy monitor
                await RunLiveLegacyInternalAsync(vm, output, ct);
            }
            finally
            {
                output.ClearInteractiveEndpoints();
                aggregator?.Dispose();
                pipeline?.Dispose();
                store?.Dispose();
            }
        }

        private async Task RunLiveLegacyAsync(ShellViewModel vm)
        {
            var session = vm.OpenAttachedPane("Network Live Monitor (Legacy)");
            var output = session.ViewModel;
            var ct = session.Cancellation.Token;
            await RunLiveLegacyInternalAsync(vm, output, ct);
        }

        private async Task RunLiveLegacyInternalAsync(ShellViewModel vm, ProgressViewModel output, CancellationToken ct)
        {
            output.ClearInteractiveEndpoints();
            output.Append("Legacy live monitor started. Ctrl+P pauses updates. PgUp/PgDn scrolls. Ctrl+W closes pane.\n");
            output.Append("This view shows active TCP/UDP connections with DNS resolution where possible.\n\n");
            output.Status = "Live";

            try
            {
                var previous = new Dictionary<string, ConnectionInfo>(StringComparer.OrdinalIgnoreCase);
                var paused = false;

                while (!ct.IsCancellationRequested)
                {
                    if (vm.IsAttachedPanePaused)
                    {
                        if (!paused)
                        {
                            output.Status = "Paused";
                            paused = true;
                        }

                        await Task.Delay(TimeSpan.FromMilliseconds(200), ct);
                        continue;
                    }

                    if (paused)
                    {
                        output.Status = "Live";
                        paused = false;
                    }

                    var connections = await _monitor.GetConnectionsAsync();
                    var current = connections.ToDictionary(BuildKey, c => c, StringComparer.OrdinalIgnoreCase);
                    var newCount = current.Keys.Except(previous.Keys).Count();
                    var endedCount = previous.Keys.Except(current.Keys).Count();

                    output.ClearOutput();

                    // Header
                    output.Append("╔═══════════════════════════════════════════════════════════════════════════╗\n");
                    output.Append($"║ Network Live Monitor (Legacy)            Updated: {DateTime.Now:T,-19} ║\n");
                    output.Append("╠═══════════════════════════════════════════════════════════════════════════╣\n");
                    output.Append($"║ Total: {connections.Count,4}  │  ✓ New: {newCount,3}  │  ✗ Ended: {endedCount,3}                              ║\n");
                    output.Append("╚═══════════════════════════════════════════════════════════════════════════╝\n\n");

                    var topProcesses = connections
                        .GroupBy(c => $"{c.ProcessName} (PID {c.Pid})")
                        .Select(g => new { Name = g.Key, Count = g.Count() })
                        .OrderByDescending(g => g.Count)
                        .Take(6)
                        .ToList();

                    if (topProcesses.Count > 0)
                    {
                        output.Append("┌─ Top Processes ───────────────────────────────────────────────────────┐\n");
                        foreach (var p in topProcesses)
                        {
                            var bar = new string('█', Math.Min(p.Count / 2, 30));
                            output.Append($"│ {Truncate(p.Name, 35),-35} {p.Count,4} {bar,-33} │\n");
                        }
                        output.Append("└───────────────────────────────────────────────────────────────────────┘\n\n");
                    }

                    output.Append("┌─ Active Connections (top 40) ─────────────────────────────────────────┐\n");
                    output.Append($"│ {"Process",-22} {"Proto",6} {"Local",20} {"→",3} {"Remote",27} {"State",12} │\n");
                    output.Append("├───────────────────────────────────────────────────────────────────────┤\n");

                    foreach (var conn in connections
                        .OrderBy(c => c.ProcessName, StringComparer.OrdinalIgnoreCase)
                        .ThenBy(c => c.RemoteAddress, StringComparer.OrdinalIgnoreCase)
                        .Take(40))
                    {
                        var host = string.IsNullOrWhiteSpace(conn.RemoteHost) ? conn.RemoteAddress : conn.RemoteHost;
                        output.Append($"│ {Truncate(conn.ProcessName, 22),-22} {conn.Protocol,6} {Truncate(conn.LocalAddress, 20),20} {"→",3} {Truncate(host, 27),27} {conn.State,12} │\n");
                    }

                    if (connections.Count > 40)
                    {
                        output.Append($"│ ... and {connections.Count - 40} more connections                                               │\n");
                    }
                    output.Append("└───────────────────────────────────────────────────────────────────────┘\n");

                    previous = current;
                    await Task.Delay(TimeSpan.FromSeconds(2), ct);
                }
            }
            catch (OperationCanceledException)
            {
                output.Status = "Closed";
            }
            catch (Exception ex)
            {
                output.Append($"[error] Live monitor failed: {ex.Message}\n");
                output.Status = "Failed";
            }
            finally
            {
                output.ClearInteractiveEndpoints();
            }
        }

        private static string BuildHybridBanner(bool isEnabled, bool isActive, string distro, string lastError)
        {
            if (!isEnabled)
            {
                return "Linux analytics: disabled.\n";
            }

            if (isActive)
            {
                return $"Linux analytics: active on {distro}.\n";
            }

            return string.IsNullOrWhiteSpace(lastError)
                ? "Linux analytics: checking status.\n"
                : $"Linux analytics: unavailable ({lastError}).\n";
        }

        private static string BuildHybridStatusLine(bool isEnabled, bool isActive, string distro, string lastError)
        {
            if (!isEnabled)
            {
                return "Linux analytics: OFF";
            }

            if (isActive)
            {
                return $"Linux analytics: ON ({distro})";
            }

            return string.IsNullOrWhiteSpace(lastError)
                ? "Linux analytics: unavailable (using Windows only)"
                : $"Linux analytics: unavailable ({lastError})";
        }

        private static string BuildRiskKey(FlowRecord flow)
        {
            return BuildRiskKey(flow.ProcessId, flow.RemoteAddress, flow.RemotePort);
        }

        private static string BuildRiskKey(HybridRiskFinding finding)
        {
            var endpoint = finding.Endpoint ?? string.Empty;
            var idx = endpoint.LastIndexOf(':');
            if (idx <= 0 || idx >= endpoint.Length - 1)
            {
                return $"{finding.ProcessId}|{endpoint.Trim().ToLowerInvariant()}";
            }

            var address = endpoint[..idx];
            var portText = endpoint[(idx + 1)..];
            if (!int.TryParse(portText, out var port))
            {
                return $"{finding.ProcessId}|{endpoint.Trim().ToLowerInvariant()}";
            }

            return BuildRiskKey(finding.ProcessId, address, port);
        }

        private static string BuildRiskKey(int processId, string remoteAddress, int remotePort)
        {
            return $"{processId}|{remoteAddress.Trim().ToLowerInvariant()}:{remotePort}";
        }

        private static string RiskToken(HybridRiskFinding finding)
        {
            return finding.Score switch
            {
                >= 55 => "HIGH",
                >= 30 => "MED",
                > 0 => "LOW",
                _ => "──"
            };
        }

        private static IReadOnlyList<EndpointFocusSnapshot> BuildEndpointFocusSnapshots(
            IReadOnlyList<FlowRecord> activeFlows,
            IReadOnlyDictionary<string, HybridRiskFinding> riskByFlow,
            IDictionary<string, Queue<long>> endpointThroughputHistory,
            IDictionary<string, long> endpointPreviousTotals)
        {
            if (activeFlows.Count == 0)
            {
                endpointThroughputHistory.Clear();
                endpointPreviousTotals.Clear();
                return Array.Empty<EndpointFocusSnapshot>();
            }

            var liveKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var snapshots = activeFlows
                .OrderByDescending(flow => flow.TotalBytes)
                .Take(16)
                .Select(flow =>
                {
                    var key = BuildRiskKey(flow);
                    liveKeys.Add(key);
                    var risk = riskByFlow.TryGetValue(key, out var finding) ? finding : null;
                    var actionSymbol = flow.Action switch
                    {
                        FlowAction.Allow => "✓",
                        FlowAction.Block => "✗",
                        FlowAction.Drop => "!",
                        _ => "?"
                    };

                    var riskToken = risk != null ? RiskToken(risk) : "--";
                    var riskReasons = risk != null && risk.Reasons.Count > 0
                        ? string.Join(", ", risk.Reasons.Take(4))
                        : "none";

                    var previousTotal = endpointPreviousTotals.TryGetValue(key, out var prev)
                        ? prev
                        : flow.TotalBytes;
                    var delta = Math.Max(0, flow.TotalBytes - previousTotal);
                    endpointPreviousTotals[key] = flow.TotalBytes;

                    if (!endpointThroughputHistory.TryGetValue(key, out var history))
                    {
                        history = new Queue<long>(16);
                        endpointThroughputHistory[key] = history;
                    }

                    history.Enqueue(delta);
                    while (history.Count > 12)
                    {
                        history.Dequeue();
                    }

                    var sparkline = BuildSparkline(history);

                    return new EndpointFocusSnapshot(
                        EndpointKey: key,
                        ProcessId: flow.ProcessId,
                        ProcessName: string.IsNullOrWhiteSpace(flow.ProcessName) ? "unknown" : flow.ProcessName,
                        ProcessPath: flow.ProcessPath ?? string.Empty,
                        ProcessSigner: flow.ProcessSigner ?? string.Empty,
                        Protocol: flow.Protocol ?? "TCP",
                        LocalAddress: flow.LocalAddress ?? string.Empty,
                        LocalPort: flow.LocalPort,
                        RemoteAddress: flow.RemoteAddress ?? string.Empty,
                        RemotePort: flow.RemotePort,
                        RemoteHostname: flow.RemoteHostname ?? string.Empty,
                        RemoteCountry: string.IsNullOrWhiteSpace(flow.RemoteCountry) ? "--" : flow.RemoteCountry!,
                        ActionSymbol: actionSymbol,
                        ActionText: flow.Action.ToString(),
                        RiskToken: riskToken,
                        RiskScore: risk?.Score ?? 0,
                        RiskReasons: riskReasons,
                        ThroughputSparkline: sparkline,
                        BytesSent: flow.BytesSent,
                        BytesReceived: flow.BytesReceived,
                        FirstSeenLocal: flow.FirstSeen.ToLocalTime(),
                        LastSeenLocal: flow.LastSeen.ToLocalTime());
                })
                .ToArray();

            var staleKeys = endpointThroughputHistory.Keys
                .Where(key => !liveKeys.Contains(key))
                .ToArray();
            foreach (var stale in staleKeys)
            {
                endpointThroughputHistory.Remove(stale);
                endpointPreviousTotals.Remove(stale);
            }

            return snapshots;
        }

        private static string BuildSparkline(IEnumerable<long> values)
        {
            var points = values?.ToArray() ?? Array.Empty<long>();
            if (points.Length == 0)
            {
                return "----------";
            }

            const string glyphs = "._:-=+*#%@";
            var max = Math.Max(1L, points.Max());
            var chars = new char[points.Length];

            for (var i = 0; i < points.Length; i++)
            {
                var normalized = points[i] / (double)max;
                var idx = (int)Math.Round(normalized * (glyphs.Length - 1));
                idx = Math.Clamp(idx, 0, glyphs.Length - 1);
                chars[i] = glyphs[idx];
            }

            return new string(chars);
        }

        private static string FormatReasonSummary(HybridRiskFinding finding)
        {
            if (finding.Reasons.Count == 0)
            {
                return "-";
            }

            var labels = finding.Reasons
                .Take(2)
                .Select(MapReasonCode)
                .ToArray();
            return string.Join(",", labels);
        }

        private static string MapReasonCode(string code)
        {
            return code switch
            {
                "burst-egress" => "burst",
                "possible-beacon" => "beacon",
                "foreign-destination" => "geo",
                "lolbin-process" => "lolbin",
                "unknown-process" => "unknown",
                "non-microsoft-signer" => "signer",
                "dns-volume" => "dns",
                "noisy-port" => "port",
                _ => code
            };
        }

        private static string BuildKey(ConnectionInfo c)
        {
            return $"{c.Protocol}|{c.LocalAddress}|{c.RemoteAddress}|{c.Pid}|{c.State}";
        }

        private static bool IsAdministrator()
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static string Truncate(string value, int max)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= max) return value;
            return value.Substring(0, Math.Max(1, max - 3)) + "...";
        }

        private static string CreateBandwidthBar(long bytes, long maxBytes, int width)
        {
            if (maxBytes == 0) return new string('─', width);

            var percentage = (double)bytes / maxBytes;
            var filled = (int)(percentage * width);
            filled = Math.Min(filled, width);

            var bar = new string('█', filled) + new string('░', width - filled);
            return $"{bar} {percentage:P0}";
        }
    }
}
