using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using TGWST.App.ViewModels;
using TGWST.App.Shell;
using TGWST.Core.Network;
using TGWST.Core.Network.Capture;

namespace TGWST.App.Shell.Commands
{
    public sealed class NetworkCommand : ICommandHandler
    {
        private readonly TaskOutputService _outputService;
        private readonly NetworkSecurityEngine _engine = new();
        private readonly FirewallStatusService _firewall = new();
        private readonly ConnectionMonitor _monitor = new();

        public NetworkCommand(TaskOutputService outputService)
        {
            _outputService = outputService;
        }

        public string Name => "network";
        public string[] Aliases => Array.Empty<string>();

        public Task ExecuteAsync(string args, ShellViewModel vm)
        {
            var sub = (args ?? string.Empty).Trim().ToLowerInvariant();

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

            vm.AddOutput("Usage: network baseline | network live | network stats\n");
            vm.AddOutput("  baseline    - Firewall profile and listening ports summary\n");
            vm.AddOutput("  live        - Real-time bandwidth monitor (enhanced)\n");
            vm.AddOutput("  stats       - Show stored network statistics\n");
            return Task.CompletedTask;
        }

        private async Task RunStatsAsync(ShellViewModel vm)
        {
            try
            {
                using var store = new FlowRecordStore();
                var (count, bytes, oldest) = store.GetStats();
                vm.AddOutput($"Network Flow Statistics\n");
                vm.AddOutput($"Total flows recorded: {count:N0}\n");
                vm.AddOutput($"Total bytes tracked: {FlowRecord.FormatBytes(bytes)}\n");
                if (oldest.HasValue)
                    vm.AddOutput($"Oldest record: {oldest.Value:g}\n");

                var totals = store.GetHistoricalProcessTotals(DateTime.UtcNow.AddDays(-7)).Take(10).ToList();
                if (totals.Count > 0)
                {
                    vm.AddOutput($"\nTop processes (last 7 days):\n");
                    foreach (var p in totals)
                    {
                        vm.AddOutput($"  {p.ProcessName,-25} In: {p.BytesReceivedDisplay,10}  Out: {p.BytesSentDisplay,10}\n");
                    }
                }
            }
            catch (Exception ex)
            {
                vm.AddOutput($"[error] Could not retrieve stats: {ex.Message}\n");
            }
        }

        private async Task RunBaselineAsync(ShellViewModel vm)
        {
            var session = _outputService.CreateSession("Network Baseline", vm.AcronymsExpanded);
            var progressVm = session.ViewModel;
            progressVm.Append($"Started: {DateTime.Now:g}\n");
            progressVm.Append("Collecting firewall profile status...\n");

            var profileCount = 0;
            var vulnerableCount = 0;
            try
            {
                var profiles = await _firewall.GetStatusAsync();
                profileCount = profiles.Count;
                vulnerableCount = profiles.Count(p => p.IsVulnerable);
                foreach (var profile in profiles)
                {
                    var status = profile.IsVulnerable ? "VULNERABLE" : "OK";
                    progressVm.Append($"- {profile.Profile}: {profile.State} / {profile.Policy} [{status}]\n");
                }
            }
            catch (Exception ex)
            {
                progressVm.Append($"[error] Firewall status failed: {ex.Message}\n");
            }

            try
            {
                progressVm.Append("\nEnumerating listening ports...\n");
                var ports = await _engine.GetListeningPortsAsync();
                var list = ports.Take(10).ToList();
                progressVm.Append($"Listening ports detected: {ports.Count} (top {list.Count} shown)\n");
                foreach (var port in list)
                {
                    progressVm.Append($"{port.Protocol} {port.Address}:{port.Port} {port.ProcessName} (PID {port.Pid})\n");
                }

                if (ports.Count > list.Count)
                    progressVm.Append($"... and {ports.Count - list.Count} more.\n");
            }
            catch (Exception ex)
            {
                progressVm.Append($"[error] Port enumeration failed: {ex.Message}\n");
            }

            progressVm.Status = "Completed";
            vm.AddOutput($"Network baseline completed: {profileCount} profiles checked, {vulnerableCount} vulnerable. Listening ports: collected.\n");

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

            try
            {
                enrichment = new EnrichmentService();
                aggregator = new FlowAggregator(enrichment);
                pipeline = new FlowCapturePipeline();

                pipeline.Start(TimeSpan.FromSeconds(2));
                aggregator.ConnectTo(pipeline);
                aggregator.Start();

                var modeText = pipeline.IsLimitedMode
                    ? "[Limited Mode - Run as Admin for bandwidth tracking]"
                    : "[Full Mode - ETW bandwidth tracking active]";

                output.ClearOutput();
                output.Append($"Network Monitor {modeText}\n");
                output.Append("Press Ctrl+W to close pane.\n\n");
                output.Status = "Live";

                while (!ct.IsCancellationRequested)
                {
                    var (sent, received, flowCount, processCount) = aggregator.GetTotalStats();
                    var processTotals = aggregator.GetProcessTotals()
                        .Values
                        .OrderByDescending(p => p.TotalBytes)
                        .Take(10)
                        .ToList();
                    var activeFlows = aggregator.GetActiveFlows();

                    output.ClearOutput();
                    output.Append($"Network Monitor  Updated: {DateTime.Now:T}\n");
                    output.Append($"Total In: {FlowRecord.FormatBytes(received)}  Out: {FlowRecord.FormatBytes(sent)}  ");
                    output.Append($"Flows: {flowCount}  Processes: {processCount}\n");
                    output.Append(modeText + "\n\n");

                    if (processTotals.Count > 0)
                    {
                        output.Append("Bandwidth by Process:\n");
                        output.Append($"{"Process",-28} {"In",12} {"Out",12} {"Conn",6}\n");
                        output.Append(new string('-', 60) + "\n");
                        foreach (var p in processTotals)
                        {
                            output.Append($"{Truncate(p.ProcessName, 28),-28} {p.BytesReceivedDisplay,12} {p.BytesSentDisplay,12} {p.ConnectionCount,6}\n");
                        }
                        output.Append("\n");
                    }

                    if (activeFlows.Count > 0)
                    {
                        output.Append("Active Flows (top 20):\n");
                        output.Append($"{"Process",-20} {"Remote",30} {"Bytes",12}\n");
                        output.Append(new string('-', 64) + "\n");
                        foreach (var flow in activeFlows.Take(20))
                        {
                            var remote = !string.IsNullOrEmpty(flow.RemoteHostname)
                                ? flow.RemoteHostname
                                : $"{flow.RemoteAddress}:{flow.RemotePort}";
                            output.Append($"{Truncate(flow.ProcessName, 20),-20} {Truncate(remote, 30),-30} {flow.TotalBytesDisplay,12}\n");
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
                output.Append("Falling back to legacy monitor...\n");
                output.Status = "Fallback";
                // Fall back to legacy monitor
                await RunLiveLegacyInternalAsync(output, ct);
            }
            finally
            {
                aggregator?.Dispose();
                pipeline?.Dispose();
            }
        }

        private async Task RunLiveLegacyAsync(ShellViewModel vm)
        {
            var session = vm.OpenAttachedPane("Network Live Monitor (Legacy)");
            var output = session.ViewModel;
            var ct = session.Cancellation.Token;
            await RunLiveLegacyInternalAsync(output, ct);
        }

        private async Task RunLiveLegacyInternalAsync(ProgressViewModel output, System.Threading.CancellationToken ct)
        {
            output.Append("Legacy live monitor started. Press Ctrl+W to close pane.\n");
            output.Append("This view shows active TCP/UDP connections with DNS resolution where possible.\n\n");
            output.Status = "Live";

            try
            {
                var previous = new Dictionary<string, ConnectionInfo>(StringComparer.OrdinalIgnoreCase);

                while (!ct.IsCancellationRequested)
                {
                    var connections = await _monitor.GetConnectionsAsync();
                    var current = connections.ToDictionary(BuildKey, c => c, StringComparer.OrdinalIgnoreCase);
                    var newCount = current.Keys.Except(previous.Keys).Count();
                    var endedCount = previous.Keys.Except(current.Keys).Count();

                    output.ClearOutput();
                    output.Append($"Network > Live Monitor (Legacy)   Updated: {DateTime.Now:T}\n");
                    output.Append($"Connections: {connections.Count}   New: {newCount}   Ended: {endedCount}\n");

                    var topProcesses = connections
                        .GroupBy(c => $"{c.ProcessName} (PID {c.Pid})")
                        .Select(g => new { Name = g.Key, Count = g.Count() })
                        .OrderByDescending(g => g.Count)
                        .Take(6)
                        .ToList();

                    if (topProcesses.Count > 0)
                    {
                        output.Append("Top processes: ");
                        output.Append(string.Join(", ", topProcesses.Select(p => $"{p.Name}:{p.Count}")) + "\n");
                    }

                    output.Append("\n");
                    output.Append("Process (PID)           Proto   Local -> Remote                     State\n");
                    output.Append("--------------------------------------------------------------------------\n");

                    foreach (var conn in connections
                        .OrderBy(c => c.ProcessName, StringComparer.OrdinalIgnoreCase)
                        .ThenBy(c => c.RemoteAddress, StringComparer.OrdinalIgnoreCase)
                        .Take(40))
                    {
                        var host = string.IsNullOrWhiteSpace(conn.RemoteHost) ? conn.RemoteAddress : conn.RemoteHost;
                        output.Append($"{Truncate(conn.ProcessName, 22),-22} {conn.Protocol,-6} {Truncate(conn.LocalAddress, 21),-21} -> {Truncate(host, 28),-28} {conn.State}\n");
                    }

                    if (connections.Count > 40)
                    {
                        output.Append($"... {connections.Count - 40} more\n");
                    }

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
        }

        private static string BuildKey(ConnectionInfo c)
        {
            return $"{c.Protocol}|{c.LocalAddress}|{c.RemoteAddress}|{c.Pid}|{c.State}";
        }

        private static string Truncate(string value, int max)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= max) return value;
            return value.Substring(0, Math.Max(1, max - 3)) + "...";
        }
    }
}
