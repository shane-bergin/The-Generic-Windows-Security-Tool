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

                output.ClearOutput();
                output.Append($"Network Monitor {modeText}\n");
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

                    output.ClearOutput();

                    // Header with stats
                    output.Append("╔═══════════════════════════════════════════════════════════════════════════╗\n");
                    output.Append($"║ Network Monitor                          Updated: {DateTime.Now:T,-19} ║\n");
                    output.Append("╠═══════════════════════════════════════════════════════════════════════════╣\n");
                    output.Append($"║ ↓ In: {FlowRecord.FormatBytes(received),12}  │  ↑ Out: {FlowRecord.FormatBytes(sent),12}  │  Flows: {flowCount,5}  │  Procs: {processCount,4} ║\n");
                    output.Append("╠═══════════════════════════════════════════════════════════════════════════╣\n");
                    output.Append($"║ {modeText,-73} ║\n");
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
                        output.Append($"│ {"Process",-20} {"Remote",28} {"Geo",5} {"Act",5} {"Bytes",11} │\n");
                        output.Append("├───────────────────────────────────────────────────────────────────────┤\n");
                        foreach (var flow in activeFlows.Take(20))
                        {
                            var remote = !string.IsNullOrEmpty(flow.RemoteHostname)
                                ? flow.RemoteHostname
                                : $"{flow.RemoteAddress}:{flow.RemotePort}";
                            var country = string.IsNullOrEmpty(flow.RemoteCountry) ? "──" : flow.RemoteCountry;
                            var actionSymbol = flow.Action == "Allow" ? "✓" : "✗";
                            output.Append($"│ {Truncate(flow.ProcessName, 20),-20} {Truncate(remote, 28),-28} {country,5} {actionSymbol,5} {flow.TotalBytesDisplay,11} │\n");
                        }
                        output.Append("└───────────────────────────────────────────────────────────────────────┘\n");
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
                await RunLiveLegacyInternalAsync(vm, output, ct);
            }
            finally
            {
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

        private async Task RunLiveLegacyInternalAsync(ShellViewModel vm, ProgressViewModel output, System.Threading.CancellationToken ct)
        {
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
