using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using TGWST.App.Services;
using TGWST.App.ViewModels;
using TGWST.Core.Network;
using TGWST.Core.Network.Hybrid;

namespace TGWST.App.Windows
{
    public partial class NetworkOpsWindow : Window
    {
        private readonly ConnectionMonitor _monitor = new();
        private readonly HybridModeService _hybridMode;
        private readonly WslCredentialService _credentials;
        private readonly PiHoleBridgeService _piHole;
        private readonly IWslHybridAnalyzer _wslHybrid;
        private readonly DispatcherTimer _timer;
        private readonly Dictionary<string, EndpointInspectorWindow> _endpointWindows = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, EndpointTelemetrySnapshot> _endpointTelemetry = new(StringComparer.OrdinalIgnoreCase);
        private readonly EnrichmentService _enrichment = new();
        private readonly FlowRecordStore? _flowStore;
        private readonly object _flowStoreSync = new();
        private readonly List<int> _connectionHistory = new();
        private readonly List<int> _processHistory = new();
        private EndpointRow[] _allEndpointRows = Array.Empty<EndpointRow>();
        private string _selectedEndpointKey = string.Empty;

        private bool _refreshInProgress;
        private int _selectedTelemetryVersion;

        public NetworkOpsWindow(
            HybridModeService hybridMode,
            WslCredentialService credentials,
            PiHoleBridgeService piHole,
            IWslHybridAnalyzer wslHybrid)
        {
            InitializeComponent();
            _hybridMode = hybridMode;
            _credentials = credentials;
            _piHole = piHole;
            _wslHybrid = wslHybrid;
            try
            {
                _flowStore = new FlowRecordStore();
            }
            catch
            {
                _flowStore = null;
            }

            _timer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(3)
            };
            _timer.Tick += async (_, _) => await RefreshAllAsync(refreshPiHole: false);

            Loaded += OnLoaded;
            Closed += OnClosed;
            SizeChanged += (_, _) => RedrawSparklines();
        }

        private async void OnLoaded(object sender, RoutedEventArgs e)
        {
            _timer.Start();
            await RefreshAllAsync(refreshPiHole: true);
        }

        private void OnClosed(object? sender, EventArgs e)
        {
            _timer.Stop();
            foreach (var window in _endpointWindows.Values.ToArray())
            {
                try
                {
                    if (window.IsLoaded)
                    {
                        window.Close();
                    }
                }
                catch
                {
                    // best effort cleanup
                }
            }

            _endpointWindows.Clear();
            try
            {
                lock (_flowStoreSync)
                {
                    _flowStore?.Dispose();
                }
            }
            catch
            {
                // best effort cleanup
            }
        }

        private async Task RefreshAllAsync(bool refreshPiHole)
        {
            if (_refreshInProgress)
            {
                return;
            }

            _refreshInProgress = true;
            try
            {
                FooterText.Text = "Refreshing network operations data...";
                await RefreshOverviewAsync();

                if (refreshPiHole || ModeTabs.SelectedIndex == 1)
                {
                    await RefreshPiHoleStatusAsync();
                }

                if (string.IsNullOrWhiteSpace(FooterText.Text) || FooterText.Text.StartsWith("Refreshing", StringComparison.OrdinalIgnoreCase))
                {
                    FooterText.Text = "Dynamic dashboard active. Terminal remains available for command-level operations.";
                }
            }
            catch (Exception ex)
            {
                FooterText.Text = $"[X] Refresh failed: {ex.Message}";
            }
            finally
            {
                _refreshInProgress = false;
            }
        }

        private async Task RefreshOverviewAsync()
        {
            var connections = await _monitor.GetConnectionsAsync();
            var total = connections.Count;
            var uniqueProcesses = connections
                .Select(c => $"{c.ProcessName}:{c.Pid}")
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();
            var established = connections.Count(c =>
                string.Equals(c.State, "ESTABLISHED", StringComparison.OrdinalIgnoreCase));
            var uniqueRemotes = connections
                .Select(c => ParseEndpoint(c.RemoteAddress).Address)
                .Where(a => !string.IsNullOrWhiteSpace(a))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();
            var dnsResolved = connections.Count(c => !string.IsNullOrWhiteSpace(c.RemoteHost));
            var archiveRecordCount = TryGetFlowRecordCount();
            var topProcess = connections
                .Where(c => !string.IsNullOrWhiteSpace(c.ProcessName))
                .GroupBy(c => c.ProcessName, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Count())
                .Select(g => $"{g.Key} ({g.Count()})")
                .FirstOrDefault() ?? "-";
            var topRemote = connections
                .Select(c => string.IsNullOrWhiteSpace(c.RemoteHost) ? ParseEndpoint(c.RemoteAddress).Address : c.RemoteHost)
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .GroupBy(v => v, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Count())
                .Select(g => $"{g.Key} ({g.Count()})")
                .FirstOrDefault() ?? "-";

            TotalConnectionsValue.Text = total.ToString("N0");
            UniqueProcessesValue.Text = uniqueProcesses.ToString("N0");
            EstablishedValue.Text = established.ToString("N0");
            UniqueRemotesValue.Text = uniqueRemotes.ToString("N0");
            LastUpdateValue.Text = DateTime.Now.ToString("T");
            HeaderStatusText.Text = $"Live polling every {_timer.Interval.TotalSeconds:0}s | dns resolved: {dnsResolved:N0} | archive records: {archiveRecordCount:N0} | source: netstat + DNS + flowdb";
            FooterText.Text = $"Top process: {topProcess}  |  Top remote: {topRemote}";

            PushHistory(_connectionHistory, total, max: 50);
            PushHistory(_processHistory, uniqueProcesses, max: 50);
            RedrawSparklines();

            var rows = connections
                .OrderByDescending(c => c.Pid)
                .ThenBy(c => c.ProcessName, StringComparer.OrdinalIgnoreCase)
                .Take(250)
                .Select(MapEndpointRow)
                .ToArray();
            _allEndpointRows = rows;

            var liveKeys = rows.Select(r => r.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var staleTelemetryKeys = _endpointTelemetry.Keys
                .Where(key => !liveKeys.Contains(key))
                .ToArray();
            foreach (var stale in staleTelemetryKeys)
            {
                _endpointTelemetry.Remove(stale);
            }

            ApplyEndpointFilterAndSelection();

            UpdateOpenEndpointWindows(rows);
        }

        private async Task RefreshPiHoleStatusAsync()
        {
            try
            {
                var preferred = _hybridMode.PreferredDistro;
                var probeTask = _piHole.ProbeAsync(preferred);
                var hybridTask = _wslHybrid.ProbeAsync(preferred);
                var credentials = _credentials.GetSnapshot();

                var probe = await probeTask;
                var hybrid = await hybridTask;

                PiholeStatusLine.Text = $"Pi-hole: {(probe.IsPiHoleInstalled ? "Installed" : "Missing")} | Blocking: {(probe.IsBlockingEnabled ? "On" : "Off")} | FTL: {(probe.IsFtlReachable ? "Reachable" : "Not reachable")}";
                PiholeDistroLine.Text = $"Distro: {probe.Distro ?? "(none)"}";
                HybridLine.Text = $"Hybrid: {(hybrid.IsReady ? $"Ready ({hybrid.SelectedDistro})" : $"Degraded ({hybrid.FailureReason ?? "not ready"})")}";
                CredCacheLine.Text = $"WSL Cred Cache: {(credentials.IsEnabled && credentials.HasStoredPassword ? $"Configured ({credentials.UserName})" : "Not configured")}";
                PiholeReasonLine.Text = $"Detail: {probe.FailureReason ?? probe.StatusSummary ?? "No issues detected."}";
            }
            catch (Exception ex)
            {
                PiholeStatusLine.Text = "Pi-hole: error";
                PiholeReasonLine.Text = $"Detail: {ex.Message}";
            }
        }

        private void PushHistory(List<int> history, int value, int max)
        {
            history.Add(value);
            while (history.Count > max)
            {
                history.RemoveAt(0);
            }
        }

        private void RedrawSparklines()
        {
            DrawSparkline(ConnectionsSparkline, _connectionHistory);
            DrawSparkline(ProcessesSparkline, _processHistory);
        }

        private static void DrawSparkline(Polyline polyline, IReadOnlyList<int> points)
        {
            polyline.Points.Clear();
            if (points.Count == 0)
            {
                return;
            }

            var canvas = VisualTreeHelper.GetParent(polyline) as Canvas;
            var width = canvas?.ActualWidth ?? 0;
            var height = canvas?.ActualHeight ?? 0;
            if (width < 10 || height < 10)
            {
                width = 420;
                height = 64;
            }

            var max = Math.Max(1, points.Max());
            var min = Math.Min(points.Min(), max);
            var range = Math.Max(1, max - min);

            for (var i = 0; i < points.Count; i++)
            {
                var x = points.Count == 1 ? 0 : i * (width - 2) / (points.Count - 1);
                var normalized = (points[i] - min) / (double)range;
                var y = (height - 2) - (normalized * (height - 4));
                polyline.Points.Add(new Point(x + 1, y + 1));
            }
        }

        private EndpointRow MapEndpointRow(ConnectionInfo connection)
        {
            var local = ParseEndpoint(connection.LocalAddress);
            var remote = ParseEndpoint(connection.RemoteAddress);
            var remoteHost = string.IsNullOrWhiteSpace(connection.RemoteHost)
                ? remote.Address
                : connection.RemoteHost;

            return new EndpointRow(
                Key: BuildEndpointKey(connection),
                ProcessName: string.IsNullOrWhiteSpace(connection.ProcessName) ? "unknown" : connection.ProcessName,
                LocalDisplay: $"{local.Address}:{local.Port}",
                RemoteDisplay: $"{remoteHost}:{remote.Port}",
                Protocol: connection.Protocol,
                State: connection.State,
                Pid: connection.Pid,
                RemoteAddress: remote.Address,
                RemotePort: remote.Port,
                LocalAddress: local.Address,
                LocalPort: local.Port,
                RemoteHost: connection.RemoteHost ?? string.Empty);
        }

        private static bool MatchesEndpointFilter(EndpointRow row, string filter)
        {
            if (string.IsNullOrWhiteSpace(filter))
            {
                return true;
            }

            var term = filter.Trim();
            return row.ProcessName.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                   row.LocalDisplay.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                   row.RemoteDisplay.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                   row.RemoteAddress.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                   row.RemoteHost.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                   row.State.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                   row.Protocol.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                   row.Pid.ToString().Contains(term, StringComparison.OrdinalIgnoreCase);
        }

        private void ApplyEndpointFilterAndSelection()
        {
            var filter = EndpointFilterBox.Text ?? string.Empty;
            var filtered = _allEndpointRows
                .Where(row => MatchesEndpointFilter(row, filter))
                .ToArray();

            EndpointList.ItemsSource = filtered;
            OverviewStatusText.Text = $"{filtered.Length:N0}/{_allEndpointRows.Length:N0} rows";

            if (filtered.Length == 0)
            {
                UpdateSelectedEndpointPanel(null);
                return;
            }

            var selected = filtered.FirstOrDefault(row =>
                string.Equals(row.Key, _selectedEndpointKey, StringComparison.OrdinalIgnoreCase)) ?? filtered[0];
            EndpointList.SelectedItem = selected;
            UpdateSelectedEndpointPanel(selected);
        }

        private static string BuildEndpointInsight(EndpointRow row)
        {
            if (string.IsNullOrWhiteSpace(row.RemoteAddress))
            {
                return "Listening/local endpoint. Monitor inbound exposure.";
            }

            if (row.RemotePort is 23 or 445 or 3389 or 5900)
            {
                return "High-risk remote service port observed. Validate necessity and source.";
            }

            if (IsPrivateAddress(row.RemoteAddress))
            {
                return "Private/internal endpoint traffic. Lower exposure unless untrusted VLANs exist.";
            }

            if (string.IsNullOrWhiteSpace(row.RemoteHost))
            {
                return "External IP without DNS hostname. Inspect this endpoint for reputation and ownership.";
            }

            if (row.RemotePort is 80 or 443 or 53)
            {
                return "Common service port. Correlate with process identity and expected destination.";
            }

            return "Endpoint observed. Use isolate window for per-connection DNS/process review.";
        }

        private static bool IsPrivateAddress(string address)
        {
            if (!System.Net.IPAddress.TryParse(address, out var ip))
            {
                return false;
            }

            if (System.Net.IPAddress.IsLoopback(ip))
            {
                return true;
            }

            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast;
            }

            var bytes = ip.GetAddressBytes();
            if (bytes.Length != 4)
            {
                return false;
            }

            return bytes[0] switch
            {
                10 => true,
                127 => true,
                172 when bytes[1] is >= 16 and <= 31 => true,
                192 when bytes[1] == 168 => true,
                _ => false
            };
        }

        private void UpdateSelectedEndpointPanel(EndpointRow? row)
        {
            if (row == null)
            {
                SelectedEndpointPrimary.Text = "[SELECTED ENDPOINT] none";
                SelectedEndpointSecondary.Text = "Select a row to view local/remote route and DNS context.";
                SelectedEndpointInsight.Text = "Insight: -";
                SelectedEndpointDnsEvidence.Text = "DNS evidence: -";
                SelectedEndpointHistory.Text = "History pull: -";
                SelectedEndpointActions.Text = "Action mix: -";
                SelectedEndpointRecordSource.Text = "Record source: -";
                return;
            }

            var dnsHost = string.IsNullOrWhiteSpace(row.RemoteHost) ? "(unresolved)" : row.RemoteHost;
            SelectedEndpointPrimary.Text = $"[SELECTED ENDPOINT] {row.ProcessName} (PID {row.Pid})  {row.Protocol}/{row.State}";
            SelectedEndpointSecondary.Text = $"Route: {row.LocalDisplay} -> {row.RemoteDisplay}  |  DNS: {dnsHost}";
            SelectedEndpointInsight.Text = $"Insight: {BuildEndpointInsight(row)}";
            SelectedEndpointDnsEvidence.Text = "DNS evidence: collecting live + archive context...";
            SelectedEndpointHistory.Text = "History pull: querying archived flow records...";
            SelectedEndpointActions.Text = "Action mix: loading...";
            SelectedEndpointRecordSource.Text = "Record source: live netstat + DNS + flowdb (if available).";
        }

        private async Task RefreshSelectedEndpointTelemetryAsync(EndpointRow? row)
        {
            var version = Interlocked.Increment(ref _selectedTelemetryVersion);
            if (row == null)
            {
                return;
            }

            var telemetry = await BuildAndCacheEndpointTelemetryAsync(row);
            if (version != Volatile.Read(ref _selectedTelemetryVersion))
            {
                return;
            }

            ApplySelectedEndpointTelemetry(telemetry);
        }

        private void ApplySelectedEndpointTelemetry(EndpointTelemetrySnapshot telemetry)
        {
            SelectedEndpointDnsEvidence.Text = telemetry.DnsEvidence;
            SelectedEndpointHistory.Text = telemetry.HistoryPull;
            SelectedEndpointActions.Text = telemetry.ActionMix;
            SelectedEndpointRecordSource.Text = telemetry.RecordSource;

            if (!string.IsNullOrWhiteSpace(_selectedEndpointKey) &&
                !string.IsNullOrWhiteSpace(telemetry.ResolvedRemoteHost))
            {
                var selected = _allEndpointRows.FirstOrDefault(row =>
                    string.Equals(row.Key, _selectedEndpointKey, StringComparison.OrdinalIgnoreCase));
                if (selected != null)
                {
                    SelectedEndpointSecondary.Text =
                        $"Route: {selected.LocalDisplay} -> {selected.RemoteDisplay}  |  DNS: {telemetry.ResolvedRemoteHost}";
                }
            }
        }

        private async Task<EndpointTelemetrySnapshot> BuildAndCacheEndpointTelemetryAsync(EndpointRow row)
        {
            EndpointTelemetrySnapshot telemetry;
            try
            {
                telemetry = await Task.Run(() => BuildEndpointTelemetry(row));
            }
            catch (Exception ex)
            {
                telemetry = EndpointTelemetrySnapshot.Error($"Telemetry unavailable: {ex.Message}");
            }

            _endpointTelemetry[row.Key] = telemetry;

            if (_endpointWindows.TryGetValue(row.Key, out var window) && window.IsLoaded)
            {
                window.RefreshTarget(CreateInspectorItem(row));
            }

            return telemetry;
        }

        private EndpointTelemetrySnapshot BuildEndpointTelemetry(EndpointRow row)
        {
            var resolvedHost = string.IsNullOrWhiteSpace(row.RemoteHost)
                ? string.Empty
                : row.RemoteHost.Trim();

            string dnsEvidence;
            if (string.IsNullOrWhiteSpace(row.RemoteAddress))
            {
                dnsEvidence = "DNS evidence: local/listening endpoint; no remote hostname to resolve.";
            }
            else if (!string.IsNullOrWhiteSpace(resolvedHost))
            {
                dnsEvidence = $"DNS evidence: live resolver mapped {row.RemoteAddress} -> {resolvedHost}.";
            }
            else if (System.Net.IPAddress.TryParse(row.RemoteAddress, out var ip))
            {
                try
                {
                    var reverse = System.Net.Dns.GetHostEntry(ip).HostName;
                    if (string.IsNullOrWhiteSpace(reverse))
                    {
                        dnsEvidence = $"DNS evidence: reverse lookup returned no hostname for {row.RemoteAddress}.";
                    }
                    else
                    {
                        resolvedHost = reverse;
                        dnsEvidence = $"DNS evidence: on-demand reverse lookup resolved {row.RemoteAddress} -> {reverse}.";
                    }
                }
                catch
                {
                    dnsEvidence = $"DNS evidence: reverse lookup unavailable for {row.RemoteAddress}.";
                }
            }
            else
            {
                dnsEvidence = $"DNS evidence: remote endpoint '{row.RemoteAddress}' is not an IP literal.";
            }

            var historyPull = "History pull: flow archive unavailable on this host.";
            var actionMix = "Action mix: unavailable.";
            var recordSource = "Record source: live netstat + DNS resolver.";

            if (_flowStore != null && !string.IsNullOrWhiteSpace(row.RemoteAddress))
            {
                var sinceUtc = DateTime.UtcNow.AddDays(-7);
                List<FlowRecord> records;
                lock (_flowStoreSync)
                {
                    records = _flowStore
                        .GetFlowsByEndpoint(
                            row.RemoteAddress,
                            row.RemotePort,
                            row.Pid > 0 ? row.Pid : null,
                            sinceUtc,
                            limit: 300)
                        .ToList();
                }

                if (records.Count == 0)
                {
                    historyPull = "History pull: no archived flow matches for this endpoint in last 7 days.";
                    actionMix = "Action mix: none observed in archive window.";
                    recordSource = $"Record source: SQLite flow archive (0 rows) + live monitor ({row.RemoteAddress}:{row.RemotePort}).";
                }
                else
                {
                    var totalBytes = records.Sum(f => f.TotalBytes);
                    var firstSeen = records.Min(f => f.FirstSeen).ToLocalTime();
                    var lastSeen = records.Max(f => f.LastSeen).ToLocalTime();
                    var allow = records.Count(f => f.Action == FlowAction.Allow);
                    var blocked = records.Count(f => f.Action == FlowAction.Block);
                    var dropped = records.Count(f => f.Action == FlowAction.Drop);

                    historyPull = $"History pull: {records.Count} records / 7d | total {FlowRecord.FormatBytes(totalBytes)} | first {firstSeen:g} | last {lastSeen:g}";
                    actionMix = $"Action mix: allow {allow} | block {blocked} | drop {dropped}";
                    recordSource = $"Record source: SQLite flow archive + live monitor (query {row.RemoteAddress}:{row.RemotePort}, pid {row.Pid}).";

                    if (string.IsNullOrWhiteSpace(resolvedHost))
                    {
                        var archiveHost = records
                            .Select(r => r.RemoteHostname)
                            .FirstOrDefault(host => !string.IsNullOrWhiteSpace(host));
                        if (!string.IsNullOrWhiteSpace(archiveHost))
                        {
                            resolvedHost = archiveHost;
                            dnsEvidence += $" Archive telemetry hostname: {archiveHost}.";
                        }
                    }
                }
            }

            var processIdentity = BuildProcessIdentity(row, out var processPath, out var processSigner);
            return new EndpointTelemetrySnapshot(
                DnsEvidence: dnsEvidence,
                HistoryPull: historyPull,
                ActionMix: actionMix,
                RecordSource: recordSource,
                ProcessIdentity: processIdentity,
                ResolvedRemoteHost: resolvedHost,
                ProcessPath: processPath,
                ProcessSigner: processSigner);
        }

        private string BuildProcessIdentity(EndpointRow row, out string processPath, out string processSigner)
        {
            processPath = string.Empty;
            processSigner = string.Empty;

            if (row.Pid <= 0)
            {
                processSigner = "system";
                return "Process identity: reserved/system PID; executable identity unavailable.";
            }

            try
            {
                var info = _enrichment.GetProcessInfo(row.Pid);
                processPath = info.Path ?? string.Empty;
                var displayPath = string.IsNullOrWhiteSpace(processPath) ? "(path unavailable)" : processPath;
                processSigner = string.IsNullOrWhiteSpace(processPath)
                    ? "unknown"
                    : _enrichment.GetFileSigner(processPath) ?? "unsigned/unknown";

                return $"Process identity: {Truncate(displayPath, 74)} | signer: {Truncate(processSigner, 30)}";
            }
            catch (Exception ex)
            {
                processSigner = "unknown";
                return $"Process identity: unavailable ({Truncate(ex.Message, 56)}).";
            }
        }

        private void UpdateOpenEndpointWindows(IReadOnlyCollection<EndpointRow> rows)
        {
            if (_endpointWindows.Count == 0)
            {
                return;
            }

            var byKey = rows.ToDictionary(r => r.Key, StringComparer.OrdinalIgnoreCase);
            foreach (var (key, window) in _endpointWindows.ToArray())
            {
                if (!window.IsLoaded)
                {
                    _endpointWindows.Remove(key);
                    continue;
                }

                if (!byKey.TryGetValue(key, out var row))
                {
                    continue;
                }

                window.RefreshTarget(CreateInspectorItem(row));
            }
        }

        private static string BuildEndpointKey(ConnectionInfo connection)
        {
            var remote = ParseEndpoint(connection.RemoteAddress);
            return $"{connection.Pid}|{remote.Address.ToLowerInvariant()}:{remote.Port}";
        }

        private static (string Address, int Port) ParseEndpoint(string endpoint)
        {
            var value = (endpoint ?? string.Empty).Trim();
            if (value.Length == 0 || value == "*:*" || value == "*")
            {
                return (string.Empty, 0);
            }

            if (value.StartsWith("[", StringComparison.Ordinal))
            {
                var idx = value.LastIndexOf("]:", StringComparison.Ordinal);
                if (idx > 0)
                {
                    var address = value[1..idx].Trim();
                    var portText = value[(idx + 2)..].Trim();
                    return (address, int.TryParse(portText, out var p) ? p : 0);
                }
            }

            var lastColon = value.LastIndexOf(':');
            if (lastColon > 0 && lastColon < value.Length - 1)
            {
                var address = value[..lastColon].Trim();
                var portText = value[(lastColon + 1)..].Trim();
                return (address, int.TryParse(portText, out var p) ? p : 0);
            }

            return (value, 0);
        }

        private static string Truncate(string value, int max)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= max)
            {
                return value;
            }

            if (max <= 3)
            {
                return value[..Math.Max(1, max)];
            }

            return value[..(max - 3)] + "...";
        }

        private EndpointFocusItem CreateInspectorItem(EndpointRow row)
        {
            var telemetry = _endpointTelemetry.TryGetValue(row.Key, out var cached)
                ? cached
                : EndpointTelemetrySnapshot.Empty;
            var remoteHost = !string.IsNullOrWhiteSpace(row.RemoteHost)
                ? row.RemoteHost
                : telemetry.ResolvedRemoteHost;
            var now = DateTime.Now;
            var snapshot = new EndpointFocusSnapshot(
                EndpointKey: row.Key,
                ProcessId: row.Pid,
                ProcessName: row.ProcessName,
                ProcessPath: telemetry.ProcessPath,
                ProcessSigner: telemetry.ProcessSigner,
                Protocol: row.Protocol,
                LocalAddress: row.LocalAddress,
                LocalPort: row.LocalPort,
                RemoteAddress: row.RemoteAddress,
                RemotePort: row.RemotePort,
                RemoteHostname: remoteHost ?? string.Empty,
                RemoteCountry: "--",
                ActionSymbol: "✓",
                ActionText: "Observe",
                RiskToken: "--",
                RiskScore: 0,
                RiskReasons: "none",
                ThroughputSparkline: "----------",
                BytesSent: 0,
                BytesReceived: 0,
                FirstSeenLocal: now,
                LastSeenLocal: now);

            var item = EndpointFocusItem.FromSnapshot(snapshot);
            item.SetInspectionContext(new EndpointInspectionContext(
                HistoricalRecords: telemetry.HistoryPull,
                HistoricalActions: telemetry.ActionMix,
                RecordPull: telemetry.RecordSource,
                DnsEvidence: telemetry.DnsEvidence,
                ProcessIdentity: telemetry.ProcessIdentity));
            return item;
        }

        private async void RefreshNowButton_Click(object sender, RoutedEventArgs e)
        {
            await RefreshAllAsync(refreshPiHole: true);
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void OpenWslCredsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var window = new WslCredentialsWindow(_credentials, _hybridMode.PreferredDistro) { Owner = this };
                window.Show();
            }
            catch (Exception ex)
            {
                FooterText.Text = $"[X] Unable to open WSL credentials: {ex.Message}";
            }
        }

        private async void EndpointList_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (EndpointList.SelectedItem is not EndpointRow row)
            {
                return;
            }

            try
            {
                var item = CreateInspectorItem(row);
                if (_endpointWindows.TryGetValue(row.Key, out var existing) && existing.IsLoaded)
                {
                    existing.RefreshTarget(item);
                    existing.Activate();
                    await BuildAndCacheEndpointTelemetryAsync(row);
                    return;
                }

                var window = new EndpointInspectorWindow(item) { Owner = this };
                window.Closed += (_, _) => _endpointWindows.Remove(row.Key);
                _endpointWindows[row.Key] = window;
                window.Show();
                await BuildAndCacheEndpointTelemetryAsync(row);
            }
            catch (Exception ex)
            {
                FooterText.Text = $"[X] Unable to open endpoint inspector: {ex.Message}";
            }
        }

        private async void EndpointList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var row = EndpointList.SelectedItem as EndpointRow;
            _selectedEndpointKey = row?.Key ?? string.Empty;
            UpdateSelectedEndpointPanel(row);
            await RefreshSelectedEndpointTelemetryAsync(row);
        }

        private void EndpointFilterBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            ApplyEndpointFilterAndSelection();
        }

        private async void RefreshPiHoleButton_Click(object sender, RoutedEventArgs e)
        {
            await RefreshPiHoleStatusAsync();
            PiHoleActionStatusText.Text = $"Refreshed {DateTime.Now:T}";
        }

        private async void RefreshTopBlockedButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var items = await _piHole.GetTopBlockedDomainsAsync(20);
                TopBlockedList.ItemsSource = items.Select(i => new TopBlockedRow(i.Domain, i.BlockedCount.ToString("N0"))).ToArray();
                PiHoleActionStatusText.Text = $"Loaded {items.Count} domains";
            }
            catch (Exception ex)
            {
                PiHoleActionStatusText.Text = $"[X] {ex.Message}";
            }
        }

        private async void EnablePiHoleButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var message = await _piHole.EnableBlockingAsync(_hybridMode.PreferredDistro);
                PiHoleActionStatusText.Text = message;
                await RefreshPiHoleStatusAsync();
            }
            catch (Exception ex)
            {
                PiHoleActionStatusText.Text = $"[X] {ex.Message}";
            }
        }

        private async void DisablePiHoleButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var message = await _piHole.DisableBlockingAsync("5m", _hybridMode.PreferredDistro);
                PiHoleActionStatusText.Text = message;
                await RefreshPiHoleStatusAsync();
            }
            catch (Exception ex)
            {
                PiHoleActionStatusText.Text = $"[X] {ex.Message}";
            }
        }

        private async void UpdateGravityButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var message = await _piHole.UpdateGravityAsync(_hybridMode.PreferredDistro);
                PiHoleActionStatusText.Text = message;
                await RefreshPiHoleStatusAsync();
            }
            catch (Exception ex)
            {
                PiHoleActionStatusText.Text = $"[X] {ex.Message}";
            }
        }

        private long TryGetFlowRecordCount()
        {
            if (_flowStore == null)
            {
                return 0;
            }

            try
            {
                lock (_flowStoreSync)
                {
                    return _flowStore.GetStats().FlowCount;
                }
            }
            catch
            {
                return 0;
            }
        }

        private sealed record EndpointTelemetrySnapshot(
            string DnsEvidence,
            string HistoryPull,
            string ActionMix,
            string RecordSource,
            string ProcessIdentity,
            string ResolvedRemoteHost,
            string ProcessPath,
            string ProcessSigner)
        {
            public static EndpointTelemetrySnapshot Empty { get; } = new(
                DnsEvidence: "DNS evidence: unresolved.",
                HistoryPull: "History pull: unavailable.",
                ActionMix: "Action mix: unavailable.",
                RecordSource: "Record source: live netstat + DNS resolver.",
                ProcessIdentity: "Process identity: unavailable.",
                ResolvedRemoteHost: string.Empty,
                ProcessPath: string.Empty,
                ProcessSigner: string.Empty);

            public static EndpointTelemetrySnapshot Error(string message)
            {
                var normalized = string.IsNullOrWhiteSpace(message)
                    ? "unavailable"
                    : message.Trim();
                return new EndpointTelemetrySnapshot(
                    DnsEvidence: $"DNS evidence: {normalized}",
                    HistoryPull: "History pull: unavailable.",
                    ActionMix: "Action mix: unavailable.",
                    RecordSource: "Record source: live netstat + DNS resolver.",
                    ProcessIdentity: "Process identity: unavailable.",
                    ResolvedRemoteHost: string.Empty,
                    ProcessPath: string.Empty,
                    ProcessSigner: string.Empty);
            }
        }

        private sealed record EndpointRow(
            string Key,
            string ProcessName,
            string LocalDisplay,
            string RemoteDisplay,
            string Protocol,
            string State,
            int Pid,
            string RemoteAddress,
            int RemotePort,
            string LocalAddress,
            int LocalPort,
            string RemoteHost);

        private sealed record TopBlockedRow(string Domain, string BlockedCount);
    }
}
