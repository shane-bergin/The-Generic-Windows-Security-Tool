using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using TGWST.App.ViewModels;
using TGWST.Core.Network;
using TGWST.Core.Network.Capture;

namespace TGWST.App.Services;

public sealed class NetworkTelemetryService : IDisposable
{
    private readonly FirewallStatusService _firewallStatus;
    private readonly IpHelperPoller _poller = new();
    private readonly object _sampleGate = new();
    private long _lastBytesReceived;
    private long _lastBytesSent;
    private DateTimeOffset _lastSampleTime = DateTimeOffset.MinValue;
    private bool _disposed;

    public NetworkTelemetryService(FirewallStatusService firewallStatus)
    {
        _firewallStatus = firewallStatus;
    }

    public Task<NetworkTelemetrySnapshot> GetSnapshotAsync(CancellationToken ct = default)
    {
        return Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();
            var snapshot = _poller.GetCurrentConnections();
            var rows = snapshot.Connections
                .Select(MapConnection)
                .OrderByDescending(row => row.RiskScore)
                .ThenBy(row => row.Process, StringComparer.OrdinalIgnoreCase)
                .Take(300)
                .ToArray();

            var riskyRows = new List<NetworkConnectionRow>();
            foreach (var row in rows.Where(r => r.RiskScore >= 35).Take(80))
            {
                var enriched = await EnrichWithIntelAsync(row, ct).ConfigureAwait(false);
                riskyRows.Add(enriched);
            }
            var inboundRows = rows
                .Where(IsInboundActivity)
                .Take(100)
                .ToArray();
            var firewall = await ReadFirewallAsync(ct).ConfigureAwait(false);
            var bandwidth = SampleBandwidth();
            var inboundExposure = rows.Count(row => IsListeningExposure(row));
            var outbound = rows.Count(row => IsOutbound(row));

            return new NetworkTelemetrySnapshot(
                Timestamp: DateTimeOffset.Now,
                TotalConnections: rows.Length,
                InboundExposure: inboundExposure,
                OutboundConnections: outbound,
                RiskyConnections: riskyRows,
                InboundActivity: inboundRows,
                Connections: rows,
                BandwidthStatus: bandwidth,
                FirewallStatusText: firewall,
                HighestRiskScore: riskyRows.FirstOrDefault()?.RiskScore ?? 0);
        }, ct);
    }

    private async Task<string> ReadFirewallAsync(CancellationToken ct)
    {
        try
        {
            ct.ThrowIfCancellationRequested();
            var profiles = await _firewallStatus.GetStatusAsync().ConfigureAwait(false);
            if (profiles.Count == 0)
            {
                return "UNKNOWN";
            }

            var vulnerable = profiles.Count(profile => profile.IsVulnerable);
            return vulnerable == 0
                ? "ON / INBOUND BLOCKED"
                : $"ATTENTION / {vulnerable} PROFILE(S)";
        }
        catch
        {
            return "UNAVAILABLE";
        }
    }

    private string SampleBandwidth()
    {
        var counters = NetworkInterface.GetAllNetworkInterfaces()
            .Where(adapter => adapter.OperationalStatus == OperationalStatus.Up &&
                              adapter.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Select(adapter => adapter.GetIPv4Statistics())
            .ToArray();

        var bytesReceived = counters.Sum(stat => stat.BytesReceived);
        var bytesSent = counters.Sum(stat => stat.BytesSent);
        var now = DateTimeOffset.Now;

        lock (_sampleGate)
        {
            if (_lastSampleTime == DateTimeOffset.MinValue)
            {
                _lastBytesReceived = bytesReceived;
                _lastBytesSent = bytesSent;
                _lastSampleTime = now;
                return "sampling";
            }

            var elapsed = Math.Max(1, (now - _lastSampleTime).TotalSeconds);
            var receivedRate = Math.Max(0, (bytesReceived - _lastBytesReceived) / elapsed);
            var sentRate = Math.Max(0, (bytesSent - _lastBytesSent) / elapsed);

            _lastBytesReceived = bytesReceived;
            _lastBytesSent = bytesSent;
            _lastSampleTime = now;

            return $"IN {FormatBytes(receivedRate)}/s  OUT {FormatBytes(sentRate)}/s";
        }
    }

    private static NetworkConnectionRow MapConnection(ConnectionEntry entry)
    {
        var localAddress = NormalizeAddress(entry.LocalAddress);
        var remoteAddress = NormalizeAddress(entry.RemoteAddress);
        var local = $"{localAddress}:{entry.LocalPort}";
        var remote = entry.RemotePort > 0
            ? $"{remoteAddress}:{entry.RemotePort}"
            : remoteAddress;
        var risk = ScoreRisk(entry, out var reason);
        var service = NetworkProtocolCatalog.Classify(entry.Protocol, entry.LocalPort, entry.RemotePort);
        var state = entry.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase)
            ? "UDP"
            : entry.State.ToString().ToUpperInvariant();
        var protocolType = NetworkProtocolCatalog.BuildProtocolType(entry.Protocol, service);
        var protocolConcern = NetworkProtocolCatalog.DescribeConcern(
            entry.Protocol,
            service,
            entry.LocalPort,
            entry.RemotePort,
            localAddress,
            remoteAddress,
            state,
            reason);
        var processIdentity = CaptureProcessIdentity(entry.ProcessId);

        return new NetworkConnectionRow(
            Process: string.IsNullOrWhiteSpace(entry.ProcessName) ? "Unknown" : entry.ProcessName,
            ProcessId: entry.ProcessId,
            Protocol: entry.Protocol,
            ProtocolType: protocolType,
            Service: service,
            Local: local,
            LocalAddress: localAddress,
            LocalPort: entry.LocalPort,
            Remote: remote,
            RemoteAddress: remoteAddress,
            RemotePort: entry.RemotePort,
            State: state,
            RiskScore: risk,
            Risk: reason,
            ProtocolConcern: protocolConcern,
            ProtocolInspection: BuildInspection(entry, protocolType, service, local, remote, state, risk, reason, protocolConcern),
            ProcessStartTime: processIdentity.StartTime,
            ExecutablePath: processIdentity.ExecutablePath);
    }

    private static (DateTimeOffset? StartTime, string? ExecutablePath) CaptureProcessIdentity(int processId)
    {
        if (processId <= 0)
        {
            return (null, null);
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            var startTime = new DateTimeOffset(process.StartTime);
            string? executablePath = null;
            try
            {
                executablePath = process.MainModule?.FileName;
            }
            catch
            {
                // Protected processes remain inspectable but are not eligible for PID-based response.
            }

            return (startTime, executablePath);
        }
        catch
        {
            return (null, null);
        }
    }

    private static string BuildInspection(
        ConnectionEntry entry,
        string protocolType,
        string service,
        string local,
        string remote,
        string state,
        int risk,
        string reason,
        string protocolConcern)
    {
        var process = string.IsNullOrWhiteSpace(entry.ProcessName) ? "Unknown" : entry.ProcessName;
        var ownership = entry.ProcessId > 0
            ? $"The owning PID is {entry.ProcessId} ({process})."
            : "The owning process could not be resolved from the IP helper table.";
        var response = BuildResponseAdvice(service, state);

        return $"{protocolType} / {service}. {ownership} Local={local}; Remote={remote}; State={state}; Risk={risk}/100 ({reason}). {protocolConcern} {response}";
    }

    private static string BuildResponseAdvice(string service, string state)
    {
        var listener = state.Equals("LISTEN", StringComparison.OrdinalIgnoreCase) ||
                       state.Equals("UDP", StringComparison.OrdinalIgnoreCase);
        if (listener && service.Equals("DNS", StringComparison.OrdinalIgnoreCase))
        {
            return "Validate the owning service and interface binding. If this workstation is not intentionally acting as a DNS resolver, restrict inbound UDP/TCP 53 to localhost or trusted private ranges, or disable the resolver service.";
        }

        return listener
            ? "If this listener is unexpected, identify the service, disable it, or add a firewall block before killing anything important."
            : "If the remote endpoint is unexpected, inspect the process path and consider a remote-IP firewall block.";
    }

    private static int ScoreRisk(ConnectionEntry entry, out string reason)
    {
        var score = 0;
        var reasons = new List<string>();
        var remotePublic = IsPublicAddress(entry.RemoteAddress);
        var listening = entry.Protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase) &&
                        entry.State == TGWST.Core.Network.TcpState.Listen;

        if (listening && IsAnyAddress(entry.LocalAddress))
        {
            score += 35;
            reasons.Add("wide listener");
        }

        if (remotePublic && entry.State == TGWST.Core.Network.TcpState.Established)
        {
            score += 25;
            reasons.Add("public remote");
        }

        if (IsSensitivePort(entry.LocalPort) || IsSensitivePort(entry.RemotePort))
        {
            score += 25;
            reasons.Add("sensitive port");
        }

        if (entry.ProcessId <= 0 || entry.ProcessName.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
        {
            score += 15;
            reasons.Add("unresolved process");
        }

        if (entry.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase) && IsAnyAddress(entry.LocalAddress))
        {
            score += 10;
            reasons.Add("udp wildcard");
        }

        reason = reasons.Count == 0 ? "baseline" : string.Join(", ", reasons);
        return Math.Clamp(score, 0, 100);
    }

    private static bool IsOutbound(NetworkConnectionRow row)
    {
        return row.State.Equals("ESTABLISHED", StringComparison.OrdinalIgnoreCase) &&
               row.HasRemoteAddress &&
               !row.RemoteAddress.StartsWith("127.", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsListeningExposure(NetworkConnectionRow row)
    {
        return row.State.Equals("LISTEN", StringComparison.OrdinalIgnoreCase) &&
               IsAnyAddress(row.LocalAddress);
    }

    private static bool IsInboundActivity(NetworkConnectionRow row)
    {
        if (row.IsListener)
        {
            return true;
        }

        // The owner-PID IP Helper tables do not identify which peer initiated an
        // established TCP session. Do not label an established flow as inbound
        // solely because its remote address is public.
        return false;
    }

    private static bool IsSensitivePort(int port)
    {
        return port is 20 or 21 or 22 or 23 or 25 or 53 or 90 or 135 or 139 or 389 or 445 or 636
            or 1433 or 1521 or 3306 or 3389 or 5432 or 5900 or 5985 or 5986;
    }

    private static bool IsAnyAddress(string address)
    {
        return string.IsNullOrWhiteSpace(address) ||
               address.Equals("0.0.0.0", StringComparison.OrdinalIgnoreCase) ||
               address.Equals("::", StringComparison.OrdinalIgnoreCase) ||
               address.Equals("*", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPublicAddress(string address)
    {
        if (!IPAddress.TryParse(address, out var ip))
        {
            return false;
        }

        var bytes = ip.GetAddressBytes();
        if (bytes.Length != 4)
        {
            return false;
        }

        return bytes[0] != 10 &&
               !(bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) &&
               !(bytes[0] == 192 && bytes[1] == 168) &&
               bytes[0] != 127 &&
               !(bytes[0] == 169 && bytes[1] == 254) &&
               !address.Equals("0.0.0.0", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeAddress(string address)
    {
        return string.IsNullOrWhiteSpace(address) ? "*" : address;
    }

    private static string FormatBytes(double bytesPerSecond)
    {
        string[] units = ["B", "KB", "MB", "GB"];
        var value = bytesPerSecond;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value:0.##} {units[unit]}";
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _poller.Dispose();
    }

    // === DNS + Backdoor / CVE Heuristics ===
    private static readonly HashSet<int> SuspiciousPorts = new()
    {
        4444, 9001, 1337, 31337, 1234, 6666, 6667, 8080, 8443, 9999, 1604, 4445, 5555
    };

    public async Task<NetworkConnectionRow> EnrichWithIntelAsync(NetworkConnectionRow row, CancellationToken ct = default)
    {
        if (!row.HasRemoteAddress || row.RiskScore < 40)
            return row;

        string? remoteHost = null;
        string? anomaly = null;

        // DNS reverse lookup (best effort, non-blocking)
        try
        {
            var entry = await Dns.GetHostEntryAsync(row.RemoteAddress, ct).ConfigureAwait(false);
            remoteHost = entry.HostName;
        }
        catch { /* many IPs have no reverse DNS */ }

        // Backdoor / exploitation heuristics
        var reasons = new List<string>();

        if (SuspiciousPorts.Contains(row.RemotePort) || SuspiciousPorts.Contains(row.LocalPort))
            reasons.Add("known malicious/C2 port");

        if (row.Process.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase) && row.RemotePort > 1024)
            reasons.Add("explorer.exe outbound to high port");

        if (row.RiskScore >= 70 &&
            (row.Process.Contains("rundll32", StringComparison.OrdinalIgnoreCase) ||
             row.Process.Contains("regsvr32", StringComparison.OrdinalIgnoreCase)))
            reasons.Add("LOLBin with high-risk connection");

        if (reasons.Count > 0)
            anomaly = string.Join("; ", reasons);

        var enriched = row with { RemoteHost = remoteHost, Anomaly = anomaly };
        var category = ClassifyConnection(enriched, remoteHost);

        if (remoteHost == null && anomaly == null)
            return row with { Category = category };

        return enriched with { Category = category };
    }

    private static string ClassifyConnection(NetworkConnectionRow row, string? remoteHost)
    {
        var process = row.Process.ToLowerInvariant();
        var host = remoteHost?.ToLowerInvariant() ?? "";
        var port = row.RemotePort;

        bool hasBackdoorIndicators =
            SuspiciousPorts.Contains(port) ||
            (row.Anomaly != null) ||
            (row.RiskScore >= 70 &&
             (process.Contains("rundll32") || process.Contains("regsvr32") ||
              process.Equals("explorer.exe")));

        // === Strong backdoor signals ===
        if (hasBackdoorIndicators && row.RiskScore >= 65)
            return "PotentialC2";

        // Infrastructure naming is a weak heuristic (including attacker-controlled
        // reverse DNS), so it must never override stronger local anomaly evidence.
        if (IsTypicalInfrastructureActivity(process, host, row))
            return "typicalprocess";

        // === Microsoft Telemetry & Diagnostics (with anomaly awareness) ===
        if (process.Contains("diagtrack") || process.Contains("telemetry") ||
            host.Contains("vortex.data.microsoft") || host.Contains("settings-win.data.microsoft") ||
            host.Contains("telemetry") || host.Contains("diagnostics"))
        {
            if (hasBackdoorIndicators || row.RiskScore >= 75)
                return "PotentialC2";
            return "MicrosoftTelemetry";
        }

        // === Windows Update / Delivery Optimization ===
        if (process.Contains("wuauclt") || process.Contains("deliveryoptimization") ||
            host.Contains("windowsupdate") || host.Contains("update.microsoft") ||
            host.Contains("delivery.mp.microsoft"))
            return "WindowsUpdate";

        // === Windows Defender ===
        if (process.Contains("msmpeng") || process.Contains("mpdefender") ||
            process.Contains("defender"))
            return "WindowsDefender";

        // === Core OS Components (svchost, search, diagnostics) ===
        if (process == "svchost.exe" || process.Contains("searchindexer") ||
            process.Contains("searchprotocolhost") || process.Contains("comptelrunner"))
        {
            if (hasBackdoorIndicators || row.RiskScore >= 70)
                return "PotentialC2";
            return "CoreOSComponent";
        }

        // === Browser / Web (with risk context) ===
        if (process.Contains("chrome") || process.Contains("msedge") ||
            process.Contains("firefox") || process.Contains("brave"))
        {
            if (hasBackdoorIndicators || row.RiskScore >= 80)
                return "PotentialC2";
            return "BrowserWeb";
        }

        // === Cloud Storage ===
        if (process.Contains("onedrive") || process.Contains("syncengine"))
            return "CloudStorage";

        // === Generic Microsoft Infrastructure ===
        if (host.Contains("microsoft") || host.Contains("msft") || host.Contains("msedge"))
            return "MicrosoftInfrastructure";

        return "Other";
    }

    private static bool IsTypicalInfrastructureActivity(string process, string host, NetworkConnectionRow row)
    {
        // Known Microsoft cloud infrastructure patterns
        if (host.Contains(".scloud.microsoft") ||
            host.Contains(".microsoft.us") ||
            host.Contains("azure.microsoft.scloud") ||
            host.Contains("azure.us"))
            return true;

        // Core OS components on Microsoft infrastructure
        if ((process == "svchost.exe" || process.Contains("searchindexer")) &&
            (host.Contains("microsoft") || host.Contains("msft")) &&
            row.RiskScore >= 50)
            return true;

        // Enterprise management endpoints
        if (host.Contains("manage.microsoft") ||
            host.Contains("enterpriseregistration") ||
            host.Contains("device.microsoft") ||
            host.Contains("login.microsoftonline.us"))
            return true;

        return false;
    }
}

public sealed record NetworkTelemetrySnapshot(
    DateTimeOffset Timestamp,
    int TotalConnections,
    int InboundExposure,
    int OutboundConnections,
    IReadOnlyList<NetworkConnectionRow> RiskyConnections,
    IReadOnlyList<NetworkConnectionRow> InboundActivity,
    IReadOnlyList<NetworkConnectionRow> Connections,
    string BandwidthStatus,
    string FirewallStatusText,
    int HighestRiskScore);
