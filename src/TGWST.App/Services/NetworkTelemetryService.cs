using System;
using System.Collections.Generic;
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

            var riskyRows = rows
                .Where(row => row.RiskScore >= 35)
                .Take(80)
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
        var local = $"{NormalizeAddress(entry.LocalAddress)}:{entry.LocalPort}";
        var remote = entry.RemotePort > 0
            ? $"{NormalizeAddress(entry.RemoteAddress)}:{entry.RemotePort}"
            : NormalizeAddress(entry.RemoteAddress);
        var risk = ScoreRisk(entry, out var reason);

        return new NetworkConnectionRow(
            Process: string.IsNullOrWhiteSpace(entry.ProcessName) ? "Unknown" : entry.ProcessName,
            ProcessId: entry.ProcessId,
            Protocol: entry.Protocol,
            Local: local,
            Remote: remote,
            State: entry.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase) ? "UDP" : entry.State.ToString().ToUpperInvariant(),
            RiskScore: risk,
            Risk: reason);
    }

    private static int ScoreRisk(ConnectionEntry entry, out string reason)
    {
        var score = 0;
        var reasons = new List<string>();
        var remotePublic = IsPublicAddress(entry.RemoteAddress);
        var listening = entry.State == TGWST.Core.Network.TcpState.Listen;

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
               !row.Remote.StartsWith("0.0.0.0", StringComparison.OrdinalIgnoreCase) &&
               !row.Remote.StartsWith("127.", StringComparison.OrdinalIgnoreCase) &&
               !row.Remote.StartsWith("*", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsListeningExposure(NetworkConnectionRow row)
    {
        return row.State.Equals("LISTEN", StringComparison.OrdinalIgnoreCase) &&
               (row.Local.StartsWith("0.0.0.0", StringComparison.OrdinalIgnoreCase) ||
                row.Local.StartsWith("::", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsSensitivePort(int port)
    {
        return port is 20 or 21 or 22 or 23 or 25 or 53 or 135 or 139 or 445 or 1433 or 1521 or 3306 or 3389 or 5432 or 5900 or 5985 or 5986;
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
}

public sealed record NetworkTelemetrySnapshot(
    DateTimeOffset Timestamp,
    int TotalConnections,
    int InboundExposure,
    int OutboundConnections,
    IReadOnlyList<NetworkConnectionRow> RiskyConnections,
    IReadOnlyList<NetworkConnectionRow> Connections,
    string BandwidthStatus,
    string FirewallStatusText,
    int HighestRiskScore);
