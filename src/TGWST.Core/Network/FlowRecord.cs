using System;

namespace TGWST.Core.Network
{
    /// <summary>
    /// Represents an aggregated network flow for a specific process and remote endpoint.
    /// </summary>
    public sealed class FlowRecord
    {
        public string FlowId { get; init; } = "";

        // Process identification
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public string ProcessPath { get; set; } = "";
        public string? ProcessSigner { get; set; }

        // Connection details
        public string Protocol { get; set; } = "";
        public string LocalAddress { get; set; } = "";
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; } = "";
        public int RemotePort { get; set; }
        public string? RemoteHostname { get; set; }
        public string? RemoteCountry { get; set; }

        // Traffic statistics
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public long PacketsSent { get; set; }
        public long PacketsReceived { get; set; }

        // Timing
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public TimeSpan Duration => LastSeen - FirstSeen;

        // Firewall correlation
        public string? MatchedRuleName { get; set; }
        public FlowAction Action { get; set; } = FlowAction.Allow;

        // Computed properties
        public long TotalBytes => BytesSent + BytesReceived;
        public string TotalBytesDisplay => FormatBytes(TotalBytes);
        public string BytesSentDisplay => FormatBytes(BytesSent);
        public string BytesReceivedDisplay => FormatBytes(BytesReceived);

        public static string FormatBytes(long bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            double len = bytes;
            int order = 0;
            while (len >= 1024 && order < sizes.Length - 1)
            {
                order++;
                len /= 1024;
            }
            return $"{len:0.##} {sizes[order]}";
        }

        public static string BuildFlowKey(int processId, string localAddress, int localPort, string remoteAddress, int remotePort)
        {
            return $"{processId}|{localAddress}:{localPort}|{remoteAddress}:{remotePort}";
        }
    }

    public enum FlowAction
    {
        Allow,
        Block,
        Drop
    }

    /// <summary>
    /// Represents per-process bandwidth totals for aggregated display.
    /// </summary>
    public sealed class ProcessBandwidth
    {
        public string ProcessName { get; init; } = "";
        public int ProcessId { get; init; }
        public string? ProcessPath { get; init; }
        public string? ProcessSigner { get; init; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public int ConnectionCount { get; set; }

        public long TotalBytes => BytesSent + BytesReceived;
        public string TotalBytesDisplay => FlowRecord.FormatBytes(TotalBytes);
        public string BytesSentDisplay => FlowRecord.FormatBytes(BytesSent);
        public string BytesReceivedDisplay => FlowRecord.FormatBytes(BytesReceived);
    }

    /// <summary>
    /// Raw network event types for capture pipeline.
    /// </summary>
    public enum NetEventType
    {
        TcpConnect,
        TcpDisconnect,
        TcpAccept,
        TcpSend,
        TcpReceive,
        UdpSend,
        UdpReceive,
        DnsQuery,
        DnsResponse,
        WfpAllow,
        WfpBlock
    }

    /// <summary>
    /// Raw network event from capture sources (ETW, WFP, IP Helper).
    /// </summary>
    public sealed record RawNetworkEvent
    {
        public DateTime Timestamp { get; init; }
        public NetEventType EventType { get; init; }
        public int ProcessId { get; init; }
        public string LocalAddress { get; init; } = "";
        public int LocalPort { get; init; }
        public string RemoteAddress { get; init; } = "";
        public int RemotePort { get; init; }
        public long BytesSent { get; init; }
        public long BytesReceived { get; init; }
        public string? DnsQuery { get; init; }
        public string? DnsResponse { get; init; }
    }

    /// <summary>
    /// TCP connection state from IP Helper.
    /// </summary>
    public enum TcpState
    {
        Closed = 1,
        Listen = 2,
        SynSent = 3,
        SynReceived = 4,
        Established = 5,
        FinWait1 = 6,
        FinWait2 = 7,
        CloseWait = 8,
        Closing = 9,
        LastAck = 10,
        TimeWait = 11,
        DeleteTcb = 12
    }

    /// <summary>
    /// Connection entry from IP Helper table polling.
    /// </summary>
    public sealed record ConnectionEntry
    {
        public string Protocol { get; init; } = "";
        public string LocalAddress { get; init; } = "";
        public int LocalPort { get; init; }
        public string RemoteAddress { get; init; } = "";
        public int RemotePort { get; init; }
        public int ProcessId { get; init; }
        public TcpState State { get; init; }
        public string ProcessName { get; set; } = "";
    }

    /// <summary>
    /// Snapshot of all current connections from IP Helper.
    /// </summary>
    public sealed record ConnectionSnapshot
    {
        public DateTime Timestamp { get; init; }
        public IReadOnlyList<ConnectionEntry> Connections { get; init; } = Array.Empty<ConnectionEntry>();
    }
}
