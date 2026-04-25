using System;

namespace TGWST.Core.Network;

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

public sealed record ConnectionSnapshot
{
    public DateTime Timestamp { get; init; }
    public IReadOnlyList<ConnectionEntry> Connections { get; init; } = Array.Empty<ConnectionEntry>();
}
