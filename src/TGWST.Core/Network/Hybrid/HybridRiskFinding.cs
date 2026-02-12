using System;
using System.Collections.Generic;

namespace TGWST.Core.Network.Hybrid
{
    /// <summary>
    /// Risk signal emitted by the WSL2 analytics sidecar for an active flow.
    /// </summary>
    public sealed class HybridRiskFinding
    {
        public string ProcessName { get; init; } = "";
        public int ProcessId { get; init; }
        public string Endpoint { get; init; } = "";
        public int Score { get; init; }
        public string Severity { get; init; } = "Low";
        public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();
    }
}
