using System;
using System.Collections.Generic;

namespace TGWST.Core.Network.Hybrid
{
    /// <summary>
    /// Captures WSL2 readiness details for hybrid analytics mode.
    /// </summary>
    public sealed class WslHybridProbeResult
    {
        public bool IsWslInstalled { get; init; }
        public bool HasAnyDistribution { get; init; }
        public bool BashReachable { get; init; }
        public string? SelectedDistro { get; init; }
        public string? SelectedDistroUser { get; init; }
        public string? FailureReason { get; init; }
        public IReadOnlyList<string> AvailableDistros { get; init; } = Array.Empty<string>();

        public bool IsReady => IsWslInstalled && HasAnyDistribution && BashReachable && !string.IsNullOrWhiteSpace(SelectedDistro);
    }
}
