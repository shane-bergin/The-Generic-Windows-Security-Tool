using System;
using TGWST.Core.Network.Hybrid;

namespace TGWST.App.Services
{
    /// <summary>
    /// Stores operator preference and latest probe state for WSL hybrid analytics.
    /// </summary>
    public sealed class HybridModeService
    {
        private readonly object _sync = new();

        public bool IsEnabled { get; private set; } = true;
        public string? PreferredDistro { get; private set; }
        public WslHybridProbeResult? LastProbe { get; private set; }
        public DateTimeOffset? LastProbeAt { get; private set; }
        public string? LastError { get; private set; }

        public void Enable(string? preferredDistro = null)
        {
            lock (_sync)
            {
                IsEnabled = true;
                if (!string.IsNullOrWhiteSpace(preferredDistro))
                {
                    PreferredDistro = preferredDistro.Trim();
                }
            }
        }

        public void Disable()
        {
            lock (_sync)
            {
                IsEnabled = false;
                LastError = null;
            }
        }

        public void SetPreferredDistro(string? preferredDistro)
        {
            lock (_sync)
            {
                PreferredDistro = string.IsNullOrWhiteSpace(preferredDistro)
                    ? null
                    : preferredDistro.Trim();
            }
        }

        public void RecordProbe(WslHybridProbeResult probe)
        {
            lock (_sync)
            {
                LastProbe = probe;
                LastProbeAt = DateTimeOffset.UtcNow;
            }
        }

        public void RecordError(string? error)
        {
            lock (_sync)
            {
                LastError = string.IsNullOrWhiteSpace(error) ? null : error.Trim();
            }
        }
    }
}
