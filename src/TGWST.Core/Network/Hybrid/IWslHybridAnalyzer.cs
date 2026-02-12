using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.Core.Network.Hybrid
{
    public interface IWslHybridAnalyzer
    {
        Task<WslHybridProbeResult> ProbeAsync(string? preferredDistro = null, CancellationToken ct = default);

        Task<IReadOnlyList<HybridRiskFinding>> AnalyzeFlowsAsync(
            IReadOnlyList<FlowRecord> flows,
            string distro,
            CancellationToken ct = default);
    }
}
