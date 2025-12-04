using System;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.Core.Compliance;

public sealed class DriftDetector : IAsyncDisposable
{
    private readonly BaselineComplianceEngine _engine = new();
    private readonly string _baselinePath;
    private readonly TimeSpan _interval;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;

    public event Action<int, int>? DriftDetected; // compliant, total

    public DriftDetector(string baselinePath, TimeSpan interval)
    {
        _baselinePath = baselinePath;
        _interval = interval;
    }

    public void Start()
    {
        _loop = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                var results = _engine.Evaluate(_baselinePath);
                int compliant = 0;
                foreach (var r in results) if (r.Compliant) compliant++;
                DriftDetected?.Invoke(compliant, results.Count);
                await Task.Delay(_interval, _cts.Token).ConfigureAwait(false);
            }
        }, _cts.Token);
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        if (_loop != null) await _loop.ConfigureAwait(false);
        _cts.Dispose();
    }
}
