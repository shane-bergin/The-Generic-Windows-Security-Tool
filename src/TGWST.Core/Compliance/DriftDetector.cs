using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.Core.Compliance;

public sealed class DriftDetector : IAsyncDisposable
{
    private readonly BaselineComplianceEngine _engine = new();
    private readonly string _baselinePath;
    private readonly TimeSpan _interval;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _snapshotLock = new(1, 1);
    private IReadOnlyList<BaselineComplianceEngine.Result>? _lastSnapshot;
    private Task? _monitoringTask;

    public event Action<int, int>? DriftDetected; // compliant, total

    public DriftDetector(string baselinePath, TimeSpan interval)
    {
        _baselinePath = baselinePath;
        _interval = interval;
    }

    private async Task MonitorLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await _snapshotLock.WaitAsync(ct);
                try
                {
                    var currentSnapshot = _engine.Evaluate(_baselinePath);

                    if (_lastSnapshot != null)
                    {
                        var compliant = currentSnapshot.Count(r => r.Compliant);
                        var total = currentSnapshot.Count;

                        if (compliant != _lastSnapshot.Count(r => r.Compliant))
                        {
                            DriftDetected?.Invoke(compliant, total);
                        }
                    }

                    _lastSnapshot = currentSnapshot;
                }
                finally
                {
                    _snapshotLock.Release();
                }

                await Task.Delay(_interval, ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                // Log error and continue
                await Task.Delay(TimeSpan.FromMinutes(1), ct);
            }
        }
    }

    public void Start()
    {
        _monitoringTask = MonitorLoopAsync(_cts.Token);
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        if (_monitoringTask != null)
        {
            try { await _monitoringTask; } catch { }
        }
        _cts.Dispose();
        _snapshotLock.Dispose();
    }
}
