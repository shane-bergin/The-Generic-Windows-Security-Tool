using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.Core.Scan;

public sealed class ScanEngine
{
private readonly FileScanEngine _fileEngine = new();
private readonly SigmaEngine _sigmaEngine = new();
private readonly ClamEngine _clamEngine = new();
private bool _useClam;

public bool UseClam
{
    get => _useClam;
    set
    {
        _useClam = value;
        if (value)
            _ = _clamEngine.EnsureInstalledAsync();
    }
}

public Task<bool> EnsureClamAsync(IProgress<string>? log = null, CancellationToken ct = default) =>
    _clamEngine.EnsureInstalledAsync(log, ct);

    public async Task<IReadOnlyList<ScanResult>> RunScanAsync(
        ScanType type,
        string? root = null,
        IProgress<double>? progress = null,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        var fileHits = await _fileEngine.RunFileScanAsync(type, root, progress, ct);
        var hitsList = fileHits.ToArray();

    if (_useClam)
    {
        var clamHits = await _clamEngine.RunClamScanAsync(root ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), log, ct);
        hitsList = hitsList.Concat(clamHits).ToArray();
    }

    var suspiciousBins = hitsList.Where(h => h.Suspicious)
        .Select(h => Path.GetFileNameWithoutExtension(h.Path))
        .Where(n => !string.IsNullOrWhiteSpace(n))
        .ToHashSet(StringComparer.OrdinalIgnoreCase);

    var sigmaHits = suspiciousBins.Count > 0
        ? await _sigmaEngine.RunBehavioralScanAsync(suspiciousBins, ct)
        : Array.Empty<ScanResult>();

    return hitsList.Concat(sigmaHits)
        .GroupBy(r => r.Path)
        .Select(g => g.First())
        .OrderByDescending(r => r.Suspicious)
        .ToArray();
}


}
