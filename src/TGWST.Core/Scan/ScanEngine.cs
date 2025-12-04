using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TGWST.Core.Feeds;

namespace TGWST.Core.Scan;

public sealed class ScanEngine
{
private readonly FileScanEngine _fileEngine = new();
private readonly SigmaEngine _sigmaEngine = new();
    private readonly ClamAvEngine _clamEngine = new();

    public async Task<IReadOnlyList<ScanResult>> RunScanAsync(
        ScanType type,
        string? root = null,
        IProgress<double>? progress = null,
        IProgress<string>? log = null,
        bool useClamAv = true,
        CancellationToken ct = default)
    {
        log?.Report("Reloading feeds...");
        await FeedManager.ReloadAsync(ct).ConfigureAwait(false);
        log?.Report("Running YARA/IOC scan...");
        var fileHits = await _fileEngine.RunFileScanAsync(type, root, progress, ct);
        var hitsList = fileHits.ToArray();

    var suspiciousBins = hitsList.Where(h => h.Suspicious)
        .SelectMany(h =>
        {
            var list = new List<string>();
            if (!string.IsNullOrWhiteSpace(h.Path))
            {
                list.Add(h.Path);
                var file = Path.GetFileName(h.Path);
                if (!string.IsNullOrWhiteSpace(file)) list.Add(file);
            }
            return list;
        })
        .Where(n => !string.IsNullOrWhiteSpace(n))
        .ToHashSet(StringComparer.OrdinalIgnoreCase);

    var sigmaHits = suspiciousBins.Count > 0
        ? await _sigmaEngine.RunBehavioralScanAsync(suspiciousBins, ct)
        : Array.Empty<ScanResult>();

    var clamHits = useClamAv
        ? await _clamEngine.RunClamScanAsync(type, root, progress: null, log: log, ct: ct)
        : Array.Empty<ScanResult>();

    return hitsList
        .Concat(sigmaHits)
        .Concat(clamHits)
        .GroupBy(r => r.Path)
        .Select(g => g.First())
        .OrderByDescending(r => r.Suspicious)
        .ToArray();
}


}
