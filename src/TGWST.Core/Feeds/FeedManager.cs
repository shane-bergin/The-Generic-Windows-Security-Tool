using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.Core.Feeds;

public static class FeedManager
{
    private static readonly object _lock = new();
    private static IReadOnlyList<IocBundle> _iocBundles = Array.Empty<IocBundle>();
    private static IReadOnlyList<string> _yaraFiles = Array.Empty<string>();

    public static IReadOnlyList<IocBundle> IocBundles
    {
        get { lock (_lock) return _iocBundles; }
    }

    public static IReadOnlyList<string> YaraRuleFiles
    {
        get { lock (_lock) return _yaraFiles; }
    }

    public static async Task<FeedSummary> ReloadAsync(CancellationToken ct = default)
    {
        FeedPaths.EnsureDirectoriesExist();

        var yaraFiles = Directory.GetFiles(FeedPaths.Yara, "*.yar", SearchOption.TopDirectoryOnly);
        var iocFiles = Directory.GetFiles(FeedPaths.Iocs, "*.json", SearchOption.TopDirectoryOnly);

        var iocBundles = new List<IocBundle>();
        var feedFiles = new List<FeedFileInfo>();
        var yaraRuleTotal = 0;

        foreach (var iocFile in iocFiles)
        {
            ct.ThrowIfCancellationRequested();
            var added = 0;
            try
            {
                var text = await File.ReadAllTextAsync(iocFile, ct).ConfigureAwait(false);
                var array = JsonSerializer.Deserialize<IocBundle[]>(text, JsonOptions());
                if (array is { Length: > 0 })
                {
                    iocBundles.AddRange(array.Where(b => b != null)!);
                    added = array.Length;
                }
                else
                {
                    var single = JsonSerializer.Deserialize<IocBundle>(text, JsonOptions());
                    if (single != null)
                    {
                        iocBundles.Add(single);
                        added = 1;
                    }
                }
            }
            catch
            {
                // Ignore malformed IOC feed files.
            }

            feedFiles.Add(new FeedFileInfo
            {
                Type = "IOC",
                FileName = Path.GetFileName(iocFile),
                ItemCount = added,
                Source = "External feed"
            });
        }

        foreach (var yaraFile in yaraFiles)
        {
            ct.ThrowIfCancellationRequested();
            var count = CountRulesInFile(yaraFile);
            yaraRuleTotal += count;
            feedFiles.Add(new FeedFileInfo
            {
                Type = "YARA",
                FileName = Path.GetFileName(yaraFile),
                ItemCount = count,
                Source = "External feed"
            });
        }

        lock (_lock)
        {
            _iocBundles = iocBundles;
            _yaraFiles = yaraFiles;
        }

        var families = iocBundles
            .Select(b => b.Family)
            .Where(f => !string.IsNullOrWhiteSpace(f))
            .Select(f => f!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new FeedSummary
        {
            YaraRuleCount = yaraRuleTotal,
            IocBundleCount = iocBundles.Count,
            TotalFamilies = families.Length,
            Families = families,
            Files = feedFiles,
            ReloadedAtUtc = DateTime.UtcNow
        };
    }

    private static int CountRulesInFile(string path)
    {
        try
        {
            var text = File.ReadAllText(path);
            var regex = new Regex(@"\brule\s+([A-Za-z0-9_]+)", RegexOptions.Compiled);
            return regex.Matches(text).Count;
        }
        catch
        {
            return 0;
        }
    }

    private static JsonSerializerOptions JsonOptions() => new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };
}
