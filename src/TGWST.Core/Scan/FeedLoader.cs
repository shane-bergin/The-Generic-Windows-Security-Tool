using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using dnYara;

namespace TGWST.Core.Scan;

/// <summary>
/// Loads external YARA feeds into a dnYara compiler and captures rule names.
/// </summary>
public static class FeedLoader
{
    public sealed class YaraLoadResult
    {
        public int RuleCount { get; set; }
        public HashSet<string> RuleNames { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    }

    public static Task<YaraLoadResult> LoadExternalYaraRulesAsync(
        Compiler compiler,
        IEnumerable<string> yaraFiles,
        CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            var result = new YaraLoadResult();
            var regex = new Regex(@"\brule\s+([A-Za-z0-9_]+)", RegexOptions.Compiled);

            foreach (var file in yaraFiles ?? Array.Empty<string>())
            {
                ct.ThrowIfCancellationRequested();
                if (!File.Exists(file)) continue;

                try
                {
                    compiler.AddRuleFile(file);

                    try
                    {
                        var text = File.ReadAllText(file);
                        foreach (System.Text.RegularExpressions.Match m in regex.Matches(text))
                        {
                            if (m.Groups.Count > 1)
                                result.RuleNames.Add(m.Groups[1].Value);
                        }
                    }
                    catch
                    {
                        // Ignore parse errors when counting names.
                    }
                }
                catch
                {
                    // Skip bad or incompatible YARA files.
                }
            }

            result.RuleCount = result.RuleNames.Count;
            return result;
        }, ct);
    }
}
