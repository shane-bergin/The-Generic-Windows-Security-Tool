using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Text;
using System;
using YamlDotNet.Serialization;

namespace TGWST.Core.Scan;

public sealed class SigmaEngine
{
private readonly IReadOnlyList<SigmaRule> _rules;

public SigmaEngine()
{
    _rules = LoadEmbeddedRules("TGWST.Core.SigmaRules.process_creation.yml");
}

    public async Task<IReadOnlyList<ScanResult>> RunBehavioralScanAsync(
        IReadOnlyCollection<string> suspiciousBinaries,
        CancellationToken ct = default,
        TimeSpan? lookback = null)
    {
        var results = new List<ScanResult>();

        if (suspiciousBinaries == null || suspiciousBinaries.Count == 0)
            return results;

        var normalizedBins = NormalizeBinaries(suspiciousBinaries);
        if (normalizedBins.Count == 0)
            return results;

        var window = lookback ?? TimeSpan.FromMinutes(60);

        var candidates = _rules.Where(r =>
                r.Tags.Any(t => t.Contains("T1059", StringComparison.OrdinalIgnoreCase)) ||
                r.Tags.Any(t => t.Contains("attack.execution", StringComparison.OrdinalIgnoreCase)))
            .ToList();

        foreach (var rule in candidates)
        {
            ct.ThrowIfCancellationRequested();

            if (!string.Equals(rule.Detection.Condition, "selection", StringComparison.OrdinalIgnoreCase))
                continue;

            var xpath = TransduceToXPath(rule.Detection.Selection, normalizedBins, window);
            if (string.IsNullOrWhiteSpace(xpath))
                continue;

            var events = await QueryEventsAsync(xpath, ct);
            if (events.Count > 0)
            {
                results.Add(new ScanResult
                {
                    Path = $"Behavioral: {rule.Title}",
                    Suspicious = true,
                    Reason = $"{rule.Description} ({events.Count} events in Security Log 4688)",
                    Engine = "Sigma v0.3 + WinEvent"
                });
            }
        }

        return results;
    }

private static IReadOnlyList<SigmaRule> LoadEmbeddedRules(string resourceName)
{
    var asm = Assembly.GetExecutingAssembly();
    using var stream = asm.GetManifestResourceStream(resourceName)
        ?? throw new InvalidOperationException($"Resource missing: {resourceName}");
    using var reader = new StreamReader(stream);
    var yaml = reader.ReadToEnd();

    var deserializer = new DeserializerBuilder().Build();
    var rules = deserializer.Deserialize<List<SigmaRule>>(yaml) ?? new List<SigmaRule>();
    return rules;
}

    private static string TransduceToXPath(Dictionary<string, object> selection, IReadOnlyCollection<string> suspiciousBinaries, TimeSpan lookback)
    {
        var predicates = new List<string>();

        foreach (var kv in selection)
        {
            var key = kv.Key;
            var value = kv.Value;
            var fieldName = key;
            var op = "equals";

            var pipeIdx = key.IndexOf('|');
            if (pipeIdx > 0)
            {
                fieldName = key[..pipeIdx];
                op = key[(pipeIdx + 1)..];
            }

            if (value is string sVal)
            {
                var predicate = BuildPredicate(fieldName, op, new[] { sVal });
                if (!string.IsNullOrWhiteSpace(predicate)) predicates.Add(predicate);
            }
            else if (value is IEnumerable<object> listVal)
            {
                var strings = listVal.OfType<string>().ToArray();
                if (strings.Length == 0) continue;
                var predicate = BuildPredicate(fieldName, op, strings);
                if (!string.IsNullOrWhiteSpace(predicate)) predicates.Add(predicate);
            }
        }

        if (suspiciousBinaries.Count > 0)
        {
            var procPreds = suspiciousBinaries.Select(b =>
                $"contains(translate(EventData/Data[@Name='NewProcessName'], 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), {ToXPathLiteral(b)}) or contains(translate(EventData/Data[@Name='ParentProcessName'], 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), {ToXPathLiteral(b)})");
            predicates.Add($"({string.Join(" or ", procPreds)})");
        }

        if (predicates.Count == 0) return "";
        var millis = (long)lookback.TotalMilliseconds;
        return $"*[System[EventID=4688 and TimeCreated[timediff(@SystemTime) <= {millis}]] and {string.Join(" and ", predicates)}]";
    }

private static async Task<List<string>> QueryEventsAsync(string xpath, CancellationToken ct)
{
    var script = $@"
        Get-WinEvent -FilterXPath '{xpath}' -LogName Security -MaxEvents 50 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, Message |
        ConvertTo-Json -Compress
    ";

    using var ps = PowerShell.Create();
    ps.AddScript(script);
    var results = await Task.Run(() => ps.Invoke(), ct);
    return results.Select(r => r.ToString() ?? "").Where(s => s.Length > 0).ToList();
}

    private static string BuildPredicate(string fieldName, string op, IEnumerable<string> values)
    {
        var vals = values
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(ToXPathLiteral)
            .ToArray();
        if (vals.Length == 0) return "";

        string BuildExpr(string literal)
        {
            var loweredField = $"translate(EventData/Data[@Name='{fieldName}'], 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')";
            return op.ToLowerInvariant() switch
            {
                "contains" => $"contains({loweredField}, {literal})",
                "endswith" => $"substring({loweredField}, string-length({loweredField}) - string-length({literal}) + 1) = {literal}",
                _ => $"{loweredField} = {literal}"
            };
        }

        return $"({string.Join(" or ", vals.Select(BuildExpr))})";
    }

    private static string ToXPathLiteral(string value)
    {
        var v = value.ToLowerInvariant();
        if (!v.Contains("'"))
            return $"'{v}'";
        var parts = v.Split('\'');
        var sb = new StringBuilder("concat(");
        for (int i = 0; i < parts.Length; i++)
        {
            if (i > 0) sb.Append(", \"'\", ");
            sb.Append('\'').Append(parts[i]).Append('\'');
        }
        sb.Append(')');
        return sb.ToString();
    }

    private static IReadOnlyCollection<string> NormalizeBinaries(IReadOnlyCollection<string> suspiciousBinaries)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var b in suspiciousBinaries)
        {
            if (string.IsNullOrWhiteSpace(b)) continue;
            var lower = b.ToLowerInvariant();
            set.Add(lower);
            var file = Path.GetFileName(b)?.ToLowerInvariant();
            if (!string.IsNullOrWhiteSpace(file))
                set.Add(file);
        }
        return set.ToArray();
    }

}
