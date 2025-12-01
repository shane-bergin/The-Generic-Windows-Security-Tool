using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
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
    CancellationToken ct = default)
{
    var results = new List<ScanResult>();

    if (suspiciousBinaries.Count == 0)
        return results;

    var candidates = _rules.Where(r =>
            r.Tags.Any(t => t.Contains("T1059", StringComparison.OrdinalIgnoreCase)) ||
            r.Tags.Any(t => t.Contains("attack.execution", StringComparison.OrdinalIgnoreCase)))
        .ToList();

    foreach (var rule in candidates)
    {
        ct.ThrowIfCancellationRequested();

        if (!string.Equals(rule.Detection.Condition, "selection", StringComparison.OrdinalIgnoreCase))
            continue;

        var xpath = TransduceToXPath(rule.Detection.Selection);
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

private static string TransduceToXPath(Dictionary<string, object> selection)
{
    var predicates = new List<string>();
    foreach (var kv in selection)
    {
        var key = kv.Key;
        var value = kv.Value;
        var fieldName = key;
        var endswith = false;

        var pipeIdx = key.IndexOf('|');
        if (pipeIdx > 0)
        {
            fieldName = key[..pipeIdx];
            if (key[(pipeIdx + 1)..].Equals("endswith", StringComparison.OrdinalIgnoreCase))
                endswith = true;
        }

        if (value is string sVal)
        {
            var op = endswith
                ? $"substring(., string-length(.) - string-length('{sVal}') + 1) = '{sVal}'"
                : $". = '{sVal}'";
            predicates.Add($"EventData/Data[@Name='{fieldName}'][{op}]");
        }
        else if (value is IEnumerable<object> listVal && endswith)
        {
            var listOps = listVal
                .OfType<string>()
                .Select(v =>
                    $"substring(., string-length(.) - string-length('{v}') + 1) = '{v}'");
            predicates.Add($"EventData/Data[@Name='{fieldName}'][({string.Join(" or ", listOps)})]");
        }
    }

    if (predicates.Count == 0) return "";
    return $"*[System/EventID=4688 and {string.Join(" and ", predicates)}]";
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


}