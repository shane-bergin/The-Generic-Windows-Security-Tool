using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;
using System.Text.Json;

namespace TGWST.Core.Compliance;

public sealed class BaselineComplianceEngine
{
    public sealed record RegistryExpectation(string Hive, string Path, string Name, object? Value);
    public sealed record Result(RegistryExpectation Item, bool Compliant, object? CurrentValue);

    public IReadOnlyList<Result> Evaluate(string baselineJsonPath)
    {
        var expectations = JsonSerializer.Deserialize<RegistryExpectation[]>(File.ReadAllText(baselineJsonPath))
            ?? Array.Empty<RegistryExpectation>();
        var results = new List<Result>();
        foreach (var exp in expectations)
        {
            object? current = ReadValue(exp);
            bool ok = Equals(Normalize(current), Normalize(exp.Value));
            results.Add(new Result(exp, ok, current));
        }
        return results;
    }

    private static object? Normalize(object? value) => value is string s ? s.Trim() : value;

    private static object? ReadValue(RegistryExpectation exp)
    {
        RegistryKey? hive = exp.Hive.ToUpperInvariant() switch
        {
            "HKLM" => Registry.LocalMachine,
            "HKCU" => Registry.CurrentUser,
            "HKU"  => Registry.Users,
            _ => null
        };
        if (hive == null) return null;
        using var key = hive.OpenSubKey(exp.Path);
        return key?.GetValue(exp.Name);
    }
}
