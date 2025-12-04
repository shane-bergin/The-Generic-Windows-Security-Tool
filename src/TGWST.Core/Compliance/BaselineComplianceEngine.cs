using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;
using System.Text;
using System.Text.Json;

namespace TGWST.Core.Compliance;

public sealed class BaselineComplianceEngine
{
    public sealed record RegistryExpectation(string Hive, string Path, string Name, object? Value);
    public sealed record Result(RegistryExpectation Item, bool Compliant, object? CurrentValue);

    public IReadOnlyList<Result> Evaluate(string baselinePath)
    {
        var expectations = LoadExpectations(baselinePath);
        var results = new List<Result>();
        foreach (var exp in expectations)
        {
            object? current = ReadValue(exp);
            bool ok = Equals(Normalize(current), Normalize(exp.Value));
            results.Add(new Result(exp, ok, current));
        }
        return results;
    }

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

    private static IReadOnlyList<RegistryExpectation> LoadExpectations(string path)
    {
        var ext = Path.GetExtension(path)?.ToLowerInvariant();
        if (ext == ".csv")
            return LoadCsv(path);

        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true
        };

        var expectations = JsonSerializer.Deserialize<RegistryExpectation[]>(File.ReadAllText(path), options);
        return expectations ?? Array.Empty<RegistryExpectation>();
    }

    private static IReadOnlyList<RegistryExpectation> LoadCsv(string path)
    {
        var list = new List<RegistryExpectation>();
        string[]? headers = null;

        foreach (var rawLine in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(rawLine)) continue;
            if (rawLine.TrimStart().StartsWith("#")) continue;

            if (headers == null)
            {
                headers = SplitCsvLine(rawLine);
                continue;
            }

            var cols = SplitCsvLine(rawLine);
            if (cols.Length == 0) continue;

            string Get(string name)
            {
                if (headers == null) return "";
                var idx = Array.FindIndex(headers, h => h.Equals(name, StringComparison.OrdinalIgnoreCase));
                return (idx >= 0 && idx < cols.Length) ? cols[idx] : "";
            }

            var hive = Get("hive");
            var keyPath = Get("path");
            var name = Get("name");
            var valueText = Get("value");

            if (string.IsNullOrWhiteSpace(hive) ||
                string.IsNullOrWhiteSpace(keyPath) ||
                string.IsNullOrWhiteSpace(name))
                continue;

            var value = ParseValue(valueText);
            list.Add(new RegistryExpectation(hive, keyPath, name, value));
        }

        return list;
    }

    private static object? ParseValue(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var trimmed = text.Trim().Trim('"');
        if (long.TryParse(trimmed, out var longVal)) return longVal;
        if (bool.TryParse(trimmed, out var boolVal)) return boolVal;
        return trimmed;
    }

    private static string[] SplitCsvLine(string line)
    {
        var values = new List<string>();
        var current = new StringBuilder();
        var inQuotes = false;

        for (var i = 0; i < line.Length; i++)
        {
            var ch = line[i];
            if (ch == '"')
            {
                if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                {
                    current.Append('"');
                    i++;
                }
                else
                {
                    inQuotes = !inQuotes;
                }
            }
            else if (ch == ',' && !inQuotes)
            {
                values.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(ch);
            }
        }

        values.Add(current.ToString());
        return values.ToArray();
    }

    private static object? Normalize(object? value)
    {
        if (value is JsonElement element)
        {
            return element.ValueKind switch
            {
                JsonValueKind.Number when element.TryGetInt64(out var l) => l,
                JsonValueKind.Number when element.TryGetDouble(out var d) => d,
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                JsonValueKind.String => Normalize(element.GetString()),
                JsonValueKind.Null or JsonValueKind.Undefined => null,
                _ => value
            };
        }

        switch (value)
        {
            case string s:
                var trimmed = s.Trim();
                if (long.TryParse(trimmed, out var l)) return l;
                if (bool.TryParse(trimmed, out var b)) return b;
                return trimmed;
            case int or long or short or byte or uint or ulong or ushort or sbyte:
                return Convert.ToInt64(value);
        }

        return value;
    }
}
