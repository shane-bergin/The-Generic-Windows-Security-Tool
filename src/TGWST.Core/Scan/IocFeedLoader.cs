using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using TGWST.Core.Feeds;

namespace TGWST.Core.Scan;

public static class IocFeedLoader
{
    public static IReadOnlyList<string> GetYaraRuleFiles()
    {
        try
        {
            FeedPaths.EnsureDirectoriesExist();
            return Directory.EnumerateFiles(FeedPaths.Yara, "*.yar", SearchOption.TopDirectoryOnly).ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    public static IReadOnlyList<IocBundle> GetIocBundles()
    {
        var list = new List<IocBundle>();
        try
        {
            FeedPaths.EnsureDirectoriesExist();
            var files = Directory.EnumerateFiles(FeedPaths.Iocs, "*.json", SearchOption.TopDirectoryOnly);
            foreach (var file in files)
            {
                try
                {
                    using var stream = File.OpenRead(file);
                    var doc = JsonDocument.Parse(stream);
                    if (doc.RootElement.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var element in doc.RootElement.EnumerateArray())
                        {
                            if (TryReadBundle(element, out var bundle))
                                list.Add(bundle);
                        }
                    }
                    else if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                             TryReadBundle(doc.RootElement, out var single))
                    {
                        list.Add(single);
                    }
                }
                catch
                {
                    // ignore individual file errors
                }
            }
        }
        catch
        {
            // ignore directory errors
        }

        return list;
    }

    private static bool TryReadBundle(JsonElement element, out IocBundle bundle)
    {
        try
        {
            string? family = element.GetPropertyOrDefault("family")?.GetString();
            string? source = element.GetPropertyOrDefault("source")?.GetString();
            string? sampleHash = element.GetPropertyOrDefault("sampleHash")?.GetString();
            var mutexes = ReadStringArray(element.GetPropertyOrDefault("mutexes"));
            var reg = ReadStringArray(element.GetPropertyOrDefault("registryKeys"));
            var files = ReadStringArray(element.GetPropertyOrDefault("filenames"));
            var domains = ReadStringArray(element.GetPropertyOrDefault("domains"));
            var ips = ReadStringArray(element.GetPropertyOrDefault("ips"));
            var created = element.GetPropertyOrDefault("createdUtc")?.GetDateTime() ?? DateTime.MinValue;

            bundle = new IocBundle(
                family,
                source,
                sampleHash,
                mutexes,
                reg,
                files,
                domains,
                ips,
                created);
            return true;
        }
        catch
        {
            bundle = default;
            return false;
        }
    }

    private static string[] ReadStringArray(JsonElement? element)
    {
        if (element == null || element.Value.ValueKind != JsonValueKind.Array)
            return Array.Empty<string>();

        var items = element.Value.EnumerateArray()
            .Select(v => v.GetString())
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Select(s => s!)
            .ToArray();
        return items;
    }

    private static JsonElement? GetPropertyOrDefault(this JsonElement element, string name)
    {
        return element.TryGetProperty(name, out var value) ? value : null;
    }
}
