using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace TGWST.App;

internal static class BuildInfo
{
    internal sealed record BuildStamp(
        string Version,
        string? Commit,
        DateTimeOffset? BuiltAtUtc)
    {
        public string DisplayVersion
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(Commit) && Commit!.Length > 0)
                    return $"{Version} ({Commit})";

                return Version;
            }
        }
    }

    public static BuildStamp Current { get; } = Load();

    private static BuildStamp Load()
    {
        var exePath = Environment.ProcessPath
            ?? Process.GetCurrentProcess().MainModule?.FileName
            ?? Assembly.GetExecutingAssembly().Location;

        var version = TryGetFileVersion(exePath)
            ?? Assembly.GetExecutingAssembly().GetName().Version?.ToString()
            ?? "unknown";

        var stampPath = Path.Combine(AppContext.BaseDirectory, "build-info.txt");
        var data = TryReadStamp(stampPath);

        return new BuildStamp(
            Version: data.TryGetValue("Version", out var v) ? v ?? version : version,
            Commit: data.TryGetValue("Commit", out var c) ? c : null,
            BuiltAtUtc: ParseDate(data.TryGetValue("BuildTimeUtc", out var t) ? t : null));
    }

    private static string? TryGetFileVersion(string exePath)
    {
        try
        {
            if (File.Exists(exePath))
            {
                var info = FileVersionInfo.GetVersionInfo(exePath);
                return info.FileVersion ?? info.ProductVersion;
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }

    private static Dictionary<string, string> TryReadStamp(string path)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (!File.Exists(path)) return dict;

            foreach (var line in File.ReadLines(path))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var idx = line.IndexOf('=');
                if (idx <= 0 || idx == line.Length - 1) continue;
                var key = line[..idx].Trim();
                var value = line[(idx + 1)..].Trim();
                if (key.Length == 0) continue;
                dict[key] = value;
            }
        }
        catch
        {
            // best-effort only
        }

        return dict;
    }

    private static DateTimeOffset? ParseDate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        return DateTimeOffset.TryParse(value, out var dto) ? dto : null;
    }
}
