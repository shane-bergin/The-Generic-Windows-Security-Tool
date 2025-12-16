using System;
using System.IO;
using System.Text;

namespace TGWST.App;

internal static class StartupLogger
{
    private static readonly object Gate = new();
    private static string? _logPath;
    private static BuildInfo.BuildStamp _stamp = BuildInfo.Current;

    public static string LogPath => _logPath ??= ResolveLogPath();

    public static void Initialize(BuildInfo.BuildStamp stamp)
    {
        _stamp = stamp ?? BuildInfo.Current;
        _logPath = ResolveLogPath();
        Log("startup", $"app start; version={_stamp.Version}; exe={_stamp.ExePath}");
    }

    public static void LogMilestone(string message) => Log("milestone", message);

    public static void LogException(string stage, Exception ex) =>
        Log("exception", $"{stage}: {ex}");

    private static void Log(string category, string message)
    {
        try
        {
            var line = $"{DateTimeOffset.UtcNow:O}\t{category}\t{_stamp.Version}\t{_stamp.ExePath}\t{message}";
            lock (Gate)
            {
                File.AppendAllText(LogPath, line + Environment.NewLine, Encoding.UTF8);
            }
        }
        catch
        {
            // never let logging crash the app
        }
    }

    private static string ResolveLogPath()
    {
        foreach (var candidate in new[]
                 {
                     Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "TGWST", "logs", "startup.log"),
                     Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TGWST", "logs", "startup.log"),
                     Path.Combine(Path.GetTempPath(), "TGWST", "logs", "startup.log")
                 })
        {
            if (TryEnsureDirectory(candidate))
                return candidate;
        }

        // As a last resort, drop it next to the executable.
        var fallback = Path.Combine(AppContext.BaseDirectory, "startup.log");
        TryEnsureDirectory(fallback);
        return fallback;
    }

    private static bool TryEnsureDirectory(string path)
    {
        try
        {
            var dir = Path.GetDirectoryName(path);
            if (string.IsNullOrWhiteSpace(dir)) return false;
            Directory.CreateDirectory(dir);
            return Directory.Exists(dir);
        }
        catch
        {
            return false;
        }
    }
}
