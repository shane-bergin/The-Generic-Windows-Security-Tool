using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.Core.Uninstall;

/// <summary>
/// Safer leftover detection anchored to install roots and guarded deletions.
/// </summary>
public sealed class LeftoverEngine
{
    private static readonly string[] DangerRoots =
    {
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + @"\\AppData"
    };

    private static readonly string[] IgnoreTokens =
    {
        "microsoft","visual","studio","c++","redistributable","update","setup","installer","vc","vc++"
    };

    public Task<IReadOnlyList<LeftoverItem>> FindAsync(InstalledApp app, CancellationToken ct = default)
    {
        var results = new List<LeftoverItem>();
        var installRoot = NormalizePath(app.InstallLocation);
        if (!string.IsNullOrWhiteSpace(installRoot) && Directory.Exists(installRoot))
        {
            results.AddRange(FindUnderInstallRoot(installRoot, app, ct));
        }

        return Task.FromResult<IReadOnlyList<LeftoverItem>>(results);
    }

    public Task RemoveAsync(IEnumerable<LeftoverItem> items, CancellationToken ct = default)
    {
        foreach (var item in items)
        {
            ct.ThrowIfCancellationRequested();
            if (item.Type != LeftoverType.Directory) continue;
            if (!item.Selected) continue;
            if (!IsDeletionAllowed(item)) continue;
            if (Directory.Exists(item.Path)) Directory.Delete(item.Path, recursive: true);
        }

        return Task.CompletedTask;
    }

    private static IEnumerable<LeftoverItem> FindUnderInstallRoot(string installRoot, InstalledApp app, CancellationToken ct)
    {
        var items = new List<LeftoverItem>();
        var rootInfo = new DirectoryInfo(installRoot);
        if (!rootInfo.Exists) return items;

        var tokens = BuildTokens(app);

        var appSpecific = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "logs", "log", "temp", "cache", "data" };

        foreach (var dir in rootInfo.EnumerateDirectories("*", SearchOption.TopDirectoryOnly))
        {
            ct.ThrowIfCancellationRequested();
            if (!StrongMatch(dir.Name, tokens, appSpecific)) continue;
            var path = dir.FullName;
            items.Add(new LeftoverItem
            {
                Type = LeftoverType.Directory,
                Path = path,
                InstallRoot = installRoot,
                Reason = "Matches app tokens under install root",
                MatchDetail = $"Tokens: {string.Join(", ", tokens)}",
                SizeBytes = SafeDirectorySize(path)
            });
        }

        return items;
    }

    private static string? NormalizePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        try { return Path.GetFullPath(path.Trim().Trim('"')); }
        catch { return null; }
    }

    private static bool IsDeletionAllowed(LeftoverItem item)
    {
        if (string.IsNullOrWhiteSpace(item.InstallRoot)) return false;
        var path = NormalizePath(item.Path);
        var root = NormalizePath(item.InstallRoot);
        if (path == null || root == null) return false;

        if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            return false;

        var depth = path.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries).Length;
        if (depth < 3) return false;

        if (DangerRoots.Any(dr => !string.IsNullOrWhiteSpace(dr) &&
                                  path.StartsWith(dr, StringComparison.OrdinalIgnoreCase) &&
                                  !path.StartsWith(root, StringComparison.OrdinalIgnoreCase)))
            return false;

        return true;
    }

    private static IEnumerable<string> BuildTokens(InstalledApp app)
    {
        var tokens = new List<string>();
        void AddTokens(string? source)
        {
            if (string.IsNullOrWhiteSpace(source)) return;
            foreach (var part in source.Split(new[] { ' ', '-', '_', '.', ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var t = part.Trim();
                if (t.Length < 3) continue;
                if (IgnoreTokens.Any(i => t.Equals(i, StringComparison.OrdinalIgnoreCase))) continue;
                tokens.Add(t);
            }
        }

        AddTokens(app.Publisher);
        AddTokens(app.DisplayName);
        return tokens;
    }

    private static bool StrongMatch(string name, IEnumerable<string> tokens, HashSet<string> appSpecific)
    {
        if (appSpecific.Contains(name)) return true;
        var matched = tokens.Count(t => name.Contains(t, StringComparison.OrdinalIgnoreCase));
        return matched >= 2;
    }

    private static long SafeDirectorySize(string path)
    {
        try
        {
            long total = 0;
            var stack = new Stack<string>();
            stack.Push(path);
            while (stack.Count > 0 && total < 500 * 1024 * 1024) // cap to avoid hangs
            {
                var current = stack.Pop();
                foreach (var file in Directory.EnumerateFiles(current))
                {
                    try { total += new FileInfo(file).Length; } catch { }
                    if (total >= 500 * 1024 * 1024) break;
                }
                foreach (var dir in Directory.EnumerateDirectories(current))
                    stack.Push(dir);
            }
            return total;
        }
        catch
        {
            return 0;
        }
    }
}
