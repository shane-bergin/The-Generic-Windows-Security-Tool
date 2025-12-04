using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.Core.Uninstall;

/// <summary>
/// Safer leftover detection anchored to install roots and common program locations.
/// </summary>
public sealed class LeftoverEngine
{
    private static readonly string[] SafeRoots =
    {
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
    };

    public Task<IReadOnlyList<LeftoverItem>> FindAsync(InstalledApp app, CancellationToken ct = default)
    {
        var results = new List<LeftoverItem>();
        var installRoot = GuessInstallRoot(app);

        if (!string.IsNullOrWhiteSpace(installRoot) && Directory.Exists(installRoot))
        {
            foreach (var dir in Directory.EnumerateDirectories(Path.GetDirectoryName(installRoot) ?? installRoot))
            {
                ct.ThrowIfCancellationRequested();
                if (!dir.StartsWith(installRoot, StringComparison.OrdinalIgnoreCase)) continue;

                results.Add(new LeftoverItem
                {
                    Type = LeftoverType.Directory,
                    Path = dir,
                    Reason = "Under install root"
                });
            }
        }

        return Task.FromResult<IReadOnlyList<LeftoverItem>>(results);
    }

    public Task RemoveAsync(IEnumerable<LeftoverItem> items, CancellationToken ct = default)
    {
        foreach (var item in items)
        {
            ct.ThrowIfCancellationRequested();
            if (item.Type != LeftoverType.Directory) continue;
            if (!IsSafePath(item.Path)) continue;
            if (Directory.Exists(item.Path)) Directory.Delete(item.Path, recursive: true);
        }

        return Task.CompletedTask;
    }

    private static string? GuessInstallRoot(InstalledApp app)
    {
        // Try explicit install location tokens
        var uninstall = app.UninstallString ?? string.Empty;
        if (uninstall.Contains("%ProgramFiles%", StringComparison.OrdinalIgnoreCase))
            return Environment.ExpandEnvironmentVariables(uninstall);

        // Fall back to Program Files\DisplayName
        var name = app.DisplayName?.Trim();
        if (string.IsNullOrWhiteSpace(name)) return null;

        return SafeRoots
            .Where(r => !string.IsNullOrWhiteSpace(r))
            .Select(r => Path.Combine(r!, name))
            .FirstOrDefault(Directory.Exists);
    }

    private static bool IsSafePath(string path) =>
        SafeRoots.Any(r => !string.IsNullOrWhiteSpace(r) &&
                           path.StartsWith(r, StringComparison.OrdinalIgnoreCase) &&
                           path.Length > r.Length + 3);
}
