using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace TGWST.Core.Uninstall;

/// <summary>
/// Deep leftover detection similar to Revo Uninstaller - scans registry, AppData, shortcuts, etc.
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
        var tokens = BuildTokens(app);

        // Scan install location
        var installRoot = NormalizePath(app.InstallLocation);
        if (!string.IsNullOrWhiteSpace(installRoot) && Directory.Exists(installRoot))
        {
            results.AddRange(FindUnderInstallRoot(installRoot, app, ct));
        }

        // Scan registry for leftovers
        results.AddRange(FindRegistryLeftovers(app, tokens, ct));

        // Scan AppData folders
        results.AddRange(FindAppDataLeftovers(tokens, ct));

        // Scan ProgramData
        results.AddRange(FindProgramDataLeftovers(tokens, ct));

        // Scan shortcuts
        results.AddRange(FindShortcutLeftovers(tokens, ct));

        // Scan temp folders
        results.AddRange(FindTempLeftovers(tokens, ct));

        return Task.FromResult<IReadOnlyList<LeftoverItem>>(results);
    }

    public Task RemoveAsync(IEnumerable<LeftoverItem> items, CancellationToken ct = default)
    {
        foreach (var item in items)
        {
            ct.ThrowIfCancellationRequested();
            if (!item.Selected) continue;

            try
            {
                switch (item.Type)
                {
                    case LeftoverType.Directory:
                        if (IsDeletionAllowed(item) && Directory.Exists(item.Path))
                            Directory.Delete(item.Path, recursive: true);
                        break;

                    case LeftoverType.File:
                        if (File.Exists(item.Path))
                            File.Delete(item.Path);
                        break;

                    case LeftoverType.RegistryKey:
                        DeleteRegistryKey(item.Path);
                        break;

                    case LeftoverType.RegistryValue:
                        DeleteRegistryValue(item.Path, item.ValueName);
                        break;
                }
            }
            catch
            {
                // Ignore deletion errors - item may be in use or protected
            }
        }

        return Task.CompletedTask;
    }

    private static IEnumerable<LeftoverItem> FindRegistryLeftovers(InstalledApp app, IEnumerable<string> tokens, CancellationToken ct)
    {
        var results = new List<LeftoverItem>();

        // Common registry locations to scan
        var searchPaths = new[]
        {
            (Registry.LocalMachine, @"SOFTWARE"),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node"),
            (Registry.CurrentUser, @"SOFTWARE"),
            (Registry.ClassesRoot, @""),
        };

        foreach (var (root, subkey) in searchPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                ScanRegistryForMatches(root, subkey, tokens, results, maxDepth: 2);
            }
            catch
            {
                // Ignore access denied errors
            }
        }

        // Always include the app's own registry key
        if (!string.IsNullOrWhiteSpace(app.RegistryKeyPath))
        {
            results.Add(new LeftoverItem
            {
                Type = LeftoverType.RegistryKey,
                Path = app.RegistryKeyPath,
                Reason = "Application registry key",
                MatchDetail = "Main uninstall entry"
            });
        }

        return results;
    }

    private static void ScanRegistryForMatches(RegistryKey root, string subkeyPath, IEnumerable<string> tokens,
        List<LeftoverItem> results, int currentDepth = 0, int maxDepth = 2)
    {
        if (currentDepth > maxDepth) return;

        try
        {
            using var key = string.IsNullOrEmpty(subkeyPath) ? root : root.OpenSubKey(subkeyPath);
            if (key == null) return;

            foreach (var name in key.GetSubKeyNames().Take(100)) // Limit to avoid scanning too much
            {
                if (IgnoreTokens.Any(ignore => name.IndexOf(ignore, StringComparison.OrdinalIgnoreCase) >= 0))
                    continue;

                var matchCount = tokens.Count(t => name.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0);
                if (matchCount >= 2 || (matchCount >= 1 && name.Length < 50))
                {
                    var fullPath = string.IsNullOrEmpty(subkeyPath) ?
                        $"{root.Name}\\{name}" :
                        $"{root.Name}\\{subkeyPath}\\{name}";

                    results.Add(new LeftoverItem
                    {
                        Type = LeftoverType.RegistryKey,
                        Path = fullPath,
                        Reason = "Registry key matches app name",
                        MatchDetail = $"Matched {matchCount} tokens in name: {name}"
                    });
                }
                else if (currentDepth < maxDepth)
                {
                    var nextPath = string.IsNullOrEmpty(subkeyPath) ? name : $"{subkeyPath}\\{name}";
                    ScanRegistryForMatches(root, nextPath, tokens, results, currentDepth + 1, maxDepth);
                }
            }
        }
        catch
        {
            // Ignore access errors
        }
    }

    private static IEnumerable<LeftoverItem> FindAppDataLeftovers(IEnumerable<string> tokens, CancellationToken ct)
    {
        var results = new List<LeftoverItem>();
        var appDataPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "LocalLow")
        };

        foreach (var basePath in appDataPaths.Where(Directory.Exists))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var dir in Directory.EnumerateDirectories(basePath, "*", SearchOption.TopDirectoryOnly))
                {
                    var dirName = Path.GetFileName(dir);
                    var matchCount = tokens.Count(t => dirName.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0);

                    if (matchCount >= 2)
                    {
                        results.Add(new LeftoverItem
                        {
                            Type = LeftoverType.Directory,
                            Path = dir,
                            Reason = $"AppData folder matches app name ({Path.GetFileName(basePath)})",
                            MatchDetail = $"Matched {matchCount} tokens",
                            SizeBytes = SafeDirectorySize(dir)
                        });
                    }
                }
            }
            catch
            {
                // Ignore access errors
            }
        }

        return results;
    }

    private static IEnumerable<LeftoverItem> FindProgramDataLeftovers(IEnumerable<string> tokens, CancellationToken ct)
    {
        var results = new List<LeftoverItem>();
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

        if (!Directory.Exists(programData)) return results;

        ct.ThrowIfCancellationRequested();
        try
        {
            foreach (var dir in Directory.EnumerateDirectories(programData, "*", SearchOption.TopDirectoryOnly))
            {
                var dirName = Path.GetFileName(dir);
                if (IgnoreTokens.Any(ignore => dirName.IndexOf(ignore, StringComparison.OrdinalIgnoreCase) >= 0))
                    continue;

                var matchCount = tokens.Count(t => dirName.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0);

                if (matchCount >= 2)
                {
                    results.Add(new LeftoverItem
                    {
                        Type = LeftoverType.Directory,
                        Path = dir,
                        Reason = "ProgramData folder matches app name",
                        MatchDetail = $"Matched {matchCount} tokens",
                        SizeBytes = SafeDirectorySize(dir)
                    });
                }
            }
        }
        catch
        {
            // Ignore access errors
        }

        return results;
    }

    private static IEnumerable<LeftoverItem> FindShortcutLeftovers(IEnumerable<string> tokens, CancellationToken ct)
    {
        var results = new List<LeftoverItem>();
        var shortcutPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory)
        };

        foreach (var basePath in shortcutPaths.Where(Directory.Exists))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var file in Directory.EnumerateFiles(basePath, "*.lnk", SearchOption.AllDirectories))
                {
                    var fileName = Path.GetFileNameWithoutExtension(file);
                    var matchCount = tokens.Count(t => fileName.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0);

                    if (matchCount >= 1)
                    {
                        results.Add(new LeftoverItem
                        {
                            Type = LeftoverType.File,
                            Path = file,
                            Reason = "Shortcut matches app name",
                            MatchDetail = $"Found in {Path.GetFileName(Path.GetDirectoryName(basePath))}",
                            SizeBytes = new FileInfo(file).Length
                        });
                    }
                }
            }
            catch
            {
                // Ignore access errors
            }
        }

        return results;
    }

    private static IEnumerable<LeftoverItem> FindTempLeftovers(IEnumerable<string> tokens, CancellationToken ct)
    {
        var results = new List<LeftoverItem>();
        var tempPaths = new[]
        {
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
        };

        foreach (var basePath in tempPaths.Where(Directory.Exists))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var dir in Directory.EnumerateDirectories(basePath, "*", SearchOption.TopDirectoryOnly).Take(50))
                {
                    var dirName = Path.GetFileName(dir);
                    var matchCount = tokens.Count(t => dirName.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0);

                    if (matchCount >= 2)
                    {
                        results.Add(new LeftoverItem
                        {
                            Type = LeftoverType.Directory,
                            Path = dir,
                            Reason = "Temp folder matches app name",
                            MatchDetail = $"Matched {matchCount} tokens",
                            SizeBytes = SafeDirectorySize(dir)
                        });
                    }
                }
            }
            catch
            {
                // Ignore access errors
            }
        }

        return results;
    }

    private static void DeleteRegistryKey(string keyPath)
    {
        try
        {
            // Parse the key path (format: HKEY_XXX\path\to\key)
            var parts = keyPath.Split('\\', 2);
            if (parts.Length < 2) return;

            var root = parts[0] switch
            {
                "HKEY_LOCAL_MACHINE" => Registry.LocalMachine,
                "HKEY_CURRENT_USER" => Registry.CurrentUser,
                "HKEY_CLASSES_ROOT" => Registry.ClassesRoot,
                "HKEY_USERS" => Registry.Users,
                _ => null
            };

            if (root != null)
            {
                root.DeleteSubKeyTree(parts[1], throwOnMissingSubKey: false);
            }
        }
        catch
        {
            // Ignore deletion errors
        }
    }

    private static void DeleteRegistryValue(string keyPath, string? valueName)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(valueName)) return;

            var parts = keyPath.Split('\\', 2);
            if (parts.Length < 2) return;

            var root = parts[0] switch
            {
                "HKEY_LOCAL_MACHINE" => Registry.LocalMachine,
                "HKEY_CURRENT_USER" => Registry.CurrentUser,
                "HKEY_CLASSES_ROOT" => Registry.ClassesRoot,
                "HKEY_USERS" => Registry.Users,
                _ => null
            };

            if (root != null)
            {
                using var key = root.OpenSubKey(parts[1], writable: true);
                key?.DeleteValue(valueName, throwOnMissingValue: false);
            }
        }
        catch
        {
            // Ignore deletion errors
        }
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
