using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace TGWST.Core.Junk
{
    public sealed class JunkAnalyzerEngine
    {
        private const string RunSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

        private static readonly string[] TempExtensions =
        {
            ".tmp", ".temp", ".log", ".old", ".bak", ".etl", ".dmp", ".cache"
        };

        private static readonly string[] DirectorySignals =
        {
            "cache", "temp", "logs", "telemetry", "tracking", "crash", "shadercache", "code cache",
            "Default", "Session Storage", "Local Storage", "IndexedDB", "Service Worker", "GPUCache"
        };

        private static readonly string[] BrowserTelemetrySignals =
        {
            "chrome", "edge", "firefox", "brave", "opera", "vivaldi"
        };

        private static readonly string[] ProtectedPathSignals =
        {
            @"\windows\",
            @"\program files\",
            @"\program files (x86)\",
            @"\windowsapps\",
            @"\appdata\local\packages\",
            @"\appdata\roaming\microsoft\"
        };

        public Task<IReadOnlyList<JunkCandidate>> AnalyzeAsync(CancellationToken ct = default)
        {
            return Task.Run<IReadOnlyList<JunkCandidate>>(() =>
            {
                var results = new List<JunkCandidate>();
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var root in GetScanRoots())
                {
                    ct.ThrowIfCancellationRequested();
                    if (Directory.Exists(root.Path))
                    {
                        AnalyzeRoot(root, results, seen, ct);
                    }
                }

                AnalyzeRegistryResidue(results, seen, ct);

                return results
                    .OrderByDescending(x => x.SafeToClean)
                    .ThenBy(x => x.Kind, StringComparer.OrdinalIgnoreCase)
                    .ThenByDescending(x => x.SizeBytes)
                    .ThenByDescending(x => x.LastModified)
                    .ToArray();
            }, ct);
        }

        public Task<JunkCleanupResult> CleanupAsync(
            IEnumerable<JunkCandidate> items,
            bool safeOnly,
            CancellationToken ct = default)
        {
            return Task.Run(() =>
            {
                var selected = items?.ToArray() ?? Array.Empty<JunkCandidate>();
                var deleted = 0;
                var skipped = 0;
                var results = new List<JunkCleanupItemResult>();

                foreach (var item in selected)
                {
                    ct.ThrowIfCancellationRequested();

                    if (safeOnly && !item.SafeToClean)
                    {
                        skipped++;
                        results.Add(new JunkCleanupItemResult(item.Path, false, "Skipped (not marked safe)."));
                        continue;
                    }

                    if (item.Kind.Equals("RegistryValue", StringComparison.OrdinalIgnoreCase))
                    {
                        if (TryDeleteRegistryValue(item, out var message))
                        {
                            deleted++;
                            results.Add(new JunkCleanupItemResult(item.Path, true, message));
                        }
                        else
                        {
                            skipped++;
                            results.Add(new JunkCleanupItemResult(item.Path, false, message));
                        }

                        continue;
                    }

                    if (!IsSafeCleanupPath(item.Path) || !MatchesScannedFileState(item))
                    {
                        skipped++;
                        results.Add(new JunkCleanupItemResult(item.Path, false, "Skipped (path is outside cleanup roots, contains a reparse point, or changed since analysis)."));
                        continue;
                    }

                    try
                    {
                        if (File.Exists(item.Path))
                        {
                            File.Delete(item.Path);
                            deleted++;
                            results.Add(new JunkCleanupItemResult(item.Path, true, "Deleted."));
                            continue;
                        }

                        if (Directory.Exists(item.Path))
                        {
                            Directory.Delete(item.Path, recursive: true);
                            deleted++;
                            results.Add(new JunkCleanupItemResult(item.Path, true, "Deleted."));
                            continue;
                        }

                        skipped++;
                        results.Add(new JunkCleanupItemResult(item.Path, false, "Skipped (path missing)."));
                    }
                    catch (Exception ex)
                    {
                        skipped++;
                        results.Add(new JunkCleanupItemResult(item.Path, false, ex.Message));
                    }
                }

                return new JunkCleanupResult(deleted, skipped, results);
            }, ct);
        }

        private static void AnalyzeRoot(
            ScanRoot root,
            List<JunkCandidate> results,
            HashSet<string> seen,
            CancellationToken ct)
        {
            var now = DateTime.Now;
            foreach (var entry in SafeEnumerateEntries(root.Path, maxDepth: 4, maxNodes: 9000))
            {
                ct.ThrowIfCancellationRequested();
                if (!seen.Add(entry.Path) || IsProtectedPath(entry.Path))
                {
                    continue;
                }

                if (entry.IsDirectory)
                {
                    var dirName = Path.GetFileName(entry.Path);
                    var signal = DirectorySignals.FirstOrDefault(s => dirName.Contains(s, StringComparison.OrdinalIgnoreCase));
                    if (signal == null || (now - entry.LastModified).TotalDays < root.StaleDirectoryDays)
                    {
                        continue;
                    }

                    var staleDays = (now - entry.LastModified).TotalDays;
                    var cacheSignal = signal.Contains("cache", StringComparison.OrdinalIgnoreCase);
                    var safe = root.SafeRoot || (cacheSignal && staleDays >= 30);
                    var isBrowser = BrowserTelemetrySignals.Any(b => entry.Path.Contains(b, StringComparison.OrdinalIgnoreCase));
                    var category = isBrowser
                        ? "Browser Telemetry"
                        : signal.Contains("telemetry", StringComparison.OrdinalIgnoreCase) ||
                          signal.Contains("tracking", StringComparison.OrdinalIgnoreCase)
                            ? $"{root.Area} Telemetry Residue"
                            : $"{root.Area} Cache/Temp Directory";

                    results.Add(new JunkCandidate(
                        ItemId: Guid.NewGuid().ToString("N"),
                        Path: entry.Path,
                        Kind: "Directory",
                        SizeBytes: SafeDirectorySize(entry.Path),
                        LastModified: entry.LastModified,
                        Category: category,
                        Reason: $"Directory name suggests stale {signal} residue.",
                        SafeToClean: safe));
                }
                else
                {
                    var ext = Path.GetExtension(entry.Path);
                    var fileName = Path.GetFileName(entry.Path);
                    var extensionSignal = TempExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase);
                    var textSignal = fileName.Contains("telemetry", StringComparison.OrdinalIgnoreCase) ||
                                     fileName.Contains("tracking", StringComparison.OrdinalIgnoreCase) ||
                                     fileName.Contains("cache", StringComparison.OrdinalIgnoreCase);

                    if (!extensionSignal && !textSignal && !root.SafeRoot)
                    {
                        continue;
                    }

                    if ((now - entry.LastModified).TotalDays < root.StaleFileDays)
                    {
                        continue;
                    }

                    var staleDays = (now - entry.LastModified).TotalDays;
                    var safe = root.SafeRoot || (extensionSignal && staleDays >= 30);
                    var category = textSignal ? $"{root.Area} Telemetry/Cache File" : $"{root.Area} Temp File";
                    var reason = extensionSignal
                        ? $"Temporary extension {ext} and stale age."
                        : "Filename suggests cache or telemetry residue.";

                    results.Add(new JunkCandidate(
                        ItemId: Guid.NewGuid().ToString("N"),
                        Path: entry.Path,
                        Kind: "File",
                        SizeBytes: entry.SizeBytes,
                        LastModified: entry.LastModified,
                        Category: category,
                        Reason: reason,
                        SafeToClean: safe));
                }
            }
        }

        private static void AnalyzeRegistryResidue(
            List<JunkCandidate> results,
            HashSet<string> seen,
            CancellationToken ct)
        {
            foreach (var location in RegistryScanLocations())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var root = RegistryKey.OpenBaseKey(location.Hive, location.View);
                    using var key = root.OpenSubKey(location.SubKey, writable: false);
                    if (key == null)
                    {
                        continue;
                    }

                    foreach (var valueName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        var command = Convert.ToString(key.GetValue(valueName)) ?? string.Empty;
                        var displayPath = $@"{location.Scope}\{location.SubKey}\{valueName}";
                        if (!seen.Add(displayPath))
                        {
                            continue;
                        }

                        var executable = ResolveExecutablePath(command);
                        var targetMissing = !string.IsNullOrWhiteSpace(executable) &&
                                            IsFullyQualifiedPath(executable) &&
                                            !File.Exists(executable);
                        var tempTarget = !string.IsNullOrWhiteSpace(executable) && IsUnderTempRoot(executable);
                        var appDataTarget = !string.IsNullOrWhiteSpace(executable) && IsUnderAppDataRoot(executable);
                        var emptyValue = string.IsNullOrWhiteSpace(command);

                        if (!emptyValue && !targetMissing && !tempTarget && !appDataTarget)
                        {
                            continue;
                        }

                        var safe = emptyValue || targetMissing;
                        var reason = emptyValue
                            ? "Startup registry value is empty."
                            : targetMissing
                                ? "Startup registry value targets a missing executable."
                                : tempTarget
                                    ? "Startup registry value targets a temporary directory."
                                    : "Startup registry value targets a user AppData directory.";

                        results.Add(new JunkCandidate(
                            ItemId: Guid.NewGuid().ToString("N"),
                            Path: displayPath,
                            Kind: "RegistryValue",
                            SizeBytes: 0,
                            LastModified: DateTime.MinValue,
                            Category: "Registry Startup Residue",
                            Reason: reason,
                            SafeToClean: safe,
                            RegistryHive: location.Hive,
                            RegistryView: location.View,
                            RegistrySubKey: location.SubKey,
                            RegistryValueName: valueName,
                            RegistryValueData: command,
                            RegistryValueKind: key.GetValueKind(valueName)));
                    }
                }
                catch
                {
                }
            }
        }

        private static bool TryDeleteRegistryValue(JunkCandidate item, out string message)
        {
            if (item.RegistryHive == null ||
                item.RegistryView == null ||
                string.IsNullOrWhiteSpace(item.RegistrySubKey) ||
                string.IsNullOrWhiteSpace(item.RegistryValueName))
            {
                message = "Skipped (registry metadata missing).";
                return false;
            }

            try
            {
                using var root = RegistryKey.OpenBaseKey(item.RegistryHive.Value, item.RegistryView.Value);
                using var key = root.OpenSubKey(item.RegistrySubKey, writable: true);
                if (key == null)
                {
                    message = "Skipped (registry key missing).";
                    return false;
                }

                if (!key.GetValueNames().Contains(item.RegistryValueName, StringComparer.OrdinalIgnoreCase))
                {
                    message = "Skipped (registry value missing).";
                    return false;
                }

                var currentKind = key.GetValueKind(item.RegistryValueName);
                var currentData = Convert.ToString(key.GetValue(item.RegistryValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames)) ?? string.Empty;
                if (item.RegistryValueKind != currentKind ||
                    !string.Equals(item.RegistryValueData ?? string.Empty, currentData, StringComparison.Ordinal))
                {
                    message = "Skipped (registry value changed after analysis).";
                    return false;
                }

                key.DeleteValue(item.RegistryValueName, throwOnMissingValue: false);
                message = "Registry value deleted.";
                return true;
            }
            catch (Exception ex)
            {
                message = ex.Message;
                return false;
            }
        }

        private static bool IsSafeCleanupPath(string path)
        {
            var fullPath = SafeFullPath(path);
            if (string.IsNullOrWhiteSpace(fullPath) || IsProtectedPath(fullPath))
            {
                return false;
            }

            var matchedRoot = GetScanRoots()
                .Select(root => SafeFullPath(root.Path))
                .Where(root => !string.IsNullOrWhiteSpace(root))
                .FirstOrDefault(root => IsStrictDescendant(fullPath, root));
            if (matchedRoot == null)
            {
                return false;
            }

            return !ContainsReparsePoint(matchedRoot, fullPath);
        }

        private static bool IsStrictDescendant(string path, string root)
        {
            var relative = Path.GetRelativePath(root, path);
            return !relative.Equals(".", StringComparison.Ordinal) &&
                   !Path.IsPathRooted(relative) &&
                   !relative.Equals("..", StringComparison.Ordinal) &&
                   !relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal);
        }

        private static bool ContainsReparsePoint(string root, string path)
        {
            try
            {
                var current = path;
                while (!current.Equals(root, StringComparison.OrdinalIgnoreCase))
                {
                    if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    {
                        return true;
                    }

                    current = Path.GetDirectoryName(current) ?? string.Empty;
                    if (string.IsNullOrWhiteSpace(current))
                    {
                        return true;
                    }
                }

                if (!Directory.Exists(path))
                {
                    return false;
                }

                var pending = new Stack<string>();
                pending.Push(path);
                while (pending.Count > 0)
                {
                    foreach (var entry in Directory.EnumerateFileSystemEntries(pending.Pop()))
                    {
                        var attributes = File.GetAttributes(entry);
                        if ((attributes & FileAttributes.ReparsePoint) != 0)
                        {
                            return true;
                        }

                        if ((attributes & FileAttributes.Directory) != 0)
                        {
                            pending.Push(entry);
                        }
                    }
                }

                return false;
            }
            catch
            {
                return true;
            }
        }

        private static bool MatchesScannedFileState(JunkCandidate item)
        {
            try
            {
                if (!File.Exists(item.Path))
                {
                    return Directory.Exists(item.Path);
                }

                var info = new FileInfo(item.Path);
                return info.Length == item.SizeBytes &&
                       Math.Abs((info.LastWriteTime - item.LastModified).TotalSeconds) < 1;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsProtectedPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return true;
            }

            var normalized = path.Replace('/', '\\').ToLowerInvariant();
            return ProtectedPathSignals.Any(signal => normalized.Contains(signal, StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsUnderTempRoot(string path)
        {
            return IsUnderAnyRoot(path, TempRoots());
        }

        private static bool IsUnderAppDataRoot(string path)
        {
            return IsUnderAnyRoot(path, AppDataRoots());
        }

        private static bool IsUnderAnyRoot(string path, IEnumerable<string> roots)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            var fullPath = SafeFullPath(path);
            if (string.IsNullOrWhiteSpace(fullPath))
            {
                return false;
            }

            return roots.Any(root =>
            {
                var fullRoot = SafeFullPath(root);
                return !string.IsNullOrWhiteSpace(fullRoot) &&
                       fullPath.StartsWith(fullRoot.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
            });
        }

        private static ScanRoot[] GetScanRoots()
        {
            var roots = new[]
            {
                new ScanRoot(Path.GetTempPath(), "%TEMP%", SafeRoot: true, StaleFileDays: 2, StaleDirectoryDays: 2),
                new ScanRoot(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"), "%LOCALAPPDATA%\\Temp", SafeRoot: true, StaleFileDays: 2, StaleDirectoryDays: 2),
                new ScanRoot(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "%APPDATA%", SafeRoot: false, StaleFileDays: 14, StaleDirectoryDays: 14),
                new ScanRoot(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "%LOCALAPPDATA%", SafeRoot: false, StaleFileDays: 14, StaleDirectoryDays: 14)
            };

            return roots
                .Where(root => !string.IsNullOrWhiteSpace(root.Path))
                .GroupBy(root => NormalizeRoot(root.Path), StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .ToArray();
        }

        private static IEnumerable<string> TempRoots()
        {
            yield return Path.GetTempPath();
            yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp");
        }

        private static IEnumerable<string> AppDataRoots()
        {
            yield return Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            yield return Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        }

        private static RegistryScanLocation[] RegistryScanLocations()
        {
            return
            [
                new RegistryScanLocation(RegistryHive.CurrentUser, RegistryView.Default, "HKCU", RunSubKey),
                new RegistryScanLocation(RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM64", RunSubKey),
                new RegistryScanLocation(RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM32", RunSubKey)
            ];
        }

        private static string ResolveExecutablePath(string command)
        {
            if (string.IsNullOrWhiteSpace(command))
            {
                return string.Empty;
            }

            var expanded = Environment.ExpandEnvironmentVariables(command.Trim());
            if (expanded.StartsWith('"'))
            {
                var end = expanded.IndexOf('"', 1);
                return end > 1 ? expanded[1..end] : string.Empty;
            }

            var executableEnd = FindExecutableEnd(expanded);
            if (executableEnd > 0)
            {
                return expanded[..executableEnd].Trim();
            }

            return expanded.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? string.Empty;
        }

        private static int FindExecutableEnd(string command)
        {
            var extensions = new[] { ".exe", ".dll", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js" };
            foreach (var extension in extensions)
            {
                var index = command.IndexOf(extension, StringComparison.OrdinalIgnoreCase);
                if (index >= 0)
                {
                    return index + extension.Length;
                }
            }

            return -1;
        }

        private static bool IsFullyQualifiedPath(string path)
        {
            try
            {
                return Path.IsPathFullyQualified(path);
            }
            catch
            {
                return false;
            }
        }

        private static string NormalizeRoot(string path)
        {
            return SafeFullPath(path).TrimEnd('\\');
        }

        private static string SafeFullPath(string path)
        {
            try
            {
                return Path.GetFullPath(path);
            }
            catch
            {
                return string.Empty;
            }
        }

        private static IEnumerable<ScanEntry> SafeEnumerateEntries(string root, int maxDepth, int maxNodes)
        {
            var stack = new Stack<(string Path, int Depth)>();
            stack.Push((root, 0));
            var visited = 0;

            while (stack.Count > 0 && visited < maxNodes)
            {
                var (current, depth) = stack.Pop();
                if (depth > maxDepth)
                {
                    continue;
                }

                IEnumerable<string> dirs = Array.Empty<string>();
                IEnumerable<string> files = Array.Empty<string>();
                try
                {
                    dirs = Directory.EnumerateDirectories(current, "*", System.IO.SearchOption.TopDirectoryOnly);
                }
                catch
                {
                }

                foreach (var dir in dirs)
                {
                    visited++;
                    DateTime modified;
                    try
                    {
                        if ((File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0)
                        {
                            continue;
                        }

                        modified = Directory.GetLastWriteTime(dir);
                    }
                    catch
                    {
                        modified = DateTime.MinValue;
                    }

                    yield return new ScanEntry(dir, IsDirectory: true, 0, modified);
                    stack.Push((dir, depth + 1));
                    if (visited >= maxNodes)
                    {
                        yield break;
                    }
                }

                try
                {
                    files = Directory.EnumerateFiles(current, "*", System.IO.SearchOption.TopDirectoryOnly);
                }
                catch
                {
                }

                foreach (var file in files)
                {
                    visited++;
                    ScanEntry? entry = null;
                    try
                    {
                        var info = new FileInfo(file);
                        entry = new ScanEntry(info.FullName, IsDirectory: false, info.Length, info.LastWriteTime);
                    }
                    catch
                    {
                    }

                    if (entry.HasValue)
                    {
                        yield return entry.Value;
                    }

                    if (visited >= maxNodes)
                    {
                        yield break;
                    }
                }
            }
        }

        private static long SafeDirectorySize(string directoryPath)
        {
            try
            {
                long total = 0;
                foreach (var file in Directory.EnumerateFiles(directoryPath, "*", System.IO.SearchOption.AllDirectories))
                {
                    try
                    {
                        total += new FileInfo(file).Length;
                        if (total >= 2L * 1024 * 1024 * 1024)
                        {
                            break;
                        }
                    }
                    catch
                    {
                    }
                }

                return total;
            }
            catch
            {
                return 0;
            }
        }

        private readonly record struct ScanRoot(
            string Path,
            string Area,
            bool SafeRoot,
            int StaleFileDays,
            int StaleDirectoryDays);

        private readonly record struct RegistryScanLocation(
            RegistryHive Hive,
            RegistryView View,
            string Scope,
            string SubKey);

        private readonly record struct ScanEntry(
            string Path,
            bool IsDirectory,
            long SizeBytes,
            DateTime LastModified);
    }
}
