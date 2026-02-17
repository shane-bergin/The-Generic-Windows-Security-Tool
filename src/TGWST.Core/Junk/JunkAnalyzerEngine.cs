using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using VBFileIO = Microsoft.VisualBasic.FileIO;

namespace TGWST.Core.Junk
{
    public sealed class JunkAnalyzerEngine
    {
        private static readonly string[] TempExtensions =
        {
            ".tmp", ".temp", ".log", ".old", ".bak", ".etl", ".dmp", ".cache"
        };

        private static readonly string[] DirectorySignals =
        {
            "cache", "temp", "logs", "telemetry", "tracking", "crash", "shadercache", "code cache"
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
                var roots = GetScanRoots();
                var results = new List<JunkCandidate>();
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var root in roots)
                {
                    ct.ThrowIfCancellationRequested();
                    if (!Directory.Exists(root))
                    {
                        continue;
                    }

                    AnalyzeRoot(root, results, seen, ct);
                }

                return results
                    .OrderByDescending(x => x.SafeToClean)
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

                    if (IsProtectedPath(item.Path))
                    {
                        skipped++;
                        results.Add(new JunkCleanupItemResult(item.Path, false, "Skipped (protected path)."));
                        continue;
                    }

                    try
                    {
                        if (File.Exists(item.Path))
                        {
                            DeleteFileWithRecycleFallback(item.Path);
                            deleted++;
                            results.Add(new JunkCleanupItemResult(item.Path, true, "Deleted."));
                            continue;
                        }

                        if (Directory.Exists(item.Path))
                        {
                            DeleteDirectoryWithRecycleFallback(item.Path);
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
            string root,
            List<JunkCandidate> results,
            HashSet<string> seen,
            CancellationToken ct)
        {
            var now = DateTime.Now;
            foreach (var entry in SafeEnumerateEntries(root, maxDepth: 4, maxNodes: 8000))
            {
                ct.ThrowIfCancellationRequested();
                if (!seen.Add(entry.Path))
                {
                    continue;
                }

                if (IsProtectedPath(entry.Path))
                {
                    continue;
                }

                if (entry.IsDirectory)
                {
                    var dirName = Path.GetFileName(entry.Path);
                    var signal = DirectorySignals.FirstOrDefault(s => dirName.Contains(s, StringComparison.OrdinalIgnoreCase));
                    if (signal == null)
                    {
                        continue;
                    }

                    if ((now - entry.LastModified).TotalDays < 14)
                    {
                        continue;
                    }

                    var safe = IsUnderTempRoot(entry.Path) || signal.Contains("cache", StringComparison.OrdinalIgnoreCase);
                    var category = signal.Contains("telemetry", StringComparison.OrdinalIgnoreCase) ||
                                   signal.Contains("tracking", StringComparison.OrdinalIgnoreCase)
                        ? "Telemetry/Tracking Residue"
                        : "Cache/Temp Directory";

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

                    if (!extensionSignal && !textSignal && !IsUnderTempRoot(entry.Path))
                    {
                        continue;
                    }

                    if ((now - entry.LastModified).TotalDays < 7)
                    {
                        continue;
                    }

                    var safe = IsUnderTempRoot(entry.Path) || extensionSignal;
                    var category = textSignal ? "Telemetry/Tracking File" : "Temp/Cache File";
                    var reason = extensionSignal
                        ? $"Temporary extension {ext} and stale age."
                        : "Filename suggests cache/telemetry residue.";

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

        private static void DeleteFileWithRecycleFallback(string path)
        {
            try
            {
                VBFileIO.FileSystem.DeleteFile(
                    path,
                    VBFileIO.UIOption.OnlyErrorDialogs,
                    VBFileIO.RecycleOption.SendToRecycleBin,
                    VBFileIO.UICancelOption.DoNothing);
            }
            catch
            {
                File.Delete(path);
            }
        }

        private static void DeleteDirectoryWithRecycleFallback(string path)
        {
            try
            {
                VBFileIO.FileSystem.DeleteDirectory(
                    path,
                    VBFileIO.UIOption.OnlyErrorDialogs,
                    VBFileIO.RecycleOption.SendToRecycleBin,
                    VBFileIO.UICancelOption.DoNothing);
            }
            catch
            {
                Directory.Delete(path, recursive: true);
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
            var roots = new[]
            {
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
            };

            return roots.Any(root =>
                !string.IsNullOrWhiteSpace(root) &&
                path.StartsWith(root, StringComparison.OrdinalIgnoreCase));
        }

        private static string[] GetScanRoots()
        {
            var roots = new[]
            {
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
            };

            return roots
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray()!;
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
                    // ignore inaccessible dirs
                }

                foreach (var dir in dirs)
                {
                    visited++;
                    DateTime modified;
                    try
                    {
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
                    // ignore inaccessible files
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
                        // skip inaccessible files
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
                        // skip inaccessible files
                    }
                }

                return total;
            }
            catch
            {
                return 0;
            }
        }

        private readonly record struct ScanEntry(
            string Path,
            bool IsDirectory,
            long SizeBytes,
            DateTime LastModified);
    }
}
