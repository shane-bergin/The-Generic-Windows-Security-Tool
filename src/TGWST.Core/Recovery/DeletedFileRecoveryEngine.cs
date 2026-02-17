using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.Core.Recovery
{
    public sealed class DeletedFileRecoveryEngine
    {
        private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".txt", ".log", ".csv", ".json", ".xml", ".ini", ".config", ".md", ".ps1", ".bat", ".cmd"
        };

        private static readonly HashSet<string> ImageExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tif", ".tiff", ".webp"
        };

        private static readonly string[] WinFrFilters =
        {
            "txt", "log", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
            "jpg", "jpeg", "png", "gif", "zip", "rar", "7z"
        };

        public async Task<DeletedFileRecoveryScanResult> ScanAsync(
            string sourceDrive,
            string recoveryRoot,
            CancellationToken ct = default)
        {
            var normalizedSource = NormalizeDrive(sourceDrive);
            if (string.IsNullOrWhiteSpace(normalizedSource))
            {
                return new DeletedFileRecoveryScanResult(
                    Array.Empty<DeletedFileRecoveryItem>(),
                    UsedWinFr: false,
                    UsedRecycleBinFallback: false,
                    StatusMessage: "Invalid source drive. Expected format like C:");
            }

            var targetRoot = string.IsNullOrWhiteSpace(recoveryRoot)
                ? Path.Combine(Path.GetTempPath(), "TGWST-Recovery")
                : recoveryRoot.Trim();

            Directory.CreateDirectory(targetRoot);

            var targetDrive = NormalizeDrive(targetRoot);
            var canRunWinFr = !string.IsNullOrWhiteSpace(targetDrive) &&
                              !string.Equals(normalizedSource, targetDrive, StringComparison.OrdinalIgnoreCase);
            var winfrPath = FindWinFr();

            if (!string.IsNullOrWhiteSpace(winfrPath) && canRunWinFr)
            {
                var winfrResult = await RunWinFrScanAsync(winfrPath!, normalizedSource, targetRoot, ct).ConfigureAwait(false);
                if (winfrResult.Items.Count > 0)
                {
                    return winfrResult;
                }

                var recycleItems = await ScanRecycleBinAsync(ct).ConfigureAwait(false);
                if (recycleItems.Count > 0)
                {
                    return new DeletedFileRecoveryScanResult(
                        recycleItems,
                        UsedWinFr: true,
                        UsedRecycleBinFallback: true,
                        StatusMessage: $"{winfrResult.StatusMessage} Fallback to Recycle Bin metadata succeeded.");
                }

                return new DeletedFileRecoveryScanResult(
                    Array.Empty<DeletedFileRecoveryItem>(),
                    UsedWinFr: true,
                    UsedRecycleBinFallback: true,
                    StatusMessage: $"{winfrResult.StatusMessage} No fallback recoverables were found.");
            }

            var fallbackReason = string.IsNullOrWhiteSpace(winfrPath)
                ? "Windows File Recovery (winfr.exe) was not found."
                : "Source and recovery destination are on the same drive.";

            var items = await ScanRecycleBinAsync(ct).ConfigureAwait(false);
            return new DeletedFileRecoveryScanResult(
                items,
                UsedWinFr: false,
                UsedRecycleBinFallback: true,
                StatusMessage: $"{fallbackReason} Using Recycle Bin fallback mode.");
        }

        public async Task<RecoveryPreviewResult> BuildPreviewAsync(
            DeletedFileRecoveryItem item,
            CancellationToken ct = default)
        {
            if (item == null || string.IsNullOrWhiteSpace(item.SourcePath) || !File.Exists(item.SourcePath))
            {
                return new RecoveryPreviewResult(
                    RecoveryPreviewKind.None,
                    "File is no longer available for preview.",
                    null);
            }

            var extension = Path.GetExtension(item.FileName);
            if (ImageExtensions.Contains(extension))
            {
                return new RecoveryPreviewResult(
                    RecoveryPreviewKind.Image,
                    $"Image preview ready: {item.FileName}",
                    item.SourcePath);
            }

            if (TextExtensions.Contains(extension))
            {
                var text = await ReadTextPreviewAsync(item.SourcePath, ct).ConfigureAwait(false);
                return new RecoveryPreviewResult(
                    RecoveryPreviewKind.Text,
                    text,
                    null);
            }

            var hex = await ReadBinaryPreviewAsync(item.SourcePath, ct).ConfigureAwait(false);
            return new RecoveryPreviewResult(
                RecoveryPreviewKind.Binary,
                hex,
                null);
        }

        public Task<RecoveryRestoreResult> RestoreAsync(
            DeletedFileRecoveryItem item,
            string destinationRoot,
            CancellationToken ct = default)
        {
            if (item == null || string.IsNullOrWhiteSpace(item.SourcePath))
            {
                return Task.FromResult(new RecoveryRestoreResult(false, "Invalid recovery item.", null));
            }

            if (!File.Exists(item.SourcePath))
            {
                return Task.FromResult(new RecoveryRestoreResult(false, "Source file no longer exists.", null));
            }

            if (string.IsNullOrWhiteSpace(destinationRoot))
            {
                return Task.FromResult(new RecoveryRestoreResult(false, "Destination folder is required.", null));
            }

            try
            {
                ct.ThrowIfCancellationRequested();
                Directory.CreateDirectory(destinationRoot);

                var desiredName = ResolvePreferredName(item);
                var finalPath = ResolveCollisionPath(destinationRoot, desiredName);
                File.Copy(item.SourcePath, finalPath, overwrite: false);

                return Task.FromResult(new RecoveryRestoreResult(
                    true,
                    "Recovery file restored successfully.",
                    finalPath));
            }
            catch (OperationCanceledException)
            {
                return Task.FromResult(new RecoveryRestoreResult(false, "Restore canceled.", null));
            }
            catch (Exception ex)
            {
                return Task.FromResult(new RecoveryRestoreResult(false, ex.Message, null));
            }
        }

        private static async Task<DeletedFileRecoveryScanResult> RunWinFrScanAsync(
            string winfrPath,
            string sourceDrive,
            string recoveryRoot,
            CancellationToken ct)
        {
            var scanFolder = Path.Combine(
                recoveryRoot,
                $"winfr-{DateTime.Now:yyyyMMdd-HHmmss}");
            Directory.CreateDirectory(scanFolder);

            var extensionFilter = string.Join(",", WinFrFilters);
            var arguments = $"\"{sourceDrive}\\\" \"{scanFolder}\" /regular /n *.* /y:{extensionFilter}";

            var output = new StringBuilder();

            var startInfo = new ProcessStartInfo
            {
                FileName = winfrPath,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
            process.Start();

            // winfr asks for confirmation; feed yes once.
            await process.StandardInput.WriteLineAsync("y").ConfigureAwait(false);
            await process.StandardInput.FlushAsync().ConfigureAwait(false);

            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync(ct).ConfigureAwait(false);
            output.AppendLine(await stdoutTask.ConfigureAwait(false));
            output.AppendLine(await stderrTask.ConfigureAwait(false));

            var items = EnumerateRecoveredFiles(scanFolder, source: "WinFR");
            var status = process.ExitCode == 0
                ? $"WinFR completed. Candidates found: {items.Count}."
                : $"WinFR exited with code {process.ExitCode}.";

            if (process.ExitCode != 0 && output.Length > 0)
            {
                status = $"{status} {Truncate(output.ToString().Replace(Environment.NewLine, " "), 220)}";
            }

            return new DeletedFileRecoveryScanResult(items, UsedWinFr: true, UsedRecycleBinFallback: false, status);
        }

        private static List<DeletedFileRecoveryItem> EnumerateRecoveredFiles(string root, string source)
        {
            var results = new List<DeletedFileRecoveryItem>();
            if (!Directory.Exists(root))
            {
                return results;
            }

            var threshold = DateTime.Now.AddDays(-30);
            var files = SafeEnumerateFiles(root)
                .Take(3000)
                .ToArray();

            foreach (var file in files)
            {
                try
                {
                    var info = new FileInfo(file);
                    var modified = info.LastWriteTime;
                    if (modified < threshold)
                    {
                        continue;
                    }

                    results.Add(new DeletedFileRecoveryItem(
                        ItemId: Guid.NewGuid().ToString("N"),
                        FileName: info.Name,
                        FileType: DetectFileType(info.Name),
                        FileSize: info.Length,
                        DateModified: modified,
                        Source: source,
                        SourcePath: info.FullName,
                        OriginalPath: null));
                }
                catch
                {
                    // skip inaccessible files
                }
            }

            return results
                .OrderByDescending(x => x.DateModified)
                .ToList();
        }

        private static async Task<List<DeletedFileRecoveryItem>> ScanRecycleBinAsync(CancellationToken ct)
        {
            return await Task.Run(() =>
            {
                var results = new List<DeletedFileRecoveryItem>();
                var recycleRoots = DriveInfo.GetDrives()
                    .Where(d => d.IsReady && d.DriveType == DriveType.Fixed)
                    .Select(d => Path.Combine(d.RootDirectory.FullName, "$Recycle.Bin"))
                    .Where(Directory.Exists)
                    .ToArray();

                var threshold = DateTime.Now.AddDays(-30);
                foreach (var recycleRoot in recycleRoots)
                {
                    foreach (var iFile in SafeEnumerateFiles(recycleRoot, "$I*"))
                    {
                        ct.ThrowIfCancellationRequested();

                        try
                        {
                            var iName = Path.GetFileName(iFile);
                            if (string.IsNullOrWhiteSpace(iName) || iName.Length < 3)
                            {
                                continue;
                            }

                            var rName = "$R" + iName[2..];
                            var rPath = Path.Combine(Path.GetDirectoryName(iFile) ?? string.Empty, rName);
                            if (!File.Exists(rPath))
                            {
                                continue;
                            }

                            var meta = ParseRecycleMetadata(iFile);
                            var rInfo = new FileInfo(rPath);
                            var modified = rInfo.LastWriteTime;
                            if (modified < threshold)
                            {
                                continue;
                            }

                            var fileName = !string.IsNullOrWhiteSpace(meta.OriginalPath)
                                ? Path.GetFileName(meta.OriginalPath)
                                : rInfo.Name;

                            results.Add(new DeletedFileRecoveryItem(
                                ItemId: Guid.NewGuid().ToString("N"),
                                FileName: fileName,
                                FileType: DetectFileType(fileName),
                                FileSize: rInfo.Length > 0 ? rInfo.Length : meta.OriginalSize,
                                DateModified: modified,
                                Source: "RecycleBin",
                                SourcePath: rInfo.FullName,
                                OriginalPath: meta.OriginalPath));
                        }
                        catch
                        {
                            // skip malformed records
                        }
                    }
                }

                return results
                    .OrderByDescending(x => x.DateModified)
                    .ToList();
            }, ct).ConfigureAwait(false);
        }

        private static (long OriginalSize, string? OriginalPath) ParseRecycleMetadata(string iFilePath)
        {
            var bytes = File.ReadAllBytes(iFilePath);
            if (bytes.Length < 24)
            {
                return (0, null);
            }

            var size = BitConverter.ToInt64(bytes, 8);
            if (bytes.Length <= 24)
            {
                return (size, null);
            }

            var pathBytes = bytes[24..];
            var pathRaw = Encoding.Unicode.GetString(pathBytes);
            var terminator = pathRaw.IndexOf('\0');
            if (terminator >= 0)
            {
                pathRaw = pathRaw[..terminator];
            }

            return (size, string.IsNullOrWhiteSpace(pathRaw) ? null : pathRaw.Trim());
        }

        private static string ResolvePreferredName(DeletedFileRecoveryItem item)
        {
            var candidate = !string.IsNullOrWhiteSpace(item.OriginalPath)
                ? Path.GetFileName(item.OriginalPath)
                : item.FileName;

            if (string.IsNullOrWhiteSpace(candidate))
            {
                candidate = $"recovered-{DateTime.Now:yyyyMMdd-HHmmss}.bin";
            }

            foreach (var invalid in Path.GetInvalidFileNameChars())
            {
                candidate = candidate.Replace(invalid, '_');
            }

            return candidate;
        }

        private static string ResolveCollisionPath(string destinationRoot, string fileName)
        {
            var baseName = Path.GetFileNameWithoutExtension(fileName);
            var extension = Path.GetExtension(fileName);
            var candidate = Path.Combine(destinationRoot, fileName);
            if (!File.Exists(candidate))
            {
                return candidate;
            }

            for (var i = 1; i < 10000; i++)
            {
                var next = Path.Combine(destinationRoot, $"{baseName} ({i}){extension}");
                if (!File.Exists(next))
                {
                    return next;
                }
            }

            return Path.Combine(destinationRoot, $"{baseName}-{Guid.NewGuid():N}{extension}");
        }

        private static async Task<string> ReadTextPreviewAsync(string path, CancellationToken ct)
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var length = (int)Math.Min(8192, stream.Length);
            var buffer = new byte[length];
            var read = await stream.ReadAsync(buffer.AsMemory(0, length), ct).ConfigureAwait(false);
            var utf8 = Encoding.UTF8.GetString(buffer, 0, read);
            return Truncate(utf8, 4000);
        }

        private static async Task<string> ReadBinaryPreviewAsync(string path, CancellationToken ct)
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var buffer = new byte[Math.Min(64, (int)Math.Max(stream.Length, 1))];
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
            if (read <= 0)
            {
                return "Binary file is empty.";
            }

            var slice = buffer.Take(read)
                .Select(b => b.ToString("X2", CultureInfo.InvariantCulture));
            return string.Join(" ", slice);
        }

        private static string DetectFileType(string fileName)
        {
            var ext = Path.GetExtension(fileName);
            if (string.IsNullOrWhiteSpace(ext))
            {
                return "Unknown";
            }

            return ext.TrimStart('.').ToUpperInvariant();
        }

        private static string? FindWinFr()
        {
            try
            {
                var systemWinFr = Path.Combine(Environment.SystemDirectory, "winfr.exe");
                if (File.Exists(systemWinFr))
                {
                    return systemWinFr;
                }

                var windowsApps = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "WindowsApps");
                if (Directory.Exists(windowsApps))
                {
                    var candidate = SafeEnumerateFiles(windowsApps, "winfr.exe")
                        .FirstOrDefault();
                    if (!string.IsNullOrWhiteSpace(candidate))
                    {
                        return candidate;
                    }
                }
            }
            catch
            {
                // best effort lookup
            }

            return null;
        }

        private static string? NormalizeDrive(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return null;
            }

            var value = path.Trim();
            if (value.Length >= 2 && value[1] == ':')
            {
                return value[..2].ToUpperInvariant();
            }

            var root = Path.GetPathRoot(value);
            if (!string.IsNullOrWhiteSpace(root) && root!.Length >= 2 && root[1] == ':')
            {
                return root[..2].ToUpperInvariant();
            }

            return null;
        }

        private static IEnumerable<string> SafeEnumerateFiles(string root, string pattern = "*")
        {
            var pending = new Stack<string>();
            pending.Push(root);

            while (pending.Count > 0)
            {
                var current = pending.Pop();
                IEnumerable<string> files = Array.Empty<string>();
                IEnumerable<string> dirs = Array.Empty<string>();

                try
                {
                    files = Directory.EnumerateFiles(current, pattern, SearchOption.TopDirectoryOnly);
                }
                catch
                {
                    // ignore inaccessible nodes
                }

                foreach (var file in files)
                {
                    yield return file;
                }

                try
                {
                    dirs = Directory.EnumerateDirectories(current, "*", SearchOption.TopDirectoryOnly);
                }
                catch
                {
                    // ignore inaccessible nodes
                }

                foreach (var dir in dirs)
                {
                    pending.Push(dir);
                }
            }
        }

        private static string Truncate(string value, int max)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= max)
            {
                return value;
            }

            return value[..(max - 3)] + "...";
        }
    }
}
