using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.Core.Scan;

public sealed class ClamAvEngine
{
    private readonly string? _clamPath;
    private readonly string? _dbPath;
    private readonly string? _freshclamPath;
    private readonly TimeSpan _maxDbAge = TimeSpan.FromHours(24);

    public ClamAvEngine()
    {
        (_clamPath, _dbPath, _freshclamPath) = FindClamExecutable();
    }

    public bool Available => !string.IsNullOrWhiteSpace(_clamPath);

    public async Task<IReadOnlyList<ScanResult>> RunClamScanAsync(
        ScanType type,
        string? root,
        IProgress<double>? progress = null,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        if (!Available)
        {
            log?.Report("ClamAV not found - deep scan skipped.");
            return Array.Empty<ScanResult>();
        }

        await EnsureSignaturesAsync(log, ct).ConfigureAwait(false);

        var roots = ResolveRoots(type, root).ToArray();
        if (roots.Length == 0)
        {
            log?.Report("ClamAV: no roots to scan.");
            return Array.Empty<ScanResult>();
        }

        var results = new List<ScanResult>();
        for (var i = 0; i < roots.Length; i++)
        {
            ct.ThrowIfCancellationRequested();
            var target = roots[i];
            log?.Report($"ClamAV scanning {target} ...");

            var args = BuildArgs(target);
            var output = await RunProcessAsync(_clamPath!, args, ct).ConfigureAwait(false);
            foreach (var line in output.Lines)
            {
                if (!line.EndsWith("FOUND", StringComparison.OrdinalIgnoreCase)) continue;
                var colon = line.LastIndexOf(':');
                if (colon <= 0) continue;

                var path = line[..colon].Trim();
                var signature = line[(colon + 1)..].Replace("FOUND", "", StringComparison.OrdinalIgnoreCase).Trim();
                if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(signature)) continue;

                results.Add(new ScanResult
                {
                    Path = path,
                    Suspicious = true,
                    Reason = $"ClamAV: {signature}",
                    Engine = $"ClamAV ({Path.GetFileNameWithoutExtension(_clamPath)})",
                    Source = "ClamAV",
                    ThreatFamily = signature
                });
            }

            progress?.Report(((i + 1) / (double)roots.Length) * 100.0);

            if (output.ExitCode > 1)
            {
                log?.Report($"ClamAV exited with code {output.ExitCode}. stderr: {output.Stderr}");
                break;
            }
        }

        return results
            .GroupBy(r => r.Path, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToArray();
    }

    private string BuildArgs(string target)
    {
        var quoted = $"\"{target}\"";
        var exeName = Path.GetFileName(_clamPath);
        var fdPass = exeName != null && exeName.Contains("clamdscan", StringComparison.OrdinalIgnoreCase)
            ? "--fdpass "
            : string.Empty;
        var dbArg = string.IsNullOrWhiteSpace(_dbPath) ? string.Empty : $"--database=\"{_dbPath}\" ";
        return $"--infected --recursive --no-summary {dbArg}{fdPass}{quoted}";
    }

    private async Task EnsureSignaturesAsync(IProgress<string>? log, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(_freshclamPath) || string.IsNullOrWhiteSpace(_dbPath))
        {
            log?.Report("ClamAV DB check skipped (no freshclam).");
            return;
        }

        Directory.CreateDirectory(_dbPath);
        var cvdFiles = Directory.EnumerateFiles(_dbPath, "*.c?v?d", SearchOption.TopDirectoryOnly).ToArray();
        var newest = cvdFiles.Select(f => File.GetLastWriteTimeUtc(f)).DefaultIfEmpty(DateTime.MinValue).Max();
        var age = DateTime.UtcNow - newest;
        if (cvdFiles.Length == 0 || age > _maxDbAge)
        {
            log?.Report("Refreshing ClamAV signatures...");
            await RunFreshClamAsync(_dbPath, log, ct).ConfigureAwait(false);
        }
    }

    private async Task RunFreshClamAsync(string dbDir, IProgress<string>? log, CancellationToken ct)
    {
        try
        {
            Directory.CreateDirectory(dbDir);
            var conf = Path.Combine(dbDir, "freshclam.conf");
            if (!File.Exists(conf))
            {
                var programDataClam = dbDir;
                await File.WriteAllTextAsync(conf,
@"DatabaseDirectory """ + programDataClam + @"""
UpdateLogFile """ + Path.Combine(programDataClam, "freshclam.log") + @"""
LogTime yes
DatabaseMirror database.clamav.net
NotifyClamd false
", ct).ConfigureAwait(false);
            }

            var args = $"--datadir=\"{dbDir}\" --config-file=\"{Path.Combine(dbDir, "freshclam.conf")}\"";
            var output = await RunProcessAsync(_freshclamPath!, args, ct).ConfigureAwait(false);
            if (output.ExitCode != 0)
            {
                log?.Report($"freshclam exited with code {output.ExitCode}. stderr: {output.Stderr}");
            }
            else
            {
                log?.Report("ClamAV signatures refreshed.");
            }
        }
        catch (Exception ex)
        {
            log?.Report($"freshclam failed: {ex.Message}");
        }
    }

    private static (string? ClamPath, string? DbPath, string? FreshclamPath) FindClamExecutable()
    {
        string? TryPath(string? path, out string? db, out string? fresh)
        {
            db = null;
            fresh = null;
            if (string.IsNullOrWhiteSpace(path)) return null;

            string exePath = path;
            if (Directory.Exists(path))
            {
                exePath = Path.Combine(path, "clamscan.exe");
            }
            if (!File.Exists(exePath)) return null;

            var baseDir = Path.GetDirectoryName(exePath);
            if (!string.IsNullOrWhiteSpace(baseDir))
            {
                var parent = Directory.GetParent(baseDir);
                if (parent != null)
                {
                    var dbDir = Path.Combine(parent.FullName, "db");
                    if (Directory.Exists(dbDir)) db = dbDir;
                }
                var freshPath = Path.Combine(baseDir, "freshclam.exe");
                if (File.Exists(freshPath)) fresh = freshPath;
            }
            return exePath;
        }

        string? dbPath;
        string? freshclamPath;

        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var bundled = Path.Combine(programData, "TGWST", "ClamAV", "bin");
        var found = TryPath(bundled, out dbPath, out freshclamPath);
        if (!string.IsNullOrWhiteSpace(found)) return (found, dbPath, freshclamPath);

        var envPath = Environment.GetEnvironmentVariable("CLAMAV_PATH");
        found = TryPath(envPath, out dbPath, out freshclamPath);
        if (!string.IsNullOrWhiteSpace(found)) return (found, dbPath, freshclamPath);

        found = TryPath(GetOnPathExecutable("clamscan.exe"), out dbPath, out freshclamPath);
        if (!string.IsNullOrWhiteSpace(found)) return (found, dbPath, freshclamPath);

        found = TryPath(GetOnPathExecutable("clamdscan.exe"), out dbPath, out freshclamPath);
        return (found, dbPath, freshclamPath);
    }

    private static string? GetOnPathExecutable(string name)
    {
        try
        {
            var cmd = new ProcessStartInfo("where", name)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(cmd);
            if (p == null) return null;
            var line = p.StandardOutput.ReadLine();
            p.WaitForExit();
            return (!string.IsNullOrWhiteSpace(line) && File.Exists(line)) ? line.Trim() : null;
        }
        catch
        {
            return null;
        }
    }

    private static IEnumerable<string> ResolveRoots(ScanType type, string? root)
    {
        if (type == ScanType.Custom && !string.IsNullOrWhiteSpace(root) && Directory.Exists(root))
        {
            yield return root;
            yield break;
        }

        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        if (type == ScanType.Quick)
        {
            var quickFolders = new[]
            {
                Environment.SpecialFolder.Desktop,
                Environment.SpecialFolder.MyDocuments,
                Environment.SpecialFolder.LocalApplicationData
            };

            foreach (var folder in quickFolders)
            {
                var path = Environment.GetFolderPath(folder);
                if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
                    yield return path;
            }
        }

        if (type == ScanType.Full)
        {
            var fixedDrives = DriveInfo.GetDrives()
                .Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
                .Select(d => d.RootDirectory.FullName);

            foreach (var drive in fixedDrives)
                yield return drive;
        }
        else
        {
            if (!string.IsNullOrWhiteSpace(root) && Directory.Exists(root))
            {
                yield return root;
            }
            else if (!string.IsNullOrWhiteSpace(userProfile) && Directory.Exists(userProfile))
            {
                yield return userProfile;
            }
        }
    }

    private static async Task<(int ExitCode, string Stdout, string Stderr, string[] Lines)> RunProcessAsync(
        string exePath,
        string arguments,
        CancellationToken ct)
    {
        var psi = new ProcessStartInfo(exePath, arguments)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi) ?? throw new InvalidOperationException($"Failed to start {exePath}");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();

        await Task.WhenAll(stdoutTask, stderrTask).ConfigureAwait(false);
        await process.WaitForExitAsync(ct).ConfigureAwait(false);

        var stdout = stdoutTask.Result ?? string.Empty;
        var stderr = stderrTask.Result ?? string.Empty;
        var lines = stdout.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
        return (process.ExitCode, stdout, stderr, lines);
    }
}
