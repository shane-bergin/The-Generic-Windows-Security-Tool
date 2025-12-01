using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.Core.Scan;

public sealed class ClamEngine
{
    private const string DefaultClamDir = @"C:\ProgramData\TGWST\ClamAV";
    private const string ClamZipSha256 = "2644A778016D3B4F64CBB0B5B4D8D1236E6F65813329FD93ECDD57D968F85D0";
    private readonly string _clamDir;
    private readonly string _clamExe;
    private readonly string _freshExe;
    private readonly string _dbDir;
    private static readonly string ClamZipUrl = "https://www.clamav.net/downloads/production/clamav-1.5.1.win.x64.zip";

    public ClamEngine()
    {
        _clamDir = ResolveClamDirectory();
        _clamExe = Path.Combine(_clamDir, "clamscan.exe");
        _freshExe = Path.Combine(_clamDir, "freshclam.exe");
        _dbDir = Path.Combine(_clamDir, "db");
    }

    public async Task<bool> EnsureInstalledAsync(IProgress<string>? log = null, CancellationToken ct = default)
    {
        var present = File.Exists(_clamExe) && File.Exists(_freshExe);
        if (present) return true;

        try
        {
            Directory.CreateDirectory(_clamDir);
            HardenDirectory(_clamDir);
            var zipPath = Path.Combine(_clamDir, "clamav.zip");

            var packaged = GetPackagedZipPath();
            if (!string.IsNullOrWhiteSpace(packaged) && File.Exists(packaged))
            {
                log?.Report("Found bundled ClamAV package, using local copy...");
                File.Copy(packaged, zipPath, overwrite: true);
            }
            else
            {
                using var http = new HttpClient();
                log?.Report("Downloading ClamAV package...");
                var bytes = await http.GetByteArrayAsync(ClamZipUrl, ct);
                await File.WriteAllBytesAsync(zipPath, bytes, ct);
            }

            log?.Report("Verifying ClamAV package checksum...");
            using (var sha = SHA256.Create())
            await using (var stream = File.OpenRead(zipPath))
            {
                var hash = Convert.ToHexString(sha.ComputeHash(stream));
                if (!hash.Equals(ClamZipSha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("ClamAV package failed integrity check.");
            }

            log?.Report("Extracting ClamAV...");
            ZipFile.ExtractToDirectory(zipPath, _clamDir, overwriteFiles: true);
            File.Delete(zipPath);
            HardenDirectory(_clamDir);
        }
        catch
        {
            return false;
        }

        return File.Exists(_clamExe) && File.Exists(_freshExe);
    }

    public async Task<IReadOnlyList<ScanResult>> RunClamScanAsync(string root, IProgress<string>? log = null, CancellationToken ct = default)
    {
        var installed = await EnsureInstalledAsync(log, ct);
        if (!installed)
        {
            return new[]
            {
                new ScanResult
                {
                    Path = "ClamAV",
                    Suspicious = false,
                    Reason = $"ClamAV binaries not found in '{_clamDir}'. Install ClamAV and set CLAMAV_HOME to skip runtime downloads.",
                    Engine = "ClamAV"
                }
            };
        }

        Directory.CreateDirectory(_dbDir);
        HardenDirectory(_dbDir);

        var updatePsi = new ProcessStartInfo
        {
            FileName = _freshExe,
            Arguments = $"--datadir=\"{_dbDir}\" --quiet",
            UseShellExecute = false,
            CreateNoWindow = true
        };
        log?.Report("Updating ClamAV definitions (freshclam)...");
        using (var updateP = Process.Start(updatePsi))
        {
            if (updateP != null)
                await updateP.WaitForExitAsync(ct);
        }

        var psi = new ProcessStartInfo
        {
            FileName = _clamExe,
            Arguments = $"--database=\"{_dbDir}\" -r \"{root}\" --no-summary --infected",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        };
        log?.Report("Running ClamAV scan...");
        using var p = Process.Start(psi);
        var output = p == null ? "" : await p.StandardOutput.ReadToEndAsync();
        if (p != null)
            await p.WaitForExitAsync(ct);

        var hits = output.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Where(line => line.Contains(": ") && line.Contains(" FOUND", StringComparison.OrdinalIgnoreCase))
            .Select(line =>
            {
                var parts = line.Split(':');
                var reason = parts.Length > 1 ? parts[1].Trim() : "Detected";
                return new ScanResult
                {
                    Path = parts[0].Trim(),
                    Suspicious = true,
                    Reason = reason,
                    Engine = "ClamAV"
                };
            }).ToArray();

        return hits;
    }

    private static void HardenDirectory(string path)
    {
        try
        {
            var dir = new DirectoryInfo(path);
            if (!dir.Exists) dir.Create();
            var security = dir.GetAccessControl();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            security.SetAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            security.SetAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));

            dir.SetAccessControl(security);
        }
        catch
        {
            // best-effort hardening
        }
    }

    private static string ResolveClamDirectory()
    {
        var envDir = Environment.GetEnvironmentVariable("CLAMAV_HOME");
        if (!string.IsNullOrWhiteSpace(envDir))
            return envDir;

        var programFilesDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "ClamAV");
        if (Directory.Exists(programFilesDir))
            return programFilesDir;

        return DefaultClamDir;
    }

    private static string? GetPackagedZipPath()
    {
        var baseDir = AppContext.BaseDirectory;
        var candidate1 = Path.Combine(baseDir, "clamav-1.5.1.win.x64.zip");
        if (File.Exists(candidate1)) return candidate1;

        var candidate2 = Path.Combine(baseDir, "Assets", "clamav-1.5.1.win.x64.zip");
        if (File.Exists(candidate2)) return candidate2;

        return null;
    }
}
