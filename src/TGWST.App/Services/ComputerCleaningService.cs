using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using TGWST.App.ViewModels;

namespace TGWST.App.Services;

public sealed class ComputerCleaningService
{
    private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int argumentCount);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);

    public Task<IReadOnlyList<InstalledAppRow>> GetInstalledAppsAsync(string? search, CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            var rows = new List<InstalledAppRow>();
            foreach (var source in GetRegistrySources())
            {
                ct.ThrowIfCancellationRequested();
                rows.AddRange(ReadInstalledApps(source, ct));
            }

            var filtered = rows
                .GroupBy(row => $"{row.Name}|{row.Version}|{row.Publisher}", StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .Where(row => string.IsNullOrWhiteSpace(search) ||
                              row.Name.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                              row.Publisher.Contains(search, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(row => row.Risk == "HIGH")
                .ThenByDescending(row => row.Risk == "MEDIUM")
                .ThenBy(row => row.Name, StringComparer.OrdinalIgnoreCase)
                .Take(800)
                .ToArray();

            return (IReadOnlyList<InstalledAppRow>)filtered;
        }, ct);
    }

    public Task<IReadOnlyList<CleanerResidueRow>> FindResiduesAsync(InstalledAppRow? app, CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            var rows = new List<CleanerResidueRow>();
            if (app != null)
            {
                rows.Add(new CleanerResidueRow(
                    "Registry",
                    app.RegistryKey,
                    "-",
                    "REVIEW",
                    "Primary uninstall registry component. This is identified for audit; it is not automatically deleted because incorrect registry deletion can break repair/uninstall state.",
                    SafeToClean: false));

                foreach (var path in FindAppDataCandidates(app, ct))
                {
                    rows.Add(new CleanerResidueRow(
                        "AppData",
                        path,
                        FormatBytes(MeasurePath(path)),
                        "MEDIUM",
                        "App-specific residue under a user or common application data directory. Cleaning is appropriate after the app is uninstalled or if you intentionally want to reset its local profile data.",
                        SafeToClean: true));
                }

                foreach (var key in FindSoftwareKeyCandidates(app, ct))
                {
                    rows.Add(new CleanerResidueRow(
                        "Registry",
                        key,
                        "-",
                        "REVIEW",
                        "Potential app registry component under Software. Listed for inspection only; export and verify ownership before manual deletion.",
                        SafeToClean: false));
                }
            }

            foreach (var temp in FindTempCandidates(ct))
            {
                rows.Add(temp);
            }

            return (IReadOnlyList<CleanerResidueRow>)rows
                .OrderByDescending(row => row.SafeToClean)
                .ThenByDescending(row => row.Risk == "HIGH")
                .ThenBy(row => row.Kind, StringComparer.OrdinalIgnoreCase)
                .Take(300)
                .ToArray();
        }, ct);
    }

    public Task<IReadOnlyList<CleanerRiskRow>> BuildRiskWarningsAsync(
        IReadOnlyCollection<InstalledAppRow> apps,
        IReadOnlyCollection<CleanerResidueRow> residues,
        CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            var risks = new List<CleanerRiskRow>();
            var userWritableApps = apps
                .Where(app => IsUserWritableInstall(app.InstallLocation))
                .Take(6)
                .ToArray();
            if (userWritableApps.Length > 0)
            {
                risks.Add(new CleanerRiskRow(
                    "HIGH",
                    "User-writable installs",
                    $"{userWritableApps.Length} app(s) appear to run from AppData, Temp, Downloads, or another user-writable location.",
                    "Attackers often place persistence payloads in user-writable paths because standard users can modify them and some allow-list rules trust the parent app name.",
                    "Inspect publisher/path, uninstall unneeded apps, and prefer Program Files installations for software that must stay."));
            }

            var unknownPublisherApps = apps.Count(app => string.IsNullOrWhiteSpace(app.Publisher));
            if (unknownPublisherApps > 0)
            {
                risks.Add(new CleanerRiskRow(
                    "MEDIUM",
                    "Unknown publishers",
                    $"{unknownPublisherApps} installed app record(s) have no publisher metadata.",
                    "Missing publisher data weakens triage because rogue software can blend into normal uninstall inventory without a clear vendor trail.",
                    "Search the app names, inspect install paths, and remove software you do not recognize."));
            }

            var autoCleanBytes = residues
                .Where(row => row.SafeToClean)
                .Select(row => ParseSizeHint(row.Size))
                .Sum();
            if (autoCleanBytes > 0)
            {
                risks.Add(new CleanerRiskRow(
                    "LOW",
                    "Temp and residue buildup",
                    $"{FormatBytes(autoCleanBytes)} of safe cleanup candidates are visible in the current scan.",
                    "Old temp files can leak filenames, installer fragments, scripts, logs, and cached payloads useful to an intruder with local access.",
                    "Use Clean Safe Residue after reviewing the rows. Registry rows remain manual-review only."));
            }

            var reviewRegistryRows = residues.Count(row => row.Kind.Equals("Registry", StringComparison.OrdinalIgnoreCase));
            if (reviewRegistryRows > 0)
            {
                risks.Add(new CleanerRiskRow(
                    "REVIEW",
                    "Registry components",
                    $"{reviewRegistryRows} registry component(s) were identified for the selected app.",
                    "Orphaned Run keys, shell extensions, services, and uninstall keys can preserve persistence or cause failed cleanup after uninstall.",
                    "Review the keys, export backups before manual edits, and avoid deleting keys while the app is still installed."));
            }

            if (risks.Count == 0)
            {
                risks.Add(new CleanerRiskRow(
                    "INFO",
                    "No major cleaner risk",
                    "The current app/residue sample did not produce high-signal cleaner warnings.",
                    "This does not prove the machine is clean; it only means the scanned uninstall inventory and safe residue targets look ordinary.",
                    "Run startup audit, network inspection, and Defender scan for broader coverage."));
            }

            return (IReadOnlyList<CleanerRiskRow>)risks;
        }, ct);
    }

    public Task<string> LaunchUninstallerAsync(InstalledAppRow app, CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            var launch = BuildUninstallLaunch(app);

            var startInfo = new ProcessStartInfo
            {
                FileName = launch.FileName,
                UseShellExecute = false
            };
            foreach (var argument in launch.Arguments)
            {
                startInfo.ArgumentList.Add(argument);
            }

            _ = Process.Start(startInfo) ?? throw new InvalidOperationException("The uninstaller process could not be started.");

            return $"launched uninstaller for {app.Name} directly without a command shell";
        }, ct);
    }

    public Task<(int Deleted, int Failed)> CleanSafeResiduesAsync(
        IEnumerable<CleanerResidueRow> rows,
        CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            var deleted = 0;
            var failed = 0;
            foreach (var row in rows.Where(row => row.SafeToClean))
            {
                ct.ThrowIfCancellationRequested();
                if (!IsSafeCleanupTarget(row.Target))
                {
                    failed++;
                    continue;
                }

                try
                {
                    if (Directory.Exists(row.Target))
                    {
                        Directory.Delete(row.Target, recursive: true);
                        deleted++;
                    }
                    else if (File.Exists(row.Target))
                    {
                        File.Delete(row.Target);
                        deleted++;
                    }
                }
                catch
                {
                    failed++;
                }
            }

            return (deleted, failed);
        }, ct);
    }

    private static IEnumerable<RegistrySource> GetRegistrySources()
    {
        yield return new RegistrySource(RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM64", UninstallPath);
        yield return new RegistrySource(RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM32", UninstallPath);
        yield return new RegistrySource(RegistryHive.CurrentUser, RegistryView.Default, "HKCU", UninstallPath);
    }

    private static IEnumerable<InstalledAppRow> ReadInstalledApps(RegistrySource source, CancellationToken ct)
    {
        using var root = RegistryKey.OpenBaseKey(source.Hive, source.View);
        using var uninstall = root.OpenSubKey(source.Path);
        if (uninstall == null)
        {
            yield break;
        }

        foreach (var subKeyName in uninstall.GetSubKeyNames())
        {
            ct.ThrowIfCancellationRequested();
            using var subKey = uninstall.OpenSubKey(subKeyName);
            if (subKey == null)
            {
                continue;
            }

            var name = ReadString(subKey, "DisplayName");
            if (string.IsNullOrWhiteSpace(name) || ReadInt(subKey, "SystemComponent") == 1)
            {
                continue;
            }

            var version = ReadString(subKey, "DisplayVersion");
            var publisher = ReadString(subKey, "Publisher");
            var installLocation = ReadString(subKey, "InstallLocation");
            var uninstallString = ReadString(subKey, "UninstallString");
            var quietUninstallString = ReadString(subKey, "QuietUninstallString");
            var (risk, concern) = ScoreAppRisk(name, publisher, installLocation, uninstallString);

            yield return new InstalledAppRow(
                Name: name,
                Version: version,
                Publisher: publisher,
                InstallLocation: installLocation,
                UninstallString: uninstallString,
                QuietUninstallString: quietUninstallString,
                RegistryKey: $@"{source.Label}\{source.Path}\{subKeyName}",
                Scope: source.Label,
                Risk: risk,
                Concern: concern);
        }
    }

    private static IEnumerable<string> FindAppDataCandidates(InstalledAppRow app, CancellationToken ct)
    {
        var searchTerms = BuildSearchTerms(app).ToArray();
        foreach (var root in GetDataRoots())
        {
            if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
            {
                continue;
            }

            foreach (var directory in SafeEnumerateDirectories(root).Take(500))
            {
                ct.ThrowIfCancellationRequested();
                var name = Path.GetFileName(directory);
                if (searchTerms.Any(term => name.Contains(term, StringComparison.OrdinalIgnoreCase)))
                {
                    yield return directory;
                }
            }
        }
    }

    private static IEnumerable<string> FindSoftwareKeyCandidates(InstalledAppRow app, CancellationToken ct)
    {
        var searchTerms = BuildSearchTerms(app).ToArray();
        foreach (var rootInfo in new[]
                 {
                     (Hive: RegistryHive.CurrentUser, View: RegistryView.Default, Label: "HKCU", Path: "SOFTWARE"),
                     (Hive: RegistryHive.LocalMachine, View: RegistryView.Registry64, Label: "HKLM64", Path: "SOFTWARE"),
                     (Hive: RegistryHive.LocalMachine, View: RegistryView.Registry32, Label: "HKLM32", Path: "SOFTWARE")
                 })
        {
            using var root = RegistryKey.OpenBaseKey(rootInfo.Hive, rootInfo.View);
            using var software = root.OpenSubKey(rootInfo.Path);
            if (software == null)
            {
                continue;
            }

            foreach (var subKeyName in software.GetSubKeyNames().Take(1000))
            {
                ct.ThrowIfCancellationRequested();
                if (searchTerms.Any(term => subKeyName.Contains(term, StringComparison.OrdinalIgnoreCase)))
                {
                    yield return $@"{rootInfo.Label}\{rootInfo.Path}\{subKeyName}";
                }
            }
        }
    }

    private static IEnumerable<CleanerResidueRow> FindTempCandidates(CancellationToken ct)
    {
        var temp = Path.GetTempPath();
        if (!Directory.Exists(temp))
        {
            yield break;
        }

        foreach (var path in SafeEnumerateFileSystemEntries(temp).Take(350))
        {
            ct.ThrowIfCancellationRequested();
            var age = GetLastWriteAge(path);
            if (age < TimeSpan.FromDays(7))
            {
                continue;
            }

            yield return new CleanerResidueRow(
                "Temp",
                path,
                FormatBytes(MeasurePath(path)),
                "LOW",
                $"Temporary item has not changed for {age.TotalDays:0} day(s). Safe cleanup removes stale installer/cache material but skips anything locked by the OS.",
                SafeToClean: true);
        }
    }

    private static IEnumerable<string> BuildSearchTerms(InstalledAppRow app)
    {
        foreach (var value in new[] { app.Name, app.Publisher })
        {
            var cleaned = CleanTerm(value);
            if (cleaned.Length >= 3)
            {
                yield return cleaned;
            }
        }
    }

    private static string CleanTerm(string value)
    {
        var chars = value.Where(char.IsLetterOrDigit).Take(32).ToArray();
        return new string(chars);
    }

    private static IEnumerable<string> GetDataRoots()
    {
        yield return Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        yield return Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        yield return Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
    }

    private static (string Risk, string Concern) ScoreAppRisk(
        string name,
        string publisher,
        string installLocation,
        string uninstallString)
    {
        if (IsUserWritableInstall(installLocation))
        {
            return ("HIGH", "Install path is user-writable or commonly abused for persistence. Verify this app is expected before trusting it.");
        }

        if (string.IsNullOrWhiteSpace(publisher))
        {
            return ("MEDIUM", "Publisher metadata is missing. That does not make the app malicious, but it weakens provenance checks.");
        }

        if (string.IsNullOrWhiteSpace(uninstallString))
        {
            return ("REVIEW", "No uninstall command is exposed in the standard registry inventory.");
        }

        if (name.Contains("remote", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("admin", StringComparison.OrdinalIgnoreCase))
        {
            return ("REVIEW", "Remote/admin software can be legitimate, but it should be intentionally installed and access-controlled.");
        }

        return ("LOW", "Standard uninstall metadata is present. Review only if you do not recognize the app.");
    }

    private static bool IsUserWritableInstall(string installLocation)
    {
        if (string.IsNullOrWhiteSpace(installLocation))
        {
            return false;
        }

        var path = installLocation.Trim().ToLowerInvariant();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile).ToLowerInvariant();
        return path.Contains(@"\appdata\", StringComparison.OrdinalIgnoreCase) ||
               path.Contains(@"\temp\", StringComparison.OrdinalIgnoreCase) ||
               path.Contains(@"\downloads\", StringComparison.OrdinalIgnoreCase) ||
               (!string.IsNullOrWhiteSpace(userProfile) && path.StartsWith(userProfile, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsSafeCleanupTarget(string target)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            return false;
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(target);
        }
        catch
        {
            return false;
        }

        var roots = GetDataRoots()
            .Append(Path.GetTempPath())
            .Where(root => !string.IsNullOrWhiteSpace(root))
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase);

        foreach (var root in roots)
        {
            var relative = Path.GetRelativePath(root, fullPath);
            if (relative.Equals(".", StringComparison.Ordinal) ||
                Path.IsPathRooted(relative) ||
                relative.Equals("..", StringComparison.Ordinal) ||
                relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            {
                continue;
            }

            if (ContainsReparsePoint(root, fullPath))
            {
                return false;
            }

            return true;
        }

        return false;
    }

    private static bool ContainsReparsePoint(string root, string target)
    {
        try
        {
            var current = target;
            while (!current.Equals(root, StringComparison.OrdinalIgnoreCase))
            {
                if (File.Exists(current) || Directory.Exists(current))
                {
                    var attributes = File.GetAttributes(current);
                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        return true;
                    }
                }

                current = Path.GetDirectoryName(current) ?? string.Empty;
                if (string.IsNullOrWhiteSpace(current))
                {
                    return true;
                }
            }

            if (!Directory.Exists(target))
            {
                return false;
            }

            var pending = new Stack<string>();
            pending.Push(target);
            while (pending.Count > 0)
            {
                var directory = pending.Pop();
                foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
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

    private static IEnumerable<string> SafeEnumerateDirectories(string path)
    {
        try
        {
            return Directory.EnumerateDirectories(path);
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static IEnumerable<string> SafeEnumerateFileSystemEntries(string path)
    {
        try
        {
            return Directory.EnumerateFileSystemEntries(path);
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static TimeSpan GetLastWriteAge(string path)
    {
        try
        {
            var timestamp = Directory.Exists(path)
                ? Directory.GetLastWriteTimeUtc(path)
                : File.GetLastWriteTimeUtc(path);
            return DateTime.UtcNow - timestamp;
        }
        catch
        {
            return TimeSpan.Zero;
        }
    }

    private static long MeasurePath(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                return new FileInfo(path).Length;
            }

            if (!Directory.Exists(path))
            {
                return 0;
            }

            long total = 0;
            var count = 0;
            foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
            {
                if (++count > 4000)
                {
                    break;
                }

                try
                {
                    total += new FileInfo(file).Length;
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

    private static long ParseSizeHint(string size)
    {
        var parts = size.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2 || !double.TryParse(parts[0], out var value))
        {
            return 0;
        }

        var multiplier = parts[1] switch
        {
            "KB" => 1024L,
            "MB" => 1024L * 1024,
            "GB" => 1024L * 1024 * 1024,
            _ => 1L
        };

        return (long)(value * multiplier);
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB"];
        var value = (double)Math.Max(0, bytes);
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value:0.##} {units[unit]}";
    }

    internal static UninstallLaunch BuildUninstallLaunch(InstalledAppRow app)
    {
        var command = string.IsNullOrWhiteSpace(app.UninstallString)
            ? app.QuietUninstallString
            : app.UninstallString;

        if (string.IsNullOrWhiteSpace(command))
        {
            throw new InvalidOperationException("Selected app does not expose an uninstall command.");
        }

        var arguments = ParseCommandLine(command);
        if (arguments.Count == 0)
        {
            throw new InvalidOperationException("The uninstall command could not be parsed safely.");
        }

        var executable = Environment.ExpandEnvironmentVariables(arguments[0]);
        if (IsWindowsInstaller(executable))
        {
            var productCode = ExtractMsiProductCode(arguments.Skip(1));
            if (productCode == null)
            {
                throw new InvalidOperationException("TGWST only launches Windows Installer uninstall entries that contain one explicit MSI product code.");
            }

            return new UninstallLaunch(
                Path.Combine(Environment.SystemDirectory, "msiexec.exe"),
                ["/X", productCode]);
        }

        if (!Path.IsPathFullyQualified(executable) ||
            !Path.GetExtension(executable).Equals(".exe", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("TGWST refuses an uninstall entry that is not an explicit, fully qualified executable path.");
        }

        var fullPath = Path.GetFullPath(executable);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("The registered uninstaller executable does not exist.", fullPath);
        }

        if (IsCommandHost(fullPath))
        {
            throw new InvalidOperationException("TGWST refuses uninstall metadata that launches a shell, script host, or living-off-the-land command interpreter.");
        }

        return new UninstallLaunch(fullPath, arguments.Skip(1).ToArray());
    }

    private static IReadOnlyList<string> ParseCommandLine(string commandLine)
    {
        var pointer = CommandLineToArgvW(commandLine, out var argumentCount);
        if (pointer == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Windows could not parse the uninstall command line.");
        }

        try
        {
            var arguments = new string[argumentCount];
            for (var index = 0; index < argumentCount; index++)
            {
                var argumentPointer = Marshal.ReadIntPtr(pointer, index * IntPtr.Size);
                arguments[index] = Marshal.PtrToStringUni(argumentPointer) ?? string.Empty;
            }

            return arguments;
        }
        finally
        {
            _ = LocalFree(pointer);
        }
    }

    private static bool IsWindowsInstaller(string executable)
    {
        return Path.GetFileName(executable).Equals("msiexec", StringComparison.OrdinalIgnoreCase) ||
               Path.GetFileName(executable).Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsCommandHost(string executable)
    {
        string[] deniedNames =
        [
            "cmd.exe",
            "powershell.exe",
            "pwsh.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "rundll32.exe",
            "regsvr32.exe"
        ];

        return deniedNames.Contains(Path.GetFileName(executable), StringComparer.OrdinalIgnoreCase);
    }

    private static string? ExtractMsiProductCode(IEnumerable<string> arguments)
    {
        var text = string.Join(' ', arguments);
        var matches = Regex.Matches(
            text,
            @"(?i)(?<![0-9a-f])\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}(?![0-9a-f])");

        return matches.Count == 1 ? matches[0].Value : null;
    }

    private static string ReadString(RegistryKey key, string name)
    {
        return key.GetValue(name)?.ToString() ?? string.Empty;
    }

    private static int ReadInt(RegistryKey key, string name)
    {
        return key.GetValue(name) is int value ? value : 0;
    }

    private sealed record RegistrySource(RegistryHive Hive, RegistryView View, string Label, string Path);

    internal sealed record UninstallLaunch(string FileName, IReadOnlyList<string> Arguments);
}
