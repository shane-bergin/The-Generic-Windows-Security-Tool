using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace TGWST.Core.Uninstall;

public sealed class UninstallEngine
{
public IReadOnlyList<InstalledApp> ListInstalled()
{
var apps = new List<InstalledApp>();

    void ScanRoot(RegistryKey root, string subkey)
    {
        using var key = root.OpenSubKey(subkey);
        if (key == null) return;

        foreach (var name in key.GetSubKeyNames())
        {
            using var appKey = key.OpenSubKey(name);
            if (appKey == null) continue;

            var displayName = appKey.GetValue("DisplayName") as string;
            var uninstallString = appKey.GetValue("UninstallString") as string;

            if (string.IsNullOrWhiteSpace(displayName) || string.IsNullOrWhiteSpace(uninstallString))
                continue;

            apps.Add(new InstalledApp
            {
                DisplayName = displayName,
                Publisher = appKey.GetValue("Publisher") as string ?? "",
                UninstallString = uninstallString,
                ProductCode = appKey.GetValue("ProductCode") as string
            });
        }
    }

    ScanRoot(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
    ScanRoot(Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall");
    ScanRoot(Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");

    return apps
        .OrderBy(a => a.DisplayName, StringComparer.OrdinalIgnoreCase)
        .ToList();
}

public Task RunUninstallerAsync(InstalledApp app, bool quiet = true, CancellationToken ct = default)
{
    var (fileName, arguments, isMsiexec) = ParseCommandLine(app.UninstallString);
    if (string.IsNullOrWhiteSpace(fileName))
        throw new InvalidOperationException($"Invalid uninstall command for {app.DisplayName}.");

    if (isMsiexec)
    {
        if (quiet && !ContainsMsiQuiet(arguments))
            arguments = string.IsNullOrWhiteSpace(arguments) ? "/quiet" : arguments + " /quiet";
    }
    else if (quiet && !arguments.Contains("/S", StringComparison.OrdinalIgnoreCase))
    {
        arguments = string.IsNullOrWhiteSpace(arguments) ? "/S" : arguments + " /S";
    }

    var psi = new ProcessStartInfo
    {
        FileName = fileName,
        Arguments = arguments,
        UseShellExecute = false
    };

    var p = Process.Start(psi);
    if (p == null) return Task.CompletedTask;
    return p.WaitForExitAsync(ct);
}

private static (string fileName, string arguments, bool isMsiexec) ParseCommandLine(string? commandLine)
{
    var trimmed = (commandLine ?? string.Empty).Trim();
    if (trimmed.Length == 0)
        return ("", "", false);

    string fileName;
    string arguments;

    if (trimmed.StartsWith("\"", StringComparison.Ordinal))
    {
        var closingQuote = trimmed.IndexOf('"', 1);
        if (closingQuote > 1)
        {
            fileName = trimmed.Substring(1, closingQuote - 1);
            arguments = trimmed[(closingQuote + 1)..].Trim();
        }
        else
        {
            fileName = trimmed.Trim('"');
            arguments = "";
        }
    }
    else
    {
        var firstSpace = trimmed.IndexOf(' ');
        if (firstSpace > 0)
        {
            fileName = trimmed[..firstSpace];
            arguments = trimmed[(firstSpace + 1)..].Trim();
        }
        else
        {
            fileName = trimmed;
            arguments = "";
        }
    }

    var isMsiexec = Path.GetFileNameWithoutExtension(fileName)
        .Equals("msiexec", StringComparison.OrdinalIgnoreCase);
    if (isMsiexec)
        fileName = "msiexec.exe";

    return (fileName, arguments, isMsiexec);
}

private static bool ContainsMsiQuiet(string arguments) =>
    arguments.Contains("/quiet", StringComparison.OrdinalIgnoreCase) ||
    arguments.Contains("/qn", StringComparison.OrdinalIgnoreCase);

public async Task<IReadOnlyList<LeftoverItem>> FindLeftoversAsync(
    InstalledApp app,
    CancellationToken ct = default)
{
    var leftovers = new List<LeftoverItem>();

    var nameTokens = Tokenize(app.DisplayName);
    var publisherTokens = Tokenize(app.Publisher);

    leftovers.AddRange(FindFilesystemLeftovers(app, nameTokens, publisherTokens));
    leftovers.AddRange(FindRegistryLeftovers(app, nameTokens, publisherTokens));

    await Task.CompletedTask;
    return leftovers;
}

public async Task RemoveLeftoversAsync(
    IEnumerable<LeftoverItem> items,
    CancellationToken ct = default)
{
    foreach (var item in items)
    {
        ct.ThrowIfCancellationRequested();

        try
        {
            switch (item.Type)
            {
                case LeftoverType.File:
                    if (File.Exists(item.Path))
                        File.Delete(item.Path);
                    break;

                case LeftoverType.Directory:
                    if (Directory.Exists(item.Path))
                        Directory.Delete(item.Path, recursive: true);
                    break;

                case LeftoverType.RegistryKey:
                    DeleteRegistryKeyRecursive(item.Path);
                    break;

                case LeftoverType.RegistryValue:
                    DeleteRegistryValue(item.Path, item.ValueName);
                    break;
            }
        }
        catch
        {
            // ignore; best-effort
        }
    }

    await Task.CompletedTask;
}

private static IReadOnlyList<string> Tokenize(string text)
{
    if (string.IsNullOrWhiteSpace(text)) return Array.Empty<string>();

    return text
        .Split(new[] { ' ', '\t', '-', '_', '.', ',' }, StringSplitOptions.RemoveEmptyEntries)
        .Select(t => t.Trim().ToLowerInvariant())
        .Where(t => t.Length >= 3)
        .Distinct()
        .ToArray();
}

private static bool MatchesTokens(string candidate, IReadOnlyList<string> tokens)
{
    if (tokens.Count == 0) return false;

    foreach (var token in tokens)
    {
        if (candidate.Contains(token, StringComparison.OrdinalIgnoreCase))
            return true;
    }

    return false;
}

private static IEnumerable<LeftoverItem> FindFilesystemLeftovers(
    InstalledApp app,
    IReadOnlyList<string> nameTokens,
    IReadOnlyList<string> publisherTokens)
{
    var results = new List<LeftoverItem>();

    var roots = new[]
    {
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
    }
    .Where(p => !string.IsNullOrWhiteSpace(p))
    .Distinct(StringComparer.OrdinalIgnoreCase)
    .ToArray();

    foreach (var root in roots)
    {
        if (!Directory.Exists(root)) continue;

        foreach (var dir in Directory.GetDirectories(root))
        {
            var dirName = Path.GetFileName(dir).ToLowerInvariant();
            if (MatchesTokens(dirName, nameTokens) || MatchesTokens(dirName, publisherTokens))
            {
                results.Add(new LeftoverItem
                {
                    Type = LeftoverType.Directory,
                    Path = dir,
                    Reason = $"Directory name resembles '{app.DisplayName}' or publisher '{app.Publisher}'"
                });
            }
        }
    }

    return results;
}

private static IEnumerable<LeftoverItem> FindRegistryLeftovers(
    InstalledApp app,
    IReadOnlyList<string> nameTokens,
    IReadOnlyList<string> publisherTokens)
{
    var results = new List<LeftoverItem>();

    void ScanHive(RegistryKey hive, string rootPath)
    {
        using var root = hive.OpenSubKey(rootPath);
        if (root == null) return;

        foreach (var sub in root.GetSubKeyNames())
        {
            using var sk = root.OpenSubKey(sub);
            if (sk == null) continue;

            var fullPath = $"{root.Name}\\{rootPath}\\{sub}";
            var pathLower = fullPath.ToLowerInvariant();

            if (MatchesTokens(pathLower, nameTokens) || MatchesTokens(pathLower, publisherTokens))
            {
                results.Add(new LeftoverItem
                {
                    Type = LeftoverType.RegistryKey,
                    Path = fullPath,
                    Reason = $"Registry key path resembles '{app.DisplayName}' or publisher '{app.Publisher}'"
                });
                continue;
            }

            foreach (var valueName in sk.GetValueNames())
            {
                var val = sk.GetValue(valueName)?.ToString() ?? "";
                var combined = (valueName + " " + val).ToLowerInvariant();

                if (MatchesTokens(combined, nameTokens) || MatchesTokens(combined, publisherTokens))
                {
                    results.Add(new LeftoverItem
                    {
                        Type = LeftoverType.RegistryValue,
                        Path = fullPath,
                        ValueName = valueName,
                        Reason = $"Registry value resembles '{app.DisplayName}' or publisher '{app.Publisher}'"
                    });
                }
            }
        }
    }

    ScanHive(Registry.LocalMachine, @"SOFTWARE");
    ScanHive(Registry.LocalMachine, @"SOFTWARE\WOW6432Node");
    ScanHive(Registry.CurrentUser, @"SOFTWARE");

    return results;
}

private static void DeleteRegistryKeyRecursive(string fullPath)
{
    var firstSlash = fullPath.IndexOf('\\');
    if (firstSlash <= 0) return;

    var hiveName = fullPath[..firstSlash];
    var subPath = fullPath[(firstSlash + 1)..];

    RegistryKey? hive = hiveName.ToUpperInvariant() switch
    {
        "HKEY_LOCAL_MACHINE" => Registry.LocalMachine,
        "HKEY_CURRENT_USER"  => Registry.CurrentUser,
        "HKEY_CLASSES_ROOT"  => Registry.ClassesRoot,
        "HKEY_USERS"         => Registry.Users,
        "HKEY_CURRENT_CONFIG"=> Registry.CurrentConfig,
        _ => null
    };

    hive?.DeleteSubKeyTree(subPath, throwOnMissingSubKey: false);
}

private static void DeleteRegistryValue(string fullPath, string? valueName)
{
    if (string.IsNullOrWhiteSpace(valueName)) return;

    var firstSlash = fullPath.IndexOf('\\');
    if (firstSlash <= 0) return;

    var hiveName = fullPath[..firstSlash];
    var subPath = fullPath[(firstSlash + 1)..];

    RegistryKey? hive = hiveName.ToUpperInvariant() switch
    {
        "HKEY_LOCAL_MACHINE" => Registry.LocalMachine,
        "HKEY_CURRENT_USER"  => Registry.CurrentUser,
        "HKEY_CLASSES_ROOT"  => Registry.ClassesRoot,
        "HKEY_USERS"         => Registry.Users,
        "HKEY_CURRENT_CONFIG"=> Registry.CurrentConfig,
        _ => null
    };

    if (hive == null) return;

    using var key = hive.OpenSubKey(subPath, writable: true);
    key?.DeleteValue(valueName, throwOnMissingValue: false);
}


}
