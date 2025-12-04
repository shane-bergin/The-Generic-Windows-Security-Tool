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
private readonly LeftoverEngine _leftoverEngine = new();
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
    return await _leftoverEngine.FindAsync(app, ct);
}

public async Task RemoveLeftoversAsync(
    IEnumerable<LeftoverItem> items,
    CancellationToken ct = default)
{
    await _leftoverEngine.RemoveAsync(items, ct);
}
}
