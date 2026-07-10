using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TGWST.App.ViewModels;

namespace TGWST.App.Services;

public sealed class NetworkResponseService
{
    public Task<string> KillProcessAsync(NetworkConnectionRow row, CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            if (row.ProcessId <= 0)
            {
                throw new InvalidOperationException("No owning process is available for this connection.");
            }

            using var process = Process.GetProcessById(row.ProcessId);
            var target = ResolveProcessTarget(process);
            EnsureProcessCanBeTargeted(row, process, target);
            process.Kill(entireProcessTree: false);
            process.WaitForExit(5000);
            return $"terminated {target.DisplayName} pid={row.ProcessId}";
        }, ct);
    }

    public Task<string> BlockProcessNetworkAsync(NetworkConnectionRow row, CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            if (row.ProcessId <= 0)
            {
                throw new InvalidOperationException("No owning process is available for this connection.");
            }

            using var process = Process.GetProcessById(row.ProcessId);
            var target = ResolveProcessTarget(process);
            EnsureProcessCanBeTargeted(row, process, target);
            var executable = target.ExecutablePath;
            if (string.IsNullOrWhiteSpace(executable) || !File.Exists(executable))
            {
                throw new InvalidOperationException("The process executable path could not be resolved.");
            }

            var ruleId = Guid.NewGuid().ToString("N");
            var encodedPath = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(executable));
            var script = $$"""
$ErrorActionPreference = 'Stop'
$program = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{encodedPath}}'))
$names = @('TGWST-{{ruleId}}-OUT', 'TGWST-{{ruleId}}-IN')
try {
    New-NetFirewallRule -Name $names[0] -DisplayName 'TGWST process containment (outbound)' -Group 'TGWST Managed Response' -Direction Outbound -Action Block -Program $program -Profile Any -Enabled True | Out-Null
    New-NetFirewallRule -Name $names[1] -DisplayName 'TGWST process containment (inbound)' -Group 'TGWST Managed Response' -Direction Inbound -Action Block -Program $program -Profile Any -Enabled True | Out-Null
    $verified = @(Get-NetFirewallRule -Name $names -ErrorAction Stop | Where-Object Enabled -eq 'True')
    if ($verified.Count -ne 2) { throw 'TGWST firewall rule verification failed.' }
}
catch {
    Remove-NetFirewallRule -Name $names -ErrorAction SilentlyContinue
    Write-Error $_
    exit 2
}
""";
            RunElevatedPowerShell(script);
            return $"verified firewall containment for {Path.GetFileName(executable)}; rule id={ruleId}";
        }, ct);
    }

    public Task<string> BlockRemoteAddressAsync(NetworkConnectionRow row, CancellationToken ct = default)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            if (!IPAddress.TryParse(row.RemoteAddress, out var remoteAddress))
            {
                throw new InvalidOperationException("The remote endpoint is not a concrete IP address.");
            }

            var ruleId = Guid.NewGuid().ToString("N");
            var address = remoteAddress.ToString();
            var script = $$"""
$ErrorActionPreference = 'Stop'
$names = @('TGWST-{{ruleId}}-OUT', 'TGWST-{{ruleId}}-IN')
try {
    New-NetFirewallRule -Name $names[0] -DisplayName 'TGWST remote containment (outbound)' -Group 'TGWST Managed Response' -Direction Outbound -Action Block -RemoteAddress '{{address}}' -Profile Any -Enabled True | Out-Null
    New-NetFirewallRule -Name $names[1] -DisplayName 'TGWST remote containment (inbound)' -Group 'TGWST Managed Response' -Direction Inbound -Action Block -RemoteAddress '{{address}}' -Profile Any -Enabled True | Out-Null
    $verified = @(Get-NetFirewallRule -Name $names -ErrorAction Stop | Where-Object Enabled -eq 'True')
    if ($verified.Count -ne 2) { throw 'TGWST firewall rule verification failed.' }
}
catch {
    Remove-NetFirewallRule -Name $names -ErrorAction SilentlyContinue
    Write-Error $_
    exit 2
}
""";
            RunElevatedPowerShell(script);
            return $"verified firewall containment for remote {address}; rule id={ruleId}";
        }, ct);
    }

    private static ProcessTarget ResolveProcessTarget(Process process)
    {
        var displayName = process.ProcessName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? process.ProcessName
            : $"{process.ProcessName}.exe";
        string? executablePath = null;
        DateTimeOffset? startTime = null;

        try
        {
            executablePath = process.MainModule?.FileName;
            startTime = new DateTimeOffset(process.StartTime);
        }
        catch
        {
            // Fail-closed identity validation below prevents targeting unresolved processes.
        }

        return new ProcessTarget(displayName, executablePath, startTime);
    }

    public static bool HasTargetableProcessIdentity(NetworkConnectionRow? row)
    {
        if (row is null || !row.HasProcess || row.ProcessId == Environment.ProcessId)
        {
            return false;
        }

        if (row.ProcessStartTime is null || string.IsNullOrWhiteSpace(row.ExecutablePath))
        {
            return false;
        }

        var displayName = row.Process.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? row.Process
            : $"{row.Process}.exe";
        if (IsProtectedProcessName(displayName) || IsProtectedPath(row.ExecutablePath))
        {
            return false;
        }

        return true;
    }

    private static void EnsureProcessCanBeTargeted(NetworkConnectionRow observed, Process process, ProcessTarget current)
    {
        if (process.Id == Environment.ProcessId)
        {
            throw new InvalidOperationException("TGWST refuses to target its own process.");
        }

        if (observed.ProcessStartTime == null || string.IsNullOrWhiteSpace(observed.ExecutablePath))
        {
            throw new InvalidOperationException("TGWST did not capture enough process identity evidence with this connection. Refresh and inspect it again; PID-only response is refused.");
        }

        if (current.StartTime == null || string.IsNullOrWhiteSpace(current.ExecutablePath))
        {
            throw new InvalidOperationException("The current process identity cannot be resolved safely. TGWST refuses to act on a PID alone.");
        }

        if (Math.Abs((current.StartTime.Value - observed.ProcessStartTime.Value).TotalSeconds) >= 1 ||
            !Path.GetFullPath(current.ExecutablePath).Equals(Path.GetFullPath(observed.ExecutablePath), StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The PID now belongs to a different process identity. Refresh the network view before taking action.");
        }

        if (IsProtectedProcessName(current.DisplayName))
        {
            throw new InvalidOperationException($"TGWST refuses to target protected process {current.DisplayName}.");
        }

        if (IsProtectedPath(current.ExecutablePath))
        {
            throw new InvalidOperationException($"TGWST refuses to target Windows protected path {current.ExecutablePath}.");
        }
    }

    private static bool IsProtectedProcessName(string displayName)
    {
        string[] protectedNames =
        [
            "idle.exe",
            "system.exe",
            "registry.exe",
            "smss.exe",
            "csrss.exe",
            "wininit.exe",
            "services.exe",
            "lsass.exe",
            "svchost.exe",
            "fontdrvhost.exe",
            "dwm.exe",
            "explorer.exe",
            "winlogon.exe",
            "conhost.exe",
            "sihost.exe",
            "taskhostw.exe",
            "wudfhost.exe",
            "wmiprvse.exe",
            "msmpeng.exe",
            "nissrv.exe",
            "securityhealthservice.exe",
            "securityhealthsystray.exe",
            "mpdefendercoreservice.exe",
            "sense.exe",
            "powershell.exe",
            "pwsh.exe"
        ];

        return protectedNames.Contains(displayName, StringComparer.OrdinalIgnoreCase);
    }

    private static bool IsProtectedPath(string? executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            return false;
        }

        var windowsRoot = Environment.GetEnvironmentVariable("WINDIR");
        var systemRoot = Environment.SystemDirectory;
        return IsUnderRoot(executablePath, windowsRoot) || IsUnderRoot(executablePath, systemRoot);
    }

    private static bool IsUnderRoot(string path, string? root)
    {
        if (string.IsNullOrWhiteSpace(root))
        {
            return false;
        }

        var normalizedPath = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var normalizedRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return normalizedPath.Equals(normalizedRoot, StringComparison.OrdinalIgnoreCase) ||
               normalizedPath.StartsWith(normalizedRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
               normalizedPath.StartsWith(normalizedRoot + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static void RunElevatedPowerShell(string script)
    {
        var encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script));
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
            UseShellExecute = true,
            Verb = "runas",
            Arguments = $"-NoLogo -NoProfile -NonInteractive -EncodedCommand {encoded}"
        };

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Unable to launch the firewall response process.");
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"Firewall response returned exit code {process.ExitCode}; partially created rules were removed.");
        }
    }

    private sealed record ProcessTarget(string DisplayName, string? ExecutablePath, DateTimeOffset? StartTime);
}
