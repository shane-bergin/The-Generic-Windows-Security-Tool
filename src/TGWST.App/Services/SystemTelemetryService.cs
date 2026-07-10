using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using TGWST.App.ViewModels;
using TGWST.Core.Native;

namespace TGWST.App.Services;

public sealed class SystemTelemetryService : IDisposable
{
    private readonly GuiLogService _log;
    private readonly SuspendedProcessDetector _suspendedProcessDetector;
    private readonly CancellationTokenSource _cts = new();
    private readonly List<ManagementEventWatcher> _watchers = new();
    private readonly List<FileSystemWatcher> _fileWatchers = new();
    private bool _started;
    private bool _disposed;

    public event EventHandler<TelemetryEventRow>? EventObserved;

    public SystemTelemetryService(GuiLogService log, SuspendedProcessDetector suspendedProcessDetector)
    {
        _log = log;
        _suspendedProcessDetector = suspendedProcessDetector;
    }

    public void Start()
    {
        if (_started || _disposed)
        {
            return;
        }

        _started = true;
        StartProcessWatcher();
        StartRegistryWatchers();
        StartFileWatchers();
        _log.Success(
            "Telemetry",
            "active discovery started",
            "Watching WMI process starts, Run-key registry changes, Startup folder changes, and suspended-thread starts.",
            "This creates high-signal telemetry without continuously scanning the whole disk.",
            "Use the Telemetry tab for live detail and Logs for retained warning/critical pivots.",
            "Event Viewer",
            "eventvwr.msc");
    }

    private void StartProcessWatcher()
    {
        try
        {
            var watcher = new ManagementEventWatcher(
                new ManagementScope(@"\\.\root\CIMV2"),
                new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));

            watcher.EventArrived += (_, args) =>
            {
                var processName = Convert.ToString(args.NewEvent.Properties["ProcessName"]?.Value) ?? "process";
                var processId = Convert.ToString(args.NewEvent.Properties["ProcessID"]?.Value) ?? "-";
                var parentProcessId = Convert.ToString(args.NewEvent.Properties["ParentProcessID"]?.Value) ?? string.Empty;
                var numericProcessId = TryParseInt(processId);
                var numericParentProcessId = TryParseInt(parentProcessId);
                var context = numericProcessId.HasValue
                    ? TryReadProcessContext(numericProcessId.Value)
                    : ProcessContext.Empty;
                var parentName = numericParentProcessId.HasValue
                    ? TryGetProcessName(numericParentProcessId.Value)
                    : string.Empty;
                var startedByTgwst = numericParentProcessId == Environment.ProcessId;
                var severity = ClassifyProcessStart(
                    processName,
                    context.CommandLine,
                    startedByTgwst,
                    out var impact,
                    out var recommendedAction);

                // High-signal Defender service parent anomaly: Defender should not normally spawn interactive shells.
                if (IsDefenderParentAnomaly(processName, numericParentProcessId, numericProcessId))
                {
                    severity = CyberSeverity.Warning;
                    impact = "Heuristic: WMI reported a shell-like child and a parent PID that currently resolves to MsMpEng at high integrity. PID exit/reuse can make this ancestry evidence stale.";
                    recommendedAction = "Capture the process path, signer, creation time, command line, and independent process-start logs. Do not terminate it from this heuristic alone.";
                }
                var detail = BuildProcessDetail(processName, processId, parentProcessId, parentName, context);

                Publish(
                    severity,
                    "Process",
                    "start",
                    processName,
                    detail,
                    numericProcessId,
                    numericParentProcessId,
                    parentName,
                    impact,
                    recommendedAction,
                    "Task Manager",
                    "taskmgr.exe");

                if (numericProcessId.HasValue)
                {
                    _ = InspectSuspendedProcessStartAsync(numericProcessId.Value, processName, _cts.Token);
                }
            };
            watcher.Start();
            _watchers.Add(watcher);
        }
        catch (Exception ex)
        {
            _log.Warning("Telemetry", $"process watcher unavailable: {TrimError(ex.Message)}");
        }
    }

    private void StartRegistryWatchers()
    {
        var keys = new List<(string Hive, string RootPath, string DisplayPath)>
        {
            (
                "HKEY_LOCAL_MACHINE",
                @"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
        };

        var currentUserSid = TryGetCurrentUserSid();
        if (!string.IsNullOrWhiteSpace(currentUserSid))
        {
            keys.Add((
                "HKEY_USERS",
                $@"{currentUserSid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"));
        }

        foreach (var (hive, rootPath, displayPath) in keys)
        {
            try
            {
                var query = $"SELECT * FROM RegistryTreeChangeEvent WHERE Hive='{hive}' AND RootPath='{rootPath}'";
                var watcher = new ManagementEventWatcher(
                    new ManagementScope(@"\\.\root\default"),
                    new WqlEventQuery(query));

                watcher.EventArrived += (_, _) =>
                    Publish(
                        CyberSeverity.Warning,
                        "Registry",
                        "startup key changed",
                        displayPath,
                        displayPath,
                        null,
                        null,
                        string.Empty,
                        "A Run-key changed. This can be normal software setup, but it is also a common persistence location.",
                        "Open Startup Audit or inspect the Run key before trusting the change.",
                        "Registry Editor",
                        "regedit.exe");
                watcher.Start();
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _log.Warning("Telemetry", $"registry watcher unavailable: {TrimError(ex.Message)}");
            }
        }
    }

    private static string TryGetCurrentUserSid()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.User?.Value ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private void StartFileWatchers()
    {
        var roots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "Startup")
            }
            .Where(path => !string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        foreach (var root in roots)
        {
            try
            {
                var watcher = new FileSystemWatcher(root)
                {
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime,
                    EnableRaisingEvents = true
                };

                watcher.Created += (_, args) => PublishStartupFileEvent(CyberSeverity.Warning, "startup file created", args.FullPath);
                watcher.Changed += (_, args) => PublishStartupFileEvent(CyberSeverity.Info, "startup file changed", args.FullPath);
                watcher.Deleted += (_, args) => PublishStartupFileEvent(CyberSeverity.Warning, "startup file deleted", args.FullPath);
                watcher.Renamed += (_, args) => PublishStartupFileEvent(CyberSeverity.Warning, "startup file renamed", args.FullPath);
                _fileWatchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _log.Warning("Telemetry", $"file watcher unavailable: {TrimError(ex.Message)}");
            }
        }
    }

    private void PublishStartupFileEvent(CyberSeverity severity, string signal, string fullPath)
    {
        Publish(
            severity,
            "File",
            signal,
            Path.GetFileName(fullPath),
            fullPath,
            null,
            null,
            string.Empty,
            "The Startup folder changed. Items here can auto-launch at sign-in.",
            "Open the startup folder and verify the file owner before trusting it.",
            "Open folder",
            Path.GetDirectoryName(fullPath) ?? "shell:startup");
    }

    private void Publish(
        CyberSeverity severity,
        string source,
        string signal,
        string subject,
        string detail,
        int? processId = null,
        int? parentProcessId = null,
        string parentProcess = "",
        string impact = "",
        string recommendedAction = "",
        string linkLabel = "",
        string linkTarget = "")
    {
        var row = new TelemetryEventRow(
            DateTimeOffset.Now,
            severity,
            source,
            signal,
            string.IsNullOrWhiteSpace(subject) ? "-" : subject,
            string.IsNullOrWhiteSpace(detail) ? "-" : detail,
            processId,
            parentProcessId,
            parentProcess,
            impact,
            recommendedAction,
            linkLabel,
            linkTarget);

        EventObserved?.Invoke(this, row);

        if (severity == CyberSeverity.Critical)
        {
            _log.Critical(
                "Telemetry",
                $"{source} {signal}: {subject}",
                detail,
                impact,
                recommendedAction,
                linkLabel,
                linkTarget);
        }
        else if (severity == CyberSeverity.Warning)
        {
            _log.Warning(
                "Telemetry",
                $"{source} {signal}: {subject}",
                detail,
                impact,
                recommendedAction,
                linkLabel,
                linkTarget);
        }
    }

    private async Task InspectSuspendedProcessStartAsync(int processId, string processName, CancellationToken ct)
    {
        try
        {
            var inspection = await _suspendedProcessDetector
                .InspectRecentStartAsync(processId, processName, ct)
                .ConfigureAwait(false);

            if (inspection?.SuspendedThreadCount > 0)
            {
                var isCommonWindowsHost = IsCommonWindowsSuspendedHost(inspection.ProcessName);
                Publish(
                    isCommonWindowsHost ? CyberSeverity.Info : CyberSeverity.Warning,
                    "Process",
                    "suspended start",
                    inspection.ProcessName,
                    $"pid={inspection.ProcessId} suspended_threads={inspection.SuspendedThreadCount}/{inspection.ThreadCount}",
                    inspection.ProcessId,
                    null,
                    string.Empty,
                    isCommonWindowsHost
                        ? "A common Windows shell/AppContainer host briefly retained suspended threads after launch."
                        : "A new process retained suspended threads after launch. This can be benign, but it is also seen in injection and staging patterns.",
                    isCommonWindowsHost
                        ? "No action needed unless the parent process or executable path is unexpected."
                        : "Review process start time, path, signer, parent, and whether suspension persists. Treat this as low-confidence evidence until corroborated.",
                    "Task Manager",
                    "taskmgr.exe");
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            _log.Warning("Telemetry", $"suspended process inspection failed: {TrimError(ex.Message)}");
        }
    }

    private static CyberSeverity ClassifyProcessStart(
        string processName,
        string commandLine,
        bool startedByTgwst,
        out string impact,
        out string recommendedAction)
    {
        var normalizedName = processName.Trim();
        var normalizedCommand = commandLine ?? string.Empty;
        var lower = normalizedCommand.ToLowerInvariant();

        impact = "Process started. Baseline system activity if parent, path, and command line are expected.";
        recommendedAction = "No action needed unless the parent process or command line is unexpected.";

        if (startedByTgwst)
        {
            impact = "TGWST launched this helper process for a requested scan, posture check, or response action.";
            recommendedAction = "No action needed unless the action was not user initiated.";
            return CyberSeverity.Info;
        }

        if (normalizedName.Equals("netsh.exe", StringComparison.OrdinalIgnoreCase) &&
            lower.Contains("advfirewall", StringComparison.OrdinalIgnoreCase))
        {
            impact = "netsh is changing or querying firewall state. This is expected during TGWST remediation, but suspicious if not user initiated.";
            recommendedAction = "Open Advanced Firewall and confirm new rules/profile state.";
            return lower.Contains("state off", StringComparison.OrdinalIgnoreCase)
                ? CyberSeverity.Critical
                : CyberSeverity.Warning;
        }

        if ((normalizedName.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase) ||
             normalizedName.Equals("pwsh.exe", StringComparison.OrdinalIgnoreCase)) &&
            (lower.Contains("-encodedcommand", StringComparison.OrdinalIgnoreCase) ||
             lower.Contains("downloadstring", StringComparison.OrdinalIgnoreCase) ||
             lower.Contains("invoke-webrequest", StringComparison.OrdinalIgnoreCase) ||
             lower.Contains("iex", StringComparison.OrdinalIgnoreCase)))
        {
            impact = "PowerShell started with encoded/download/execution indicators commonly used by automation and attacks.";
            recommendedAction = "If you did not start this, kill the process, block network egress, and run the emergency baseline.";
            return CyberSeverity.Critical;
        }

        var suspiciousNames = new[]
        {
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "mshta.exe",
            "bitsadmin.exe",
            "certutil.exe",
            "netsh.exe",
            "schtasks.exe",
            "sc.exe",
            "reg.exe"
        };

        if (suspiciousNames.Any(name => normalizedName.Equals(name, StringComparison.OrdinalIgnoreCase)))
        {
            impact = $"{normalizedName} is a powerful Windows administration tool. Legitimate if expected; risky when launched by browsers, Office apps, scripts, or unknown parents.";
            recommendedAction = "Check the command line and parent process. Use Task Manager or the process-kill action only if unexpected.";
            return CyberSeverity.Warning;
        }

        return CyberSeverity.Info;
    }

    /// <summary>
    /// Heuristic for a shell-like process whose current parent PID resolves to
    /// MsMpEng at elevated integrity. WMI delivery and PID reuse prevent this
    /// from being treated as authoritative ancestry evidence.
    /// </summary>
    private static bool IsDefenderParentAnomaly(string childName, int? parentPid, int? childPid)
    {
        if (string.IsNullOrWhiteSpace(childName) || !parentPid.HasValue)
            return false;

        var lower = childName.Trim().ToLowerInvariant();
        var shells = new[] { "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe", "cscript.exe", "wscript.exe", "rundll32.exe", "regsvr32.exe" };
        if (!shells.Any(s => lower.EndsWith(s)))
            return false;

        // Resolve parent name more reliably
        string parentName = string.Empty;
        try
        {
            if (parentPid.Value > 0)
                parentName = TryGetProcessName(parentPid.Value);
        }
        catch { }

        if (!parentName.EndsWith("MsMpEng.exe", StringComparison.OrdinalIgnoreCase) &&
            !parentName.Contains("MsMpEng", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Check integrity of the child (or parent). Prefer child for post-impersonation.
        var childIntegrity = childPid.HasValue ? ProcessIntegrity.GetIntegrityLevel(childPid.Value) : ProcessIntegrity.IntegrityLevel.Unknown;
        var parentIntegrity = ProcessIntegrity.GetIntegrityLevel(parentPid.Value);

        bool highOrSystem = ProcessIntegrity.IsSystemOrHigh(childIntegrity) || ProcessIntegrity.IsSystemOrHigh(parentIntegrity);

        return highOrSystem;
    }

    private static string BuildProcessDetail(
        string processName,
        string processId,
        string parentProcessId,
        string parentName,
        ProcessContext context)
    {
        var executable = string.IsNullOrWhiteSpace(context.ExecutablePath) ? "path=unavailable" : $"path={context.ExecutablePath}";
        var command = string.IsNullOrWhiteSpace(context.CommandLine) ? "command=unavailable" : $"command={context.CommandLine}";
        var parent = string.IsNullOrWhiteSpace(parentProcessId)
            ? "parent=unknown"
            : string.IsNullOrWhiteSpace(parentName)
                ? $"parent_pid={parentProcessId}"
                : $"parent={parentName} pid={parentProcessId}";
        return $"{processName} pid={processId}; {parent}; {executable}; {command}";
    }

    private static ProcessContext TryReadProcessContext(int processId)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"\\.\root\CIMV2",
                $"SELECT CommandLine, ExecutablePath FROM Win32_Process WHERE ProcessId = {processId}");
            foreach (ManagementObject process in searcher.Get())
            {
                using (process)
                {
                    return new ProcessContext(
                        Convert.ToString(process["ExecutablePath"]) ?? string.Empty,
                        Convert.ToString(process["CommandLine"]) ?? string.Empty);
                }
            }
        }
        catch
        {
        }

        return ProcessContext.Empty;
    }

    private static string TryGetProcessName(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return process.ProcessName + ".exe";
        }
        catch
        {
            return string.Empty;
        }
    }

    private static int? TryParseInt(string value)
    {
        return int.TryParse(value, out var numeric) ? numeric : null;
    }

    private static bool IsCommonWindowsSuspendedHost(string processName)
    {
        var knownHosts = new[]
        {
            "ApplicationFrameHost.exe",
            "backgroundTaskHost.exe",
            "RuntimeBroker.exe",
            "SearchApp.exe",
            "SearchHost.exe",
            "ShellExperienceHost.exe",
            "StartMenuExperienceHost.exe",
            "TextInputHost.exe",
            "Widgets.exe"
        };

        return knownHosts.Any(name => processName.Equals(name, StringComparison.OrdinalIgnoreCase));
    }

    private static string TrimError(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return "no detail";
        }

        return message.Length <= 140 ? message : message[..140];
    }

    private sealed record ProcessContext(string ExecutablePath, string CommandLine)
    {
        public static ProcessContext Empty { get; } = new(string.Empty, string.Empty);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _cts.Cancel();

        foreach (var watcher in _watchers)
        {
            try
            {
                watcher.Stop();
                watcher.Dispose();
            }
            catch
            {
            }
        }

        foreach (var watcher in _fileWatchers)
        {
            try
            {
                watcher.Dispose();
            }
            catch
            {
            }
        }

        _cts.Dispose();
    }
}
