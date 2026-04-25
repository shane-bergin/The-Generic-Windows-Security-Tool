using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using TGWST.App.ViewModels;

namespace TGWST.App.Services;

public sealed class SystemTelemetryService : IDisposable
{
    private readonly GuiLogService _log;
    private readonly List<ManagementEventWatcher> _watchers = new();
    private readonly List<FileSystemWatcher> _fileWatchers = new();
    private bool _started;
    private bool _disposed;

    public event EventHandler<TelemetryEventRow>? EventObserved;

    public SystemTelemetryService(GuiLogService log)
    {
        _log = log;
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
        _log.Success("Telemetry", "active discovery started");
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
                var severity = IsSuspiciousProcess(processName) ? CyberSeverity.Warning : CyberSeverity.Info;
                Publish(severity, "Process", "start", $"{processName} pid={processId}");
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
        var keys = new[]
        {
            ("HKEY_LOCAL_MACHINE", @"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            ("HKEY_CURRENT_USER", @"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
        };

        foreach (var (hive, rootPath) in keys)
        {
            try
            {
                var query = $"SELECT * FROM RegistryTreeChangeEvent WHERE Hive='{hive}' AND RootPath='{rootPath}'";
                var watcher = new ManagementEventWatcher(
                    new ManagementScope(@"\\.\root\default"),
                    new WqlEventQuery(query));

                watcher.EventArrived += (_, _) =>
                    Publish(CyberSeverity.Warning, "Registry", "startup key changed", hive);
                watcher.Start();
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _log.Warning("Telemetry", $"registry watcher unavailable: {TrimError(ex.Message)}");
            }
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

                watcher.Created += (_, args) => Publish(CyberSeverity.Warning, "File", "startup file created", Path.GetFileName(args.FullPath));
                watcher.Changed += (_, args) => Publish(CyberSeverity.Info, "File", "startup file changed", Path.GetFileName(args.FullPath));
                watcher.Deleted += (_, args) => Publish(CyberSeverity.Warning, "File", "startup file deleted", Path.GetFileName(args.FullPath));
                watcher.Renamed += (_, args) => Publish(CyberSeverity.Warning, "File", "startup file renamed", Path.GetFileName(args.FullPath));
                _fileWatchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _log.Warning("Telemetry", $"file watcher unavailable: {TrimError(ex.Message)}");
            }
        }
    }

    private void Publish(CyberSeverity severity, string source, string signal, string detail)
    {
        var row = new TelemetryEventRow(
            DateTimeOffset.Now,
            severity,
            source,
            signal,
            string.IsNullOrWhiteSpace(detail) ? "-" : detail);

        EventObserved?.Invoke(this, row);

        if (severity == CyberSeverity.Critical)
        {
            _log.Critical("Telemetry", $"{source} {signal}");
        }
        else if (severity == CyberSeverity.Warning)
        {
            _log.Warning("Telemetry", $"{source} {signal}");
        }
    }

    private static bool IsSuspiciousProcess(string processName)
    {
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
            "certutil.exe"
        };

        return suspiciousNames.Any(name => processName.Equals(name, StringComparison.OrdinalIgnoreCase));
    }

    private static string TrimError(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return "no detail";
        }

        return message.Length <= 140 ? message : message[..140];
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

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
    }
}
