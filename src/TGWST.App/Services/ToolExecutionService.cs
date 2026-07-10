using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using TGWST.App.ViewModels;
using TGWST.Core.EventLog;
using TGWST.Core.Junk;

namespace TGWST.App.Services;

public sealed class ToolExecutionService
{
    private readonly JunkAnalyzerEngine _junkAnalyzer;
    private readonly EventLogAnalyzer _eventLogAnalyzer;

    public ToolExecutionService(JunkAnalyzerEngine junkAnalyzer, EventLogAnalyzer eventLogAnalyzer)
    {
        _junkAnalyzer = junkAnalyzer;
        _eventLogAnalyzer = eventLogAnalyzer;
    }

    public async Task<ToolResult> RunIntegrityVerifyAsync(CancellationToken ct)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "sfc.exe"),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        startInfo.ArgumentList.Add("/verifyonly");

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Unable to start integrity verification.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = process.StandardError.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct).ConfigureAwait(false);
        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);

        if (process.ExitCode == 0)
        {
            return new ToolResult(true, "Windows Resource Protection did not report integrity violations.");
        }

        var detail = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
        return new ToolResult(false, $"Integrity verification returned exit code {process.ExitCode}: {Trim(detail)}");
    }

    public Task<IReadOnlyList<StartupAuditRow>> AuditStartupAsync(CancellationToken ct)
    {
        return Task.Run<IReadOnlyList<StartupAuditRow>>(() =>
        {
            var rows = new List<StartupAuditRow>();
            ReadRunKey(rows, RegistryHive.CurrentUser, RegistryView.Default, "HKCU", ct);
            ReadRunKey(rows, RegistryHive.LocalMachine, RegistryView.Registry64, "HKLM64", ct);
            ReadRunKey(rows, RegistryHive.LocalMachine, RegistryView.Registry32, "HKLM32", ct);
            return rows
                .OrderByDescending(row => RiskRank(row.Risk))
                .ThenBy(row => row.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }, ct);
    }

    public async Task<(IReadOnlyList<JunkFindingRow> Rows, IReadOnlyList<JunkCandidate> Candidates)> AnalyzeJunkAsync(CancellationToken ct)
    {
        var candidates = await _junkAnalyzer.AnalyzeAsync(ct).ConfigureAwait(false);
        var rows = candidates
            .GroupBy(candidate => new { candidate.Kind, candidate.Category })
            .Select(group => new JunkFindingRow(
                Kind: group.Key.Kind,
                Category: group.Key.Category,
                Count: group.Count(),
                Size: FormatBytes(group.Sum(item => item.SizeBytes)),
                Risk: group.Any(item => !item.SafeToClean) ? "REVIEW" : "SAFE"))
            .OrderByDescending(row => row.Risk == "REVIEW")
            .ThenBy(row => row.Kind, StringComparer.OrdinalIgnoreCase)
            .ThenBy(row => row.Category, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return (rows, candidates);
    }

    public Task<JunkCleanupResult> CleanSafeJunkAsync(IEnumerable<JunkCandidate> candidates, CancellationToken ct)
    {
        var safe = candidates.Where(candidate => candidate.SafeToClean).ToArray();
        return _junkAnalyzer.CleanupAsync(safe, safeOnly: true, ct);
    }

    public async Task<IReadOnlyList<EventFindingRow>> GetEventFindingsAsync(CancellationToken ct)
    {
        var result = await _eventLogAnalyzer.ScanWithWarningsAsync(TimeSpan.FromHours(24), ct).ConfigureAwait(false);
        return result.Findings
            .GroupBy(finding => new { finding.Severity, finding.Rule, finding.Recommendation })
            .Select(group => new EventFindingRow(
                Severity: group.Key.Severity,
                Rule: group.Key.Rule,
                Count: group.Sum(item => Math.Max(1, item.Count)),
                Recommendation: group.Key.Recommendation))
            .OrderByDescending(row => SeverityRank(row.Severity))
            .ThenByDescending(row => row.Count)
            .Take(40)
            .ToArray();
    }

    private static void ReadRunKey(
        List<StartupAuditRow> rows,
        RegistryHive hive,
        RegistryView view,
        string scope,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            using var root = RegistryKey.OpenBaseKey(hive, view);
            using var key = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", writable: false);
            if (key == null)
            {
                return;
            }

            foreach (var valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                var command = Convert.ToString(key.GetValue(valueName)) ?? string.Empty;
                var executable = ExtractExecutableName(command);
                var risk = ScoreStartup(command, out var reason);
                rows.Add(new StartupAuditRow(scope, valueName, executable, risk, reason));
            }
        }
        catch
        {
        }
    }

    private static string ExtractExecutableName(string command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return "(empty)";
        }

        var trimmed = command.Trim();
        if (trimmed.StartsWith('"'))
        {
            var end = trimmed.IndexOf('"', 1);
            if (end > 1)
            {
                return Path.GetFileName(trimmed[1..end]);
            }
        }

        var firstToken = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? trimmed;
        return Path.GetFileName(firstToken);
    }

    private static string ScoreStartup(string command, out string reason)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            reason = "empty command";
            return "HIGH";
        }

        var expanded = Environment.ExpandEnvironmentVariables(command).ToLowerInvariant();
        if (expanded.Contains("\\temp\\", StringComparison.OrdinalIgnoreCase) ||
            expanded.Contains("\\downloads\\", StringComparison.OrdinalIgnoreCase))
        {
            reason = "user-writable launch location";
            return "HIGH";
        }

        if (expanded.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
            expanded.Contains("wscript", StringComparison.OrdinalIgnoreCase) ||
            expanded.Contains("cscript", StringComparison.OrdinalIgnoreCase) ||
            expanded.Contains("mshta", StringComparison.OrdinalIgnoreCase) ||
            expanded.Contains("rundll32", StringComparison.OrdinalIgnoreCase))
        {
            reason = "script or LOLBin startup launcher";
            return "MEDIUM";
        }

        reason = "standard startup registration";
        return "LOW";
    }

    private static int RiskRank(string risk)
    {
        return risk switch
        {
            "HIGH" => 3,
            "MEDIUM" => 2,
            "LOW" => 1,
            _ => 0
        };
    }

    private static int SeverityRank(string severity)
    {
        return severity.Equals("High", StringComparison.OrdinalIgnoreCase) ? 3 :
            severity.Equals("Medium", StringComparison.OrdinalIgnoreCase) ? 2 :
            severity.Equals("Low", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
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

    private static string Trim(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "no detail";
        }

        var builder = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            builder.Append(char.IsControl(ch) ? ' ' : ch);
        }

        var normalized = builder.ToString().Trim();
        return normalized.Length <= 220 ? normalized : normalized[..220];
    }
}
