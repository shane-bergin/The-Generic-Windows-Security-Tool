using System;

namespace TGWST.App.ViewModels;

public enum CyberSeverity
{
    Info,
    Success,
    Warning,
    Critical
}

public enum CyberThreatLevel
{
    Normal,
    Elevated,
    Critical
}

public sealed record SecurityLogEntry(
    DateTimeOffset Timestamp,
    CyberSeverity Severity,
    string Source,
    string Message)
{
    public string DisplayLine => $"[{Timestamp:HH:mm:ss}] [{Severity.ToString().ToUpperInvariant()}] {Source} :: {Message}";
}

public sealed record NetworkConnectionRow(
    string Process,
    int ProcessId,
    string Protocol,
    string Local,
    string Remote,
    string State,
    int RiskScore,
    string Risk);

public sealed record TelemetryEventRow(
    DateTimeOffset Timestamp,
    CyberSeverity Severity,
    string Source,
    string Signal,
    string Detail)
{
    public string DisplayLine => $"[{Timestamp:HH:mm:ss}] [{Severity.ToString().ToUpperInvariant()}] {Source} :: {Signal} :: {Detail}";
}

public sealed record RiskTimelineItem(string Label, int Info, int Warning, int Critical);

public sealed record StartupAuditRow(
    string Scope,
    string Name,
    string Executable,
    string Risk,
    string Reason);

public sealed record EventFindingRow(
    string Severity,
    string Rule,
    int Count,
    string Recommendation);

public sealed record JunkFindingRow(
    string Category,
    int Count,
    string Size,
    string Risk);

public sealed record ToolResult(bool Success, string Message);
