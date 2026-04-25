using System;

namespace TGWST.Core.EventLog;

public sealed record EventLogFinding(
    DateTime TimeCreated,
    string LogName,
    int EventId,
    string? Source,
    string Severity,
    string Importance,
    bool IsDrastic,
    string Rule,
    string Evidence,
    string Purpose,
    string WhyItMatters,
    string Recommendation,
    string? Message,
    int Count);

public sealed record EventLogScanResult(
    IReadOnlyList<EventLogFinding> Findings,
    IReadOnlyList<string> Warnings);
