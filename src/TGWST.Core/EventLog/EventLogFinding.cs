using System;

namespace TGWST.Core.EventLog;

public sealed record EventLogFinding(
    DateTime TimeCreated,
    int EventId,
    string? Source,
    string? Level,
    string? Rule,
    string? Message);
