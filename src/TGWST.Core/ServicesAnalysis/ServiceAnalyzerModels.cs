using System;
using System.Collections.Generic;

namespace TGWST.Core.ServicesAnalysis
{
    public sealed record ServiceAnalysisItem(
        string ServiceName,
        string DisplayName,
        string Status,
        string StartupType,
        string Origin,
        bool Essential,
        string Reason,
        string StateNote,
        bool HighImpact,
        string Purpose,
        string KeepEnabledReason,
        string DisableReason,
        string Recommendation);

    public sealed record ServiceActionResult(
        bool Success,
        string Message);

    public sealed record ServiceStateBackupRecord(
        string ServiceName,
        string StartupType,
        bool WasRunning,
        DateTime SavedAtUtc);

    public sealed record ServiceAnalysisSnapshot(
        IReadOnlyList<ServiceAnalysisItem> Services,
        DateTime GeneratedAtUtc);
}
