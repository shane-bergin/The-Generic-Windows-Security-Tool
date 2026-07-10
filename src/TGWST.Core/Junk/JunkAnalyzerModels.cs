using System;
using System.Collections.Generic;
using Microsoft.Win32;

namespace TGWST.Core.Junk
{
    public sealed record JunkCandidate(
        string ItemId,
        string Path,
        string Kind,
        long SizeBytes,
        DateTime LastModified,
        string Category,
        string Reason,
        bool SafeToClean,
        RegistryHive? RegistryHive = null,
        RegistryView? RegistryView = null,
        string? RegistrySubKey = null,
        string? RegistryValueName = null,
        string? RegistryValueData = null,
        RegistryValueKind? RegistryValueKind = null);

    public sealed record JunkCleanupItemResult(
        string Path,
        bool Deleted,
        string Message);

    public sealed record JunkCleanupResult(
        int DeletedCount,
        int SkippedCount,
        IReadOnlyList<JunkCleanupItemResult> Results);
}
