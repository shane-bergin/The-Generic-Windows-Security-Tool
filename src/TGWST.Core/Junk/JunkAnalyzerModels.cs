using System;
using System.Collections.Generic;

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
        bool SafeToClean);

    public sealed record JunkCleanupItemResult(
        string Path,
        bool Deleted,
        string Message);

    public sealed record JunkCleanupResult(
        int DeletedCount,
        int SkippedCount,
        IReadOnlyList<JunkCleanupItemResult> Results);
}
