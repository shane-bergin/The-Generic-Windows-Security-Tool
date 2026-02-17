using System;
using System.Collections.Generic;

namespace TGWST.Core.Recovery
{
    public enum RecoveryPreviewKind
    {
        None,
        Text,
        Image,
        Binary
    }

    public sealed record DeletedFileRecoveryItem(
        string ItemId,
        string FileName,
        string FileType,
        long FileSize,
        DateTime DateModified,
        string Source,
        string SourcePath,
        string? OriginalPath);

    public sealed record DeletedFileRecoveryScanResult(
        IReadOnlyList<DeletedFileRecoveryItem> Items,
        bool UsedWinFr,
        bool UsedRecycleBinFallback,
        string StatusMessage);

    public sealed record RecoveryPreviewResult(
        RecoveryPreviewKind Kind,
        string Content,
        string? ImagePath);

    public sealed record RecoveryRestoreResult(
        bool Success,
        string Message,
        string? RestoredPath);
}
