using System;

namespace TGWST.Core.Policies
{
    public sealed record WdacSnapshot(
        string PolicyId,
        string? FriendlyName,
        string SourcePolicyPath,
        bool EnforceUmci,
        DateTimeOffset CapturedAtUtc);
}
