using System;

namespace TGWST.Core.Policies
{
    public sealed record WdacDevAllowRecord(
        string PolicyId,
        string BasePolicyId,
        string TargetPath,
        string? XmlPath,
        string? CipPath,
        DateTimeOffset AppliedAtUtc);
}
