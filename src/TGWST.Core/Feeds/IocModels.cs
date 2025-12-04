using System;
using System.Collections.Generic;

namespace TGWST.Core.Feeds;

public sealed class IocBundle
{
    public string? Family { get; set; }
    public string? Source { get; set; }
    public string? SampleHash { get; set; }
    public List<string>? Mutexes { get; set; }
    public List<string>? RegistryKeys { get; set; }
    public List<string>? Filenames { get; set; }
    public List<string>? Domains { get; set; }
    public List<string>? Ips { get; set; }
    public DateTime? CreatedUtc { get; set; }
}

public sealed class FeedFileInfo
{
    public string Type { get; init; } = "";
    public string FileName { get; init; } = "";
    public int ItemCount { get; init; }
    public string? Source { get; init; }
}

public sealed class FeedSummary
{
    public int YaraRuleCount { get; init; }
    public int IocBundleCount { get; init; }
    public int TotalFamilies { get; init; }
    public DateTime ReloadedAtUtc { get; init; }
    public IReadOnlyList<string> Families { get; init; } = Array.Empty<string>();
    public IReadOnlyList<FeedFileInfo> Files { get; init; } = Array.Empty<FeedFileInfo>();
}
