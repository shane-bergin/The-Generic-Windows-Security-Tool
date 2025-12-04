namespace TGWST.Core.Uninstall;

public enum LeftoverType
{
Directory,
File,
RegistryKey,
RegistryValue
}

public sealed class LeftoverItem
{
public LeftoverType Type { get; init; }
public string Path { get; init; } = "";
public string? ValueName { get; init; }
public string? Reason { get; init; }
public bool Selected { get; set; }
public long SizeBytes { get; init; }
public string SizeDisplay => SizeBytes > 0 ? $"{SizeBytes / 1024 / 1024} MB" : "Unknown";
public string? InstallRoot { get; init; }
public string? MatchDetail { get; init; }
}
