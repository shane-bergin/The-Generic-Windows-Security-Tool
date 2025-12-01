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
}