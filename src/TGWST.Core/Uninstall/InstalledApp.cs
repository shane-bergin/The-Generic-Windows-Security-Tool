namespace TGWST.Core.Uninstall;

public sealed class InstalledApp
{
public string DisplayName { get; init; } = "";
public string Publisher { get; init; } = "";
public string UninstallString { get; init; } = "";
public bool IsStoreApp { get; init; }
public string? ProductCode { get; init; }
public string? InstallLocation { get; init; }
public string? InstallSource { get; init; }
}
