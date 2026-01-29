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
public string? Version { get; init; }
public string? InstallDate { get; init; }
public long EstimatedSizeBytes { get; init; }
public string SizeDisplay => EstimatedSizeBytes > 0 ?
    EstimatedSizeBytes >= 1073741824 ? $"{EstimatedSizeBytes / 1073741824.0:F2} GB" :
    EstimatedSizeBytes >= 1048576 ? $"{EstimatedSizeBytes / 1048576.0:F2} MB" :
    $"{EstimatedSizeBytes / 1024.0:F2} KB" : "";
public string RegistryKeyPath { get; init; } = "";
}
