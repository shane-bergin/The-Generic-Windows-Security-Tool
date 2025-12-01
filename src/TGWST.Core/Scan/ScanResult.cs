namespace TGWST.Core.Scan;

public class ScanResult
{
public string Path { get; init; } = "";
public bool Suspicious { get; init; }
public string Reason { get; init; } = "";
public string? YaraRule { get; init; }
public string? Engine { get; init; } = "dnYara v2.1.0 (YARA 4.1.1)";
}
