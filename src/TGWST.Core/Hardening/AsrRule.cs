namespace TGWST.Core.Hardening;

public enum AsrAction { Off = 0, Audit = 1, Block = 2 }

public class AsrRule
{
public string Id { get; init; } = "";
public string Name { get; init; } = "";
public AsrAction Action { get; set; }
}