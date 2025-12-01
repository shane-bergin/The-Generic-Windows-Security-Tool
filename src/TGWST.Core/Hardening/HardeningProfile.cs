using System.Collections.Generic;

namespace TGWST.Core.Hardening;

public enum HardeningProfileLevel { Balanced, Aggressive, Audit, Revert }

public class HardeningProfile
{
public HardeningProfileLevel Level { get; init; }
public bool DefenderRealtimeOn { get; init; }
public bool NetworkProtectionOn { get; init; }
public bool ControlledFolderAccessOn { get; init; }
public bool SmartScreenOn { get; init; }
public IReadOnlyList<AsrRule> AsrRules { get; set; } = Array.Empty<AsrRule>();
public bool RebootRequired { get; set; }
}
