using System.Collections.Generic;
using YamlDotNet.Serialization;

namespace TGWST.Core.Scan;

public sealed class SigmaDetection
{
[YamlMember(Alias = "selection")]
public Dictionary<string, object> Selection { get; init; } = new();

[YamlMember(Alias = "condition")]
public string Condition { get; init; } = "";


}