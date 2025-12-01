using System.Collections.Generic;
using YamlDotNet.Serialization;

namespace TGWST.Core.Scan;

public sealed class SigmaRule
{
[YamlMember(Alias = "title")]
public string Title { get; init; } = "";

[YamlMember(Alias = "description")]
public string Description { get; init; } = "";

[YamlMember(Alias = "tags")]
public string[] Tags { get; init; } = Array.Empty<string>();

[YamlMember(Alias = "detection")]
public SigmaDetection Detection { get; init; } = new();


}