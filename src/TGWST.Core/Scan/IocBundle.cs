using System;
using System.Text.Json.Serialization;

namespace TGWST.Core.Scan;

public readonly record struct IocBundle
{
    [JsonPropertyName("family")]
    public string? Family { get; init; }

    [JsonPropertyName("source")]
    public string? Source { get; init; }

    [JsonPropertyName("sampleHash")]
    public string? SampleHash { get; init; }

    [JsonPropertyName("mutexes")]
    public string[] Mutexes { get; init; }

    [JsonPropertyName("registryKeys")]
    public string[] RegistryKeys { get; init; }

    [JsonPropertyName("filenames")]
    public string[] Filenames { get; init; }

    [JsonPropertyName("domains")]
    public string[] Domains { get; init; }

    [JsonPropertyName("ips")]
    public string[] Ips { get; init; }

    [JsonPropertyName("createdUtc")]
    public DateTime CreatedUtc { get; init; }

    [JsonConstructor]
    public IocBundle(
        string? family,
        string? source,
        string? sampleHash,
        string[]? mutexes,
        string[]? registryKeys,
        string[]? filenames,
        string[]? domains,
        string[]? ips,
        DateTime createdUtc)
    {
        Family = family;
        Source = source;
        SampleHash = sampleHash;
        Mutexes = mutexes ?? Array.Empty<string>();
        RegistryKeys = registryKeys ?? Array.Empty<string>();
        Filenames = filenames ?? Array.Empty<string>();
        Domains = domains ?? Array.Empty<string>();
        Ips = ips ?? Array.Empty<string>();
        CreatedUtc = createdUtc;
    }
}
