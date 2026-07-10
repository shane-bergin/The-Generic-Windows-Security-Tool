using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TGWST.App.ViewModels;
using TGWST.Core.Network;
using TGWST.Core.Network.Capture;

namespace TGWST.App.Services;

public sealed class DeepNetworkAnalyzerService
{
    private static readonly TimeSpan HttpTimeout = TimeSpan.FromSeconds(3);
    private static readonly HttpClient Http = new() { Timeout = HttpTimeout };

    public Task<DeepNetworkAnalysisSnapshot> ScanAsync(CancellationToken ct = default)
    {
        return Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();

            using var poller = new IpHelperPoller();
            var snapshot = poller.GetCurrentConnections();
            var routeRows = await ReadRoutesAsync(ct).ConfigureAwait(false);
            var dnsCache = await ReadDnsCacheAsync(ct).ConfigureAwait(false);
            var endpointRows = new List<DeepNetworkEndpointRow>();
            var findings = new List<DeepNetworkFindingRow>();

            AddRouteFindings(routeRows, findings);
            findings.AddRange(await ReadNetworkStackFindingsAsync(ct).ConfigureAwait(false));

            var candidates = snapshot.Connections
                .Where(IsEndpointCandidate)
                .GroupBy(c => $"{NormalizeAddress(c.RemoteAddress)}|{c.RemotePort}|{c.ProcessId}|{c.Protocol}", StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .OrderByDescending(EndpointSortScore)
                .Take(45)
                .ToArray();

            foreach (var connection in candidates)
            {
                ct.ThrowIfCancellationRequested();
                endpointRows.Add(await AnalyzeEndpointAsync(connection, routeRows, ct).ConfigureAwait(false));
            }

            AddEndpointFindings(endpointRows, findings);

            var dnsRows = MergeDnsRows(dnsCache, endpointRows);
            AddDnsFindings(dnsRows, findings);

            var summary = BuildSummary(endpointRows, routeRows, findings);
            return new DeepNetworkAnalysisSnapshot(
                DateTimeOffset.Now,
                summary,
                findings.OrderByDescending(SeverityRank).ThenBy(f => f.Category, StringComparer.OrdinalIgnoreCase).ToArray(),
                endpointRows.OrderByDescending(e => e.RiskScore).ThenBy(e => e.Process, StringComparer.OrdinalIgnoreCase).ToArray(),
                routeRows.OrderBy(r => r.DestinationPrefix, StringComparer.OrdinalIgnoreCase).Take(160).ToArray(),
                dnsRows.Take(220).ToArray());
        }, ct);
    }

    private static Task<DeepNetworkEndpointRow> AnalyzeEndpointAsync(
        ConnectionEntry connection,
        IReadOnlyList<DeepNetworkRouteRow> routes,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var remoteAddress = NormalizeAddress(connection.RemoteAddress);
        var process = string.IsNullOrWhiteSpace(connection.ProcessName) ? "Unknown" : connection.ProcessName;
        var processPath = TryGetProcessPath(connection.ProcessId);
        // Local-only is the safe default: do not disclose the observed endpoint
        // inventory through reverse-DNS, active DNS, or third-party RDAP lookups.
        // The DNS tab still reports records already present in the local cache.
        string? remoteHost = null;
        var dnsRecords = string.Empty;
        var route = DescribeRoute(remoteAddress, routes);
        var geo = IsPublicAddress(remoteAddress)
            ? "public IP; external owner enrichment disabled (privacy)"
            : IsPrivateOrLocalAddress(remoteAddress)
                ? "local/private address"
                : "non-public address";
        var classification = ClassifyEndpoint(connection, remoteAddress, remoteHost, processPath, geo, out var risk, out var explanation);

        return Task.FromResult(new DeepNetworkEndpointRow(
            classification,
            risk,
            process,
            connection.ProcessId,
            processPath,
            remoteAddress,
            connection.RemotePort,
            remoteHost ?? "no reverse DNS",
            string.IsNullOrWhiteSpace(dnsRecords) ? "no A/CNAME data" : dnsRecords,
            route,
            geo,
            explanation));
    }

    private static string ClassifyEndpoint(
        ConnectionEntry connection,
        string remoteAddress,
        string? remoteHost,
        string processPath,
        string geo,
        out int risk,
        out string explanation)
    {
        var host = (remoteHost ?? "").ToLowerInvariant();
        var process = (connection.ProcessName ?? "").ToLowerInvariant();
        var path = processPath.ToLowerInvariant();
        var publicIp = IsPublicAddress(remoteAddress);
        var privateOrLocal = IsPrivateOrLocalAddress(remoteAddress);
        var multicast = IsMulticastAddress(remoteAddress);
        var highPort = connection.RemotePort >= 1024;
        var sensitivePort = connection.RemotePort is 20 or 21 or 22 or 23 or 25 or 53 or 139 or 445 or 3389 or 4444 or 5900 or 5985 or 5986;
        var userWritableProcess = path.Contains("\\appdata\\", StringComparison.OrdinalIgnoreCase) ||
                                  path.Contains("\\temp\\", StringComparison.OrdinalIgnoreCase) ||
                                  path.Contains("\\downloads\\", StringComparison.OrdinalIgnoreCase);

        if (multicast || privateOrLocal)
        {
            risk = connection.RemotePort is 5353 or 5355 or 1900 or 3702 ? 15 : 8;
            explanation = "Local/private or multicast traffic. Usually discovery, LAN service lookup, adapter chatter, or self-check activity rather than external exfiltration.";
            return "LocalDiscovery";
        }

        if (IsMicrosoftEndpoint(process, host, geo))
        {
            risk = 18;
            explanation = "Microsoft-owned or Microsoft-process traffic. Usually Windows Update, Defender, identity, diagnostics, Store, Edge/WebView, or Microsoft service telemetry.";
            return host.Contains("telemetry", StringComparison.OrdinalIgnoreCase) ||
                   host.Contains("vortex", StringComparison.OrdinalIgnoreCase) ||
                   host.Contains("data.microsoft", StringComparison.OrdinalIgnoreCase)
                ? "MicrosoftTelemetry"
                : "MicrosoftInfrastructure";
        }

        if (IsAdOrTrackerHost(host))
        {
            risk = process.Contains("chrome") || process.Contains("edge") || process.Contains("firefox") || process.Contains("brave") ? 42 : 58;
            explanation = "Host naming matches advertising, tracking, analytics, crash, metrics, or attribution infrastructure. Browser-owned traffic is often normal web/app telemetry; non-browser ownership deserves review.";
            return "AdwareOrTracker";
        }

        if (IsCloudOrSync(process, host))
        {
            risk = 34;
            explanation = "Cloud storage, sync, backup, or browser profile-sync style endpoint. This can be legitimate collection/synchronization; review if the app or account is unexpected.";
            return "PotentialCollection";
        }

        if (userWritableProcess && publicIp)
        {
            risk = 86;
            explanation = "A process running from a user-writable location is communicating with a public IP. This is high-signal for unwanted collection, payload staging, or unknown exfiltration.";
            return "PotentialUnknownExfiltration";
        }

        if (string.IsNullOrWhiteSpace(remoteHost) && publicIp && highPort)
        {
            risk = sensitivePort ? 78 : 64;
            explanation = "Public endpoint has no reverse DNS and uses a high or sensitive remote port. This is not proof of compromise, but it is an unknown egress path worth validating.";
            return "PotentialUnknownExfiltration";
        }

        if (IsScriptCapableProcess(process))
        {
            risk = 74;
            explanation = "Administrative or script-capable Windows binary owns a public connection. Legitimate automation is possible, but this pattern is commonly abused for staging or command-and-control.";
            return "NeedsReview";
        }

        if (process.Contains("chrome") || process.Contains("edge") || process.Contains("firefox") || process.Contains("brave"))
        {
            risk = 28;
            explanation = "Browser-owned public traffic. Usually normal web/app traffic unless the host, port, or timing is unexpected.";
            return "TypicalAppTraffic";
        }

        risk = publicIp ? 48 : 20;
        explanation = publicIp
            ? "Public endpoint did not match known safe or high-risk classifiers. Review the process path, DNS owner, and route before allowing persistent egress."
            : "Endpoint did not match a high-risk pattern.";
        return publicIp ? "NeedsReview" : "TypicalAppTraffic";
    }

    private static async Task<IReadOnlyList<DeepNetworkRouteRow>> ReadRoutesAsync(CancellationToken ct)
    {
        const string script = """
Get-NetRoute -ErrorAction SilentlyContinue |
  Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric,InterfaceMetric,Protocol,State |
  ConvertTo-Json -Depth 4 -Compress
""";

        var output = await RunPowerShellAsync(script, ct).ConfigureAwait(false);
        var rows = new List<DeepNetworkRouteRow>();
        foreach (var element in EnumerateJsonObjects(output))
        {
            var prefix = ReadString(element, "DestinationPrefix");
            var nextHop = ReadString(element, "NextHop");
            var alias = ReadString(element, "InterfaceAlias");
            var routeMetric = ReadInt(element, "RouteMetric");
            var interfaceMetric = ReadInt(element, "InterfaceMetric");
            var protocol = ReadString(element, "Protocol");
            var state = ReadString(element, "State");
            rows.Add(new DeepNetworkRouteRow(
                prefix,
                nextHop,
                alias,
                routeMetric,
                interfaceMetric,
                protocol,
                state,
                AssessRoute(prefix, nextHop, alias, routeMetric, interfaceMetric)));
        }

        return rows;
    }

    private static async Task<IReadOnlyList<DeepNetworkDnsRow>> ReadDnsCacheAsync(CancellationToken ct)
    {
        const string script = """
Get-DnsClientCache -ErrorAction SilentlyContinue |
  Select-Object -First 160 Entry,Name,Type,Data,Status,TimeToLive |
  ConvertTo-Json -Depth 4 -Compress
""";

        var output = await RunPowerShellAsync(script, ct).ConfigureAwait(false);
        var rows = new List<DeepNetworkDnsRow>();
        foreach (var element in EnumerateJsonObjects(output))
        {
            var name = ReadString(element, "Name");
            if (string.IsNullOrWhiteSpace(name))
            {
                name = ReadString(element, "Entry");
            }

            var type = ReadString(element, "Type");
            var data = ReadString(element, "Data");
            rows.Add(new DeepNetworkDnsRow(
                name,
                type,
                data,
                "DNS cache",
                AssessDns(name, type, data)));
        }

        return rows;
    }

    private static async Task<IReadOnlyList<DeepNetworkFindingRow>> ReadNetworkStackFindingsAsync(CancellationToken ct)
    {
        const string script = """
$config = Get-NetIPConfiguration -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{
    InterfaceAlias = $_.InterfaceAlias
    InterfaceDescription = $_.InterfaceDescription
    IPv4Gateway = (($_.IPv4DefaultGateway | ForEach-Object NextHop) -join ',')
    IPv6Gateway = (($_.IPv6DefaultGateway | ForEach-Object NextHop) -join ',')
    DnsServers = ($_.DNSServer.ServerAddresses -join ',')
  }
}
$profiles = Get-NetConnectionProfile -ErrorAction SilentlyContinue |
  Select-Object InterfaceAlias,NetworkCategory,IPv4Connectivity,IPv6Connectivity
$proxy = (netsh winhttp show proxy 2>$null) -join ' '
[pscustomobject]@{ Config = $config; Profiles = $profiles; WinHttpProxy = $proxy } |
  ConvertTo-Json -Depth 6 -Compress
""";

        var output = await RunPowerShellAsync(script, ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(output))
        {
            return Array.Empty<DeepNetworkFindingRow>();
        }

        var findings = new List<DeepNetworkFindingRow>();
        try
        {
            using var document = JsonDocument.Parse(output);
            var root = document.RootElement;
            if (root.TryGetProperty("Config", out var config))
            {
                foreach (var item in EnumeratePropertyObjects(config))
                {
                    var alias = ReadString(item, "InterfaceAlias");
                    var dnsServers = ReadString(item, "DnsServers");
                    foreach (var dnsServer in dnsServers.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase))
                    {
                        if (IPAddress.TryParse(dnsServer, out _) && IsPublicAddress(dnsServer))
                        {
                            findings.Add(new DeepNetworkFindingRow(
                                "WARN",
                                "DNS Resolver",
                                string.IsNullOrWhiteSpace(alias) ? dnsServer : $"{alias} -> {dnsServer}",
                                "Interface is configured to use a public DNS resolver. This can be expected on personal networks, but it can also bypass VPN, enterprise DNS, filtering, or local collection controls.",
                                "Validate whether this resolver is intentional for the adapter and whether DNS should stay inside VPN or enterprise policy."));
                        }
                    }
                }
            }

            if (root.TryGetProperty("WinHttpProxy", out var proxyElement))
            {
                var proxy = proxyElement.GetString() ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(proxy) &&
                    !proxy.Contains("Direct access", StringComparison.OrdinalIgnoreCase) &&
                    !proxy.Contains("no proxy", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new DeepNetworkFindingRow(
                        "WARN",
                        "Proxy",
                        "WinHTTP proxy",
                        $"WinHTTP proxy is configured: {TrimForDisplay(proxy)}. System services and updaters may use this path for outbound connectivity.",
                        "Confirm this proxy is expected. Unexpected proxy settings can redirect telemetry, app traffic, or credential-bearing requests."));
                }
            }
        }
        catch (JsonException)
        {
            return findings;
        }

        return findings;
    }

    private static IReadOnlyList<DeepNetworkDnsRow> MergeDnsRows(
        IReadOnlyList<DeepNetworkDnsRow> cacheRows,
        IReadOnlyList<DeepNetworkEndpointRow> endpoints)
    {
        var rows = new List<DeepNetworkDnsRow>(cacheRows);
        foreach (var endpoint in endpoints)
        {
            if (endpoint.RemoteHost == "no reverse DNS" || endpoint.DnsRecords == "no A/CNAME data")
            {
                continue;
            }

            foreach (var part in endpoint.DnsRecords.Split("; ", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var idx = part.IndexOf('=', StringComparison.Ordinal);
                rows.Add(new DeepNetworkDnsRow(
                    endpoint.RemoteHost,
                    idx > 0 ? part[..idx] : "DNS",
                    idx > 0 ? part[(idx + 1)..] : part,
                    "active resolution",
                    AssessDns(endpoint.RemoteHost, part, part)));
            }
        }

        return rows
            .GroupBy(row => $"{row.Name}|{row.RecordType}|{row.Data}|{row.Source}", StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderByDescending(row => row.Assessment.Contains("review", StringComparison.OrdinalIgnoreCase))
            .ThenBy(row => row.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static async Task<string> ResolveDnsRecordsAsync(string host, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(host) || host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            return "";
        }

        if (!IsSafeDnsName(host))
        {
            return "";
        }

        var safeHost = host.Replace("'", "''", StringComparison.Ordinal);
        var script = $$"""
$records = @()
foreach ($type in @('CNAME','A','AAAA')) {
  try {
    $records += Resolve-DnsName -Name '{{safeHost}}' -Type $type -DnsOnly -QuickTimeout -ErrorAction Stop |
      Select-Object Type,NameHost,IPAddress
  } catch { }
}
$records | ConvertTo-Json -Depth 4 -Compress
""";

        var output = await RunPowerShellAsync(script, ct).ConfigureAwait(false);
        var parts = new List<string>();
        foreach (var element in EnumerateJsonObjects(output))
        {
            var type = ReadString(element, "Type");
            var data = ReadString(element, "IPAddress");
            if (string.IsNullOrWhiteSpace(data))
            {
                data = ReadString(element, "NameHost");
            }

            if (!string.IsNullOrWhiteSpace(type) && !string.IsNullOrWhiteSpace(data))
            {
                parts.Add($"{type}={data}");
            }
        }

        return string.Join("; ", parts.Distinct(StringComparer.OrdinalIgnoreCase).Take(12));
    }

    private static async Task<string> ResolveNetworkOwnerAsync(string remoteAddress, CancellationToken ct)
    {
        if (!IsPublicAddress(remoteAddress))
        {
            return IsPrivateOrLocalAddress(remoteAddress) ? "local/private address" : "non-public address";
        }

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"https://rdap.org/ip/{remoteAddress}");
            request.Headers.UserAgent.ParseAdd("TGWST/10.0 deep-network-analyzer");
            using var response = await Http.SendAsync(request, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return $"public IP; RDAP unavailable ({(int)response.StatusCode})";
            }

            await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
            var root = document.RootElement;
            var name = ReadString(root, "name");
            var country = ReadString(root, "country");
            var start = ReadString(root, "startAddress");
            var end = ReadString(root, "endAddress");
            var owner = FirstEntityName(root);
            return string.Join("; ", new[]
            {
                string.IsNullOrWhiteSpace(owner) ? null : owner,
                string.IsNullOrWhiteSpace(name) ? null : name,
                string.IsNullOrWhiteSpace(country) ? null : $"country={country}",
                string.IsNullOrWhiteSpace(start) || string.IsNullOrWhiteSpace(end) ? null : $"{start}-{end}"
            }.Where(part => !string.IsNullOrWhiteSpace(part))) is { Length: > 0 } summary
                ? summary
                : "public IP; RDAP returned no owner summary";
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return "public IP; RDAP lookup timed out or failed";
        }
    }

    private static string? FirstEntityName(JsonElement root)
    {
        if (!root.TryGetProperty("entities", out var entities) || entities.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var entity in entities.EnumerateArray())
        {
            if (!entity.TryGetProperty("vcardArray", out var vcard) || vcard.ValueKind != JsonValueKind.Array || vcard.GetArrayLength() < 2)
            {
                continue;
            }

            var items = vcard[1];
            if (items.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var item in items.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.Array &&
                    item.GetArrayLength() >= 4 &&
                    item[0].GetString()?.Equals("fn", StringComparison.OrdinalIgnoreCase) == true)
                {
                    return item[3].GetString();
                }
            }
        }

        return null;
    }

    private static async Task<string?> TryReverseDnsAsync(string address, CancellationToken ct)
    {
        if (!IPAddress.TryParse(address, out var ip) || !IsPublicAddress(address))
        {
            return null;
        }

        try
        {
            var entry = await Dns.GetHostEntryAsync(ip).WaitAsync(ct).ConfigureAwait(false);
            return entry.HostName;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    private static string TryGetProcessPath(int pid)
    {
        if (pid <= 0)
        {
            return "System";
        }

        try
        {
            using var process = Process.GetProcessById(pid);
            return process.MainModule?.FileName ?? "unavailable";
        }
        catch
        {
            return "unavailable";
        }
    }

    private static string DescribeRoute(string remoteAddress, IReadOnlyList<DeepNetworkRouteRow> routes)
    {
        if (!IPAddress.TryParse(remoteAddress, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return "route match not available for this address family";
        }

        var match = routes
            .Select(route => new { Route = route, PrefixLength = TryGetPrefixLength(route.DestinationPrefix), Matches = RouteMatches(ip, route.DestinationPrefix) })
            .Where(item => item.Matches)
            .OrderByDescending(item => item.PrefixLength)
            .ThenBy(item => item.Route.RouteMetric + item.Route.InterfaceMetric)
            .FirstOrDefault();

        return match == null
            ? "no IPv4 route matched"
            : $"{match.Route.DestinationPrefix} via {match.Route.NextHop} on {match.Route.InterfaceAlias} metric {match.Route.RouteMetric + match.Route.InterfaceMetric}";
    }

    private static bool RouteMatches(IPAddress ip, string destinationPrefix)
    {
        var slash = destinationPrefix.IndexOf('/', StringComparison.Ordinal);
        if (slash <= 0 || !IPAddress.TryParse(destinationPrefix[..slash], out var network) ||
            !int.TryParse(destinationPrefix[(slash + 1)..], out var prefix) ||
            prefix is < 0 or > 32 ||
            network.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return false;
        }

        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        return (ToUInt32(ip) & mask) == (ToUInt32(network) & mask);
    }

    private static uint ToUInt32(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    private static int TryGetPrefixLength(string destinationPrefix)
    {
        var slash = destinationPrefix.IndexOf('/', StringComparison.Ordinal);
        return slash > 0 && int.TryParse(destinationPrefix[(slash + 1)..], out var prefix) ? prefix : -1;
    }

    private static void AddRouteFindings(IReadOnlyList<DeepNetworkRouteRow> routes, List<DeepNetworkFindingRow> findings)
    {
        var defaults = routes.Where(route => route.DestinationPrefix is "0.0.0.0/0" or "::/0").ToArray();
        if (defaults.Length == 0)
        {
            findings.Add(new DeepNetworkFindingRow("WARN", "Routing", "Default route", "No default route was found. Connectivity may be broken or hidden behind an unsupported stack.", "Review adapters, VPN clients, and route policy."));
        }
        else if (defaults.Length > 2)
        {
            findings.Add(new DeepNetworkFindingRow("WARN", "Routing", "Multiple default routes", $"{defaults.Length} default routes are active. This can leak traffic outside a VPN or send telemetry over an unexpected interface.", "Review default routes and interface metrics."));
        }

        foreach (var route in routes.Where(r => r.Assessment.Contains("review", StringComparison.OrdinalIgnoreCase)).Take(10))
        {
            findings.Add(new DeepNetworkFindingRow("WARN", "Routing", route.DestinationPrefix, route.Assessment, "Validate whether this route is expected for VPN, Hyper-V, WSL, Docker, or physical adapters."));
        }
    }

    private static void AddEndpointFindings(IReadOnlyList<DeepNetworkEndpointRow> endpoints, List<DeepNetworkFindingRow> findings)
    {
        foreach (var endpoint in endpoints.Where(e => e.RiskScore >= 70).Take(12))
        {
            findings.Add(new DeepNetworkFindingRow("CRITICAL", endpoint.Classification, endpoint.Endpoint, endpoint.Explanation, "Inspect the process path, publisher, command line, DNS owner, and route. Block the remote or process if unexpected."));
        }

        foreach (var endpoint in endpoints.Where(e => e.Classification is "AdwareOrTracker" or "PotentialCollection").Take(12))
        {
            findings.Add(new DeepNetworkFindingRow("WARN", endpoint.Classification, endpoint.Endpoint, endpoint.Explanation, "Review whether this application should be allowed to collect or synchronize data."));
        }
    }

    private static void AddDnsFindings(IReadOnlyList<DeepNetworkDnsRow> rows, List<DeepNetworkFindingRow> findings)
    {
        var odd = rows.Where(row => row.Assessment.Contains("review", StringComparison.OrdinalIgnoreCase)).Take(8).ToArray();
        foreach (var row in odd)
        {
            findings.Add(new DeepNetworkFindingRow("WARN", "DNS", row.Name, row.Assessment, "Review the owning process and endpoint before allowing recurring resolution."));
        }
    }

    private static string BuildSummary(
        IReadOnlyList<DeepNetworkEndpointRow> endpoints,
        IReadOnlyList<DeepNetworkRouteRow> routes,
        IReadOnlyList<DeepNetworkFindingRow> findings)
    {
        var critical = findings.Count(f => f.Severity == "CRITICAL");
        var warn = findings.Count(f => f.Severity == "WARN");
        var publicEndpoints = endpoints.Count(e => e.GeoNetwork.StartsWith("public IP", StringComparison.OrdinalIgnoreCase) == false &&
                                                   e.GeoNetwork != "local/private address" &&
                                                   e.GeoNetwork != "non-public address");
        var defaultRoutes = routes.Count(r => r.DestinationPrefix is "0.0.0.0/0" or "::/0");
        return $"deep scan complete: {endpoints.Count} endpoint(s), {defaultRoutes} default route(s), {publicEndpoints} public-owner lookup(s), {critical} critical / {warn} warning finding(s)";
    }

    private static string AssessRoute(string prefix, string nextHop, string alias, int routeMetric, int interfaceMetric)
    {
        var lowerAlias = alias.ToLowerInvariant();
        if (prefix is "0.0.0.0/0" or "::/0")
        {
            return lowerAlias.Contains("vpn", StringComparison.Ordinal) || lowerAlias.Contains("tailscale", StringComparison.Ordinal) || lowerAlias.Contains("wireguard", StringComparison.Ordinal)
                ? "default route exits through VPN-like interface"
                : "default route exits through normal interface; review if VPN should be full-tunnel";
        }

        if ((lowerAlias.Contains("vethernet", StringComparison.Ordinal) ||
             lowerAlias.Contains("wsl", StringComparison.Ordinal) ||
             lowerAlias.Contains("docker", StringComparison.Ordinal) ||
             lowerAlias.Contains("hyper-v", StringComparison.Ordinal)) &&
            !prefix.StartsWith("172.", StringComparison.OrdinalIgnoreCase) &&
            !prefix.StartsWith("192.168.", StringComparison.OrdinalIgnoreCase) &&
            !prefix.StartsWith("10.", StringComparison.OrdinalIgnoreCase))
        {
            return "review: public or broad route through virtual adapter";
        }

        return routeMetric + interfaceMetric > 5000 ? "low-priority route" : "expected route";
    }

    private static string AssessDns(string name, string type, string data)
    {
        var combined = $"{name} {type} {data}".ToLowerInvariant();
        if (IsAdOrTrackerHost(combined))
        {
            return "review: DNS name matches advertising/tracking/analytics pattern";
        }

        if (combined.Contains("microsoft", StringComparison.Ordinal) ||
            combined.Contains("windowsupdate", StringComparison.Ordinal) ||
            combined.Contains("msft", StringComparison.Ordinal))
        {
            return "typical Microsoft infrastructure";
        }

        if (combined.Contains("duckdns", StringComparison.Ordinal) ||
            combined.Contains("no-ip", StringComparison.Ordinal) ||
            combined.Contains("dynu", StringComparison.Ordinal) ||
            combined.Contains("pastebin", StringComparison.Ordinal))
        {
            return "review: dynamic DNS or staging-like domain";
        }

        return "baseline DNS record";
    }

    private static bool IsEndpointCandidate(ConnectionEntry entry)
    {
        var remote = NormalizeAddress(entry.RemoteAddress);
        if (remote is "*" or "0.0.0.0" or "::")
        {
            return entry.Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase) || entry.State == TcpState.Listen;
        }

        return IsPublicAddress(remote) ||
               IsPrivateOrLocalAddress(remote) ||
               IsMulticastAddress(remote);
    }

    private static int EndpointSortScore(ConnectionEntry entry)
    {
        var remote = NormalizeAddress(entry.RemoteAddress);
        var score = IsPublicAddress(remote) ? 100 : 10;
        if (entry.State == TcpState.Established) score += 20;
        if (entry.RemotePort >= 1024) score += 5;
        if (entry.ProcessName.Equals("Unknown", StringComparison.OrdinalIgnoreCase)) score += 15;
        return score;
    }

    private static bool IsMicrosoftEndpoint(string process, string host, string geo)
    {
        return host.Contains("microsoft", StringComparison.Ordinal) ||
               host.Contains("windowsupdate", StringComparison.Ordinal) ||
               host.Contains("msft", StringComparison.Ordinal) ||
               host.Contains("azureedge", StringComparison.Ordinal) ||
               host.Contains("akadns", StringComparison.Ordinal) ||
               host.Contains("office.com", StringComparison.Ordinal) ||
               host.Contains("live.com", StringComparison.Ordinal) ||
               host.Contains("sharepoint", StringComparison.Ordinal) ||
               host.Contains("1drv", StringComparison.Ordinal) ||
               geo.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsScriptCapableProcess(string process)
    {
        return process.Contains("rundll32", StringComparison.Ordinal) ||
               process.Contains("regsvr32", StringComparison.Ordinal) ||
               process.Contains("mshta", StringComparison.Ordinal) ||
               process.Contains("wscript", StringComparison.Ordinal) ||
               process.Contains("cscript", StringComparison.Ordinal) ||
               process.Contains("powershell", StringComparison.Ordinal) ||
               process.Contains("pwsh", StringComparison.Ordinal);
    }

    private static bool IsAdOrTrackerHost(string host)
    {
        return host.Contains("doubleclick", StringComparison.Ordinal) ||
               host.Contains("googlesyndication", StringComparison.Ordinal) ||
               host.Contains("adservice", StringComparison.Ordinal) ||
               host.Contains(".ads.", StringComparison.Ordinal) ||
               host.Contains("analytics", StringComparison.Ordinal) ||
               host.Contains("metrics", StringComparison.Ordinal) ||
               host.Contains("telemetry", StringComparison.Ordinal) ||
               host.Contains("segment", StringComparison.Ordinal) ||
               host.Contains("amplitude", StringComparison.Ordinal) ||
               host.Contains("crashlytics", StringComparison.Ordinal) ||
               host.Contains("appsflyer", StringComparison.Ordinal);
    }

    private static bool IsCloudOrSync(string process, string host)
    {
        return process.Contains("onedrive", StringComparison.Ordinal) ||
               process.Contains("dropbox", StringComparison.Ordinal) ||
               process.Contains("googledrive", StringComparison.Ordinal) ||
               host.Contains("onedrive", StringComparison.Ordinal) ||
               host.Contains("dropbox", StringComparison.Ordinal) ||
               host.Contains("drive.google", StringComparison.Ordinal) ||
               host.Contains("icloud", StringComparison.Ordinal);
    }

    private static bool IsPublicAddress(string address)
    {
        if (!IPAddress.TryParse(address, out var ip))
        {
            return false;
        }

        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return false;
        }

        var bytes = ip.GetAddressBytes();
        return bytes[0] != 10 &&
               !(bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) &&
               !(bytes[0] == 192 && bytes[1] == 168) &&
               bytes[0] != 127 &&
               !(bytes[0] == 169 && bytes[1] == 254) &&
               bytes[0] < 224;
    }

    private static bool IsPrivateOrLocalAddress(string address)
    {
        if (string.IsNullOrWhiteSpace(address) || address is "*" or "0.0.0.0" or "::")
        {
            return true;
        }

        if (!IPAddress.TryParse(address, out var ip))
        {
            return false;
        }

        if (IPAddress.IsLoopback(ip))
        {
            return true;
        }

        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal;
        }

        var bytes = ip.GetAddressBytes();
        return bytes[0] == 10 ||
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
               (bytes[0] == 192 && bytes[1] == 168) ||
               (bytes[0] == 169 && bytes[1] == 254);
    }

    private static bool IsMulticastAddress(string address)
    {
        return IPAddress.TryParse(address, out var ip) &&
               ((ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && ip.GetAddressBytes()[0] >= 224 && ip.GetAddressBytes()[0] <= 239) ||
                (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && ip.IsIPv6Multicast));
    }

    private static string NormalizeAddress(string address) => string.IsNullOrWhiteSpace(address) ? "*" : address;

    private static async Task<string> RunPowerShellAsync(string script, CancellationToken ct)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-EncodedCommand");
        startInfo.ArgumentList.Add(encoded);

        using var process = Process.Start(startInfo);
        if (process == null)
        {
            return string.Empty;
        }

        var stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
        _ = process.StandardError.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct).ConfigureAwait(false);
        return (await stdoutTask.ConfigureAwait(false)).Trim();
    }

    private static IEnumerable<JsonElement> EnumeratePropertyObjects(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.Object)
                {
                    yield return item;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Object)
        {
            yield return element;
        }
    }

    private static IReadOnlyList<JsonElement> EnumerateJsonObjects(string json)
    {
        var rows = new List<JsonElement>();
        if (string.IsNullOrWhiteSpace(json))
        {
            return rows;
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in document.RootElement.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.Object)
                    {
                        rows.Add(item.Clone());
                    }
                }
            }
            else if (document.RootElement.ValueKind == JsonValueKind.Object)
            {
                rows.Add(document.RootElement.Clone());
            }
        }
        catch (JsonException)
        {
            return rows;
        }

        return rows;
    }

    private static string ReadString(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value))
        {
            return string.Empty;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? string.Empty,
            JsonValueKind.Number => value.ToString(),
            JsonValueKind.True => "True",
            JsonValueKind.False => "False",
            _ => string.Empty
        };
    }

    private static int ReadInt(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value))
        {
            return 0;
        }

        return value.TryGetInt32(out var result) ? result : 0;
    }

    private static bool IsSafeDnsName(string host)
    {
        return host.Length <= 253 && host.All(ch =>
            char.IsLetterOrDigit(ch) ||
            ch is '-' or '.' or '_');
    }

    private static string TrimForDisplay(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? "no detail" : value.Length <= 180 ? value : value[..180];
    }

    private static int SeverityRank(DeepNetworkFindingRow row)
    {
        return row.Severity switch
        {
            "CRITICAL" => 3,
            "WARN" => 2,
            "INFO" => 1,
            _ => 0
        };
    }
}
