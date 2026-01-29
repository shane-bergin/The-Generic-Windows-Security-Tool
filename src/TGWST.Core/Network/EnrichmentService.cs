using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.IO;

namespace TGWST.Core.Network
{
    /// <summary>
    /// Enriches flow records with DNS hostnames, process information, and code signing data.
    /// Uses caching to minimize repeated lookups and timeouts.
    /// </summary>
    public sealed class EnrichmentService
    {
        private readonly ConcurrentDictionary<string, string> _dnsCache = new();
        private readonly ConcurrentDictionary<int, ProcessInfo> _processCache = new();
        private readonly ConcurrentDictionary<string, string?> _signerCache = new();
        private readonly ConcurrentDictionary<string, string?> _geoCache = new();
        private List<GeoRange> _geoRanges = new();
        private sealed record GeoRange(uint Start, uint End, string Country);

        // DNS resolution timeout
        private readonly TimeSpan _dnsTimeout = TimeSpan.FromSeconds(2);

        /// <summary>
        /// Enrich a flow record with DNS, process, and signer information.
        /// </summary>
        public async Task EnrichAsync(FlowRecord flow, CancellationToken ct = default)
        {
            // Run enrichments in parallel
            var tasks = new[]
            {
                EnrichDnsAsync(flow, ct),
                Task.Run(() => EnrichProcess(flow)),
                Task.Run(() => EnrichSigner(flow))
            };

            await Task.WhenAll(tasks);
        }

        /// <summary>
        /// Enrich multiple flow records in parallel.
        /// </summary>
        public async Task EnrichBatchAsync(IEnumerable<FlowRecord> flows, CancellationToken ct = default)
        {
            var tasks = flows.Select(f => EnrichAsync(f, ct));
            await Task.WhenAll(tasks);
        }

        /// <summary>
        /// Resolve DNS hostname for a flow's remote address.
        /// </summary>
        public async Task EnrichDnsAsync(FlowRecord flow, CancellationToken ct = default)
        {
            if (string.IsNullOrEmpty(flow.RemoteAddress) ||
                flow.RemoteAddress == "0.0.0.0" ||
                flow.RemoteAddress == "*" ||
                flow.RemoteAddress.StartsWith("127.") ||
                flow.RemoteAddress == "::1")
            {
                return;
            }

            // Check cache first
            if (_dnsCache.TryGetValue(flow.RemoteAddress, out var cached))
            {
                flow.RemoteHostname = cached;
                return;
            }

            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(_dnsTimeout);

                var entry = await Dns.GetHostEntryAsync(flow.RemoteAddress, cts.Token);
                var hostname = entry.HostName;

                _dnsCache[flow.RemoteAddress] = hostname;
                flow.RemoteHostname = hostname;
            }
            catch (OperationCanceledException)
            {
                // Timeout - cache as empty to avoid repeated timeouts
                _dnsCache[flow.RemoteAddress] = "";
            }
            catch
            {
                // Resolution failed - cache as empty
                _dnsCache[flow.RemoteAddress] = "";
            }
        }

        /// <summary>
        /// Lookup DNS hostname synchronously (from cache only if available).
        /// </summary>
        public string? GetCachedHostname(string ipAddress)
        {
            return _dnsCache.TryGetValue(ipAddress, out var hostname) && !string.IsNullOrEmpty(hostname)
                ? hostname
                : null;
        }

        /// <summary>
        /// Enrich process information for a flow.
        /// </summary>
        public void EnrichProcess(FlowRecord flow)
        {
            if (flow.ProcessId <= 0)
            {
                flow.ProcessName = "System";
                return;
            }

            // Check cache first
            if (_processCache.TryGetValue(flow.ProcessId, out var cached))
            {
                flow.ProcessName = cached.Name;
                flow.ProcessPath = cached.Path;
                return;
            }

            try
            {
                using var proc = Process.GetProcessById(flow.ProcessId);
                var info = new ProcessInfo
                {
                    Name = proc.ProcessName,
                    Path = GetProcessPath(proc)
                };

                _processCache[flow.ProcessId] = info;
                flow.ProcessName = info.Name;
                flow.ProcessPath = info.Path;
            }
            catch
            {
                // Process not found or access denied
                flow.ProcessName = "Unknown";
                // Don't cache failures - process might appear later
            }
        }

        /// <summary>
        /// Get process info synchronously (from cache or live lookup).
        /// </summary>
        public (string Name, string? Path) GetProcessInfo(int processId)
        {
            if (processId <= 0)
                return ("System", null);

            if (_processCache.TryGetValue(processId, out var cached))
                return (cached.Name, cached.Path);

            try
            {
                using var proc = Process.GetProcessById(processId);
                var info = new ProcessInfo
                {
                    Name = proc.ProcessName,
                    Path = GetProcessPath(proc)
                };
                _processCache[processId] = info;
                return (info.Name, info.Path);
            }
            catch
            {
                return ("Unknown", null);
            }
        }

        private static string GetProcessPath(Process proc)
        {
            try
            {
                return proc.MainModule?.FileName ?? "";
            }
            catch
            {
                // Access denied to main module (common for system processes)
                return "";
            }
        }

        /// <summary>
        /// Enrich code signing information for a flow's process.
        /// </summary>
        public void EnrichSigner(FlowRecord flow)
        {
            if (string.IsNullOrEmpty(flow.ProcessPath))
                return;

            // Check cache first
            if (_signerCache.TryGetValue(flow.ProcessPath, out var cached))
            {
                flow.ProcessSigner = cached;
                return;
            }

            try
            {
                var signer = GetFileSigner(flow.ProcessPath);
                _signerCache[flow.ProcessPath] = signer;
                flow.ProcessSigner = signer;
            }
            catch
            {
                _signerCache[flow.ProcessPath] = null;
                flow.ProcessSigner = "Unsigned";
            }
        }

        /// <summary>
        /// Get code signer for a file path.
        /// </summary>
        public string? GetFileSigner(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                return null;

            if (_signerCache.TryGetValue(filePath, out var cached))
                return cached;

            try
            {
                using var cert = X509Certificate.CreateFromSignedFile(filePath);
                var subject = cert.Subject;

                // Extract CN from subject
                var match = Regex.Match(subject, @"CN=([^,]+)");
                var signer = match.Success ? match.Groups[1].Value.Trim('"') : subject;

                _signerCache[filePath] = signer;
                return signer;
            }
            catch
            {
                _signerCache[filePath] = null;
                return null;
            }
        }

        /// <summary>
        /// Clear all caches (useful after extended periods or for memory management).
        /// </summary>
        private void EnrichGeo(FlowRecord flow)
        {
            if (string.IsNullOrEmpty(flow.RemoteCountry))
            {
                flow.RemoteCountry = GetCountry(flow.RemoteAddress);
            }
        }

        private void LoadGeoDb()
        {
            try
            {
                var csvPath = Path.Combine(AppContext.BaseDirectory, "Assets", "GeoLite2-Country-Blocks-IPv4.csv");
                if (!File.Exists(csvPath)) return;

                _geoRanges = File.ReadLines(csvPath).Skip(1)
                    .Select(line =>
                    {
                        var parts = line.Split(',');
                        if (parts.Length < 3 || !ParseCidr(parts[0], out var s, out var e)) return null;
                        return new GeoRange(s, e, parts[2].Trim('"'));
                    })
                    .Where(r => r != null)
                    .Cast<GeoRange>()
                    .ToList();

                _geoRanges.Sort((a, b) => a.Start.CompareTo(b.Start));
            }
            catch
            {
                // Ignore load errors
            }
        }

        private bool ParseCidr(string cidrStr, out uint start, out uint end)
        {
            start = 0;
            end = 0;
            var slashIdx = cidrStr.IndexOf('/');
            if (slashIdx == -1) return false;
            if (!IPAddress.TryParse(cidrStr[..slashIdx], out var ip)) return false;
            var bytes = ip.GetAddressBytes();
            Array.Reverse(bytes);
            uint ipNum = BitConverter.ToUInt32(bytes, 0);
            if (!int.TryParse(cidrStr[(slashIdx + 1)..], out int bits) || bits < 0 || bits > 32) return false;
            uint mask = bits == 0 ? 0u : 0xFFFFFFFFu << (32 - bits);
            start = ipNum & mask;
            end = bits == 32 ? start : start | ~mask;
            return true;
        }

        public string? GetCountry(string ipAddress)
        {
            if (_geoCache.TryGetValue(ipAddress, out var cached) && cached != null)
                return cached;
            if (_geoRanges.Count == 0)
                LoadGeoDb();
            string? country = null;
            if (IPAddress.TryParse(ipAddress, out var addr) && addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var bytes = addr.GetAddressBytes();
                Array.Reverse(bytes);
                uint ipNum = BitConverter.ToUInt32(bytes, 0);
                // Binary search for the largest index where _geoRanges[mid].Start <= ipNum
                int left = 0, right = _geoRanges.Count - 1;
                while (left <= right)
                {
                    int mid = left + (right - left) / 2;
                    if (_geoRanges[mid].Start <= ipNum)
                    {
                        left = mid + 1;
                    }
                    else
                    {
                        right = mid - 1;
                    }
                }
                int candidateIdx = right;
                if (candidateIdx >= 0 && ipNum >= _geoRanges[candidateIdx].Start && ipNum <= _geoRanges[candidateIdx].End)
                {
                    country = _geoRanges[candidateIdx].Country;
                }
            }
            _geoCache[ipAddress] = country;
            return country;
        }

        public void ClearCaches()
        {
            _dnsCache.Clear();
            _processCache.Clear();
            _signerCache.Clear();
            _geoCache.Clear();
        }

        /// <summary>
        /// Clear expired process cache entries (processes that no longer exist).
        /// </summary>
        public void ClearStaleProcessCache()
        {
            var stalePids = new System.Collections.Generic.List<int>();

            foreach (var pid in _processCache.Keys)
            {
                try
                {
                    using var _ = Process.GetProcessById(pid);
                }
                catch
                {
                    stalePids.Add(pid);
                }
            }

            foreach (var pid in stalePids)
            {
                _processCache.TryRemove(pid, out _);
            }
        }

        /// <summary>
        /// Get cache statistics for monitoring.
        /// </summary>
        public (int DnsEntries, int ProcessEntries, int SignerEntries) GetCacheStats()
        {
            return (_dnsCache.Count, _processCache.Count, _signerCache.Count);
        }

        private sealed class ProcessInfo
        {
            public string Name { get; init; } = "";
            public string Path { get; init; } = "";
        }
    }
}
