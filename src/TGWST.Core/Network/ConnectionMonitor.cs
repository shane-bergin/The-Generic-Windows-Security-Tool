using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace TGWST.Core.Network
{
    public sealed class ConnectionInfo
    {
        public string Protocol { get; init; } = "";
        public string LocalAddress { get; init; } = "";
        public string RemoteAddress { get; init; } = "";
        public string RemoteHost { get; set; } = "";
        public string State { get; init; } = "";
        public int Pid { get; init; }
        public string ProcessName { get; init; } = "";
    }

    public sealed class ConnectionMonitor
    {
        private readonly ConcurrentDictionary<string, string> _dnsCache = new(StringComparer.OrdinalIgnoreCase);

        public async Task<IReadOnlyList<ConnectionInfo>> GetConnectionsAsync()
        {
            var output = await Task.Run(() => RunNetstat());
            var parsed = Parse(output);

            var tasks = parsed.Select(async c =>
            {
                if (string.IsNullOrWhiteSpace(c.RemoteHost) && IPAddress.TryParse(c.RemoteAddress.Split(':').FirstOrDefault(), out var ip))
                {
                    if (_dnsCache.TryGetValue(ip.ToString(), out var cached))
                    {
                        c.RemoteHost = cached;
                    }
                    else
                    {
                        try
                        {
                            var host = (await Dns.GetHostEntryAsync(ip)).HostName;
                            _dnsCache[ip.ToString()] = host;
                            c.RemoteHost = host;
                        }
                        catch
                        {
                            _dnsCache[ip.ToString()] = "";
                        }
                    }
                }
            }).ToArray();

            await Task.WhenAll(tasks);
            return parsed;
        }

        public async Task<IReadOnlyList<ConnectionInfo>> GetTcpConnectionsAsync()
        {
            var all = await GetConnectionsAsync();
            return all.Where(c => string.Equals(c.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)).ToList();
        }

        private static string RunNetstat()
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netstat.exe",
                Arguments = "-ano",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var p = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start netstat.exe");
            var stdout = p.StandardOutput.ReadToEnd();
            var stderr = p.StandardError.ReadToEnd();
            p.WaitForExit();
            if (p.ExitCode != 0)
            {
                var error = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
                throw new InvalidOperationException($"netstat failed: {error}");
            }

            return stdout;
        }

        private static List<ConnectionInfo> Parse(string output)
        {
            var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            var list = new List<ConnectionInfo>();

            foreach (var line in lines)
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 4) continue;
                var proto = parts[0];
                if (!proto.Equals("TCP", StringComparison.OrdinalIgnoreCase) && !proto.Equals("UDP", StringComparison.OrdinalIgnoreCase))
                    continue;

                var local = parts[1];
                var remote = parts[2];
                var state = proto.Equals("TCP", StringComparison.OrdinalIgnoreCase) && parts.Length >= 5 ? parts[3] : "UDP";
                var pidStr = proto.Equals("TCP", StringComparison.OrdinalIgnoreCase) && parts.Length >= 5 ? parts[4] : parts[3];
                if (!int.TryParse(pidStr, out var pid)) pid = 0;

                var processName = ResolveProcessName(pid);

                list.Add(new ConnectionInfo
                {
                    Protocol = proto,
                    LocalAddress = local,
                    RemoteAddress = remote,
                    State = state,
                    Pid = pid,
                    ProcessName = processName,
                    RemoteHost = ""
                });
            }

            return list;
        }

        private static string ResolveProcessName(int pid)
        {
            if (pid <= 0) return "Unknown";
            try
            {
                return Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                return "Unknown";
            }
        }
    }
}
