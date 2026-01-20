using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace TGWST.Core.Network
{
    public sealed class FirewallProfileStatus
    {
        public string Profile { get; init; } = "";
        public string State { get; init; } = "Unknown";
        public string Policy { get; init; } = "Unknown";
        public bool IsVulnerable { get; init; }
    }

    public sealed class FirewallStatusService
    {
        public async Task<IReadOnlyList<FirewallProfileStatus>> GetStatusAsync()
        {
            var output = await RunNetshAsync("advfirewall show allprofiles");
            return Parse(output);
        }

        private static async Task<string> RunNetshAsync(string args)
        {
            return await Task.Run(() =>
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = args,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var p = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start netsh.");
                var stdout = p.StandardOutput.ReadToEnd();
                var stderr = p.StandardError.ReadToEnd();
                p.WaitForExit();
                if (p.ExitCode != 0)
                {
                    var error = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
                    throw new InvalidOperationException($"netsh failed: {error}");
                }
                return stdout;
            });
        }

        private static IReadOnlyList<FirewallProfileStatus> Parse(string output)
        {
            var result = new List<FirewallProfileStatus>();
            var sections = Regex.Split(output, @"\r?\n(?=[A-Za-z]+ Profile Settings)", RegexOptions.Multiline)
                                .Where(s => s.Contains("Profile Settings", StringComparison.OrdinalIgnoreCase));

            foreach (var section in sections)
            {
                var lines = section.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                var header = lines.FirstOrDefault(l => l.Contains("Profile Settings", StringComparison.OrdinalIgnoreCase)) ?? "Profile";
                var profile = header.Replace("Profile Settings", "", StringComparison.OrdinalIgnoreCase).Trim();
                var state = ExtractValue(lines, "State") ?? "Unknown";
                var policy = ExtractValue(lines, "Firewall Policy") ?? "Unknown";

                var inboundBlocked = policy.Contains("BlockInbound", StringComparison.OrdinalIgnoreCase);
                var outboundAllowed = policy.Contains("AllowOutbound", StringComparison.OrdinalIgnoreCase);
                var enabled = state.Equals("ON", StringComparison.OrdinalIgnoreCase);
                var vulnerable = !(enabled && inboundBlocked && outboundAllowed);

                result.Add(new FirewallProfileStatus
                {
                    Profile = string.IsNullOrWhiteSpace(profile) ? "Unknown" : profile,
                    State = state,
                    Policy = policy,
                    IsVulnerable = vulnerable
                });
            }

            return result;
        }

        private static string? ExtractValue(IEnumerable<string> lines, string key)
        {
            foreach (var line in lines)
            {
                if (!line.TrimStart().StartsWith(key, StringComparison.OrdinalIgnoreCase)) continue;
                var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2) return parts[^1];
            }
            return null;
        }
    }
}
