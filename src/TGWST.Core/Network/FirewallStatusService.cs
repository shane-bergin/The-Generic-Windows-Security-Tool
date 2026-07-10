using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
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
            var output = await RunPowerShellAsync();
            return Parse(output);
        }

        private static async Task<string> RunPowerShellAsync()
        {
            return await Task.Run(() =>
            {
                const string script = "@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Enabled = [bool]$_.Enabled; DefaultInboundAction = [string]$_.DefaultInboundAction; DefaultOutboundAction = [string]$_.DefaultOutboundAction } }) | ConvertTo-Json -Compress";
                var psi = new ProcessStartInfo
                {
                    FileName = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                psi.ArgumentList.Add("-NoLogo");
                psi.ArgumentList.Add("-NoProfile");
                psi.ArgumentList.Add("-NonInteractive");
                psi.ArgumentList.Add("-Command");
                psi.ArgumentList.Add(script);

                using var p = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start Windows PowerShell for firewall posture collection.");
                var stdout = p.StandardOutput.ReadToEnd();
                var stderr = p.StandardError.ReadToEnd();
                p.WaitForExit();
                if (p.ExitCode != 0)
                {
                    var error = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
                    throw new InvalidOperationException($"Get-NetFirewallProfile failed: {Trim(error)}");
                }

                return stdout;
            });
        }

        internal static IReadOnlyList<FirewallProfileStatus> Parse(string output)
        {
            var result = new List<FirewallProfileStatus>();
            if (string.IsNullOrWhiteSpace(output))
            {
                throw new InvalidOperationException("Get-NetFirewallProfile returned no data.");
            }

            using var document = JsonDocument.Parse(output);
            var profiles = document.RootElement.ValueKind == JsonValueKind.Array
                ? document.RootElement.EnumerateArray().ToArray()
                : [document.RootElement];
            foreach (var profile in profiles)
            {
                var name = ReadString(profile, "Name") ?? "Unknown";
                var enabled = ReadBool(profile, "Enabled");
                var inbound = ReadString(profile, "DefaultInboundAction") ?? "Unknown";
                var outbound = ReadString(profile, "DefaultOutboundAction") ?? "Unknown";
                var inboundBlocked = inbound.Equals("Block", StringComparison.OrdinalIgnoreCase) || inbound.Equals("4", StringComparison.Ordinal);
                result.Add(new FirewallProfileStatus
                {
                    Profile = name,
                    State = enabled switch { true => "ON", false => "OFF", null => "UNKNOWN" },
                    Policy = $"{inbound}Inbound,{outbound}Outbound",
                    IsVulnerable = enabled != true || !inboundBlocked
                });
            }

            if (result.Count == 0)
            {
                throw new InvalidOperationException("Get-NetFirewallProfile returned no profile records.");
            }

            return result;
        }

        private static string? ReadString(JsonElement element, string name)
        {
            return element.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String
                ? property.GetString()
                : null;
        }

        private static bool? ReadBool(JsonElement element, string name)
        {
            return element.TryGetProperty(name, out var property) && property.ValueKind is JsonValueKind.True or JsonValueKind.False
                ? property.GetBoolean()
                : null;
        }

        private static string Trim(string value)
        {
            var normalized = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
            return normalized.Length <= 220 ? normalized : normalized[..220];
        }
    }
}
