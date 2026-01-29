using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace TGWST.App.Shell
{
    public static class AcronymExpander
    {
        private static readonly Dictionary<string, string> Map = new(StringComparer.OrdinalIgnoreCase)
        {
            ["WDAC"] = "Windows Defender Application Control",
            ["UMCI"] = "User Mode Code Integrity",
            ["HVCI"] = "Hypervisor-Protected Code Integrity",
            ["VBS"] = "Virtualization-based Security",
            ["VSM"] = "Virtual Secure Mode",
            ["ASR"] = "Attack Surface Reduction",
            ["TPM"] = "Trusted Platform Module",
            ["UEFI"] = "Unified Extensible Firmware Interface",
            ["LSA"] = "Local Security Authority",
            ["EDR"] = "Endpoint Detection and Response",
            ["AV"] = "Antivirus",
            ["SIEM"] = "Security Information and Event Management",
            ["MFA"] = "Multi-Factor Authentication",
            ["RDP"] = "Remote Desktop Protocol",
            ["SMB"] = "Server Message Block",
            ["TLS"] = "Transport Layer Security",
            ["NTLM"] = "NT LAN Manager"
        };

        private static readonly Regex Pattern = new(
            "\\b(" + string.Join("|", Map.Keys) + ")\\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public static string Expand(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return input;
            }

            return Pattern.Replace(input, match =>
            {
                if (Map.TryGetValue(match.Value, out var expanded))
                {
                    return expanded;
                }

                return match.Value;
            });
        }
    }
}
