using System;
using System.Collections.Generic;

namespace TGWST.App.Services;

public static class NetworkProtocolCatalog
{
    private static readonly Dictionary<int, string> PortNames = new()
    {
        [20] = "FTP-DATA",
        [21] = "FTP",
        [22] = "SSH",
        [23] = "TELNET",
        [25] = "SMTP",
        [53] = "DNS",
        [67] = "DHCP",
        [68] = "DHCP",
        [80] = "HTTP",
        [110] = "POP3",
        [123] = "NTP",
        [135] = "MS-RPC",
        [137] = "NETBIOS-NS",
        [138] = "NETBIOS-DGM",
        [139] = "NETBIOS-SSN",
        [143] = "IMAP",
        [389] = "LDAP",
        [443] = "HTTPS",
        [445] = "SMB",
        [465] = "SMTPS",
        [500] = "IKE",
        [587] = "SMTP-SUBMIT",
        [636] = "LDAPS",
        [853] = "DNS-TLS",
        [993] = "IMAPS",
        [995] = "POP3S",
        [1433] = "MSSQL",
        [1521] = "ORACLE",
        [3306] = "MYSQL",
        [3389] = "RDP",
        [5432] = "POSTGRES",
        [5900] = "VNC",
        [5985] = "WINRM",
        [5986] = "WINRM-TLS"
    };

    public static string Classify(string transport, int localPort, int remotePort)
    {
        if (TryGetServiceName(remotePort, out var remoteService))
        {
            return RefineForTransport(transport, remotePort, remoteService);
        }

        if (TryGetServiceName(localPort, out var localService))
        {
            return RefineForTransport(transport, localPort, localService);
        }

        return localPort >= 49152 || remotePort >= 49152 ? "EPHEMERAL" : "UNMAPPED";
    }

    public static string BuildProtocolType(string transport, string service)
    {
        return string.IsNullOrWhiteSpace(service) || service == "UNMAPPED"
            ? transport.ToUpperInvariant()
            : $"{transport.ToUpperInvariant()} / {service.ToUpperInvariant()}";
    }

    public static string DescribeConcern(
        string transport,
        string service,
        int localPort,
        int remotePort,
        string localAddress,
        string remoteAddress,
        string state,
        string riskReason)
    {
        var endpoint = BuildEndpointRole(localPort, remotePort, localAddress, remoteAddress, state);
        var serviceConcern = service.ToUpperInvariant() switch
        {
            "DNS" => "DNS traffic is expected for name resolution. A wildcard local listener on UDP/TCP 53 is more concerning because exposed DNS services can be abused for tunneling, amplification, or unwanted resolver behavior.",
            "DNS-TLS" => "DNS over TLS can be normal privacy-preserving resolution. It deserves review when the process is unknown, because malware can use encrypted DNS to hide command-and-control lookups.",
            "SMB" => "SMB exposes Windows file sharing. If reachable from untrusted networks it can support credential relay, lateral movement, and data theft.",
            "RDP" => "RDP exposes interactive remote desktop access. Unexpected listeners or public remote sessions are brute-force and remote-access risk indicators.",
            "WINRM" or "WINRM-TLS" => "WinRM is Windows remote management. It is powerful for administration and equally powerful for lateral movement if exposed or enabled unexpectedly.",
            "MS-RPC" => "MS-RPC supports Windows service control and management traffic. External exposure can increase lateral movement and reconnaissance risk.",
            "NETBIOS-NS" or "NETBIOS-DGM" or "NETBIOS-SSN" => "NetBIOS is legacy Windows discovery and file-sharing support. On modern networks it can leak host information and assist credential attacks.",
            "LDAP" or "LDAPS" => "LDAP/LDAPS is directory service traffic. On a workstation it is often domain-related; unexpected exposure can leak identity infrastructure details.",
            "SSH" => "SSH is remote shell/file-transfer access. Expected on servers, unusual on many Windows clients unless an admin tool or developer service enabled it.",
            "TELNET" => "Telnet is clear-text remote shell traffic. Any active Telnet listener or session should be treated as unsafe unless you intentionally enabled it in a lab.",
            "FTP" or "FTP-DATA" => "FTP can expose credentials and files in clear text. Prefer SFTP/HTTPS and review any listener carefully.",
            "HTTP" or "HTTPS" or "QUIC/HTTPS" => "Web traffic is common. The concern rises when a local listener appears unexpectedly, or when an unknown process maintains sessions to unfamiliar public addresses.",
            "MSSQL" or "MYSQL" or "POSTGRES" or "ORACLE" => "Database ports should rarely be exposed from a workstation. Exposure can lead to credential guessing, data access, and service enumeration.",
            "VNC" => "VNC is remote screen/control access. Unexpected listeners are high-risk because they can allow interactive access to the machine.",
            "EPHEMERAL" => "Ephemeral ports are usually client-side temporary ports. They become interesting when paired with an unknown process or unfamiliar public remote endpoint.",
            "UNMAPPED" => "This port is not mapped in the local high-signal catalog. Inspect the owning process and remote endpoint before assuming it is benign or hostile.",
            _ => "This protocol or service can be legitimate when owned by an expected process. The concern depends on listener exposure, remote endpoint, and whether the process is trusted."
        };

        return $"{endpoint} {serviceConcern} Risk flags: {riskReason}.";
    }

    private static bool TryGetServiceName(int port, out string name)
    {
        if (PortNames.TryGetValue(port, out name!))
        {
            return true;
        }

        name = string.Empty;
        return false;
    }

    private static string RefineForTransport(string transport, int port, string service)
    {
        if (port == 443 && transport.Equals("UDP", StringComparison.OrdinalIgnoreCase))
        {
            return "QUIC/HTTPS";
        }

        return service;
    }

    private static string BuildEndpointRole(
        int localPort,
        int remotePort,
        string localAddress,
        string remoteAddress,
        string state)
    {
        if (state.Equals("LISTEN", StringComparison.OrdinalIgnoreCase))
        {
            return IsAnyAddress(localAddress)
                ? $"Local wildcard listener on port {localPort}."
                : $"Local listener on {localAddress}:{localPort}.";
        }

        if (remotePort > 0 && !string.IsNullOrWhiteSpace(remoteAddress) && remoteAddress != "*")
        {
            return $"Session between local {localAddress}:{localPort} and remote {remoteAddress}:{remotePort}.";
        }

        return $"Local socket on {localAddress}:{localPort}.";
    }

    private static bool IsAnyAddress(string address)
    {
        return string.IsNullOrWhiteSpace(address) ||
               address.Equals("0.0.0.0", StringComparison.OrdinalIgnoreCase) ||
               address.Equals("::", StringComparison.OrdinalIgnoreCase) ||
               address.Equals("*", StringComparison.OrdinalIgnoreCase);
    }
}
