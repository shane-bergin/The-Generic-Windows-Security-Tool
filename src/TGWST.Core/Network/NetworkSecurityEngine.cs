using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.Core.Network;

public sealed class NetworkSecurityEngine
{
private static void RunCmd(string cmd)
{
using var p = Process.Start(new ProcessStartInfo
{
FileName = "cmd.exe",
Arguments = "/c " + cmd,
UseShellExecute = false,
CreateNoWindow = true
});
p?.WaitForExit();
}

public void EnableFortressMode()
{
    RunCmd("netsh advfirewall set allprofiles state on");
    RunCmd("netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound");
}

public void ResetFirewallToDefault()
{
    RunCmd("netsh advfirewall reset");
}

public ObservableCollection<PortInfo> GetListeningPorts()
{
    var list = new List<PortInfo>();

    foreach (var proto in new[] { "tcp", "udp" })
    {
        var lines = RunNetstat(proto);
        foreach (var line in lines)
        {
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4) continue;

            var protocol = parts[0].ToUpperInvariant();
            var local = parts[1];
            var pidPart = parts[^1];
            if (!int.TryParse(pidPart, out var pid)) pid = 0;

            var (addr, port) = ParseAddress(local);
            var processName = ResolveProcessName(pid);
            var serviceName = ResolveServiceName(pid);

            list.Add(new PortInfo(addr, port, protocol, pid, processName, serviceName));
        }
    }

    return new ObservableCollection<PortInfo>(list
        .OrderBy(p => p.Protocol)
        .ThenBy(p => p.Port)
        .ThenBy(p => p.Address));
}

public void BlockPort(int port, string protocol = "TCP")
{
    RunCmd($@"netsh advfirewall firewall add rule name=""TGWST Block {protocol} {port}"" dir=in action=block protocol={protocol} localport={port}");
}

public void KillPid(int pid)
{
    Process.GetProcessById(pid).Kill();
}

private const string RulePrefix = "TGWST Threat Block";

    public async Task ApplyThreatBlocklistsAsync(
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        progress?.Report("Downloading threat blocklists...");

    using var http = new HttpClient();

    var urls = new[]
    {
        "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt",
        "https://iplists.firehol.org/files/firehol_level1.netset"
    };

    var allLines = new List<string>();

    foreach (var url in urls)
    {
        ct.ThrowIfCancellationRequested();

        try
        {
            progress?.Report($"Fetching {url}...");
            var text = await http.GetStringAsync(url, ct).ConfigureAwait(false);
            var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            allLines.AddRange(lines);
        }
        catch
        {
            // ignore source failure
        }
    }

    var ipsOrCidrs = allLines
        .Select(l => l.Trim())
        .Where(l => l.Length > 0 && !l.StartsWith("#") && !l.StartsWith(";"))
        .ToArray();

    if (ipsOrCidrs.Length == 0)
    {
        progress?.Report("No IPs found in threat lists.");
        return;
    }

    progress?.Report($"Loaded {ipsOrCidrs.Length} IPs/networks. Creating firewall rules...");

    await Task.Run(() =>
    {
        RemoveThreatBlocklistRules();

        const int batchSize = 100;
        var batch = new List<string>();
        var ruleIndex = 1;

        foreach (var entry in ipsOrCidrs)
        {
            ct.ThrowIfCancellationRequested();
            batch.Add(entry);

            if (batch.Count >= batchSize)
            {
                AddThreatRuleBatch(batch, ruleIndex++);
                batch.Clear();
            }
        }

        if (batch.Count > 0)
        {
            AddThreatRuleBatch(batch, ruleIndex++);
        }

        progress?.Report($"Applied {ruleIndex - 1} threat block rules (outbound).");
    }, ct).ConfigureAwait(false);
}

public void RemoveThreatBlocklistRules()
{
    var tempFile = Path.GetTempFileName();
    try
    {
        RunCmd($@"netsh advfirewall firewall show rule name=all > ""{tempFile}""");

        var lines = File.ReadAllLines(tempFile);
        foreach (var line in lines)
        {
            if (!line.StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase))
                continue;

            var name = line["Rule Name:".Length..].Trim();
            if (!name.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
                continue;

            RunCmd($@"netsh advfirewall firewall delete rule name=""{name}""");
        }
    }
    catch
    {
        // best-effort cleanup
    }
    finally
    {
        try { File.Delete(tempFile); } catch { }
    }
}

private static void AddThreatRuleBatch(
    IEnumerable<string> batch,
    int index)
{
    var remoteIp = string.Join(",", batch);
    var cmd = $@"netsh advfirewall firewall add rule name=""{RulePrefix} #{index}"" dir=out action=block remoteip={remoteIp}";
    RunCmd(cmd);
}

    private static IEnumerable<string> RunNetstat(string protocol)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "netstat.exe",
            Arguments = protocol.Equals("tcp", StringComparison.OrdinalIgnoreCase) ? "-ano -p tcp" : "-ano -p udp",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        };
        using var p = Process.Start(psi);
        var output = p?.StandardOutput.ReadToEnd() ?? string.Empty;
        p?.WaitForExit();

        return output.Split('\n')
            .Select(l => l.Trim())
            .Where(l => l.StartsWith(protocol, StringComparison.OrdinalIgnoreCase))
            .ToArray();
    }

    private static (string address, int port) ParseAddress(string value)
    {
        try
        {
            if (value.StartsWith("["))
            {
                var idx = value.LastIndexOf("]:", StringComparison.Ordinal);
                var addr = value.Substring(1, idx - 1);
                var portStr = value[(idx + 2)..];
                return (addr, int.TryParse(portStr, out var port) ? port : 0);
            }

            var parts = value.Split(':');
            if (parts.Length >= 2 && int.TryParse(parts[^1], out var portNum))
            {
                var addr = string.Join(":", parts.Take(parts.Length - 1));
                return (addr, portNum);
            }
        }
        catch
        {
        }

        return (value, 0);
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

    private static string ResolveServiceName(int pid)
    {
        if (pid <= 0) return "Unknown";
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, ProcessId FROM Win32_Service WHERE ProcessId = " + pid);
            var svc = searcher.Get().Cast<ManagementObject>().FirstOrDefault();
            if (svc != null)
            {
                var name = svc["Name"]?.ToString();
                if (!string.IsNullOrWhiteSpace(name))
                    return name;
            }
        }
        catch
        {
        }

        return "Unknown";
    }
}
