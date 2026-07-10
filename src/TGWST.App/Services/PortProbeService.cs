using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TGWST.App.ViewModels;

namespace TGWST.App.Services;

public sealed class PortProbeService
{
    private static readonly int[] HighSignalPorts =
    [
        21, 22, 23, 25, 53, 80, 90, 135, 139, 389, 443, 445, 636, 1433, 1521,
        3306, 3389, 5432, 5900, 5985, 5986
    ];

    public async Task<IReadOnlyList<PortProbeRow>> ProbeLocalExposureAsync(CancellationToken ct = default)
    {
        var endpoints = GetProbeAddresses()
            .SelectMany(address => HighSignalPorts.Select(port => new { address, port }))
            .ToArray();
        using var gate = new SemaphoreSlim(32);
        var tasks = endpoints.Select(endpoint => ProbeOneAsync(endpoint.address, endpoint.port, gate, ct));
        var results = await Task.WhenAll(tasks).ConfigureAwait(false);

        return results
            .Where(row => row != null)
            .Cast<PortProbeRow>()
            .OrderByDescending(row => RiskRank(row.Risk))
            .ThenBy(row => row.Address, StringComparer.OrdinalIgnoreCase)
            .ThenBy(row => row.Port)
            .ToArray();
    }

    private static async Task<PortProbeRow?> ProbeOneAsync(
        IPAddress address,
        int port,
        SemaphoreSlim gate,
        CancellationToken ct)
    {
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            using var client = new TcpClient(address.AddressFamily);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromMilliseconds(350));

            try
            {
                await client.ConnectAsync(address, port, timeout.Token).ConfigureAwait(false);
            }
            catch
            {
                return null;
            }

            var service = NetworkProtocolCatalog.Classify("TCP", port, 0);
            var risk = ClassifyRisk(port);
            return new PortProbeRow(
                Address: address.ToString(),
                Port: port,
                Service: service,
                Status: "OPEN",
                Risk: risk,
                Detail: $"TCP connect probe succeeded locally on {address}:{port}. This means a local listener accepted a connection.",
                Recommendation: risk == "HIGH"
                    ? "Confirm the owning process in the Network tab. Disable the service or block inbound traffic if unexpected."
                    : "Expected only if you intentionally run this service locally.");
        }
        finally
        {
            gate.Release();
        }
    }

    private static IReadOnlyList<IPAddress> GetProbeAddresses()
    {
        var addresses = new HashSet<IPAddress>
        {
            IPAddress.Loopback
        };

        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.OperationalStatus != OperationalStatus.Up ||
                adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback)
            {
                continue;
            }

            foreach (var unicast in adapter.GetIPProperties().UnicastAddresses)
            {
                if (unicast.Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    addresses.Add(unicast.Address);
                }
            }
        }

        return addresses.ToArray();
    }

    private static string ClassifyRisk(int port)
    {
        return port is 21 or 22 or 23 or 90 or 135 or 139 or 445 or 3389 or 5900 or 5985 or 5986
            ? "HIGH"
            : port < 1024 ? "MEDIUM" : "INFO";
    }

    private static int RiskRank(string risk)
    {
        return risk switch
        {
            "HIGH" => 3,
            "MEDIUM" => 2,
            "INFO" => 1,
            _ => 0
        };
    }
}
