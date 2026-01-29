using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace TGWST.Core.Network.Capture
{
    /// <summary>
    /// Polls IP Helper API for TCP/UDP connection tables.
    /// Works without elevation but provides connection state only (no bandwidth).
    /// </summary>
    public sealed class IpHelperPoller : IDisposable
    {
        #region P/Invoke Declarations

        private const int AF_INET = 2;
        private const int AF_INET6 = 23;

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref int pdwSize,
            bool bOrder,
            int ulAf,
            TCP_TABLE_CLASS tableClass,
            uint reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(
            IntPtr pUdpTable,
            ref int pdwSize,
            bool bOrder,
            int ulAf,
            UDP_TABLE_CLASS tableClass,
            uint reserved);

        private enum TCP_TABLE_CLASS
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        private enum UDP_TABLE_CLASS
        {
            UDP_TABLE_BASIC,
            UDP_TABLE_OWNER_PID,
            UDP_TABLE_OWNER_MODULE
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
            public uint dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            // Followed by MIB_TCPROW_OWNER_PID[] table
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDPROW_OWNER_PID
        {
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwOwningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            // Followed by MIB_UDPROW_OWNER_PID[] table
        }

        #endregion

        private readonly CancellationTokenSource _cts = new();
        private readonly Channel<ConnectionSnapshot> _snapshotChannel;
        private Task? _pollingTask;
        private bool _disposed;

        public ChannelReader<ConnectionSnapshot> Snapshots => _snapshotChannel.Reader;

        public IpHelperPoller()
        {
            _snapshotChannel = Channel.CreateBounded<ConnectionSnapshot>(
                new BoundedChannelOptions(100)
                {
                    FullMode = BoundedChannelFullMode.DropOldest,
                    SingleReader = true,
                    SingleWriter = true
                });
        }

        /// <summary>
        /// Start polling connection tables at the specified interval.
        /// </summary>
        public void Start(TimeSpan pollInterval)
        {
            if (_pollingTask != null)
                throw new InvalidOperationException("Polling already started");

            _pollingTask = Task.Run(async () =>
            {
                while (!_cts.IsCancellationRequested)
                {
                    try
                    {
                        var snapshot = GetCurrentConnections();
                        await _snapshotChannel.Writer.WriteAsync(snapshot, _cts.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch
                    {
                        // Log error but continue polling
                    }

                    try
                    {
                        await Task.Delay(pollInterval, _cts.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }
            });
        }

        /// <summary>
        /// Get a single snapshot of current connections synchronously.
        /// </summary>
        public ConnectionSnapshot GetCurrentConnections()
        {
            var connections = new List<ConnectionEntry>();

            // Get TCP connections
            GetTcpConnections(connections);

            // Get UDP endpoints
            GetUdpEndpoints(connections);

            // Resolve process names
            foreach (var conn in connections)
            {
                conn.ProcessName = GetProcessName(conn.ProcessId);
            }

            return new ConnectionSnapshot
            {
                Timestamp = DateTime.UtcNow,
                Connections = connections
            };
        }

        private void GetTcpConnections(List<ConnectionEntry> connections)
        {
            int size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);

            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedTcpTable(buffer, ref size, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0) == 0)
                {
                    var table = Marshal.PtrToStructure<MIB_TCPTABLE_OWNER_PID>(buffer);
                    var rowPtr = buffer + Marshal.SizeOf<uint>();
                    var rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                    for (int i = 0; i < table.dwNumEntries; i++)
                    {
                        var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);

                        connections.Add(new ConnectionEntry
                        {
                            Protocol = "TCP",
                            LocalAddress = new IPAddress(row.dwLocalAddr).ToString(),
                            LocalPort = NetworkToHostPort(row.dwLocalPort),
                            RemoteAddress = new IPAddress(row.dwRemoteAddr).ToString(),
                            RemotePort = NetworkToHostPort(row.dwRemotePort),
                            ProcessId = (int)row.dwOwningPid,
                            State = (TcpState)row.dwState
                        });

                        rowPtr += rowSize;
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private void GetUdpEndpoints(List<ConnectionEntry> connections)
        {
            int size = 0;
            GetExtendedUdpTable(IntPtr.Zero, ref size, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);

            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedUdpTable(buffer, ref size, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0) == 0)
                {
                    var table = Marshal.PtrToStructure<MIB_UDPTABLE_OWNER_PID>(buffer);
                    var rowPtr = buffer + Marshal.SizeOf<uint>();
                    var rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();

                    for (int i = 0; i < table.dwNumEntries; i++)
                    {
                        var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);

                        connections.Add(new ConnectionEntry
                        {
                            Protocol = "UDP",
                            LocalAddress = new IPAddress(row.dwLocalAddr).ToString(),
                            LocalPort = NetworkToHostPort(row.dwLocalPort),
                            RemoteAddress = "*",
                            RemotePort = 0,
                            ProcessId = (int)row.dwOwningPid,
                            State = TcpState.Listen // UDP is stateless, mark as listening
                        });

                        rowPtr += rowSize;
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static int NetworkToHostPort(uint port)
        {
            // Port is stored in network byte order (big-endian)
            return IPAddress.NetworkToHostOrder((short)(port & 0xFFFF));
        }

        private static string GetProcessName(int pid)
        {
            if (pid <= 0) return "System";
            try
            {
                using var proc = Process.GetProcessById(pid);
                return proc.ProcessName;
            }
            catch
            {
                return "Unknown";
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            _cts.Cancel();
            _snapshotChannel.Writer.Complete();

            try
            {
                _pollingTask?.Wait(TimeSpan.FromSeconds(2));
            }
            catch
            {
                // Ignore timeout
            }

            _cts.Dispose();
        }
    }
}
