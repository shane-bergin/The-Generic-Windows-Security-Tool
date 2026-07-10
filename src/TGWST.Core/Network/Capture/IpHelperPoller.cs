using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace TGWST.Core.Network.Capture
{
    public sealed class IpHelperPoller : IDisposable
    {
        private const int AF_INET = 2;
        private const uint ErrorSuccess = 0;
        private const uint ErrorInsufficientBuffer = 122;
        private const int MaxTableReadAttempts = 4;
        private const int MaxTableBufferBytes = 64 * 1024 * 1024;

        [DllImport("iphlpapi.dll", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref int pdwSize,
            bool bOrder,
            int ulAf,
            TCP_TABLE_CLASS tableClass,
            uint reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
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
        }

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
                    catch (Exception ex)
                    {
                        Trace.TraceWarning($"IP Helper polling failed: {ex.Message}");
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

        public ConnectionSnapshot GetCurrentConnections()
        {
            var connections = new List<ConnectionEntry>();

            GetTcpConnections(connections);
            GetUdpEndpoints(connections);

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
            var sizingResult = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (sizingResult is not (ErrorSuccess or ErrorInsufficientBuffer) || size <= 0)
            {
                throw new Win32Exception((int)sizingResult, "Unable to size the TCP owner table.");
            }

            for (var attempt = 0; attempt < MaxTableReadAttempts; attempt++)
            {
                ValidateBufferSize(size, "TCP");
                var allocatedSize = size;
                var buffer = Marshal.AllocHGlobal(allocatedSize);
                try
                {
                    var result = GetExtendedTcpTable(buffer, ref size, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
                    if (result == ErrorInsufficientBuffer && size > allocatedSize)
                    {
                        continue;
                    }

                    if (result != ErrorSuccess)
                    {
                        throw new Win32Exception((int)result, "Unable to read the TCP owner table.");
                    }

                    ParseTcpTable(buffer, Math.Min(size, allocatedSize), connections);
                    return;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            throw new InvalidOperationException("The TCP owner table changed too quickly to capture safely.");
        }

        private void GetUdpEndpoints(List<ConnectionEntry> connections)
        {
            int size = 0;
            var sizingResult = GetExtendedUdpTable(IntPtr.Zero, ref size, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            if (sizingResult is not (ErrorSuccess or ErrorInsufficientBuffer) || size <= 0)
            {
                throw new Win32Exception((int)sizingResult, "Unable to size the UDP owner table.");
            }

            for (var attempt = 0; attempt < MaxTableReadAttempts; attempt++)
            {
                ValidateBufferSize(size, "UDP");
                var allocatedSize = size;
                var buffer = Marshal.AllocHGlobal(allocatedSize);
                try
                {
                    var result = GetExtendedUdpTable(buffer, ref size, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
                    if (result == ErrorInsufficientBuffer && size > allocatedSize)
                    {
                        continue;
                    }

                    if (result != ErrorSuccess)
                    {
                        throw new Win32Exception((int)result, "Unable to read the UDP owner table.");
                    }

                    ParseUdpTable(buffer, Math.Min(size, allocatedSize), connections);
                    return;
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            throw new InvalidOperationException("The UDP owner table changed too quickly to capture safely.");
        }

        private static void ParseTcpTable(IntPtr buffer, int bufferSize, List<ConnectionEntry> connections)
        {
            var headerSize = Marshal.SizeOf<uint>();
            var rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            var table = Marshal.PtrToStructure<MIB_TCPTABLE_OWNER_PID>(buffer);
            ValidateRowCount(table.dwNumEntries, headerSize, rowSize, bufferSize, "TCP");
            var rowPtr = buffer + headerSize;
            for (var index = 0u; index < table.dwNumEntries; index++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                connections.Add(new ConnectionEntry
                {
                    Protocol = "TCP",
                    LocalAddress = new IPAddress(row.dwLocalAddr).ToString(),
                    LocalPort = NetworkToHostPort(row.dwLocalPort),
                    RemoteAddress = new IPAddress(row.dwRemoteAddr).ToString(),
                    RemotePort = NetworkToHostPort(row.dwRemotePort),
                    ProcessId = checked((int)row.dwOwningPid),
                    State = row.dwState is >= 1 and <= 12 ? (TcpState)row.dwState : TcpState.Closed
                });
                rowPtr += rowSize;
            }
        }

        private static void ParseUdpTable(IntPtr buffer, int bufferSize, List<ConnectionEntry> connections)
        {
            var headerSize = Marshal.SizeOf<uint>();
            var rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
            var table = Marshal.PtrToStructure<MIB_UDPTABLE_OWNER_PID>(buffer);
            ValidateRowCount(table.dwNumEntries, headerSize, rowSize, bufferSize, "UDP");
            var rowPtr = buffer + headerSize;
            for (var index = 0u; index < table.dwNumEntries; index++)
            {
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                connections.Add(new ConnectionEntry
                {
                    Protocol = "UDP",
                    LocalAddress = new IPAddress(row.dwLocalAddr).ToString(),
                    LocalPort = NetworkToHostPort(row.dwLocalPort),
                    RemoteAddress = "*",
                    RemotePort = 0,
                    ProcessId = checked((int)row.dwOwningPid),
                    State = TcpState.Bound
                });
                rowPtr += rowSize;
            }
        }

        internal static void ValidateRowCount(uint rowCount, int headerSize, int rowSize, int bufferSize, string tableName)
        {
            var required = checked((long)headerSize + ((long)rowCount * rowSize));
            if (bufferSize < headerSize || required > bufferSize)
            {
                throw new InvalidDataException($"{tableName} owner table row count exceeds the returned buffer.");
            }
        }

        private static void ValidateBufferSize(int bufferSize, string tableName)
        {
            if (bufferSize <= 0 || bufferSize > MaxTableBufferBytes)
            {
                throw new InvalidDataException($"{tableName} owner table requested an invalid buffer size ({bufferSize} bytes).");
            }
        }

        private static int NetworkToHostPort(uint port)
        {
            return (ushort)IPAddress.NetworkToHostOrder((short)(port & 0xFFFF));
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
            }

            _cts.Dispose();
        }
    }
}
