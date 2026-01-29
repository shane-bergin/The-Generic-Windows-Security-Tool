using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace TGWST.Core.Network.Capture
{
    /// <summary>
    /// ETW-based network event capture using Microsoft-Windows-TCPIP and DNS providers.
    /// Requires Administrator privileges to create ETW sessions.
    /// Provides real-time flow events with byte counts.
    /// </summary>
    public sealed class EtwNetCapture : IDisposable
    {
        private const string SessionName = "TGWST-NetMon";

        // ETW Provider GUIDs
        private static readonly Guid TcpIpProvider = new("2F07E2EE-15DB-40F1-90EF-9D7BA282188A");
        private static readonly Guid DnsClientProvider = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");
        private static readonly Guid WfpProvider = new("0C478C5B-0351-41B1-8C58-4A6737DA32E3");

        private TraceEventSession? _session;
        private readonly Channel<RawNetworkEvent> _eventChannel;
        private Task? _processingTask;
        private bool _disposed;
        private bool _isRunning;

        public ChannelReader<RawNetworkEvent> Events => _eventChannel.Reader;
        public bool IsRunning => _isRunning;
        public bool RequiresElevation => true;

        public EtwNetCapture()
        {
            _eventChannel = Channel.CreateBounded<RawNetworkEvent>(
                new BoundedChannelOptions(10000)
                {
                    FullMode = BoundedChannelFullMode.DropOldest,
                    SingleReader = true,
                    SingleWriter = false
                });
        }

        /// <summary>
        /// Check if the current process has Administrator privileges.
        /// </summary>
        public static bool HasAdminPrivileges()
        {
            try
            {
                using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Start the ETW session and begin capturing network events.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown if not running as Administrator.</exception>
        public void Start()
        {
            if (_isRunning)
                throw new InvalidOperationException("ETW capture already running");

            if (!HasAdminPrivileges())
                throw new InvalidOperationException("ETW capture requires Administrator privileges");

            try
            {
                // Stop any existing session with the same name
                TraceEventSession.GetActiveSession(SessionName)?.Stop(true);
            }
            catch
            {
                // Ignore errors stopping old session
            }

            _session = new TraceEventSession(SessionName, TraceEventSessionOptions.Create);

            // Enable TCP/IP provider for connection and data transfer events
            // Keywords: 0x80000000 includes network events
            _session.EnableProvider(TcpIpProvider, TraceEventLevel.Informational, 0x80000000);

            // Enable DNS client provider for query resolution
            _session.EnableProvider(DnsClientProvider, TraceEventLevel.Informational);

            // Subscribe to all dynamic events
            _session.Source.Dynamic.All += OnEvent;

            _isRunning = true;

            // Start processing on background thread
            _processingTask = Task.Run(() =>
            {
                try
                {
                    _session.Source.Process();
                }
                catch (Exception)
                {
                    // Session stopped or disposed
                }
                finally
                {
                    _isRunning = false;
                }
            });
        }

        private void OnEvent(TraceEvent evt)
        {
            if (_disposed) return;

            try
            {
                RawNetworkEvent? netEvent = null;

                // Parse based on provider and event ID
                if (evt.ProviderGuid == TcpIpProvider)
                {
                    netEvent = ParseTcpIpEvent(evt);
                }
                else if (evt.ProviderGuid == DnsClientProvider)
                {
                    netEvent = ParseDnsEvent(evt);
                }

                if (netEvent != null)
                {
                    _eventChannel.Writer.TryWrite(netEvent);
                }
            }
            catch
            {
                // Ignore parsing errors for individual events
            }
        }

        private RawNetworkEvent? ParseTcpIpEvent(TraceEvent evt)
        {
            // Microsoft-Windows-TCPIP Event IDs:
            // 1001 - TcpConnectAttempt
            // 1002 - TcpDisconnect
            // 1003 - TcpAccept
            // 1011 - TcpDataSent
            // 1012 - TcpDataReceived
            // 1021 - UdpSendMessage
            // 1022 - UdpReceiveMessage

            return (int)evt.ID switch
            {
                1001 => ParseTcpConnect(evt),
                1002 => ParseTcpDisconnect(evt),
                1003 => ParseTcpAccept(evt),
                1011 => ParseTcpDataSent(evt),
                1012 => ParseTcpDataReceived(evt),
                1021 => ParseUdpSend(evt),
                1022 => ParseUdpReceive(evt),
                _ => null
            };
        }

        private RawNetworkEvent? ParseTcpConnect(TraceEvent evt)
        {
            return new RawNetworkEvent
            {
                Timestamp = evt.TimeStamp,
                EventType = NetEventType.TcpConnect,
                ProcessId = evt.ProcessID,
                LocalAddress = GetPayloadString(evt, "saddr") ?? GetPayloadString(evt, "LocalAddr") ?? "",
                LocalPort = GetPayloadInt(evt, "sport") ?? GetPayloadInt(evt, "LocalPort") ?? 0,
                RemoteAddress = GetPayloadString(evt, "daddr") ?? GetPayloadString(evt, "RemoteAddr") ?? "",
                RemotePort = GetPayloadInt(evt, "dport") ?? GetPayloadInt(evt, "RemotePort") ?? 0
            };
        }

        private RawNetworkEvent? ParseTcpDisconnect(TraceEvent evt)
        {
            return new RawNetworkEvent
            {
                Timestamp = evt.TimeStamp,
                EventType = NetEventType.TcpDisconnect,
                ProcessId = evt.ProcessID,
                LocalAddress = GetPayloadString(evt, "saddr") ?? GetPayloadString(evt, "LocalAddr") ?? "",
                LocalPort = GetPayloadInt(evt, "sport") ?? GetPayloadInt(evt, "LocalPort") ?? 0,
                RemoteAddress = GetPayloadString(evt, "daddr") ?? GetPayloadString(evt, "RemoteAddr") ?? "",
                RemotePort = GetPayloadInt(evt, "dport") ?? GetPayloadInt(evt, "RemotePort") ?? 0
            };
        }

        private RawNetworkEvent? ParseTcpAccept(TraceEvent evt)
        {
            return new RawNetworkEvent
            {
                Timestamp = evt.TimeStamp,
                EventType = NetEventType.TcpAccept,
                ProcessId = evt.ProcessID,
                LocalAddress = GetPayloadString(evt, "saddr") ?? GetPayloadString(evt, "LocalAddr") ?? "",
                LocalPort = GetPayloadInt(evt, "sport") ?? GetPayloadInt(evt, "LocalPort") ?? 0,
                RemoteAddress = GetPayloadString(evt, "daddr") ?? GetPayloadString(evt, "RemoteAddr") ?? "",
                RemotePort = GetPayloadInt(evt, "dport") ?? GetPayloadInt(evt, "RemotePort") ?? 0
            };
        }

        private RawNetworkEvent? ParseTcpDataSent(TraceEvent evt)
        {
            var size = GetPayloadLong(evt, "size") ?? GetPayloadLong(evt, "BytesSent") ?? 0;
            if (size == 0) return null;

            return new RawNetworkEvent
            {
                Timestamp = evt.TimeStamp,
                EventType = NetEventType.TcpSend,
                ProcessId = evt.ProcessID,
                LocalAddress = GetPayloadString(evt, "saddr") ?? GetPayloadString(evt, "LocalAddr") ?? "",
                LocalPort = GetPayloadInt(evt, "sport") ?? GetPayloadInt(evt, "LocalPort") ?? 0,
                RemoteAddress = GetPayloadString(evt, "daddr") ?? GetPayloadString(evt, "RemoteAddr") ?? "",
                RemotePort = GetPayloadInt(evt, "dport") ?? GetPayloadInt(evt, "RemotePort") ?? 0,
                BytesSent = size
            };
        }

        private RawNetworkEvent? ParseTcpDataReceived(TraceEvent evt)
        {
            var size = GetPayloadLong(evt, "size") ?? GetPayloadLong(evt, "BytesReceived") ?? 0;
            if (size == 0) return null;

            return new RawNetworkEvent
            {
                Timestamp = evt.TimeStamp,
                EventType = NetEventType.TcpReceive,
                ProcessId = evt.ProcessID,
                LocalAddress = GetPayloadString(evt, "saddr") ?? GetPayloadString(evt, "LocalAddr") ?? "",
                LocalPort = GetPayloadInt(evt, "sport") ?? GetPayloadInt(evt, "LocalPort") ?? 0,
                RemoteAddress = GetPayloadString(evt, "daddr") ?? GetPayloadString(evt, "RemoteAddr") ?? "",
                RemotePort = GetPayloadInt(evt, "dport") ?? GetPayloadInt(evt, "RemotePort") ?? 0,
                BytesReceived = size
            };
        }

        private RawNetworkEvent? ParseUdpSend(TraceEvent evt)
        {
            var size = GetPayloadLong(evt, "size") ?? GetPayloadLong(evt, "BytesSent") ?? 0;

            return new RawNetworkEvent
            {
                Timestamp = evt.TimeStamp,
                EventType = NetEventType.UdpSend,
                ProcessId = evt.ProcessID,
                LocalAddress = GetPayloadString(evt, "saddr") ?? GetPayloadString(evt, "LocalAddr") ?? "",
                LocalPort = GetPayloadInt(evt, "sport") ?? GetPayloadInt(evt, "LocalPort") ?? 0,
                RemoteAddress = GetPayloadString(evt, "daddr") ?? GetPayloadString(evt, "RemoteAddr") ?? "",
                RemotePort = GetPayloadInt(evt, "dport") ?? GetPayloadInt(evt, "RemotePort") ?? 0,
                BytesSent = size
            };
        }

        private RawNetworkEvent? ParseUdpReceive(TraceEvent evt)
        {
            var size = GetPayloadLong(evt, "size") ?? GetPayloadLong(evt, "BytesReceived") ?? 0;

            return new RawNetworkEvent
            {
                Timestamp = evt.TimeStamp,
                EventType = NetEventType.UdpReceive,
                ProcessId = evt.ProcessID,
                LocalAddress = GetPayloadString(evt, "saddr") ?? GetPayloadString(evt, "LocalAddr") ?? "",
                LocalPort = GetPayloadInt(evt, "sport") ?? GetPayloadInt(evt, "LocalPort") ?? 0,
                RemoteAddress = GetPayloadString(evt, "daddr") ?? GetPayloadString(evt, "RemoteAddr") ?? "",
                RemotePort = GetPayloadInt(evt, "dport") ?? GetPayloadInt(evt, "RemotePort") ?? 0,
                BytesReceived = size
            };
        }

        private RawNetworkEvent? ParseDnsEvent(TraceEvent evt)
        {
            // Microsoft-Windows-DNS-Client Event IDs:
            // 3006 - DNS query sent
            // 3008 - DNS query completed
            // 3020 - DNS response received

            return (int)evt.ID switch
            {
                3006 or 3008 => ParseDnsQuery(evt),
                3020 => ParseDnsResponse(evt),
                _ => null
            };
        }

        private RawNetworkEvent? ParseDnsQuery(TraceEvent evt)
        {
            var queryName = GetPayloadString(evt, "QueryName") ?? GetPayloadString(evt, "DnsName");
            if (string.IsNullOrEmpty(queryName)) return null;

            return new RawNetworkEvent
            {
                Timestamp = evt.TimeStamp,
                EventType = NetEventType.DnsQuery,
                ProcessId = evt.ProcessID,
                DnsQuery = queryName
            };
        }

        private RawNetworkEvent? ParseDnsResponse(TraceEvent evt)
        {
            var queryName = GetPayloadString(evt, "QueryName") ?? GetPayloadString(evt, "DnsName");
            var result = GetPayloadString(evt, "QueryResult") ?? GetPayloadString(evt, "IpAddress");

            return new RawNetworkEvent
            {
                Timestamp = evt.TimeStamp,
                EventType = NetEventType.DnsResponse,
                ProcessId = evt.ProcessID,
                DnsQuery = queryName,
                DnsResponse = result
            };
        }

        #region Payload Helpers

        private static string? GetPayloadString(TraceEvent evt, string name)
        {
            try
            {
                var value = evt.PayloadByName(name);
                return value?.ToString();
            }
            catch
            {
                return null;
            }
        }

        private static int? GetPayloadInt(TraceEvent evt, string name)
        {
            try
            {
                var value = evt.PayloadByName(name);
                if (value == null) return null;
                return Convert.ToInt32(value);
            }
            catch
            {
                return null;
            }
        }

        private static long? GetPayloadLong(TraceEvent evt, string name)
        {
            try
            {
                var value = evt.PayloadByName(name);
                if (value == null) return null;
                return Convert.ToInt64(value);
            }
            catch
            {
                return null;
            }
        }

        #endregion

        /// <summary>
        /// Stop the ETW session.
        /// </summary>
        public void Stop()
        {
            if (!_isRunning) return;

            _session?.Stop();
            _isRunning = false;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            _eventChannel.Writer.Complete();

            try
            {
                _session?.Stop();
            }
            catch
            {
                // Ignore stop errors
            }

            try
            {
                _processingTask?.Wait(TimeSpan.FromSeconds(2));
            }
            catch
            {
                // Ignore wait errors
            }

            _session?.Dispose();
        }
    }
}
