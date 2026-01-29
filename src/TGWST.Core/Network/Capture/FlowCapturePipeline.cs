using System;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace TGWST.Core.Network.Capture
{
    /// <summary>
    /// Unified capture pipeline that merges events from ETW, IP Helper, and WFP sources.
    /// Automatically falls back to IP Helper polling if ETW is unavailable (non-admin).
    /// </summary>
    public sealed class FlowCapturePipeline : IDisposable
    {
        private readonly Channel<RawNetworkEvent> _outputChannel;
        private readonly EtwNetCapture? _etwCapture;
        private readonly IpHelperPoller _ipHelperPoller;
        private readonly CancellationTokenSource _cts = new();
        private Task? _etwMergeTask;
        private Task? _ipHelperMergeTask;
        private bool _disposed;
        private bool _isRunning;

        /// <summary>
        /// Unified event stream from all capture sources.
        /// </summary>
        public ChannelReader<RawNetworkEvent> Events => _outputChannel.Reader;

        /// <summary>
        /// Indicates if the pipeline is actively capturing.
        /// </summary>
        public bool IsRunning => _isRunning;

        /// <summary>
        /// Indicates if ETW capture is active (requires admin).
        /// </summary>
        public bool IsEtwActive => _etwCapture?.IsRunning ?? false;

        /// <summary>
        /// Indicates if running with limited capabilities (non-admin).
        /// </summary>
        public bool IsLimitedMode { get; private set; }

        public FlowCapturePipeline()
        {
            _outputChannel = Channel.CreateBounded<RawNetworkEvent>(
                new BoundedChannelOptions(20000)
                {
                    FullMode = BoundedChannelFullMode.DropOldest,
                    SingleReader = true,
                    SingleWriter = false
                });

            _ipHelperPoller = new IpHelperPoller();

            // Only create ETW capture if we have admin privileges
            if (EtwNetCapture.HasAdminPrivileges())
            {
                try
                {
                    _etwCapture = new EtwNetCapture();
                }
                catch
                {
                    // ETW initialization failed, will use IP Helper only
                    _etwCapture = null;
                }
            }
        }

        /// <summary>
        /// Start the capture pipeline.
        /// </summary>
        /// <param name="ipHelperPollInterval">Interval for IP Helper polling (for connection state).</param>
        public void Start(TimeSpan? ipHelperPollInterval = null)
        {
            if (_isRunning)
                throw new InvalidOperationException("Pipeline already running");

            _isRunning = true;

            // Start ETW capture if available
            if (_etwCapture != null)
            {
                try
                {
                    _etwCapture.Start();
                    _etwMergeTask = MergeEtwEventsAsync(_cts.Token);
                    IsLimitedMode = false;
                }
                catch
                {
                    // ETW start failed, fall back to IP Helper only
                    IsLimitedMode = true;
                }
            }
            else
            {
                IsLimitedMode = true;
            }

            // Start IP Helper polling (always enabled for connection state)
            var pollInterval = ipHelperPollInterval ?? TimeSpan.FromSeconds(2);
            _ipHelperPoller.Start(pollInterval);
            _ipHelperMergeTask = MergeIpHelperSnapshotsAsync(_cts.Token);
        }

        /// <summary>
        /// Get a single snapshot of current connections (synchronous).
        /// </summary>
        public ConnectionSnapshot GetCurrentConnections()
        {
            return _ipHelperPoller.GetCurrentConnections();
        }

        private async Task MergeEtwEventsAsync(CancellationToken ct)
        {
            if (_etwCapture == null) return;

            try
            {
                await foreach (var evt in _etwCapture.Events.ReadAllAsync(ct))
                {
                    await _outputChannel.Writer.WriteAsync(evt, ct);
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown
            }
            catch (ChannelClosedException)
            {
                // Channel closed
            }
        }

        private async Task MergeIpHelperSnapshotsAsync(CancellationToken ct)
        {
            try
            {
                ConnectionSnapshot? previousSnapshot = null;

                await foreach (var snapshot in _ipHelperPoller.Snapshots.ReadAllAsync(ct))
                {
                    // Convert connection state changes to events
                    if (previousSnapshot != null)
                    {
                        EmitConnectionDeltaEvents(previousSnapshot, snapshot);
                    }

                    previousSnapshot = snapshot;
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown
            }
            catch (ChannelClosedException)
            {
                // Channel closed
            }
        }

        private void EmitConnectionDeltaEvents(ConnectionSnapshot previous, ConnectionSnapshot current)
        {
            // Build lookup of previous connections
            var prevSet = new System.Collections.Generic.HashSet<string>();
            foreach (var conn in previous.Connections)
            {
                var key = $"{conn.Protocol}|{conn.LocalAddress}:{conn.LocalPort}|{conn.RemoteAddress}:{conn.RemotePort}|{conn.ProcessId}";
                prevSet.Add(key);
            }

            // Find new connections
            foreach (var conn in current.Connections)
            {
                var key = $"{conn.Protocol}|{conn.LocalAddress}:{conn.LocalPort}|{conn.RemoteAddress}:{conn.RemotePort}|{conn.ProcessId}";
                if (!prevSet.Contains(key))
                {
                    // New connection detected
                    var eventType = conn.Protocol == "TCP" ? NetEventType.TcpConnect : NetEventType.UdpSend;
                    var evt = new RawNetworkEvent
                    {
                        Timestamp = current.Timestamp,
                        EventType = eventType,
                        ProcessId = conn.ProcessId,
                        LocalAddress = conn.LocalAddress,
                        LocalPort = conn.LocalPort,
                        RemoteAddress = conn.RemoteAddress,
                        RemotePort = conn.RemotePort
                    };

                    _outputChannel.Writer.TryWrite(evt);
                }
            }

            // Build lookup of current connections to find closed ones
            var currSet = new System.Collections.Generic.HashSet<string>();
            foreach (var conn in current.Connections)
            {
                var key = $"{conn.Protocol}|{conn.LocalAddress}:{conn.LocalPort}|{conn.RemoteAddress}:{conn.RemotePort}|{conn.ProcessId}";
                currSet.Add(key);
            }

            // Find closed connections
            foreach (var conn in previous.Connections)
            {
                var key = $"{conn.Protocol}|{conn.LocalAddress}:{conn.LocalPort}|{conn.RemoteAddress}:{conn.RemotePort}|{conn.ProcessId}";
                if (!currSet.Contains(key) && conn.Protocol == "TCP" && conn.State == TcpState.Established)
                {
                    // Connection closed
                    var evt = new RawNetworkEvent
                    {
                        Timestamp = current.Timestamp,
                        EventType = NetEventType.TcpDisconnect,
                        ProcessId = conn.ProcessId,
                        LocalAddress = conn.LocalAddress,
                        LocalPort = conn.LocalPort,
                        RemoteAddress = conn.RemoteAddress,
                        RemotePort = conn.RemotePort
                    };

                    _outputChannel.Writer.TryWrite(evt);
                }
            }
        }

        /// <summary>
        /// Stop the capture pipeline.
        /// </summary>
        public void Stop()
        {
            if (!_isRunning) return;

            _cts.Cancel();
            _etwCapture?.Stop();
            _isRunning = false;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            _cts.Cancel();
            _outputChannel.Writer.Complete();

            _etwCapture?.Dispose();
            _ipHelperPoller.Dispose();

            try
            {
                Task.WhenAll(
                    _etwMergeTask ?? Task.CompletedTask,
                    _ipHelperMergeTask ?? Task.CompletedTask
                ).Wait(TimeSpan.FromSeconds(2));
            }
            catch
            {
                // Ignore wait errors
            }

            _cts.Dispose();
        }
    }
}
