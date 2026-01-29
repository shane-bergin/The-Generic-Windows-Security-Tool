using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TGWST.Core.Network.Capture;

namespace TGWST.Core.Network
{
    /// <summary>
    /// Aggregates raw network events into per-process and per-flow bandwidth statistics.
    /// Periodically archives completed flows to persistent storage.
    /// </summary>
    public sealed class FlowAggregator : IDisposable
    {
        private readonly ConcurrentDictionary<string, FlowRecord> _activeFlows = new();
        private readonly EnrichmentService _enrichment;
        private readonly FlowRecordStore? _store;
        private readonly Channel<RawNetworkEvent> _inputChannel;
        private readonly CancellationTokenSource _cts = new();
        private Task? _processingTask;
        private bool _disposed;

        // Aggregation window settings
        private readonly TimeSpan _windowSize;
        private readonly TimeSpan _idleTimeout;
        private DateTime _currentWindowStart = DateTime.UtcNow;
        private DateTime _lastCleanup = DateTime.UtcNow;

        /// <summary>
        /// Event fired when per-process totals are updated.
        /// </summary>
        public event Action<IReadOnlyDictionary<string, ProcessBandwidth>>? ProcessTotalsUpdated;

        /// <summary>
        /// Event fired when active flows change.
        /// </summary>
        public event Action<IReadOnlyList<FlowRecord>>? ActiveFlowsUpdated;

        /// <summary>
        /// Input channel for raw network events.
        /// </summary>
        public ChannelWriter<RawNetworkEvent> Input => _inputChannel.Writer;

        public FlowAggregator(
            EnrichmentService enrichment,
            FlowRecordStore? store = null,
            TimeSpan? windowSize = null,
            TimeSpan? idleTimeout = null)
        {
            _enrichment = enrichment;
            _store = store;
            _windowSize = windowSize ?? TimeSpan.FromMinutes(1);
            _idleTimeout = idleTimeout ?? TimeSpan.FromSeconds(30);

            _inputChannel = Channel.CreateBounded<RawNetworkEvent>(
                new BoundedChannelOptions(50000)
                {
                    FullMode = BoundedChannelFullMode.DropOldest,
                    SingleReader = true,
                    SingleWriter = false
                });
        }

        /// <summary>
        /// Start processing events from the input channel.
        /// </summary>
        public void Start()
        {
            if (_processingTask != null)
                throw new InvalidOperationException("Already started");

            _processingTask = ProcessEventsAsync(_cts.Token);
        }

        /// <summary>
        /// Connect to a FlowCapturePipeline and start processing its events.
        /// </summary>
        public void ConnectTo(FlowCapturePipeline pipeline)
        {
            Task.Run(async () =>
            {
                try
                {
                    await foreach (var evt in pipeline.Events.ReadAllAsync(_cts.Token))
                    {
                        await _inputChannel.Writer.WriteAsync(evt, _cts.Token);
                    }
                }
                catch (OperationCanceledException)
                {
                    // Normal shutdown
                }
                catch (ChannelClosedException)
                {
                    // Pipeline closed
                }
            });
        }

        private async Task ProcessEventsAsync(CancellationToken ct)
        {
            try
            {
                await foreach (var evt in _inputChannel.Reader.ReadAllAsync(ct))
                {
                    await ProcessEventAsync(evt, ct);
                    CheckWindowRollover();
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

        /// <summary>
        /// Process a single raw network event and update aggregated flow records.
        /// </summary>
        public async Task ProcessEventAsync(RawNetworkEvent evt, CancellationToken ct = default)
        {
            // Skip non-traffic events for aggregation
            if (evt.EventType == NetEventType.DnsQuery || evt.EventType == NetEventType.DnsResponse)
            {
                // DNS events update the enrichment cache, handled separately
                if (evt.EventType == NetEventType.DnsResponse && !string.IsNullOrEmpty(evt.DnsQuery) && !string.IsNullOrEmpty(evt.DnsResponse))
                {
                    // Could populate DNS cache from ETW DNS events
                }
                return;
            }

            var flowKey = FlowRecord.BuildFlowKey(evt.ProcessId, evt.LocalAddress, evt.LocalPort, evt.RemoteAddress, evt.RemotePort);

            var flow = _activeFlows.GetOrAdd(flowKey, _ => new FlowRecord
            {
                FlowId = flowKey,
                ProcessId = evt.ProcessId,
                Protocol = GetProtocol(evt.EventType),
                LocalAddress = evt.LocalAddress,
                LocalPort = evt.LocalPort,
                RemoteAddress = evt.RemoteAddress,
                RemotePort = evt.RemotePort,
                FirstSeen = evt.Timestamp
            });

            // Update statistics (thread-safe via lock)
            lock (flow)
            {
                flow.LastSeen = evt.Timestamp;
                flow.BytesSent += evt.BytesSent;
                flow.BytesReceived += evt.BytesReceived;

                if (evt.BytesSent > 0) flow.PacketsSent++;
                if (evt.BytesReceived > 0) flow.PacketsReceived++;

                // Handle disconnect events
                if (evt.EventType == NetEventType.TcpDisconnect)
                {
                    flow.Action = FlowAction.Allow; // Completed normally
                }
            }

            // Enrich if not yet enriched (only once per flow)
            if (string.IsNullOrEmpty(flow.ProcessName))
            {
                await _enrichment.EnrichAsync(flow, ct);
            }
        }

        private static string GetProtocol(NetEventType eventType)
        {
            return eventType switch
            {
                NetEventType.TcpConnect or NetEventType.TcpDisconnect or NetEventType.TcpAccept or
                NetEventType.TcpSend or NetEventType.TcpReceive => "TCP",
                NetEventType.UdpSend or NetEventType.UdpReceive => "UDP",
                _ => "Unknown"
            };
        }

        private void CheckWindowRollover()
        {
            var now = DateTime.UtcNow;
            if (now - _lastCleanup < TimeSpan.FromSeconds(10))
                return;

            _lastCleanup = now;

            // Archive and remove idle flows
            var idleFlows = _activeFlows
                .Where(kvp => now - kvp.Value.LastSeen > _idleTimeout)
                .Select(kvp => kvp.Key)
                .ToArray();

            foreach (var key in idleFlows)
            {
                if (_activeFlows.TryRemove(key, out var flow))
                {
                    // Archive to storage
                    try
                    {
                        _store?.Append(flow);
                        _store?.UpdateProcessTotals(
                            flow.ProcessName,
                            flow.FirstSeen.Date,
                            flow.BytesSent,
                            flow.BytesReceived);
                    }
                    catch
                    {
                        // Ignore storage errors
                    }
                }
            }

            // Fire update events
            if (idleFlows.Length > 0)
            {
                NotifyUpdates();
            }

            // Check window rollover
            if (now - _currentWindowStart > _windowSize)
            {
                _currentWindowStart = now;
                NotifyUpdates();
            }
        }

        private void NotifyUpdates()
        {
            var totals = GetProcessTotals();
            ProcessTotalsUpdated?.Invoke(totals);

            var flows = GetActiveFlows();
            ActiveFlowsUpdated?.Invoke(flows);
        }

        /// <summary>
        /// Get per-process bandwidth totals for the current session.
        /// </summary>
        public IReadOnlyDictionary<string, ProcessBandwidth> GetProcessTotals()
        {
            var totals = new Dictionary<string, ProcessBandwidth>();

            foreach (var flow in _activeFlows.Values)
            {
                var key = !string.IsNullOrEmpty(flow.ProcessName)
                    ? $"{flow.ProcessName} ({flow.ProcessId})"
                    : $"PID {flow.ProcessId}";

                if (!totals.TryGetValue(key, out var bandwidth))
                {
                    bandwidth = new ProcessBandwidth
                    {
                        ProcessName = flow.ProcessName,
                        ProcessId = flow.ProcessId,
                        ProcessPath = flow.ProcessPath,
                        ProcessSigner = flow.ProcessSigner
                    };
                    totals[key] = bandwidth;
                }

                bandwidth.BytesSent += flow.BytesSent;
                bandwidth.BytesReceived += flow.BytesReceived;
                bandwidth.ConnectionCount++;
            }

            return totals;
        }

        /// <summary>
        /// Get list of active flows.
        /// </summary>
        public IReadOnlyList<FlowRecord> GetActiveFlows()
        {
            return _activeFlows.Values
                .OrderByDescending(f => f.TotalBytes)
                .ThenByDescending(f => f.LastSeen)
                .Take(100)
                .ToList();
        }

        /// <summary>
        /// Get active flows grouped by process.
        /// </summary>
        public IReadOnlyDictionary<string, IReadOnlyList<FlowRecord>> GetActiveFlowsByProcess()
        {
            return _activeFlows.Values
                .GroupBy(f => f.ProcessName ?? "Unknown")
                .ToDictionary(
                    g => g.Key,
                    g => (IReadOnlyList<FlowRecord>)g.OrderByDescending(f => f.TotalBytes).ToList());
        }

        /// <summary>
        /// Get total bandwidth statistics.
        /// </summary>
        public (long TotalBytesSent, long TotalBytesReceived, int ActiveFlowCount, int ActiveProcessCount) GetTotalStats()
        {
            long sent = 0, received = 0;
            var processes = new HashSet<int>();

            foreach (var flow in _activeFlows.Values)
            {
                sent += flow.BytesSent;
                received += flow.BytesReceived;
                processes.Add(flow.ProcessId);
            }

            return (sent, received, _activeFlows.Count, processes.Count);
        }

        /// <summary>
        /// Clear all active flows (reset counters).
        /// </summary>
        public void Clear()
        {
            _activeFlows.Clear();
            _currentWindowStart = DateTime.UtcNow;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            _cts.Cancel();
            _inputChannel.Writer.Complete();

            try
            {
                _processingTask?.Wait(TimeSpan.FromSeconds(2));
            }
            catch
            {
                // Ignore wait errors
            }

            // Archive remaining flows
            foreach (var flow in _activeFlows.Values)
            {
                try
                {
                    _store?.Append(flow);
                }
                catch
                {
                    // Ignore storage errors
                }
            }

            _cts.Dispose();
        }
    }
}
