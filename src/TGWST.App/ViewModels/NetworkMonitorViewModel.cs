using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using TGWST.Core.Network;
using TGWST.Core.Network.Capture;

namespace TGWST.App.ViewModels
{
    /// <summary>
    /// ViewModel for the network monitor attached pane.
    /// Provides batched UI updates for real-time network flow display.
    /// </summary>
    public sealed class NetworkMonitorViewModel : ObservableObject, IDisposable
    {
        private readonly FlowCapturePipeline _pipeline;
        private readonly FlowAggregator _aggregator;
        private readonly EnrichmentService _enrichment;
        private readonly FlowRecordStore? _store;
        private readonly DispatcherTimer _uiUpdateTimer;
        private bool _disposed;

        public ObservableCollection<FlowRecordViewModel> ActiveFlows { get; } = new();
        public ObservableCollection<ProcessBandwidthViewModel> ProcessTotals { get; } = new();

        private string _status = "Initializing...";
        public string Status
        {
            get => _status;
            set => SetProperty(ref _status, value);
        }

        private string _modeIndicator = "";
        public string ModeIndicator
        {
            get => _modeIndicator;
            set => SetProperty(ref _modeIndicator, value);
        }

        private long _totalBytesIn;
        public long TotalBytesIn
        {
            get => _totalBytesIn;
            set
            {
                if (SetProperty(ref _totalBytesIn, value))
                    OnPropertyChanged(nameof(TotalBytesInDisplay));
            }
        }

        private long _totalBytesOut;
        public long TotalBytesOut
        {
            get => _totalBytesOut;
            set
            {
                if (SetProperty(ref _totalBytesOut, value))
                    OnPropertyChanged(nameof(TotalBytesOutDisplay));
            }
        }

        public string TotalBytesInDisplay => FlowRecord.FormatBytes(TotalBytesIn);
        public string TotalBytesOutDisplay => FlowRecord.FormatBytes(TotalBytesOut);

        private int _activeFlowCount;
        public int ActiveFlowCount
        {
            get => _activeFlowCount;
            set => SetProperty(ref _activeFlowCount, value);
        }

        private int _activeProcessCount;
        public int ActiveProcessCount
        {
            get => _activeProcessCount;
            set => SetProperty(ref _activeProcessCount, value);
        }

        public NetworkMonitorViewModel(bool persistToStorage = false)
        {
            _enrichment = new EnrichmentService();

            if (persistToStorage)
            {
                try
                {
                    _store = new FlowRecordStore();
                }
                catch
                {
                    // Storage initialization failed, continue without persistence
                }
            }

            _aggregator = new FlowAggregator(_enrichment, _store);
            _pipeline = new FlowCapturePipeline();

            // Batch UI updates every 500ms
            _uiUpdateTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(500)
            };
            _uiUpdateTimer.Tick += (_, _) => UpdateUI();
        }

        /// <summary>
        /// Start the network monitor.
        /// </summary>
        public void Start()
        {
            _pipeline.Start(TimeSpan.FromSeconds(2));
            _aggregator.ConnectTo(_pipeline);
            _aggregator.Start();

            // Update mode indicator
            if (_pipeline.IsLimitedMode)
            {
                ModeIndicator = "[Limited Mode - Run as Admin for full monitoring]";
            }
            else
            {
                ModeIndicator = "[Full Monitoring Active]";
            }

            _uiUpdateTimer.Start();
            Status = "Monitoring...";
        }

        /// <summary>
        /// Stop the network monitor.
        /// </summary>
        public void Stop()
        {
            _uiUpdateTimer.Stop();
            _pipeline.Stop();
            Status = "Stopped";
        }

        private void UpdateUI()
        {
            if (_disposed) return;

            var dispatcher = Application.Current?.Dispatcher;
            if (dispatcher == null) return;

            dispatcher.BeginInvoke(() =>
            {
                try
                {
                    // Get current stats
                    var (sent, received, flowCount, processCount) = _aggregator.GetTotalStats();
                    TotalBytesIn = received;
                    TotalBytesOut = sent;
                    ActiveFlowCount = flowCount;
                    ActiveProcessCount = processCount;

                    // Update process totals
                    var totals = _aggregator.GetProcessTotals()
                        .Values
                        .OrderByDescending(t => t.TotalBytes)
                        .Take(15)
                        .ToList();

                    ProcessTotals.Clear();
                    foreach (var total in totals)
                    {
                        ProcessTotals.Add(new ProcessBandwidthViewModel(total));
                    }

                    // Update active flows
                    var flows = _aggregator.GetActiveFlows();
                    ActiveFlows.Clear();
                    foreach (var flow in flows.Take(50))
                    {
                        ActiveFlows.Add(new FlowRecordViewModel(flow));
                    }

                    Status = $"Monitoring | In: {TotalBytesInDisplay} | Out: {TotalBytesOutDisplay} | Flows: {flowCount}";
                }
                catch
                {
                    // Ignore UI update errors
                }
            }, DispatcherPriority.Background);
        }

        /// <summary>
        /// Get a text summary suitable for the attached pane output.
        /// </summary>
        public string GetTextSummary()
        {
            var lines = new List<string>
            {
                $"Network Monitor {(_pipeline.IsLimitedMode ? "(Limited)" : "(Full)")}",
                $"Total In: {TotalBytesInDisplay} | Out: {TotalBytesOutDisplay}",
                $"Active Flows: {ActiveFlowCount} | Processes: {ActiveProcessCount}",
                ""
            };

            if (ProcessTotals.Count > 0)
            {
                lines.Add("Top Processes by Bandwidth:");
                foreach (var proc in ProcessTotals.Take(10))
                {
                    lines.Add($"  {proc.ProcessName,-20} In: {proc.BytesReceived,10} Out: {proc.BytesSent,10}");
                }
            }

            return string.Join("\n", lines);
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            _uiUpdateTimer.Stop();
            _aggregator.Dispose();
            _pipeline.Dispose();
            _store?.Dispose();
        }
    }

    /// <summary>
    /// ViewModel wrapper for FlowRecord for UI binding.
    /// </summary>
    public sealed class FlowRecordViewModel
    {
        private readonly FlowRecord _flow;

        public FlowRecordViewModel(FlowRecord flow)
        {
            _flow = flow;
        }

        public string ProcessName => _flow.ProcessName;
        public int ProcessId => _flow.ProcessId;
        public string Protocol => _flow.Protocol;
        public string LocalEndpoint => $"{_flow.LocalAddress}:{_flow.LocalPort}";
        public string RemoteEndpoint => $"{_flow.RemoteAddress}:{_flow.RemotePort}";
        public string RemoteHostname => _flow.RemoteHostname ?? "";
        public string BytesSent => _flow.BytesSentDisplay;
        public string BytesReceived => _flow.BytesReceivedDisplay;
        public string TotalBytes => _flow.TotalBytesDisplay;
        public string Duration => _flow.Duration.TotalSeconds < 60
            ? $"{_flow.Duration.TotalSeconds:F0}s"
            : $"{_flow.Duration.TotalMinutes:F1}m";
        public string Action => _flow.Action.ToString();

        public string Summary => $"{ProcessName} -> {RemoteHostname ?? RemoteEndpoint} ({TotalBytes})";
    }

    /// <summary>
    /// ViewModel wrapper for ProcessBandwidth for UI binding.
    /// </summary>
    public sealed class ProcessBandwidthViewModel
    {
        private readonly ProcessBandwidth _bandwidth;

        public ProcessBandwidthViewModel(ProcessBandwidth bandwidth)
        {
            _bandwidth = bandwidth;
        }

        public string ProcessName => _bandwidth.ProcessName;
        public int ProcessId => _bandwidth.ProcessId;
        public string? ProcessPath => _bandwidth.ProcessPath;
        public string? ProcessSigner => _bandwidth.ProcessSigner;
        public int ConnectionCount => _bandwidth.ConnectionCount;
        public string BytesSent => _bandwidth.BytesSentDisplay;
        public string BytesReceived => _bandwidth.BytesReceivedDisplay;
        public string TotalBytes => _bandwidth.TotalBytesDisplay;

        public string Summary => $"{ProcessName}: In {BytesReceived} / Out {BytesSent} ({ConnectionCount} conn)";
    }

    public sealed class HistoricalFlowViewModel
    {
        private readonly FlowRecord _flow;

        public HistoricalFlowViewModel(FlowRecord flow)
        {
            _flow = flow;
        }

        public string ProcessName => _flow.ProcessName;
        public string Path => _flow.ProcessPath;
        public string? Signer => _flow.ProcessSigner;
        public string LocalEndpoint => $"{_flow.LocalAddress}:{_flow.LocalPort}";
        public string RemoteIPPort => $"{_flow.RemoteAddress}:{_flow.RemotePort}";
        public string? Hostname => _flow.RemoteHostname ?? "";
        public string? Country => _flow.RemoteCountry ?? "";
        public string BytesIn => _flow.BytesReceivedDisplay;
        public string BytesOut => _flow.BytesSentDisplay;
        public string BytesTotal => _flow.TotalBytesDisplay;
        public string LastActive => $"{Math.Round((DateTime.UtcNow - _flow.LastSeen).TotalMinutes, 1)} min ago";
        public string Action => _flow.Action.ToString();
    }
}
