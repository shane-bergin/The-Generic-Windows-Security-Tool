using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TGWST.App.Services;
using TGWST.Core.Junk;

namespace TGWST.App.ViewModels;

public sealed class MainWindowViewModel : ObservableObject, IDisposable
{
    private readonly SecurityPostureService _postureService;
    private readonly GuiLogService _log;
    private readonly DispatcherTimer _dashboardTimer;
    private readonly DispatcherTimer _networkTimer;
    private bool _disposed;
    private bool _dashboardRefreshInProgress;

    public DashboardViewModel Dashboard { get; }
    public NetworkDashboardViewModel Network { get; }
    public TelemetryDashboardViewModel Telemetry { get; }
    public ToolsDashboardViewModel Tools { get; }
    public LogsDashboardViewModel Logs { get; }
    public IAsyncRelayCommand RefreshCommand { get; }

    public event EventHandler<CyberThreatLevel>? ThreatLevelChanged;

    public MainWindowViewModel(
        SecurityPostureService postureService,
        NetworkDashboardViewModel network,
        TelemetryDashboardViewModel telemetry,
        ToolsDashboardViewModel tools,
        LogsDashboardViewModel logs,
        GuiLogService log)
    {
        _postureService = postureService;
        _log = log;
        Dashboard = new DashboardViewModel();
        Network = network;
        Telemetry = telemetry;
        Tools = tools;
        Logs = logs;
        RefreshCommand = new AsyncRelayCommand(RefreshDashboardAsync);

        Dashboard.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(Dashboard.ThreatLevel))
            {
                ThreatLevelChanged?.Invoke(this, Dashboard.ThreatLevel);
            }
        };

        _dashboardTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _dashboardTimer.Tick += async (_, _) => await RefreshDashboardAsync();
        _networkTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        _networkTimer.Tick += async (_, _) => await Network.RefreshAsync();
    }

    public async Task StartAsync()
    {
        _log.Info("GUI", "pure dashboard mode initialized");
        Telemetry.Start();
        _networkTimer.Start();
        _dashboardTimer.Start();
        await Network.RefreshAsync();
        await RefreshDashboardAsync();
    }

    private async Task RefreshDashboardAsync()
    {
        if (_dashboardRefreshInProgress)
        {
            return;
        }

        _dashboardRefreshInProgress = true;
        try
        {
            var criticalTelemetry = Telemetry.Events.Count(row =>
                row.Severity == CyberSeverity.Critical &&
                DateTimeOffset.Now - row.Timestamp <= TimeSpan.FromMinutes(10));
            var posture = await _postureService.GetSnapshotAsync(Network.LastSnapshot, criticalTelemetry);
            Dashboard.Apply(posture);
        }
        catch (Exception ex)
        {
            _log.Warning("Dashboard", $"posture refresh degraded: {Trim(ex.Message)}");
        }
        finally
        {
            _dashboardRefreshInProgress = false;
        }
    }

    private static string Trim(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return "no detail";
        }

        return message.Length <= 160 ? message : message[..160];
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _dashboardTimer.Stop();
        _networkTimer.Stop();
        Telemetry.Dispose();
        Network.Dispose();
    }
}

public sealed class DashboardViewModel : ObservableObject
{
    private int _securityScore;
    private CyberThreatLevel _threatLevel = CyberThreatLevel.Normal;
    private int _systemIntegrityPercent;
    private string _networkExposure = "UNKNOWN";
    private string _lastFullScan = "unknown";
    private int _activeThreats;
    private string _defenderRealtime = "UNKNOWN";
    private int _asrBlockedControls;
    private int _vulnerableFirewallProfiles;
    private string _lastUpdated = "-";

    public int SecurityScore
    {
        get => _securityScore;
        private set => SetProperty(ref _securityScore, value);
    }

    public CyberThreatLevel ThreatLevel
    {
        get => _threatLevel;
        private set
        {
            if (SetProperty(ref _threatLevel, value))
            {
                OnPropertyChanged(nameof(ThreatLabel));
            }
        }
    }

    public string ThreatLabel => ThreatLevel.ToString().ToUpperInvariant();

    public int SystemIntegrityPercent
    {
        get => _systemIntegrityPercent;
        private set => SetProperty(ref _systemIntegrityPercent, value);
    }

    public string NetworkExposure
    {
        get => _networkExposure;
        private set => SetProperty(ref _networkExposure, value);
    }

    public string LastFullScan
    {
        get => _lastFullScan;
        private set => SetProperty(ref _lastFullScan, value);
    }

    public int ActiveThreats
    {
        get => _activeThreats;
        private set => SetProperty(ref _activeThreats, value);
    }

    public string DefenderRealtime
    {
        get => _defenderRealtime;
        private set => SetProperty(ref _defenderRealtime, value);
    }

    public int AsrBlockedControls
    {
        get => _asrBlockedControls;
        private set => SetProperty(ref _asrBlockedControls, value);
    }

    public int VulnerableFirewallProfiles
    {
        get => _vulnerableFirewallProfiles;
        private set => SetProperty(ref _vulnerableFirewallProfiles, value);
    }

    public string LastUpdated
    {
        get => _lastUpdated;
        private set => SetProperty(ref _lastUpdated, value);
    }

    public void Apply(SecurityPostureSnapshot snapshot)
    {
        SecurityScore = snapshot.SecurityScore;
        ThreatLevel = snapshot.ThreatLevel;
        SystemIntegrityPercent = snapshot.SystemIntegrityPercent;
        NetworkExposure = snapshot.NetworkExposure;
        LastFullScan = snapshot.LastFullScan;
        ActiveThreats = snapshot.ActiveThreats;
        DefenderRealtime = snapshot.DefenderRealtime;
        AsrBlockedControls = snapshot.AsrBlockedControls;
        VulnerableFirewallProfiles = snapshot.VulnerableFirewallProfiles;
        LastUpdated = DateTime.Now.ToString("HH:mm:ss");
    }
}

public sealed class NetworkDashboardViewModel : ObservableObject, IDisposable
{
    private readonly NetworkTelemetryService _networkTelemetry;
    private readonly GuiLogService _log;
    private bool _refreshInProgress;
    private int _lastHighRiskCount = -1;
    private string _status = "initializing";
    private int _totalConnections;
    private int _inboundExposure;
    private int _outboundConnections;
    private string _bandwidthStatus = "sampling";
    private string _firewallStatusText = "unknown";
    private string _lastUpdated = "-";

    public ObservableCollection<NetworkConnectionRow> RiskyConnections { get; } = new();
    public ObservableCollection<NetworkConnectionRow> Connections { get; } = new();
    public NetworkTelemetrySnapshot? LastSnapshot { get; private set; }

    public string Status
    {
        get => _status;
        private set => SetProperty(ref _status, value);
    }

    public int TotalConnections
    {
        get => _totalConnections;
        private set => SetProperty(ref _totalConnections, value);
    }

    public int InboundExposure
    {
        get => _inboundExposure;
        private set => SetProperty(ref _inboundExposure, value);
    }

    public int OutboundConnections
    {
        get => _outboundConnections;
        private set => SetProperty(ref _outboundConnections, value);
    }

    public string BandwidthStatus
    {
        get => _bandwidthStatus;
        private set => SetProperty(ref _bandwidthStatus, value);
    }

    public string FirewallStatusText
    {
        get => _firewallStatusText;
        private set => SetProperty(ref _firewallStatusText, value);
    }

    public string LastUpdated
    {
        get => _lastUpdated;
        private set => SetProperty(ref _lastUpdated, value);
    }

    public NetworkDashboardViewModel(NetworkTelemetryService networkTelemetry, GuiLogService log)
    {
        _networkTelemetry = networkTelemetry;
        _log = log;
    }

    public async Task RefreshAsync()
    {
        if (_refreshInProgress)
        {
            return;
        }

        _refreshInProgress = true;
        try
        {
            var snapshot = await _networkTelemetry.GetSnapshotAsync();
            Apply(snapshot);
            Status = "active polling";
        }
        catch (Exception ex)
        {
            Status = "degraded";
            _log.Warning("Network", $"telemetry refresh failed: {Trim(ex.Message)}");
        }
        finally
        {
            _refreshInProgress = false;
        }
    }

    private void Apply(NetworkTelemetrySnapshot snapshot)
    {
        LastSnapshot = snapshot;
        TotalConnections = snapshot.TotalConnections;
        InboundExposure = snapshot.InboundExposure;
        OutboundConnections = snapshot.OutboundConnections;
        BandwidthStatus = snapshot.BandwidthStatus;
        FirewallStatusText = snapshot.FirewallStatusText;
        LastUpdated = snapshot.Timestamp.ToString("HH:mm:ss");
        Replace(RiskyConnections, snapshot.RiskyConnections);
        Replace(Connections, snapshot.Connections.Take(180));

        var highRisk = snapshot.RiskyConnections.Count(row => row.RiskScore >= 70);
        if (highRisk != _lastHighRiskCount)
        {
            _lastHighRiskCount = highRisk;
            if (highRisk > 0)
            {
                _log.Warning("Network", $"{highRisk} high-risk connection(s) detected");
            }
        }
    }

    private static void Replace<T>(ObservableCollection<T> target, IEnumerable<T> values)
    {
        target.Clear();
        foreach (var value in values)
        {
            target.Add(value);
        }
    }

    private static string Trim(string message)
    {
        return string.IsNullOrWhiteSpace(message) ? "no detail" : message.Length <= 160 ? message : message[..160];
    }

    public void Dispose() => _networkTelemetry.Dispose();
}

public sealed class TelemetryDashboardViewModel : ObservableObject, IDisposable
{
    private readonly SystemTelemetryService _telemetryService;
    private readonly GuiLogService _log;
    private bool _started;
    private string _status = "stopped";
    private int _processSignals;
    private int _registrySignals;
    private int _fileSignals;

    public ObservableCollection<TelemetryEventRow> Events { get; } = new();
    public ObservableCollection<RiskTimelineItem> Timeline { get; } = new();

    public string Status
    {
        get => _status;
        private set => SetProperty(ref _status, value);
    }

    public int ProcessSignals
    {
        get => _processSignals;
        private set => SetProperty(ref _processSignals, value);
    }

    public int RegistrySignals
    {
        get => _registrySignals;
        private set => SetProperty(ref _registrySignals, value);
    }

    public int FileSignals
    {
        get => _fileSignals;
        private set => SetProperty(ref _fileSignals, value);
    }

    public TelemetryDashboardViewModel(SystemTelemetryService telemetryService, GuiLogService log)
    {
        _telemetryService = telemetryService;
        _log = log;
        _telemetryService.EventObserved += OnEventObserved;
        Timeline.Add(new RiskTimelineItem("LAST 10 MIN", 0, 0, 0));
    }

    public void Start()
    {
        if (_started)
        {
            return;
        }

        _started = true;
        _telemetryService.Start();
        Status = "active discovery";
    }

    private void OnEventObserved(object? sender, TelemetryEventRow row)
    {
        var dispatcher = System.Windows.Application.Current?.Dispatcher;
        if (dispatcher?.CheckAccess() == true)
        {
            AddEvent(row);
        }
        else
        {
            _ = dispatcher?.BeginInvoke(() => AddEvent(row));
        }
    }

    private void AddEvent(TelemetryEventRow row)
    {
        Events.Insert(0, row);
        while (Events.Count > 250)
        {
            Events.RemoveAt(Events.Count - 1);
        }

        if (row.Source.Equals("Process", StringComparison.OrdinalIgnoreCase)) ProcessSignals++;
        if (row.Source.Equals("Registry", StringComparison.OrdinalIgnoreCase)) RegistrySignals++;
        if (row.Source.Equals("File", StringComparison.OrdinalIgnoreCase)) FileSignals++;

        var window = DateTimeOffset.Now - TimeSpan.FromMinutes(10);
        var recent = Events.Where(item => item.Timestamp >= window).ToArray();
        Timeline.Clear();
        Timeline.Add(new RiskTimelineItem(
            "LAST 10 MIN",
            recent.Count(item => item.Severity is CyberSeverity.Info or CyberSeverity.Success),
            recent.Count(item => item.Severity == CyberSeverity.Warning),
            recent.Count(item => item.Severity == CyberSeverity.Critical)));
    }

    public void Dispose()
    {
        _telemetryService.EventObserved -= OnEventObserved;
        _telemetryService.Dispose();
        _log.Info("Telemetry", "active discovery stopped");
    }
}

public sealed class ToolsDashboardViewModel : ObservableObject
{
    private readonly ToolExecutionService _tools;
    private readonly GuiLogService _log;
    private IReadOnlyList<JunkCandidate> _latestJunkCandidates = Array.Empty<JunkCandidate>();
    private bool _isBusy;
    private string _status = "ready";

    public ObservableCollection<StartupAuditRow> StartupItems { get; } = new();
    public ObservableCollection<JunkFindingRow> JunkFindings { get; } = new();
    public ObservableCollection<EventFindingRow> EventFindings { get; } = new();
    public IAsyncRelayCommand IntegrityScanCommand { get; }
    public IAsyncRelayCommand StartupAuditCommand { get; }
    public IAsyncRelayCommand JunkAnalyzeCommand { get; }
    public IAsyncRelayCommand JunkCleanCommand { get; }
    public IAsyncRelayCommand EventReviewCommand { get; }

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (SetProperty(ref _isBusy, value))
            {
                IntegrityScanCommand.NotifyCanExecuteChanged();
                StartupAuditCommand.NotifyCanExecuteChanged();
                JunkAnalyzeCommand.NotifyCanExecuteChanged();
                JunkCleanCommand.NotifyCanExecuteChanged();
                EventReviewCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public string Status
    {
        get => _status;
        private set => SetProperty(ref _status, value);
    }

    public ToolsDashboardViewModel(ToolExecutionService tools, GuiLogService log)
    {
        _tools = tools;
        _log = log;
        IntegrityScanCommand = new AsyncRelayCommand(RunIntegrityAsync, () => !IsBusy);
        StartupAuditCommand = new AsyncRelayCommand(RunStartupAuditAsync, () => !IsBusy);
        JunkAnalyzeCommand = new AsyncRelayCommand(RunJunkAnalyzeAsync, () => !IsBusy);
        JunkCleanCommand = new AsyncRelayCommand(RunJunkCleanAsync, () => !IsBusy && _latestJunkCandidates.Any(candidate => candidate.SafeToClean));
        EventReviewCommand = new AsyncRelayCommand(RunEventReviewAsync, () => !IsBusy);
    }

    private async Task RunIntegrityAsync()
    {
        await RunToolAsync("Integrity", async ct =>
        {
            var result = await _tools.RunIntegrityVerifyAsync(ct);
            if (result.Success) _log.Success("Integrity", result.Message);
            else _log.Warning("Integrity", result.Message);
            Status = result.Message;
        });
    }

    private async Task RunStartupAuditAsync()
    {
        await RunToolAsync("Startup", async ct =>
        {
            var rows = await _tools.AuditStartupAsync(ct);
            Replace(StartupItems, rows);
            Status = $"{rows.Count} startup item(s) reviewed";
            _log.Success("Startup", Status);
        });
    }

    private async Task RunJunkAnalyzeAsync()
    {
        await RunToolAsync("Junk", AnalyzeJunkCoreAsync);
    }

    private async Task RunJunkCleanAsync()
    {
        await RunToolAsync("Junk", async ct =>
        {
            var result = await _tools.CleanSafeJunkAsync(_latestJunkCandidates, ct);
            Status = $"safe cleanup deleted={result.DeletedCount} skipped={result.SkippedCount}";
            _log.Warning("Junk", Status);
            await AnalyzeJunkCoreAsync(ct);
        });
    }

    private async Task RunEventReviewAsync()
    {
        await RunToolAsync("Events", async ct =>
        {
            var rows = await _tools.GetEventFindingsAsync(ct);
            Replace(EventFindings, rows);
            Status = $"{rows.Count} event finding group(s) in last 24h";
            _log.Success("Events", Status);
        });
    }

    private async Task AnalyzeJunkCoreAsync(CancellationToken ct)
    {
        var (rows, candidates) = await _tools.AnalyzeJunkAsync(ct);
        _latestJunkCandidates = candidates;
        Replace(JunkFindings, rows);
        Status = $"{candidates.Count} junk candidate(s) grouped";
        _log.Success("Junk", Status);
        JunkCleanCommand.NotifyCanExecuteChanged();
    }

    private async Task RunToolAsync(string name, Func<CancellationToken, Task> action)
    {
        if (IsBusy)
        {
            return;
        }

        IsBusy = true;
        Status = $"{name} running";
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(10));
        try
        {
            await action(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            Status = $"{name} canceled or timed out";
            _log.Warning(name, Status);
        }
        catch (Exception ex)
        {
            Status = $"{name} failed: {Trim(ex.Message)}";
            _log.Warning(name, Status);
        }
        finally
        {
            IsBusy = false;
        }
    }

    private static void Replace<T>(ObservableCollection<T> target, IEnumerable<T> values)
    {
        target.Clear();
        foreach (var value in values)
        {
            target.Add(value);
        }
    }

    private static string Trim(string message)
    {
        return string.IsNullOrWhiteSpace(message) ? "no detail" : message.Length <= 160 ? message : message[..160];
    }
}

public sealed class LogsDashboardViewModel : ObservableObject
{
    private string _selectedSeverityFilter = "ALL";

    public ObservableCollection<SecurityLogEntry> Entries { get; }
    public IReadOnlyList<string> SeverityFilters { get; } = ["ALL", "INFO", "SUCCESS", "WARNING", "CRITICAL"];

    public string SelectedSeverityFilter
    {
        get => _selectedSeverityFilter;
        set => SetProperty(ref _selectedSeverityFilter, value);
    }

    public LogsDashboardViewModel(GuiLogService log)
    {
        Entries = log.Entries;
    }

    public IEnumerable<SecurityLogEntry> FilteredEntries =>
        SelectedSeverityFilter == "ALL"
            ? Entries
            : Entries.Where(entry => entry.Severity.ToString().Equals(SelectedSeverityFilter, StringComparison.OrdinalIgnoreCase));
}
