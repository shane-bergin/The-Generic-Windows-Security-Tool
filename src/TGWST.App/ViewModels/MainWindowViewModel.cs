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
using Microsoft.Extensions.DependencyInjection;
using TGWST.App.Services;
using TGWST.App.Views;
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
    private bool _isLiveRefreshEnabled = false;

    public DashboardViewModel Dashboard { get; }
    public NetworkDashboardViewModel Network { get; }
    public TelemetryDashboardViewModel Telemetry { get; }
    public ToolsDashboardViewModel Tools { get; }
    public LogsDashboardViewModel Logs { get; }
    public IAsyncRelayCommand RefreshCommand { get; }
    public IRelayCommand ToggleLiveRefreshCommand { get; }
    public IAsyncRelayCommand ApplyBalancedCommand { get; }
    public IAsyncRelayCommand ApplyHardenedCommand { get; }
    public IAsyncRelayCommand ApplyWindowsSafeguardsProfileCommand { get; }
    public IAsyncRelayCommand ApplyWdacContainmentCommand { get; }
    public IAsyncRelayCommand ScanWindowsSafeguardsCommand { get; }

    private string _lastProfileStatus = "No profile applied this session";
    public string LastProfileStatus
    {
        get => _lastProfileStatus;
        private set => SetProperty(ref _lastProfileStatus, value);
    }

    public event EventHandler<CyberThreatLevel>? ThreatLevelChanged;

    public MainWindowViewModel(
        SecurityPostureService postureService,
        DashboardActionService dashboardActions,
        PortProbeService portProbe,
        NetworkDashboardViewModel network,
        TelemetryDashboardViewModel telemetry,
        ToolsDashboardViewModel tools,
        LogsDashboardViewModel logs,
        GuiLogService log)
    {
        _postureService = postureService;
        _log = log;
        Network = network;
        Dashboard = new DashboardViewModel(dashboardActions, portProbe, Network, log);
        Telemetry = telemetry;
        Tools = tools;
        Logs = logs;
        RefreshCommand = new AsyncRelayCommand(RefreshAllAsync);
        ToggleLiveRefreshCommand = new RelayCommand(ToggleLiveRefresh);
        ApplyBalancedCommand = new AsyncRelayCommand(() => ApplyProfileAsync(SecurityPostureService.SecurityProfile.Balanced));
        ApplyHardenedCommand = new AsyncRelayCommand(() => ApplyProfileAsync(SecurityPostureService.SecurityProfile.Hardened));
        ApplyWindowsSafeguardsProfileCommand = new AsyncRelayCommand(
            () => RunSafeguardActionAsync(
                "Windows safeguards profile",
                "Apply the Windows Safeguards profile? This launches an elevated TGWST process and may change firewall, Defender, WDAC staging, BitLocker guidance, symlink evaluation, and related hardening posture.",
                () => dashboardActions.ApplyWindowsSafeguardsProfileAsync()));
        ApplyWdacContainmentCommand = new AsyncRelayCommand(
            () => RunSafeguardActionAsync(
                "WDAC containment profile",
                "Generate the WDAC containment profile? Start in audit/review before enforcement on production systems.",
                () => dashboardActions.ApplyWdacContainmentProfileAsync()));
        ScanWindowsSafeguardsCommand = new AsyncRelayCommand(
            () => RunSafeguardActionAsync(
                "Windows safeguards scan",
                "Run the Windows Safeguards scan? This launches a TGWST CLI scan and writes a JSON report under ProgramData.",
                () => dashboardActions.ScanWindowsSafeguardsAsync()));

        Dashboard.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(Dashboard.ThreatLevel))
            {
                ThreatLevelChanged?.Invoke(this, Dashboard.ThreatLevel);
            }
        };
        Dashboard.ActionCompleted += DashboardActionCompleted;

        _dashboardTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(12) };
        _dashboardTimer.Tick += async (_, _) => await RefreshDashboardAsync();
        _networkTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(8) };
        _networkTimer.Tick += async (_, _) => await Network.RefreshAsync();
    }

    public bool IsLiveRefreshEnabled
    {
        get => _isLiveRefreshEnabled;
        private set
        {
            if (SetProperty(ref _isLiveRefreshEnabled, value))
            {
                OnPropertyChanged(nameof(LiveRefreshButtonText));
                OnPropertyChanged(nameof(LiveRefreshStatus));
            }
        }
    }

    public string LiveRefreshButtonText => IsLiveRefreshEnabled ? "[ PAUSE LIVE ]" : "[ RESUME LIVE ]";

    public string LiveRefreshStatus => IsLiveRefreshEnabled
        ? "rapid mode: on (WDAC/profiles only)"
        : "manual mode: click Scan buttons (recommended for low CPU)";

    public async Task StartAsync()
    {
        _log.Info("GUI", "manual blue-team mode initialized (live refresh off by default)");
        Telemetry.Start();
        if (IsLiveRefreshEnabled)
        {
            _networkTimer.Start();
            _dashboardTimer.Start();
        }

        await Network.RefreshAsync();
        await RefreshDashboardAsync();
    }

    private void ToggleLiveRefresh()
    {
        IsLiveRefreshEnabled = !IsLiveRefreshEnabled;
        if (IsLiveRefreshEnabled)
        {
            _networkTimer.Start();
            _dashboardTimer.Start();
            _log.Success("GUI", "rapid mode enabled (WDAC/profile watching)");
            _ = Network.RefreshAsync();
            _ = RefreshDashboardAsync();
            return;
        }

        _networkTimer.Stop();
        _dashboardTimer.Stop();
        _log.Info("GUI", "rapid mode disabled; manual scans only (low CPU)");
    }

    private async Task ApplyProfileAsync(SecurityPostureService.SecurityProfile profile)
    {
        LastProfileStatus = $"Applying {profile}...";
        try
        {
            var result = await OneTouchProgressRunner.RunAsync(
                $"{profile} profile",
                () => _postureService.ApplySecurityProfileAsync(profile));
            LastProfileStatus = $"{profile} applied: {result}";
            _log.Success("Profile", $"{profile} profile activated", result, "ASR rules + firewall updated via PowerShell. Review Windows Security for confirmation.");
        }
        catch (Exception ex)
        {
            LastProfileStatus = $"{profile} failed";
            _log.Warning("Profile", $"Failed to apply {profile}", ex.Message, "Run as Administrator or check PowerShell execution policy.");
        }
    }

    private async Task RunSafeguardActionAsync(string actionName, string prompt, Func<Task<string>> run)
    {
        if (!Confirm(prompt, "TGWST safeguards"))
        {
            return;
        }

        LastProfileStatus = $"{actionName} requested...";
        try
        {
            var result = await OneTouchProgressRunner.RunAsync(actionName, run);
            LastProfileStatus = result;
            _log.Warning("Safeguards", result);
        }
        catch (Exception ex)
        {
            LastProfileStatus = $"{actionName} failed";
            _log.Warning("Safeguards", $"{actionName} failed", ex.Message);
        }
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
            Dashboard.Apply(posture, Network.LastSnapshot);
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

    private async Task RefreshAllAsync()
    {
        await Network.RefreshAsync();
        await RefreshDashboardAsync();
    }

    private async void DashboardActionCompleted(object? sender, EventArgs e)
    {
        try
        {
            await RefreshAllAsync();
        }
        catch (Exception ex)
        {
            _log.Warning("Dashboard", $"post-action refresh degraded: {Trim(ex.Message)}");
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

    private static bool Confirm(string message, string caption)
    {
        return System.Windows.MessageBox.Show(
            message,
            caption,
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No) == MessageBoxResult.Yes;
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
        Dashboard.ActionCompleted -= DashboardActionCompleted;
        Telemetry.Dispose();
        Network.Dispose();
    }
}

public sealed class DashboardViewModel : ObservableObject
{
    private readonly DashboardActionService _actions;
    private readonly PortProbeService _portProbe;
    private readonly NetworkDashboardViewModel _network;
    private readonly GuiLogService _log;
    private int _securityScore;
    private CyberThreatLevel _threatLevel = CyberThreatLevel.Normal;
    private int _systemIntegrityPercent;
    private string _networkExposure = "UNKNOWN";
    private string _lastFullScan = "unknown";
    private int _activeThreats;
    private string _defenderRealtime = "UNKNOWN";
    private int _asrBlockedControls;
    private int _vulnerableFirewallProfiles;
    private string _firewallStatusText = "UNKNOWN";
    private string _coverageStatus = "WAITING";
    private string _lastUpdated = "-";
    private string _status = "ready";
    private string _securityScoreExplanation = "Waiting for posture data.";
    private string _threatExplanation = "Waiting for posture data.";
    private string _integrityExplanation = "Waiting for posture data.";
    private string _networkExposureExplanation = "Waiting for network data.";
    private string _defenderExplanation = "Waiting for Defender data.";
    private string _asrExplanation = "Waiting for ASR data.";
    private string _firewallExplanation = "Waiting for firewall data.";
    private string _portProbeSummary = "Local port probe has not run.";
    private bool _isBusy;

    public ObservableCollection<DashboardFindingRow> Findings { get; } = new();
    public ObservableCollection<PortProbeRow> PortProbeResults { get; } = new();
    public IAsyncRelayCommand WindowsSecurityBaselineCommand { get; }
    public IAsyncRelayCommand AdvancedFirewallControlsCommand { get; }
    public IAsyncRelayCommand NetworkSettingsBaselineCommand { get; }
    public IAsyncRelayCommand EnableFirewallCommand { get; }
    public IAsyncRelayCommand FirewallBaselineCommand { get; }
    public IAsyncRelayCommand NetworkSurfaceHardeningCommand { get; }
    public IAsyncRelayCommand Windows11BarebonesLockdownCommand { get; }
    public IAsyncRelayCommand InboundSurfaceAuditCommand { get; }
    public IAsyncRelayCommand WindowsCveExposureAuditCommand { get; }
    public IAsyncRelayCommand WindowsCveSafeguardsCommand { get; }
    public IAsyncRelayCommand EicarDefenderTestCommand { get; }
    public IAsyncRelayCommand EnableDefenderRealtimeCommand { get; }
    public IAsyncRelayCommand EnableDefenderCloudCommand { get; }
    public IAsyncRelayCommand RunQuickScanCommand { get; }
    public IAsyncRelayCommand UpdateDefenderSignaturesCommand { get; }
    public IAsyncRelayCommand EmergencyBaselineCommand { get; }
    public IAsyncRelayCommand DisableSmb1Command { get; }
    public IAsyncRelayCommand LocalPortProbeCommand { get; }
    public IAsyncRelayCommand BlockTopNetworkRiskCommand { get; }
    public IAsyncRelayCommand KillTopNetworkTaskCommand { get; }
    public IAsyncRelayCommand<DashboardFindingRow?> RunFindingActionCommand { get; }

    public event EventHandler? ActionCompleted;

    public DashboardViewModel(
        DashboardActionService actions,
        PortProbeService portProbe,
        NetworkDashboardViewModel network,
        GuiLogService log)
    {
        _actions = actions;
        _portProbe = portProbe;
        _network = network;
        _log = log;
        WindowsSecurityBaselineCommand = new AsyncRelayCommand(WindowsSecurityBaselineAsync, CanRunAction);
        AdvancedFirewallControlsCommand = new AsyncRelayCommand(AdvancedFirewallControlsAsync, CanRunAction);
        NetworkSettingsBaselineCommand = new AsyncRelayCommand(NetworkSettingsBaselineAsync, CanRunAction);
        EnableFirewallCommand = new AsyncRelayCommand(EnableFirewallAsync, CanRunAction);
        FirewallBaselineCommand = new AsyncRelayCommand(FirewallBaselineAsync, CanRunAction);
        NetworkSurfaceHardeningCommand = new AsyncRelayCommand(NetworkSurfaceHardeningAsync, CanRunAction);
        Windows11BarebonesLockdownCommand = new AsyncRelayCommand(Windows11BarebonesLockdownAsync, CanRunAction);
        InboundSurfaceAuditCommand = new AsyncRelayCommand(InboundSurfaceAuditAsync, CanRunAction);
        WindowsCveExposureAuditCommand = new AsyncRelayCommand(WindowsCveExposureAuditAsync, CanRunAction);
        WindowsCveSafeguardsCommand = new AsyncRelayCommand(WindowsCveSafeguardsAsync, CanRunAction);
        EicarDefenderTestCommand = new AsyncRelayCommand(EicarDefenderTestAsync, CanRunAction);
        EnableDefenderRealtimeCommand = new AsyncRelayCommand(EnableDefenderRealtimeAsync, CanRunAction);
        EnableDefenderCloudCommand = new AsyncRelayCommand(EnableDefenderCloudAsync, CanRunAction);
        RunQuickScanCommand = new AsyncRelayCommand(RunQuickScanAsync, CanRunAction);
        UpdateDefenderSignaturesCommand = new AsyncRelayCommand(UpdateDefenderSignaturesAsync, CanRunAction);
        EmergencyBaselineCommand = new AsyncRelayCommand(EmergencyBaselineAsync, CanRunAction);
        DisableSmb1Command = new AsyncRelayCommand(DisableSmb1Async, CanRunAction);
        LocalPortProbeCommand = new AsyncRelayCommand(LocalPortProbeAsync, CanRunAction);
        BlockTopNetworkRiskCommand = new AsyncRelayCommand(BlockTopNetworkRiskAsync, CanBlockTopNetworkRisk);
        KillTopNetworkTaskCommand = new AsyncRelayCommand(KillTopNetworkTaskAsync, () => false);
        RunFindingActionCommand = new AsyncRelayCommand<DashboardFindingRow?>(RunFindingActionAsync, CanRunFindingAction);
    }

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

    public string FirewallStatusText
    {
        get => _firewallStatusText;
        private set => SetProperty(ref _firewallStatusText, value);
    }

    public string CoverageStatus
    {
        get => _coverageStatus;
        private set => SetProperty(ref _coverageStatus, value);
    }

    public string LastUpdated
    {
        get => _lastUpdated;
        private set => SetProperty(ref _lastUpdated, value);
    }

    public string Status
    {
        get => _status;
        private set => SetProperty(ref _status, value);
    }

    public string SecurityScoreExplanation
    {
        get => _securityScoreExplanation;
        private set => SetProperty(ref _securityScoreExplanation, value);
    }

    public string ThreatExplanation
    {
        get => _threatExplanation;
        private set => SetProperty(ref _threatExplanation, value);
    }

    public string IntegrityExplanation
    {
        get => _integrityExplanation;
        private set => SetProperty(ref _integrityExplanation, value);
    }

    public string NetworkExposureExplanation
    {
        get => _networkExposureExplanation;
        private set => SetProperty(ref _networkExposureExplanation, value);
    }

    public string DefenderExplanation
    {
        get => _defenderExplanation;
        private set => SetProperty(ref _defenderExplanation, value);
    }

    public string AsrExplanation
    {
        get => _asrExplanation;
        private set => SetProperty(ref _asrExplanation, value);
    }

    public string FirewallExplanation
    {
        get => _firewallExplanation;
        private set => SetProperty(ref _firewallExplanation, value);
    }

    public string PortProbeSummary
    {
        get => _portProbeSummary;
        private set => SetProperty(ref _portProbeSummary, value);
    }

    public void Apply(SecurityPostureSnapshot snapshot, NetworkTelemetrySnapshot? network)
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
        FirewallStatusText = snapshot.Findings.Any(row =>
            row.Area.Equals("Collection", StringComparison.OrdinalIgnoreCase) &&
            row.Detail.Contains("Firewall", StringComparison.OrdinalIgnoreCase))
            ? "UNKNOWN"
            : $"{snapshot.VulnerableFirewallProfiles} profile(s) need action";
        CoverageStatus = snapshot.Findings.Any(row => row.Area.Equals("Collection", StringComparison.OrdinalIgnoreCase))
            ? "DEGRADED"
            : "COMPLETE";
        LastUpdated = DateTime.Now.ToString("HH:mm:ss");
        SecurityScoreExplanation = snapshot.SecurityScoreExplanation;
        ThreatExplanation = snapshot.ThreatExplanation;
        IntegrityExplanation = snapshot.IntegrityExplanation;
        NetworkExposureExplanation = snapshot.NetworkExposureExplanation;
        DefenderExplanation = snapshot.DefenderExplanation;
        AsrExplanation = snapshot.AsrExplanation;
        FirewallExplanation = snapshot.FirewallExplanation;
        Replace(Findings, snapshot.Findings);
        NotifyActionCommands();
    }

    private async Task EnableFirewallAsync()
    {
        if (!Confirm(
                "Enable Windows Defender Firewall for all profiles?",
                "TGWST firewall automation"))
        {
            return;
        }

        await RunActionAsync("enable firewall", () => _actions.EnableFirewallProfilesAsync());
    }

    private async Task RunFindingActionAsync(DashboardFindingRow? finding)
    {
        if (!CanRunFindingAction(finding))
        {
            return;
        }

        switch (finding!.Action)
        {
            case DashboardFindingAction.EnableFirewall:
                await EnableFirewallAsync();
                break;
            case DashboardFindingAction.ApplyFirewallBaseline:
                await FirewallBaselineAsync();
                break;
            default:
                Status = "This finding does not expose an automatic action.";
                break;
        }
    }

    private async Task WindowsSecurityBaselineAsync()
    {
        if (!Confirm(
                "Apply the Windows Security baseline? TGWST will request Defender signature update, realtime/IOAV, behavior/script/archive/email/removable/network scanning, cloud protection, PUA blocking, ASR block rules, and post-change verification. Policy or Tamper Protection may still block some effective-state changes.",
                "TGWST Windows Security baseline"))
        {
            return;
        }

        await RunActionAsync("Windows Security baseline", () => _actions.ApplyWindowsSecurityBaselineAsync());
    }

    private async Task AdvancedFirewallControlsAsync()
    {
        if (!Confirm(
                "Apply advanced firewall controls? TGWST will enable all firewall profiles, block default inbound traffic, allow outbound traffic, enable packet logging, disable discovery/file-sharing inbound allow groups, and enforce TGWST inbound block rules for high-risk local services.",
                "TGWST advanced firewall controls"))
        {
            return;
        }

        await RunActionAsync("advanced firewall controls", () => _actions.ApplyAdvancedFirewallControlsAsync());
    }

    private async Task NetworkSettingsBaselineAsync()
    {
        if (!Confirm(
                "Apply network privacy baseline? TGWST will set non-domain active network profiles to Public, preserve domain-authenticated profiles, reduce LLMNR/WPAD/NetBIOS name-resolution exposure, require SMB client signing, enable firewall/default inbound blocking, and disable discovery/file-sharing inbound allow rules. This can affect local sharing, casting, discovery, and legacy SMB devices.",
                "TGWST network privacy baseline"))
        {
            return;
        }

        await RunActionAsync("network privacy baseline", () => _actions.ApplyNetworkSettingsBaselineAsync());
    }

    private async Task FirewallBaselineAsync()
    {
        if (!Confirm(
                "Apply firewall baseline? This enables all profiles and blocks default inbound traffic while allowing outbound traffic.",
                "TGWST firewall baseline"))
        {
            return;
        }

        await RunActionAsync("firewall baseline", () => _actions.ApplyFirewallBaselineAsync());
    }

    private async Task NetworkSurfaceHardeningAsync()
    {
        if (!Confirm(
                "Apply network surface hardening? This disables discovery/file-sharing helper services, blocks SMB/NetBIOS, mDNS/LLMNR, SSDP/WSD, qWave, CDPSvc, USB-over-IP and IKE/IPsec inbound ports, disables LLMNR and NetBIOS over TCP/IP, and enables firewall packet logging. This may break file sharing, device discovery, casting, Remote Assistance, VPN/IPsec, USB-over-IP, and some device pairing flows. A reboot is recommended after applying.",
                "TGWST network surface hardening"))
        {
            return;
        }

        await RunActionAsync("network surface hardening", () => _actions.ApplyNetworkSurfaceHardeningAsync());
    }

    private async Task Windows11BarebonesLockdownAsync()
    {
        if (!Confirm(
                "Activate Windows 11 Barebones Lockdown? TGWST will save rollback snapshots, enable firewall/default inbound blocking, disable non-core inbound allow rules, block common remote-service ports, stop and disable convenience/remote/discovery services, and terminate user-space anomaly process candidates. This will disrupt file sharing, Remote Desktop, WinRM, discovery, casting, printing, VPN/IPsec, USB-over-IP, Xbox/device workflows, and may require a reboot. Use only during a suspected security anomaly.",
                "TGWST Windows 11 Barebones Lockdown"))
        {
            return;
        }

        await RunActionAsync("Windows 11 Barebones Lockdown", () => _actions.ApplyWindows11BarebonesLockdownAsync());
    }

    private async Task InboundSurfaceAuditAsync()
    {
        if (!Confirm(
                "Run a 7-day inbound surface audit? TGWST will inspect firewall profile logging, WFP Security events, network logons, file-share audit events, SMB logs, and enabled inbound allow rules, then open a JSON report.",
                "TGWST inbound surface audit"))
        {
            return;
        }

        await RunActionAsync("inbound surface audit", () => _actions.RunInboundSurfaceAuditAsync());
    }

    private async Task WindowsCveExposureAuditAsync()
    {
        if (!Confirm(
                "Run a Windows CVE exposure audit for May 1, 2026 through June 22, 2026? TGWST will retrieve MSRC and CISA KEV data, check installed Windows updates, Defender engine/platform versions, BitLocker/WinRE posture, and write a JSON report.",
                "TGWST Windows CVE exposure audit"))
        {
            return;
        }

        await RunActionAsync("Windows CVE exposure audit", () => _actions.RunWindowsCveExposureAuditAsync());
    }

    private async Task WindowsCveSafeguardsAsync()
    {
        if (!Confirm(
                "Apply Windows CVE safeguards? This updates and hardens Microsoft Defender, requests common ASR block rules, enables firewall/default inbound blocking, starts Windows Update scan, and starts a Defender quick scan. It does not modify WinRE recovery images; review Microsoft's CVE-2026-45585 guidance before changing recovery media.",
                "TGWST Windows CVE safeguards"))
        {
            return;
        }

        await RunActionAsync("Windows CVE safeguards", () => _actions.ApplyWindowsCveSafeguardsAsync());
    }

    private async Task EicarDefenderTestAsync()
    {
        if (!Confirm(
                "Run the EICAR Defender readiness test? EICAR intentionally exercises Defender's scanner path, so TGWST will refuse to create it unless Defender is already on the June 2026 engine/platform thresholds with realtime protection enabled. If safe, TGWST creates the harmless standard test file in a temporary directory, requests inspection, waits for detection/remediation, cleans up, and opens a JSON report. Windows Security may show a real detection notification for this benign test.",
                "TGWST EICAR Defender test"))
        {
            return;
        }

        await RunActionAsync("EICAR Defender readiness test", () => _actions.RunEicarDefenderTestAsync());
    }

    private async Task EnableDefenderRealtimeAsync()
    {
        if (!Confirm(
                "Enable Microsoft Defender realtime and downloaded-file inspection?",
                "TGWST Defender automation"))
        {
            return;
        }

        await RunActionAsync("Defender realtime", () => _actions.EnableDefenderRealtimeAsync());
    }

    private async Task EnableDefenderCloudAsync()
    {
        if (!Confirm(
                "Enable Microsoft Defender cloud-delivered protection and safe sample submission?",
                "TGWST Defender cloud automation"))
        {
            return;
        }

        await RunActionAsync("Defender cloud protection", () => _actions.EnableDefenderCloudAsync());
    }

    private async Task RunQuickScanAsync()
    {
        if (!Confirm(
                "Start a Microsoft Defender quick scan?",
                "TGWST Defender automation"))
        {
            return;
        }

        await RunActionAsync("Defender quick scan", () => _actions.RunDefenderQuickScanAsync());
    }

    private async Task UpdateDefenderSignaturesAsync()
    {
        if (!Confirm(
                "Request a Microsoft Defender security-intelligence update and verify that signature state is readable afterward?",
                "TGWST Defender update"))
        {
            return;
        }

        await RunActionAsync("Defender signature update", () => _actions.UpdateDefenderSignaturesAsync());
    }

    private async Task EmergencyBaselineAsync()
    {
        if (!Confirm(
                "Activate emergency baseline? This enables Windows Firewall, blocks default inbound traffic, restores Defender realtime monitoring, and starts a quick scan.",
                "TGWST emergency baseline"))
        {
            return;
        }

        await RunActionAsync("emergency baseline", () => _actions.ActivateEmergencyBaselineAsync());
    }

    private async Task DisableSmb1Async()
    {
        if (!Confirm(
                "Disable SMBv1? This is generally safer on modern Windows, but old devices may rely on it. A reboot may be required.",
                "TGWST legacy protocol hardening"))
        {
            return;
        }

        await RunActionAsync("disable SMBv1", () => _actions.DisableSmb1Async());
    }

    private async Task LocalPortProbeAsync()
    {
        if (_isBusy)
        {
            return;
        }

        SetBusy(true);
        try
        {
            await OneTouchProgressRunner.RunAsync("brief local port probe", async () =>
            {
                PortProbeSummary = "brief local TCP connect probe running";
                var rows = await _portProbe.ProbeLocalExposureAsync();
                Replace(PortProbeResults, rows);
                var high = rows.Count(row => row.Risk == "HIGH");
                PortProbeSummary = rows.Count == 0
                    ? "No high-signal local TCP listeners accepted the brief probe."
                    : $"{rows.Count} local listener(s) accepted probe; {high} high-risk port(s).";
                _log.Warning(
                    "PortProbe",
                    PortProbeSummary,
                    rows.Count == 0 ? "No open high-signal ports found." : string.Join("; ", rows.Take(8).Select(row => $"{row.Endpoint} {row.Service} {row.Risk}")),
                    "This is a local blue-team exposure probe, not a network-wide scan.",
                    "Review any unexpected open service in the Network tab and close/block it if not needed.",
                    "Network settings",
                    "ms-settings:network-status");
                return PortProbeSummary;
            });
        }
        catch (Exception ex)
        {
            PortProbeSummary = $"port probe failed: {Trim(ex.Message)}";
            _log.Warning("PortProbe", PortProbeSummary);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async Task BlockTopNetworkRiskAsync()
    {
        await RunActionAsync("block top network risk", async () =>
        {
            var target = FindTopNetworkRisk();
            if (target == null)
            {
                return "no high-risk network target is available";
            }

            Status = $"network block target: {target.Process} {target.Remote}";
            if (target.HasRemoteAddress)
            {
                await _network.BlockRemoteCommand.ExecuteAsync(target);
            }
            else
            {
                await _network.BlockProcessCommand.ExecuteAsync(target);
            }

            return $"network block requested for {target.Process} {target.Remote}";
        });
    }

    private async Task KillTopNetworkTaskAsync()
    {
        await RunActionAsync("kill top network task", async () =>
        {
            var target = FindTopNetworkRisk();
            if (target == null)
            {
                return "no high-risk network task is available";
            }

            Status = $"task kill target: {target.Process} pid={target.ProcessId}";
            await _network.KillProcessCommand.ExecuteAsync(target);
            return $"task kill requested for {target.Process} pid={target.ProcessId}";
        });
    }

    private async Task RunActionAsync(string action, Func<Task<string>> run)
    {
        if (_isBusy)
        {
            return;
        }

        SetBusy(true);
        try
        {
            Status = $"{action} requested";
            var message = await OneTouchProgressRunner.RunAsync(action, run);
            Status = message;
            _log.Success("Dashboard", message);
            ActionCompleted?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex)
        {
            var detail = $"{action} failed: {Trim(ex.Message)}";
            Status = detail;
            _log.Warning("Dashboard", detail);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private NetworkConnectionRow? FindTopNetworkRisk()
    {
        var snapshot = _network.LastSnapshot;
        if (snapshot == null)
        {
            return null;
        }

        return snapshot.RiskyConnections
                   .Where(row => row.RiskScore >= 70)
                   .OrderByDescending(row => row.RiskScore)
                   .FirstOrDefault()
               ?? snapshot.InboundActivity
                   .Where(row => row.RiskScore >= 35)
                   .OrderByDescending(row => row.RiskScore)
                   .FirstOrDefault();
    }

    private bool CanRunAction()
    {
        return !_isBusy;
    }

    private bool CanRunFindingAction(DashboardFindingRow? finding)
    {
        return !_isBusy && finding?.HasAutomatedAction == true;
    }

    private bool CanBlockTopNetworkRisk()
    {
        var target = FindTopNetworkRisk();
        return !_isBusy && target != null && (target.HasRemoteAddress || target.HasProcess);
    }

    private bool CanKillTopNetworkTask()
    {
        return !_isBusy && FindTopNetworkRisk()?.HasProcess == true;
    }

    private void SetBusy(bool isBusy)
    {
        if (SetProperty(ref _isBusy, isBusy, nameof(_isBusy)))
        {
            NotifyActionCommands();
        }
    }

    private void NotifyActionCommands()
    {
        WindowsSecurityBaselineCommand.NotifyCanExecuteChanged();
        AdvancedFirewallControlsCommand.NotifyCanExecuteChanged();
        NetworkSettingsBaselineCommand.NotifyCanExecuteChanged();
        EnableFirewallCommand.NotifyCanExecuteChanged();
        FirewallBaselineCommand.NotifyCanExecuteChanged();
        NetworkSurfaceHardeningCommand.NotifyCanExecuteChanged();
        Windows11BarebonesLockdownCommand.NotifyCanExecuteChanged();
        InboundSurfaceAuditCommand.NotifyCanExecuteChanged();
        WindowsCveExposureAuditCommand.NotifyCanExecuteChanged();
        WindowsCveSafeguardsCommand.NotifyCanExecuteChanged();
        EicarDefenderTestCommand.NotifyCanExecuteChanged();
        EnableDefenderRealtimeCommand.NotifyCanExecuteChanged();
        EnableDefenderCloudCommand.NotifyCanExecuteChanged();
        RunQuickScanCommand.NotifyCanExecuteChanged();
        UpdateDefenderSignaturesCommand.NotifyCanExecuteChanged();
        EmergencyBaselineCommand.NotifyCanExecuteChanged();
        DisableSmb1Command.NotifyCanExecuteChanged();
        LocalPortProbeCommand.NotifyCanExecuteChanged();
        BlockTopNetworkRiskCommand.NotifyCanExecuteChanged();
        KillTopNetworkTaskCommand.NotifyCanExecuteChanged();
        RunFindingActionCommand.NotifyCanExecuteChanged();
    }

    private static bool Confirm(string message, string caption)
    {
        return System.Windows.MessageBox.Show(
            message,
            caption,
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No) == MessageBoxResult.Yes;
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

public sealed class NetworkDashboardViewModel : ObservableObject, IDisposable
{
    private readonly NetworkTelemetryService _networkTelemetry;
    private readonly NetworkResponseService _response;
    private readonly DeepNetworkAnalyzerService _deepAnalyzer;
    private readonly GuiLogService _log;
    private bool _refreshInProgress;
    private bool _deepScanInProgress;
    private int _lastHighRiskCount = -1;
    private string _status = "initializing";
    private int _totalConnections;
    private int _inboundExposure;
    private int _outboundConnections;
    private string _inboundInfraSummary = "watching listeners";
    private string _connectionInspection = "Right-click a connection and choose Inspect for endpoint, service, and response guidance.";
    private string _bandwidthStatus = "sampling";
    private string _firewallStatusText = "unknown";
    private string _lastUpdated = "-";
    private string _deepScanStatus = "not run";
    private string _deepScanSummary = "Deep network analyzer has not run.";

    public ObservableCollection<NetworkConnectionRow> RiskyConnections { get; } = new();
    public ObservableCollection<NetworkConnectionRow> InboundActivity { get; } = new();
    public ObservableCollection<NetworkConnectionRow> Connections { get; } = new();
    public ObservableCollection<DeepNetworkFindingRow> DeepFindings { get; } = new();
    public ObservableCollection<DeepNetworkEndpointRow> DeepEndpoints { get; } = new();
    public ObservableCollection<DeepNetworkRouteRow> DeepRoutes { get; } = new();
    public ObservableCollection<DeepNetworkDnsRow> DeepDnsRecords { get; } = new();
    public NetworkTelemetrySnapshot? LastSnapshot { get; private set; }
    public IRelayCommand<NetworkConnectionRow?> InspectConnectionCommand { get; }
    public IAsyncRelayCommand<NetworkConnectionRow?> KillProcessCommand { get; }
    public IAsyncRelayCommand<NetworkConnectionRow?> BlockProcessCommand { get; }
    public IAsyncRelayCommand<NetworkConnectionRow?> BlockRemoteCommand { get; }
    public IAsyncRelayCommand DeepNetworkScanCommand { get; }

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

    public string InboundInfraSummary
    {
        get => _inboundInfraSummary;
        private set => SetProperty(ref _inboundInfraSummary, value);
    }

    public string ConnectionInspection
    {
        get => _connectionInspection;
        private set => SetProperty(ref _connectionInspection, value);
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

    public string DeepScanStatus
    {
        get => _deepScanStatus;
        private set => SetProperty(ref _deepScanStatus, value);
    }

    public string DeepScanSummary
    {
        get => _deepScanSummary;
        private set => SetProperty(ref _deepScanSummary, value);
    }

    public Dictionary<string, int> CategoryCounts { get; } = new();

    public NetworkDashboardViewModel(
        NetworkTelemetryService networkTelemetry,
        NetworkResponseService response,
        DeepNetworkAnalyzerService deepAnalyzer,
        GuiLogService log)
    {
        _networkTelemetry = networkTelemetry;
        _response = response;
        _deepAnalyzer = deepAnalyzer;
        _log = log;
        InspectConnectionCommand = new RelayCommand<NetworkConnectionRow?>(InspectConnection, row => row != null);
        KillProcessCommand = new AsyncRelayCommand<NetworkConnectionRow?>(KillProcessAsync, _ => false);
        BlockProcessCommand = new AsyncRelayCommand<NetworkConnectionRow?>(BlockProcessAsync, CanTargetProcess);
        BlockRemoteCommand = new AsyncRelayCommand<NetworkConnectionRow?>(BlockRemoteAsync, CanTargetRemote);
        DeepNetworkScanCommand = new AsyncRelayCommand(RunDeepNetworkScanAsync, () => !_deepScanInProgress);
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
        InboundInfraSummary = BuildInboundInfraSummary(snapshot.InboundActivity);
        Replace(RiskyConnections, snapshot.RiskyConnections);
        Replace(InboundActivity, snapshot.InboundActivity);
        Replace(Connections, snapshot.Connections
            .Where(row => row.RiskScore >= 35 || row.IsListener || (row.HasRemoteAddress && !row.Category.Equals("typicalprocess", StringComparison.OrdinalIgnoreCase)))
            .Take(120));

        // Compute category counts for polish / status visibility (typicalprocess, PotentialC2, etc.)
        CategoryCounts.Clear();
        foreach (var row in snapshot.Connections.Concat(snapshot.RiskyConnections))
        {
            var cat = string.IsNullOrWhiteSpace(row.Category) ? "uncategorized" : row.Category;
            CategoryCounts[cat] = CategoryCounts.GetValueOrDefault(cat, 0) + 1;
        }
        OnPropertyChanged(nameof(CategoryCounts));
        BlockProcessCommand.NotifyCanExecuteChanged();
        BlockRemoteCommand.NotifyCanExecuteChanged();

        var highRisk = snapshot.RiskyConnections.Count(row => row.RiskScore >= 70);
        if (highRisk != _lastHighRiskCount)
        {
            _lastHighRiskCount = highRisk;
            if (highRisk > 0)
            {
                var topRisk = snapshot.RiskyConnections
                    .OrderByDescending(row => row.RiskScore)
                    .First();
                _log.Warning(
                    "Network",
                    $"{highRisk} high-risk connection(s) detected",
                    BuildConnectionDetail(topRisk),
                    $"{topRisk.BlueTeamSignal}: {topRisk.Risk}. Service={topRisk.Service}, State={topRisk.State}.",
                    "Review the Network tab. Right-click the exact row to inspect it or apply a verified process/IP firewall block.",
                    "Network settings",
                    "ms-settings:network-status");
            }
        }
    }

    private void InspectConnection(NetworkConnectionRow? row)
    {
        if (row == null)
        {
            return;
        }

        ConnectionInspection = row.ProtocolInspection;
        Status = "connection inspected";
        _log.Info(
            "NetworkInspect",
            $"inspected {row.Process} {row.ProtocolType}",
            BuildConnectionDetail(row),
            $"{row.BlueTeamSignal}. {row.ProtocolConcern}",
            "Use the selected-row firewall actions only if the process or remote endpoint is unexpected. Process termination remains staged.",
            "Network settings",
            "ms-settings:network-status");
    }

    private async Task KillProcessAsync(NetworkConnectionRow? row)
    {
        if (row == null || !Confirm(
                $"Terminate {row.Process} (PID {row.ProcessId})?",
                "TGWST task kill"))
        {
            return;
        }

        await RunResponseActionAsync("kill process", () => _response.KillProcessAsync(row));
    }

    private async Task BlockProcessAsync(NetworkConnectionRow? row)
    {
        if (row == null || !Confirm(
                $"Add inbound and outbound firewall blocks for {row.Process} (PID {row.ProcessId})?",
                "TGWST firewall block"))
        {
            return;
        }

        await RunResponseActionAsync("block process", () => _response.BlockProcessNetworkAsync(row));
    }

    private async Task BlockRemoteAsync(NetworkConnectionRow? row)
    {
        if (row == null || !Confirm(
                $"Add inbound and outbound firewall blocks for remote address {row.RemoteAddress}?",
                "TGWST firewall block"))
        {
            return;
        }

        await RunResponseActionAsync("block remote", () => _response.BlockRemoteAddressAsync(row));
    }

    private async Task RunDeepNetworkScanAsync()
    {
        if (_deepScanInProgress)
        {
            return;
        }

        _deepScanInProgress = true;
        DeepNetworkScanCommand.NotifyCanExecuteChanged();
        DeepScanStatus = "scan running";
        Status = "deep network scan running";

        try
        {
            var summary = await OneTouchProgressRunner.RunAsync("deep network analyzer scan", async () =>
            {
                var snapshot = await _deepAnalyzer.ScanAsync();
                ApplyDeepScan(snapshot);
                return snapshot.Summary;
            });

            DeepScanStatus = $"last scan {DateTimeOffset.Now:HH:mm:ss}";
            Status = "deep network scan complete";
            var critical = DeepFindings.Count(row => row.Severity.Equals("CRITICAL", StringComparison.OrdinalIgnoreCase));
            var warnings = DeepFindings.Count(row => row.Severity.Equals("WARN", StringComparison.OrdinalIgnoreCase));
            if (critical > 0 || warnings > 0)
            {
                _log.Warning(
                    "DeepNetwork",
                    summary,
                    $"critical={critical}; warnings={warnings}; endpoints={DeepEndpoints.Count}; routes={DeepRoutes.Count}; dns={DeepDnsRecords.Count}",
                    "The on-demand deep network analyzer found routing, DNS, or endpoint items that should be reviewed.",
                    "Inspect Findings, Endpoints, Routes, and DNS in the Network tab before blocking any traffic.");
            }
            else
            {
                _log.Success(
                    "DeepNetwork",
                    summary,
                    $"endpoints={DeepEndpoints.Count}; routes={DeepRoutes.Count}; dns={DeepDnsRecords.Count}",
                    "No high-severity network findings were produced by this scan.",
                    "Run again after suspicious activity starts if a point-in-time scan misses transient traffic.");
            }
        }
        catch (Exception ex)
        {
            var detail = $"deep network scan failed: {Trim(ex.Message)}";
            DeepScanStatus = "scan failed";
            DeepScanSummary = detail;
            Status = detail;
            _log.Warning("DeepNetwork", detail);
        }
        finally
        {
            _deepScanInProgress = false;
            DeepNetworkScanCommand.NotifyCanExecuteChanged();
        }
    }

    private void ApplyDeepScan(DeepNetworkAnalysisSnapshot snapshot)
    {
        DeepScanSummary = snapshot.Summary;
        Replace(DeepFindings, snapshot.Findings);
        Replace(DeepEndpoints, snapshot.Endpoints);
        Replace(DeepRoutes, snapshot.Routes);
        Replace(DeepDnsRecords, snapshot.DnsRecords);
    }

    private async Task RunResponseActionAsync(string action, Func<Task<string>> run)
    {
        try
        {
            Status = $"{action} requested";
            var message = await OneTouchProgressRunner.RunAsync(action, run);
            Status = message;
            _log.Warning("Network", message);
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            var detail = $"{action} failed: {Trim(ex.Message)}";
            Status = detail;
            _log.Warning("Network", detail);
        }
        finally
        {
            BlockProcessCommand.NotifyCanExecuteChanged();
            BlockRemoteCommand.NotifyCanExecuteChanged();
        }
    }

    private static bool Confirm(string message, string caption)
    {
        return System.Windows.MessageBox.Show(
            message,
            caption,
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No) == MessageBoxResult.Yes;
    }

    private static bool CanTargetProcess(NetworkConnectionRow? row)
    {
        return NetworkResponseService.HasTargetableProcessIdentity(row);
    }

    private static bool CanTargetRemote(NetworkConnectionRow? row)
    {
        return row?.HasRemoteAddress == true;
    }

    private static string BuildInboundInfraSummary(IReadOnlyCollection<NetworkConnectionRow> rows)
    {
        var listeners = rows.Count(row => row.IsListener);
        var udpSockets = rows.Count(row => row.IsUdpSocket);
        var remoteSessions = rows.Count(row => row.HasRemoteAddress && !row.IsListener);
        return $"watching {listeners} listener(s), {udpSockets} udp socket(s), {remoteSessions} remote session(s)";
    }

    private static string BuildConnectionDetail(NetworkConnectionRow row)
    {
        var baseInfo = $"process={row.Process} pid={row.ProcessId}; protocol={row.ProtocolType}; local={row.Local}; remote={row.Remote}; state={row.State}; risk={row.RiskScore}/100; why={row.Risk}; concern={row.ProtocolConcern}";
        var enriched = $" category={row.Category}; host={row.RemoteHost ?? "none"}; anomaly={row.Anomaly ?? "none"}";
        return baseInfo + enriched;
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
    private int _suspendedProcessSignals;

    public ObservableCollection<TelemetryEventRow> Events { get; } = new();
    public ObservableCollection<TelemetryEventRow> ActionableEvents { get; } = new();
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

    public int SuspendedProcessSignals
    {
        get => _suspendedProcessSignals;
        private set => SetProperty(ref _suspendedProcessSignals, value);
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

        if (IsActionableTelemetry(row))
        {
            ActionableEvents.Insert(0, row);
            while (ActionableEvents.Count > 120)
            {
                ActionableEvents.RemoveAt(ActionableEvents.Count - 1);
            }
        }

        if (row.Source.Equals("Process", StringComparison.OrdinalIgnoreCase)) ProcessSignals++;
        if (row.Source.Equals("Registry", StringComparison.OrdinalIgnoreCase)) RegistrySignals++;
        if (row.Source.Equals("File", StringComparison.OrdinalIgnoreCase)) FileSignals++;
        if (row.Signal.Equals("suspended start", StringComparison.OrdinalIgnoreCase)) SuspendedProcessSignals++;

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

    private static bool IsActionableTelemetry(TelemetryEventRow row)
    {
        return row.Severity is CyberSeverity.Warning or CyberSeverity.Critical;
    }
}

public sealed class ToolsDashboardViewModel : ObservableObject
{
    private readonly ToolExecutionService _tools;
    private readonly GuiLogService _log;
    private readonly IServiceProvider _services;
    private IReadOnlyList<JunkCandidate> _latestJunkCandidates = Array.Empty<JunkCandidate>();
    private bool _isBusy;
    private string _status = "ready";
    private ComputerCleaningMultiToolWindow? _cleanerWindow;

    public ObservableCollection<StartupAuditRow> StartupItems { get; } = new();
    public ObservableCollection<JunkFindingRow> JunkFindings { get; } = new();
    public ObservableCollection<EventFindingRow> EventFindings { get; } = new();
    public IAsyncRelayCommand IntegrityScanCommand { get; }
    public IAsyncRelayCommand StartupAuditCommand { get; }
    public IAsyncRelayCommand JunkAnalyzeCommand { get; }
    public IAsyncRelayCommand JunkCleanCommand { get; }
    public IAsyncRelayCommand EventReviewCommand { get; }
    public IRelayCommand OpenComputerCleaningToolCommand { get; }

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

    public ToolsDashboardViewModel(ToolExecutionService tools, GuiLogService log, IServiceProvider services)
    {
        _tools = tools;
        _log = log;
        _services = services;
        IntegrityScanCommand = new AsyncRelayCommand(RunIntegrityAsync, () => !IsBusy);
        StartupAuditCommand = new AsyncRelayCommand(RunStartupAuditAsync, () => !IsBusy);
        JunkAnalyzeCommand = new AsyncRelayCommand(RunJunkAnalyzeAsync, () => !IsBusy);
        JunkCleanCommand = new AsyncRelayCommand(RunJunkCleanAsync, () => !IsBusy && _latestJunkCandidates.Any(candidate => candidate.SafeToClean));
        EventReviewCommand = new AsyncRelayCommand(RunEventReviewAsync, () => !IsBusy);
        OpenComputerCleaningToolCommand = new RelayCommand(OpenComputerCleaningTool);
    }

    private void OpenComputerCleaningTool()
    {
        if (_cleanerWindow != null)
        {
            if (_cleanerWindow.IsVisible)
            {
                _cleanerWindow.Activate();
                Status = "computer cleaning multi-tool already open";
                return;
            }

            _cleanerWindow = null;
        }

        var window = _services.GetRequiredService<ComputerCleaningMultiToolWindow>();
        window.Owner = System.Windows.Application.Current?.MainWindow;
        window.Closed += (_, _) =>
        {
            if (ReferenceEquals(_cleanerWindow, window))
            {
                _cleanerWindow = null;
            }
        };
        _cleanerWindow = window;
        window.Show();
        window.Activate();
        Status = "computer cleaning multi-tool opened";
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
        await RunToolAsync("Residue", AnalyzeJunkCoreAsync);
    }

    private async Task RunJunkCleanAsync()
    {
        var safeCount = _latestJunkCandidates.Count(candidate => candidate.SafeToClean);
        if (safeCount == 0 ||
            System.Windows.MessageBox.Show(
                $"Delete {safeCount} safe residue target(s)?\n\nReview-only items and non-safe candidates will not be deleted.",
                "TGWST residue cleanup",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            return;
        }

        await RunToolAsync("Residue", async ct =>
        {
            var result = await _tools.CleanSafeJunkAsync(_latestJunkCandidates, ct);
            Status = $"safe cleanup deleted={result.DeletedCount} skipped={result.SkippedCount}";
            _log.Warning("Residue", Status);
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
        Status = $"{candidates.Count} residue candidate(s) grouped";
        _log.Success("Residue", Status);
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
    private string _selectedSeverityFilter = "ACTIONABLE";

    public ObservableCollection<SecurityLogEntry> Entries { get; }
    public ObservableCollection<SecurityLogEntry> FilteredEntries { get; } = new();
    public IReadOnlyList<string> SeverityFilters { get; } = ["ACTIONABLE", "WARNING", "CRITICAL", "SUCCESS", "ALL"];

    public string SelectedSeverityFilter
    {
        get => _selectedSeverityFilter;
        set
        {
            if (SetProperty(ref _selectedSeverityFilter, value))
            {
                RefreshFilteredEntries();
            }
        }
    }

    public LogsDashboardViewModel(GuiLogService log)
    {
        Entries = log.Entries;
        Entries.CollectionChanged += (_, _) => RefreshFilteredEntries();
        RefreshFilteredEntries();
    }

    private void RefreshFilteredEntries()
    {
        var rows = SelectedSeverityFilter switch
        {
            "ALL" => Entries,
            "ACTIONABLE" => Entries.Where(IsActionableLogEntry),
            _ => Entries.Where(entry => entry.Severity.ToString().Equals(SelectedSeverityFilter, StringComparison.OrdinalIgnoreCase))
        };

        FilteredEntries.Clear();
        foreach (var entry in rows.TakeLast(600))
        {
            FilteredEntries.Add(entry);
        }
    }

    private static bool IsActionableLogEntry(SecurityLogEntry entry)
    {
        return entry.Severity is CyberSeverity.Warning or CyberSeverity.Critical ||
               entry.HasLink ||
               !string.IsNullOrWhiteSpace(entry.RecommendedAction);
    }
}
