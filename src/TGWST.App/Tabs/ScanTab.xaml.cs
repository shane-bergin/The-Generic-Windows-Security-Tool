using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using TGWST.Core.Feeds;
using TGWST.Core.Scan;
using MessageBox = System.Windows.MessageBox;
using FeedIocBundle = TGWST.Core.Feeds.IocBundle;

namespace TGWST.App.Tabs;

public partial class ScanTab : System.Windows.Controls.UserControl, INotifyPropertyChanged
{
    private readonly ScanEngine _engine = new();
    private CancellationTokenSource? _cts;
    public ObservableCollection<ScanResult> Results { get; } = new();
    public ObservableCollection<IocBundleView> IocBundles { get; } = new();
    public ThreatFeedsViewModel ThreatFeeds { get; } = new();

    private string _status = "Ready";
    public string Status { get => _status; set { _status = value; OnPropertyChanged(); } }

    private string _clamStatus = "Checking ClamAV...";
    public string ClamStatus { get => _clamStatus; set { _clamStatus = value; OnPropertyChanged(); } }

    public ObservableCollection<string> LogLines { get; } = new();

private bool _useClamAv = true;
public bool UseClamAv { get => _useClamAv; set { _useClamAv = value; OnPropertyChanged(); } }

private bool _isBusy;
public bool IsBusy { get => _isBusy; set { _isBusy = value; OnPropertyChanged(); } }

private int _scanTypeIndex = 0;
public int ScanTypeIndex { get => _scanTypeIndex; set { _scanTypeIndex = value; OnPropertyChanged(); } }

private double _progress;
public double Progress { get => _progress; set { _progress = value; OnPropertyChanged(); } }

    private Visibility _progressVisible = Visibility.Collapsed;
    public Visibility ProgressVisible { get => _progressVisible; set { _progressVisible = value; OnPropertyChanged(); } }

    private bool _progressIndeterminate;
    public bool ProgressIndeterminate { get => _progressIndeterminate; set { _progressIndeterminate = value; OnPropertyChanged(); } }

    public ScanTab()
    {
        InitializeComponent();
        DataContext = this;
        ScanTypeIndex = 0;
        RefreshClamStatus();
        _ = ReloadFeedsAsync();
    }

private async void Scan_Click(object sender, RoutedEventArgs e)
{
    if (IsBusy) return;

    _cts = new CancellationTokenSource();
    var ct = _cts.Token;

    try
    {
        IsBusy = true;
        RefreshClamStatus();
        Status = "Scanning...";
        ProgressVisible = Visibility.Visible;
        ProgressIndeterminate = false;
        Progress = 0;
        Results.Clear();
        LogLines.Clear();

        var type = ScanTypeIndex switch
        {
            0 => ScanType.Quick,
            1 => ScanType.Full,
            _ => ScanType.Quick
        };

        string? root = null;

        var textLog = new Progress<string>(msg => Dispatcher.Invoke(() => AppendLog(msg)));

        Dispatcher.Invoke(() => AppendLog($"Starting scan ({type}) at {(root ?? "default roots")}..."));
        double lastLogged = 0;
        var progress = new Progress<double>(p =>
        {
            Dispatcher.Invoke(() =>
            {
                Progress = p;
                if (p - lastLogged >= 5)
                {
                    AppendLog($"Progress {p:0}%");
                    lastLogged = p;
                }
            });
        });

        var hits = await _engine.RunScanAsync(type, root, progress, textLog, UseClamAv, ct);

        foreach (var hit in hits) Results.Add(hit);
        Status = $"{Results.Count} hits";
        AppendLog($"Scan complete. Hits: {Results.Count}");
    }
    catch (OperationCanceledException)
    {
        Status = "Scan cancelled";
        AppendLog("Scan cancelled by user.");
    }
    catch (Exception ex)
    {
        Status = $"ERROR: Scan failed: {ex.Message}";
        AppendLog(Status);
    }
    finally
    {
        _cts = null;
        IsBusy = false;
        ProgressVisible = Visibility.Collapsed;
        ProgressIndeterminate = false;
        RefreshClamStatus();
    }
}

    private async void ReloadFeeds_Click(object sender, RoutedEventArgs e) => await ReloadFeedsAsync();

private async void UpdateSignatures_Click(object sender, RoutedEventArgs e)
{
    if (IsBusy) return;

    try
    {
        IsBusy = true;
        Status = "Updating signatures...";
        var textLog = new Progress<string>(msg => AppendLog(msg));
        await _engine.UpdateSignaturesAsync(textLog);
        Status = "Signatures updated";
        AppendLog("Signature update completed.");
    }
    catch (Exception ex)
    {
        Status = $"ERROR: Signature update failed: {ex.Message}";
        AppendLog(Status);
    }
    finally
    {
        IsBusy = false;
        RefreshClamStatus();
    }
}

private void Cancel_Click(object sender, RoutedEventArgs e)
{
    _cts?.Cancel();
}

private async Task ReloadFeedsAsync()
{
    if (IsBusy) return;

    try
    {
        IsBusy = true;
        var summary = await ThreatFeeds.ReloadAsync();

        IocBundles.Clear();
        foreach (var b in FeedManager.IocBundles)
        {
            IocBundles.Add(new IocBundleView(b));
        }
        Status = $"Feeds: {ThreatFeeds.YaraRuleCount} YARA rules, {ThreatFeeds.IocBundleCount} IOC bundles";
    }
    catch (Exception ex)
    {
        Status = $"ERROR: Feed reload failed: {ex.Message}";
    }
    finally
    {
        IsBusy = false;
        RefreshClamStatus();
    }
}

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private void AppendLog(string message)
    {
        Dispatcher.Invoke(() => LogLines.Add($"{DateTime.Now:HH:mm:ss} {message}"));
    }

    private void RefreshClamStatus()
    {
        var status = _engine.GetDatabaseStatus();
        ClamStatus = DescribeClamStatus(status);
    }

    private static string DescribeClamStatus(ClamAvEngine.ClamAvDbStatus status)
    {
        if (!status.Available)
            return "WARNING: ClamAV not found; deep scan will be skipped.";

        if (!status.DatabaseFound && !status.FreshclamAvailable)
            return "WARNING: ClamAV DB missing and updater unavailable; deep scan will be skipped.";

        if (!status.DatabaseFound && status.FreshclamAvailable)
            return "INFO: ClamAV DB missing; updater will download signatures before scanning.";

        if (status.IsStale && status.FreshclamAvailable)
            return $"INFO: ClamAV DB stale ({FormatAge(status.Age)}); updater will refresh before scanning.";

        if (status.IsStale && !status.FreshclamAvailable)
            return $"WARNING: ClamAV DB stale ({FormatAge(status.Age)}); updater unavailable.";

        if (!status.FreshclamAvailable)
            return $"INFO: ClamAV DB current ({FormatAge(status.Age)}); updater unavailable.";

        return $"INFO: ClamAV DB current ({FormatAge(status.Age)}).";
    }

    private static string FormatAge(TimeSpan? age)
    {
        if (age == null) return "unknown age";
        if (age.Value.TotalDays >= 1) return $"{age.Value.TotalDays:0.#}d";
        if (age.Value.TotalHours >= 1) return $"{age.Value.TotalHours:0.#}h";
        return $"{age.Value.TotalMinutes:0.#}m";
    }

    public sealed class IocBundleView
    {
        public string? Family { get; }
        public int MutexCount { get; }
        public int DomainCount { get; }
        public int FilenameCount { get; }

        public IocBundleView(FeedIocBundle bundle)
        {
            Family = string.IsNullOrWhiteSpace(bundle.Family) ? "(unknown)" : bundle.Family;
            MutexCount = bundle.Mutexes?.Count ?? 0;
            DomainCount = bundle.Domains?.Count ?? 0;
            FilenameCount = bundle.Filenames?.Count ?? 0;
        }
    }
}

public sealed class ThreatFeedsViewModel : INotifyPropertyChanged
{
    private int _yaraRuleCount;
    public int YaraRuleCount { get => _yaraRuleCount; private set { _yaraRuleCount = value; OnPropertyChanged(); OnPropertyChanged(nameof(LastReloadDisplay)); } }

    private int _iocBundleCount;
    public int IocBundleCount { get => _iocBundleCount; private set { _iocBundleCount = value; OnPropertyChanged(); OnPropertyChanged(nameof(LastReloadDisplay)); } }

    private int _totalFamilies;
    public int TotalFamilies { get => _totalFamilies; private set { _totalFamilies = value; OnPropertyChanged(); OnPropertyChanged(nameof(LastReloadDisplay)); } }

    private DateTime? _reloadedAtLocal;
    public DateTime? ReloadedAtLocal { get => _reloadedAtLocal; private set { _reloadedAtLocal = value; OnPropertyChanged(); OnPropertyChanged(nameof(LastReloadDisplay)); } }

    public string LastReloadDisplay => ReloadedAtLocal.HasValue ? $"Reloaded {ReloadedAtLocal.Value:G}" : "";

    public ObservableCollection<string> Families { get; } = new();

    public async Task<FeedSummary> ReloadAsync()
    {
        var summary = await FeedManager.ReloadAsync().ConfigureAwait(true);
        Families.Clear();
        foreach (var f in summary.Families) Families.Add(f);
        YaraRuleCount = summary.YaraRuleCount;
        IocBundleCount = summary.IocBundleCount;
        TotalFamilies = summary.TotalFamilies;
        ReloadedAtLocal = summary.ReloadedAtUtc.ToLocalTime();
        return summary;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
