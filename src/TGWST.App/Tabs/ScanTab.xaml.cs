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
    public ObservableCollection<ScanResult> Results { get; } = new();
    public ObservableCollection<IocBundleView> IocBundles { get; } = new();
    public ThreatFeedsViewModel ThreatFeeds { get; } = new();

    private string _status = "Ready";
    public string Status { get => _status; set { _status = value; OnPropertyChanged(); } }

    private string _logText = "";
    public string LogText { get => _logText; set { _logText = value; OnPropertyChanged(); } }

    private bool _useClamAv = true;
    public bool UseClamAv { get => _useClamAv; set { _useClamAv = value; OnPropertyChanged(); } }

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
        ScanTypeCombo.SelectedIndex = 0;
        _ = ReloadFeedsAsync();
    }

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Status = "Scanning...";
            ProgressVisible = Visibility.Visible;
            ProgressIndeterminate = false;
            Progress = 0;
            Results.Clear();
            LogText = "";

            var type = ScanTypeCombo.SelectedIndex switch
            {
                0 => ScanType.Quick,
                1 => ScanType.Full,
                _ => ScanType.Quick
            };

            string? root = null;

            var textLog = new Progress<string>(msg => AppendLog(msg));

            AppendLog($"Starting scan ({type}) at {(root ?? "default roots")}...");
            double lastLogged = 0;
            var progress = new Progress<double>(p =>
            {
                Progress = p;
                if (p - lastLogged >= 5)
                {
                    AppendLog($"Progress {p:0}%");
                    lastLogged = p;
                }
            });

            var hits = await _engine.RunScanAsync(type, root, progress, textLog, UseClamAv);

            foreach (var hit in hits) Results.Add(hit);
            Status = $"{Results.Count} hits";
            AppendLog($"Scan complete. Hits: {Results.Count}");
        }
        catch (Exception ex)
        {
            Status = $"Scan failed: {ex.Message}";
            AppendLog(Status);
        }
        finally
        {
            ProgressVisible = Visibility.Collapsed;
            ProgressIndeterminate = false;
        }
    }

    private async void ReloadFeeds_Click(object sender, RoutedEventArgs e) => await ReloadFeedsAsync();

    private async Task ReloadFeedsAsync()
    {
        try
        {
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
            Status = $"Feed reload failed: {ex.Message}";
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private void AppendLog(string message)
    {
        var line = $"{DateTime.Now:HH:mm:ss} {message}";
        LogText = string.IsNullOrEmpty(LogText) ? line : $"{LogText}{Environment.NewLine}{line}";
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
