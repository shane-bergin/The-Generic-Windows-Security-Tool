using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using TGWST.Core.Feeds;
using TGWST.Core.Scan;
using TGWST.Core.LLM;
using MessageBox = System.Windows.MessageBox;
using TGWST.App.Windows;

namespace TGWST.App.Tabs;

public partial class ScanTab : System.Windows.Controls.UserControl, INotifyPropertyChanged
{
    private readonly ScanEngine _engine = new();
    private CancellationTokenSource? _cts;
    public ObservableCollection<ScanResult> Results { get; } = new();
    public ThreatFeedsViewModel ThreatFeeds { get; } = new();

    private string _status = "Ready";
    public string Status { get => _status; set { _status = value; OnPropertyChanged(); } }


    public ObservableCollection<string> LogLines { get; } = new();

private bool _useLLM = true;
public bool UseLLM { get => _useLLM; set { _useLLM = value; OnPropertyChanged(); } }

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
        Status = "Scanning...";
        ProgressVisible = Visibility.Visible;
        ProgressIndeterminate = false;
        Progress = 0;
        Results.Clear();
        LogLines.Clear();

        var type = ScanTypeIndex switch
        {
            0 => ScanType.Quick,
            1 => ScanType.Standard,
            2 => ScanType.Full,
            _ => ScanType.Custom
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

        var hits = await _engine.RunScanAsync(type, root, progress, textLog, UseLLM, ct);

        var hitList = hits.ToList();
        var hitCount = hitList.Count;
        Dispatcher.Invoke(() =>
        {
            foreach (var hit in hitList) Results.Add(hit);
            Status = $"{hitCount} hits";
            AppendLog($"Scan complete. Hits: {hitCount}");
        });
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
    }
}

    private async void ReloadFeeds_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            await ReloadFeeds_ClickAsync(sender, e);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Operation failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task ReloadFeeds_ClickAsync(object sender, RoutedEventArgs e)
    {
        await ReloadFeedsAsync();
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
        var yaraCount = ThreatFeeds.YaraRuleCount;
        var iocCount = ThreatFeeds.IocBundleCount;
        Dispatcher.Invoke(() =>
        {
            Status = $"Feeds: {yaraCount} YARA rules, {iocCount} IOC bundles";
        });
    }
    catch (Exception ex)
    {
        Status = $"ERROR: Feed reload failed: {ex.Message}";
    }
    finally
    {
        IsBusy = false;
    }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    private void LLMSettings_Click(object sender, RoutedEventArgs e)
    {
        var window = new LLMSettingsWindow
        {
            Owner = System.Windows.Application.Current.MainWindow
        };
        window.ShowDialog();
    }

    private void AppendLog(string message)
    {
        Dispatcher.Invoke(() => LogLines.Add($"{DateTime.Now:HH:mm:ss} {message}"));
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
