using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using TGWST.Core.Scan;
using MessageBox = System.Windows.MessageBox;

namespace TGWST.App.Tabs;

public partial class ScanTab : System.Windows.Controls.UserControl, INotifyPropertyChanged
{
private readonly ScanEngine _engine = new();
public ObservableCollection<ScanResult> Results { get; } = new();

private string _status = "Ready";
public string Status { get => _status; set { _status = value; OnPropertyChanged(); } }

private string _logText = "";
public string LogText { get => _logText; set { _logText = value; OnPropertyChanged(); } }

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

        _engine.UseClam = false; // ClamAV disabled; YARA-only
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

        var hits = await _engine.RunScanAsync(type, root, progress, textLog);

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

public event PropertyChangedEventHandler? PropertyChanged;
protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

private void AppendLog(string message)
{
    var line = $"{DateTime.Now:HH:mm:ss} {message}";
    LogText = string.IsNullOrEmpty(LogText) ? line : $"{LogText}{Environment.NewLine}{line}";
}


}
