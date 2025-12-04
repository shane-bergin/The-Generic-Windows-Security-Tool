using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Security.Principal;
using System.Threading;
using System.Windows;
using TGWST.Core.EventLog;

namespace TGWST.App.Tabs;

public partial class EventLogTab : System.Windows.Controls.UserControl
{
    private readonly EventLogAnalyzer _analyzer = new();
    private readonly EventLogViewModel _vm = new();
    private CancellationTokenSource? _cts;

    public EventLogTab()
    {
        InitializeComponent();
        DataContext = _vm;
    }

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        try
        {
            var lookback = _vm.SelectedLookbackChoice?.Span ?? TimeSpan.FromHours(24);
            _vm.Status = $"Scanning last {lookback.TotalHours:0}h...";
            var results = await _analyzer.ScanAsync(lookback, _cts.Token);

            _vm.Findings.Clear();
            foreach (var f in results)
                _vm.Findings.Add(f);

            _vm.Status = $"Found {_vm.Findings.Count} events.";
        }
        catch (OperationCanceledException)
        {
            _vm.Status = "Scan canceled.";
        }
        catch (Exception ex)
        {
            _vm.Status = $"Scan failed: {ex.Message}";
        }
    }
}

public sealed class EventLogViewModel : INotifyPropertyChanged
{
    public ObservableCollection<EventLogFinding> Findings { get; } = new();

    public ObservableCollection<LookbackChoice> LookbackChoices { get; } = new(new[]
    {
        new LookbackChoice("1 hour", TimeSpan.FromHours(1)),
        new LookbackChoice("6 hours", TimeSpan.FromHours(6)),
        new LookbackChoice("24 hours", TimeSpan.FromHours(24)),
        new LookbackChoice("72 hours", TimeSpan.FromHours(72)),
        new LookbackChoice("7 days", TimeSpan.FromDays(7)),
    });

    private LookbackChoice? _selectedLookbackChoice;
    public LookbackChoice? SelectedLookbackChoice { get => _selectedLookbackChoice; set { _selectedLookbackChoice = value; OnPropertyChanged(nameof(SelectedLookbackChoice)); } }

    public string RunContextDescription { get; }

    private string _status = "Idle";
    public string Status { get => _status; set { _status = value; OnPropertyChanged(nameof(Status)); } }

    public EventLogViewModel()
    {
        SelectedLookbackChoice = LookbackChoices[2];
        RunContextDescription = IsAdmin()
            ? "Running as Administrator: all security logs available."
            : "Running as standard user: some logs may be missing.";
    }

    private static bool IsAdmin()
    {
        try
        {
            var id = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(id);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged(string propertyName) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

public sealed class LookbackChoice
{
    public string Name { get; }
    public TimeSpan Span { get; }

    public LookbackChoice(string name, TimeSpan span)
    {
        Name = name;
        Span = span;
    }
}
