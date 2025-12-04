using System;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using TGWST.Core.EventLog;

namespace TGWST.App.Tabs;

public partial class EventLogTab : System.Windows.Controls.UserControl
{
    private readonly EventLogAnalyzer _analyzer = new();
    private readonly ObservableCollection<EventLogFinding> _findings = new();
    private CancellationTokenSource? _cts;

    public EventLogTab()
    {
        InitializeComponent();
        FindingsGrid.ItemsSource = _findings;
    }

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        try
        {
            var lookbackHours = GetLookbackHours();
            StatusText.Text = $"Scanning last {lookbackHours}h...";
            var results = await _analyzer.ScanAsync(TimeSpan.FromHours(lookbackHours), _cts.Token);

            _findings.Clear();
            foreach (var f in results)
                _findings.Add(f);

            StatusText.Text = $"Found {_findings.Count} events.";
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = "Scan canceled.";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Scan failed: {ex.Message}";
        }
    }

    private int GetLookbackHours()
    {
        if (LookbackCombo.SelectedItem is System.Windows.Controls.ComboBoxItem item &&
            int.TryParse(item.Tag?.ToString(), out var hours))
            return hours;
        return 24;
    }
}
