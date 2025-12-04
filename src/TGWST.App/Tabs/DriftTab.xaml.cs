using System;
using System.Windows;
using TGWST.Core.Compliance;

namespace TGWST.App.Tabs;

public partial class DriftTab : System.Windows.Controls.UserControl
{
    private DriftDetector? _detector;

    public DriftTab()
    {
        InitializeComponent();
    }

    private void Start_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Stop_Click(sender, e);
            var intervalSeconds = int.TryParse(IntervalBox.Text, out var seconds) ? seconds : 300;
            _detector = new DriftDetector(BaselineBox.Text, TimeSpan.FromSeconds(intervalSeconds));
            _detector.DriftDetected += (compliant, total) =>
            {
                Dispatcher.Invoke(() =>
                {
                    StatusText.Text = $"Drift check: {compliant}/{total} compliant @ {DateTime.Now:T}";
                });
            };
            _detector.Start();
            StatusText.Text = "Drift detector running.";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Start failed: {ex.Message}";
        }
    }

    private async void Stop_Click(object? sender, RoutedEventArgs e)
    {
        if (_detector == null) return;
        await _detector.DisposeAsync();
        _detector = null;
        StatusText.Text = "Drift detector stopped.";
    }
}
