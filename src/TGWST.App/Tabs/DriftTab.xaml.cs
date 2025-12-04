using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows;
using TGWST.App.Services;
using TGWST.Core.Compliance;

namespace TGWST.App.Tabs;

public partial class DriftTab : System.Windows.Controls.UserControl
{
    private DriftDetector? _detector;
    private readonly DriftViewModel _vm = new();

    public DriftTab()
    {
        InitializeComponent();
        DataContext = _vm;
        BaselineSelectionService.SelectionChanged += baseline => _vm.SetBaseline(baseline);
    }

    private async void Start_Click(object sender, RoutedEventArgs e)
    {
        if (!_vm.CanStart || string.IsNullOrWhiteSpace(_vm.SelectedBaselinePath)) return;
        try
        {
            await StopMonitoringAsync();
            _detector = new DriftDetector(_vm.SelectedBaselinePath, TimeSpan.FromSeconds(_vm.IntervalSeconds));
            _detector.DriftDetected += (compliant, total) =>
            {
                Dispatcher.Invoke(() =>
                {
                    _vm.Status = $"Drift check: {compliant}/{total} compliant @ {DateTime.Now:T}";
                });
            };
            _detector.Start();
            _vm.IsMonitoring = true;
            _vm.Status = "Drift detector running.";
        }
        catch (Exception ex)
        {
            _vm.Status = $"Start failed: {ex.Message}";
        }
    }

    private async void Stop_Click(object? sender, RoutedEventArgs e)
    {
        await StopMonitoringAsync();
    }

    private async Task StopMonitoringAsync()
    {
        if (_detector != null)
        {
            await _detector.DisposeAsync();
            _detector = null;
        }
        _vm.IsMonitoring = false;
        _vm.Status = "Drift detector stopped.";
    }
}

public sealed class DriftViewModel : INotifyPropertyChanged
{
    public ObservableCollection<int> Intervals { get; } = new(new[] { 30, 60, 300, 900 });

    private string _selectedBaselineName = "";
    public string SelectedBaselineName { get => _selectedBaselineName; set { _selectedBaselineName = value; OnPropertyChanged(); UpdateCanStart(); } }

    public string? SelectedBaselinePath { get; private set; }

    private int _intervalSeconds = 300;
    public int IntervalSeconds { get => _intervalSeconds; set { _intervalSeconds = value; OnPropertyChanged(); } }

    private bool _isMonitoring;
    public bool IsMonitoring { get => _isMonitoring; set { _isMonitoring = value; OnPropertyChanged(); } }

    private bool _canStart;
    public bool CanStart { get => _canStart; private set { _canStart = value; OnPropertyChanged(); } }

    private string _status = "Idle";
    public string Status { get => _status; set { _status = value; OnPropertyChanged(); } }

    public void SetBaseline(ComplianceBaselineInfo? baseline)
    {
        SelectedBaselinePath = baseline?.FullPath;
        SelectedBaselineName = baseline?.DisplayName ?? "";
        UpdateCanStart();
    }

    private void UpdateCanStart() => CanStart = !string.IsNullOrWhiteSpace(SelectedBaselinePath);

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
