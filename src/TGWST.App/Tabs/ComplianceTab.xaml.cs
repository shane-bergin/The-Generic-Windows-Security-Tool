using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using Microsoft.Win32;
using TGWST.App.Services;
using TGWST.Core.Compliance;

namespace TGWST.App.Tabs;

public partial class ComplianceTab : System.Windows.Controls.UserControl
{
    private readonly BaselineComplianceEngine _engine = new();
    private readonly ComplianceViewModel _vm = new();

    public ComplianceTab()
    {
        InitializeComponent();
        DataContext = _vm;
        _vm.LoadBaselines();
    }

    private void Evaluate_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.SelectedBaseline == null) return;
        try
        {
            var results = (IReadOnlyList<BaselineComplianceEngine.Result>)_engine.Evaluate(_vm.SelectedBaseline.FullPath);
            _vm.SetResults(results);
            BaselineSelectionService.Selected = _vm.SelectedBaseline;
        }
        catch (Exception ex)
        {
            _vm.Status = $"Evaluate failed: {ex.Message}";
        }
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Filter = "Baseline files (*.json;*.csv)|*.json;*.csv|All files (*.*)|*.*",
            Multiselect = false
        };
        if (dlg.ShowDialog() == true)
        {
            var path = dlg.FileName;
            var display = $"Custom: {Path.GetFileName(path)}";
            var existing = _vm.Baselines.FirstOrDefault(b => b.FullPath.Equals(path, StringComparison.OrdinalIgnoreCase));
            if (existing == null)
            {
                var info = new ComplianceBaselineInfo(display, path);
                _vm.Baselines.Add(info);
                _vm.SelectedBaseline = info;
            }
            else
            {
                _vm.SelectedBaseline = existing;
            }
        }
    }
}

public sealed class ComplianceViewModel : INotifyPropertyChanged
{
    public ObservableCollection<ComplianceBaselineInfo> Baselines { get; } = new();
    public ObservableCollection<BaselineComplianceEngine.Result> Results { get; } = new();

    private ComplianceBaselineInfo? _selectedBaseline;
    public ComplianceBaselineInfo? SelectedBaseline
    {
        get => _selectedBaseline;
        set
        {
            _selectedBaseline = value;
            OnPropertyChanged();
            BaselineSelectionService.Selected = _selectedBaseline;
        }
    }

    private string _status = "Ready";
    public string Status { get => _status; set { _status = value; OnPropertyChanged(); } }

    public void LoadBaselines()
    {
        Baselines.Clear();
        foreach (var path in EnumerateBaselines())
        {
            Baselines.Add(path);
        }
        SelectedBaseline = Baselines.FirstOrDefault();
    }

    public void SetResults(IReadOnlyList<BaselineComplianceEngine.Result> results)
    {
        Results.Clear();
        foreach (var r in results) Results.Add(r);
        var compliant = results.Count(r => r.Compliant);
        Status = $"Compliant {compliant}/{results.Count}";
    }

    private static string ProgramDataBaselines => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "TGWST", "Baselines");

    private static ComplianceBaselineInfo[] EnumerateBaselines()
    {
        var candidates = new[]
        {
            "CIS_L1_Windows11.csv",
            "CIS_L2_Windows11.csv",
            "CISA_Recommended.csv",
            "TGWST_Balanced.csv"
        };

        var list = candidates
            .Select(file => Path.Combine(ProgramDataBaselines, file))
            .Where(File.Exists)
            .Select(p => new ComplianceBaselineInfo(Path.GetFileNameWithoutExtension(p), p))
            .ToList();

        return list.ToArray();
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
