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
            _vm.Status = $"ERROR: Evaluate failed: {ex.Message}";
        }
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "Baseline files (*.json;*.csv)|*.json;*.csv|All files (*.*)|*.*",
            Multiselect = false
        };
        if (dlg.ShowDialog() == true)
        {
            var path = dlg.FileName;
            var destDir = ComplianceViewModel.ProgramDataBaselines;
            Directory.CreateDirectory(destDir);
            var destPath = Path.Combine(destDir, Path.GetFileName(path));
            File.Copy(path, destPath, overwrite: true);
            var display = $"Imported: {Path.GetFileNameWithoutExtension(path)}";
            var info = new ComplianceBaselineInfo(display, destPath);
            _vm.Baselines.Add(info);
            _vm.SelectedBaseline = info;
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
        if (Baselines.Count == 0)
        {
            if (!Directory.Exists(ProgramDataBaselines))
            {
                Status = $"Baselines directory is missing: {ProgramDataBaselines}";
            }
            else
            {
                Status = $"Baselines directory is empty: {ProgramDataBaselines}";
            }
        }
        else
        {
            Status = "Ready";
        }
    }

    public void SetResults(IReadOnlyList<BaselineComplianceEngine.Result> results)
    {
        Results.Clear();
        foreach (var r in results) Results.Add(r);
        var compliant = results.Count(r => r.Compliant);
        Status = $"Compliant {compliant}/{results.Count}";
    }

    internal static string ProgramDataBaselines => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "TGWST", "Baselines");

    private static ComplianceBaselineInfo[] EnumerateBaselines()
    {
        var dir = ProgramDataBaselines;
        if (!Directory.Exists(dir))
        {
            return Array.Empty<ComplianceBaselineInfo>();
        }
        var files = Directory.EnumerateFiles(dir, "*.csv", SearchOption.TopDirectoryOnly)
            .Concat(Directory.EnumerateFiles(dir, "*.json", SearchOption.TopDirectoryOnly))
            .Select(p => new ComplianceBaselineInfo(Path.GetFileNameWithoutExtension(p), p))
            .ToArray();
        return files;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
