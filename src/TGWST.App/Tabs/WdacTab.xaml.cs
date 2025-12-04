using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using TGWST.Core.AppControl;

namespace TGWST.App.Tabs;

public partial class WdacTab : System.Windows.Controls.UserControl
{
    private readonly WdacViewModel _vm = new();
    private readonly WdacEngine _engine = new();

    public WdacTab()
    {
        InitializeComponent();
        DataContext = _vm;
        _vm.LoadPolicies();
    }

    private void Apply_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.SelectedPolicy == null) return;
        try
        {
            _vm.Status = "Applying WDAC policy...";
            _engine.ApplyPolicy(_vm.SelectedPolicy.FullPath, _vm.EnforceUmci);
            _vm.HasActivePolicy = true;
            _vm.Status = "WDAC policy applied.";
        }
        catch (Exception ex)
        {
            _vm.Status = $"Apply failed: {ex.Message}";
        }
    }

    private void Remove_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _vm.Status = "Removing WDAC policy...";
            _engine.RemovePolicy();
            _vm.HasActivePolicy = false;
            _vm.Status = "WDAC policy removed.";
        }
        catch (Exception ex)
        {
            _vm.Status = $"Remove failed: {ex.Message}";
        }
    }
}

public record WdacPolicyOption(string DisplayName, string FullPath);

public sealed class WdacViewModel : INotifyPropertyChanged
{
    public ObservableCollection<WdacPolicyOption> Policies { get; } = new();

    private WdacPolicyOption? _selectedPolicy;
    public WdacPolicyOption? SelectedPolicy { get => _selectedPolicy; set { _selectedPolicy = value; OnPropertyChanged(); } }

    private bool _enforceUmci;
    public bool EnforceUmci { get => _enforceUmci; set { _enforceUmci = value; OnPropertyChanged(); } }

    private bool _hasActivePolicy;
    public bool HasActivePolicy { get => _hasActivePolicy; set { _hasActivePolicy = value; OnPropertyChanged(); } }

    private string _status = "Ready";
    public string Status { get => _status; set { _status = value; OnPropertyChanged(); } }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    public void LoadPolicies()
    {
        Policies.Clear();
        foreach (var path in EnumeratePolicies())
        {
            var display = Path.GetFileName(path);
            Policies.Add(new WdacPolicyOption(display, path));
        }

        HasActivePolicy = DetectActivePolicy();
        if (Policies.Count > 0) SelectedPolicy = Policies[0];
    }

    private static bool DetectActivePolicy()
    {
        var paths = new[]
        {
            @"C:\Windows\System32\CodeIntegrity\SiPolicy.p7b",
            @"C:\Windows\System32\CodeIntegrity\tgwst.cip"
        };
        return paths.Any(File.Exists);
    }

    private static string GetProgramDataPath() => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "TGWST", "WDAC");

    private static string[] EnumeratePolicies()
    {
        var list = new[]
        {
            Path.Combine(GetProgramDataPath(), "Balanced.xml"),
            Path.Combine(GetProgramDataPath(), "Aggressive.xml"),
            Path.Combine(GetProgramDataPath(), "Audit.xml"),
            Path.Combine(GetProgramDataPath(), "Revert.xml"),
        }.Where(File.Exists).ToList();

        var sysXml = Directory.Exists(@"C:\Windows\schemas\CodeIntegrity")
            ? Directory.GetFiles(@"C:\Windows\schemas\CodeIntegrity", "*.xml", SearchOption.TopDirectoryOnly)
            : Array.Empty<string>();
        var cip = Directory.Exists(@"C:\Windows\System32\CodeIntegrity")
            ? Directory.GetFiles(@"C:\Windows\System32\CodeIntegrity", "*.cip", SearchOption.TopDirectoryOnly)
            : Array.Empty<string>();

        list.AddRange(sysXml);
        list.AddRange(cip);
        return list.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }
}
