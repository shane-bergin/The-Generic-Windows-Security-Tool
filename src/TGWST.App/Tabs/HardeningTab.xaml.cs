using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using TGWST.Core.AppControl;
using TGWST.Core.Hardening;
using MessageBox = System.Windows.MessageBox;

namespace TGWST.App.Tabs;

public partial class HardeningTab : System.Windows.Controls.UserControl
{
    private readonly HardeningEngine _engine = new();
    private readonly WdacEngine _wdacEngine = new();
    private readonly WdacSectionViewModel _wdacVm = new();

    public HardeningTab()
    {
        InitializeComponent();
        ProfileCombo.SelectedIndex = 0;
        WdacBox.DataContext = _wdacVm;
        _ = RefreshWdacPoliciesAsync();
    }

    private async void ApplyProfile_Click(object sender, RoutedEventArgs e)
    {
        var levelText = (ProfileCombo.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Balanced";
        var level = levelText switch
        {
            "Aggressive" => HardeningProfileLevel.Aggressive,
            "Audit"      => HardeningProfileLevel.Audit,
            "Revert"     => HardeningProfileLevel.Revert,
            _            => HardeningProfileLevel.Balanced
        };

        try
        {
            var profile = _engine.GetProfile(level);
            if (profile.ShowCfaWarning)
            {
                MessageBox.Show(
                    "To change Controlled Folder Access, Windows Tamper Protection must be disabled.\n\nStart -> Windows Security -> Virus & threat protection -> Manage ransomware protection -> Tamper Protection.\n\nThis app cannot change Tamper Protection.",
                    "Tamper Protection",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }

            if (level is HardeningProfileLevel.Audit)
            {
                var auditWarn = MessageBox.Show(
                    "Audit mode will log ASR events but will NOT block threats.\nUse caution: protections are reduced.",
                    "ASR Audit Warning",
                    MessageBoxButton.OKCancel,
                    MessageBoxImage.Warning);
                if (auditWarn != MessageBoxResult.OK) return;
            }

            StatusText.Text = "Applying profile...";
            LogBox.Clear();
            var progress = new Progress<string>(msg =>
            {
                LogBox.AppendText($"{DateTime.Now:HH:mm:ss} {msg}{Environment.NewLine}");
                LogBox.ScrollToEnd();
            });
            profile = await _engine.ApplyProfileAsync(profile, progress);
            StatusText.Text = $"Applied profile: {level}";
            if (profile.RebootRequired) StatusText.Text += " (reboot required for HVCI/CG)";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Failed to apply profile: {ex.Message}";
        }
    }

    private async void WdacImport_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "WDAC Policy (*.xml;*.cip)|*.xml;*.cip|All files (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false
        };

        if (dialog.ShowDialog() != true) return;

        _wdacVm.Status = "Importing policy...";

        var result = await Task.Run(() => _wdacEngine.ImportPolicy(dialog.FileName));
        _wdacVm.Status = result.Success
            ? $"Imported: {Path.GetFileName(result.AffectedPath ?? dialog.FileName)}"
            : result.Message;

        await RefreshWdacPoliciesAsync(selectBaseName: Path.GetFileNameWithoutExtension(result.AffectedPath ?? dialog.FileName));
    }

    private async void WdacApply_Click(object sender, RoutedEventArgs e)
    {
        if (_wdacVm.SelectedPolicy == null) return;

        _wdacVm.Status = "Applying WDAC policy...";

        var policy = _wdacVm.SelectedPolicy;
        var enforce = _wdacVm.EnforceUmci;
        var result = await Task.Run(() => _wdacEngine.ApplyPolicy(policy, enforce));

        if (!result.Success && result.RequiresElevation)
        {
            _wdacVm.Status = result.Message;
            MessageBox.Show(result.Message, "WDAC", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _wdacVm.Status = result.Success ? result.Message : BuildWdacError(result);
        await RefreshWdacPoliciesAsync(selectBaseName: policy.BaseName);
    }

    private async void WdacRemove_Click(object sender, RoutedEventArgs e)
    {
        _wdacVm.Status = "Removing WDAC policy...";

        var result = await Task.Run(() => _wdacEngine.RemovePolicy());

        if (!result.Success && result.RequiresElevation)
        {
            _wdacVm.Status = result.Message;
            MessageBox.Show(result.Message, "WDAC", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!result.Success && result.Message.Contains("system policy", StringComparison.OrdinalIgnoreCase))
        {
            var confirm = MessageBox.Show(
                result.Message,
                "WDAC - Confirm System Policy Removal",
                MessageBoxButton.OKCancel,
                MessageBoxImage.Warning);

            if (confirm == MessageBoxResult.OK)
                result = await Task.Run(() => _wdacEngine.RemovePolicy(allowSystemPolicyRemoval: true));
        }

        _wdacVm.Status = result.Success ? result.Message : BuildWdacError(result);
        await RefreshWdacPoliciesAsync();
    }

    private async Task RefreshWdacPoliciesAsync(string? selectBaseName = null)
    {
        var seed = await Task.Run(() => _wdacEngine.EnsureProgramDataWdacPolicies());
        var policies = await Task.Run(() => _wdacEngine.EnumeratePolicies());

        _wdacVm.LoadPolicies(policies, selectBaseName);
        if (!seed.Success && seed.Errors.Count > 0)
        {
            _wdacVm.Status = $"{seed.Message} ({string.Join("; ", seed.Errors.Take(3))})";
        }
        else if (seed.CopiedFiles.Count > 0)
        {
            _wdacVm.Status = seed.Message;
        }
        else if (string.IsNullOrWhiteSpace(_wdacVm.Status))
        {
            _wdacVm.Status = "Ready";
        }
    }

    private static string BuildWdacError(WdacEngine.WdacOperationResult result)
    {
        var msg = result.Message;
        if (!string.IsNullOrWhiteSpace(result.Stderr))
            msg += $" ({result.Stderr.Trim()})";
        return msg;
    }
}

public sealed class WdacSectionViewModel : INotifyPropertyChanged
{
    public ObservableCollection<WdacEngine.WdacPolicy> Policies { get; } = new();

    private WdacEngine.WdacPolicy? _selectedPolicy;
    public WdacEngine.WdacPolicy? SelectedPolicy
    {
        get => _selectedPolicy;
        set
        {
            _selectedPolicy = value;
            OnPropertyChanged();
        }
    }

    private bool _enforceUmci = true;
    public bool EnforceUmci
    {
        get => _enforceUmci;
        set
        {
            _enforceUmci = value;
            OnPropertyChanged();
        }
    }

    private string _status = "Ready";
    public string Status
    {
        get => _status;
        set
        {
            _status = value;
            OnPropertyChanged();
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public void LoadPolicies(IReadOnlyList<WdacEngine.WdacPolicy> policies, string? selectBaseName = null)
    {
        Policies.Clear();
        foreach (var p in policies)
            Policies.Add(p);

        if (!string.IsNullOrWhiteSpace(selectBaseName))
        {
            var match = Policies.FirstOrDefault(p => string.Equals(p.BaseName, selectBaseName, StringComparison.OrdinalIgnoreCase));
            if (match != null) SelectedPolicy = match;
        }

        if (SelectedPolicy == null && Policies.Count > 0)
            SelectedPolicy = Policies[0];
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
