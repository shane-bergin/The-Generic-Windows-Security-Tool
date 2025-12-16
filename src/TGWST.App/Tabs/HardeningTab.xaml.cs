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
            : BuildWdacError(result);

        await RefreshWdacPoliciesAsync(selectBaseName: result.BaseName ?? Path.GetFileNameWithoutExtension(dialog.FileName));
        UpdateWdacLogStatus();
    }

    private async void WdacCompile_Click(object sender, RoutedEventArgs e)
    {
        var policy = _wdacVm.SelectedPolicy;
        if (policy?.XmlPath == null)
        {
            _wdacVm.Status = "Selected policy has no XML to compile.";
            return;
        }

        _wdacVm.Status = "Compiling WDAC XML...";
        var result = await Task.Run(() => _wdacEngine.CompileXmlToCip(policy.XmlPath, out var _));
        _wdacVm.Status = result.Success
            ? $"Compiled: {Path.GetFileName(result.AffectedPath ?? policy.XmlPath)}"
            : BuildWdacError(result);

        await RefreshWdacPoliciesAsync(selectBaseName: policy.BaseName);
        UpdateWdacLogStatus();
    }

    private async void WdacExport_Click(object sender, RoutedEventArgs e)
    {
        var policy = _wdacVm.SelectedPolicy;
        if (policy == null)
        {
            _wdacVm.Status = "Select a policy to export.";
            return;
        }

        var source = policy.CipPath ?? policy.XmlPath;
        if (string.IsNullOrWhiteSpace(source))
        {
            _wdacVm.Status = "Selected policy has no file to export.";
            return;
        }

        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            FileName = Path.GetFileName(source),
            Filter = "WDAC Policy (*.cip;*.xml)|*.cip;*.xml|All files (*.*)|*.*",
            OverwritePrompt = false
        };

        if (dlg.ShowDialog() != true) return;

        _wdacVm.Status = "Exporting WDAC policy...";
        var result = await Task.Run(() => _wdacEngine.ExportPolicy(policy, dlg.FileName));
        _wdacVm.Status = result.Success ? result.Message : BuildWdacError(result);
        UpdateWdacLogStatus();
    }

    private async void WdacRefresh_Click(object sender, RoutedEventArgs e)
    {
        await RefreshWdacPoliciesAsync(_wdacVm.SelectedPolicy?.BaseName);
        UpdateWdacLogStatus();
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
        UpdateWdacLogStatus();
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
        UpdateWdacLogStatus();
    }

    private async Task RefreshWdacPoliciesAsync(string? selectBaseName = null)
    {
        var seed = await Task.Run(() => _wdacEngine.EnsureProgramDataWdacPolicies());
        var catalog = await Task.Run(() => _wdacEngine.EnumeratePolicies());

        var previousStatus = _wdacVm.Status;
        _wdacVm.LoadPolicies(catalog, selectBaseName);
        var loadStatus = _wdacVm.Status;

        var notes = new List<string>();
        if (!seed.Success && seed.Errors.Count > 0)
            notes.Add($"{seed.Message} ({string.Join("; ", seed.Errors.Take(3))})");
        else if (seed.CopiedFiles.Count > 0)
            notes.Add(seed.Message);

        if (catalog.Errors.Count > 0)
            notes.Add(string.Join("; ", catalog.Errors.Take(3)));

        var collisions = catalog.Policies.Where(p => !string.IsNullOrWhiteSpace(p.CollisionWarning)).Select(p => $"{p.BaseName}: {p.CollisionWarning}").ToArray();
        if (collisions.Length > 0)
            notes.Add($"Collision warning: {string.Join("; ", collisions)}");

        if (notes.Count > 0)
        {
            _wdacVm.Status = string.Join(" | ", notes);
        }
        else if (!string.IsNullOrWhiteSpace(loadStatus) && !string.Equals(loadStatus, "Ready", StringComparison.OrdinalIgnoreCase))
        {
            _wdacVm.Status = loadStatus;
        }
        else if (!string.IsNullOrWhiteSpace(previousStatus))
        {
            _wdacVm.Status = previousStatus;
        }
        else
        {
            _wdacVm.Status = "Ready";
        }

        UpdateWdacLogStatus();
    }

    private static string BuildWdacError(WdacEngine.WdacOperationResult result)
    {
        var msg = result.Message;
        var detail = new[] { result.Stderr, result.Stdout, result.Details }
            .FirstOrDefault(d => !string.IsNullOrWhiteSpace(d));
        if (!string.IsNullOrWhiteSpace(detail))
            msg += $" ({detail.Trim()})";
        if (result.ExitCode.HasValue)
            msg += $" [exit {result.ExitCode}]";
        return msg;
    }

    private void UpdateWdacLogStatus()
    {
        var (lastAction, lastError) = _wdacEngine.GetLastActionAndError();
        _wdacVm.LastAction = lastAction == null
            ? "Last action: none logged yet."
            : $"Last action: {lastAction.Action} - {lastAction.Message} ({lastAction.TimestampUtc.ToLocalTime():g})";
        _wdacVm.LastError = lastError == null
            ? string.Empty
            : $"Last error: {lastError.Action} - {lastError.Message}";
    }
}

public sealed class WdacSectionViewModel : INotifyPropertyChanged
{
    public ObservableCollection<WdacEngine.WdacPolicyInfo> Policies { get; } = new();

    private WdacEngine.WdacPolicyInfo? _selectedPolicy;
    public WdacEngine.WdacPolicyInfo? SelectedPolicy
    {
        get => _selectedPolicy;
        set
        {
            _selectedPolicy = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(SelectedDetails));
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

    private string _lastAction = string.Empty;
    public string LastAction
    {
        get => _lastAction;
        set
        {
            _lastAction = value;
            OnPropertyChanged();
        }
    }

    private string _lastError = string.Empty;
    public string LastError
    {
        get => _lastError;
        set
        {
            _lastError = value;
            OnPropertyChanged();
        }
    }

    public string SelectedDetails
    {
        get
        {
            if (SelectedPolicy == null) return "Select a WDAC policy to see details.";

            var parts = new[]
            {
                SelectedPolicy.FriendlyName ?? SelectedPolicy.BaseName,
                string.IsNullOrWhiteSpace(SelectedPolicy.PolicyId) ? null : $"PolicyID: {SelectedPolicy.PolicyId}",
                string.IsNullOrWhiteSpace(SelectedPolicy.Version) ? null : $"Version: {SelectedPolicy.Version}",
                SelectedPolicy.IsAuditMode ? "Audit" : "Enforced",
                $"UMCI {(SelectedPolicy.UmciEnabled ? "On" : "Off")}",
                $"Source: {SelectedPolicy.Source}"
            }.Where(p => !string.IsNullOrWhiteSpace(p));

            var details = string.Join(" | ", parts);
            if (!string.IsNullOrWhiteSpace(SelectedPolicy.CollisionWarning))
                details += $" (Warning: {SelectedPolicy.CollisionWarning})";

            return details;
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public void LoadPolicies(WdacEngine.WdacCatalogResult catalog, string? selectBaseName = null)
    {
        Policies.Clear();
        foreach (var p in catalog.Policies)
            Policies.Add(p);

        if (!string.IsNullOrWhiteSpace(selectBaseName))
        {
            var match = Policies.FirstOrDefault(p => string.Equals(p.BaseName, selectBaseName, StringComparison.OrdinalIgnoreCase));
            if (match != null) SelectedPolicy = match;
        }

        if (SelectedPolicy == null && Policies.Count > 0)
            SelectedPolicy = Policies[0];

        if (catalog.Errors.Count > 0)
        {
            Status = $"Catalog loaded with warnings: {string.Join("; ", catalog.Errors)}";
        }
        else if (Policies.Count == 0)
        {
            Status = "No WDAC policies found in ProgramData.";
        }
        else
        {
            Status = "Ready";
        }
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
