using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using TGWST.Core.Uninstall;
using MessageBox = System.Windows.MessageBox;

namespace TGWST.App.Tabs;

public partial class UninstallTab : System.Windows.Controls.UserControl, INotifyPropertyChanged
{
    private readonly UninstallEngine _engine = new();
    private IList<InstalledApp> _apps = new List<InstalledApp>();
    private IList<LeftoverItem> _leftovers = new List<LeftoverItem>();

    public IEnumerable<InstalledApp> Apps => _apps;
    public IEnumerable<LeftoverItem> Leftovers => _leftovers;

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

    public UninstallTab()
    {
        InitializeComponent();
        DataContext = this;
        LoadApps();
    }

    private void LoadApps()
    {
        _apps = _engine.ListInstalled().ToList();
        OnPropertyChanged(nameof(Apps));
        _leftovers = Array.Empty<LeftoverItem>();
        OnPropertyChanged(nameof(Leftovers));
        Status = $"Loaded {_apps.Count} apps.";
    }

    private void Refresh_Click(object sender, RoutedEventArgs e) => LoadApps();

    private async void Uninstall_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            await Uninstall_ClickAsync(sender, e);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Operation failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task Uninstall_ClickAsync(object sender, RoutedEventArgs e)
    {
        if (AppsGrid.SelectedItem is not InstalledApp app) return;

        Status = $"Uninstalling {app.DisplayName}...";
        await _engine.RunUninstallerAsync(app);
        Status = "Scanning for leftovers...";

        var leftovers = (await _engine.FindLeftoversAsync(app)).Select(l =>
        {
            l.Selected = false;
            return l;
        }).ToList();
        Dispatcher.Invoke(() =>
        {
            _leftovers = leftovers;
            OnPropertyChanged(nameof(Leftovers));
            Status = $"Found {_leftovers.Count} potential leftovers.";
        });
    }

    private async void RemoveLeftovers_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            await RemoveLeftovers_ClickAsync(sender, e);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Operation failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task RemoveLeftovers_ClickAsync(object sender, RoutedEventArgs e)
    {
        var selected = _leftovers.Where(l => l.Selected).ToList();
        if (selected.Count == 0)
        {
            Status = "Select leftovers to remove.";
            return;
        }

        var confirm = MessageBox.Show(
            DryRunCheck.IsChecked == true
                ? "Dry run: show what would be removed?"
                : "Remove selected leftovers? This will delete the selected directories.",
            "Confirm removal",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes)
        {
            Status = "Leftover removal canceled.";
            return;
        }

        if (DryRunCheck.IsChecked == true)
        {
            Status = $"Dry run: would remove {selected.Count} items.";
        }
        else
        {
            Status = "Removing leftovers...";
            await _engine.RemoveLeftoversAsync(selected, CancellationToken.None);
            var newLeftovers = _leftovers.Except(selected).ToList();
            Dispatcher.Invoke(() =>
            {
                _leftovers = newLeftovers;
                OnPropertyChanged(nameof(Leftovers));
                Status = "Leftovers removal complete.";
            });
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
