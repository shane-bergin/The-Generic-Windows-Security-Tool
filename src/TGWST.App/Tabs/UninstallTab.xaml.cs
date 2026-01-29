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
    private IList<InstalledApp> _allApps = new List<InstalledApp>();
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
        _allApps = _engine.ListInstalled().ToList();
        _apps = _allApps;
        OnPropertyChanged(nameof(Apps));
        _leftovers = Array.Empty<LeftoverItem>();
        OnPropertyChanged(nameof(Leftovers));
        Status = $"Loaded {_apps.Count} applications";
    }

    private void Refresh_Click(object sender, RoutedEventArgs e) => LoadApps();

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        var searchText = SearchBox.Text?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(searchText))
        {
            _apps = _allApps;
        }
        else
        {
            _apps = _allApps.Where(app =>
                app.DisplayName.Contains(searchText, StringComparison.OrdinalIgnoreCase) ||
                (app.Publisher?.Contains(searchText, StringComparison.OrdinalIgnoreCase) ?? false)
            ).ToList();
        }
        OnPropertyChanged(nameof(Apps));
        Status = $"Showing {_apps.Count} of {_allApps.Count} applications";
    }

    private void SelectAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (var item in _leftovers)
        {
            item.Selected = true;
        }
        LeftoversGrid.Items.Refresh();
        Status = $"Selected all {_leftovers.Count} leftovers";
    }

    private void DeselectAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (var item in _leftovers)
        {
            item.Selected = false;
        }
        LeftoversGrid.Items.Refresh();
        Status = "Deselected all leftovers";
    }

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
        if (AppsGrid.SelectedItem is not InstalledApp app)
        {
            Status = "Please select an application to uninstall";
            return;
        }

        var confirm = MessageBox.Show(
            $"Uninstall {app.DisplayName}?\n\nPublisher: {app.Publisher}\nVersion: {app.Version}",
            "Confirm Uninstall",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (confirm != MessageBoxResult.Yes)
        {
            Status = "Uninstall canceled";
            return;
        }

        Status = $"Uninstalling {app.DisplayName}...";
        await _engine.RunUninstallerAsync(app);

        Status = "Deep scanning for leftovers (registry, files, shortcuts)...";
        Dispatcher.Invoke(() => ScanProgress.Visibility = Visibility.Visible);

        var leftovers = (await _engine.FindLeftoversAsync(app)).Select(l =>
        {
            l.Selected = false;
            return l;
        }).ToList();

        Dispatcher.Invoke(() =>
        {
            ScanProgress.Visibility = Visibility.Collapsed;
            _leftovers = leftovers;
            OnPropertyChanged(nameof(Leftovers));

            var totalSize = _leftovers.Sum(l => l.SizeBytes);
            var sizeDisplay = totalSize > 1073741824 ?
                $"{totalSize / 1073741824.0:F2} GB" :
                $"{totalSize / 1048576.0:F2} MB";

            Status = $"Found {_leftovers.Count} leftovers ({sizeDisplay} total)";
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
            Status = "Please select leftovers to remove";
            return;
        }

        var totalSize = selected.Sum(l => l.SizeBytes);
        var sizeDisplay = totalSize > 1073741824 ?
            $"{totalSize / 1073741824.0:F2} GB" :
            $"{totalSize / 1048576.0:F2} MB";

        var fileCount = selected.Count(l => l.Type == LeftoverType.File);
        var dirCount = selected.Count(l => l.Type == LeftoverType.Directory);
        var regCount = selected.Count(l => l.Type == LeftoverType.RegistryKey || l.Type == LeftoverType.RegistryValue);

        var message = DryRunCheck.IsChecked == true
            ? $"Dry run: Show what would be removed?\n\n{selected.Count} items ({sizeDisplay}):\n" +
              $"• {fileCount} files\n• {dirCount} directories\n• {regCount} registry items"
            : $"Permanently delete selected leftovers?\n\n{selected.Count} items ({sizeDisplay}):\n" +
              $"• {fileCount} files\n• {dirCount} directories\n• {regCount} registry items\n\n" +
              "WARNING: This action cannot be undone!";

        var confirm = MessageBox.Show(
            message,
            "Confirm Removal",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes)
        {
            Status = "Removal canceled";
            return;
        }

        if (DryRunCheck.IsChecked == true)
        {
            Status = $"Dry run: would remove {selected.Count} items ({sizeDisplay})";
        }
        else
        {
            Status = $"Removing {selected.Count} leftovers...";
            await _engine.RemoveLeftoversAsync(selected, CancellationToken.None);
            var newLeftovers = _leftovers.Except(selected).ToList();
            Dispatcher.Invoke(() =>
            {
                _leftovers = newLeftovers;
                OnPropertyChanged(nameof(Leftovers));
                Status = $"Removed {selected.Count} leftovers ({sizeDisplay}). {_leftovers.Count} remaining.";
            });
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
