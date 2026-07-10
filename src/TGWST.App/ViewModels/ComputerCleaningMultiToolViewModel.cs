using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using TGWST.App.Services;

namespace TGWST.App.ViewModels;

public sealed class ComputerCleaningMultiToolViewModel : ObservableObject
{
    private readonly ComputerCleaningService _cleaner;
    private readonly GuiLogService _log;
    private string _searchText = string.Empty;
    private string _status = "ready";
    private bool _isBusy;
    private InstalledAppRow? _selectedApp;

    public ObservableCollection<InstalledAppRow> InstalledApps { get; } = new();
    public ObservableCollection<CleanerResidueRow> Residues { get; } = new();
    public ObservableCollection<CleanerRiskRow> Risks { get; } = new();

    public IAsyncRelayCommand ScanAppsCommand { get; }
    public IAsyncRelayCommand FindResidueCommand { get; }
    public IAsyncRelayCommand UninstallSelectedCommand { get; }
    public IAsyncRelayCommand CleanSafeResidueCommand { get; }
    public IAsyncRelayCommand RefreshRisksCommand { get; }

    public ComputerCleaningMultiToolViewModel(ComputerCleaningService cleaner, GuiLogService log)
    {
        _cleaner = cleaner;
        _log = log;
        ScanAppsCommand = new AsyncRelayCommand(ScanAppsAsync, () => !IsBusy);
        FindResidueCommand = new AsyncRelayCommand(FindResidueAsync, () => !IsBusy);
        UninstallSelectedCommand = new AsyncRelayCommand(UninstallSelectedAsync, () => !IsBusy && SelectedApp?.HasUninstaller == true);
        CleanSafeResidueCommand = new AsyncRelayCommand(CleanSafeResidueAsync, () => !IsBusy && Residues.Any(row => row.SafeToClean));
        RefreshRisksCommand = new AsyncRelayCommand(RefreshRisksAsync, () => !IsBusy);
    }

    public string SearchText
    {
        get => _searchText;
        set => SetProperty(ref _searchText, value);
    }

    public string Status
    {
        get => _status;
        private set => SetProperty(ref _status, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        private set
        {
            if (SetProperty(ref _isBusy, value))
            {
                NotifyCommands();
            }
        }
    }

    public InstalledAppRow? SelectedApp
    {
        get => _selectedApp;
        set
        {
            if (SetProperty(ref _selectedApp, value))
            {
                UninstallSelectedCommand.NotifyCanExecuteChanged();
            }
        }
    }

    private async Task ScanAppsAsync()
    {
        await RunToolAsync("app inventory", async ct =>
        {
            var rows = await _cleaner.GetInstalledAppsAsync(SearchText, ct);
            Replace(InstalledApps, rows);
            Status = $"{rows.Count} app record(s) found";
            _log.Success("Cleaner", Status);
            await RefreshRisksCoreAsync(ct);
        });
    }

    private async Task FindResidueAsync()
    {
        await RunToolAsync("residue scan", async ct =>
        {
            var rows = await _cleaner.FindResiduesAsync(SelectedApp, ct);
            Replace(Residues, rows);
            Status = $"{rows.Count} residue/component row(s) found";
            _log.Success("Cleaner", Status);
            CleanSafeResidueCommand.NotifyCanExecuteChanged();
            await RefreshRisksCoreAsync(ct);
        });
    }

    private async Task UninstallSelectedAsync()
    {
        if (SelectedApp == null ||
            System.Windows.MessageBox.Show(
                $"Launch the registered uninstaller for {SelectedApp.Name}?\n\nTGWST will start the vendor uninstaller elevated; review prompts before removal.",
                "Computer cleaning multi-tool",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            return;
        }

        await RunToolAsync("uninstall launch", async ct =>
        {
            var message = await _cleaner.LaunchUninstallerAsync(SelectedApp, ct);
            Status = message;
            _log.Warning("Cleaner", message);
        });
    }

    private async Task CleanSafeResidueAsync()
    {
        var safeRows = Residues.Where(row => row.SafeToClean).ToArray();
        if (safeRows.Length == 0 ||
            System.Windows.MessageBox.Show(
                $"Delete {safeRows.Length} safe cleanup target(s)?\n\nRegistry rows and review-only items will not be deleted.",
                "Computer cleaning multi-tool",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No) != MessageBoxResult.Yes)
        {
            return;
        }

        await RunToolAsync("safe cleanup", async ct =>
        {
            var result = await _cleaner.CleanSafeResiduesAsync(safeRows, ct);
            Status = $"safe cleanup deleted={result.Deleted} failed={result.Failed}";
            _log.Warning("Cleaner", Status);
            var rows = await _cleaner.FindResiduesAsync(SelectedApp, ct);
            Replace(Residues, rows);
            CleanSafeResidueCommand.NotifyCanExecuteChanged();
            await RefreshRisksCoreAsync(ct);
        });
    }

    private async Task RefreshRisksAsync()
    {
        await RunToolAsync("risk refresh", RefreshRisksCoreAsync);
    }

    private async Task RefreshRisksCoreAsync(CancellationToken ct)
    {
        var rows = await _cleaner.BuildRiskWarningsAsync(InstalledApps, Residues, ct);
        Replace(Risks, rows);
    }

    private async Task RunToolAsync(string name, Func<CancellationToken, Task> action)
    {
        if (IsBusy)
        {
            return;
        }

        IsBusy = true;
        Status = $"{name} running";
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        try
        {
            await action(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            Status = $"{name} canceled or timed out";
            _log.Warning("Cleaner", Status);
        }
        catch (Exception ex)
        {
            Status = $"{name} failed: {Trim(ex.Message)}";
            _log.Warning("Cleaner", Status);
        }
        finally
        {
            IsBusy = false;
            NotifyCommands();
        }
    }

    private void NotifyCommands()
    {
        ScanAppsCommand.NotifyCanExecuteChanged();
        FindResidueCommand.NotifyCanExecuteChanged();
        UninstallSelectedCommand.NotifyCanExecuteChanged();
        CleanSafeResidueCommand.NotifyCanExecuteChanged();
        RefreshRisksCommand.NotifyCanExecuteChanged();
    }

    private static void Replace<T>(ObservableCollection<T> target, IEnumerable<T> values)
    {
        target.Clear();
        foreach (var value in values)
        {
            target.Add(value);
        }
    }

    private static string Trim(string message)
    {
        return string.IsNullOrWhiteSpace(message) ? "no detail" : message.Length <= 180 ? message : message[..180];
    }
}
