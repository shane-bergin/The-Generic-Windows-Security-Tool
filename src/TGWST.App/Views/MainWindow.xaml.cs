using System;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using TGWST.App.ViewModels;

namespace TGWST.App.Views;

public partial class MainWindow : Window
{
    private MainWindowViewModel? _viewModel;

    public MainWindow(MainWindowViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        _viewModel = viewModel;
        Loaded += OnLoaded;
        Closed += OnClosed;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (_viewModel == null)
        {
            return;
        }

        _viewModel.Logs.FilteredEntries.CollectionChanged += LogEntriesChanged;
        _viewModel.Logs.PropertyChanged += LogsPropertyChanged;
        await _viewModel.StartAsync();
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        if (_viewModel == null)
        {
            return;
        }

        _viewModel.Logs.FilteredEntries.CollectionChanged -= LogEntriesChanged;
        _viewModel.Logs.PropertyChanged -= LogsPropertyChanged;
        _viewModel.Dispose();
    }

    private void LogEntriesChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (LogGrid.Items.Count > 0)
        {
            LogGrid.ScrollIntoView(LogGrid.Items[^1]);
        }
    }

    private void LogsPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(LogsDashboardViewModel.SelectedSeverityFilter))
        {
            LogEntriesChanged(sender, new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
        }
    }

    private void OpenLinkedTarget_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.Button { Tag: string target } || string.IsNullOrWhiteSpace(target))
        {
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = target,
                UseShellExecute = true
            });
        }
        catch
        {
        }
    }

    private void NetworkGrid_OnPreviewMouseRightButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (sender is not DataGrid grid)
        {
            return;
        }

        var row = FindVisualParent<DataGridRow>(e.OriginalSource as DependencyObject);
        if (row == null)
        {
            grid.SelectedItem = null;
            return;
        }

        row.IsSelected = true;
        grid.SelectedItem = row.Item;
    }

    private static T? FindVisualParent<T>(DependencyObject? child) where T : DependencyObject
    {
        while (child != null)
        {
            if (child is T match)
            {
                return match;
            }

            child = VisualTreeHelper.GetParent(child);
        }

        return null;
    }
}
