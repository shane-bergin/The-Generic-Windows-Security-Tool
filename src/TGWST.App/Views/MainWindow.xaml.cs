using System;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;
using System.Windows;
using System.Windows.Documents;
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

        _viewModel.Telemetry.Events.CollectionChanged += TelemetryEventsChanged;
        _viewModel.Logs.Entries.CollectionChanged += LogEntriesChanged;
        _viewModel.Logs.PropertyChanged += LogsPropertyChanged;
        RenderTelemetry();
        RenderLogs();
        await _viewModel.StartAsync();
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        if (_viewModel == null)
        {
            return;
        }

        _viewModel.Telemetry.Events.CollectionChanged -= TelemetryEventsChanged;
        _viewModel.Logs.Entries.CollectionChanged -= LogEntriesChanged;
        _viewModel.Logs.PropertyChanged -= LogsPropertyChanged;
        _viewModel.Dispose();
    }

    private void TelemetryEventsChanged(object? sender, NotifyCollectionChangedEventArgs e) => RenderTelemetry();

    private void LogEntriesChanged(object? sender, NotifyCollectionChangedEventArgs e) => RenderLogs();

    private void LogsPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(LogsDashboardViewModel.SelectedSeverityFilter))
        {
            RenderLogs();
        }
    }

    private void RenderTelemetry()
    {
        if (_viewModel == null)
        {
            return;
        }

        TelemetryFeedBox.Document.Blocks.Clear();
        foreach (var entry in _viewModel.Telemetry.Events.Take(220).Reverse())
        {
            AppendRun(TelemetryFeedBox.Document, entry.DisplayLine, entry.Severity);
        }

        TelemetryFeedBox.ScrollToEnd();
    }

    private void RenderLogs()
    {
        if (_viewModel == null)
        {
            return;
        }

        LogFeedBox.Document.Blocks.Clear();
        foreach (var entry in _viewModel.Logs.FilteredEntries.TakeLast(500))
        {
            AppendRun(LogFeedBox.Document, entry.DisplayLine, entry.Severity);
        }

        LogFeedBox.ScrollToEnd();
    }

    private static void AppendRun(FlowDocument document, string text, CyberSeverity severity)
    {
        var paragraph = new Paragraph
        {
            Margin = new Thickness(0, 0, 0, 2),
            LineHeight = 16
        };
        paragraph.Inlines.Add(new Run(text) { Foreground = BrushFor(severity) });
        document.Blocks.Add(paragraph);
    }

    private static System.Windows.Media.Brush BrushFor(CyberSeverity severity)
    {
        return severity switch
        {
            CyberSeverity.Success => System.Windows.Media.Brushes.White,
            CyberSeverity.Warning => (System.Windows.Media.Brush)System.Windows.Application.Current.FindResource("OrangeBrush"),
            CyberSeverity.Critical => (System.Windows.Media.Brush)System.Windows.Application.Current.FindResource("RedBrush"),
            _ => (System.Windows.Media.Brush)System.Windows.Application.Current.FindResource("CyanBrush")
        };
    }
}
