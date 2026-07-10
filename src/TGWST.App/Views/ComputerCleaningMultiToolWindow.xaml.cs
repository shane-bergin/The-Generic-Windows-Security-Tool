using System.Windows;
using TGWST.App.ViewModels;

namespace TGWST.App.Views;

public partial class ComputerCleaningMultiToolWindow : Window
{
    private readonly ComputerCleaningMultiToolViewModel _viewModel;

    public ComputerCleaningMultiToolWindow(ComputerCleaningMultiToolViewModel viewModel)
    {
        InitializeComponent();
        _viewModel = viewModel;
        DataContext = viewModel;
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        Loaded -= OnLoaded;
        if (_viewModel.ScanAppsCommand.CanExecute(null))
        {
            await _viewModel.ScanAppsCommand.ExecuteAsync(null);
        }
    }
}
