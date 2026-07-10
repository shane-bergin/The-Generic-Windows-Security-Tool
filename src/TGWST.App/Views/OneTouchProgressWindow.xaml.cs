using System.ComponentModel;
using System.Windows;
using TGWST.App.ViewModels;

namespace TGWST.App.Views;

public partial class OneTouchProgressWindow : Window
{
    private readonly OneTouchProgressViewModel _viewModel;

    public OneTouchProgressWindow(OneTouchProgressViewModel viewModel)
    {
        InitializeComponent();
        _viewModel = viewModel;
        DataContext = viewModel;
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        if (!_viewModel.IsRunning)
        {
            Close();
        }
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (_viewModel.IsRunning)
        {
            e.Cancel = true;
            return;
        }

        base.OnClosing(e);
    }
}
