using System.Windows;
using TGWST.App.ViewModels;

namespace TGWST.App.Views
{
    public partial class ProgressView : Window
    {
        public ProgressView(ProgressViewModel viewModel)
        {
            InitializeComponent();
            DataContext = viewModel;
            Owner = Application.Current?.MainWindow;
        }
    }
}
