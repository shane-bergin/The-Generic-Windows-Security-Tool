using System.Windows;
using TGWST.App.ViewModels;

namespace TGWST.App.Windows
{
    public partial class ServiceInspectorWindow : Window
    {
        public ServiceInspectorWindow(ServiceRow target)
        {
            InitializeComponent();
            DataContext = target;
        }

        public void RefreshTarget(ServiceRow target)
        {
            DataContext = target;
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
