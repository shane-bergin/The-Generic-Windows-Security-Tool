using System.Windows;
using TGWST.App.ViewModels;

namespace TGWST.App.Windows
{
    public partial class EndpointInspectorWindow : Window
    {
        public EndpointInspectorWindow(EndpointFocusItem endpoint)
        {
            InitializeComponent();
            DataContext = endpoint;
        }

        public void RefreshTarget(EndpointFocusItem endpoint)
        {
            DataContext = endpoint;
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
