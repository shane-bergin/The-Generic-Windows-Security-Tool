using System.Windows;
using TGWST.App.ViewModels;

namespace TGWST.App.Windows
{
    public partial class JunkInspectorWindow : Window
    {
        public JunkInspectorWindow(JunkRow target)
        {
            InitializeComponent();
            DataContext = target;
        }

        public void RefreshTarget(JunkRow target)
        {
            DataContext = target;
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
