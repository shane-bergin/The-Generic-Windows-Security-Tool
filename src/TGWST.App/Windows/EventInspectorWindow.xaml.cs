using System.Windows;
using TGWST.App.ViewModels;

namespace TGWST.App.Windows
{
    public partial class EventInspectorWindow : Window
    {
        public EventInspectorWindow(EventLogRow target)
        {
            InitializeComponent();
            DataContext = target;
        }

        public void RefreshTarget(EventLogRow target)
        {
            DataContext = target;
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
