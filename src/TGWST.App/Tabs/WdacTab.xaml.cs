using System.Windows;
using System.Windows.Media;

namespace TGWST.App.Tabs;

public partial class WdacTab : System.Windows.Controls.UserControl
{
    public WdacTab()
    {
        InitializeComponent();
    }

    private void OpenHardening_Click(object sender, RoutedEventArgs e)
    {
        DependencyObject? current = this;
        while (current != null && current is not System.Windows.Controls.TabControl)
        {
            current = VisualTreeHelper.GetParent(current) ?? LogicalTreeHelper.GetParent(current);
        }

        if (current is System.Windows.Controls.TabControl tabs)
            tabs.SelectedIndex = 0;
    }
}
