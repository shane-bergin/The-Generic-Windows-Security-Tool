using System;
using System.Windows;
using TGWST.Core.AppControl;

namespace TGWST.App.Tabs;

public partial class WdacTab : System.Windows.Controls.UserControl
{
    private readonly WdacEngine _engine = new();

    public WdacTab()
    {
        InitializeComponent();
    }

    private void Apply_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            StatusText.Text = "Applying WDAC policy...";
            _engine.ApplyPolicy(PolicyPathBox.Text, EnforceCheck.IsChecked == true);
            StatusText.Text = "WDAC policy applied.";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Apply failed: {ex.Message}";
        }
    }

    private void Remove_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            StatusText.Text = "Removing WDAC policy...";
            _engine.RemovePolicy();
            StatusText.Text = "WDAC policy removed.";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Remove failed: {ex.Message}";
        }
    }
}
