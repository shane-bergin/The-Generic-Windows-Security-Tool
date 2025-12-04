using System;
using System.Windows;
using TGWST.Core.Security;

namespace TGWST.App.Tabs;

public partial class BitLockerTab : System.Windows.Controls.UserControl
{
    private readonly BitLockerEngine _engine = new();

    public BitLockerTab()
    {
        InitializeComponent();
    }

    private void Status_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            OutputBox.Text = _engine.GetStatus();
        }
        catch (Exception ex)
        {
            OutputBox.Text = $"Status failed: {ex.Message}";
        }
    }

    private void EnableOs_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _engine.EnableOsDrive(DriveLetterBox.Text, PinBox.Text);
            OutputBox.Text = "OS drive encryption started.";
        }
        catch (Exception ex)
        {
            OutputBox.Text = $"Enable OS failed: {ex.Message}";
        }
    }

    private void EnableFixed_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _engine.EnableFixed(DriveLetterBox.Text);
            OutputBox.Text = "Fixed drive encryption started.";
        }
        catch (Exception ex)
        {
            OutputBox.Text = $"Enable fixed failed: {ex.Message}";
        }
    }

    private void EnableRemovable_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _engine.EnableRemovable(DriveLetterBox.Text, PinBox.Text);
            OutputBox.Text = "Removable drive encryption started.";
        }
        catch (Exception ex)
        {
            OutputBox.Text = $"Enable removable failed: {ex.Message}";
        }
    }

    private void Suspend_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _engine.Suspend(DriveLetterBox.Text);
            OutputBox.Text = "Suspended BitLocker protectors.";
        }
        catch (Exception ex)
        {
            OutputBox.Text = $"Suspend failed: {ex.Message}";
        }
    }

    private void Resume_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _engine.Resume(DriveLetterBox.Text);
            OutputBox.Text = "Resumed BitLocker protectors.";
        }
        catch (Exception ex)
        {
            OutputBox.Text = $"Resume failed: {ex.Message}";
        }
    }

    private void AddRecovery_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var dir = string.IsNullOrWhiteSpace(RecoveryDirBox.Text)
                ? Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                : RecoveryDirBox.Text;
            _engine.AddRecoveryKey(DriveLetterBox.Text, dir);
            OutputBox.Text = $"Recovery key written to {dir}.";
        }
        catch (Exception ex)
        {
            OutputBox.Text = $"Recovery key failed: {ex.Message}";
        }
    }
}
