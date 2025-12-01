using System;
using System.Windows;
using System.Windows.Controls;
using TGWST.Core.Hardening;
using MessageBox = System.Windows.MessageBox;

namespace TGWST.App.Tabs;

public partial class HardeningTab : System.Windows.Controls.UserControl
{
    private readonly HardeningEngine _engine = new();

    public HardeningTab()
    {
        InitializeComponent();
        ProfileCombo.SelectedIndex = 0;
    }

    private async void ApplyProfile_Click(object sender, RoutedEventArgs e)
    {
        var levelText = (ProfileCombo.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Balanced";
        var level = levelText switch
        {
            "Aggressive" => HardeningProfileLevel.Aggressive,
            "Audit"      => HardeningProfileLevel.Audit,
            "Revert"     => HardeningProfileLevel.Revert,
            _            => HardeningProfileLevel.Balanced
        };

        try
        {
        if (level is HardeningProfileLevel.Balanced or HardeningProfileLevel.Audit)
        {
            MessageBox.Show(
                "To change Controlled Folder Access, Windows Tamper Protection must be disabled.\n\nStart -> Windows Security -> Virus & threat protection -> Manage ransomware protection -> Tamper Protection.\n\nThis app cannot change Tamper Protection.",
                "Tamper Protection",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }

            if (level is HardeningProfileLevel.Audit)
            {
                var auditWarn = MessageBox.Show(
                    "Audit mode will log ASR events but will NOT block threats.\nUse caution: protections are reduced.",
                    "ASR Audit Warning",
                    MessageBoxButton.OKCancel,
                    MessageBoxImage.Warning);
                if (auditWarn != MessageBoxResult.OK) return;
            }

            StatusText.Text = "Applying profile...";
            LogBox.Clear();
            var progress = new Progress<string>(msg =>
            {
                LogBox.AppendText($"{DateTime.Now:HH:mm:ss} {msg}{Environment.NewLine}");
                LogBox.ScrollToEnd();
            });
            var profile = _engine.GetProfile(level);
            profile = await _engine.ApplyProfileAsync(profile, progress);
            StatusText.Text = $"Applied profile: {level}";
            if (profile.RebootRequired) StatusText.Text += " (reboot required for HVCI/CG)";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Failed to apply profile: {ex.Message}";
        }
    }
}
