using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Security.Principal;
using TGWST.Core.Network;
using MessageBox = System.Windows.MessageBox;

namespace TGWST.App.Tabs;

public partial class NetworkTab : System.Windows.Controls.UserControl
{
private readonly NetworkSecurityEngine _engine = new();
private readonly System.Windows.Threading.DispatcherTimer _timer;
private readonly bool _isAdmin;

public NetworkTab()
{
    InitializeComponent();
    _isAdmin = IsAdministrator();

    if (!_isAdmin)
    {
        StatusText.Text = "Admin rights required for firewall actions. View-only mode.";
        MessageBox.Show(
            "Administrator rights are required to change Windows Firewall or apply threat blocklists. Please restart the app as Administrator.",
            "Administrator required",
            MessageBoxButton.OK,
            MessageBoxImage.Warning);
    }
    else
    {
        StatusText.Text = "Ready";
    }

    RefreshPorts();

    _timer = new System.Windows.Threading.DispatcherTimer
    {
        Interval = TimeSpan.FromSeconds(5)
    };
    _timer.Tick += (_, _) => RefreshPorts();
    _timer.Start();
    Unloaded += (_, _) => _timer.Stop();
}

private void RefreshPorts()
{
    PortsGrid.ItemsSource = _engine.GetListeningPorts();
}

private void Fortress_Click(object sender, RoutedEventArgs e)
{
    if (!EnsureAdminForAction()) return;
    try
    {
        StatusText.Text = "Enabling fortress mode (block inbound, allow outbound)...";
        _engine.EnableFortressMode();
        StatusText.Text = "Fortress mode enabled.";
        RefreshPorts();
    }
    catch (Exception ex)
    {
        StatusText.Text = $"Failed to enable fortress mode: {ex.Message}";
    }
}

private void ResetFw_Click(object sender, RoutedEventArgs e)
{
    if (!EnsureAdminForAction()) return;
    try
    {
        StatusText.Text = "Resetting Windows Firewall to defaults...";
        _engine.ResetFirewallToDefault();
        StatusText.Text = "Firewall reset to defaults.";
        RefreshPorts();
    }
    catch (Exception ex)
    {
        StatusText.Text = $"Failed to reset firewall: {ex.Message}";
    }
}

private async void Blocklists_Click(object sender, RoutedEventArgs e)
{
    if (!EnsureAdminForAction()) return;
    StatusText.Text = "Applying threat blocklists...";
    var progress = new Progress<string>(msg => StatusText.Text = msg);

    try
    {
        await _engine.ApplyThreatBlocklistsAsync(progress, CancellationToken.None);
        StatusText.Text += " Done.";
    }
    catch (Exception ex)
    {
        StatusText.Text = "Error applying blocklists: " + ex.Message;
    }
}

private void RemoveBlocklists_Click(object sender, RoutedEventArgs e)
{
    if (!EnsureAdminForAction()) return;
    StatusText.Text = "Removing TGWST threat block rules...";
    _engine.RemoveThreatBlocklistRules();
        StatusText.Text = "Threat block rules removed.";
}

private void Block_Click(object sender, RoutedEventArgs e)
{
    if (!EnsureAdminForAction()) return;
    if ((sender as FrameworkElement)?.DataContext is not PortInfo port) return;
    try
    {
        _engine.BlockPort(port.Port, port.Protocol);
        StatusText.Text = $"Blocked inbound {port.Protocol} {port.Port} (Process: {port.ProcessName}, PID: {port.Pid}).";
    }
    catch (Exception ex)
    {
        StatusText.Text = $"Failed to block port: {ex.Message}";
    }
}

private bool EnsureAdminForAction()
{
    if (_isAdmin) return true;

    MessageBox.Show(
        "This action requires Administrator rights. Please restart the app as Administrator.",
        "Administrator required",
        MessageBoxButton.OK,
        MessageBoxImage.Warning);
    return false;
}

private static bool IsAdministrator()
{
    using var identity = WindowsIdentity.GetCurrent();
    var principal = new WindowsPrincipal(identity);
    return principal.IsInRole(WindowsBuiltInRole.Administrator);
}

}
