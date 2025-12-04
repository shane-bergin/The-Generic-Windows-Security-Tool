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
private readonly CancellationTokenSource _cts = new();
private bool _refreshInFlight;

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

    _ = RefreshPortsAsync();

    _timer = new System.Windows.Threading.DispatcherTimer
    {
        Interval = TimeSpan.FromSeconds(10)
    };
    _timer.Tick += async (_, _) => await RefreshPortsAsync();
    _timer.Start();
    Unloaded += (_, _) =>
    {
        _cts.Cancel();
        _timer.Stop();
    };
}

private async Task RefreshPortsAsync()
{
    if (_refreshInFlight) return;
    try
    {
        _refreshInFlight = true;
        var ports = await _engine.GetListeningPortsAsync(_cts.Token);
        PortsGrid.ItemsSource = ports;
    }
    catch (OperationCanceledException)
    {
    }
    catch (Exception ex)
    {
        StatusText.Text = $"Failed to refresh ports: {ex.Message}";
    }
    finally
    {
        _refreshInFlight = false;
    }
}

private async void Fortress_Click(object sender, RoutedEventArgs e)
{
    if (!EnsureAdminForAction()) return;
    try
    {
        StatusText.Text = "Enabling fortress mode (block inbound, allow outbound)...";
        await _engine.EnableFortressModeAsync(_cts.Token);
        StatusText.Text = "Fortress mode enabled.";
        await RefreshPortsAsync();
    }
    catch (Exception ex)
    {
        StatusText.Text = $"Failed to enable fortress mode: {ex.Message}";
    }
}

private async void ResetFw_Click(object sender, RoutedEventArgs e)
{
    if (!EnsureAdminForAction()) return;
    try
    {
        StatusText.Text = "Resetting Windows Firewall to defaults...";
        await _engine.ResetFirewallToDefaultAsync(_cts.Token);
        StatusText.Text = "Firewall reset to defaults.";
        await RefreshPortsAsync();
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

private async void RemoveBlocklists_Click(object sender, RoutedEventArgs e)
{
    if (!EnsureAdminForAction()) return;
    StatusText.Text = "Removing TGWST threat block rules...";
    await Task.Run(() => _engine.RemoveThreatBlocklistRules(), _cts.Token);
        StatusText.Text = "Threat block rules removed.";
}

private async void Block_Click(object sender, RoutedEventArgs e)
{
    if (!EnsureAdminForAction()) return;
    if ((sender as FrameworkElement)?.DataContext is not PortInfo port) return;
    try
    {
        await Task.Run(() => _engine.BlockPort(port.Port, port.Protocol), _cts.Token);
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
