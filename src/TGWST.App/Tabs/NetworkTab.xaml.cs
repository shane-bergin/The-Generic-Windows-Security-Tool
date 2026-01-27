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
        StatusText.Text = "WARNING: Admin rights required for firewall actions. View-only mode.";
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
        Dispatcher.Invoke(() => PortsGrid.ItemsSource = ports);
    }
    catch (OperationCanceledException)
    {
    }
    catch (Exception ex)
    {
        StatusText.Text = $"ERROR: Failed to refresh ports: {ex.Message}";
    }
    finally
    {
        _refreshInFlight = false;
    }
}

private async void Fortress_Click(object sender, RoutedEventArgs e)
{
    try
    {
        await Fortress_ClickAsync(sender, e);
    }
    catch (Exception ex)
    {
        MessageBox.Show($"Operation failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}

private async Task Fortress_ClickAsync(object sender, RoutedEventArgs e)
{
    if (!EnsureAdminForAction()) return;
    StatusText.Text = "Enabling fortress mode (block inbound, allow outbound)...";
    await _engine.EnableFortressModeAsync(_cts.Token);
    Dispatcher.Invoke(() => StatusText.Text = "Fortress mode enabled.");
    await RefreshPortsAsync();
}

private async void ResetFw_Click(object sender, RoutedEventArgs e)
{
    try
    {
        await ResetFw_ClickAsync(sender, e);
    }
    catch (Exception ex)
    {
        MessageBox.Show($"Operation failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}

private async Task ResetFw_ClickAsync(object sender, RoutedEventArgs e)
{
    if (!EnsureAdminForAction()) return;
    StatusText.Text = "Resetting Windows Firewall to defaults...";
    await _engine.ResetFirewallToDefaultAsync(_cts.Token);
    Dispatcher.Invoke(() => StatusText.Text = "Firewall reset to defaults.");
    await RefreshPortsAsync();
}

private async void Blocklists_Click(object sender, RoutedEventArgs e)
{
    try
    {
        await Blocklists_ClickAsync(sender, e);
    }
    catch (Exception ex)
    {
        MessageBox.Show($"Operation failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}

private async Task Blocklists_ClickAsync(object sender, RoutedEventArgs e)
{
    if (!EnsureAdminForAction()) return;
    StatusText.Text = "Applying threat blocklists...";
    var progress = new Progress<string>(msg => Dispatcher.Invoke(() => StatusText.Text = msg));

    StatusText.Text = "Applying threat blocklists...";
    await _engine.ApplyThreatBlocklistsAsync(progress, CancellationToken.None);
    Dispatcher.Invoke(() => StatusText.Text += " Done.");
}

private void RemoveBlocklists_Click(object sender, RoutedEventArgs e)
{
    try
    {
        RemoveBlocklists_ClickAsync(sender, e);
    }
    catch (Exception ex)
    {
        MessageBox.Show($"Operation failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}

private void RemoveBlocklists_ClickAsync(object sender, RoutedEventArgs e)
{
    if (!EnsureAdminForAction()) return;
    StatusText.Text = "Removing threat blocklists...";
    _engine.RemoveThreatBlocklistRules();
    StatusText.Text = "Threat blocklists removed.";
    _ = RefreshPortsAsync();
}

private async void Block_Click(object sender, RoutedEventArgs e)
{
    if (!EnsureAdminForAction()) return;
    if ((sender as FrameworkElement)?.DataContext is not PortInfo port) return;
    try
    {
        await Task.Run(() => _engine.BlockPort(port.Port, port.Protocol), _cts.Token);
        Dispatcher.Invoke(() => StatusText.Text = $"Blocked inbound {port.Protocol} {port.Port} (Process: {port.ProcessName}, PID: {port.Pid}).");
    }
    catch (Exception ex)
    {
        StatusText.Text = $"ERROR: Failed to block port: {ex.Message}";
    }
}

private bool EnsureAdminForAction()
{
    return _isAdmin;
}

private static bool IsAdministrator()
{
    using var identity = WindowsIdentity.GetCurrent();
    var principal = new WindowsPrincipal(identity);
    return principal.IsInRole(WindowsBuiltInRole.Administrator);
}

}
