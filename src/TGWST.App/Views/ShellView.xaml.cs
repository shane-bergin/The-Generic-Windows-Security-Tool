using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Extensions.DependencyInjection;
using TGWST.App.Shell;
using TGWST.App.Services;
using TGWST.App.ViewModels;
using TGWST.App.Windows;
using TGWST.Core.Network.Hybrid;
using Key = System.Windows.Input.Key;
using KeyEventArgs = System.Windows.Input.KeyEventArgs;

namespace TGWST.App.Views
{
    public partial class ShellView : Window
    {
        private ScrollViewer? _outputScroll;
        private ScrollViewer? _attachedScroll;
        private ConnectionsWindow? _connectionsWindow;
        private WslCredentialsWindow? _wslCredentialsWindow;
        private BootstrapWizardWindow? _bootstrapWizardWindow;
        private NetworkOpsWindow? _networkOpsWindow;
        private MaintenanceOpsWindow? _maintenanceOpsWindow;
        private readonly Dictionary<string, EndpointInspectorWindow> _endpointInspectorWindows = new(StringComparer.OrdinalIgnoreCase);
        private readonly WslCredentialService _wslCredentialService;
        private readonly HybridModeService _hybridModeService;
        private readonly PiHoleBridgeService _piHoleBridgeService;
        private readonly IWslHybridAnalyzer _wslHybridAnalyzer;
        private readonly BootstrapProvisioningService _bootstrapProvisioningService;
        private readonly InsightService _insightService;
        private readonly IServiceProvider _services;

        public ShellView(
            ShellViewModel viewModel,
            WslCredentialService wslCredentialService,
            HybridModeService hybridModeService,
            PiHoleBridgeService piHoleBridgeService,
            IWslHybridAnalyzer wslHybridAnalyzer,
            BootstrapProvisioningService bootstrapProvisioningService,
            InsightService insightService,
            IServiceProvider services)
        {
            InitializeComponent();
            DataContext = viewModel;
            _wslCredentialService = wslCredentialService;
            _hybridModeService = hybridModeService;
            _piHoleBridgeService = piHoleBridgeService;
            _wslHybridAnalyzer = wslHybridAnalyzer;
            _bootstrapProvisioningService = bootstrapProvisioningService;
            _insightService = insightService;
            _services = services;
            Loaded += OnLoaded;
        }

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            CommandInput.Focus();
        }

        private async void OnKeyDown(object sender, KeyEventArgs e)
        {
            await HandleKeyAsync(e, isCommandInputPreview: false);
        }

        private async void OnCommandInputPreviewKeyDown(object sender, KeyEventArgs e)
        {
            await HandleKeyAsync(e, isCommandInputPreview: true);
        }

        private async Task HandleKeyAsync(KeyEventArgs e, bool isCommandInputPreview)
        {
            if (DataContext is not ShellViewModel vm)
            {
                return;
            }

            try
            {
                if (!IsCtrlKey(e, Key.W))
                {
                    vm.ClearAttachedPaneClosePrompt();
                }

                if (TryHandleScrollKey(e, vm) ||
                    TryHandleControlKey(e, vm) ||
                    TryHandleBackKey(e, vm))
                {
                    return;
                }

                if (isCommandInputPreview)
                {
                    TryHandleMenuNavigationForPreview(e, vm);
                    return;
                }

                await HandleWindowOnlyKeyAsync(e, vm);
            }
            catch (Exception ex)
            {
                vm.AddOutput($"[X] Input handling error: {ex.Message}\n");
            }
        }

        private bool TryHandleScrollKey(KeyEventArgs e, ShellViewModel vm)
        {
            if (e.Key == Key.PageUp)
            {
                e.Handled = true;
                ScrollActivePane(pageDown: false, vm);
                return true;
            }

            if (e.Key == Key.PageDown)
            {
                e.Handled = true;
                ScrollActivePane(pageDown: true, vm);
                return true;
            }

            if (e.Key == Key.Home)
            {
                e.Handled = true;
                ScrollToEdge(toEnd: false, vm);
                return true;
            }

            if (e.Key == Key.End)
            {
                e.Handled = true;
                ScrollToEdge(toEnd: true, vm);
                return true;
            }

            return false;
        }

        private static bool TryHandleControlKey(KeyEventArgs e, ShellViewModel vm)
        {
            if ((Keyboard.Modifiers & ModifierKeys.Control) != ModifierKeys.Control)
            {
                return false;
            }

            if (e.Key == Key.P)
            {
                e.Handled = true;
                vm.ToggleAttachedPanePause();
                return true;
            }

            if (e.Key == Key.W)
            {
                e.Handled = true;
                vm.RequestCloseAttachedPane();
                return true;
            }

            if (e.Key == Key.Up)
            {
                e.Handled = true;
                vm.HistoryUp();
                return true;
            }

            if (e.Key == Key.Down)
            {
                e.Handled = true;
                vm.HistoryDown();
                return true;
            }

            return false;
        }

        private static bool TryHandleBackKey(KeyEventArgs e, ShellViewModel vm)
        {
            if ((Keyboard.Modifiers & ModifierKeys.Alt) == ModifierKeys.Alt && e.Key == Key.Left)
            {
                e.Handled = true;
                vm.NavigateBack();
                return true;
            }

            if (e.Key == Key.Left && string.IsNullOrWhiteSpace(vm.CommandLine))
            {
                e.Handled = true;
                vm.NavigateBack();
                return true;
            }

            return false;
        }

        private static void TryHandleMenuNavigationForPreview(KeyEventArgs e, ShellViewModel vm)
        {
            if (e.Key == Key.Up)
            {
                e.Handled = true;
                vm.MenuUp();
                return;
            }

            if (e.Key == Key.Down)
            {
                e.Handled = true;
                vm.MenuDown();
                return;
            }

            if (e.Key == Key.Right && string.IsNullOrWhiteSpace(vm.CommandLine))
            {
                e.Handled = true;
                vm.ToggleMenuDetails();
            }
        }

        private async Task HandleWindowOnlyKeyAsync(KeyEventArgs e, ShellViewModel vm)
        {
            if (e.Key == Key.Enter)
            {
                e.Handled = true;
                if (string.IsNullOrWhiteSpace(vm.CommandLine))
                {
                    await vm.ExecuteSelectedMenuAsync();
                }
                else
                {
                    await vm.ExecuteAsync();
                }

                return;
            }

            if (e.Key == Key.Up)
            {
                e.Handled = true;
                vm.MenuUp();
                return;
            }

            if (e.Key == Key.Down)
            {
                e.Handled = true;
                vm.MenuDown();
                return;
            }

            if (e.Key == Key.Right)
            {
                e.Handled = true;
                vm.ToggleMenuDetails();
                return;
            }

            if (e.Key == Key.F10)
            {
                e.Handled = true;
                Application.Current.Shutdown();
                return;
            }

            if (e.Key == Key.F2)
            {
                e.Handled = true;
                vm.ToggleAcronyms();
                return;
            }

            if (e.Key == Key.F3)
            {
                e.Handled = true;
                await vm.ExplainLastBlockAsync();
                return;
            }

            if (e.Key == Key.F4)
            {
                e.Handled = true;
                await vm.SummarizeBlocksAsync();
            }
        }

        private static bool IsCtrlKey(KeyEventArgs e, Key key)
        {
            return (Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control && e.Key == key;
        }

        private async void OnMenuItemClick(object sender, MouseButtonEventArgs e)
        {
            if (DataContext is not ShellViewModel vm)
            {
                return;
            }

            if (sender is FrameworkElement element && element.DataContext is MenuEntryViewModel entry)
            {
                try
                {
                    vm.SelectMenuEntry(entry, toggleDetails: true);
                    if (e.ClickCount >= 2)
                    {
                        if (string.Equals(entry.Node.Command, "network board", StringComparison.OrdinalIgnoreCase))
                        {
                            OpenNetworkOpsWindow();
                        }
                        else
                        {
                            await vm.ExecuteSelectedMenuAsync();
                        }
                    }
                }
                catch (Exception ex)
                {
                    vm.AddOutput($"[X] Menu action failed: {ex.Message}\n");
                }

                CommandInput.Focus();
                e.Handled = true;
            }
        }

        private async void OnQuickActionClick(object sender, RoutedEventArgs e)
        {
            if (DataContext is not ShellViewModel vm)
            {
                return;
            }

            if (sender is not Button button)
            {
                return;
            }

            var command = (button.Tag as string)?.Trim();
            if (string.IsNullOrWhiteSpace(command))
            {
                return;
            }

            try
            {
                await ExecuteUiActionAsync(vm, command);
            }
            catch (Exception ex)
            {
                vm.AddOutput($"[X] Quick action failed: {ex.Message}\n");
            }
            CommandInput.Focus();
        }

        private async void OnQuickMenuSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (DataContext is not ShellViewModel vm || sender is not ComboBox combo || combo.SelectedIndex <= 0)
            {
                return;
            }

            if (combo.SelectedItem is not ComboBoxItem item)
            {
                combo.SelectedIndex = 0;
                return;
            }

            var actionTag = (item.Tag as string)?.Trim();
            if (string.IsNullOrWhiteSpace(actionTag))
            {
                combo.SelectedIndex = 0;
                return;
            }

            try
            {
                await ExecuteUiActionAsync(vm, actionTag);
            }
            catch (Exception ex)
            {
                vm.AddOutput($"[X] Tool action failed: {ex.Message}\n");
            }
            finally
            {
                combo.SelectedIndex = 0;
                CommandInput.Focus();
            }

            e.Handled = true;
        }

        private async Task ExecuteUiActionAsync(ShellViewModel vm, string actionTag)
        {
            switch (actionTag)
            {
                case "__open_connections":
                    OpenConnectionsWindow();
                    return;
                case "__open_wsl_credentials":
                    OpenWslCredentialsWindow();
                    return;
                case "__open_bootstrap_wizard":
                    OpenBootstrapWizardWindow();
                    return;
                case "__open_network_ops":
                    OpenNetworkOpsWindow();
                    return;
                case "__open_maintenance_ops":
                    OpenMaintenanceOpsWindow();
                    return;
                case "__focus_pane":
                    FocusActivePane(vm);
                    return;
                case "__explain_last":
                    await vm.ExplainLastBlockAsync();
                    return;
                case "__summarize_output":
                    await vm.SummarizeBlocksAsync();
                    return;
                default:
                    vm.CommandLine = actionTag;
                    await vm.ExecuteAsync();
                    return;
            }
        }

        public void ShowNetworkOpsWindow()
        {
            OpenNetworkOpsWindow();
        }

        public void ShowMaintenanceOpsWindow()
        {
            OpenMaintenanceOpsWindow();
        }

        private void OpenNetworkOpsWindow()
        {
            try
            {
                if (_networkOpsWindow is { IsLoaded: true })
                {
                    if (_networkOpsWindow.WindowState == WindowState.Minimized)
                    {
                        _networkOpsWindow.WindowState = WindowState.Normal;
                    }

                    _networkOpsWindow.Activate();
                    return;
                }

                var window = new NetworkOpsWindow(_hybridModeService, _wslCredentialService, _piHoleBridgeService, _wslHybridAnalyzer, _insightService)
                {
                    Owner = this
                };
                window.Closed += (_, _) => _networkOpsWindow = null;
                _networkOpsWindow = window;
                window.Show();
            }
            catch (Exception ex)
            {
                ReportUiError("open Network Operations window", ex);
            }
        }

        private void OpenMaintenanceOpsWindow()
        {
            try
            {
                if (_maintenanceOpsWindow is { IsLoaded: true })
                {
                    if (_maintenanceOpsWindow.WindowState == WindowState.Minimized)
                    {
                        _maintenanceOpsWindow.WindowState = WindowState.Normal;
                    }

                    _maintenanceOpsWindow.Activate();
                    return;
                }

                var vm = _services.GetRequiredService<MaintenanceOpsViewModel>();
                var window = new MaintenanceOpsWindow(vm)
                {
                    Owner = this
                };
                window.Closed += (_, _) => _maintenanceOpsWindow = null;
                _maintenanceOpsWindow = window;
                window.Show();
            }
            catch (Exception ex)
            {
                ReportUiError("open Maintenance Operations window", ex);
            }
        }

        private void OpenBootstrapWizardWindow()
        {
            try
            {
                if (_bootstrapWizardWindow is { IsLoaded: true })
                {
                    if (_bootstrapWizardWindow.WindowState == WindowState.Minimized)
                    {
                        _bootstrapWizardWindow.WindowState = WindowState.Normal;
                    }

                    _bootstrapWizardWindow.Activate();
                    return;
                }

                var window = new BootstrapWizardWindow(_bootstrapProvisioningService, _wslCredentialService)
                {
                    Owner = this
                };
                window.Closed += (_, _) => _bootstrapWizardWindow = null;
                _bootstrapWizardWindow = window;
                window.Show();
            }
            catch (Exception ex)
            {
                ReportUiError("open bootstrap wizard window", ex);
            }
        }

        private void OpenConnectionsWindow()
        {
            try
            {
                if (_connectionsWindow is { IsLoaded: true })
                {
                    if (_connectionsWindow.WindowState == WindowState.Minimized)
                    {
                        _connectionsWindow.WindowState = WindowState.Normal;
                    }

                    _connectionsWindow.Activate();
                    return;
                }

                var window = new ConnectionsWindow { Owner = this };
                window.Closed += (_, _) => _connectionsWindow = null;
                _connectionsWindow = window;
                window.Show();
            }
            catch (Exception ex)
            {
                ReportUiError("open Connections window", ex);
            }
        }

        private void OpenWslCredentialsWindow()
        {
            try
            {
                if (_wslCredentialsWindow is { IsLoaded: true })
                {
                    if (_wslCredentialsWindow.WindowState == WindowState.Minimized)
                    {
                        _wslCredentialsWindow.WindowState = WindowState.Normal;
                    }

                    _wslCredentialsWindow.Activate();
                    return;
                }

                var window = new WslCredentialsWindow(_wslCredentialService, _hybridModeService.PreferredDistro) { Owner = this };
                window.Closed += (_, _) => _wslCredentialsWindow = null;
                _wslCredentialsWindow = window;
                window.Show();
            }
            catch (Exception ex)
            {
                ReportUiError("open WSL credentials window", ex);
            }
        }

        private void OnEndpointRowClick(object sender, MouseButtonEventArgs e)
        {
            if (sender is not FrameworkElement element ||
                element.DataContext is not EndpointFocusItem endpoint)
            {
                return;
            }

            if (DataContext is ShellViewModel vm && vm.AttachedPane != null)
            {
                vm.AttachedPane.SelectInteractiveEndpoint(endpoint.EndpointKey);
            }

            if (e.ClickCount >= 2)
            {
                OpenEndpointInspectorWindow(endpoint);
            }

            e.Handled = true;
        }

        private void OnEndpointInspectClick(object sender, RoutedEventArgs e)
        {
            if (TryGetEndpointFromSender(sender, out var endpoint))
            {
                if (DataContext is ShellViewModel vm && vm.AttachedPane != null)
                {
                    vm.AttachedPane.SelectInteractiveEndpoint(endpoint.EndpointKey);
                }

                OpenEndpointInspectorWindow(endpoint);
            }

            e.Handled = true;
        }

        private void OnEndpointCopyIpClick(object sender, RoutedEventArgs e)
        {
            if (!TryGetEndpointFromSender(sender, out var endpoint))
            {
                e.Handled = true;
                return;
            }

            try
            {
                var ip = (endpoint.RemoteAddress ?? string.Empty).Trim();
                if (ip.Length == 0)
                {
                    ReportUiError("copy remote IP", new InvalidOperationException("No remote IP available for selected endpoint."));
                    e.Handled = true;
                    return;
                }

                Clipboard.SetText(ip);
                ReportUiInfo($"Copied remote IP: {ip}");
            }
            catch (Exception ex)
            {
                ReportUiError("copy remote IP", ex);
            }

            e.Handled = true;
        }

        private void OnEndpointWhoisClick(object sender, RoutedEventArgs e)
        {
            if (!TryGetEndpointFromSender(sender, out var endpoint))
            {
                e.Handled = true;
                return;
            }

            try
            {
                var ip = (endpoint.RemoteAddress ?? string.Empty).Trim();
                if (ip.Length == 0)
                {
                    ReportUiError("open WHOIS lookup", new InvalidOperationException("No remote IP available for selected endpoint."));
                    e.Handled = true;
                    return;
                }

                var url = $"https://rdap.arin.net/registry/ip/{Uri.EscapeDataString(ip)}";
                Process.Start(new ProcessStartInfo
                {
                    FileName = url,
                    UseShellExecute = true
                });
                ReportUiInfo($"Opened WHOIS/RDAP lookup for {ip}");
            }
            catch (Exception ex)
            {
                ReportUiError("open WHOIS lookup", ex);
            }

            e.Handled = true;
        }

        private void OpenEndpointInspectorWindow(EndpointFocusItem endpoint)
        {
            try
            {
                if (_endpointInspectorWindows.TryGetValue(endpoint.EndpointKey, out var existing) &&
                    existing.IsLoaded)
                {
                    existing.RefreshTarget(endpoint);
                    if (existing.WindowState == WindowState.Minimized)
                    {
                        existing.WindowState = WindowState.Normal;
                    }

                    existing.Activate();
                    return;
                }

                var window = new EndpointInspectorWindow(endpoint) { Owner = this };
                window.Closed += (_, _) => _endpointInspectorWindows.Remove(endpoint.EndpointKey);
                _endpointInspectorWindows[endpoint.EndpointKey] = window;
                window.Show();
            }
            catch (Exception ex)
            {
                ReportUiError("open endpoint inspector window", ex);
            }
        }

        private void FocusActivePane(ShellViewModel vm)
        {
            if (vm.IsAttachedPaneVisible && _attachedScroll != null)
            {
                _attachedScroll.Focus();
                return;
            }

            if (_outputScroll != null)
            {
                _outputScroll.Focus();
            }
        }

        private void OnOutputScrollLoaded(object sender, RoutedEventArgs e)
        {
            _outputScroll = sender as ScrollViewer;
        }

        private void OnOutputScrollUnloaded(object sender, RoutedEventArgs e)
        {
            if (ReferenceEquals(_outputScroll, sender))
            {
                _outputScroll = null;
            }
        }

        private void OnAttachedScrollLoaded(object sender, RoutedEventArgs e)
        {
            _attachedScroll = sender as ScrollViewer;
        }

        private void OnAttachedScrollUnloaded(object sender, RoutedEventArgs e)
        {
            if (ReferenceEquals(_attachedScroll, sender))
            {
                _attachedScroll = null;
            }
        }

        private void ScrollActivePane(bool pageDown, ShellViewModel vm)
        {
            var target = (vm.IsAttachedPaneVisible && _attachedScroll != null)
                ? _attachedScroll
                : _outputScroll;

            if (target == null)
            {
                return;
            }

            if (pageDown)
            {
                target.PageDown();
            }
            else
            {
                target.PageUp();
            }
        }

        private void ScrollToEdge(bool toEnd, ShellViewModel vm)
        {
            var target = (vm.IsAttachedPaneVisible && _attachedScroll != null)
                ? _attachedScroll
                : _outputScroll;

            if (target == null)
            {
                return;
            }

            if (toEnd)
            {
                target.ScrollToEnd();
            }
            else
            {
                target.ScrollToHome();
            }
        }

        private void ReportUiError(string action, Exception ex)
        {
            if (DataContext is ShellViewModel vm)
            {
                vm.AddOutput($"[X] Unable to {action}: {ex.Message}\n");
            }
        }

        private void ReportUiInfo(string message)
        {
            if (DataContext is ShellViewModel vm)
            {
                vm.AddOutput($"[i] {message}\n");
            }
        }

        private static bool TryGetEndpointFromSender(object sender, out EndpointFocusItem endpoint)
        {
            endpoint = default!;
            if (sender is not FrameworkElement element ||
                element.DataContext is not EndpointFocusItem endpointItem)
            {
                return false;
            }

            endpoint = endpointItem;
            return true;
        }
    }
}
