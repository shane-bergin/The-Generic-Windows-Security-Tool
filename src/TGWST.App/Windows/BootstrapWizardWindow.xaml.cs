using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using TGWST.App.Services;

namespace TGWST.App.Windows
{
    public partial class BootstrapWizardWindow : Window
    {
        private readonly BootstrapProvisioningService _bootstrap;
        private readonly WslCredentialService _credentials;
        private BootstrapStatus? _lastStatus;

        public BootstrapWizardWindow(BootstrapProvisioningService bootstrap, WslCredentialService credentials)
        {
            InitializeComponent();
            _bootstrap = bootstrap;
            _credentials = credentials;
            Loaded += OnLoaded;
        }

        private async void OnLoaded(object sender, RoutedEventArgs e)
        {
            var snapshot = _credentials.GetSnapshot();
            if (!string.IsNullOrWhiteSpace(snapshot.UserName))
            {
                UsernameBox.Text = snapshot.UserName;
            }

            await RefreshStatusAsync();
        }

        private async void RefreshButton_Click(object sender, RoutedEventArgs e)
        {
            await RefreshStatusAsync();
        }

        private async void RunButton_Click(object sender, RoutedEventArgs e)
        {
            await RunProvisionAsync();
        }

        private void ContinueButton_Click(object sender, RoutedEventArgs e)
        {
            if (_lastStatus?.CoreReady == true)
            {
                _bootstrap.MarkWizardCompleted(_lastStatus.ResolvedDistro);
            }

            Close();
        }

        private async Task RefreshStatusAsync()
        {
            await WithBusyStateAsync(async () =>
            {
                FooterStatusText.Text = "Probing local machine dependencies...";
                _lastStatus = await _bootstrap.ProbeAsync(CancellationToken.None);
                RenderStatus(_lastStatus);
                FooterStatusText.Text = _lastStatus.CoreReady
                    ? "Core provisioning ready. Continue to main console."
                    : "Provisioning incomplete. Run selected setup steps.";
            });
        }

        private async Task RunProvisionAsync()
        {
            await WithBusyStateAsync(async () =>
            {
                AppendLog("=== TGWST Bootstrap Run Started ===");

                var plan = new BootstrapPlan(
                    EnsureWslAndUbuntu: EnsureWslCheck.IsChecked == true,
                    InstallDocker: InstallDockerCheck.IsChecked == true,
                    InstallPiHole: InstallPiHoleCheck.IsChecked == true,
                    SyncWindowsDns: SyncDnsCheck.IsChecked == true,
                    InterfaceAlias: InterfaceAliasBox.Text,
                    SaveCredentials: SaveCredsCheck.IsChecked == true,
                    WslUserName: UsernameBox.Text,
                    WslPassword: string.IsNullOrWhiteSpace(PasswordBox.Password) ? null : PasswordBox.Password);

                try
                {
                    _lastStatus = await _bootstrap.RunProvisionAsync(plan, AppendLog, CancellationToken.None);
                    RenderStatus(_lastStatus);
                    FooterStatusText.Text = _lastStatus.CoreReady
                        ? "Provisioning complete. You can continue."
                        : "Provisioning run finished with remaining gaps.";
                }
                catch (Exception ex)
                {
                    AppendLog($"[X] {ex.Message}");
                    FooterStatusText.Text = "Provisioning failed. Review log and retry.";
                }

                AppendLog("=== TGWST Bootstrap Run Finished ===");
            });
        }

        private async Task WithBusyStateAsync(Func<Task> action)
        {
            try
            {
                RefreshButton.IsEnabled = false;
                RunButton.IsEnabled = false;
                await action();
            }
            finally
            {
                RefreshButton.IsEnabled = true;
                RunButton.IsEnabled = true;
            }
        }

        private void AppendLog(string line)
        {
            var message = (line ?? string.Empty).TrimEnd();
            if (message.Length == 0)
            {
                return;
            }

            if (LogBox.Text.Length == 0)
            {
                LogBox.Text = message;
            }
            else
            {
                LogBox.AppendText(Environment.NewLine + message);
            }

            LogBox.ScrollToEnd();
        }

        private void RenderStatus(BootstrapStatus status)
        {
            WslStatusText.Text = status.IsWslInstalled
                ? $"[✓] WSL installed | distro: {status.ResolvedDistro ?? "(none)"} | bash: {(status.BashReachable ? "ready" : "unavailable")}" 
                : $"[X] WSL unavailable ({status.FailureReason ?? "not detected"})";
            SetStatusColor(WslStatusText, status.IsWslInstalled && status.BashReachable);

            DockerStatusText.Text = status.DockerInstalled
                ? $"[✓] Docker installed | service: {(status.DockerActive ? "active" : "inactive")}" 
                : "[X] Docker not installed in selected distro";
            SetStatusColor(DockerStatusText, status.DockerInstalled && status.DockerActive);

            PiHoleStatusText.Text = status.PiHoleInstalled
                ? $"[✓] Pi-hole installed | blocking: {(status.PiHoleBlockingEnabled ? "on" : "off")}" 
                : "[X] Pi-hole appliance not installed";
            SetStatusColor(PiHoleStatusText, status.PiHoleInstalled);

            FtlStatusText.Text = status.PiHoleFtlReachable
                ? "[✓] FTL socket reachable on localhost:4711"
                : "[X] FTL socket not reachable";
            SetStatusColor(FtlStatusText, status.PiHoleFtlReachable);

            DnsTargetText.Text = string.IsNullOrWhiteSpace(status.WslIpAddress)
                ? "[i] WSL IP unknown"
                : $"[i] Current WSL IP: {status.WslIpAddress}";
            DnsTargetText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#94A4C1"));

            CredsStatusText.Text = status.CredentialsConfigured
                ? $"[✓] Stored credentials configured ({status.CredentialsUser})"
                : "[X] Stored sudo credentials missing";
            SetStatusColor(CredsStatusText, status.CredentialsConfigured);
        }

        private static void SetStatusColor(System.Windows.Controls.TextBlock block, bool ok)
        {
            var color = ok ? "#8ED26D" : "#E16E74";
            block.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color));
        }
    }
}
