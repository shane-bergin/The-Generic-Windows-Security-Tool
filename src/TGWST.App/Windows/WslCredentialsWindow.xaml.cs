using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using TGWST.App.Services;

namespace TGWST.App.Windows
{
    public partial class WslCredentialsWindow : Window
    {
        private readonly WslCredentialService _credentialService;
        private readonly string? _preferredDistro;

        public WslCredentialsWindow(WslCredentialService credentialService, string? preferredDistro = null)
        {
            InitializeComponent();
            _credentialService = credentialService;
            _preferredDistro = string.IsNullOrWhiteSpace(preferredDistro) ? null : preferredDistro.Trim();
            Loaded += OnLoaded;
            LoadState();
        }

        private async void OnLoaded(object sender, RoutedEventArgs e)
        {
            await RefreshEnvironmentAsync();
        }

        private void LoadState()
        {
            var snapshot = _credentialService.GetSnapshot();

            EnableCheck.IsChecked = snapshot.IsEnabled;
            UserBox.Text = snapshot.UserName ?? string.Empty;
            PasswordBox.Password = string.Empty;

            StoredPasswordText.Text = snapshot.HasStoredPassword
                ? "[i] Stored password: present (encrypted)"
                : "[i] Stored password: none";

            SetStatus("[i] Save credentials, then use Verify to test sudo in WSL.", isSuccess: null);
        }

        private void Save_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var password = string.IsNullOrEmpty(PasswordBox.Password) ? null : PasswordBox.Password;
                _credentialService.Save(
                    userName: UserBox.Text,
                    password: password,
                    enabled: EnableCheck.IsChecked == true);

                PasswordBox.Password = string.Empty;
                LoadState();
                SetStatus("[OK] WSL credentials saved and encrypted.", isSuccess: true);
            }
            catch (Exception ex)
            {
                SetStatus($"[X] Save failed: {ex.Message}", isSuccess: false);
            }
        }

        private async void Verify_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                await WithBusyStateAsync(async () =>
                {
                    SetStatus("[i] Verifying sudo credentials in WSL...", isSuccess: null);
                    var (success, message) = await _credentialService.VerifyAsync(_preferredDistro);
                    SetStatus(success ? $"[OK] {message}" : $"[X] {message}", success);
                });
            }
            catch (Exception ex)
            {
                SetStatus($"[X] Verification failed: {ex.Message}", isSuccess: false);
            }
        }

        private void Clear_Click(object sender, RoutedEventArgs e)
        {
            _credentialService.Clear();
            LoadState();
            SetStatus("[OK] Stored WSL credentials were cleared.", isSuccess: true);
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private async Task WithBusyStateAsync(Func<Task> action)
        {
            try
            {
                SaveButton.IsEnabled = false;
                VerifyButton.IsEnabled = false;
                ClearButton.IsEnabled = false;
                await action();
                await RefreshEnvironmentAsync();
            }
            finally
            {
                SaveButton.IsEnabled = true;
                VerifyButton.IsEnabled = true;
                ClearButton.IsEnabled = true;
            }
        }

        private void SetStatus(string message, bool? isSuccess)
        {
            StatusText.Text = message;

            if (isSuccess == true)
            {
                StatusText.Foreground = new System.Windows.Media.SolidColorBrush(
                    (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#00FF9A"));
                return;
            }

            if (isSuccess == false)
            {
                StatusText.Foreground = new System.Windows.Media.SolidColorBrush(
                    (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#FF4E63"));
                return;
            }

            StatusText.Foreground = new System.Windows.Media.SolidColorBrush(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#7F99B8"));
        }

        private async Task RefreshEnvironmentAsync()
        {
            try
            {
                var snapshot = await _credentialService.DetectEnvironmentAsync(_preferredDistro, CancellationToken.None);
                DetectedDistroText.Text = $"Distro: {snapshot.ResolvedDistro ?? "(not detected)"}";
                DetectedUserText.Text = $"User: {snapshot.CurrentUser ?? "(unknown)"}";
                DetectedKernelText.Text = $"Kernel: {snapshot.KernelInfo ?? "(not available)"}";

                if (!string.IsNullOrWhiteSpace(snapshot.FailureReason))
                {
                    EnvironmentHintText.Text = $"[X] {snapshot.FailureReason}";
                    EnvironmentHintText.Foreground = new System.Windows.Media.SolidColorBrush(
                        (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#FF4E63"));
                }
                else
                {
                    EnvironmentHintText.Text = "[OK] WSL environment detected automatically.";
                    EnvironmentHintText.Foreground = new System.Windows.Media.SolidColorBrush(
                        (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#00FF9A"));
                }
            }
            catch (Exception ex)
            {
                DetectedDistroText.Text = "Distro: (error)";
                DetectedUserText.Text = "User: (error)";
                DetectedKernelText.Text = "Kernel: (error)";
                EnvironmentHintText.Text = $"[X] WSL probe failed: {ex.Message}";
                EnvironmentHintText.Foreground = new System.Windows.Media.SolidColorBrush(
                    (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#FF4E63"));
            }
        }
    }
}
