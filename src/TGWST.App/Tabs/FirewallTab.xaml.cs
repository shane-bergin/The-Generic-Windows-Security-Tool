using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using TGWST.App.Windows;
using TGWST.Core.Network;

namespace TGWST.App.Tabs
{
    public partial class FirewallTab : System.Windows.Controls.UserControl
    {
        private readonly FirewallStatusService _service = new();
        private readonly ObservableCollection<FirewallProfileStatus> _profiles = new();

        public FirewallTab()
        {
            InitializeComponent();
            ProfilesGrid.ItemsSource = _profiles;
            _ = LoadAsync();
        }

        private async System.Threading.Tasks.Task LoadAsync()
        {
            try
            {
                ErrorText.Text = "";
                var statuses = await _service.GetStatusAsync();
                _profiles.Clear();
                foreach (var s in statuses) _profiles.Add(s);

                var anyVulnerable = statuses.Any(s => s.IsVulnerable);
                SummaryText.Text = anyVulnerable ? "Firewall: Vulnerable" : "Firewall: Healthy";
                SummaryText.Foreground = anyVulnerable ? System.Windows.Media.Brushes.DarkRed : System.Windows.Media.Brushes.DarkGreen;
            }
            catch (Exception ex)
            {
                ErrorText.Text = $"Failed to read firewall status: {ex.Message}";
                SummaryText.Text = "Firewall: Unknown";
                SummaryText.Foreground = System.Windows.Media.Brushes.DarkRed;
            }
        }

        private async void Refresh_Click(object sender, RoutedEventArgs e) => await LoadAsync();

        private void OpenConnections_Click(object sender, RoutedEventArgs e)
        {
            var win = new ConnectionsWindow
            {
                Owner = System.Windows.Application.Current.MainWindow
            };
            win.Show();
        }
    }
}
