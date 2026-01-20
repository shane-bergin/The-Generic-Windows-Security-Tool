using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Threading;
using TGWST.Core.Network;

namespace TGWST.App.Windows
{
    public partial class ConnectionsWindow : Window
    {
        private readonly ConnectionMonitor _monitor = new();
        private readonly ObservableCollection<ConnectionInfo> _connections = new();
        private readonly DispatcherTimer _timer;

        public ConnectionsWindow()
        {
            InitializeComponent();
            ConnectionsGrid.ItemsSource = _connections;

            _timer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(5)
            };
            _timer.Tick += async (_, _) => await LoadAsync();
            _timer.Start();

            Unloaded += (_, _) => _timer.Stop();
            _ = LoadAsync();
        }

        private async System.Threading.Tasks.Task LoadAsync()
        {
            try
            {
                ErrorText.Text = "";
                var data = await _monitor.GetTcpConnectionsAsync();
                var filtered = ApplyFilter(data);

                _connections.Clear();
                foreach (var c in filtered) _connections.Add(c);
                StatusText.Text = $"{filtered.Count} connections";
            }
            catch (Exception ex)
            {
                ErrorText.Text = $"Failed to load connections: {ex.Message}";
            }
        }

        private void Refresh_Click(object sender, RoutedEventArgs e) => _ = LoadAsync();

        private IReadOnlyList<ConnectionInfo> ApplyFilter(IReadOnlyList<ConnectionInfo> data)
        {
            var filter = FilterBox.Text?.Trim();
            if (string.IsNullOrWhiteSpace(filter)) return data;

            return data
                .Where(c =>
                    c.LocalAddress.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                    c.RemoteAddress.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                    (!string.IsNullOrWhiteSpace(c.RemoteHost) && c.RemoteHost.Contains(filter, StringComparison.OrdinalIgnoreCase)) ||
                    c.ProcessName.Contains(filter, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }
    }
}
