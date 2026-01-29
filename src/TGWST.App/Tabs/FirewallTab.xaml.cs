using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using TGWST.App.Windows;
using TGWST.Core.Network;

namespace TGWST.App.Tabs
{
    public partial class FirewallTab : System.Windows.Controls.UserControl
    {
        private readonly FirewallStatusService _service = new();
        private readonly GeoBlockService _geoBlockService = new();
        private readonly ObservableCollection<FirewallProfileStatus> _profiles = new();
        private readonly ObservableCollection<RegionCountryRow> _regionCountries = new();

        public FirewallTab()
        {
            InitializeComponent();
            ProfilesGrid.ItemsSource = _profiles;
            RegionCountriesList.ItemsSource = _regionCountries;

            foreach (var country in GeoBlockService.Countries)
                _regionCountries.Add(new RegionCountryRow(country));

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
            finally
            {
                await LoadRegionLockAsync();
            }
        }

        private async System.Threading.Tasks.Task LoadRegionLockAsync()
        {
            try
            {
                RegionStatusText.Text = "Loading...";
                var blocked = await _geoBlockService.GetBlockedCountriesAsync();
                foreach (var row in _regionCountries)
                    row.IsBlocked = blocked.Contains(row.Name);
                RegionStatusText.Text = "";
            }
            catch (Exception ex)
            {
                RegionStatusText.Text = "";
                ErrorText.Text = $"Failed to load region lock rules: {ex.Message}";
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

        private async void RegionApply_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ErrorText.Text = "";
                RegionApplyButton.IsEnabled = false;
                RegionStatusText.Text = "Applying...";

                var selections = _regionCountries.Select(c => new GeoBlockSelection(c.Name, c.Code, c.IsBlocked)).ToArray();
                await _geoBlockService.ApplyAsync(selections);

                await LoadRegionLockAsync();
                RegionStatusText.Text = "Applied.";
            }
            catch (Exception ex)
            {
                RegionStatusText.Text = "";
                ErrorText.Text = $"Failed to apply region lock rules: {ex.Message}";
            }
            finally
            {
                RegionApplyButton.IsEnabled = true;
            }
        }

        private sealed class RegionCountryRow : INotifyPropertyChanged
        {
            public RegionCountryRow(GeoBlockCountry country)
            {
                Name = country.Name;
                Code = country.Code;
                Label = country.Label;
            }

            public string Name { get; }
            public string Code { get; }
            public string Label { get; }

            private bool _isBlocked;
            public bool IsBlocked
            {
                get => _isBlocked;
                set
                {
                    if (_isBlocked == value) return;
                    _isBlocked = value;
                    OnPropertyChanged();
                }
            }

            public event PropertyChangedEventHandler? PropertyChanged;

            private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
                => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
