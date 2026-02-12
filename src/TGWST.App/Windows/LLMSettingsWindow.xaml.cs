using System;
using System.Linq;
using System.Windows;
using TGWST.Core.LLM;
using MessageBox = System.Windows.MessageBox;

namespace TGWST.App.Windows
{
    public partial class LLMSettingsWindow : Window
    {
        public LLMSettingsWindow()
        {
            InitializeComponent();
            LoadSettings();
        }

        private void LoadSettings()
        {
            var settings = LLMSettings.Load();

            foreach (var item in ProviderCombo.Items.Cast<System.Windows.Controls.ComboBoxItem>())
            {
                var tag = item.Tag?.ToString();
                if (Enum.TryParse<LLMProvider>(tag, out var provider) && provider == settings.Provider)
                {
                    ProviderCombo.SelectedItem = item;
                    break;
                }
            }

            ApiKeyBox.Password = settings.ApiKey;
            ModelBox.Text = settings.Model ?? string.Empty;
            EndpointBox.Text = settings.Endpoint ?? string.Empty;
        }

        private void Save_Click(object sender, RoutedEventArgs e)
        {
            if (ProviderCombo.SelectedItem is not System.Windows.Controls.ComboBoxItem item ||
                !Enum.TryParse<LLMProvider>(item.Tag?.ToString(), out var provider))
            {
                MessageBox.Show("Select a provider.", "LLM Settings", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var apiKey = ApiKeyBox.Password?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(apiKey))
            {
                MessageBox.Show("Enter an API key.", "LLM Settings", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var settings = new LLMSettings
            {
                Provider = provider,
                ApiKey = apiKey,
                Model = string.IsNullOrWhiteSpace(ModelBox.Text) ? null : ModelBox.Text.Trim(),
                Endpoint = string.IsNullOrWhiteSpace(EndpointBox.Text) ? null : EndpointBox.Text.Trim()
            };

            try
            {
                settings.Save();
                MessageBox.Show("LLM settings saved.", "LLM Settings", MessageBoxButton.OK, MessageBoxImage.Information);
                Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to save settings: {ex.Message}", "LLM Settings", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
