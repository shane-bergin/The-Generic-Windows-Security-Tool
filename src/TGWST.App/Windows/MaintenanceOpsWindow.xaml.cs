using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Input;
using TGWST.App.ViewModels;
using Forms = System.Windows.Forms;

namespace TGWST.App.Windows
{
    public partial class MaintenanceOpsWindow : Window
    {
        private readonly MaintenanceOpsViewModel _viewModel;
        private readonly Dictionary<string, ServiceInspectorWindow> _serviceInspectorWindows = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, EventInspectorWindow> _eventInspectorWindows = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, JunkInspectorWindow> _junkInspectorWindows = new(StringComparer.OrdinalIgnoreCase);

        public MaintenanceOpsWindow(MaintenanceOpsViewModel viewModel)
        {
            InitializeComponent();
            _viewModel = viewModel;
            DataContext = _viewModel;
            Closed += (_, _) => _viewModel.CancelActiveOperation();
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void CancelActive_Click(object sender, RoutedEventArgs e)
        {
            _viewModel.CancelActiveOperation();
        }

        private async void RecoveryScan_Click(object sender, RoutedEventArgs e)
        {
            await _viewModel.ScanRecoveryAsync();
        }

        private async void RecoveryPreview_Click(object sender, RoutedEventArgs e)
        {
            await _viewModel.PreviewSelectedRecoveryAsync();
        }

        private async void RecoveryRestore_Click(object sender, RoutedEventArgs e)
        {
            await _viewModel.RestoreSelectedRecoveryAsync();
        }

        private void BrowseRecoveryFolder_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                using var picker = new Forms.FolderBrowserDialog
                {
                    Description = "Choose a folder for recovered items.",
                    UseDescriptionForTitle = true,
                    ShowNewFolderButton = true
                };

                var result = picker.ShowDialog();
                if (result == Forms.DialogResult.OK &&
                    !string.IsNullOrWhiteSpace(picker.SelectedPath))
                {
                    _viewModel.RecoveryDestinationRoot = picker.SelectedPath;
                }
            }
            catch (Exception ex)
            {
                _viewModel.FooterText = $"[X] Folder selection failed: {ex.Message}";
            }
        }

        private async void AnalyzeServices_Click(object sender, RoutedEventArgs e)
        {
            await _viewModel.AnalyzeServicesAsync();
        }

        private async void DisableService_Click(object sender, RoutedEventArgs e)
        {
            await _viewModel.DisableSelectedServiceAsync();
        }

        private async void RestoreService_Click(object sender, RoutedEventArgs e)
        {
            await _viewModel.RestoreSelectedServiceAsync();
        }

        private void InspectService_Click(object sender, RoutedEventArgs e)
        {
            var row = _viewModel.SelectedServiceItem;
            if (row == null)
            {
                _viewModel.FooterText = "Select a service first.";
                return;
            }

            OpenServiceInspector(row);
        }

        private async void AnalyzeJunk_Click(object sender, RoutedEventArgs e)
        {
            await _viewModel.AnalyzeJunkAsync();
        }

        private async void CleanSelectedJunk_Click(object sender, RoutedEventArgs e)
        {
            await _viewModel.CleanSelectedJunkAsync();
        }

        private async void CleanAllSafeJunk_Click(object sender, RoutedEventArgs e)
        {
            await _viewModel.CleanAllSafeJunkAsync();
        }

        private void InspectJunk_Click(object sender, RoutedEventArgs e)
        {
            var row = _viewModel.SelectedJunkItem;
            if (row == null)
            {
                _viewModel.FooterText = "Select a junk candidate first.";
                return;
            }

            OpenJunkInspector(row);
        }

        private async void AnalyzeEvents_Click(object sender, RoutedEventArgs e)
        {
            await _viewModel.AnalyzeEventLogsAsync();
        }

        private void InspectEvent_Click(object sender, RoutedEventArgs e)
        {
            var row = _viewModel.SelectedEventItem;
            if (row == null)
            {
                _viewModel.FooterText = "Select an event finding first.";
                return;
            }

            OpenEventInspector(row);
        }

        private void ServiceGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            var row = _viewModel.SelectedServiceItem;
            if (row == null)
            {
                return;
            }

            OpenServiceInspector(row);
        }

        private void EventGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            var row = _viewModel.SelectedEventItem;
            if (row == null)
            {
                return;
            }

            OpenEventInspector(row);
        }

        private void JunkGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            var row = _viewModel.SelectedJunkItem;
            if (row == null)
            {
                return;
            }

            OpenJunkInspector(row);
        }

        private void OpenServiceInspector(ServiceRow row)
        {
            try
            {
                if (_serviceInspectorWindows.TryGetValue(row.ServiceName, out var existing) &&
                    existing.IsLoaded)
                {
                    existing.RefreshTarget(row);
                    if (existing.WindowState == WindowState.Minimized)
                    {
                        existing.WindowState = WindowState.Normal;
                    }

                    existing.Activate();
                    return;
                }

                var window = new ServiceInspectorWindow(row)
                {
                    Owner = this
                };

                window.Closed += (_, _) => _serviceInspectorWindows.Remove(row.ServiceName);
                _serviceInspectorWindows[row.ServiceName] = window;
                window.Show();
            }
            catch (Exception ex)
            {
                _viewModel.FooterText = $"[X] Unable to open service inspector: {ex.Message}";
            }
        }

        private void OpenEventInspector(EventLogRow row)
        {
            try
            {
                if (_eventInspectorWindows.TryGetValue(row.InspectorKey, out var existing) &&
                    existing.IsLoaded)
                {
                    existing.RefreshTarget(row);
                    if (existing.WindowState == WindowState.Minimized)
                    {
                        existing.WindowState = WindowState.Normal;
                    }

                    existing.Activate();
                    return;
                }

                var window = new EventInspectorWindow(row)
                {
                    Owner = this
                };

                window.Closed += (_, _) => _eventInspectorWindows.Remove(row.InspectorKey);
                _eventInspectorWindows[row.InspectorKey] = window;
                window.Show();
            }
            catch (Exception ex)
            {
                _viewModel.FooterText = $"[X] Unable to open event inspector: {ex.Message}";
            }
        }

        private void OpenJunkInspector(JunkRow row)
        {
            try
            {
                if (_junkInspectorWindows.TryGetValue(row.InspectorKey, out var existing) &&
                    existing.IsLoaded)
                {
                    existing.RefreshTarget(row);
                    if (existing.WindowState == WindowState.Minimized)
                    {
                        existing.WindowState = WindowState.Normal;
                    }

                    existing.Activate();
                    return;
                }

                var window = new JunkInspectorWindow(row)
                {
                    Owner = this
                };

                window.Closed += (_, _) => _junkInspectorWindows.Remove(row.InspectorKey);
                _junkInspectorWindows[row.InspectorKey] = window;
                window.Show();
            }
            catch (Exception ex)
            {
                _viewModel.FooterText = $"[X] Unable to open junk inspector: {ex.Message}";
            }
        }
    }
}
