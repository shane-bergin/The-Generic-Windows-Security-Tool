using System.Windows;
using System.Windows.Input;
using TGWST.App.ViewModels;

namespace TGWST.App.Views
{
    public partial class ShellView : Window
    {
        public ShellView(ShellViewModel viewModel)
        {
            InitializeComponent();
            DataContext = viewModel;
            Loaded += OnLoaded;
        }

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            CommandInput.Focus();
        }

        private async void OnKeyDown(object sender, KeyEventArgs e)
        {
            if (DataContext is not ShellViewModel vm)
            {
                return;
            }

            if (!((Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control && e.Key == Key.W))
            {
                vm.ClearAttachedPaneClosePrompt();
            }

            if ((Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control)
            {
                if (e.Key == Key.W)
                {
                    e.Handled = true;
                    vm.RequestCloseAttachedPane();
                    return;
                }

                if (e.Key == Key.Up)
                {
                    e.Handled = true;
                    vm.HistoryUp();
                    return;
                }

                if (e.Key == Key.Down)
                {
                    e.Handled = true;
                    vm.HistoryDown();
                    return;
                }
            }

            if ((Keyboard.Modifiers & ModifierKeys.Alt) == ModifierKeys.Alt && e.Key == Key.Left)
            {
                e.Handled = true;
                vm.NavigateBack();
                return;
            }

            if (e.Key == Key.Left && string.IsNullOrWhiteSpace(vm.CommandLine))
            {
                e.Handled = true;
                vm.NavigateBack();
                return;
            }

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
                return;
            }
        }

        private void OnCommandInputPreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (DataContext is not ShellViewModel vm)
            {
                return;
            }

            if (!((Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control && e.Key == Key.W))
            {
                vm.ClearAttachedPaneClosePrompt();
            }

            if ((Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control)
            {
                if (e.Key == Key.W)
                {
                    e.Handled = true;
                    vm.RequestCloseAttachedPane();
                    return;
                }

                if (e.Key == Key.Up)
                {
                    e.Handled = true;
                    vm.HistoryUp();
                    return;
                }

                if (e.Key == Key.Down)
                {
                    e.Handled = true;
                    vm.HistoryDown();
                    return;
                }
            }

            if ((Keyboard.Modifiers & ModifierKeys.Alt) == ModifierKeys.Alt && e.Key == Key.Left)
            {
                e.Handled = true;
                vm.NavigateBack();
                return;
            }

            if (e.Key == Key.Left && string.IsNullOrWhiteSpace(vm.CommandLine))
            {
                e.Handled = true;
                vm.NavigateBack();
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

            if (e.Key == Key.Right && string.IsNullOrWhiteSpace(vm.CommandLine))
            {
                e.Handled = true;
                vm.ToggleMenuDetails();
            }
        }

        private void OnMenuItemClick(object sender, MouseButtonEventArgs e)
        {
            if (DataContext is not ShellViewModel vm)
            {
                return;
            }

            if (sender is FrameworkElement element && element.DataContext is MenuEntryViewModel entry)
            {
                vm.SelectMenuEntry(entry, toggleDetails: true);
                e.Handled = true;
            }
        }
    }
}
