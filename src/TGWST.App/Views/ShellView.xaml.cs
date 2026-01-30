using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using TGWST.App.ViewModels;

namespace TGWST.App.Views
{
    public partial class ShellView : Window
    {
        private ScrollViewer? _outputScroll;
        private ScrollViewer? _attachedScroll;

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

            if (e.Key == Key.PageUp)
            {
                e.Handled = true;
                ScrollActivePane(pageDown: false, vm);
                return;
            }

            if (e.Key == Key.PageDown)
            {
                e.Handled = true;
                ScrollActivePane(pageDown: true, vm);
                return;
            }

            if (e.Key == Key.Home)
            {
                e.Handled = true;
                ScrollToEdge(toEnd: false, vm);
                return;
            }

            if (e.Key == Key.End)
            {
                e.Handled = true;
                ScrollToEdge(toEnd: true, vm);
                return;
            }

            if ((Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control)
            {
                if (e.Key == Key.P)
                {
                    e.Handled = true;
                    vm.ToggleAttachedPanePause();
                    return;
                }

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

            if (e.Key == Key.PageUp)
            {
                e.Handled = true;
                ScrollActivePane(pageDown: false, vm);
                return;
            }

            if (e.Key == Key.PageDown)
            {
                e.Handled = true;
                ScrollActivePane(pageDown: true, vm);
                return;
            }

            if (e.Key == Key.Home)
            {
                e.Handled = true;
                ScrollToEdge(toEnd: false, vm);
                return;
            }

            if (e.Key == Key.End)
            {
                e.Handled = true;
                ScrollToEdge(toEnd: true, vm);
                return;
            }

            if ((Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control)
            {
                if (e.Key == Key.P)
                {
                    e.Handled = true;
                    vm.ToggleAttachedPanePause();
                    return;
                }

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
    }
}
