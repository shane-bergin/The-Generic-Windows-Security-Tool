using System;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Extensions.DependencyInjection;
using TGWST.Core.AppControl;
using TGWST.Core.Audit;
using TGWST.Core.Hardening;
using TGWST.Core.Network;
using TGWST.Core.Network.Hybrid;
using TGWST.Core.Policies;
using TGWST.Core.Recovery;
using TGWST.Core.Services;
using TGWST.Core.ServicesAnalysis;
using TGWST.Core.Junk;
using TGWST.Core.EventLog;
using TGWST.App.Shell;
using TGWST.App.Shell.Commands;
using TGWST.App.Services;
using TGWST.App.ViewModels;
using TGWST.App.Views;
using TGWST.App.Windows;
using Forms = System.Windows.Forms;

namespace TGWST.App
{
    public partial class App : System.Windows.Application
    {
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool DestroyIcon(IntPtr hIcon);

        public IServiceProvider ServiceProvider { get; private set; } = null!;
        private Forms.NotifyIcon? _trayIcon;
        private bool _trayHintShown;

        protected override void OnStartup(StartupEventArgs e)
        {
            try
            {
                StartupLogger.Initialize(BuildInfo.Current);
                StartupLogger.LogMilestone("OnStartup entered");
                RegisterGlobalExceptionHandlers();

                if (!IsAdministrator())
                {
                    StartupLogger.LogMilestone("Admin check failed");
                    MessageBox.Show(
                        "TGWST requires Administrator privileges and will now close.\n\nPlease relaunch using 'Run as administrator'.",
                        "Administrator Required",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);

                    Shutdown(-1);
                    return;
                }

                var serviceCollection = new ServiceCollection();
                ConfigureServices(serviceCollection);

                ServiceProvider = serviceCollection.BuildServiceProvider();
                StartupLogger.LogMilestone("Services built");
            }
            catch (Exception ex)
            {
                StartupLogger.LogException("startup preflight", ex);
                MessageBox.Show(
                    $"TGWST startup failed before GUI initialization.\n\n{ex.Message}\n\nStartup log:\n{StartupLogger.LogPath}",
                    "TGWST Startup Failure",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                Shutdown(-2);
                return;
            }

            try
            {
                // Resolve the Shell View and show it
                var shellView = ServiceProvider.GetRequiredService<ShellView>();
                MainWindow = shellView;
                shellView.StateChanged += OnMainWindowStateChanged;
                shellView.Closed += (_, _) => DisposeTrayIcon();
                shellView.Show();
                InitializeTrayIcon();
                StartupLogger.LogMilestone("Shell shown");
                _ = RunBootstrapPreflightAsync();
            }
            catch (Exception ex)
            {
                StartupLogger.LogException("shell startup", ex);
                MessageBox.Show(
                    $"TGWST failed to launch the GUI.\n\n{ex.Message}\n\nStartup log:\n{StartupLogger.LogPath}",
                    "TGWST Startup Failure",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                Shutdown(-2);
                return;
            }

            base.OnStartup(e);
        }

        private async Task RunBootstrapPreflightAsync()
        {
            try
            {
                StartupLogger.LogMilestone("Bootstrap preflight async start");
                var bootstrapProvisioning = ServiceProvider.GetRequiredService<BootstrapProvisioningService>();

                using var probeTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
                BootstrapStatus bootstrapStatus;
                try
                {
                    bootstrapStatus = await bootstrapProvisioning.ProbeAsync(probeTimeout.Token);
                }
                catch (OperationCanceledException)
                {
                    StartupLogger.LogMilestone("Bootstrap preflight timed out; skipped");
                    return;
                }
                catch (TimeoutException ex)
                {
                    StartupLogger.LogException("bootstrap preflight timeout", ex);
                    return;
                }

                StartupLogger.LogMilestone("Bootstrap preflight async complete");
                if (!bootstrapProvisioning.ShouldShowWizard(bootstrapStatus))
                {
                    return;
                }

                await Dispatcher.InvokeAsync(() =>
                {
                    if (MainWindow is not Window owner || !owner.IsLoaded)
                    {
                        return;
                    }

                    var wizard = new BootstrapWizardWindow(
                        bootstrapProvisioning,
                        ServiceProvider.GetRequiredService<WslCredentialService>())
                    {
                        Owner = owner
                    };
                    wizard.ShowDialog();
                }, DispatcherPriority.Background);
                StartupLogger.LogMilestone("Bootstrap wizard closed");
            }
            catch (Exception ex)
            {
                StartupLogger.LogException("bootstrap preflight async", ex);
            }
        }

        protected override void OnExit(ExitEventArgs e)
        {
            DisposeTrayIcon();
            base.OnExit(e);
        }

        private void InitializeTrayIcon()
        {
            if (_trayIcon != null)
            {
                return;
            }

            var menu = new Forms.ContextMenuStrip();
            menu.Items.Add("Open TGWST", null, (_, _) => Dispatcher.Invoke(RestoreMainWindow));
            menu.Items.Add("Open Network Board", null, (_, _) => Dispatcher.Invoke(OpenNetworkBoardFromTray));
            menu.Items.Add(new Forms.ToolStripSeparator());
            menu.Items.Add("Exit", null, (_, _) => Dispatcher.Invoke(Shutdown));

            _trayIcon = new Forms.NotifyIcon
            {
                Text = "The Generic Windows Security Tool",
                Visible = true,
                ContextMenuStrip = menu,
                Icon = LoadTrayIcon() ?? SystemIcons.Shield
            };
            _trayIcon.DoubleClick += (_, _) => Dispatcher.Invoke(RestoreMainWindow);
        }

        private void OnMainWindowStateChanged(object? sender, EventArgs e)
        {
            if (MainWindow is not Window window || window.WindowState != WindowState.Minimized)
            {
                return;
            }

            window.Hide();
            if (_trayIcon != null && !_trayHintShown)
            {
                _trayIcon.ShowBalloonTip(
                    1800,
                    "TGWST",
                    "Minimized to system tray. Double-click tray icon to restore.",
                    Forms.ToolTipIcon.Info);
                _trayHintShown = true;
            }
        }

        private void RestoreMainWindow()
        {
            if (MainWindow is not Window window)
            {
                return;
            }

            if (!window.IsVisible)
            {
                window.Show();
            }

            window.WindowState = WindowState.Normal;
            window.Activate();
        }

        private void OpenNetworkBoardFromTray()
        {
            RestoreMainWindow();
            if (MainWindow is ShellView shell)
            {
                shell.ShowNetworkOpsWindow();
            }
        }

        private static Icon? LoadTrayIcon()
        {
            try
            {
                var uri = new Uri("pack://application:,,,/Assets/generic_windows_security_tool_icon.png");
                var streamInfo = System.Windows.Application.GetResourceStream(uri);
                if (streamInfo?.Stream == null)
                {
                    return null;
                }

                using var bitmap = new Bitmap(streamInfo.Stream);
                var handle = bitmap.GetHicon();
                try
                {
                    using var icon = Icon.FromHandle(handle);
                    return (Icon)icon.Clone();
                }
                finally
                {
                    DestroyIcon(handle);
                }
            }
            catch
            {
                return null;
            }
        }

        private void DisposeTrayIcon()
        {
            if (_trayIcon == null)
            {
                return;
            }

            _trayIcon.Visible = false;
            _trayIcon.Dispose();
            _trayIcon = null;
        }

        private static bool IsAdministrator()
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private void RegisterGlobalExceptionHandlers()
        {
            DispatcherUnhandledException += OnDispatcherUnhandledException;
            AppDomain.CurrentDomain.UnhandledException += OnCurrentDomainUnhandledException;
            TaskScheduler.UnobservedTaskException += OnTaskSchedulerUnobservedTaskException;
        }

        private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            StartupLogger.LogException("dispatcher", e.Exception);
            MessageBox.Show(
                $"Unhandled UI exception:\n{e.Exception.Message}\n\nStartup log:\n{StartupLogger.LogPath}",
                "TGWST Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            e.Handled = true;
        }

        private static void OnCurrentDomainUnhandledException(object? sender, UnhandledExceptionEventArgs e)
        {
            if (e.ExceptionObject is Exception ex)
            {
                StartupLogger.LogException("appdomain", ex);
            }
            else
            {
                StartupLogger.LogMilestone("appdomain unhandled non-exception object");
            }
        }

        private static void OnTaskSchedulerUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
        {
            StartupLogger.LogException("task scheduler", e.Exception);
            e.SetObserved();
        }

        private void ConfigureServices(IServiceCollection services)
        {
            // 1. Register Core Native Services (Singletons = created once, reused)
            services.AddSingleton<NativeScanner>();
            // services.AddSingleton<LocalIntelligence>();
            services.AddSingleton<DeletedFileRecoveryEngine>();
            services.AddSingleton<ServiceAnalyzerEngine>();
            services.AddSingleton<JunkAnalyzerEngine>();
            services.AddSingleton<EventLogAnalyzer>();

            // 2. Register ViewModels
            services.AddTransient<ShellViewModel>();
            services.AddTransient<NetworkLiveViewModel>();
            services.AddTransient<MaintenanceOpsViewModel>();

            // 3. Register Shell Infrastructure
            services.AddSingleton<TaskOutputService>();
            services.AddSingleton<OperationCoordinatorService>();
            services.AddSingleton<InsightService>();
            services.AddSingleton<AuditLogService>();
            services.AddSingleton<PolicySnapshotStore>();
            services.AddSingleton<IWslHybridAnalyzer, WslHybridAnalyzer>();
            services.AddSingleton<HybridModeService>();
            services.AddSingleton<WslCredentialService>();
            services.AddSingleton<WslDnsResolver>();
            services.AddSingleton<PiHoleBridgeService>();
            services.AddSingleton<HardeningEngine>();
            services.AddSingleton<FirewallStatusService>();
            services.AddSingleton<WdacEngine>();
            services.AddSingleton<BootstrapProvisioningService>();
            services.AddSingleton<ICommandHandler, HelpCommand>();
            services.AddSingleton<ICommandHandler, ClearCommand>();
            services.AddSingleton<ICommandHandler, QuitCommand>();
            services.AddSingleton<ICommandHandler, WdacCommand>();
            services.AddSingleton<ICommandHandler, AsrCommand>();
            services.AddSingleton<ICommandHandler, DefenderScanCommand>();
            services.AddSingleton<ICommandHandler, NetworkCommand>();
            services.AddSingleton<ICommandHandler, TempCleanupCommand>();
            services.AddSingleton<ICommandHandler, MaintenanceCommand>();
            services.AddSingleton<CommandRegistry>();

            // 4. Register Views
            services.AddSingleton<ShellView>();
        }
    }
}
