using System;
using System.ComponentModel;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Extensions.DependencyInjection;
using TGWST.App.Services;
using TGWST.App.ViewModels;
using TGWST.App.Views;
using TGWST.Core.EventLog;
using TGWST.Core.Junk;
using TGWST.Core.Network;
using Forms = System.Windows.Forms;

namespace TGWST.App;

public partial class App : System.Windows.Application
{
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr hIcon);

    private ServiceProvider? _serviceProvider;
    private Forms.NotifyIcon? _trayIcon;
    private MainWindowViewModel? _mainViewModel;

    protected override void OnStartup(StartupEventArgs e)
    {
        StartupLogger.Initialize(BuildInfo.Current);
        RegisterGlobalExceptionHandlers();

        var services = new ServiceCollection();
        ConfigureServices(services);
        _serviceProvider = services.BuildServiceProvider();

        _mainViewModel = _serviceProvider.GetRequiredService<MainWindowViewModel>();
        _mainViewModel.ThreatLevelChanged += OnThreatLevelChanged;

        var window = _serviceProvider.GetRequiredService<MainWindow>();
        MainWindow = window;
        window.StateChanged += OnMainWindowStateChanged;
        window.Closed += (_, _) => Shutdown();
        InitializeTrayIcon(_mainViewModel.Dashboard.ThreatLevel);
        window.Show();

        if (!IsAdministrator())
        {
            _serviceProvider.GetRequiredService<GuiLogService>()
                .Warning("Privileges", "running without elevation; protected checks may report degraded status");
        }

        base.OnStartup(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        DisposeTrayIcon();
        if (_mainViewModel != null)
        {
            _mainViewModel.ThreatLevelChanged -= OnThreatLevelChanged;
        }

        _serviceProvider?.Dispose();
        base.OnExit(e);
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        services.AddSingleton<GuiLogService>();
        services.AddSingleton<FirewallStatusService>();
        services.AddSingleton<JunkAnalyzerEngine>();
        services.AddSingleton<EventLogAnalyzer>();
        services.AddSingleton<SecurityPostureService>();
        services.AddSingleton<NetworkTelemetryService>();
        services.AddSingleton<SystemTelemetryService>();
        services.AddSingleton<ToolExecutionService>();
        services.AddSingleton<NetworkDashboardViewModel>();
        services.AddSingleton<TelemetryDashboardViewModel>();
        services.AddSingleton<ToolsDashboardViewModel>();
        services.AddSingleton<LogsDashboardViewModel>();
        services.AddSingleton<MainWindowViewModel>();
        services.AddSingleton<MainWindow>();
    }

    private void InitializeTrayIcon(CyberThreatLevel threatLevel)
    {
        if (_trayIcon != null)
        {
            return;
        }

        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Open TGWST", null, (_, _) => Dispatcher.Invoke(RestoreMainWindow));
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => Dispatcher.Invoke(Shutdown));

        _trayIcon = new Forms.NotifyIcon
        {
            Text = BuildTrayText(threatLevel),
            Visible = true,
            ContextMenuStrip = menu,
            Icon = CreateStatusIcon(threatLevel)
        };
        _trayIcon.DoubleClick += (_, _) => Dispatcher.Invoke(RestoreMainWindow);
    }

    private void OnThreatLevelChanged(object? sender, CyberThreatLevel threatLevel)
    {
        if (_trayIcon == null)
        {
            return;
        }

        var oldIcon = _trayIcon.Icon;
        _trayIcon.Text = BuildTrayText(threatLevel);
        _trayIcon.Icon = CreateStatusIcon(threatLevel);
        oldIcon?.Dispose();
    }

    private void OnMainWindowStateChanged(object? sender, EventArgs e)
    {
        if (MainWindow?.WindowState == WindowState.Minimized)
        {
            MainWindow.Hide();
        }
    }

    private void RestoreMainWindow()
    {
        if (MainWindow == null)
        {
            return;
        }

        if (!MainWindow.IsVisible)
        {
            MainWindow.Show();
        }

        MainWindow.WindowState = WindowState.Normal;
        MainWindow.Activate();
    }

    private static string BuildTrayText(CyberThreatLevel threatLevel)
    {
        return $"TGWST :: {threatLevel.ToString().ToUpperInvariant()}";
    }

    private static Icon CreateStatusIcon(CyberThreatLevel threatLevel)
    {
        var color = threatLevel switch
        {
            CyberThreatLevel.Critical => Color.FromArgb(255, 59, 59),
            CyberThreatLevel.Elevated => Color.FromArgb(255, 159, 28),
            _ => Color.FromArgb(0, 212, 255)
        };

        using var bitmap = new Bitmap(32, 32);
        using (var graphics = Graphics.FromImage(bitmap))
        using (var borderPen = new Pen(Color.White, 2))
        using (var fillBrush = new SolidBrush(color))
        {
            graphics.Clear(Color.Black);
            graphics.FillEllipse(fillBrush, 5, 5, 22, 22);
            graphics.DrawEllipse(borderPen, 5, 5, 22, 22);
        }

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

    private void DisposeTrayIcon()
    {
        if (_trayIcon == null)
        {
            return;
        }

        _trayIcon.Visible = false;
        _trayIcon.Icon?.Dispose();
        _trayIcon.Dispose();
        _trayIcon = null;
    }

    private static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
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
        System.Windows.MessageBox.Show(
            "TGWST encountered a UI error. The local startup log has details.",
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
    }

    private static void OnTaskSchedulerUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        StartupLogger.LogException("task scheduler", e.Exception);
        e.SetObserved();
    }
}
