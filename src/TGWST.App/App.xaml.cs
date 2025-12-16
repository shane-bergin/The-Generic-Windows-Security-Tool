using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Security.Principal;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using Forms = System.Windows.Forms;
using MessageBox = System.Windows.MessageBox;

namespace TGWST.App;

public partial class App : System.Windows.Application
{
    private Forms.NotifyIcon? _trayIcon;
    private Icon? _trayIconHandle;
    private SplashWindow? _splashWindow;
    private const string AsrExecutableBlockGuid = "d4f940ab-401b-4efc-aadc-ad5f3c50688a";
    private int _adminPromptShown;
    private int _asrPromptShown;
    private int _fatalUiNotified;
    private string[] _startupArgs = Array.Empty<string>();

    protected override void OnStartup(StartupEventArgs e)
    {
        _startupArgs = e.Args ?? Array.Empty<string>();
        StartupLogger.Initialize(BuildInfo.Current);
        HookExceptionHandlers();
        StartupLogger.LogMilestone("App start");

        _splashWindow = new SplashWindow();
        _splashWindow.Show();
        StartupLogger.LogMilestone("Splash shown");

        StartupLogger.LogMilestone("DI init start");
        StartupLogger.LogMilestone("DI init complete");

        try
        {
            MainWindow = new MainWindow();
            StartupLogger.LogMilestone("MainWindow created");

            MainWindow.ContentRendered += (_, _) =>
            {
                StartupLogger.LogMilestone("MainWindow shown");
                CloseSplash();
            };

            base.OnStartup(e);

            MainWindow.Show();
            MainWindow.Activate();
            StartupLogger.LogMilestone("MainWindow show invoked");

            InitTrayIcon();
            _ = Dispatcher.InvokeAsync(RunPostShowInitAsync, DispatcherPriority.Background);
        }
        catch (Exception ex)
        {
            StartupLogger.LogException("OnStartup", ex);
            CloseSplash();
            TryShowFatal("Failed to start TGWST", ex);
            Shutdown(-1);
        }
    }

    private void HookExceptionHandlers()
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        StartupLogger.LogException("DispatcherUnhandledException", e.Exception);
        if (Interlocked.Exchange(ref _fatalUiNotified, 1) == 0)
            TryShowFatal("An unexpected error occurred", e.Exception);

        e.Handled = true;
        Shutdown(-1);
    }

    private void OnUnhandledException(object? sender, UnhandledExceptionEventArgs e)
    {
        var ex = e.ExceptionObject as Exception ?? new Exception(e.ExceptionObject?.ToString() ?? "Unknown fatal error");
        StartupLogger.LogException("AppDomain.UnhandledException", ex);
        if (Interlocked.Exchange(ref _fatalUiNotified, 1) == 0)
            TryShowFatal("A fatal error occurred", ex);
    }

    private async Task RunPostShowInitAsync()
    {
        StartupLogger.LogMilestone("Post-show async init started");
        try
        {
            await Task.Yield();

            if (await MaybePromptForElevationAsync()) return;

            var asrWarning = await Task.Run(TryGetAsrWarningMessage);
            if (!string.IsNullOrWhiteSpace(asrWarning) && Interlocked.Exchange(ref _asrPromptShown, 1) == 0)
            {
                await Dispatcher.InvokeAsync(() =>
                    MessageBox.Show(asrWarning, "ASR may block TGWST", MessageBoxButton.OK, MessageBoxImage.Warning),
                    DispatcherPriority.Background);
            }
        }
        catch (Exception ex)
        {
            StartupLogger.LogException("Post-show init", ex);
            await Dispatcher.InvokeAsync(() =>
                MessageBox.Show(
                    $"Startup initialization failed: {ex.Message}\nSee {StartupLogger.LogPath}",
                    "Startup error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error));
        }
        finally
        {
            StartupLogger.LogMilestone("Post-show async init finished");
        }
    }

    private async Task<bool> MaybePromptForElevationAsync()
    {
        if (IsAdministrator() || Interlocked.Exchange(ref _adminPromptShown, 1) != 0)
            return false;

        const string title = "Administrator Required";
        const string message = "Administrator rights are required for hardening and ASR features. Click OK to relaunch with elevated permissions, or Cancel to continue in limited mode.";

        var result = await Dispatcher.InvokeAsync(() =>
            MessageBox.Show(message, title, MessageBoxButton.OKCancel, MessageBoxImage.Exclamation));

        if (result != MessageBoxResult.OK) return false;

        var relaunched = await Task.Run(() => TryLaunchElevated(_startupArgs));
        if (relaunched)
        {
            StartupLogger.LogMilestone("Elevation requested; shutting down current instance");
            Shutdown();
            return true;
        }

        await Dispatcher.InvokeAsync(() =>
        {
            MessageBox.Show(
                "Failed to relaunch elevated. Continuing without admin rights.",
                title,
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        });

        return false;
    }

    private bool TryLaunchElevated(IEnumerable<string> args)
    {
        try
        {
            var exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(exePath)) return false;

            var psi = new ProcessStartInfo(exePath)
            {
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = AppContext.BaseDirectory,
                Arguments = string.Join(" ", args.Select(a => $"\"{a}\""))
            };

            var started = Process.Start(psi);
            return started != null;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            StartupLogger.LogMilestone("Elevation cancelled by user");
            return false;
        }
        catch (Exception ex)
        {
            StartupLogger.LogException("Elevation", ex);
            return false;
        }
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private string? TryGetAsrWarningMessage()
    {
        try
        {
            var json = GetMpPreferenceJson();
            if (string.IsNullOrWhiteSpace(json)) return null;

            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("AttackSurfaceReductionRules_Ids", out var idsElem) ||
                !doc.RootElement.TryGetProperty("AttackSurfaceReductionRules_Actions", out var actionsElem) ||
                idsElem.ValueKind != JsonValueKind.Array ||
                actionsElem.ValueKind != JsonValueKind.Array)
                return null;

            var len = Math.Min(idsElem.GetArrayLength(), actionsElem.GetArrayLength());
            for (var i = 0; i < len; i++)
            {
                var id = idsElem[i].GetString();
                var action = actionsElem[i].GetInt32();
                if (!string.IsNullOrWhiteSpace(id) &&
                    string.Equals(id, AsrExecutableBlockGuid, StringComparison.OrdinalIgnoreCase) &&
                    action == 1)
                {
                    return "Windows Defender ASR rule \"Block executable content from email and webmail clients\" is set to Block. Unsigned builds of TGWST may be prevented from running.\n\nRecommendation: run a signed build from Program Files or set the rule to Audit while testing.";
                }
            }
        }
        catch (Exception ex)
        {
            StartupLogger.LogException("ASR detection", ex);
        }

        return null;
    }

    private static string GetMpPreferenceJson()
    {
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", "-NoLogo -NoProfile -Command \"Get-MpPreference | ConvertTo-Json -Depth 4\"")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return "";
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(3000);
            return output;
        }
        catch
        {
            return "";
        }
    }

    private void InitTrayIcon()
    {
        try
        {
            var iconPath = System.IO.Path.Combine(AppContext.BaseDirectory, "Assets", "TGWST.png");
            if (!System.IO.File.Exists(iconPath)) return;

            using var bmp = new Bitmap(iconPath);
            _trayIconHandle = Icon.FromHandle(bmp.GetHicon());
            _trayIcon = new Forms.NotifyIcon
            {
                Icon = _trayIconHandle,
                Visible = true,
                Text = "TGWST"
            };

            _trayIcon.Click += (_, _) =>
            {
                Current.MainWindow?.Show();
                Current.MainWindow?.Activate();
            };

            var menu = new Forms.ContextMenuStrip();
            menu.Items.Add("Open", null, (_, _) =>
            {
                Current.MainWindow?.Show();
                Current.MainWindow?.Activate();
            });
            menu.Items.Add("Exit", null, (_, _) => Current.Shutdown());
            _trayIcon.ContextMenuStrip = menu;
        }
        catch (Exception ex)
        {
            StartupLogger.LogException("Tray init", ex);
        }
    }

    private void CloseSplash()
    {
        if (_splashWindow != null)
        {
            try { _splashWindow.Close(); }
            catch { /* ignore */ }
            _splashWindow = null;
        }
    }

    private void TryShowFatal(string title, Exception ex)
    {
        try
        {
            var message = $"{title}: {ex.Message}\nSee {StartupLogger.LogPath} for details.";
            if (Dispatcher.CheckAccess())
            {
                MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Error);
            }
            else
            {
                Dispatcher.Invoke(() => MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Error));
            }
        }
        catch
        {
            // do not throw from error handler
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        CloseSplash();
        if (_trayIcon != null)
        {
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
        }
        _trayIconHandle?.Dispose();
        base.OnExit(e);
    }
}
