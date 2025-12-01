using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Security.Principal;
using System.Windows;
using MessageBox = System.Windows.MessageBox;

namespace TGWST.App;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        if (!IsAdministrator())
        {
            const string title = "Administrator Required";
            const string message = "Administrator rights are required for hardening and ASR features. Click OK to relaunch with elevated permissions, or Cancel to continue in limited mode.";

            var result = MessageBox.Show(message, title, MessageBoxButton.OKCancel, MessageBoxImage.Exclamation);
            if (result == MessageBoxResult.OK)
            {
                try
                {
                    var exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName;
                    if (!string.IsNullOrWhiteSpace(exePath))
                    {
                        var psi = new ProcessStartInfo(exePath)
                        {
                            UseShellExecute = true,
                            Verb = "runas",
                            WorkingDirectory = AppContext.BaseDirectory,
                            Arguments = string.Join(" ", e.Args.Select(a => $"\"{a}\""))
                        };
                        var started = Process.Start(psi);
                        if (started != null)
                        {
                            Shutdown();
                            return;
                        }
                    }
                }
                catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
                {
                    MessageBox.Show("Elevation was cancelled; continuing without admin rights. Some features may fail.", title, MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to relaunch elevated: {ex.Message}\nContinuing without admin rights.", title, MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            // If user chose Cancel or elevation failed, continue in limited mode (UI loads, admin-required features may fail).
        }

        base.OnStartup(e);
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}
