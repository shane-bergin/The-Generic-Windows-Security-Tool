using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Security.Principal;
using System.Text.Json;
using System.Collections.Generic;
using System.Drawing;
using Forms = System.Windows.Forms;
using System.Windows;
using MessageBox = System.Windows.MessageBox;

namespace TGWST.App;

public partial class App : System.Windows.Application
{
    private Forms.NotifyIcon? _trayIcon;
    private Icon? _trayIconHandle;
    private const string AsrExecutableBlockGuid = "d4f940ab-401b-4efc-aadc-ad5f3c50688a";

    protected override void OnStartup(StartupEventArgs e)
    {
        WarnIfAsrLikelyBlocking();

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

        InitTrayIcon();
        base.OnStartup(e);
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private void WarnIfAsrLikelyBlocking()
    {
        try
        {
            var json = GetMpPreferenceJson();
            if (string.IsNullOrWhiteSpace(json)) return;

            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("AttackSurfaceReductionRules_Ids", out var idsElem) ||
                !doc.RootElement.TryGetProperty("AttackSurfaceReductionRules_Actions", out var actionsElem) ||
                idsElem.ValueKind != JsonValueKind.Array ||
                actionsElem.ValueKind != JsonValueKind.Array)
                return;

            var pairs = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var len = Math.Min(idsElem.GetArrayLength(), actionsElem.GetArrayLength());
            for (var i = 0; i < len; i++)
            {
                var id = idsElem[i].GetString();
                var action = actionsElem[i].GetInt32();
                if (!string.IsNullOrWhiteSpace(id))
                    pairs[id] = action;
            }

            if (pairs.TryGetValue(AsrExecutableBlockGuid, out var val) && val == 1)
            {
                MessageBox.Show(
                    "Windows Defender ASR rule \"Block executable content from email and webmail clients\" is set to Block. Unsigned builds of TGWST may be prevented from running.\n\nRecommendation: run a signed build from Program Files or set the rule to Audit while testing.",
                    "ASR may block TGWST",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
        }
        catch
        {
            // best effort only
        }
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
        catch
        {
            // best-effort tray icon
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (_trayIcon != null)
        {
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
        }
        _trayIconHandle?.Dispose();
        base.OnExit(e);
    }
}
