using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Windows;
using System.Windows.Forms;

namespace TGWST.App;

public partial class MainWindow : Window
{
    private NotifyIcon? _trayIcon;

    public MainWindow()
    {
        InitializeComponent();
        SetupTrayIcon();
    }

    private void SetupTrayIcon()
    {
        var icon = LoadAppIcon();
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open", null, (_, _) => ShowFromTray());
        menu.Items.Add("Exit", null, (_, _) => Close());

        _trayIcon = new NotifyIcon
        {
            Icon = icon,
            Text = "The Generic Windows Security Tool",
            Visible = true,
            ContextMenuStrip = menu
        };
        _trayIcon.DoubleClick += (_, _) => ShowFromTray();
    }

    private static System.Drawing.Icon LoadAppIcon()
    {
        try
        {
            var path = Process.GetCurrentProcess().MainModule?.FileName;
            var icon = !string.IsNullOrWhiteSpace(path)
                ? System.Drawing.Icon.ExtractAssociatedIcon(path)
                : null;
            return icon ?? System.Drawing.SystemIcons.Application;
        }
        catch
        {
            return System.Drawing.SystemIcons.Application;
        }
    }

    private void ShowFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    protected override void OnStateChanged(EventArgs e)
    {
        base.OnStateChanged(e);
        if (WindowState == WindowState.Minimized)
        {
            Hide();
        }
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        _trayIcon?.Dispose();
        base.OnClosing(e);
    }
}
