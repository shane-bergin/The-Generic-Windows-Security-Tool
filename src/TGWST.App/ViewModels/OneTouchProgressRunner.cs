using System;
using System.Threading.Tasks;
using System.Windows;
using TGWST.App.Views;

namespace TGWST.App.ViewModels;

public static class OneTouchProgressRunner
{
    public static async Task<string> RunAsync(string actionName, Func<Task<string>> run)
    {
        var progress = new OneTouchProgressViewModel(actionName, BuildSteps(actionName));
        var window = new OneTouchProgressWindow(progress);
        var owner = System.Windows.Application.Current?.MainWindow;
        if (owner != null && owner.IsVisible)
        {
            window.Owner = owner;
        }

        window.Show();
        window.Activate();

        try
        {
            progress.MarkCurrent(0, 0, "preparing the requested operation");
            var work = run();
            progress.MarkCurrent(1, 0, "waiting for the operation to return an actual result");
            var result = await work;
            progress.MarkCurrent(2, 100, "recording the returned result");
            progress.MarkComplete(result);
            return result;
        }
        catch (Exception ex)
        {
            var detail = $"{actionName} failed: {Trim(ex.Message)}";
            progress.MarkFailed(detail);
            throw;
        }
    }

    private static IReadOnlyList<string> BuildSteps(string actionName)
    {
        return
        [
            "prepare request",
            "wait for operation result",
            "record returned result"
        ];
    }

    private static string Trim(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return "no detail";
        }

        return message.Length <= 180 ? message : message[..180];
    }
}
