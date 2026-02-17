using System;
using System.Windows;
using TGWST.App.ViewModels;
using TGWST.App.Views;

namespace TGWST.App.Shell.Commands
{
    public sealed class MaintenanceCommand : ICommandHandler
    {
        public string Name => "maintenance";
        public string[] Aliases => new[] { "maint" };

        public Task ExecuteAsync(string args, ShellViewModel vm)
        {
            var sub = (args ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(sub) ||
                string.Equals(sub, "open", StringComparison.OrdinalIgnoreCase))
            {
                var dispatcher = Application.Current?.Dispatcher;
                if (dispatcher == null)
                {
                    vm.AddOutput("[X] UI dispatcher unavailable. Unable to open maintenance window.\n");
                    return Task.CompletedTask;
                }

                dispatcher.Invoke(() =>
                {
                    if (Application.Current?.MainWindow is ShellView shell)
                    {
                        shell.ShowMaintenanceOpsWindow();
                        vm.AddOutput("[i] Opened Maintenance Operations window.\n");
                    }
                    else
                    {
                        vm.AddOutput("[X] Shell window was not available.\n");
                    }
                });

                return Task.CompletedTask;
            }

            vm.AddOutput("Usage: maintenance [open]\n");
            return Task.CompletedTask;
        }
    }
}
