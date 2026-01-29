using System;
using System.Linq;
using System.Threading;
using TGWST.App.ViewModels;
using TGWST.App.Shell;
using TGWST.Core.Uninstall;
using TGWST.Core.Audit;

namespace TGWST.App.Shell.Commands
{
    public sealed class UninstallCommand : ICommandHandler
    {
        private readonly TaskOutputService _outputService;
        private readonly UninstallEngine _engine = new();
        private readonly AuditLogService _audit;

        public UninstallCommand(TaskOutputService outputService, AuditLogService audit)
        {
            _outputService = outputService;
            _audit = audit;
        }

        public string Name => "uninstall";
        public string[] Aliases => Array.Empty<string>();

        public Task ExecuteAsync(string args, ShellViewModel vm)
        {
            var sub = (args ?? string.Empty).Trim();
            if (sub.StartsWith("remnants", StringComparison.OrdinalIgnoreCase))
            {
                return RunUninstallAsync(vm, sub);
            }

            vm.AddOutput("Usage: uninstall remnants\n");
            return Task.CompletedTask;
        }

        private async Task RunUninstallAsync(ShellViewModel vm, string sub)
        {
            var tokens = sub.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var remove = tokens.Any(t => t.Equals("--remove", StringComparison.OrdinalIgnoreCase) || t.Equals("-r", StringComparison.OrdinalIgnoreCase));
            var queryTokens = tokens.Skip(1).Where(t => !t.StartsWith("-", StringComparison.OrdinalIgnoreCase)).ToArray();
            var query = string.Join(' ', queryTokens).Trim();

            var apps = _engine.ListInstalled().ToList();
            if (apps.Count == 0)
            {
                vm.AddOutput("[error] No installed apps detected.\n");
                return;
            }

            if (string.IsNullOrWhiteSpace(query))
            {
                var progressVm = _outputService.CreateAndShow("Installed Apps", vm.AcronymsExpanded);
                progressVm.Append("Select an app by number:\n");
                for (var i = 0; i < Math.Min(50, apps.Count); i++)
                {
                    var app = apps[i];
                    progressVm.Append($"{i + 1}. {app.DisplayName} ({app.Publisher})\n");
                }
                if (apps.Count > 50)
                {
                    progressVm.Append($"... and {apps.Count - 50} more.\n");
                }
                progressVm.Append("\nRun: uninstall remnants <number|name> [--remove]\n");
                progressVm.Status = "Awaiting selection";
                return;
            }

            InstalledApp? selected = null;
            if (int.TryParse(query, out var index))
            {
                if (index >= 1 && index <= apps.Count)
                {
                    selected = apps[index - 1];
                }
            }
            else
            {
                selected = apps.FirstOrDefault(a => a.DisplayName.Equals(query, StringComparison.OrdinalIgnoreCase))
                           ?? apps.FirstOrDefault(a => a.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase));
            }

            if (selected == null)
            {
                var progressVm = _outputService.CreateAndShow("Uninstall + Remnants", vm.AcronymsExpanded);
                progressVm.Append($"No match found for: {query}\n");
                var matches = apps.Where(a => a.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase)).Take(20).ToList();
                if (matches.Count > 0)
                {
                    progressVm.Append("Closest matches:\n");
                    for (var i = 0; i < matches.Count; i++)
                    {
                        var app = matches[i];
                        progressVm.Append($"{i + 1}. {app.DisplayName} ({app.Publisher})\n");
                    }
                }
                progressVm.Status = "No match";
                return;
            }

            var progress = _outputService.CreateAndShow($"Uninstall + Remnants - {selected.DisplayName}", vm.AcronymsExpanded);
            try
            {
                var correlationId = Guid.NewGuid().ToString("N");
                progress.Append($"Running uninstaller: {selected.DisplayName}\n");
                await _engine.RunUninstallerAsync(selected);
                _audit.Write("Uninstall.Run", $"app={selected.DisplayName}", correlationId, privileged: true);
                progress.Append("Scanning for leftovers...\n");

                var leftovers = (await _engine.FindLeftoversAsync(selected)).ToList();
                if (leftovers.Count == 0)
                {
                    progress.Append("No leftovers detected.\n");
                    progress.Status = "Completed";
                    return;
                }

                progress.Append($"Found {leftovers.Count} potential leftovers:\n");
                foreach (var item in leftovers)
                {
                    progress.Append($"- {item.Path} ({item.SizeDisplay})\n");
                }

                if (remove)
                {
                    foreach (var item in leftovers)
                    {
                        item.Selected = true;
                    }
                    progress.Append("Removing leftovers...\n");
                    await _engine.RemoveLeftoversAsync(leftovers, CancellationToken.None);
                    _audit.Write("Uninstall.RemoveLeftovers", $"app={selected.DisplayName} count={leftovers.Count}", correlationId, privileged: true);
                    progress.Append("Leftover removal complete.\n");
                }
                else
                {
                    progress.Append("\nRun again with --remove to delete these items.\n");
                }

                progress.Status = "Completed";
            }
            catch (Exception ex)
            {
                progress.Status = "Failed";
                progress.Append($"[error] {ex.Message}\n");
            }
        }
    }
}
