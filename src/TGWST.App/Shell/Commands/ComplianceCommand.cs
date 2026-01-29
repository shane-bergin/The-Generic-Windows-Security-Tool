using System;
using System.IO;
using System.Linq;
using TGWST.App.Services;
using TGWST.App.ViewModels;
using TGWST.App.Shell;
using TGWST.Core.Compliance;

namespace TGWST.App.Shell.Commands
{
    public sealed class ComplianceCommand : ICommandHandler
    {
        private readonly TaskOutputService _outputService;
        private readonly BaselineComplianceEngine _engine = new();

        public ComplianceCommand(TaskOutputService outputService)
        {
            _outputService = outputService;
        }

        public string Name => "compliance";
        public string[] Aliases => Array.Empty<string>();

        public Task ExecuteAsync(string args, ShellViewModel vm)
        {
            var sub = (args ?? string.Empty).Trim();
            if (sub.Equals("snapshot", StringComparison.OrdinalIgnoreCase))
            {
                return RunSnapshotAsync(vm, null);
            }

            if (sub.StartsWith("snapshot ", StringComparison.OrdinalIgnoreCase))
            {
                var path = sub.Substring("snapshot".Length).Trim().Trim('"');
                return RunSnapshotAsync(vm, path);
            }

            vm.AddOutput("Usage: compliance snapshot\n");
            return Task.CompletedTask;
        }

        private async Task RunSnapshotAsync(ShellViewModel vm, string? baselinePath)
        {
            var progressVm = _outputService.CreateAndShow("Compliance Snapshot", vm.AcronymsExpanded);

            try
            {
                var resolved = ResolveBaseline(baselinePath);
                if (resolved == null)
                {
                    progressVm.Status = "No baseline found";
                    progressVm.Append("[error] No compliance baseline found. Import one first.\n");
                    return;
                }

                progressVm.Append($"Baseline: {resolved}\n");
                var results = await Task.Run(() => _engine.Evaluate(resolved));
                var compliant = results.Count(r => r.Compliant);
                progressVm.Append($"Compliant {compliant}/{results.Count}\n");

                var nonCompliant = results.Where(r => !r.Compliant).ToList();
                if (nonCompliant.Count == 0)
                {
                    progressVm.Append("All baseline checks are compliant.\n");
                }
                else
                {
                    progressVm.Append("\nNon-compliant items (top 50):\n");
                    foreach (var item in nonCompliant.Take(50))
                    {
                        var exp = item.Item;
                        var expected = item.Item.Value ?? "null";
                        var current = item.CurrentValue ?? "null";
                        progressVm.Append($"{exp.Hive}\\{exp.Path} :: {exp.Name} expected={expected} current={current}\n");
                    }

                    if (nonCompliant.Count > 50)
                    {
                        progressVm.Append($"... and {nonCompliant.Count - 50} more.\n");
                    }
                }

                progressVm.Status = "Completed";
            }
            catch (Exception ex)
            {
                progressVm.Status = "Failed";
                progressVm.Append($"[error] {ex.Message}\n");
            }
        }

        private static string? ResolveBaseline(string? baselinePath)
        {
            if (!string.IsNullOrWhiteSpace(baselinePath) && File.Exists(baselinePath))
            {
                return baselinePath;
            }

            var selected = BaselineSelectionService.Selected;
            if (selected != null && File.Exists(selected.FullPath))
            {
                return selected.FullPath;
            }

            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "TGWST", "Baselines");
            if (!Directory.Exists(dir))
            {
                return null;
            }

            var file = Directory.EnumerateFiles(dir, "*.json", SearchOption.TopDirectoryOnly)
                .Concat(Directory.EnumerateFiles(dir, "*.csv", SearchOption.TopDirectoryOnly))
                .FirstOrDefault();

            return file;
        }
    }
}
