using System;
using System.IO;
using System.Linq;
using TGWST.App.ViewModels;
using TGWST.Core.Hardening;
using Microsoft.Win32;
using TGWST.App.Shell;

namespace TGWST.App.Shell.Commands
{
    public sealed class DefenderScanCommand : ICommandHandler
    {
        private readonly TaskOutputService _outputService;

        public DefenderScanCommand(TaskOutputService outputService)
        {
            _outputService = outputService;
        }

        public string Name => "scan";
        public string[] Aliases => Array.Empty<string>();

        public async Task ExecuteAsync(string args, ShellViewModel vm)
        {
            var sub = (args ?? string.Empty).Trim();
            var tokens = sub.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length == 0)
            {
                vm.AddOutput("Usage: scan defender <quick|full> | scan sdk sigcheck <path>\n");
                return;
            }

            if (tokens[0].Equals("defender", StringComparison.OrdinalIgnoreCase))
            {
                if (tokens.Length < 2)
                {
                    vm.AddOutput("Usage: scan defender <quick|full>\n");
                    return;
                }

                var mode = tokens[1].Trim().ToLowerInvariant();
                var scanArg = mode switch
                {
                    "quick" => "QuickScan",
                    "full" => "FullScan",
                    _ => string.Empty
                };

                if (string.IsNullOrEmpty(scanArg))
                {
                    vm.AddOutput("Usage: scan defender <quick|full>\n");
                    return;
                }

                var progressVm = _outputService.CreateAndShow($"Windows Defender - {scanArg}", vm.AcronymsExpanded);
                progressVm.Append($"Starting {scanArg}...\n");

                try
                {
                    var script = $"Start-MpScan -ScanType {scanArg}; Get-MpComputerStatus | Select-Object AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,QuickScanEndTime,FullScanEndTime | Format-List";
                    var exitCode = await ProcessRunner.RunAsync(
                        "powershell.exe",
                        $"-NoProfile -ExecutionPolicy Bypass -Command \"{script}\"",
                        progressVm.Append);
                    progressVm.Append($"Exit code: {exitCode}\n");
                    progressVm.Status = exitCode == 0 ? "Completed" : "Failed";
                    progressVm.Append(exitCode == 0 ? "Scan completed.\n" : "Scan completed with errors.\n");
                }
                catch (Exception ex)
                {
                    progressVm.Status = "Failed";
                    progressVm.Append($"[error] {ex.Message}\n");
                }

                return;
            }

            if (tokens[0].Equals("sdk", StringComparison.OrdinalIgnoreCase))
            {
                if (tokens.Length < 2 || !tokens[1].Equals("sigcheck", StringComparison.OrdinalIgnoreCase))
                {
                    vm.AddOutput("Usage: scan sdk sigcheck <path>\n");
                    return;
                }

                var target = tokens.Length > 2 ? string.Join(' ', tokens.Skip(2)) : string.Empty;
                if (string.IsNullOrWhiteSpace(target))
                {
                    var dialog = new OpenFileDialog
                    {
                        Filter = "Executable files (*.exe;*.dll;*.sys)|*.exe;*.dll;*.sys|All files (*.*)|*.*",
                        Multiselect = false,
                        CheckFileExists = true
                    };

                    if (dialog.ShowDialog() == true)
                    {
                        target = dialog.FileName;
                    }
                }

                if (string.IsNullOrWhiteSpace(target))
                {
                    vm.AddOutput("Usage: scan sdk sigcheck <path>\n");
                    return;
                }

                var progressVm = _outputService.CreateAndShow("Windows SDK Signature Check", vm.AcronymsExpanded);
                progressVm.Append($"Target: {target}\n");

                var files = ResolveTargets(target);
                if (files.Length == 0)
                {
                    progressVm.Status = "No targets found";
                    progressVm.Append("[error] No .exe/.dll/.sys targets found.\n");
                    return;
                }

                var signtool = FindSigntool();
                progressVm.Append(signtool == null
                    ? "Signtool not found; using Get-AuthenticodeSignature.\n"
                    : $"Using signtool: {signtool}\n");

                foreach (var file in files)
                {
                    progressVm.Append($"\n==> {file}\n");
                    try
                    {
                        if (signtool != null)
                        {
                            await ProcessRunner.RunAsync(signtool, $"verify /pa /v \"{file}\"", line => progressVm.Append(line));
                        }
                        else
                        {
                            var script = $"Get-AuthenticodeSignature -FilePath '{file}' | Format-List";
                            var progress = new Progress<string>(msg => progressVm.Append(msg + "\n"));
                            await HardeningEngine.RunPowerShellAsync(script, progress);
                        }
                    }
                    catch (Exception ex)
                    {
                        progressVm.Append($"[error] {ex.Message}\n");
                    }
                }

                progressVm.Status = "Completed";
                return;
            }

            vm.AddOutput("Usage: scan defender <quick|full> | scan sdk sigcheck <path>\n");
        }

        private static string[] ResolveTargets(string target)
        {
            if (File.Exists(target))
            {
                return new[] { Path.GetFullPath(target) };
            }

            if (Directory.Exists(target))
            {
                return Directory.EnumerateFiles(target, "*.*", SearchOption.TopDirectoryOnly)
                    .Where(p =>
                    {
                        var ext = Path.GetExtension(p);
                        return ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)
                               || ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
                               || ext.Equals(".sys", StringComparison.OrdinalIgnoreCase);
                    })
                    .Select(Path.GetFullPath)
                    .ToArray();
            }

            return Array.Empty<string>();
        }

        private static string? FindSigntool()
        {
            var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            if (string.IsNullOrWhiteSpace(pf86))
            {
                return null;
            }

            var roots = new[]
            {
                Path.Combine(pf86, "Windows Kits", "10", "bin"),
                Path.Combine(pf86, "Windows Kits", "8.1", "bin")
            };

            var candidates = roots
                .Where(Directory.Exists)
                .SelectMany(r => Directory.EnumerateFiles(r, "signtool.exe", SearchOption.AllDirectories))
                .Select(p => new { Path = p, Version = TryParseVersion(p), IsX64 = p.Contains("x64", StringComparison.OrdinalIgnoreCase) })
                .OrderByDescending(c => c.IsX64)
                .ThenByDescending(c => c.Version)
                .ToList();

            return candidates.FirstOrDefault()?.Path;
        }

        private static Version? TryParseVersion(string path)
        {
            var segments = path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            foreach (var segment in segments)
            {
                if (Version.TryParse(segment, out var version))
                {
                    return version;
                }
            }

            return null;
        }
    }
}
