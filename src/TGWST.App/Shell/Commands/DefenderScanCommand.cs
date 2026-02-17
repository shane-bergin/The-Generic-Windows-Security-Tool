using System;
using System.IO;
using System.Linq;
using System.Text;
using TGWST.App.Services;
using TGWST.App.ViewModels;
using TGWST.Core.Hardening;
using Microsoft.Win32;
using TGWST.App.Shell;

namespace TGWST.App.Shell.Commands
{
    public sealed class DefenderScanCommand : ICommandHandler
    {
        private readonly TaskOutputService _outputService;
        private readonly OperationCoordinatorService _operations;

        public DefenderScanCommand(TaskOutputService outputService, OperationCoordinatorService operations)
        {
            _outputService = outputService;
            _operations = operations;
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

                if (!_operations.TryAcquireHeavy($"Defender {scanArg}", out var lease, out var blockingOwner))
                {
                    vm.AddOutput($"[X] Busy: '{blockingOwner}'. Wait for the active heavy task to finish.\n");
                    return;
                }

                var session = _outputService.CreateSession($"Windows Defender - {scanArg}", vm.AcronymsExpanded);
                var progressVm = session.ViewModel;
                progressVm.Append($"Starting {scanArg}...\n");

                using (lease)
                {
                    try
                    {
                        var script = BuildDefenderScanScript(scanArg);
                        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
                        var exitCode = await ProcessRunner.RunAsync(
                            "powershell.exe",
                            $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}",
                            progressVm.Append,
                            session.Cancellation.Token);
                        progressVm.Append($"Exit code: {exitCode}\n");
                        progressVm.Status = exitCode == 0 ? "Completed" : "Failed";
                        progressVm.Append(exitCode == 0 ? "Scan completed.\n" : "Scan completed with errors.\n");
                    }
                    catch (OperationCanceledException)
                    {
                        progressVm.Status = "Canceled";
                        progressVm.Append("Scan canceled by user.\n");
                    }
                    catch (Exception ex)
                    {
                        progressVm.Status = "Failed";
                        progressVm.Append($"[error] {ex.Message}\n");
                    }
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

        private static string BuildDefenderScanScript(string scanArg)
        {
            var maxMinutes = string.Equals(scanArg, "FullScan", StringComparison.OrdinalIgnoreCase) ? 240 : 40;
            var statusField = string.Equals(scanArg, "FullScan", StringComparison.OrdinalIgnoreCase)
                ? "FullScanEndTime"
                : "QuickScanEndTime";

            var template = """
$scanType = '__SCAN_TYPE__'
$maxMinutes = __MAX_MINUTES__
$pollSeconds = 5
$statusField = '__STATUS_FIELD__'

$baseline = $null
try {
    $baseline = (Get-MpComputerStatus).$statusField
}
catch {
    # keep null baseline
}

Write-Output ('Starting Defender scan: ' + $scanType)
try {
    Start-MpScan -ScanType $scanType -ErrorAction Stop
    Write-Output 'Defender accepted the scan request.'
}
catch {
    Write-Output ('Scan launch failed: ' + $_.Exception.Message)
    exit 1
}

$deadline = (Get-Date).AddMinutes($maxMinutes)
$completed = $false
while ((Get-Date) -lt $deadline) {
    $status = Get-MpComputerStatus | Select-Object AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,QuickScanEndTime,FullScanEndTime
    $endRaw = $status.$statusField
    $endValue = [string]$endRaw

    if ([string]::IsNullOrWhiteSpace($endValue)) {
        Write-Output 'status: pending'
    }
    else {
        Write-Output ('status: ' + $endValue)
    }

    if (-not [string]::IsNullOrWhiteSpace($endValue)) {
        if ($null -eq $baseline) {
            $completed = $true
            break
        }

        try {
            if ([datetime]$endRaw -gt [datetime]$baseline) {
                $completed = $true
                break
            }
        }
        catch {
            $completed = $true
            break
        }
    }

    Start-Sleep -Seconds $pollSeconds
}

if (-not $completed) {
    Write-Output ('Scan still running after timeout of ' + $maxMinutes + ' minutes.')
}

Get-MpComputerStatus |
    Select-Object AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,QuickScanEndTime,FullScanEndTime |
    Format-List
""";

            return template
                .Replace("__SCAN_TYPE__", scanArg, StringComparison.Ordinal)
                .Replace("__MAX_MINUTES__", maxMinutes.ToString(), StringComparison.Ordinal)
                .Replace("__STATUS_FIELD__", statusField, StringComparison.Ordinal);
        }
    }
}
