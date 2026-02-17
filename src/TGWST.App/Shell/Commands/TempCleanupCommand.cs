using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using TGWST.App.Services;
using TGWST.App.Shell;
using TGWST.App.ViewModels;

namespace TGWST.App.Shell.Commands
{
    public sealed class TempCleanupCommand : ICommandHandler
    {
        private readonly TaskOutputService _output;
        private readonly OperationCoordinatorService _operations;

        public TempCleanupCommand(TaskOutputService output, OperationCoordinatorService operations)
        {
            _output = output;
            _operations = operations;
        }

        public string Name => "tempcheck";
        public string[] Aliases => new[] { "temp", "cleanup" };

        public async Task ExecuteAsync(string args, ShellViewModel vm)
        {
            if (!_operations.TryAcquireHeavy("Temp Cleanup Analysis", out var lease, out var blockingOwner))
            {
                vm.AddOutput($"[X] Busy: '{blockingOwner}'. Wait for the active heavy task to finish.\n");
                return;
            }

            using (lease)
            {
                var session = _output.CreateSession("Temp File Scan", vm.AcronymsExpanded);
                var progress = session.ViewModel;
                progress.Append("Scanning TEMP/APPDATA for recent/large files...\n");

                var paths = new[]
                {
                    Path.GetTempPath(),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
                };

                var files = new List<(string Path, long Size, DateTime Modified, string Signer)>();

                foreach (var path in paths)
                {
                    if (!Directory.Exists(path))
                    {
                        continue;
                    }

                    try
                    {
                        var recent = Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories)
                            .AsParallel()
                            .Where(f => File.GetLastWriteTime(f) > DateTime.Now.AddDays(-14))
                            .Select(f => new
                            {
                                Path = f,
                                Size = new FileInfo(f).Length,
                                Modified = File.GetLastWriteTime(f)
                            })
                            .OrderByDescending(x => x.Size)
                            .Take(50)
                            .ToArray();

                        foreach (var item in recent)
                        {
                            var signer = GetSigner(item.Path);
                            files.Add((item.Path, item.Size, item.Modified, signer));
                        }
                    }
                    catch (Exception ex)
                    {
                        progress.Append($"[error] {path}: {ex.Message}\n");
                    }
                }

                if (files.Count == 0)
                {
                    progress.Append("No recent temp files found.\n");
                }
                else
                {
                    progress.Append($"Found {files.Count} recent/large temp files:\n");
                    progress.Append("Path".PadRight(60) + "SizeMB".PadRight(10) + "Modified".PadRight(20) + "Signer\n");
                    progress.Append(new string('-', 110) + "\n");

                    foreach (var file in files.OrderByDescending(f => f.Size).Take(20))
                    {
                        var sizeMb = Math.Round(file.Size / (1024.0 * 1024), 1);
                        progress.Append($"{file.Path.PadRight(60)} {sizeMb,8:F1}MB {file.Modified:yyyy-MM-dd HH:mm,15} {file.Signer}\n");
                    }

                    progress.Append("\nSuggestions:\n");
                    progress.Append("- del /q /s %TEMP%\\*.* (cleans current session temp)\n");
                    progress.Append("- Use Disk Cleanup (cleanmgr.exe) for system temp\n");
                    progress.Append("- Schedule weekly: forfiles /p %TEMP% /s /m * /d -14 /c \"cmd /c del @path\"\n");
                    progress.Append("- Unsigned/large recent files may be malware droppers—review manually.\n");
                }

                progress.Status = "Completed";
                await Task.CompletedTask;
            }
        }

        private static string GetSigner(string path)
        {
            try
            {
                var sig = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(path);
                return sig.Subject ?? "self-signed/unknown";
            }
            catch
            {
                return "unsigned";
            }
        }
    }
}
