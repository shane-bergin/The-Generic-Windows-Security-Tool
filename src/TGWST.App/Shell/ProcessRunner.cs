using System.Diagnostics;
using System.IO;

namespace TGWST.App.Shell
{
    public static class ProcessRunner
    {
        public static async Task<int> RunAsync(
            string fileName,
            string arguments,
            Action<string> onLine,
            CancellationToken ct = default)
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = psi, EnableRaisingEvents = true };
            process.Start();

            async Task PumpAsync(StreamReader reader)
            {
                while (!reader.EndOfStream && !ct.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync();
                    if (line != null)
                    {
                        onLine(line + "\n");
                    }
                }
            }

            var stdoutTask = PumpAsync(process.StandardOutput);
            var stderrTask = PumpAsync(process.StandardError);

            await Task.WhenAll(stdoutTask, stderrTask);
            await process.WaitForExitAsync(ct);
            return process.ExitCode;
        }
    }
}
