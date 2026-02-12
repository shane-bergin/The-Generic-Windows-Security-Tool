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
                while (!ct.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync().ConfigureAwait(false);
                    if (line is null)
                    {
                        break;
                    }

                    if (line.Length > 0)
                    {
                        onLine(line + "\n");
                    }
                }
            }

            try
            {
                var stdoutTask = PumpAsync(process.StandardOutput);
                var stderrTask = PumpAsync(process.StandardError);

                await Task.WhenAll(stdoutTask, stderrTask).ConfigureAwait(false);
                await process.WaitForExitAsync(ct).ConfigureAwait(false);
                return process.ExitCode;
            }
            catch (OperationCanceledException)
            {
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                    }
                }
                catch
                {
                    // best effort cleanup
                }

                throw;
            }
        }
    }
}
