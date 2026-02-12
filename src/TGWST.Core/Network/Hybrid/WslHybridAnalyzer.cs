using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.Core.Network.Hybrid
{
    /// <summary>
    /// Uses hidden WSL2 + bash invocations to score current flow snapshots.
    /// Windows remains the source of truth for capture; WSL provides sidecar analytics.
    /// </summary>
    public sealed class WslHybridAnalyzer : IWslHybridAnalyzer
    {
        private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(4);
        private static readonly TimeSpan AnalyzeTimeout = TimeSpan.FromSeconds(6);

        private readonly object _scriptSync = new();
        private readonly string _workingRoot;
        private readonly string _awkScriptPath;

        public WslHybridAnalyzer()
        {
            var root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "TGWST",
                "Hybrid");

            try
            {
                Directory.CreateDirectory(root);
            }
            catch
            {
                root = Path.Combine(Path.GetTempPath(), "TGWST-Hybrid");
                Directory.CreateDirectory(root);
            }

            _workingRoot = root;
            _awkScriptPath = Path.Combine(_workingRoot, "score-flows.awk");
        }

        public async Task<WslHybridProbeResult> ProbeAsync(string? preferredDistro = null, CancellationToken ct = default)
        {
            try
            {
                var status = await RunProcessAsync(
                    "wsl.exe",
                    new[] { "--status" },
                    ProbeTimeout,
                    ct);

                if (status.ExitCode != 0)
                {
                    return new WslHybridProbeResult
                    {
                        IsWslInstalled = false,
                        FailureReason = FirstLine(status.StdErr) ?? FirstLine(status.StdOut) ?? "WSL2 is not available."
                    };
                }

                var distroList = await RunProcessAsync(
                    "wsl.exe",
                    new[] { "-l", "-q" },
                    ProbeTimeout,
                    ct);

                var distros = distroList.StdOut
                    .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(SanitizeToken)
                    .Where(d => !string.IsNullOrWhiteSpace(d))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();

                if (distros.Length == 0)
                {
                    return new WslHybridProbeResult
                    {
                        IsWslInstalled = true,
                        HasAnyDistribution = false,
                        AvailableDistros = Array.Empty<string>(),
                        FailureReason = "No WSL distributions are installed."
                    };
                }

                var selected = SelectDistro(distros, preferredDistro);
                if (selected == null)
                {
                    return new WslHybridProbeResult
                    {
                        IsWslInstalled = true,
                        HasAnyDistribution = true,
                        AvailableDistros = distros,
                        FailureReason = $"Requested distro '{preferredDistro}' is not installed."
                    };
                }

                var bashProbe = await RunProcessAsync(
                    "wsl.exe",
                    new[] { "--distribution", selected, "--exec", "bash", "-lc", "printf READY && printf '\\n' && id -un" },
                    ProbeTimeout,
                    ct);

                if (bashProbe.ExitCode != 0 || !bashProbe.StdOut.Contains("READY", StringComparison.Ordinal))
                {
                    return new WslHybridProbeResult
                    {
                        IsWslInstalled = true,
                        HasAnyDistribution = true,
                        AvailableDistros = distros,
                        SelectedDistro = selected,
                        BashReachable = false,
                        FailureReason = FirstLine(bashProbe.StdErr) ?? "Unable to execute bash inside selected WSL distro."
                    };
                }

                var lines = bashProbe.StdOut
                    .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .ToArray();
                var user = lines.Length >= 2 ? lines[^1].Trim() : null;

                return new WslHybridProbeResult
                {
                    IsWslInstalled = true,
                    HasAnyDistribution = true,
                    AvailableDistros = distros,
                    SelectedDistro = selected,
                    SelectedDistroUser = user,
                    BashReachable = true
                };
            }
            catch (TimeoutException ex)
            {
                return new WslHybridProbeResult
                {
                    IsWslInstalled = false,
                    FailureReason = ex.Message
                };
            }
            catch (Exception ex)
            {
                return new WslHybridProbeResult
                {
                    IsWslInstalled = false,
                    FailureReason = FirstLine(ex.Message) ?? "WSL probe failed."
                };
            }
        }

        public async Task<IReadOnlyList<HybridRiskFinding>> AnalyzeFlowsAsync(
            IReadOnlyList<FlowRecord> flows,
            string distro,
            CancellationToken ct = default)
        {
            if (flows.Count == 0)
            {
                return Array.Empty<HybridRiskFinding>();
            }

            EnsureAwkScript();

            var payload = BuildTsvPayload(flows);
            if (string.IsNullOrWhiteSpace(payload))
            {
                return Array.Empty<HybridRiskFinding>();
            }

            var inputPath = Path.Combine(_workingRoot, $"flows-{Guid.NewGuid():N}.tsv");
            await File.WriteAllTextAsync(inputPath, payload, Encoding.UTF8, ct);

            try
            {
                var wslInputPath = ToWslPath(inputPath);
                var wslScriptPath = ToWslPath(_awkScriptPath);
                var command = $"LC_ALL=C awk -F '\\t' -f '{EscapeForBashSingleQuotes(wslScriptPath)}' '{EscapeForBashSingleQuotes(wslInputPath)}'";

                var result = await RunProcessAsync(
                    "wsl.exe",
                    new[] { "--distribution", distro, "--exec", "bash", "-lc", command },
                    AnalyzeTimeout,
                    ct);

                if (result.ExitCode != 0)
                {
                    throw new InvalidOperationException(FirstLine(result.StdErr) ?? "Hybrid analysis command failed.");
                }

                var findings = ParseFindings(result.StdOut);
                return findings
                    .OrderByDescending(f => f.Score)
                    .ThenBy(f => f.ProcessName, StringComparer.OrdinalIgnoreCase)
                    .Take(24)
                    .ToArray();
            }
            finally
            {
                TryDelete(inputPath);
            }
        }

        private void EnsureAwkScript()
        {
            lock (_scriptSync)
            {
                try
                {
                    var existing = File.Exists(_awkScriptPath)
                        ? File.ReadAllText(_awkScriptPath)
                        : null;
                    if (string.Equals(existing, AwkRuleScript, StringComparison.Ordinal))
                    {
                        return;
                    }

                    File.WriteAllText(_awkScriptPath, AwkRuleScript, new UTF8Encoding(false));
                }
                catch
                {
                    // If script cannot be persisted, analysis call will fail and caller will degrade gracefully.
                }
            }
        }

        private static string BuildTsvPayload(IReadOnlyList<FlowRecord> flows)
        {
            var sb = new StringBuilder(16 * 1024);

            foreach (var flow in flows.Take(256))
            {
                sb
                    .Append(SanitizeField(flow.ProcessName))
                    .Append('\t')
                    .Append(flow.ProcessId)
                    .Append('\t')
                    .Append(SanitizeField(flow.RemoteAddress))
                    .Append('\t')
                    .Append(flow.RemotePort)
                    .Append('\t')
                    .Append(flow.TotalBytes)
                    .Append('\t')
                    .Append(Math.Max(0, (int)flow.Duration.TotalSeconds))
                    .Append('\t')
                    .Append(SanitizeField((flow.RemoteCountry ?? string.Empty).ToUpperInvariant()))
                    .Append('\t')
                    .Append(SanitizeField((flow.ProcessSigner ?? string.Empty).ToLowerInvariant()))
                    .Append('\t')
                    .Append(SanitizeField(flow.Protocol))
                    .Append('\n');
            }

            return sb.ToString();
        }

        private static IReadOnlyList<HybridRiskFinding> ParseFindings(string output)
        {
            var findings = new List<HybridRiskFinding>();

            foreach (var rawLine in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var line = rawLine.Trim();
                if (line.Length == 0)
                {
                    continue;
                }

                var parts = line.Split('\t');
                if (parts.Length < 6)
                {
                    continue;
                }

                if (!int.TryParse(parts[1], out var pid))
                {
                    pid = 0;
                }

                if (!int.TryParse(parts[3], out var score))
                {
                    score = 0;
                }

                var reasons = parts[5]
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .ToArray();

                findings.Add(new HybridRiskFinding
                {
                    ProcessName = parts[0],
                    ProcessId = pid,
                    Endpoint = parts[2],
                    Score = score,
                    Severity = parts[4],
                    Reasons = reasons
                });
            }

            return findings;
        }

        private static string? SelectDistro(IReadOnlyList<string> distros, string? preferredDistro)
        {
            if (!string.IsNullOrWhiteSpace(preferredDistro))
            {
                var match = distros.FirstOrDefault(d =>
                    string.Equals(d, preferredDistro, StringComparison.OrdinalIgnoreCase));
                if (match != null)
                {
                    return match;
                }

                match = distros.FirstOrDefault(d => MatchesDistroAlias(d, preferredDistro));
                if (match != null)
                {
                    return match;
                }
            }

            var ubuntu = distros.FirstOrDefault(d => d.StartsWith("Ubuntu", StringComparison.OrdinalIgnoreCase));
            return ubuntu ?? distros.FirstOrDefault();
        }

        private static string SanitizeField(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return "";
            }

            var sanitized = value
                .Replace('\t', ' ')
                .Replace('\r', ' ')
                .Replace('\n', ' ')
                .Trim();

            return sanitized;
        }

        private static string ToWslPath(string windowsPath)
        {
            var full = Path.GetFullPath(windowsPath);
            if (full.Length > 2 && full[1] == ':')
            {
                var driveLetter = char.ToLowerInvariant(full[0]);
                var tail = full[2..].Replace('\\', '/');
                return $"/mnt/{driveLetter}{tail}";
            }

            return full.Replace('\\', '/');
        }

        private static string EscapeForBashSingleQuotes(string value)
        {
            return value.Replace("'", "'\"'\"'");
        }

        private static string? FirstLine(string? text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return null;
            }

            var line = SanitizeOutput(text)
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .FirstOrDefault();

            return string.IsNullOrWhiteSpace(line) ? null : line.Trim();
        }

        private static void TryDelete(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch
            {
                // Best effort cleanup.
            }
        }

        private static async Task<ProcessResult> RunProcessAsync(
            string fileName,
            IReadOnlyList<string> arguments,
            TimeSpan timeout,
            CancellationToken ct)
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            foreach (var arg in arguments)
            {
                psi.ArgumentList.Add(arg);
            }

            using var process = new Process
            {
                StartInfo = psi,
                EnableRaisingEvents = true
            };

            if (!process.Start())
            {
                throw new InvalidOperationException($"Failed to start process: {fileName}");
            }

            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(timeout);

            try
            {
                await process.WaitForExitAsync(timeoutCts.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                TryKill(process);
                throw new TimeoutException($"Timed out waiting for '{fileName}' after {timeout.TotalSeconds:0.#}s.");
            }
            catch
            {
                TryKill(process);
                throw;
            }

            var stdout = await stdoutTask;
            var stderr = await stderrTask;
            return new ProcessResult(process.ExitCode, SanitizeOutput(stdout), SanitizeOutput(stderr));
        }

        private static void TryKill(Process process)
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
                // Best effort process cleanup.
            }
        }

        private static bool MatchesDistroAlias(string distro, string preferred)
        {
            if (distro.StartsWith(preferred, StringComparison.OrdinalIgnoreCase) ||
                preferred.StartsWith(distro, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            var distroNorm = NormalizeForCompare(distro);
            var preferredNorm = NormalizeForCompare(preferred);
            if (distroNorm.Length == 0 || preferredNorm.Length == 0)
            {
                return false;
            }

            return distroNorm.StartsWith(preferredNorm, StringComparison.Ordinal) ||
                   preferredNorm.StartsWith(distroNorm, StringComparison.Ordinal) ||
                   distroNorm.Contains(preferredNorm, StringComparison.Ordinal);
        }

        private static string NormalizeForCompare(string value)
        {
            var chars = value.Where(char.IsLetterOrDigit)
                .Select(char.ToLowerInvariant)
                .ToArray();
            return new string(chars);
        }

        private static string SanitizeToken(string? value)
        {
            return SanitizeOutput(value)
                .Trim()
                .Trim('\uFEFF');
        }

        private static string SanitizeOutput(string? value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }

            return value.Replace("\0", string.Empty);
        }

        private sealed record ProcessResult(int ExitCode, string StdOut, string StdErr);

        private const string AwkRuleScript = @"BEGIN {
    OFS=""\t""
}
function add_reason(code) {
    if (reasons == """") {
        reasons = code
    } else {
        reasons = reasons "","" code
    }
}
{
    process = tolower($1)
    pid = $2 + 0
    remote = $3
    port = $4 + 0
    bytes = $5 + 0
    duration = $6 + 0
    country = toupper($7)
    signer = tolower($8)
    protocol = toupper($9)

    score = 0
    reasons = """"

    if (bytes > 52428800 && duration < 30) {
        score += 30
        add_reason(""burst-egress"")
    }

    if (duration >= 600 && bytes <= 262144) {
        score += 20
        add_reason(""possible-beacon"")
    }

    if (country != """" && country != ""US"" && country != ""CA"" && country != ""GB"" && country != ""AU"" && country != ""NZ"") {
        score += 10
        add_reason(""foreign-destination"")
    }

    if (process ~ /(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|wmic)/) {
        score += 20
        add_reason(""lolbin-process"")
    }

    if (process == ""unknown"" || process == """") {
        score += 15
        add_reason(""unknown-process"")
    }

    if (index(signer, ""microsoft"") == 0 && signer != """") {
        score += 8
        add_reason(""non-microsoft-signer"")
    }

    if (protocol == ""UDP"" && port == 53 && bytes > 2097152) {
        score += 10
        add_reason(""dns-volume"")
    }

    if (port == 0 || port == 1 || port == 7 || port == 19 || port == 1900 || port == 5353) {
        score += 10
        add_reason(""noisy-port"")
    }

    if (score > 0) {
        severity = ""Low""
        if (score >= 55) {
            severity = ""High""
        } else if (score >= 30) {
            severity = ""Medium""
        }

        endpoint = remote "":"" port
        print $1, pid, endpoint, score, severity, reasons
    }
}";
    }
}
