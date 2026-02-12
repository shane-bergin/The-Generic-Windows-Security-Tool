using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.App.Services
{
    public sealed class PiHoleBridgeService
    {
        private static readonly Regex DurationSpecRegex = new(@"^\d+[smhd]$", RegexOptions.Compiled);
        private static readonly Regex DomainRegex = new(@"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$", RegexOptions.Compiled);
        private static readonly Regex InterfaceAliasRegex = new(@"^[A-Za-z0-9 _\-\.\(\)]+$", RegexOptions.Compiled);
        private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(12);
        private static readonly TimeSpan FtlTimeout = TimeSpan.FromSeconds(3);
        private readonly WslCredentialService _credentialService;

        public PiHoleBridgeService(WslCredentialService credentialService)
        {
            _credentialService = credentialService;
        }

        public async Task<PiHoleProbeResult> ProbeAsync(string? preferredDistro = null, CancellationToken ct = default)
        {
            var distro = await ResolveDistroAsync(preferredDistro, ct);
            if (string.IsNullOrWhiteSpace(distro))
            {
                return new PiHoleProbeResult
                {
                    IsWslAvailable = false,
                    FailureReason = "No WSL distro found. Install WSL and a Linux distro first."
                };
            }

            var probeInstall = await RunWslCommandAsync(
                distro,
                runAsRoot: false,
                command: "bash",
                args: new[] { "-lc", "command -v pihole >/dev/null 2>&1 && printf READY" },
                ct);

            if (probeInstall.ExitCode != 0 || !probeInstall.StdOut.Contains("READY", StringComparison.Ordinal))
            {
                return new PiHoleProbeResult
                {
                    IsWslAvailable = true,
                    Distro = distro,
                    IsPiHoleInstalled = false,
                    FailureReason = "Pi-hole CLI is not installed in the selected distro."
                };
            }

            var status = await RunPiHoleAsync(distro, new[] { "status" }, ct);
            var statusText = FirstMeaningfulLine(status.StdOut) ?? "Status unavailable";
            var blockingEnabled = IsBlockingEnabled(status.StdOut);

            var ftlCheck = await QueryFtlAsync(">stats", ct);
            var ftlReady = ftlCheck.Success;

            return new PiHoleProbeResult
            {
                IsWslAvailable = true,
                Distro = distro,
                IsPiHoleInstalled = true,
                IsBlockingEnabled = blockingEnabled,
                IsFtlReachable = ftlReady,
                StatusSummary = statusText,
                FailureReason = ftlReady ? null : ftlCheck.Error
            };
        }

        public async Task<IReadOnlyList<PiHoleTopBlockedDomain>> GetTopBlockedDomainsAsync(
            int maxCount,
            CancellationToken ct = default)
        {
            var count = Math.Clamp(maxCount, 1, 25);
            var ftlResponse = await QueryFtlAsync($">top-ads ({count})", ct);
            if (!ftlResponse.Success)
            {
                throw new InvalidOperationException(ftlResponse.Error ?? "Unable to query Pi-hole FTL socket.");
            }

            return ParseTopAds(ftlResponse.RawLines, count);
        }

        public async Task<string> EnableBlockingAsync(string? preferredDistro = null, CancellationToken ct = default)
        {
            var distro = await RequireDistroAsync(preferredDistro, ct);
            var result = await RunPiHoleAsync(distro, new[] { "enable" }, ct);
            return SummarizeOutput("Blocking enabled.", result.StdOut);
        }

        public async Task<string> DisableBlockingAsync(
            string? durationSpec = null,
            string? preferredDistro = null,
            CancellationToken ct = default)
        {
            var distro = await RequireDistroAsync(preferredDistro, ct);
            var args = new List<string> { "disable" };
            if (!string.IsNullOrWhiteSpace(durationSpec))
            {
                if (!DurationSpecRegex.IsMatch(durationSpec.Trim()))
                {
                    throw new InvalidOperationException("Duration must look like 5m, 1h, or 30s.");
                }

                args.Add(durationSpec.Trim());
            }

            var result = await RunPiHoleAsync(distro, args, ct);
            return SummarizeOutput("Blocking disabled.", result.StdOut);
        }

        public async Task<string> UpdateGravityAsync(string? preferredDistro = null, CancellationToken ct = default)
        {
            var distro = await RequireDistroAsync(preferredDistro, ct);
            var result = await RunPiHoleAsync(distro, new[] { "updateGravity" }, ct);
            return SummarizeOutput("Gravity/blocklists updated.", result.StdOut);
        }

        public async Task<string> AllowDomainAsync(string domain, string? preferredDistro = null, CancellationToken ct = default)
        {
            var normalized = (domain ?? string.Empty).Trim().Trim('.');
            if (!DomainRegex.IsMatch(normalized))
            {
                throw new InvalidOperationException("Provide a valid domain name, e.g. example.com");
            }

            var distro = await RequireDistroAsync(preferredDistro, ct);
            var result = await RunPiHoleAsync(distro, new[] { "allow", normalized }, ct);
            return SummarizeOutput($"Allowlisted domain: {normalized}", result.StdOut);
        }

        public async Task<string> GetWslIpAsync(string? preferredDistro = null, CancellationToken ct = default)
        {
            var distro = await RequireDistroAsync(preferredDistro, ct);
            var result = await RunWslCommandAsync(
                distro,
                runAsRoot: false,
                command: "hostname",
                args: new[] { "-I" },
                ct);

            var ip = result.StdOut
                .Split(new[] { ' ', '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries)
                .FirstOrDefault(token => IPAddress.TryParse(token, out _));

            if (string.IsNullOrWhiteSpace(ip))
            {
                throw new InvalidOperationException("Could not determine WSL IP address.");
            }

            return ip;
        }

        public async Task<string> SyncWindowsDnsAsync(
            string interfaceAlias,
            string dnsServerIp,
            CancellationToken ct = default)
        {
            var iface = (interfaceAlias ?? string.Empty).Trim();
            var dns = (dnsServerIp ?? string.Empty).Trim();

            if (!InterfaceAliasRegex.IsMatch(iface))
            {
                throw new InvalidOperationException("Interface alias contains unsupported characters.");
            }

            if (!IPAddress.TryParse(dns, out _))
            {
                throw new InvalidOperationException("DNS server must be a valid IP address.");
            }

            var command = $"Set-DnsClientServerAddress -InterfaceAlias '{EscapePowerShellLiteral(iface)}' -ServerAddresses '{EscapePowerShellLiteral(dns)}'";
            var result = await RunProcessAsync(
                "powershell.exe",
                new[] { "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command },
                CommandTimeout,
                ct);

            if (result.ExitCode != 0)
            {
                throw new InvalidOperationException(FirstMeaningfulLine(result.StdErr) ?? "Failed to set DNS server on Windows.");
            }

            return $"Windows DNS for '{iface}' set to {dns}.";
        }

        private async Task<string> RequireDistroAsync(string? preferredDistro, CancellationToken ct)
        {
            var distro = await ResolveDistroAsync(preferredDistro, ct);
            if (string.IsNullOrWhiteSpace(distro))
            {
                throw new InvalidOperationException("No WSL distro found.");
            }

            return distro;
        }

        private async Task<string?> ResolveDistroAsync(string? preferredDistro, CancellationToken ct)
        {
            var result = await RunProcessAsync(
                "wsl.exe",
                new[] { "-l", "-q" },
                CommandTimeout,
                ct);

            if (result.ExitCode != 0)
            {
                return null;
            }

            var distros = result.StdOut
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(SanitizeToken)
                .Where(d => !string.IsNullOrWhiteSpace(d))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (distros.Length == 0)
            {
                return null;
            }

            if (!string.IsNullOrWhiteSpace(preferredDistro))
            {
                var preferred = distros.FirstOrDefault(d => string.Equals(d, preferredDistro, StringComparison.OrdinalIgnoreCase));
                if (!string.IsNullOrWhiteSpace(preferred))
                {
                    return preferred;
                }

                preferred = distros.FirstOrDefault(d => MatchesDistroAlias(d, preferredDistro));
                if (!string.IsNullOrWhiteSpace(preferred))
                {
                    return preferred;
                }
            }

            var ubuntu = distros.FirstOrDefault(d => d.StartsWith("Ubuntu", StringComparison.OrdinalIgnoreCase));
            return ubuntu ?? distros[0];
        }

        private async Task<ProcessResult> RunPiHoleAsync(
            string distro,
            IReadOnlyList<string> piHoleArgs,
            CancellationToken ct)
        {
            var result = await RunWslCommandAsync(
                distro,
                runAsRoot: true,
                command: "pihole",
                args: piHoleArgs,
                ct);

            if (result.ExitCode != 0)
            {
                var error = FirstMeaningfulLine(result.StdErr) ?? FirstMeaningfulLine(result.StdOut) ?? "Pi-hole command failed.";
                throw new InvalidOperationException(error);
            }

            return result;
        }

        private async Task<ProcessResult> RunWslCommandAsync(
            string distro,
            bool runAsRoot,
            string command,
            IReadOnlyList<string> args,
            CancellationToken ct)
        {
            if (runAsRoot && _credentialService.TryGetCredentials(distro, out var creds))
            {
                var sudoArgs = new List<string>
                {
                    "--distribution", distro,
                    "--user", creds.UserName,
                    "--exec",
                    "sudo", "-S", "-p", "",
                    "--",
                    command
                };
                sudoArgs.AddRange(args);

                var sudoResult = await RunProcessAsync(
                    "wsl.exe",
                    sudoArgs,
                    CommandTimeout,
                    ct,
                    stdinText: creds.Password + "\n");

                if (sudoResult.ExitCode == 0)
                {
                    return sudoResult;
                }
            }

            var cli = new List<string> { "--distribution", distro };
            if (runAsRoot)
            {
                cli.Add("--user");
                cli.Add("root");
            }

            cli.Add("--exec");
            cli.Add(command);
            cli.AddRange(args);

            return await RunProcessAsync("wsl.exe", cli, CommandTimeout, ct, stdinText: null);
        }

        private async Task<FtlQueryResult> QueryFtlAsync(string command, CancellationToken ct)
        {
            try
            {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(FtlTimeout);

                using var client = new TcpClient();
                await client.ConnectAsync(IPAddress.Loopback, 4711, timeoutCts.Token);

                using var stream = client.GetStream();
                using var writer = new StreamWriter(stream, new UTF8Encoding(false), leaveOpen: true)
                {
                    NewLine = "\n",
                    AutoFlush = true
                };
                using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);

                await writer.WriteLineAsync(command);
                await writer.WriteLineAsync(">quit");

                var lines = new List<string>(64);
                while (!timeoutCts.IsCancellationRequested && lines.Count < 1024)
                {
                    string? line;
                    try
                    {
                        line = await reader.ReadLineAsync(timeoutCts.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }

                    if (line == null)
                    {
                        break;
                    }

                    if (!string.IsNullOrWhiteSpace(line))
                    {
                        lines.Add(line.Trim());
                    }
                }

                return new FtlQueryResult
                {
                    Success = true,
                    RawLines = lines
                };
            }
            catch (Exception ex)
            {
                return new FtlQueryResult
                {
                    Success = false,
                    Error = FirstMeaningfulLine(ex.Message) ?? "Unable to connect to FTL socket."
                };
            }
        }

        private static IReadOnlyList<PiHoleTopBlockedDomain> ParseTopAds(
            IReadOnlyList<string> rawLines,
            int limit)
        {
            var rows = new List<PiHoleTopBlockedDomain>(limit);

            foreach (var line in rawLines)
            {
                if (rows.Count >= limit)
                {
                    break;
                }

                if (!TryParseTopDomainLine(line, out var row))
                {
                    continue;
                }

                rows.Add(row);
            }

            return rows
                .OrderByDescending(r => r.BlockedCount)
                .ThenBy(r => r.Domain, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        private static bool TryParseTopDomainLine(string line, out PiHoleTopBlockedDomain domain)
        {
            domain = default!;
            if (string.IsNullOrWhiteSpace(line))
            {
                return false;
            }

            var parts = line
                .Split(new[] { ' ', '\t', ',', ';', '|' }, StringSplitOptions.RemoveEmptyEntries)
                .ToArray();

            if (parts.Length < 2)
            {
                return false;
            }

            for (var i = 0; i < parts.Length - 1; i++)
            {
                var maybeDomain = parts[i].Trim().Trim('"');
                if (!DomainRegex.IsMatch(maybeDomain))
                {
                    continue;
                }

                for (var j = i + 1; j < parts.Length; j++)
                {
                    if (!long.TryParse(parts[j], out var count))
                    {
                        continue;
                    }

                    domain = new PiHoleTopBlockedDomain(maybeDomain, count);
                    return true;
                }
            }

            return false;
        }

        private static bool IsBlockingEnabled(string statusOutput)
        {
            if (string.IsNullOrWhiteSpace(statusOutput))
            {
                return false;
            }

            if (statusOutput.IndexOf("disabled", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return false;
            }

            return statusOutput.IndexOf("enabled", StringComparison.OrdinalIgnoreCase) >= 0
                || statusOutput.IndexOf("active", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static string SummarizeOutput(string fallback, string output)
        {
            return FirstMeaningfulLine(output) ?? fallback;
        }

        private static string? FirstMeaningfulLine(string? text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return null;
            }

            return SanitizeOutput(text)
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Replace('\0', ' ').Trim())
                .FirstOrDefault(line => line.Length > 0);
        }

        private static string EscapePowerShellLiteral(string value)
        {
            return value.Replace("'", "''");
        }

        private static async Task<ProcessResult> RunProcessAsync(
            string fileName,
            IReadOnlyList<string> args,
            TimeSpan timeout,
            CancellationToken ct,
            string? stdinText = null)
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = stdinText != null,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            foreach (var arg in args)
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

            if (stdinText != null)
            {
                await process.StandardInput.WriteAsync(stdinText);
                process.StandardInput.Close();
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
                throw new TimeoutException($"Timed out running '{fileName}'.");
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
                // best effort
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

        private sealed class FtlQueryResult
        {
            public bool Success { get; init; }
            public string? Error { get; init; }
            public IReadOnlyList<string> RawLines { get; init; } = Array.Empty<string>();
        }
    }

    public sealed class PiHoleProbeResult
    {
        public bool IsWslAvailable { get; init; }
        public string? Distro { get; init; }
        public bool IsPiHoleInstalled { get; init; }
        public bool IsBlockingEnabled { get; init; }
        public bool IsFtlReachable { get; init; }
        public string? StatusSummary { get; init; }
        public string? FailureReason { get; init; }
    }

    public sealed record PiHoleTopBlockedDomain(string Domain, long BlockedCount);
}
