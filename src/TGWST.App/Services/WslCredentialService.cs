using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.App.Services
{
    /// <summary>
    /// Stores optional WSL sudo credentials encrypted with Windows DPAPI.
    /// </summary>
    public sealed class WslCredentialService
    {
        private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("TGWST::WSL::SUDO::v1");
        private static readonly TimeSpan VerifyTimeout = TimeSpan.FromSeconds(8);

        private readonly object _sync = new();
        private StoredRecord _record;

        public WslCredentialService()
        {
            _record = LoadRecord();
        }

        public WslCredentialSnapshot GetSnapshot()
        {
            lock (_sync)
            {
                return new WslCredentialSnapshot(
                    IsEnabled: _record.IsEnabled,
                    UserName: _record.UserName,
                    PreferredDistro: _record.PreferredDistro,
                    HasStoredPassword: !string.IsNullOrWhiteSpace(_record.EncryptedPassword),
                    UpdatedAtUtc: _record.UpdatedAtUtc,
                    StoragePath: GetSettingsPath());
            }
        }

        public bool TryGetCredentials(string? distro, out WslSudoCredentials credentials)
        {
            lock (_sync)
            {
                credentials = default;

                if (!_record.IsEnabled || string.IsNullOrWhiteSpace(_record.UserName))
                {
                    return false;
                }

                var decrypted = TryDecrypt(_record.EncryptedPassword);
                if (string.IsNullOrWhiteSpace(decrypted))
                {
                    return false;
                }

                credentials = new WslSudoCredentials(
                    UserName: _record.UserName!,
                    Password: decrypted,
                    PreferredDistro: _record.PreferredDistro);
                return true;
            }
        }

        public void Save(string userName, string? password, bool enabled)
        {
            var normalizedUser = (userName ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(normalizedUser))
            {
                throw new InvalidOperationException("WSL username is required.");
            }

            if (normalizedUser.Contains(' ') || normalizedUser.Contains('\t'))
            {
                throw new InvalidOperationException("WSL username cannot contain spaces.");
            }

            lock (_sync)
            {
                var encryptedPassword = string.IsNullOrEmpty(password)
                    ? _record.EncryptedPassword
                    : Encrypt(password);

                if (string.IsNullOrWhiteSpace(encryptedPassword))
                {
                    throw new InvalidOperationException("WSL sudo password is required.");
                }

                _record = new StoredRecord
                {
                    IsEnabled = enabled,
                    UserName = normalizedUser,
                    PreferredDistro = string.Empty,
                    EncryptedPassword = encryptedPassword,
                    UpdatedAtUtc = DateTimeOffset.UtcNow
                };

                SaveRecord(_record);
            }
        }

        public void SetEnabled(bool enabled)
        {
            lock (_sync)
            {
                _record.IsEnabled = enabled;
                _record.UpdatedAtUtc = DateTimeOffset.UtcNow;
                SaveRecord(_record);
            }
        }

        public void Clear()
        {
            lock (_sync)
            {
                _record = new StoredRecord
                {
                    IsEnabled = false,
                    UpdatedAtUtc = DateTimeOffset.UtcNow
                };

                SaveRecord(_record);
            }
        }

        public async Task<(bool Success, string Message)> VerifyAsync(string? preferredDistro = null, CancellationToken ct = default)
        {
            WslSudoCredentials creds;
            lock (_sync)
            {
                if (!TryGetCredentials(preferredDistro, out creds))
                {
                    return (false, "No enabled WSL credentials are available.");
                }
            }

            var distro = await ResolveDistroAsync(preferredDistro, ct);
            if (string.IsNullOrWhiteSpace(distro))
            {
                return (false, "No WSL distro found to verify credentials.");
            }

            var result = await RunSudoCommandAsync(
                distro: distro,
                userName: creds.UserName,
                password: creds.Password,
                commandArgs: new[] { "id", "-u" },
                ct: ct);

            if (result.ExitCode == 0 && result.StdOut.Contains("0", StringComparison.Ordinal))
            {
                return (true, $"Credential verification succeeded for distro '{distro}' as '{creds.UserName}'.");
            }

            var reason = FirstMeaningfulLine(result.StdErr) ?? FirstMeaningfulLine(result.StdOut) ?? "sudo verification failed.";
            return (false, reason);
        }

        public async Task<WslEnvironmentSnapshot> DetectEnvironmentAsync(
            string? preferredDistro = null,
            CancellationToken ct = default)
        {
            var (distros, error) = await QueryDistrosAsync(ct);
            if (distros.Length == 0)
            {
                return new WslEnvironmentSnapshot(
                    IsWslAvailable: false,
                    ResolvedDistro: null,
                    KernelInfo: null,
                    CurrentUser: null,
                    FailureReason: error ?? "No WSL distributions are installed.");
            }

            var distro = SelectDistro(distros, preferredDistro);
            if (string.IsNullOrWhiteSpace(distro))
            {
                return new WslEnvironmentSnapshot(
                    IsWslAvailable: true,
                    ResolvedDistro: null,
                    KernelInfo: null,
                    CurrentUser: null,
                    FailureReason: "Unable to select a WSL distribution.");
            }

            var unameResult = await RunProcessAsync(
                "wsl.exe",
                new[] { "--distribution", distro, "--exec", "bash", "-lc", "uname -a" },
                VerifyTimeout,
                ct,
                stdinText: null);

            var userResult = await RunProcessAsync(
                "wsl.exe",
                new[] { "--distribution", distro, "--exec", "id", "-un" },
                VerifyTimeout,
                ct,
                stdinText: null);

            var kernelLine = FirstMeaningfulLine(unameResult.StdOut);
            var userLine = FirstMeaningfulLine(userResult.StdOut);

            if (unameResult.ExitCode != 0 && userResult.ExitCode != 0)
            {
                var failure = FirstMeaningfulLine(unameResult.StdErr)
                    ?? FirstMeaningfulLine(userResult.StdErr)
                    ?? "Unable to execute bash in the selected WSL distribution.";

                return new WslEnvironmentSnapshot(
                    IsWslAvailable: true,
                    ResolvedDistro: distro,
                    KernelInfo: null,
                    CurrentUser: null,
                    FailureReason: failure);
            }

            return new WslEnvironmentSnapshot(
                IsWslAvailable: true,
                ResolvedDistro: distro,
                KernelInfo: kernelLine,
                CurrentUser: userLine,
                FailureReason: null);
        }

        public static string GetSettingsPath()
        {
            var root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "TGWST");
            Directory.CreateDirectory(root);
            return Path.Combine(root, "wsl-sudo-credentials.json");
        }

        private static string NormalizeOptional(string? value)
        {
            return string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();
        }

        private static StoredRecord LoadRecord()
        {
            var path = GetSettingsPath();
            if (!File.Exists(path))
            {
                return new StoredRecord { IsEnabled = false };
            }

            try
            {
                var json = File.ReadAllText(path);
                var record = JsonSerializer.Deserialize<StoredRecord>(json);
                if (record == null)
                {
                    return new StoredRecord { IsEnabled = false };
                }

                record.UserName = NormalizeOptional(record.UserName);
                record.PreferredDistro = NormalizeOptional(record.PreferredDistro);
                return record;
            }
            catch
            {
                return new StoredRecord { IsEnabled = false };
            }
        }

        private static void SaveRecord(StoredRecord record)
        {
            var path = GetSettingsPath();
            var json = JsonSerializer.Serialize(record, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, json);
        }

        private static string? TryDecrypt(string? encryptedValue)
        {
            if (string.IsNullOrWhiteSpace(encryptedValue))
            {
                return null;
            }

            try
            {
                var encryptedBytes = Convert.FromBase64String(encryptedValue);
                var clearBytes = ProtectedData.Unprotect(encryptedBytes, Entropy, DataProtectionScope.CurrentUser);
                try
                {
                    return Encoding.UTF8.GetString(clearBytes);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(clearBytes);
                }
            }
            catch
            {
                return null;
            }
        }

        private static string Encrypt(string password)
        {
            var clearBytes = Encoding.UTF8.GetBytes(password);
            try
            {
                var encryptedBytes = ProtectedData.Protect(clearBytes, Entropy, DataProtectionScope.CurrentUser);
                return Convert.ToBase64String(encryptedBytes);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(clearBytes);
            }
        }

        private static string? FirstMeaningfulLine(string? text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return null;
            }

            return SanitizeWslText(text)
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Replace('\0', ' ').Trim())
                .FirstOrDefault(line => line.Length > 0);
        }

        private static async Task<string?> ResolveDistroAsync(string? preferredDistro, CancellationToken ct)
        {
            var (distros, _) = await QueryDistrosAsync(ct);
            return SelectDistro(distros, preferredDistro);
        }

        private static string? SelectDistro(IReadOnlyList<string> distros, string? preferredDistro)
        {
            if (distros.Count == 0)
            {
                return null;
            }

            var preferred = NormalizeOptional(preferredDistro);
            if (!string.IsNullOrWhiteSpace(preferred))
            {
                var exact = distros.FirstOrDefault(d =>
                    string.Equals(d, preferred, StringComparison.OrdinalIgnoreCase));
                if (!string.IsNullOrWhiteSpace(exact))
                {
                    return exact;
                }

                var alias = distros.FirstOrDefault(d => MatchesDistroAlias(d, preferred));
                if (!string.IsNullOrWhiteSpace(alias))
                {
                    return alias;
                }
            }

            var ubuntu = distros.FirstOrDefault(d => d.StartsWith("Ubuntu", StringComparison.OrdinalIgnoreCase));
            return ubuntu ?? distros[0];
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

        private static async Task<(string[] Distros, string? Error)> QueryDistrosAsync(CancellationToken ct)
        {
            var result = await RunProcessAsync(
                "wsl.exe",
                new[] { "-l", "-q" },
                VerifyTimeout,
                ct,
                stdinText: null);

            if (result.ExitCode != 0)
            {
                var reason = FirstMeaningfulLine(result.StdErr)
                    ?? FirstMeaningfulLine(result.StdOut)
                    ?? "WSL is not available.";
                return (Array.Empty<string>(), reason);
            }

            var distros = result.StdOut
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(line => SanitizeWslToken(line))
                .Where(line => line.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (distros.Length == 0)
            {
                return (Array.Empty<string>(), "No WSL distributions are installed.");
            }

            return (distros, null);
        }

        private static async Task<ProcessResult> RunSudoCommandAsync(
            string distro,
            string userName,
            string password,
            IReadOnlyList<string> commandArgs,
            CancellationToken ct)
        {
            var args = new List<string>
            {
                "--distribution", distro,
                "--user", userName,
                "--exec",
                "sudo", "-S", "-p", "",
                "--"
            };
            args.AddRange(commandArgs);

            return await RunProcessAsync(
                "wsl.exe",
                args,
                VerifyTimeout,
                ct,
                stdinText: password + "\n");
        }

        private static async Task<ProcessResult> RunProcessAsync(
            string fileName,
            IReadOnlyList<string> args,
            TimeSpan timeout,
            CancellationToken ct,
            string? stdinText)
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
            catch
            {
                TryKill(process);
                throw;
            }

            return new ProcessResult(
                ExitCode: process.ExitCode,
                StdOut: SanitizeWslText(await stdoutTask),
                StdErr: SanitizeWslText(await stderrTask));
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

        private static string SanitizeWslText(string? text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return string.Empty;
            }

            return text.Replace("\0", string.Empty);
        }

        private static string SanitizeWslToken(string? value)
        {
            return SanitizeWslText(value)
                .Trim()
                .Trim('\uFEFF');
        }

        private sealed class StoredRecord
        {
            public bool IsEnabled { get; set; }
            public string? UserName { get; set; }
            public string? PreferredDistro { get; set; }
            public string? EncryptedPassword { get; set; }
            public DateTimeOffset UpdatedAtUtc { get; set; }
        }

        private sealed record ProcessResult(int ExitCode, string StdOut, string StdErr);
    }

    public readonly record struct WslSudoCredentials(string UserName, string Password, string? PreferredDistro);

    public sealed record WslCredentialSnapshot(
        bool IsEnabled,
        string? UserName,
        string? PreferredDistro,
        bool HasStoredPassword,
        DateTimeOffset UpdatedAtUtc,
        string StoragePath);

    public sealed record WslEnvironmentSnapshot(
        bool IsWslAvailable,
        string? ResolvedDistro,
        string? KernelInfo,
        string? CurrentUser,
        string? FailureReason);
}
