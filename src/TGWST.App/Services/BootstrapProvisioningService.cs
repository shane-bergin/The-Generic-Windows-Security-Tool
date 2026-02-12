using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.App.Services
{
    public sealed class BootstrapProvisioningService
    {
        private static readonly TimeSpan ShortTimeout = TimeSpan.FromSeconds(12);
        private static readonly TimeSpan MediumTimeout = TimeSpan.FromMinutes(3);
        private static readonly TimeSpan LongTimeout = TimeSpan.FromMinutes(12);

        private readonly WslCredentialService _credentials;
        private readonly PiHoleBridgeService _piHole;

        public BootstrapProvisioningService(WslCredentialService credentials, PiHoleBridgeService piHole)
        {
            _credentials = credentials;
            _piHole = piHole;
        }

        public async Task<BootstrapStatus> ProbeAsync(CancellationToken ct = default)
        {
            var wslStatus = await RunProcessAsync(
                "wsl.exe",
                new[] { "--status" },
                ShortTimeout,
                ct,
                stdinText: null);

            var (distros, distroError) = await QueryDistrosAsync(ct);
            var resolvedDistro = SelectPreferredDistro(distros);

            string? kernel = null;
            string? distroUser = null;
            bool bashReachable = false;
            bool dockerInstalled = false;
            bool dockerActive = false;
            string? wslIp = null;
            string? firstError = null;

            if (!string.IsNullOrWhiteSpace(resolvedDistro))
            {
                var envProbe = await RunWslAsync(
                    resolvedDistro,
                    runAsRoot: false,
                    command: "bash",
                    args: new[] { "-lc", "uname -a && id -un" },
                    timeout: ShortTimeout,
                    ct,
                    stdinText: null);

                if (envProbe.ExitCode == 0)
                {
                    var lines = SplitLines(envProbe.StdOut);
                    kernel = lines.FirstOrDefault();
                    distroUser = lines.Skip(1).FirstOrDefault();
                    bashReachable = true;
                }
                else
                {
                    firstError ??= FirstMeaningfulLine(envProbe.StdErr) ?? FirstMeaningfulLine(envProbe.StdOut);
                }

                var dockerProbe = await RunWslAsync(
                    resolvedDistro,
                    runAsRoot: false,
                    command: "bash",
                    args: new[] { "-lc", "command -v docker >/dev/null 2>&1 && docker --version" },
                    timeout: ShortTimeout,
                    ct,
                    stdinText: null);

                dockerInstalled = dockerProbe.ExitCode == 0;
                if (dockerInstalled)
                {
                    var dockerState = await RunWslAsync(
                        resolvedDistro,
                        runAsRoot: true,
                        command: "bash",
                        args: new[] { "-lc", "systemctl is-active docker || true" },
                        timeout: ShortTimeout,
                        ct,
                        stdinText: null);

                    dockerActive = dockerState.StdOut.IndexOf("active", StringComparison.OrdinalIgnoreCase) >= 0;
                }

                var ipProbe = await RunWslAsync(
                    resolvedDistro,
                    runAsRoot: false,
                    command: "hostname",
                    args: new[] { "-I" },
                    timeout: ShortTimeout,
                    ct,
                    stdinText: null);

                if (ipProbe.ExitCode == 0)
                {
                    wslIp = ipProbe.StdOut
                        .Split(new[] { ' ', '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries)
                        .FirstOrDefault();
                }
            }

            var piHoleProbe = await _piHole.ProbeAsync(resolvedDistro, ct);
            var credentials = _credentials.GetSnapshot();

            var isWslInstalled = wslStatus.ExitCode == 0 || distros.Length > 0;
            var hasDistro = distros.Length > 0;
            var credsConfigured = credentials.IsEnabled && credentials.HasStoredPassword && !string.IsNullOrWhiteSpace(credentials.UserName);
            var statusMessage = FirstMeaningfulLine(wslStatus.StdOut) ?? FirstMeaningfulLine(wslStatus.StdErr) ?? distroError;
            var state = LoadState();

            var coreReady = isWslInstalled && hasDistro && bashReachable && dockerInstalled && dockerActive && piHoleProbe.IsPiHoleInstalled;

            return new BootstrapStatus(
                IsWslInstalled: isWslInstalled,
                HasDistro: hasDistro,
                ResolvedDistro: resolvedDistro,
                BashReachable: bashReachable,
                DistroUser: distroUser,
                KernelInfo: kernel,
                DockerInstalled: dockerInstalled,
                DockerActive: dockerActive,
                PiHoleInstalled: piHoleProbe.IsPiHoleInstalled,
                PiHoleBlockingEnabled: piHoleProbe.IsBlockingEnabled,
                PiHoleFtlReachable: piHoleProbe.IsFtlReachable,
                WslIpAddress: wslIp,
                CredentialsConfigured: credsConfigured,
                CredentialsUser: credentials.UserName,
                CoreReady: coreReady,
                WizardCompleted: state.WizardCompleted,
                FailureReason: firstError ?? piHoleProbe.FailureReason ?? statusMessage ?? distroError,
                AvailableDistros: distros);
        }

        public bool ShouldShowWizard(BootstrapStatus status)
        {
            return !status.CoreReady || !status.WizardCompleted;
        }

        public async Task<BootstrapStatus> RunProvisionAsync(
            BootstrapPlan plan,
            Action<string> log,
            CancellationToken ct = default)
        {
            if (plan.EnsureWslAndUbuntu)
            {
                log("[>] Ensuring WSL2 + Ubuntu-22.04 are installed...");
                await EnsureWslAndUbuntuAsync(log, ct);
                log("[OK] WSL/Ubuntu step completed.");
            }

            var status = await ProbeAsync(ct);
            var distro = status.ResolvedDistro;

            if (plan.InstallDocker)
            {
                if (string.IsNullOrWhiteSpace(distro))
                {
                    throw new InvalidOperationException("No Ubuntu distro available. Run WSL setup first.");
                }

                log($"[>] Installing Docker in {distro} ...");
                await EnsureDockerAsync(distro, ct);
                log("[OK] Docker step completed.");
            }

            if (plan.InstallPiHole)
            {
                if (string.IsNullOrWhiteSpace(distro))
                {
                    throw new InvalidOperationException("No Ubuntu distro available. Run WSL setup first.");
                }

                log($"[>] Installing Pi-hole appliance in {distro} ...");
                await EnsurePiHoleAsync(distro, ct);
                log("[OK] Pi-hole appliance step completed.");
            }

            if (plan.SaveCredentials)
            {
                var user = (plan.WslUserName ?? string.Empty).Trim();
                if (user.Length == 0)
                {
                    throw new InvalidOperationException("WSL username is required when saving credentials.");
                }

                _credentials.Save(userName: user, password: plan.WslPassword, enabled: true);
                log("[>] Verifying stored sudo credentials ...");
                var verify = await _credentials.VerifyAsync(distro, ct);
                if (!verify.Success)
                {
                    throw new InvalidOperationException(verify.Message);
                }

                log($"[OK] {verify.Message}");
            }

            if (plan.SyncWindowsDns)
            {
                var iface = string.IsNullOrWhiteSpace(plan.InterfaceAlias) ? "Ethernet" : plan.InterfaceAlias.Trim();
                var ip = await _piHole.GetWslIpAsync(distro, ct);
                var message = await _piHole.SyncWindowsDnsAsync(iface, ip, ct);
                log($"[OK] {message}");
            }

            var finalStatus = await ProbeAsync(ct);
            if (finalStatus.CoreReady)
            {
                MarkWizardCompleted(finalStatus.ResolvedDistro);
                return finalStatus with { WizardCompleted = true };
            }

            return finalStatus;
        }

        public void MarkWizardCompleted(string? distro)
        {
            var state = LoadState();
            state.WizardCompleted = true;
            state.CompletedAtUtc = DateTimeOffset.UtcNow;
            state.LastDistro = string.IsNullOrWhiteSpace(distro) ? state.LastDistro : distro.Trim();
            SaveState(state);
        }

        private async Task EnsureWslAndUbuntuAsync(Action<string> log, CancellationToken ct)
        {
            var (distros, _) = await QueryDistrosAsync(ct);
            if (distros.Any(d => d.StartsWith("Ubuntu", StringComparison.OrdinalIgnoreCase)))
            {
                log("[i] Ubuntu distro already present.");
                return;
            }

            var install = await RunProcessAsync(
                "wsl.exe",
                new[] { "--install", "-d", "Ubuntu-22.04" },
                LongTimeout,
                ct,
                stdinText: null);

            if (install.ExitCode != 0)
            {
                var reason = FirstMeaningfulLine(install.StdErr) ?? FirstMeaningfulLine(install.StdOut) ?? "Unable to install WSL/Ubuntu.";
                throw new InvalidOperationException(reason);
            }

            var output = FirstMeaningfulLine(install.StdOut);
            if (!string.IsNullOrWhiteSpace(output))
            {
                log($"[i] {output}");
            }
        }

        private static async Task EnsureDockerAsync(string distro, CancellationToken ct)
        {
            var script = """
set -euo pipefail
if ! command -v docker >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y docker.io ca-certificates curl
fi
systemctl enable --now docker
docker --version
docker ps >/dev/null
echo DOCKER_READY
""";

            var result = await RunWslAsync(
                distro,
                runAsRoot: true,
                command: "bash",
                args: new[] { "-lc", script },
                timeout: LongTimeout,
                ct,
                stdinText: null);

            if (result.ExitCode != 0)
            {
                var reason = FirstMeaningfulLine(result.StdErr) ?? FirstMeaningfulLine(result.StdOut) ?? "Docker installation failed.";
                throw new InvalidOperationException(reason);
            }
        }

        private static async Task EnsurePiHoleAsync(string distro, CancellationToken ct)
        {
            var script = """
set -euo pipefail
PIHOLE_ROOT=/opt/pihole
mkdir -p "$PIHOLE_ROOT/etc-pihole" "$PIHOLE_ROOT/etc-dnsmasq.d"
PASS_FILE="$PIHOLE_ROOT/.admin_password"
if [ ! -s "$PASS_FILE" ]; then
  pass=$(cat /proc/sys/kernel/random/uuid | tr -d '-')
  printf '%s' "$pass" > "$PASS_FILE"
  chmod 600 "$PASS_FILE"
fi
pass=$(cat "$PASS_FILE")
TZ_VAL=$(cat /etc/timezone 2>/dev/null || echo UTC)
WSL_IP=$(hostname -I | awk '{print $1}')
if [ -z "$WSL_IP" ]; then
  echo 'Unable to determine WSL IP'
  exit 1
fi

docker rm -f pihole >/dev/null 2>&1 || true
docker pull pihole/pihole:latest >/dev/null

docker run -d \
  --name pihole \
  -p "$WSL_IP:53:53/tcp" \
  -p "$WSL_IP:53:53/udp" \
  -p 127.0.0.1:8080:80/tcp \
  -p 127.0.0.1:4711:4711/tcp \
  -e TZ="$TZ_VAL" \
  -e FTLCONF_webserver_api_password="$pass" \
  -e WEBPASSWORD="$pass" \
  -e FTLCONF_dns_listeningMode=all \
  -v "$PIHOLE_ROOT/etc-pihole:/etc/pihole" \
  -v "$PIHOLE_ROOT/etc-dnsmasq.d:/etc/dnsmasq.d" \
  --restart unless-stopped \
  --cap-add NET_ADMIN \
  --cap-add SYS_TIME \
  --cap-add SYS_NICE \
  pihole/pihole:latest >/dev/null

cat >/usr/local/bin/pihole <<'EOSH'
#!/usr/bin/env bash
set -euo pipefail
if ! docker ps --format '{{.Names}}' | grep -qx 'pihole'; then
  echo 'Pi-hole container is not running.' >&2
  exit 1
fi
exec docker exec -i pihole pihole "$@"
EOSH
chmod 755 /usr/local/bin/pihole

cat >/usr/local/sbin/tgwst-pihole-container.sh <<'EOSH'
#!/usr/bin/env bash
set -euo pipefail
PIHOLE_ROOT=/opt/pihole
mkdir -p "$PIHOLE_ROOT/etc-pihole" "$PIHOLE_ROOT/etc-dnsmasq.d"
PASS_FILE="$PIHOLE_ROOT/.admin_password"
if [ ! -s "$PASS_FILE" ]; then
  pass=$(cat /proc/sys/kernel/random/uuid | tr -d '-')
  printf '%s' "$pass" > "$PASS_FILE"
  chmod 600 "$PASS_FILE"
fi
pass=$(cat "$PASS_FILE")
TZ_VAL=$(cat /etc/timezone 2>/dev/null || echo UTC)
WSL_IP=$(hostname -I | awk '{print $1}')
if [ -z "$WSL_IP" ]; then
  echo 'Unable to determine WSL IP'
  exit 1
fi

docker rm -f pihole >/dev/null 2>&1 || true
docker run -d \
  --name pihole \
  -p "$WSL_IP:53:53/tcp" \
  -p "$WSL_IP:53:53/udp" \
  -p 127.0.0.1:8080:80/tcp \
  -p 127.0.0.1:4711:4711/tcp \
  -e TZ="$TZ_VAL" \
  -e FTLCONF_webserver_api_password="$pass" \
  -e WEBPASSWORD="$pass" \
  -e FTLCONF_dns_listeningMode=all \
  -v "$PIHOLE_ROOT/etc-pihole:/etc/pihole" \
  -v "$PIHOLE_ROOT/etc-dnsmasq.d:/etc/dnsmasq.d" \
  --restart unless-stopped \
  --cap-add NET_ADMIN \
  --cap-add SYS_TIME \
  --cap-add SYS_NICE \
  pihole/pihole:latest >/dev/null
EOSH
chmod 755 /usr/local/sbin/tgwst-pihole-container.sh

cat >/etc/systemd/system/tgwst-pihole.service <<'EOSVC'
[Unit]
Description=TGWST Pi-hole Docker Appliance (WSL IP aware)
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/tgwst-pihole-container.sh
ExecStop=/usr/bin/docker rm -f pihole

[Install]
WantedBy=multi-user.target
EOSVC

systemctl daemon-reload
systemctl enable tgwst-pihole.service >/dev/null
systemctl restart tgwst-pihole.service

echo PIHOLE_READY
""";

            var result = await RunWslAsync(
                distro,
                runAsRoot: true,
                command: "bash",
                args: new[] { "-lc", script },
                timeout: LongTimeout,
                ct,
                stdinText: null);

            if (result.ExitCode != 0)
            {
                var reason = FirstMeaningfulLine(result.StdErr) ?? FirstMeaningfulLine(result.StdOut) ?? "Pi-hole installation failed.";
                throw new InvalidOperationException(reason);
            }
        }

        private static async Task<(string[] Distros, string? Error)> QueryDistrosAsync(CancellationToken ct)
        {
            var result = await RunProcessAsync(
                "wsl.exe",
                new[] { "-l", "-q" },
                ShortTimeout,
                ct,
                stdinText: null);

            if (result.ExitCode != 0)
            {
                return (Array.Empty<string>(), FirstMeaningfulLine(result.StdErr) ?? FirstMeaningfulLine(result.StdOut));
            }

            var distros = SplitLines(result.StdOut)
                .Select(SanitizeToken)
                .Where(d => d.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            return distros.Length == 0
                ? (Array.Empty<string>(), "No WSL distributions installed.")
                : (distros, null);
        }

        private static string? SelectPreferredDistro(IReadOnlyList<string> distros)
        {
            if (distros.Count == 0)
            {
                return null;
            }

            var preferred = distros.FirstOrDefault(d => string.Equals(d, "Ubuntu-22.04", StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrWhiteSpace(preferred))
            {
                return preferred;
            }

            preferred = distros.FirstOrDefault(d => d.StartsWith("Ubuntu", StringComparison.OrdinalIgnoreCase));
            return preferred ?? distros[0];
        }

        private static async Task<ProcessResult> RunWslAsync(
            string distro,
            bool runAsRoot,
            string command,
            IReadOnlyList<string> args,
            TimeSpan timeout,
            CancellationToken ct,
            string? stdinText)
        {
            var cli = new List<string> { "--distribution", distro };
            if (runAsRoot)
            {
                cli.Add("--user");
                cli.Add("root");
            }

            cli.Add("--exec");
            cli.Add(command);
            cli.AddRange(args);

            return await RunProcessAsync("wsl.exe", cli, timeout, ct, stdinText);
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

            using var process = new Process { StartInfo = psi, EnableRaisingEvents = true };
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

        private static string[] SplitLines(string text)
        {
            return SanitizeWslText(text)
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Replace('\0', ' ').Trim())
                .Where(line => line.Length > 0)
                .ToArray();
        }

        private static string SanitizeWslText(string? text)
        {
            return string.IsNullOrEmpty(text)
                ? string.Empty
                : text.Replace("\0", string.Empty);
        }

        private static string SanitizeToken(string? value)
        {
            return (value ?? string.Empty).Trim().Trim('\uFEFF');
        }

        private static string? FirstMeaningfulLine(string? text)
        {
            return SplitLines(text ?? string.Empty).FirstOrDefault();
        }

        private static string GetStatePath()
        {
            var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "TGWST");
            Directory.CreateDirectory(root);
            return Path.Combine(root, "bootstrap-state.json");
        }

        private static BootstrapState LoadState()
        {
            var path = GetStatePath();
            if (!File.Exists(path))
            {
                return new BootstrapState();
            }

            try
            {
                var json = File.ReadAllText(path);
                return JsonSerializer.Deserialize<BootstrapState>(json) ?? new BootstrapState();
            }
            catch
            {
                return new BootstrapState();
            }
        }

        private static void SaveState(BootstrapState state)
        {
            var path = GetStatePath();
            var json = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, json, Encoding.UTF8);
        }

        private sealed class BootstrapState
        {
            public bool WizardCompleted { get; set; }
            public DateTimeOffset? CompletedAtUtc { get; set; }
            public string? LastDistro { get; set; }
        }

        private sealed record ProcessResult(int ExitCode, string StdOut, string StdErr);
    }

    public sealed record BootstrapStatus(
        bool IsWslInstalled,
        bool HasDistro,
        string? ResolvedDistro,
        bool BashReachable,
        string? DistroUser,
        string? KernelInfo,
        bool DockerInstalled,
        bool DockerActive,
        bool PiHoleInstalled,
        bool PiHoleBlockingEnabled,
        bool PiHoleFtlReachable,
        string? WslIpAddress,
        bool CredentialsConfigured,
        string? CredentialsUser,
        bool CoreReady,
        bool WizardCompleted,
        string? FailureReason,
        IReadOnlyList<string> AvailableDistros);

    public sealed record BootstrapPlan(
        bool EnsureWslAndUbuntu,
        bool InstallDocker,
        bool InstallPiHole,
        bool SyncWindowsDns,
        string InterfaceAlias,
        bool SaveCredentials,
        string WslUserName,
        string? WslPassword);
}
