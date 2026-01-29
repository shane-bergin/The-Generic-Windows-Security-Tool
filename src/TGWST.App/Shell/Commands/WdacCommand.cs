using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using TGWST.App.ViewModels;
using TGWST.Core.AppControl;
using TGWST.App.Shell;
using TGWST.Core.Audit;
using TGWST.Core.Policies;

namespace TGWST.App.Shell.Commands
{
    public sealed class WdacCommand : ICommandHandler
    {
        private readonly WdacEngine _engine = new();
        private readonly TaskOutputService _outputService;
        private readonly PolicySnapshotStore _snapshots;
        private readonly AuditLogService _audit;

        public WdacCommand(TaskOutputService outputService, PolicySnapshotStore snapshots, AuditLogService audit)
        {
            _outputService = outputService;
            _snapshots = snapshots;
            _audit = audit;
        }

        public string Name => "wdac";
        public string[] Aliases => Array.Empty<string>();

        public async Task ExecuteAsync(string args, ShellViewModel vm)
        {
            var sub = (args ?? string.Empty).Trim();
            if (sub.StartsWith("apply", StringComparison.OrdinalIgnoreCase))
            {
                var tokens = sub.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (tokens.Length < 2)
                {
                    vm.AddOutput("Usage: wdac apply <audit|enforce>\n");
                    return;
                }

                var mode = tokens[1].Trim().ToLowerInvariant();
                var target = mode == "audit"
                    ? "WDAC_Audit_Base.xml"
                    : "WDAC_Enforced_Microsoft_Only.xml";

                var progressVm = _outputService.CreateAndShow($"WDAC Apply - {mode}", vm.AcronymsExpanded);
                progressVm.Append($"Staging policy: {target}\n");
                var correlationId = Guid.NewGuid().ToString("N");

                try
                {
                    if (_engine.TryGetLatestAppliedPolicy(out var applied) && applied != null)
                    {
                        var snapshot = new WdacSnapshot(
                            PolicyId: applied.PolicyId,
                            FriendlyName: applied.FriendlyName,
                            SourcePolicyPath: applied.SourcePolicyPath,
                            EnforceUmci: applied.EnforceUmci,
                            CapturedAtUtc: DateTimeOffset.UtcNow);
                        var snapshotPath = _snapshots.CreateSnapshotPath("WDAC");
                        File.WriteAllText(snapshotPath, JsonSerializer.Serialize(snapshot));
                        _snapshots.SetLatest("WDAC", snapshotPath);
                        _audit.Write("WDAC.Snapshot", $"path={snapshotPath}", correlationId, privileged: true);
                        progressVm.Append("Captured previous WDAC state.\n");
                    }

                    var seed = await Task.Run(() => _engine.EnsureProgramDataWdacPolicies());
                    if (!seed.Success)
                    {
                        progressVm.Append($"[warn] {seed.Message}\n");
                    }

                    var catalog = await Task.Run(() => _engine.EnumeratePolicies());
                    var policy = catalog.Policies.FirstOrDefault(p => string.Equals(Path.GetFileName(p.XmlPath), target, StringComparison.OrdinalIgnoreCase));
                    if (policy == null)
                    {
                        progressVm.Status = "Failed";
                        progressVm.Append("[error] Policy not found in ProgramData.\n");
                        return;
                    }

                    var enforceUmci = mode != "audit";
                    progressVm.Append($"Applying policy: {policy.FriendlyName ?? policy.BaseName}\n");
                    var result = await Task.Run(() => _engine.ApplyPolicy(policy, enforceUmci));
                    if (!result.Success && result.RequiresElevation)
                    {
                        progressVm.Append($"[error] {result.Message}\n");
                        progressVm.Status = "Elevation required";
                        return;
                    }

                    _audit.Write("WDAC.Apply", $"mode={mode} policy={policy.BaseName}", correlationId, privileged: true);
                    progressVm.Append(result.Success ? $"{result.Message}\n" : $"[error] {result.Message}\n");
                    progressVm.Status = result.Success ? "Completed" : "Failed";
                }
                catch (Exception ex)
                {
                    progressVm.Status = "Failed";
                    progressVm.Append($"[error] {ex.Message}\n");
                }

                return;
            }

            if (sub.StartsWith("dev", StringComparison.OrdinalIgnoreCase))
            {
                var tokens = SplitArgs(sub);
                if (tokens.Count < 2)
                {
                    vm.AddOutput("Usage: wdac dev <allow|remove|status> [path] [--base <policyId>]\n");
                    return;
                }

                var action = tokens[1].Trim().ToLowerInvariant();
                if (action == "status")
                {
                    var latest = _snapshots.GetLatest("WDAC_DEV_ALLOW");
                    if (string.IsNullOrWhiteSpace(latest) || !File.Exists(latest))
                    {
                        vm.AddOutput("WDAC Dev Allow: no record found.\n");
                        return;
                    }

                    var record = JsonSerializer.Deserialize<WdacDevAllowRecord>(File.ReadAllText(latest));
                    if (record == null)
                    {
                        vm.AddOutput("WDAC Dev Allow: record could not be parsed.\n");
                        return;
                    }

                    vm.AddOutput("WDAC Dev Allow (latest)\n");
                    vm.AddOutput($"- PolicyId: {record.PolicyId}\n");
                    vm.AddOutput($"- BasePolicyId: {record.BasePolicyId}\n");
                    vm.AddOutput($"- Target: {record.TargetPath}\n");
                    vm.AddOutput($"- Applied: {record.AppliedAtUtc:u}\n");
                    vm.AddOutput($"- XML: {record.XmlPath}\n");
                    vm.AddOutput($"- CIP: {record.CipPath}\n\n");
                    return;
                }

                if (action == "remove")
                {
                    var id = GetOption(tokens, "--id");
                    WdacDevAllowRecord? record = null;
                    if (string.IsNullOrWhiteSpace(id))
                    {
                        var latest = _snapshots.GetLatest("WDAC_DEV_ALLOW");
                        if (!string.IsNullOrWhiteSpace(latest) && File.Exists(latest))
                        {
                            record = JsonSerializer.Deserialize<WdacDevAllowRecord>(File.ReadAllText(latest));
                            id = record?.PolicyId;
                        }
                    }

                    if (string.IsNullOrWhiteSpace(id))
                    {
                        vm.AddOutput("[error] No dev-allow policy id found. Use: wdac dev remove --id <policyId>\n");
                        return;
                    }

                    var allowSystem = tokens.Any(t => string.Equals(t, "--system", StringComparison.OrdinalIgnoreCase));
                    var progressVm = _outputService.CreateAndShow("WDAC Dev Allow - Remove", vm.AcronymsExpanded);
                    progressVm.Append($"Removing policy: {id}\n");
                    var result = await Task.Run(() => _engine.RemovePolicyById(id, allowSystem));
                    if (!result.Success && result.RequiresElevation)
                    {
                        progressVm.Status = "Elevation required";
                        progressVm.Append($"[error] {result.Message}\n");
                        return;
                    }

                    if (!result.Success && result.Message.Contains("system policy", StringComparison.OrdinalIgnoreCase))
                    {
                        progressVm.Status = "Confirmation required";
                        progressVm.Append($"[warn] {result.Message}\n");
                        progressVm.Append("Re-run with: wdac dev remove --id <policyId> --system\n");
                        return;
                    }

                    _audit.Write("WDAC.DevRemove", $"policyId={id}", Guid.NewGuid().ToString("N"), privileged: true);
                    progressVm.Append(result.Success ? $"{result.Message}\n" : $"[error] {result.Message}\n");
                    progressVm.Status = result.Success ? "Completed" : "Failed";

                    if (result.Success && record != null)
                    {
                        TryDelete(record.XmlPath);
                        TryDelete(record.CipPath);
                    }

                    return;
                }

                if (action == "allow")
                {
                    var basePolicyId = GetOption(tokens, "--base");
                    var target = GetTargetPath(tokens, startIndex: 2);
                    target ??= Environment.ProcessPath;

                    if (string.IsNullOrWhiteSpace(target))
                    {
                        vm.AddOutput("[error] No target path provided.\n");
                        return;
                    }

                    if (string.IsNullOrWhiteSpace(basePolicyId))
                    {
                        var (installed, error) = _engine.GetInstalledPolicies();
                        if (!string.IsNullOrWhiteSpace(error))
                        {
                            vm.AddOutput($"[error] CiTool list-policies failed: {error}\n");
                            return;
                        }

                        basePolicyId = installed.FirstOrDefault(p => p.IsEnforced)?.PolicyId
                                       ?? installed.FirstOrDefault()?.PolicyId;
                    }

                    if (string.IsNullOrWhiteSpace(basePolicyId))
                    {
                        vm.AddOutput("[error] No installed WDAC policies found. Apply a base policy first.\n");
                        return;
                    }

                    var progressVm = _outputService.CreateAndShow("WDAC Dev Allow", vm.AcronymsExpanded);
                    progressVm.Append($"Base policy: {basePolicyId}\n");
                    progressVm.Append($"Target: {target}\n");

                    string? xmlPath = null;
                    string? cipPath = null;
                    var result = await Task.Run(() => _engine.CreateSupplementalPolicyForPath(basePolicyId, target, out xmlPath, out cipPath));
                    if (!result.Success && result.RequiresElevation)
                    {
                        progressVm.Status = "Elevation required";
                        progressVm.Append($"[error] {result.Message}\n");
                        progressVm.Append($"Generated: {result.AffectedPath}\n");
                        return;
                    }

                    if (!result.Success)
                    {
                        progressVm.Status = "Failed";
                        progressVm.Append($"[error] {result.Message}\n");
                        if (!string.IsNullOrWhiteSpace(result.Stderr))
                        {
                            progressVm.Append(result.Stderr + "\n");
                        }
                        return;
                    }

                    var record = new WdacDevAllowRecord(
                        PolicyId: result.PolicyId ?? "unknown",
                        BasePolicyId: basePolicyId,
                        TargetPath: target,
                        XmlPath: xmlPath,
                        CipPath: cipPath,
                        AppliedAtUtc: DateTimeOffset.UtcNow);
                    var recordPath = _snapshots.CreateSnapshotPath("WDAC_DEV_ALLOW");
                    File.WriteAllText(recordPath, JsonSerializer.Serialize(record));
                    _snapshots.SetLatest("WDAC_DEV_ALLOW", recordPath);
                    _audit.Write("WDAC.DevAllow", $"policyId={record.PolicyId} target={target}", Guid.NewGuid().ToString("N"), privileged: true);

                    progressVm.Status = "Completed";
                    progressVm.Append($"{result.Message}\n");
                    progressVm.Append($"PolicyId: {record.PolicyId}\n");
                    progressVm.Append($"CIP: {record.CipPath}\n");
                    return;
                }

                vm.AddOutput("Usage: wdac dev <allow|remove|status> [path] [--base <policyId>] [--id <policyId>]\n");
                return;
            }

            if (sub.StartsWith("remove", StringComparison.OrdinalIgnoreCase))
            {
                var allowSystem = sub.Contains("--system", StringComparison.OrdinalIgnoreCase);
                var progressVm = _outputService.CreateAndShow("WDAC Remove Policy", vm.AcronymsExpanded);
                progressVm.Append("Removing TGWST-applied WDAC policy...\n");
                var correlationId = Guid.NewGuid().ToString("N");

                try
                {
                    var result = await Task.Run(() => _engine.RemovePolicy(allowSystemPolicyRemoval: allowSystem));
                    if (!result.Success && result.RequiresElevation)
                    {
                        progressVm.Status = "Elevation required";
                        progressVm.Append($"[error] {result.Message}\n");
                        return;
                    }

                    if (!result.Success && result.Message.Contains("system policy", StringComparison.OrdinalIgnoreCase) && !allowSystem)
                    {
                        progressVm.Status = "Confirmation required";
                        progressVm.Append($"[warn] {result.Message}\n");
                        progressVm.Append("Re-run with: wdac remove --system\n");
                        return;
                    }

                    _audit.Write("WDAC.Remove", $"allowSystem={allowSystem}", correlationId, privileged: true);
                    progressVm.Append(result.Success ? $"{result.Message}\n" : $"[error] {result.Message}\n");
                    progressVm.Status = result.Success ? "Completed" : "Failed";
                }
                catch (Exception ex)
                {
                    progressVm.Status = "Failed";
                    progressVm.Append($"[error] {ex.Message}\n");
                }

                return;
            }

            if (sub.StartsWith("revert", StringComparison.OrdinalIgnoreCase))
            {
                var progressVm = _outputService.CreateAndShow("WDAC Revert", vm.AcronymsExpanded);
                var latest = _snapshots.GetLatest("WDAC");
                if (string.IsNullOrWhiteSpace(latest) || !File.Exists(latest))
                {
                    progressVm.Status = "No snapshot";
                    progressVm.Append("[error] No WDAC snapshot found to revert.\n");
                    return;
                }

                try
                {
                    var snapshot = JsonSerializer.Deserialize<WdacSnapshot>(File.ReadAllText(latest));
                    if (snapshot == null)
                    {
                        progressVm.Status = "Failed";
                        progressVm.Append("[error] Snapshot file is invalid.\n");
                        return;
                    }

                    var catalog = await Task.Run(() => _engine.EnumeratePolicies());
                    var policy = catalog.Policies.FirstOrDefault(p =>
                        string.Equals(p.CipPath, snapshot.SourcePolicyPath, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(p.XmlPath, snapshot.SourcePolicyPath, StringComparison.OrdinalIgnoreCase));

                    if (policy == null)
                    {
                        var import = await Task.Run(() => _engine.ImportPolicy(snapshot.SourcePolicyPath));
                        if (!import.Success)
                        {
                            progressVm.Status = "Failed";
                            progressVm.Append($"[error] Import failed: {import.Message}\n");
                            return;
                        }

                        catalog = await Task.Run(() => _engine.EnumeratePolicies());
                        policy = catalog.Policies.FirstOrDefault(p =>
                            string.Equals(p.CipPath, snapshot.SourcePolicyPath, StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(p.XmlPath, snapshot.SourcePolicyPath, StringComparison.OrdinalIgnoreCase));
                    }

                    if (policy == null)
                    {
                        progressVm.Status = "Failed";
                        progressVm.Append("[error] Snapshot policy could not be located.\n");
                        return;
                    }

                    progressVm.Append($"Re-applying policy: {policy.FriendlyName ?? policy.BaseName}\n");
                    var result = await Task.Run(() => _engine.ApplyPolicy(policy, snapshot.EnforceUmci));
                    if (!result.Success && result.RequiresElevation)
                    {
                        progressVm.Append($"[error] {result.Message}\n");
                        progressVm.Status = "Elevation required";
                        return;
                    }

                    _audit.Write("WDAC.Revert", $"snapshot={latest}", Guid.NewGuid().ToString("N"), privileged: true);
                    progressVm.Append(result.Success ? $"{result.Message}\n" : $"[error] {result.Message}\n");
                    progressVm.Status = result.Success ? "Completed" : "Failed";
                }
                catch (Exception ex)
                {
                    progressVm.Status = "Failed";
                    progressVm.Append($"[error] {ex.Message}\n");
                }

                return;
            }

            if (sub.Equals("status", StringComparison.OrdinalIgnoreCase))
            {
                vm.AddOutput("Windows Defender Application Control\n\n");

                vm.AddOutput("Device Guard / UMCI (WMI)\n");
                var ps = "Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard | Select-Object *";
                var code = await ProcessRunner.RunAsync(
                    "powershell.exe",
                    $"-NoProfile -ExecutionPolicy Bypass -Command \"{ps}\"",
                    vm.AddOutput
                );
                vm.AddOutput($"\n(exit code: {code})\n\n");

                var (installed, error) = _engine.GetInstalledPolicies();
                if (!string.IsNullOrWhiteSpace(error))
                {
                    vm.AddOutput($"[warn] CiTool list-policies failed: {error}\n\n");
                }
                else if (installed.Count == 0)
                {
                    vm.AddOutput("Installed policies: none reported by CiTool.\n\n");
                }
                else
                {
                    vm.AddOutput("Installed policies (CiTool)\n");
                    foreach (var policy in installed)
                    {
                        var enforced = policy.IsEnforced ? "Enforced" : "Audit";
                        var system = policy.IsSystemPolicy ? "System" : "User";
                        vm.AddOutput($"- {policy.FriendlyName ?? policy.PolicyId} [{enforced} | {system} | OnDisk:{policy.IsOnDisk}]\n");
                    }
                    vm.AddOutput("\n");
                }

                if (_engine.TryGetLatestAppliedPolicy(out var applied) && applied != null)
                {
                    vm.AddOutput("TGWST tracked policy\n");
                    vm.AddOutput($"- {applied.FriendlyName ?? applied.PolicyId}\n");
                    vm.AddOutput($"  PolicyId: {applied.PolicyId}\n");
                    vm.AddOutput($"  Source: {applied.SourcePolicyPath}\n");
                    vm.AddOutput($"  Applied: {applied.AppliedAtUtc:u}\n");
                    vm.AddOutput($"  UMCI Enforced: {applied.EnforceUmci}\n\n");
                }

                var catalog = await Task.Run(() => _engine.EnumeratePolicies());
                if (catalog.Policies.Count > 0)
                {
                    vm.AddOutput("Available policies (ProgramData)\n");
                    foreach (var policy in catalog.Policies)
                    {
                        var mode = policy.IsAuditMode ? "Audit" : "Enforce";
                        vm.AddOutput($"- {policy.FriendlyName ?? policy.BaseName} [{mode} | UMCI:{policy.UmciEnabled}]\n");
                    }
                    vm.AddOutput("\n");
                }

                return;
            }

            vm.AddOutput("Usage: wdac status | wdac apply <audit|enforce> | wdac remove [--system] | wdac revert | wdac dev <allow|remove|status>\n");
        }

        private static List<string> SplitArgs(string input)
        {
            var tokens = new List<string>();
            if (string.IsNullOrWhiteSpace(input)) return tokens;

            var sb = new StringBuilder();
            var inQuotes = false;
            foreach (var c in input)
            {
                if (c == '"')
                {
                    inQuotes = !inQuotes;
                    continue;
                }

                if (char.IsWhiteSpace(c) && !inQuotes)
                {
                    if (sb.Length > 0)
                    {
                        tokens.Add(sb.ToString());
                        sb.Clear();
                    }
                    continue;
                }

                sb.Append(c);
            }

            if (sb.Length > 0) tokens.Add(sb.ToString());
            return tokens;
        }

        private static string? GetOption(IReadOnlyList<string> tokens, string name)
        {
            for (var i = 0; i < tokens.Count; i++)
            {
                if (!string.Equals(tokens[i], name, StringComparison.OrdinalIgnoreCase)) continue;
                if (i + 1 < tokens.Count) return tokens[i + 1];
            }

            return null;
        }

        private static string? GetTargetPath(IReadOnlyList<string> tokens, int startIndex)
        {
            for (var i = startIndex; i < tokens.Count; i++)
            {
                if (tokens[i].StartsWith("--", StringComparison.OrdinalIgnoreCase)) continue;
                return tokens[i];
            }

            return null;
        }

        private static void TryDelete(string? path)
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
                    File.Delete(path);
            }
            catch
            {
                // best-effort
            }
        }
    }
}
