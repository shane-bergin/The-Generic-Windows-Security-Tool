using System;
using TGWST.App.ViewModels;
using TGWST.Core.Hardening;
using TGWST.App.Shell;
using TGWST.Core.Audit;
using TGWST.Core.Policies;

namespace TGWST.App.Shell.Commands
{
    public sealed class AsrCommand : ICommandHandler
    {
        private readonly HardeningEngine _engine = new();
        private readonly TaskOutputService _outputService;
        private readonly PolicySnapshotStore _snapshots;
        private readonly AuditLogService _audit;

        public AsrCommand(TaskOutputService outputService, PolicySnapshotStore snapshots, AuditLogService audit)
        {
            _outputService = outputService;
            _snapshots = snapshots;
            _audit = audit;
        }

        public string Name => "asr";
        public string[] Aliases => Array.Empty<string>();

        public async Task ExecuteAsync(string args, ShellViewModel vm)
        {
            var sub = (args ?? string.Empty).Trim();
            if (sub.StartsWith("apply", StringComparison.OrdinalIgnoreCase))
            {
                var tokens = sub.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                var levelText = tokens.Length > 1 ? tokens[1].Trim().ToLowerInvariant() : "balanced";

                var level = levelText switch
                {
                    "aggressive" => HardeningProfileLevel.Aggressive,
                    "strict" => HardeningProfileLevel.Aggressive,
                    "audit" => HardeningProfileLevel.Audit,
                    "revert" => HardeningProfileLevel.Revert,
                    _ => HardeningProfileLevel.Balanced
                };

                var progressVm = _outputService.CreateAndShow($"ASR Baseline - {level}", vm.AcronymsExpanded);
                progressVm.Append($"Starting ASR profile: {level}\n");
                var correlationId = Guid.NewGuid().ToString("N");

                try
                {
                    if (level == HardeningProfileLevel.Revert)
                    {
                        var latest = _snapshots.GetLatest("ASR");
                        if (string.IsNullOrWhiteSpace(latest))
                        {
                            progressVm.Status = "No snapshot";
                            progressVm.Append("[error] No ASR snapshot found to revert.\n");
                            return;
                        }

                        var progress = new Progress<string>(msg => progressVm.Append($"{DateTime.Now:HH:mm:ss} {msg}\n"));
                        await _engine.ApplySnapshotAsync(latest, progress);
                        _audit.Write("ASR.Revert", $"snapshot={latest}", correlationId, privileged: true);
                        progressVm.Status = "Reverted";
                        progressVm.Append("ASR snapshot applied.\n");
                        return;
                    }

                    var snapshotPath = _snapshots.CreateSnapshotPath("ASR");
                    var snapshotProgress = new Progress<string>(msg => progressVm.Append($"{DateTime.Now:HH:mm:ss} {msg}\n"));
                    await _engine.ExportSnapshotAsync(snapshotPath, snapshotProgress);
                    _snapshots.SetLatest("ASR", snapshotPath);
                    _audit.Write("ASR.Snapshot", $"path={snapshotPath}", correlationId, privileged: true);

                    var profile = _engine.GetProfile(level);
                    var applyProgress = new Progress<string>(msg => progressVm.Append($"{DateTime.Now:HH:mm:ss} {msg}\n"));
                    profile = await _engine.ApplyProfileAsync(profile, applyProgress);
                    _audit.Write("ASR.Apply", $"level={level}", correlationId, privileged: true);
                    progressVm.Status = profile.RebootRequired ? "Completed (reboot required)" : "Completed";
                    progressVm.Append("ASR profile applied.\n");
                }
                catch (Exception ex)
                {
                    progressVm.Status = "Failed";
                    progressVm.Append($"[error] {ex.Message}\n");
                }

                return;
            }

            vm.AddOutput("Usage: asr apply <balanced|aggressive|audit|revert>\n");
        }
    }
}
