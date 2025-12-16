using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;

namespace TGWST.Core.AppControl;

public sealed class WdacEngine
{
    private const string EventSource = "TGWST";
    private const string EventLogName = "Application";

    private const string SeedManifestFileName = "wdac-seed-manifest.json";
    private const string AppliedPolicyFileName = "wdac-applied.json";
    private const string GeneratedManifestFileName = "wdac-generated.json";
    private const string ActionLogFileName = "wdac-actions.log";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        WriteIndented = true
    };

    public enum WdacPolicySource
    {
        Shipped,
        Imported,
        Generated
    }

    public sealed record WdacPolicyInfo(
        string BaseName,
        string? FriendlyName,
        string? Version,
        string? PolicyId,
        string? XmlPath,
        string? CipPath,
        bool IsAuditMode,
        bool UmciEnabled,
        WdacPolicySource Source,
        string? SourceDetail,
        string? CollisionWarning)
    {
        public bool HasXml => !string.IsNullOrWhiteSpace(XmlPath);
        public bool HasCip => !string.IsNullOrWhiteSpace(CipPath);
    }

    public sealed record WdacCatalogResult(IReadOnlyList<WdacPolicyInfo> Policies, IReadOnlyList<string> Errors);

    public sealed record WdacEnsurePoliciesResult(
        bool Success,
        string Message,
        IReadOnlyList<string> CopiedFiles,
        IReadOnlyList<string> SkippedFiles,
        IReadOnlyList<string> Errors);

    public sealed record WdacOperationResult(
        bool Success,
        string Message,
        string? AffectedPath = null,
        string? Details = null,
        int? ExitCode = null,
        string? Stdout = null,
        string? Stderr = null,
        bool RequiresElevation = false,
        string? PolicyId = null,
        string? FriendlyName = null,
        string? BaseName = null);

    public sealed record WdacActionLogEntry(
        DateTimeOffset TimestampUtc,
        string Action,
        string? BaseName,
        string? PolicyId,
        bool Success,
        string Message,
        string? Details,
        string? Path,
        string? Source,
        int? ExitCode);

    private sealed record SeedManifest(Dictionary<string, string> Files);

    private sealed record WdacPolicyMetadata(
        string? FriendlyName,
        string? Version,
        string? PolicyId,
        bool AuditMode,
        bool UmciEnabled);

    private sealed record AppliedPolicyRecord(
        string PolicyId,
        string? FriendlyName,
        string SourcePolicyPath,
        DateTimeOffset AppliedAtUtc,
        bool EnforceUmci);

    private sealed record AppliedPolicyStore(List<AppliedPolicyRecord> Policies);

    private sealed record GeneratedManifest(HashSet<string> GeneratedBaseNames);

    private sealed record ProcessRunResult(int ExitCode, string Stdout, string Stderr);

    private sealed class CiToolListPoliciesResponse
    {
        public CiToolPolicy[]? Policies { get; set; }
        public int OperationResult { get; set; }
    }

    private sealed class CiToolPolicy
    {
        public string? PolicyID { get; set; }
        public string? FriendlyName { get; set; }
        public bool IsSystemPolicy { get; set; }
        public bool IsEnforced { get; set; }
        public bool IsOnDisk { get; set; }
    }

    private sealed class CiToolOperationResponse
    {
        public int OperationResult { get; set; }
    }

    public string ProgramFilesPath => GetProgramFilesWdacPath();
    public string ProgramDataPath => GetProgramDataWdacPath();

    public static string GetProgramFilesWdacPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "TGWST", "WDAC");

    public static string GetProgramDataWdacPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "TGWST", "WDAC");

    public WdacEnsurePoliciesResult EnsureProgramDataWdacPolicies()
    {
        var copied = new List<string>();
        var skipped = new List<string>();
        var errors = new List<string>();

        Directory.CreateDirectory(ProgramDataPath);
        var programFilesWdac = ProgramFilesPath;
        if (!Directory.Exists(programFilesWdac))
        {
            return new WdacEnsurePoliciesResult(
                Success: true,
                Message: $"Shipped WDAC folder not found at '{programFilesWdac}'. Nothing to seed.",
                CopiedFiles: copied,
                SkippedFiles: skipped,
                Errors: errors);
        }

        var manifestPath = Path.Combine(ProgramDataPath, SeedManifestFileName);
        var manifest = LoadSeedManifest(manifestPath);

        foreach (var sourcePath in EnumeratePolicyFiles(programFilesWdac))
        {
            var sourceName = Path.GetFileName(sourcePath);
            if (string.IsNullOrWhiteSpace(sourceName)) continue;

            try
            {
                if (manifest.Files.TryGetValue(sourceName, out var mappedDestName) && !string.IsNullOrWhiteSpace(mappedDestName))
                {
                    var mappedDestPath = Path.Combine(ProgramDataPath, mappedDestName);
                    if (File.Exists(mappedDestPath))
                    {
                        skipped.Add(mappedDestName);
                        continue;
                    }

                    var destPath = mappedDestPath;
                    if (File.Exists(destPath))
                        destPath = GetCollisionSafePath(ProgramDataPath, mappedDestName);

                    File.Copy(sourcePath, destPath, overwrite: false);
                    copied.Add(Path.GetFileName(destPath));
                    manifest.Files[sourceName] = Path.GetFileName(destPath);
                    continue;
                }

                var preferredDestPath = Path.Combine(ProgramDataPath, sourceName);
                var actualDestPath = File.Exists(preferredDestPath)
                    ? GetCollisionSafePath(ProgramDataPath, sourceName)
                    : preferredDestPath;

                if (File.Exists(actualDestPath))
                {
                    skipped.Add(Path.GetFileName(actualDestPath));
                    manifest.Files[sourceName] = Path.GetFileName(actualDestPath);
                    continue;
                }

                File.Copy(sourcePath, actualDestPath, overwrite: false);
                copied.Add(Path.GetFileName(actualDestPath));
                manifest.Files[sourceName] = Path.GetFileName(actualDestPath);
            }
            catch (Exception ex)
            {
                var msg = $"{sourceName}: {ex.Message}";
                errors.Add(msg);
                LogEvent($"WDAC seed failed for '{sourceName}': {ex}", EventLogEntryType.Error);
            }
        }

        SaveSeedManifest(manifestPath, manifest);

        var message = copied.Count > 0
            ? $"Seeded {copied.Count} WDAC file(s) into '{ProgramDataPath}'."
            : "WDAC policies already seeded.";

        return new WdacEnsurePoliciesResult(errors.Count == 0, message, copied, skipped, errors);
    }

    public WdacCatalogResult EnumeratePolicies()
    {
        var errors = new List<string>();

        try
        {
            Directory.CreateDirectory(ProgramDataPath);
            if (!Directory.Exists(ProgramDataPath)) return new WdacCatalogResult(Array.Empty<WdacPolicyInfo>(), errors);

            var manifest = LoadSeedManifest(Path.Combine(ProgramDataPath, SeedManifestFileName));
            var generated = LoadGeneratedManifest(Path.Combine(ProgramDataPath, GeneratedManifestFileName));
            var entries = new List<WdacPolicyInfo>();

            var xml = Directory.EnumerateFiles(ProgramDataPath, "*.xml", SearchOption.TopDirectoryOnly);
            var cip = Directory.EnumerateFiles(ProgramDataPath, "*.cip", SearchOption.TopDirectoryOnly);

            var groups = xml.Concat(cip)
                .Where(File.Exists)
                .GroupBy(p => Path.GetFileNameWithoutExtension(p), StringComparer.OrdinalIgnoreCase);

            foreach (var g in groups)
            {
                var baseName = g.Key ?? "Unknown";
                var xmlPath = g.FirstOrDefault(p => string.Equals(Path.GetExtension(p), ".xml", StringComparison.OrdinalIgnoreCase));
                var cipPath = g.FirstOrDefault(p => string.Equals(Path.GetExtension(p), ".cip", StringComparison.OrdinalIgnoreCase));

                var xmlMeta = TryReadMetadataFromXml(xmlPath, errors);
                var cipMeta = TryReadMetadataFromCip(cipPath, errors);
                var primaryMeta = xmlMeta ?? cipMeta ?? new WdacPolicyMetadata(null, null, null, AuditMode: false, UmciEnabled: false);

                string? collision = null;
                if (xmlMeta != null && cipMeta != null && !string.Equals(xmlMeta.PolicyId, cipMeta.PolicyId, StringComparison.OrdinalIgnoreCase))
                {
                    collision = $"XML PolicyID ({xmlMeta.PolicyId ?? "unknown"}) != CIP PolicyID ({cipMeta.PolicyId ?? "unknown"})";
                }

                var source = DetermineSource(baseName, xmlPath, cipPath, manifest, generated);

                entries.Add(new WdacPolicyInfo(
                    BaseName: baseName,
                    FriendlyName: primaryMeta.FriendlyName,
                    Version: primaryMeta.Version,
                    PolicyId: primaryMeta.PolicyId,
                    XmlPath: xmlPath,
                    CipPath: cipPath,
                    IsAuditMode: primaryMeta.AuditMode,
                    UmciEnabled: primaryMeta.UmciEnabled,
                    Source: source.source,
                    SourceDetail: source.detail,
                    CollisionWarning: collision));
            }

            // Detect collisions by PolicyId
            var duplicatePolicyIds = entries
                .Where(e => !string.IsNullOrWhiteSpace(e.PolicyId))
                .GroupBy(e => e.PolicyId!, StringComparer.OrdinalIgnoreCase)
                .Where(g => g.Count() > 1);

            foreach (var dup in duplicatePolicyIds)
            {
                var list = dup.Select(d => d.BaseName).ToArray();
                var note = $"PolicyID {dup.Key} is shared by: {string.Join(", ", list)}";
                foreach (var entry in entries.Where(e => string.Equals(e.PolicyId, dup.Key, StringComparison.OrdinalIgnoreCase)))
                {
                    entries[entries.IndexOf(entry)] = entry with { CollisionWarning = string.IsNullOrWhiteSpace(entry.CollisionWarning) ? note : $"{entry.CollisionWarning}; {note}" };
                }
            }

            var ordered = entries
                .OrderBy(e => e.Source)
                .ThenBy(e => e.BaseName, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            return new WdacCatalogResult(ordered, errors);
        }
        catch (Exception ex)
        {
            var msg = $"EnumeratePolicies failed: {ex.Message}";
            errors.Add(msg);
            LogEvent($"EnumeratePolicies failed: {ex}", EventLogEntryType.Error);
            return new WdacCatalogResult(Array.Empty<WdacPolicyInfo>(), errors);
        }
    }

    public WdacOperationResult ImportPolicy(string sourcePath)
    {
        WdacOperationResult result;
        string? baseName = null;
        string? policyId = null;
        string? friendly = null;

        try
        {
            if (string.IsNullOrWhiteSpace(sourcePath))
                return new WdacOperationResult(false, "No policy path provided.");

            if (!File.Exists(sourcePath))
                return new WdacOperationResult(false, "Policy file not found.", AffectedPath: sourcePath);

            var ext = Path.GetExtension(sourcePath);
            if (!string.Equals(ext, ".xml", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(ext, ".cip", StringComparison.OrdinalIgnoreCase))
            {
                return new WdacOperationResult(false, "Only .xml and .cip policies are supported.", AffectedPath: sourcePath);
            }

            Directory.CreateDirectory(ProgramDataPath);
            var safeName = Path.GetFileName(sourcePath);
            if (string.IsNullOrWhiteSpace(safeName))
                return new WdacOperationResult(false, "Invalid policy file name.", AffectedPath: sourcePath);

            var destPath = GetCollisionSafePath(ProgramDataPath, safeName);
            File.Copy(sourcePath, destPath, overwrite: false);

            baseName = Path.GetFileNameWithoutExtension(destPath) ?? safeName;
            var meta = string.Equals(ext, ".xml", StringComparison.OrdinalIgnoreCase)
                ? TryReadMetadataFromXml(destPath)
                : TryReadMetadataFromCip(destPath);

            policyId = meta?.PolicyId;
            friendly = meta?.FriendlyName;

            LogEvent($"Imported WDAC policy: {sourcePath} -> {destPath}", EventLogEntryType.Information);
            result = new WdacOperationResult(true, "Policy imported.", AffectedPath: destPath, PolicyId: policyId, FriendlyName: friendly, BaseName: baseName);
        }
        catch (Exception ex)
        {
            LogEvent($"ImportPolicy failed for {sourcePath}: {ex}", EventLogEntryType.Error);
            result = new WdacOperationResult(false, $"Import failed: {ex.Message}", AffectedPath: sourcePath, Details: ex.ToString(), BaseName: baseName);
        }

        AppendActionLog(new WdacActionLogEntry(
            TimestampUtc: DateTimeOffset.UtcNow,
            Action: "import",
            BaseName: result.BaseName ?? baseName,
            PolicyId: result.PolicyId ?? policyId,
            Success: result.Success,
            Message: result.Message,
            Details: result.Details,
            Path: result.AffectedPath ?? sourcePath,
            Source: "import",
            ExitCode: result.ExitCode));

        return result;
    }

    public WdacOperationResult ExportPolicy(WdacPolicyInfo policy, string destinationPath)
    {
        WdacOperationResult result;
        var baseName = policy.BaseName;
        string? resolvedDest = null;

        try
        {
            var source = policy.CipPath ?? policy.XmlPath;
            if (string.IsNullOrWhiteSpace(source) || !File.Exists(source))
            {
                result = new WdacOperationResult(false, "No policy file to export (generate or import a CIP/XML first).", BaseName: baseName, PolicyId: policy.PolicyId, FriendlyName: policy.FriendlyName);
                AppendActionLog(new WdacActionLogEntry(DateTimeOffset.UtcNow, "export", baseName, result.PolicyId, result.Success, result.Message, result.Details, destinationPath, "export", null));
                return result;
            }

            if (string.IsNullOrWhiteSpace(destinationPath))
            {
                result = new WdacOperationResult(false, "No destination selected.", BaseName: baseName, PolicyId: policy.PolicyId, FriendlyName: policy.FriendlyName);
                AppendActionLog(new WdacActionLogEntry(DateTimeOffset.UtcNow, "export", baseName, result.PolicyId, result.Success, result.Message, result.Details, destinationPath, "export", null));
                return result;
            }

            if (Directory.Exists(destinationPath))
            {
                destinationPath = Path.Combine(destinationPath, Path.GetFileName(source));
            }

            var destDir = Path.GetDirectoryName(destinationPath);
            if (!string.IsNullOrWhiteSpace(destDir))
                Directory.CreateDirectory(destDir);

            resolvedDest = File.Exists(destinationPath)
                ? GetCollisionSafePath(destDir ?? ProgramDataPath, Path.GetFileName(destinationPath) ?? Path.GetFileName(source))
                : destinationPath;

            File.Copy(source, resolvedDest, overwrite: false);
            result = new WdacOperationResult(true, $"Exported policy to {resolvedDest}", AffectedPath: resolvedDest, BaseName: baseName, PolicyId: policy.PolicyId, FriendlyName: policy.FriendlyName);
        }
        catch (Exception ex)
        {
            result = new WdacOperationResult(false, $"Export failed: {ex.Message}", AffectedPath: resolvedDest ?? destinationPath, Details: ex.ToString(), BaseName: baseName, PolicyId: policy.PolicyId, FriendlyName: policy.FriendlyName);
        }

        AppendActionLog(new WdacActionLogEntry(
            TimestampUtc: DateTimeOffset.UtcNow,
            Action: "export",
            BaseName: baseName,
            PolicyId: result.PolicyId,
            Success: result.Success,
            Message: result.Message,
            Details: result.Stderr ?? result.Details,
            Path: result.AffectedPath ?? resolvedDest ?? destinationPath,
            Source: "export",
            ExitCode: result.ExitCode));

        return result;
    }

    public WdacOperationResult CompileXmlToCip(string xmlPath, out string? cipPath)
    {
        cipPath = null;
        WdacOperationResult result;

        try
        {
            if (string.IsNullOrWhiteSpace(xmlPath))
                return new WdacOperationResult(false, "No XML policy path provided.");

            if (!File.Exists(xmlPath))
                return new WdacOperationResult(false, "XML policy file not found.", AffectedPath: xmlPath);

            if (!string.Equals(Path.GetExtension(xmlPath), ".xml", StringComparison.OrdinalIgnoreCase))
                return new WdacOperationResult(false, "Compile requires an .xml policy file.", AffectedPath: xmlPath);

            var metaErrors = new List<string>();
            var meta = TryReadMetadataFromXml(xmlPath, metaErrors);
            if (meta == null)
            {
                var detail = metaErrors.FirstOrDefault() ?? "The XML file could not be parsed as a WDAC policy.";
                result = new WdacOperationResult(false, $"Cannot compile: {detail}", AffectedPath: xmlPath, Details: detail);
                AppendActionLog(new WdacActionLogEntry(DateTimeOffset.UtcNow, "compile", Path.GetFileNameWithoutExtension(xmlPath), null, result.Success, result.Message, result.Details, xmlPath, "compile", null));
                return result;
            }

            if (string.IsNullOrWhiteSpace(meta.PolicyId))
            {
                result = new WdacOperationResult(false, "Cannot compile: PolicyID is missing from the XML.", AffectedPath: xmlPath, Details: "Add a <PolicyID> element to the XML policy.");
                AppendActionLog(new WdacActionLogEntry(DateTimeOffset.UtcNow, "compile", Path.GetFileNameWithoutExtension(xmlPath), null, result.Success, result.Message, result.Details, xmlPath, "compile", null));
                return result;
            }

            var outputCip = Path.ChangeExtension(xmlPath, ".cip");
            var tempCip = Path.Combine(Path.GetTempPath(), $"tgwst_{Path.GetFileNameWithoutExtension(xmlPath)}_{Guid.NewGuid():N}.cip");

            var script = $"ConvertFrom-CIPolicy -XmlFilePath '{EscapePwsh(xmlPath)}' -BinaryFilePath '{EscapePwsh(tempCip)}'";
            ProcessRunResult ps = new(0, string.Empty, string.Empty);
            try
            {
                ps = RunPowerShell(script);
                if (ps.ExitCode != 0 || !File.Exists(tempCip))
                {
                    result = new WdacOperationResult(
                        Success: false,
                        Message: "Failed to compile XML policy to CIP.",
                        AffectedPath: xmlPath,
                        ExitCode: ps.ExitCode,
                        Stdout: ps.Stdout,
                        Stderr: ps.Stderr,
                        PolicyId: meta.PolicyId,
                        FriendlyName: meta.FriendlyName,
                        BaseName: Path.GetFileNameWithoutExtension(xmlPath));

                    return result;
                }

                Directory.CreateDirectory(Path.GetDirectoryName(outputCip) ?? ProgramDataPath);
                File.Copy(tempCip, outputCip, overwrite: true);
                cipPath = outputCip;

                LogEvent($"Compiled WDAC XML -> CIP: {xmlPath} -> {outputCip}", EventLogEntryType.Information);
                var generated = LoadGeneratedManifest(Path.Combine(ProgramDataPath, GeneratedManifestFileName));
                generated.GeneratedBaseNames.Add(Path.GetFileNameWithoutExtension(xmlPath) ?? outputCip);
                SaveGeneratedManifest(Path.Combine(ProgramDataPath, GeneratedManifestFileName), generated);

                result = new WdacOperationResult(
                    Success: true,
                    Message: "Compiled XML policy to CIP.",
                    AffectedPath: outputCip,
                    ExitCode: ps.ExitCode,
                    Stdout: ps.Stdout,
                    Stderr: ps.Stderr,
                    PolicyId: meta.PolicyId,
                    FriendlyName: meta.FriendlyName,
                    BaseName: Path.GetFileNameWithoutExtension(xmlPath));
            }
            finally
            {
                TryDelete(tempCip);
            }
        }
        catch (Exception ex)
        {
            LogEvent($"CompileXmlToCip failed for {xmlPath}: {ex}", EventLogEntryType.Error);
            result = new WdacOperationResult(false, $"Compile failed: {ex.Message}", AffectedPath: xmlPath, Details: ex.ToString(), BaseName: Path.GetFileNameWithoutExtension(xmlPath));
        }

        AppendActionLog(new WdacActionLogEntry(
            TimestampUtc: DateTimeOffset.UtcNow,
            Action: "compile",
            BaseName: result.BaseName ?? Path.GetFileNameWithoutExtension(xmlPath),
            PolicyId: result.PolicyId,
            Success: result.Success,
            Message: result.Message,
            Details: result.Stderr ?? result.Details,
            Path: cipPath ?? xmlPath,
            Source: "compile",
            ExitCode: result.ExitCode));
        return result;
    }

    public WdacOperationResult ApplyPolicy(WdacPolicyInfo selectedPolicy, bool enforceUmci)
    {
        WdacOperationResult result;
        try
        {
            if (!IsAdministrator())
            {
                result = new WdacOperationResult(
                    Success: false,
                    Message: "Applying a WDAC policy requires Administrator rights. Re-run TGWST as Administrator.",
                    RequiresElevation: true,
                    BaseName: selectedPolicy.BaseName,
                    PolicyId: selectedPolicy.PolicyId,
                    FriendlyName: selectedPolicy.FriendlyName);
                AppendActionLog(new WdacActionLogEntry(DateTimeOffset.UtcNow, "apply", result.BaseName, result.PolicyId, result.Success, result.Message, result.Details, selectedPolicy.CipPath ?? selectedPolicy.XmlPath, "apply", null));
                return result;
            }

            var sourceCipPath = selectedPolicy.CipPath;
            if (string.IsNullOrWhiteSpace(sourceCipPath))
            {
                if (string.IsNullOrWhiteSpace(selectedPolicy.XmlPath))
                {
                    result = new WdacOperationResult(false, "Selected policy has no XML or CIP to apply.", BaseName: selectedPolicy.BaseName);
                    AppendActionLog(new WdacActionLogEntry(DateTimeOffset.UtcNow, "apply", result.BaseName, result.PolicyId, result.Success, result.Message, result.Details, null, "apply", null));
                    return result;
                }

                var compile = CompileXmlToCip(selectedPolicy.XmlPath, out var compiledCip);
                if (!compile.Success || string.IsNullOrWhiteSpace(compiledCip))
                {
                    var applyFail = compile with { Message = $"Apply failed: {compile.Message}", BaseName = selectedPolicy.BaseName ?? compile.BaseName };
                    AppendActionLog(new WdacActionLogEntry(DateTimeOffset.UtcNow, "apply", applyFail.BaseName, applyFail.PolicyId, applyFail.Success, applyFail.Message, applyFail.Stderr ?? applyFail.Details, compiledCip ?? selectedPolicy.XmlPath, "apply", applyFail.ExitCode));
                    return applyFail;
                }

                sourceCipPath = compiledCip;
            }

            if (!File.Exists(sourceCipPath))
            {
                result = new WdacOperationResult(false, "Policy file not found.", AffectedPath: sourceCipPath, BaseName: selectedPolicy.BaseName);
                AppendActionLog(new WdacActionLogEntry(DateTimeOffset.UtcNow, "apply", result.BaseName, result.PolicyId, result.Success, result.Message, result.Details, sourceCipPath, "apply", null));
                return result;
            }

            var meta = TryReadMetadataFromCip(sourceCipPath) ?? TryReadMetadataFromXml(selectedPolicy.XmlPath);
            var tempCip = Path.Combine(Path.GetTempPath(), $"tgwst_apply_{Guid.NewGuid():N}.cip");
            ProcessRunResult ci = new(0, string.Empty, string.Empty);
            try
            {
                File.Copy(sourceCipPath, tempCip, overwrite: true);

                var modeScript = enforceUmci
                    ? $"Set-RuleOption -FilePath '{EscapePwsh(tempCip)}' -Option 0;"
                    : $"Set-RuleOption -FilePath '{EscapePwsh(tempCip)}' -Option 0 -Delete;";

                var setMode = RunPowerShell(modeScript);
                if (setMode.ExitCode != 0)
                {
                    result = new WdacOperationResult(
                        Success: false,
                        Message: "Failed to set policy options (UMCI).",
                        AffectedPath: sourceCipPath,
                        ExitCode: setMode.ExitCode,
                        Stdout: setMode.Stdout,
                        Stderr: setMode.Stderr,
                        PolicyId: meta?.PolicyId ?? selectedPolicy.PolicyId,
                        FriendlyName: meta?.FriendlyName ?? selectedPolicy.FriendlyName,
                        BaseName: selectedPolicy.BaseName);

                    AppendActionLog(new WdacActionLogEntry(DateTimeOffset.UtcNow, "apply", result.BaseName, result.PolicyId, result.Success, result.Message, result.Stderr ?? result.Details, sourceCipPath, "apply", setMode.ExitCode));
                    return result;
                }

                ci = RunCiTool($"--update-policy \"{tempCip}\" --json");

                var op = TryParseCiToolOperation(ci.Stdout);
                if (ci.ExitCode != 0 || (op.HasValue && op.Value != 0))
                {
                    LogEvent($"CiTool update-policy failed: exit={ci.ExitCode} op={op} stderr={ci.Stderr} stdout={ci.Stdout}", EventLogEntryType.Error);
                    result = new WdacOperationResult(
                        Success: false,
                        Message: "Failed to apply WDAC policy.",
                        AffectedPath: sourceCipPath,
                        ExitCode: ci.ExitCode,
                        Stdout: ci.Stdout,
                        Stderr: ci.Stderr,
                        PolicyId: meta?.PolicyId ?? selectedPolicy.PolicyId,
                        FriendlyName: meta?.FriendlyName ?? selectedPolicy.FriendlyName,
                        BaseName: selectedPolicy.BaseName);

                    AppendActionLog(new WdacActionLogEntry(DateTimeOffset.UtcNow, "apply", result.BaseName, result.PolicyId, result.Success, result.Message, result.Stderr ?? result.Details, sourceCipPath, "apply", ci.ExitCode));
                    return result;
                }

                if (!string.IsNullOrWhiteSpace(meta?.PolicyId))
                {
                    var store = LoadAppliedPolicies();
                    store.Policies.RemoveAll(p => string.Equals(p.PolicyId, meta.PolicyId, StringComparison.OrdinalIgnoreCase));
                    store.Policies.Add(new AppliedPolicyRecord(
                        PolicyId: meta.PolicyId!,
                        FriendlyName: meta.FriendlyName ?? selectedPolicy.FriendlyName,
                        SourcePolicyPath: sourceCipPath,
                        AppliedAtUtc: DateTimeOffset.UtcNow,
                        EnforceUmci: enforceUmci));
                    SaveAppliedPolicies(store);
                }
            }
            finally
            {
                TryDelete(tempCip);
            }

            LogEvent($"Applied WDAC policy {sourceCipPath} (UMCI {(enforceUmci ? "Enabled" : "Disabled")})", EventLogEntryType.Information);
            result = new WdacOperationResult(
                Success: true,
                Message: "WDAC policy applied.",
                AffectedPath: sourceCipPath,
                ExitCode: ci.ExitCode,
                Stdout: ci.Stdout,
                Stderr: ci.Stderr,
                PolicyId: meta?.PolicyId ?? selectedPolicy.PolicyId,
                FriendlyName: meta?.FriendlyName ?? selectedPolicy.FriendlyName,
                BaseName: selectedPolicy.BaseName);
        }
        catch (Exception ex)
        {
            LogEvent($"ApplyPolicy failed: {ex}", EventLogEntryType.Error);
            result = new WdacOperationResult(false, $"Apply failed: {ex.Message}", Details: ex.ToString(), BaseName: selectedPolicy.BaseName);
        }

        AppendActionLog(new WdacActionLogEntry(
            TimestampUtc: DateTimeOffset.UtcNow,
            Action: "apply",
            BaseName: result.BaseName ?? selectedPolicy.BaseName,
            PolicyId: result.PolicyId,
            Success: result.Success,
            Message: result.Message,
            Details: result.Stderr ?? result.Details,
            Path: result.AffectedPath ?? selectedPolicy.CipPath ?? selectedPolicy.XmlPath,
            Source: "apply",
            ExitCode: result.ExitCode));
        return result;
    }

    public WdacOperationResult RemovePolicy(bool allowSystemPolicyRemoval = false)
    {
        WdacOperationResult result;
        try
        {
            if (!IsAdministrator())
            {
                result = new WdacOperationResult(
                    Success: false,
                    Message: "Removing a WDAC policy requires Administrator rights. Re-run TGWST as Administrator.",
                    RequiresElevation: true);
                AppendActionLog(new WdacActionLogEntry(DateTimeOffset.UtcNow, "remove", null, null, result.Success, result.Message, result.Details, null, "remove", null));
                return result;
            }

            var store = LoadAppliedPolicies();
            if (store.Policies.Count == 0)
            {
                result = new WdacOperationResult(false, "No TGWST-applied WDAC policies are tracked. Apply a policy first.");
                AppendActionLog(new WdacActionLogEntry(DateTimeOffset.UtcNow, "remove", null, null, result.Success, result.Message, result.Details, null, "remove", null));
                return result;
            }

            var record = store.Policies.OrderByDescending(p => p.AppliedAtUtc).First();
            var installed = ListPolicies();
            var match = installed.FirstOrDefault(p => string.Equals(p.PolicyID, record.PolicyId, StringComparison.OrdinalIgnoreCase));
            if (match != null && match.IsSystemPolicy && !allowSystemPolicyRemoval)
            {
                result = new WdacOperationResult(
                    false,
                    $"The applied policy '{match.FriendlyName}' ({record.PolicyId}) is a system policy. Removing it can affect Windows security features. Confirm removal to proceed.",
                    PolicyId: record.PolicyId,
                    FriendlyName: match.FriendlyName);
                AppendActionLog(new WdacActionLogEntry(DateTimeOffset.UtcNow, "remove", null, result.PolicyId, result.Success, result.Message, result.Details, record.SourcePolicyPath, "remove", null));
                return result;
            }

            if (match == null)
            {
                store.Policies.RemoveAll(p => string.Equals(p.PolicyId, record.PolicyId, StringComparison.OrdinalIgnoreCase));
                SaveAppliedPolicies(store);
                result = new WdacOperationResult(true, $"Tracked policy {record.PolicyId} is not installed. Cleared TGWST tracking.", PolicyId: record.PolicyId, FriendlyName: record.FriendlyName);
                AppendActionLog(new WdacActionLogEntry(DateTimeOffset.UtcNow, "remove", null, result.PolicyId, result.Success, result.Message, result.Details, record.SourcePolicyPath, "remove", null));
                return result;
            }

            var remove = RunCiTool($"--remove-policy {record.PolicyId} --json");
            var op = TryParseCiToolOperation(remove.Stdout);
            if (remove.ExitCode != 0 || (op.HasValue && op.Value != 0))
            {
                result = new WdacOperationResult(false, "Failed to remove WDAC policy.", ExitCode: remove.ExitCode, Stdout: remove.Stdout, Stderr: remove.Stderr, PolicyId: record.PolicyId, FriendlyName: record.FriendlyName);
                AppendActionLog(new WdacActionLogEntry(DateTimeOffset.UtcNow, "remove", null, result.PolicyId, result.Success, result.Message, result.Stderr ?? result.Details, record.SourcePolicyPath, "remove", remove.ExitCode));
                return result;
            }

            store.Policies.RemoveAll(p => string.Equals(p.PolicyId, record.PolicyId, StringComparison.OrdinalIgnoreCase));
            SaveAppliedPolicies(store);
            RunCiTool("--refresh --json");

            LogEvent($"Removed WDAC policy {record.PolicyId}", match.IsSystemPolicy ? EventLogEntryType.Warning : EventLogEntryType.Information);
            result = new WdacOperationResult(true, "WDAC policy removed.", Stdout: remove.Stdout, Stderr: remove.Stderr, PolicyId: record.PolicyId, FriendlyName: record.FriendlyName);
        }
        catch (Exception ex)
        {
            LogEvent($"RemovePolicy failed: {ex}", EventLogEntryType.Error);
            result = new WdacOperationResult(false, $"Remove failed: {ex.Message}", Details: ex.ToString());
        }

        AppendActionLog(new WdacActionLogEntry(
            TimestampUtc: DateTimeOffset.UtcNow,
            Action: "remove",
            BaseName: null,
            PolicyId: result.PolicyId,
            Success: result.Success,
            Message: result.Message,
            Details: result.Stderr ?? result.Details,
            Path: null,
            Source: "remove",
            ExitCode: result.ExitCode));
        return result;
    }

    private GeneratedManifest LoadGeneratedManifest(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                var manifest = JsonSerializer.Deserialize<GeneratedManifest>(File.ReadAllText(path), JsonOptions);
                if (manifest?.GeneratedBaseNames != null)
                    return new GeneratedManifest(new HashSet<string>(manifest.GeneratedBaseNames, StringComparer.OrdinalIgnoreCase));
            }
        }
        catch
        {
            // ignore
        }

        return new GeneratedManifest(new HashSet<string>(StringComparer.OrdinalIgnoreCase));
    }

    private void SaveGeneratedManifest(string path, GeneratedManifest manifest)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ProgramDataPath);
            File.WriteAllText(path, JsonSerializer.Serialize(manifest, JsonOptions));
        }
        catch
        {
            // best-effort
        }
    }

    private AppliedPolicyStore LoadAppliedPolicies()
    {
        try
        {
            var path = Path.Combine(ProgramDataPath, AppliedPolicyFileName);
            if (!File.Exists(path)) return new AppliedPolicyStore(new List<AppliedPolicyRecord>());

            var text = File.ReadAllText(path);
            var store = JsonSerializer.Deserialize<AppliedPolicyStore>(text, JsonOptions);
            if (store?.Policies != null)
                return new AppliedPolicyStore(store.Policies);

            // Legacy single-record format
            var legacy = JsonSerializer.Deserialize<AppliedPolicyRecord>(text, JsonOptions);
            if (legacy != null)
                return new AppliedPolicyStore(new List<AppliedPolicyRecord> { legacy });
        }
        catch
        {
            // ignore; fall through
        }

        return new AppliedPolicyStore(new List<AppliedPolicyRecord>());
    }

    private void SaveAppliedPolicies(AppliedPolicyStore store)
    {
        try
        {
            Directory.CreateDirectory(ProgramDataPath);
            var path = Path.Combine(ProgramDataPath, AppliedPolicyFileName);
            File.WriteAllText(path, JsonSerializer.Serialize(store, JsonOptions));
        }
        catch
        {
            // best-effort
        }
    }

    private (WdacPolicySource source, string detail) DetermineSource(
        string baseName,
        string? xmlPath,
        string? cipPath,
        SeedManifest seedManifest,
        GeneratedManifest generatedManifest)
    {
        var fileNames = new[]
        {
            Path.GetFileName(xmlPath) ?? string.Empty,
            Path.GetFileName(cipPath) ?? string.Empty
        };

        if (fileNames.Any(f => seedManifest.Files.Values.Contains(f, StringComparer.OrdinalIgnoreCase)))
            return (WdacPolicySource.Shipped, "Shipped with TGWST");

        if (generatedManifest.GeneratedBaseNames.Contains(baseName))
            return (WdacPolicySource.Generated, "Generated from XML on this device");

        return (WdacPolicySource.Imported, "Imported by user");
    }

    private static WdacPolicyMetadata? TryReadMetadataFromXml(string? xmlPath, List<string>? errors = null)
    {
        if (string.IsNullOrWhiteSpace(xmlPath) || !File.Exists(xmlPath)) return null;

        try
        {
            var doc = XDocument.Load(xmlPath);
            var ns = doc.Root?.Name.Namespace ?? XNamespace.None;
            var friendly = doc.Root?.Attribute("FriendlyName")?.Value?.Trim();
            var version = doc.Descendants(ns + "VersionEx").FirstOrDefault()?.Value?.Trim();
            var policyId = doc.Descendants(ns + "PolicyID").FirstOrDefault()?.Value?.Trim();
            if (string.IsNullOrWhiteSpace(policyId))
                policyId = doc.Descendants(ns + "PolicyTypeID").FirstOrDefault()?.Value?.Trim();

            var rules = doc.Descendants(ns + "Rule").Select(r => r.Element(ns + "Option")?.Value?.Trim()).Where(v => !string.IsNullOrWhiteSpace(v)).ToArray();
            var audit = rules.Any(r => string.Equals(r, "Enabled:Audit Mode", StringComparison.OrdinalIgnoreCase));
            var umci = rules.Any(r => string.Equals(r, "Enabled:UMCI", StringComparison.OrdinalIgnoreCase));

            return new WdacPolicyMetadata(friendly, version, policyId, audit, umci);
        }
        catch (Exception ex)
        {
            errors?.Add($"Failed to read XML metadata for {xmlPath}: {ex.Message}");
            return null;
        }
    }

    private static WdacPolicyMetadata? TryReadMetadataFromCip(string? cipPath, List<string>? errors = null)
    {
        if (string.IsNullOrWhiteSpace(cipPath) || !File.Exists(cipPath)) return null;

        var tmpXml = Path.Combine(Path.GetTempPath(), $"tgwst_meta_{Guid.NewGuid():N}.xml");
        var script = $"ConvertFrom-CIPolicy -BinaryFilePath '{EscapePwsh(cipPath)}' -XmlFilePath '{EscapePwsh(tmpXml)}'";
        var ps = RunPowerShell(script);
        if (ps.ExitCode != 0 || !File.Exists(tmpXml))
        {
            TryDelete(tmpXml);
            errors?.Add($"Failed to expand CIP for metadata ({Path.GetFileName(cipPath)}): exit {ps.ExitCode}, stderr: {ps.Stderr}".Trim());
            return null;
        }

        try
        {
            return TryReadMetadataFromXml(tmpXml, errors);
        }
        finally
        {
            TryDelete(tmpXml);
        }
    }

    public (WdacActionLogEntry? LastAction, WdacActionLogEntry? LastError) GetLastActionAndError()
    {
        try
        {
            var path = Path.Combine(ProgramDataPath, ActionLogFileName);
            if (!File.Exists(path)) return (null, null);

            WdacActionLogEntry? lastAction = null;
            WdacActionLogEntry? lastError = null;

            foreach (var line in File.ReadLines(path))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var entry = JsonSerializer.Deserialize<WdacActionLogEntry>(line, JsonOptions);
                if (entry == null) continue;
                lastAction = entry;
                if (!entry.Success) lastError = entry;
            }

            return (lastAction, lastError);
        }
        catch
        {
            return (null, null);
        }
    }

    private void AppendActionLog(WdacActionLogEntry entry)
    {
        try
        {
            Directory.CreateDirectory(ProgramDataPath);
            var path = Path.Combine(ProgramDataPath, ActionLogFileName);
            var json = JsonSerializer.Serialize(entry, JsonOptions);
            File.AppendAllText(path, json + Environment.NewLine);
        }
        catch
        {
            // best-effort
        }
    }

    private static string GetCollisionSafePath(string directory, string fileName)
    {
        Directory.CreateDirectory(directory);
        var name = Path.GetFileNameWithoutExtension(fileName);
        var ext = Path.GetExtension(fileName);
        var candidate = Path.Combine(directory, fileName);
        var counter = 1;

        while (File.Exists(candidate))
        {
            candidate = Path.Combine(directory, $"{name} ({counter}){ext}");
            counter++;
        }

        return candidate;
    }

    private static IEnumerable<string> EnumeratePolicyFiles(string directory)
    {
        if (!Directory.Exists(directory)) yield break;

        foreach (var pattern in new[] { "*.xml", "*.cip", "*.json" })
        {
            foreach (var file in Directory.EnumerateFiles(directory, pattern, SearchOption.TopDirectoryOnly))
                yield return file;
        }
    }

    private static SeedManifest LoadSeedManifest(string path)
    {
        try
        {
            if (!File.Exists(path))
                return new SeedManifest(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));

            var manifest = JsonSerializer.Deserialize<SeedManifest>(File.ReadAllText(path), JsonOptions);
            var files = manifest?.Files ?? new Dictionary<string, string>();
            return new SeedManifest(new Dictionary<string, string>(files, StringComparer.OrdinalIgnoreCase));
        }
        catch
        {
            return new SeedManifest(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));
        }
    }

    private static void SaveSeedManifest(string path, SeedManifest manifest)
    {
        try
        {
            File.WriteAllText(path, JsonSerializer.Serialize(manifest, JsonOptions));
        }
        catch
        {
            // best-effort
        }
    }

    private static string? TryGetPolicyIdFromPolicyFile(string? policyPath)
    {
        if (string.IsNullOrWhiteSpace(policyPath) || !File.Exists(policyPath)) return null;

        if (string.Equals(Path.GetExtension(policyPath), ".xml", StringComparison.OrdinalIgnoreCase))
            return TryGetPolicyIdFromXml(policyPath);

        if (!string.Equals(Path.GetExtension(policyPath), ".cip", StringComparison.OrdinalIgnoreCase))
            return null;

        var tmpXml = Path.Combine(Path.GetTempPath(), $"tgwst_policy_{Guid.NewGuid():N}.xml");
        try
        {
            var script = $"ConvertFrom-CIPolicy -BinaryFilePath '{EscapePwsh(policyPath)}' -XmlFilePath '{EscapePwsh(tmpXml)}'";
            var ps = RunPowerShell(script);
            if (ps.ExitCode != 0 || !File.Exists(tmpXml))
            {
                return null;
            }

            return TryGetPolicyIdFromXml(tmpXml);
        }
        finally
        {
            TryDelete(tmpXml);
        }
    }

    private static string? TryGetFriendlyNameFromPolicyFile(string? policyPath)
    {
        if (string.IsNullOrWhiteSpace(policyPath) || !File.Exists(policyPath)) return null;

        if (string.Equals(Path.GetExtension(policyPath), ".xml", StringComparison.OrdinalIgnoreCase))
            return TryGetFriendlyNameFromXml(policyPath);

        if (!string.Equals(Path.GetExtension(policyPath), ".cip", StringComparison.OrdinalIgnoreCase))
            return null;

        var tmpXml = Path.Combine(Path.GetTempPath(), $"tgwst_policy_{Guid.NewGuid():N}.xml");
        try
        {
            var script = $"ConvertFrom-CIPolicy -BinaryFilePath '{EscapePwsh(policyPath)}' -XmlFilePath '{EscapePwsh(tmpXml)}'";
            var ps = RunPowerShell(script);
            if (ps.ExitCode != 0 || !File.Exists(tmpXml))
            {
                return null;
            }

            return TryGetFriendlyNameFromXml(tmpXml);
        }
        finally
        {
            TryDelete(tmpXml);
        }
    }

    private static string? TryGetPolicyIdFromXml(string xmlPath)
    {
        try
        {
            var doc = XDocument.Load(xmlPath);
            var ns = doc.Root?.Name.Namespace ?? XNamespace.None;
            var value = doc.Descendants(ns + "PolicyID").FirstOrDefault()?.Value;
            if (string.IsNullOrWhiteSpace(value))
                value = doc.Descendants(ns + "PolicyTypeID").FirstOrDefault()?.Value;
            return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
        }
        catch
        {
            return null;
        }
    }

    private static string? TryGetFriendlyNameFromXml(string xmlPath)
    {
        try
        {
            var doc = XDocument.Load(xmlPath);
            return doc.Root?.Attribute("FriendlyName")?.Value?.Trim();
        }
        catch
        {
            return null;
        }
    }

    private static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private CiToolPolicy[] ListPolicies()
    {
        try
        {
            var result = RunCiTool("--list-policies --json");
            if (result.ExitCode != 0) return Array.Empty<CiToolPolicy>();
            var parsed = JsonSerializer.Deserialize<CiToolListPoliciesResponse>(result.Stdout, JsonOptions);
            if (parsed == null || parsed.OperationResult != 0) return Array.Empty<CiToolPolicy>();
            return parsed.Policies ?? Array.Empty<CiToolPolicy>();
        }
        catch
        {
            return Array.Empty<CiToolPolicy>();
        }
    }

    private static int? TryParseCiToolOperation(string json)
    {
        try
        {
            var parsed = JsonSerializer.Deserialize<CiToolOperationResponse>(json, JsonOptions);
            return parsed?.OperationResult;
        }
        catch
        {
            return null;
        }
    }

    private static ProcessRunResult RunCiTool(string arguments) => RunProcess("CiTool.exe", arguments);

    private static ProcessRunResult RunPowerShell(string command)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(command));
        return RunProcess("powershell.exe", $"-NoLogo -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}");
    }

    private static ProcessRunResult RunProcess(string fileName, string arguments)
    {
        var psi = new ProcessStartInfo(fileName, arguments)
        {
            UseShellExecute = false,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        };

        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"Failed to start process: {fileName}");
        var stdoutTask = p.StandardOutput.ReadToEndAsync();
        var stderrTask = p.StandardError.ReadToEndAsync();
        p.WaitForExit();
        var stdout = stdoutTask.GetAwaiter().GetResult();
        var stderr = stderrTask.GetAwaiter().GetResult();
        return new ProcessRunResult(p.ExitCode, stdout, stderr);
    }

    private static string EscapePwsh(string value) => value.Replace("'", "''");

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

    private static void LogEvent(string message, EventLogEntryType type)
    {
        try
        {
            if (!IsAdministrator())
                return;

            if (!System.Diagnostics.EventLog.SourceExists(EventSource))
                System.Diagnostics.EventLog.CreateEventSource(EventSource, EventLogName);

            System.Diagnostics.EventLog.WriteEntry(EventSource, message, type);
        }
        catch
        {
            // Best-effort logging only.
        }
    }
}
