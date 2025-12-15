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

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        WriteIndented = true
    };

    public sealed record WdacPolicy(string BaseName, string? XmlPath, string? CipPath);

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
        bool RequiresElevation = false);

    private sealed record SeedManifest(Dictionary<string, string> Files);

    private sealed record AppliedPolicyRecord(
        string PolicyId,
        string? FriendlyName,
        string SourcePolicyPath,
        DateTimeOffset AppliedAtUtc,
        bool EnforceUmci);

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

    public IReadOnlyList<WdacPolicy> EnumeratePolicies()
    {
        try
        {
            Directory.CreateDirectory(ProgramDataPath);
            if (!Directory.Exists(ProgramDataPath)) return Array.Empty<WdacPolicy>();

            var xml = Directory.EnumerateFiles(ProgramDataPath, "*.xml", SearchOption.TopDirectoryOnly);
            var cip = Directory.EnumerateFiles(ProgramDataPath, "*.cip", SearchOption.TopDirectoryOnly);

            return xml.Concat(cip)
                .Where(File.Exists)
                .GroupBy(p => Path.GetFileNameWithoutExtension(p), StringComparer.OrdinalIgnoreCase)
                .Select(g =>
                {
                    var baseName = g.Key ?? "Unknown";
                    string? xmlPath = g.FirstOrDefault(p => string.Equals(Path.GetExtension(p), ".xml", StringComparison.OrdinalIgnoreCase));
                    string? cipPath = g.FirstOrDefault(p => string.Equals(Path.GetExtension(p), ".cip", StringComparison.OrdinalIgnoreCase));
                    return new WdacPolicy(baseName, xmlPath, cipPath);
                })
                .OrderBy(p => p.BaseName, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch (Exception ex)
        {
            LogEvent($"EnumeratePolicies failed: {ex}", EventLogEntryType.Error);
            return Array.Empty<WdacPolicy>();
        }
    }

    public WdacOperationResult ImportPolicy(string sourcePath)
    {
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

            LogEvent($"Imported WDAC policy: {sourcePath} -> {destPath}", EventLogEntryType.Information);
            return new WdacOperationResult(true, "Policy imported.", AffectedPath: destPath);
        }
        catch (Exception ex)
        {
            LogEvent($"ImportPolicy failed for {sourcePath}: {ex}", EventLogEntryType.Error);
            return new WdacOperationResult(false, $"Import failed: {ex.Message}", AffectedPath: sourcePath, Details: ex.ToString());
        }
    }

    public WdacOperationResult CompileXmlToCip(string xmlPath, out string? cipPath)
    {
        cipPath = null;

        try
        {
            if (string.IsNullOrWhiteSpace(xmlPath))
                return new WdacOperationResult(false, "No XML policy path provided.");

            if (!File.Exists(xmlPath))
                return new WdacOperationResult(false, "XML policy file not found.", AffectedPath: xmlPath);

            if (!string.Equals(Path.GetExtension(xmlPath), ".xml", StringComparison.OrdinalIgnoreCase))
                return new WdacOperationResult(false, "Compile requires an .xml policy file.", AffectedPath: xmlPath);

            var outputCip = Path.ChangeExtension(xmlPath, ".cip");
            var tempCip = Path.Combine(Path.GetTempPath(), $"tgwst_{Path.GetFileNameWithoutExtension(xmlPath)}_{Guid.NewGuid():N}.cip");

            var script = $"ConvertFrom-CIPolicy -XmlFilePath '{EscapePwsh(xmlPath)}' -BinaryFilePath '{EscapePwsh(tempCip)}'";
            var ps = RunPowerShell(script);
            if (ps.ExitCode != 0 || !File.Exists(tempCip))
            {
                TryDelete(tempCip);
                return new WdacOperationResult(
                    Success: false,
                    Message: "Failed to compile XML policy to CIP.",
                    AffectedPath: xmlPath,
                    ExitCode: ps.ExitCode,
                    Stdout: ps.Stdout,
                    Stderr: ps.Stderr);
            }

            Directory.CreateDirectory(Path.GetDirectoryName(outputCip) ?? ProgramDataPath);
            File.Copy(tempCip, outputCip, overwrite: true);
            TryDelete(tempCip);

            cipPath = outputCip;
            LogEvent($"Compiled WDAC XML -> CIP: {xmlPath} -> {outputCip}", EventLogEntryType.Information);
            return new WdacOperationResult(true, "Compiled XML policy to CIP.", AffectedPath: outputCip, ExitCode: ps.ExitCode, Stdout: ps.Stdout, Stderr: ps.Stderr);
        }
        catch (Exception ex)
        {
            LogEvent($"CompileXmlToCip failed for {xmlPath}: {ex}", EventLogEntryType.Error);
            return new WdacOperationResult(false, $"Compile failed: {ex.Message}", AffectedPath: xmlPath, Details: ex.ToString());
        }
    }

    public WdacOperationResult ApplyPolicy(WdacPolicy selectedPolicy, bool enforceUmci)
    {
        try
        {
            if (!IsAdministrator())
            {
                return new WdacOperationResult(
                    Success: false,
                    Message: "Applying a WDAC policy requires Administrator rights. Re-run TGWST as Administrator.",
                    RequiresElevation: true);
            }

            var sourceCipPath = selectedPolicy.CipPath;
            if (string.IsNullOrWhiteSpace(sourceCipPath))
            {
                if (string.IsNullOrWhiteSpace(selectedPolicy.XmlPath))
                    return new WdacOperationResult(false, "Selected policy has no XML or CIP to apply.");

                var compile = CompileXmlToCip(selectedPolicy.XmlPath, out var compiledCip);
                if (!compile.Success || string.IsNullOrWhiteSpace(compiledCip))
                    return compile;

                sourceCipPath = compiledCip;
            }

            if (!File.Exists(sourceCipPath))
                return new WdacOperationResult(false, "Policy file not found.", AffectedPath: sourceCipPath);

            var tempCip = Path.Combine(Path.GetTempPath(), $"tgwst_apply_{Guid.NewGuid():N}.cip");
            File.Copy(sourceCipPath, tempCip, overwrite: true);

            var modeScript = enforceUmci
                ? $"Set-RuleOption -FilePath '{EscapePwsh(tempCip)}' -Option 0;"
                : $"Set-RuleOption -FilePath '{EscapePwsh(tempCip)}' -Option 0 -Delete;";

            var setMode = RunPowerShell(modeScript);
            if (setMode.ExitCode != 0)
            {
                TryDelete(tempCip);
                return new WdacOperationResult(
                    Success: false,
                    Message: "Failed to set policy options (UMCI).",
                    ExitCode: setMode.ExitCode,
                    Stdout: setMode.Stdout,
                    Stderr: setMode.Stderr);
            }

            var ci = RunCiTool($"--update-policy \"{tempCip}\" --json");
            TryDelete(tempCip);

            var op = TryParseCiToolOperation(ci.Stdout);
            if (ci.ExitCode != 0 || (op.HasValue && op.Value != 0))
            {
                LogEvent($"CiTool update-policy failed: exit={ci.ExitCode} op={op} stderr={ci.Stderr} stdout={ci.Stdout}", EventLogEntryType.Error);
                return new WdacOperationResult(
                    Success: false,
                    Message: "Failed to apply WDAC policy.",
                    ExitCode: ci.ExitCode,
                    Stdout: ci.Stdout,
                    Stderr: ci.Stderr);
            }

            var policyId = TryGetPolicyIdFromPolicyFile(selectedPolicy.XmlPath)
                           ?? TryGetPolicyIdFromPolicyFile(selectedPolicy.CipPath)
                           ?? TryGetPolicyIdFromPolicyFile(sourceCipPath);

            var friendly = TryGetFriendlyNameFromPolicyFile(selectedPolicy.XmlPath)
                           ?? TryGetFriendlyNameFromPolicyFile(selectedPolicy.CipPath);

            if (!string.IsNullOrWhiteSpace(policyId))
            {
                SaveAppliedPolicy(new AppliedPolicyRecord(
                    PolicyId: policyId,
                    FriendlyName: friendly,
                    SourcePolicyPath: sourceCipPath,
                    AppliedAtUtc: DateTimeOffset.UtcNow,
                    EnforceUmci: enforceUmci));
            }

            LogEvent($"Applied WDAC policy {sourceCipPath} (UMCI {(enforceUmci ? "Enabled" : "Disabled")})", EventLogEntryType.Information);
            return new WdacOperationResult(
                Success: true,
                Message: "WDAC policy applied.",
                AffectedPath: sourceCipPath,
                ExitCode: ci.ExitCode,
                Stdout: ci.Stdout,
                Stderr: ci.Stderr);
        }
        catch (Exception ex)
        {
            LogEvent($"ApplyPolicy failed: {ex}", EventLogEntryType.Error);
            return new WdacOperationResult(false, $"Apply failed: {ex.Message}", Details: ex.ToString());
        }
    }

    public WdacOperationResult RemovePolicy(bool allowSystemPolicyRemoval = false)
    {
        try
        {
            if (!IsAdministrator())
            {
                return new WdacOperationResult(
                    Success: false,
                    Message: "Removing a WDAC policy requires Administrator rights. Re-run TGWST as Administrator.",
                    RequiresElevation: true);
            }

            var record = LoadAppliedPolicy();
            if (record == null || string.IsNullOrWhiteSpace(record.PolicyId))
            {
                var candidates = ListPolicies()
                    .Where(p => !p.IsSystemPolicy)
                    .Where(p => !string.IsNullOrWhiteSpace(p.FriendlyName) && p.FriendlyName.Contains("TGWST", StringComparison.OrdinalIgnoreCase))
                    .ToArray();

                if (candidates.Length == 0)
                    return new WdacOperationResult(false, "No TGWST-applied WDAC policy was found to remove.");

                if (candidates.Length > 1)
                {
                    var list = string.Join(", ", candidates.Select(p => $"{p.FriendlyName} ({p.PolicyID})"));
                    return new WdacOperationResult(false, $"Multiple TGWST-related policies were detected ({list}). Refusing to remove automatically.");
                }

                var candidate = candidates[0];
                if (string.IsNullOrWhiteSpace(candidate.PolicyID))
                    return new WdacOperationResult(false, "Detected a TGWST policy but could not determine its PolicyID.");

                var removeFallback = RunCiTool($"--remove-policy {candidate.PolicyID} --json");
                var fallbackOp = TryParseCiToolOperation(removeFallback.Stdout);
                if (removeFallback.ExitCode != 0 || (fallbackOp.HasValue && fallbackOp.Value != 0))
                {
                    return new WdacOperationResult(false, "Failed to remove detected TGWST policy.", ExitCode: removeFallback.ExitCode, Stdout: removeFallback.Stdout, Stderr: removeFallback.Stderr);
                }

                TryDelete(Path.Combine(ProgramDataPath, AppliedPolicyFileName));
                RunCiTool("--refresh --json");
                LogEvent($"Removed WDAC policy (fallback) {candidate.FriendlyName} ({candidate.PolicyID})", EventLogEntryType.Warning);
                return new WdacOperationResult(true, $"Removed WDAC policy '{candidate.FriendlyName}'.", Stdout: removeFallback.Stdout, Stderr: removeFallback.Stderr);
            }

            var installed = ListPolicies();
            var match = installed.FirstOrDefault(p => string.Equals(p.PolicyID, record.PolicyId, StringComparison.OrdinalIgnoreCase));
            if (match != null && match.IsSystemPolicy && !allowSystemPolicyRemoval)
            {
                return new WdacOperationResult(
                    false,
                    $"The applied policy '{match.FriendlyName}' ({record.PolicyId}) is a system policy. Removing it can affect Windows security features. Confirm removal to proceed.");
            }

            var remove = RunCiTool($"--remove-policy {record.PolicyId} --json");
            var op = TryParseCiToolOperation(remove.Stdout);
            if (remove.ExitCode != 0 || (op.HasValue && op.Value != 0))
            {
                return new WdacOperationResult(false, "Failed to remove WDAC policy.", ExitCode: remove.ExitCode, Stdout: remove.Stdout, Stderr: remove.Stderr);
            }

            TryDelete(Path.Combine(ProgramDataPath, AppliedPolicyFileName));
            RunCiTool("--refresh --json");

            LogEvent($"Removed WDAC policy {record.PolicyId}", match?.IsSystemPolicy == true ? EventLogEntryType.Warning : EventLogEntryType.Information);
            return new WdacOperationResult(true, "WDAC policy removed.", Stdout: remove.Stdout, Stderr: remove.Stderr);
        }
        catch (Exception ex)
        {
            LogEvent($"RemovePolicy failed: {ex}", EventLogEntryType.Error);
            return new WdacOperationResult(false, $"Remove failed: {ex.Message}", Details: ex.ToString());
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

        foreach (var pattern in new[] { "*.xml", "*.cip" })
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

    private AppliedPolicyRecord? LoadAppliedPolicy()
    {
        try
        {
            var path = Path.Combine(ProgramDataPath, AppliedPolicyFileName);
            if (!File.Exists(path)) return null;
            return JsonSerializer.Deserialize<AppliedPolicyRecord>(File.ReadAllText(path), JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    private void SaveAppliedPolicy(AppliedPolicyRecord record)
    {
        try
        {
            Directory.CreateDirectory(ProgramDataPath);
            var path = Path.Combine(ProgramDataPath, AppliedPolicyFileName);
            File.WriteAllText(path, JsonSerializer.Serialize(record, JsonOptions));
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
        var script = $"ConvertFrom-CIPolicy -BinaryFilePath '{EscapePwsh(policyPath)}' -XmlFilePath '{EscapePwsh(tmpXml)}'";
        var ps = RunPowerShell(script);
        if (ps.ExitCode != 0 || !File.Exists(tmpXml))
        {
            TryDelete(tmpXml);
            return null;
        }

        var id = TryGetPolicyIdFromXml(tmpXml);
        TryDelete(tmpXml);
        return id;
    }

    private static string? TryGetFriendlyNameFromPolicyFile(string? policyPath)
    {
        if (string.IsNullOrWhiteSpace(policyPath) || !File.Exists(policyPath)) return null;

        if (string.Equals(Path.GetExtension(policyPath), ".xml", StringComparison.OrdinalIgnoreCase))
            return TryGetFriendlyNameFromXml(policyPath);

        if (!string.Equals(Path.GetExtension(policyPath), ".cip", StringComparison.OrdinalIgnoreCase))
            return null;

        var tmpXml = Path.Combine(Path.GetTempPath(), $"tgwst_policy_{Guid.NewGuid():N}.xml");
        var script = $"ConvertFrom-CIPolicy -BinaryFilePath '{EscapePwsh(policyPath)}' -XmlFilePath '{EscapePwsh(tmpXml)}'";
        var ps = RunPowerShell(script);
        if (ps.ExitCode != 0 || !File.Exists(tmpXml))
        {
            TryDelete(tmpXml);
            return null;
        }

        var name = TryGetFriendlyNameFromXml(tmpXml);
        TryDelete(tmpXml);
        return name;
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
