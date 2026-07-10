using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.App;

/// <summary>
/// CLI-first entry point for TGWST.
/// When launched with --* arguments, runs in console/automation mode (no GUI window).
/// Otherwise starts the WPF dashboard as before.
/// </summary>
public static class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeConsole();

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    private const int ATTACH_PARENT_PROCESS = -1;

    [STAThread]
    public static int Main(string[] args)
    {
        // Detect CLI mode via any --flag
        bool isCli = args.Length > 0 && args.Any(a => a.StartsWith("--", StringComparison.OrdinalIgnoreCase) || a.StartsWith("-", StringComparison.OrdinalIgnoreCase));

        if (isCli)
        {
            TryAttachParentConsole();
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.WriteLine($"TGWST {BuildInfo.Current.Version} - Windows Security Dashboard");
            Console.WriteLine("Only commands listed by --help are supported in this build.");
            Console.WriteLine();

            int exitCode;
            try
            {
                exitCode = RunCli(args).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"FATAL: {ex.Message}");
                Console.Error.WriteLine(ex.ToString());
                exitCode = 2;
            }

            // Give output time to flush in some consoles
            Thread.Sleep(100);
            return exitCode;
        }

        // Normal GUI path
        // Detach from console so double-clicking gives a clean WPF experience
        // (no black console window behind the dashboard).
        try { FreeConsole(); } catch { }

        var app = new App();
        app.InitializeComponent();
        app.Run();
        return 0;
    }

    private static void TryAttachParentConsole()
    {
        try
        {
            if (GetConsoleWindow() == IntPtr.Zero)
            {
                AttachConsole(ATTACH_PARENT_PROCESS);
            }
        }
        catch
        {
            // best effort
        }
    }

    private static async Task<int> RunCli(string[] args)
    {
        await Task.CompletedTask;
        // Normalize
        var lowerArgs = args.Select(a => a.ToLowerInvariant()).ToArray();
        var primary = lowerArgs.Length > 0 ? lowerArgs[0] : string.Empty;

        switch (primary)
        {
            case "--help":
            case "-h":
            case "/?":
            case "--usage":
                PrintHelp();
                return 0;

            case "--version":
            case "-v":
                PrintVersion();
                return 0;

            case "--scan-windows-safeguards":
                return CapabilityUnavailable("Windows Safeguards scan", "its current implementation contains placeholder checks that cannot support a verified security verdict");

            case "--apply-hardening":
            case "--apply-windows-safeguards":
            case "--apply-full-hardening":
                return CapabilityUnavailable("Windows Safeguards profile", "the profile does not yet provide verified per-control outcomes and secured rollback artifacts");

            case "--apply-wdac-containment-profile":
                return CapabilityUnavailable("WDAC containment", "TGWST currently has only an unvalidated starter policy and does not safely deploy or verify WDAC");

            case "--audit-bitlocker":
            case "--check-bitlocker":
                return CapabilityUnavailable("BitLocker audit", "the current command is advisory scaffolding rather than a complete audit");

            case "--audit-symlink":
            case "--harden-symlink":
                return CapabilityUnavailable("symlink audit", "the current command does not collect and verify the claimed effective state");

            case "--audit-reparse":
                return CapabilityUnavailable("reparse-point audit", "the current command does not perform the claimed complete scan");

            case "--export-logs":
                return CapabilityUnavailable("log export", "the current command writes placeholder output rather than aggregating the TGWST evidence sources");

            case "--status":
            case "--posture":
                return CapabilityUnavailable("quick posture", "the current command does not query effective control state");

            default:
                Console.WriteLine($"Unknown command: {primary}");
                Console.WriteLine();
                PrintHelp();
                return 1;
        }
    }

    private static void PrintHelp()
    {
        Console.WriteLine("Usage: TGWST.exe [command] [options]");
        Console.WriteLine();
        Console.WriteLine("Available:");
        Console.WriteLine("  --version                         Display build identity");
        Console.WriteLine("  --help                            This help");
        Console.WriteLine();
        Console.WriteLine("Safeguards, WDAC, BitLocker, reparse, status, and export commands are unavailable until their apply/verify/rollback contracts are production-ready.");
    }

    private static void PrintVersion()
    {
        var build = BuildInfo.Current;
        Console.WriteLine(build.DisplayVersion);
        if (build.BuiltAtUtc is { } builtAtUtc)
        {
            Console.WriteLine($"Built UTC: {builtAtUtc:O}");
        }
    }

    private static int CapabilityUnavailable(string capability, string reason)
    {
        Console.Error.WriteLine($"UNAVAILABLE: {capability} is disabled because {reason}.");
        Console.Error.WriteLine("No security setting was changed.");
        return 4;
    }

    // --- CLI command implementations (stubs wired to services; expanded in following edits) ---

    private static async Task<int> RunScanWindowsSafeguards(string[] args)
    {
        bool verbose = args.Any(a => a.Contains("verbose") || a.Contains("--v"));
        Console.WriteLine("[TGWST] Starting Windows Safeguards scan (Defender, update, BitLocker/WinRE, WDAC, reparse, and telemetry posture)...");
        Console.WriteLine("CVE window: MSRC May/June 2026 plus CISA KEV matches through 22 Jun 2026.");
        Console.WriteLine();

        try
        {
            var guiLog = new TGWST.App.Services.GuiLogService();
            var actions = new TGWST.App.Services.DashboardActionService();
            var defense = new TGWST.App.Services.WindowsSafeguardService(guiLog, actions);

            var scan = await defense.ScanAsync(verbose, CancellationToken.None);

            Console.WriteLine($"\nSCAN COMPLETE @ {scan.Timestamp:u}");
            Console.WriteLine($"  CRITICAL: {scan.Critical}");
            Console.WriteLine($"  WARNING : {scan.Warn}");
            Console.WriteLine($"  TTP mapping: {scan.TtpMapping}");
            Console.WriteLine("\nFindings (top):");
            foreach (var f in scan.Findings.Take(8))
            {
                Console.WriteLine($"  [{f.Severity}] {f.Area}: {f.Detail}");
            }

            Console.WriteLine("\nLive detectors (always-on while TGWST GUI or telemetry runs):");
            Console.WriteLine("  - Defender Parent Anomaly (MsMpEng -> shells @ SYSTEM/HIGH)  [CRITICAL on match]");
            Console.WriteLine("  - Reparse/Junction creation in user-writable paths correlated to privileged ops");
            Console.WriteLine("  - Cloud Files Cf* calls + .DEFAULT hive mods by non-SYSTEM");
            Console.WriteLine("  - VSS HarddiskVolumeShadowCopy enumeration from low-priv");
            Console.WriteLine("  - Anomalous service creation + token impersonation to SYSTEM");
            Console.WriteLine("  - .vhd(x) / ISO mounts from temp/network without MOTW");

            Console.WriteLine("\nLogs: Event Log source 'TGWST' + %ProgramData%\\TGWST\\logs\\*.jsonl");
            return scan.Critical > 0 ? 2 : 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Scan error: {ex.Message}");
            return 3;
        }
    }

    private static async Task<int> RunApplyWindowsSafeguardsProfile(string[] args)
    {
        Console.WriteLine("[TGWST] APPLYING WINDOWS SAFEGUARDS PROFILE");
        Console.WriteLine("This is the primary one-command rapid hardening action.");
        Console.WriteLine("Fail-closed bias. Patching is prerequisite.");
        Console.WriteLine();

        try
        {
            // Bootstrap minimal services for CLI (no WPF required)
            var guiLog = new TGWST.App.Services.GuiLogService();
            var actions = new TGWST.App.Services.DashboardActionService();
            var defense = new TGWST.App.Services.WindowsSafeguardService(guiLog, actions);

            bool dry = args.Any(a => a.Contains("dry") || a.Contains("audit"));
            var result = await defense.ApplyFullProfileAsync(dryRun: dry);

            Console.WriteLine($"\n=== RESULT: {result} ===");
            Console.WriteLine("Status: HARDENED (or PARTIAL). Reboot recommended after WDAC/policy changes.");
            Console.WriteLine("Run 'TGWST.exe --scan-windows-safeguards' to validate and monitor.");
            Console.WriteLine("Critical next step for containment: TGWST.exe --apply-wdac-containment-profile (elevated)");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Profile apply error: {ex.Message}");
            return 3;
        }
    }

    private static async Task<int> RunApplyWdacContainment(string[] args)
    {
        Console.WriteLine("[TGWST] WDAC Windows Safeguards Containment Profile");
        Console.WriteLine("This is the strongest containment layer: even after local privilege escalation, unapproved code should be blocked.");
        Console.WriteLine();

        bool auditOnly = args.Any(a => a.Contains("audit") || a.Contains("dry"));
        Console.WriteLine(auditOnly ? "Mode: AUDIT ONLY" : "Mode: ENFORCE (generates + applies policy if elevated)");

        // Real implementation will generate XML here + call ConvertFrom-CIPolicy + update CI policy via CIM.
        // For now provide actionable guidance + a generated policy file.

        var policyDir = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "TGWST", "wdac");
        System.IO.Directory.CreateDirectory(policyDir);
        var policyXml = System.IO.Path.Combine(policyDir, "TGWST_WindowsSafeguards_Containment.xml");

        // Write a starter restrictive policy (user must refine with official tools for production).
        // This demonstrates the structure required.
        var xml = GenerateWindowsSafeguardsWdacPolicyXml();
        System.IO.File.WriteAllText(policyXml, xml);
        Console.WriteLine($"Policy XML generated: {policyXml}");

        Console.WriteLine("\nTo fully apply (manual until full automation lands in this build):");
        Console.WriteLine("  1. (Admin PS) $policy = 'C:\\ProgramData\\TGWST\\wdac\\TGWST_WindowsSafeguards_Containment.xml'");
        Console.WriteLine("  2. ConvertFrom-CIPolicy -XmlFilePath $policy -BinaryFilePath $env:TEMP\\policy.bin");
        Console.WriteLine("  3. Invoke-CimMethod -Namespace root\\Microsoft\\Windows\\CI -ClassName PS_UpdatePolicy -MethodName Update -Arguments @{Policy = [byte[]](Get-Content $env:TEMP\\policy.bin -Encoding Byte); Path = 'EFIBoot'; Update = $true } - or use the official deployment guidance.");
        Console.WriteLine("\nThe generated policy blocks:");
        Console.WriteLine("  - Unsigned binaries/scripts from %TEMP%, Downloads, AppData, LocalAppData, ProgramData (unless allowlisted)");
        Console.WriteLine("  - Shells (cmd, powershell, pwsh, cscript, wscript, conhost) spawned from MsMpEng / SYSTEM unless from signed/trusted paths");
        Console.WriteLine("  - Default-deny for user-writable executable content post-LPE");
        Console.WriteLine();
        Console.WriteLine("TGWST.exe itself should be placed in a signed, Program Files, or explicitly allowed location under the policy.");

        if (!auditOnly)
        {
            Console.WriteLine("\nAttempting lightweight enforcement stub (full WDAC requires the Convert + CIM steps above).");
        }

        await Task.Delay(100);
        return 0;
    }

    public static string GenerateWindowsSafeguardsWdacPolicyXml()
    {
        // Minimal but representative WDAC policy XML illustrating the intent.
        // Production policies should be built with New-CIPolicy -Level PcaCertificate etc and audited.
        return @"<?xml version=""1.0"" encoding=""utf-8""?>
<SiPolicy xmlns=""urn:schemas-microsoft-com:sipolicy"">
  <VersionEx>1.0.0.0</VersionEx>
  <PolicyID>{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}</PolicyID>
  <BasePolicyID>{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}</BasePolicyID>
  <Rules>
    <Rule>
      <Option>Enabled:UMCI</Option>
    </Rule>
    <Rule>
      <Option>Enabled:Boot Menu Protection</Option>
    </Rule>
    <Rule>
      <Option>Enabled:Audit Mode</Option> <!-- Start in Audit; switch to Enforced after validation -->
    </Rule>
  </Rules>
  <EKUs />
  <FileRules>
    <!-- Deny unsigned from user-writable locations for post-LPE containment -->
    <FileRule ID=""ID_DENY_USER_TEMP"" FriendlyName=""Deny unsigned from TEMP"" FilePath=""%USERPROFILE%\AppData\Local\Temp\*"" MinimumFileVersion=""0.0.0.0"" />
    <FileRule ID=""ID_DENY_DOWNLOADS"" FriendlyName=""Deny unsigned from Downloads"" FilePath=""%USERPROFILE%\Downloads\*"" MinimumFileVersion=""0.0.0.0"" />
    <FileRule ID=""ID_DENY_APPDATA"" FriendlyName=""Deny unsigned from AppData"" FilePath=""%USERPROFILE%\AppData\*"" MinimumFileVersion=""0.0.0.0"" />
    <FileRule ID=""ID_DENY_PROGRAMDATA"" FriendlyName=""Deny unsigned from ProgramData"" FilePath=""%ProgramData%\*"" MinimumFileVersion=""0.0.0.0"" />
  </FileRules>
  <Signers>
    <!-- Microsoft and reputable signers should be allowed via publisher rules in full policy -->
  </Signers>
  <SigningScenarios>
    <SigningScenario Value=""12"" ID=""ID_SIGNINGSCENARIO_WINDOWS"" FriendlyName=""Windows binaries"">
      <ProductSigners />
    </SigningScenario>
    <SigningScenario Value=""131"" ID=""ID_SIGNINGSCENARIO_USERMODE"" FriendlyName=""User mode binaries"">
      <ProductSigners>
        <!-- In complete policy, explicit Allowed signers + path exceptions for approved tools here -->
      </ProductSigners>
    </SigningScenario>
  </SigningScenarios>
  <HvciOptions>0</HvciOptions>
  <Settings>
    <Setting Provider=""PolicyInfo"" Key=""Information"" ValueName=""Name"">
      <Value>
        <String>TGWST Windows Safeguards Containment Policy</String>
      </Value>
    </Setting>
    <Setting Provider=""PolicyInfo"" Key=""Information"" ValueName=""Description"">
      <Value>
        <String>High-containment policy targeting post-LPE execution from user-writable locations and anomalous Defender-parent shells. Pairs with TGWST behavioral detection.</String>
      </Value>
    </Setting>
  </Settings>
</SiPolicy>";
    }

    private static async Task<int> RunBitLockerAudit(string[] args)
    {
        bool enforcePin = args.Any(a => a.Contains("enforce") || a.Contains("pin"));
        Console.WriteLine("[TGWST] BitLocker / WinRE Audit (CVE-2026-45585 exposure check)");
        Console.WriteLine("TPM-only protection can be insufficient for physical-access recovery-environment bypass scenarios. Require PIN or USB key where risk warrants.");

        // Real impl will use Get-BitLockerVolume + manage-bde or WMI Win32_EncryptableVolume
        Console.WriteLine("\nRecommended: ");
        Console.WriteLine("  manage-bde -protectors -get C:   (review)");
        Console.WriteLine("  To add PIN: manage-bde -protectors -add C: -TPMAndPIN");
        Console.WriteLine("  Or via PowerShell: Add-BitLockerKeyProtector -MountPoint C: -PinProtector ...");

        if (enforcePin)
        {
            Console.WriteLine("\n[ATTEMPT] Requesting PIN protector addition (will prompt UAC / require admin interaction)...");
            // In real code: launch elevated manage-bde or use COM WMI
        }

        await Task.Delay(50);
        Console.WriteLine("See also packaged script findings for WinRE + BitLocker combo.");
        return 0;
    }

    private static async Task<int> RunSymlinkAudit(string[] args)
    {
        bool restrict = args.Any(a => a.Contains("restrict"));
        Console.WriteLine("[TGWST] Symlink / Reparse Evaluation Audit + Hardening");
        Console.WriteLine("fsutil behavior query SymlinkEvaluation");
        Console.WriteLine("Restrictive (R2L:0 R2R:0) reduces remote-to-local and remote-to-remote link-following surface but may impact some apps.");

        if (restrict)
        {
            Console.WriteLine("\nTo restrict (elevated): fsutil behavior set SymlinkEvaluation R2L:0 R2R:0");
        }
        else
        {
            Console.WriteLine("Run with --restrict to show the set command.");
        }

        // Real code will shell fsutil and also start a monitor for new reparse points created by non-system in sensitive dirs.
        await Task.Delay(30);
        Console.WriteLine("Monitor active in telemetry engine for creation events in user-writable paths.");
        return 0;
    }

    private static async Task<int> RunReparseAudit(string[] args)
    {
        Console.WriteLine("[TGWST] Reparse point / Junction / Symlink scan in high-risk user-writable directories...");
        var candidates = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
        };

        foreach (var p in candidates.Distinct())
        {
            if (!string.IsNullOrWhiteSpace(p) && System.IO.Directory.Exists(p))
            {
                Console.WriteLine($"  Scanning: {p}");
                // Real: use FindFirstFile + reparse tag or FSCTL_GET_REPARSE_POINT
            }
        }
        Console.WriteLine("No high-risk reparse abuse patterns detected in stub scan.");
        await Task.Delay(20);
        return 0;
    }

    private static async Task<int> RunExportLogs(string[] args)
    {
        var outArg = args.FirstOrDefault(a => a.StartsWith("--out=") || a.StartsWith("-out="));
        var outPath = outArg?.Split('=', 2)[1] ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "TGWST", "reports", $"tgwst-export-{DateTime.Now:yyyyMMdd-HHmmss}.json");

        Console.WriteLine($"Exporting logs to {outPath} ...");
        // In real: aggregate gui-events.jsonl + startup.log + custom safeguards jsonl + read EventLog TGWST
        System.IO.Directory.CreateDirectory(Path.GetDirectoryName(outPath)!);
        await System.IO.File.WriteAllTextAsync(outPath, "{ \"exported\": true, \"note\": \"Full aggregation implemented in full service\" }");
        Console.WriteLine("Done.");
        return 0;
    }

    private static async Task<int> RunQuickStatus()
    {
        Console.WriteLine("Quick posture (Windows Safeguards lens):");
        Console.WriteLine("  Defender RTP: (check via --scan or GUI)");
        Console.WriteLine("  Latest security update: prerequisite");
        Console.WriteLine("  BitLocker TPM-only risk: review with --audit-bitlocker");
        Console.WriteLine("  WDAC/AppLocker enforced: critical containment - use --apply-wdac-containment-profile");
        await Task.Delay(10);
        return 0;
    }
}
