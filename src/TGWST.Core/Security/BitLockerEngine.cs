using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace TGWST.Core.Security;

public sealed class BitLockerEngine
{
    public string GetStatus() => RunManageBde("-status");

    public void EnableOsDrive(string driveLetter, string pin)
    {
        var args = $"-on {driveLetter}: -tpmandpin -pin {pin} -used";
        RunManageBde(args);
    }

    public void EnableFixed(string driveLetter) => RunManageBde($"-on {driveLetter}: -used");
    public void EnableRemovable(string driveLetter, string password) => RunManageBde($"-on {driveLetter}: -pw -password {password}");
    public void Suspend(string driveLetter, int rebootCount = 1) => RunManageBde($"-protectors -disable {driveLetter}: -rc {rebootCount}");
    public void Resume(string driveLetter) => RunManageBde($"-protectors -enable {driveLetter}:");
    public void AddRecoveryKey(string driveLetter, string outputDir)
    {
        Directory.CreateDirectory(outputDir);
        RunManageBde($"-protectors -add {driveLetter}: -rk \"{outputDir}\"");
        if (!Directory.EnumerateFiles(outputDir, "*.bek").Any()) throw new InvalidOperationException("Recovery key not generated");
    }

    private static string RunManageBde(string args)
    {
        var psi = new ProcessStartInfo("manage-bde.exe", args)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start manage-bde");
        var stdout = p.StandardOutput.ReadToEnd();
        var stderr = p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0) throw new InvalidOperationException($"manage-bde failed: {stderr}{stdout}");
        return stdout;
    }
}
