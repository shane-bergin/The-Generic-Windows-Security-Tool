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
        var safePin = SanitizeSecret(pin, nameof(pin));
        var normalizedDrive = NormalizeDriveLetter(driveLetter);
        var args = $"-on {normalizedDrive} -tpmandpin -pin {safePin} -used";
        RunManageBde(args);
    }

    public void EnableFixed(string driveLetter)
    {
        var normalizedDrive = NormalizeDriveLetter(driveLetter);
        RunManageBde($"-on {normalizedDrive} -used");
    }

    public void EnableRemovable(string driveLetter, string password)
    {
        var safePassword = SanitizeSecret(password, nameof(password));
        var normalizedDrive = NormalizeDriveLetter(driveLetter);
        RunManageBde($"-on {normalizedDrive} -pw -password {safePassword}");
    }

    public void Suspend(string driveLetter, int rebootCount = 1)
    {
        var normalizedDrive = NormalizeDriveLetter(driveLetter);
        RunManageBde($"-protectors -disable {normalizedDrive} -rc {rebootCount}");
    }

    public void Resume(string driveLetter)
    {
        var normalizedDrive = NormalizeDriveLetter(driveLetter);
        RunManageBde($"-protectors -enable {normalizedDrive}");
    }

    public void AddRecoveryKey(string driveLetter, string outputDir)
    {
        Directory.CreateDirectory(outputDir);
        var normalizedDrive = NormalizeDriveLetter(driveLetter);
        RunManageBde($"-protectors -add {normalizedDrive} -rk \"{outputDir}\"");
        if (!Directory.EnumerateFiles(outputDir, "*.bek").Any()) throw new InvalidOperationException("Recovery key not generated");
    }

    private static string NormalizeDriveLetter(string driveLetter)
    {
        if (string.IsNullOrWhiteSpace(driveLetter))
            throw new ArgumentException("Drive letter cannot be null or empty.", nameof(driveLetter));

        var trimmed = driveLetter.Trim().TrimEnd('\\', '/');
        if (trimmed.Length == 1 && char.IsLetter(trimmed[0]))
        {
            return $"{trimmed}:";
        }
        else if (trimmed.Length == 2 && char.IsLetter(trimmed[0]) && trimmed[1] == ':')
        {
            return trimmed;
        }
        else
        {
            throw new ArgumentException($"Invalid drive letter format: '{driveLetter}'. Expected format: 'C' or 'C:'.", nameof(driveLetter));
        }
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

    private static string SanitizeSecret(string secret, string paramName)
    {
        if (string.IsNullOrWhiteSpace(secret))
            throw new ArgumentException("A non-empty value is required.", paramName);

        var trimmed = secret.Trim();
        if (trimmed.IndexOfAny(new[] { '"', '\r', '\n' }) >= 0)
            throw new ArgumentException("Value cannot contain quotes or newlines.", paramName);

        return $"\"{trimmed}\"";
    }
}
