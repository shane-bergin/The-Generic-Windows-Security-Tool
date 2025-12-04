using System;
using System.Diagnostics;
using System.IO;

namespace TGWST.Core.AppControl;

public sealed class WdacEngine
{
    public void ApplyPolicy(string xmlPath, bool enforce)
    {
        if (!File.Exists(xmlPath)) throw new FileNotFoundException(xmlPath);
        var mode = enforce ? "Enabled:UMCI" : "Audit";
        var args = $"-Command \"ConvertFrom-CIPolicy -XmlFilePath '{xmlPath}' -BinaryFilePath '$env:TEMP\\tgwst.cip'; Set-RuleOption '$env:TEMP\\tgwst.cip' 3; Set-RuleOption '$env:TEMP\\tgwst.cip' 0; if('{mode}' -eq 'Audit'){{Set-RuleOption '$env:TEMP\\tgwst.cip' 3}}; Copy-Item '$env:TEMP\\tgwst.cip' 'C:\\Windows\\System32\\CodeIntegrity\\tgwst.cip'; Invoke-CimMethod -Namespace root\\Microsoft\\Windows\\CI -ClassName CI_Policy -MethodName UpdatePolicy -Arguments @{{FilePath='C:\\Windows\\System32\\CodeIntegrity\\tgwst.cip'}}\"";
        RunPwsh(args);
    }

    public void RemovePolicy()
    {
        var args = "-Command \"Invoke-CimMethod -Namespace root\\Microsoft\\Windows\\CI -ClassName CI_Policy -MethodName DeletePolicy -Arguments @{}\"";
        RunPwsh(args);
    }

    private static void RunPwsh(string arguments)
    {
        var psi = new ProcessStartInfo("powershell.exe", arguments)
        {
            UseShellExecute = false,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start PowerShell");
        var err = p.StandardError.ReadToEnd();
        var outp = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0) throw new InvalidOperationException($"WDAC command failed: {err}{outp}");
    }
}
