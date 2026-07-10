[CmdletBinding()]
param(
    [int]$Top = 40
)

$ErrorActionPreference = 'Continue'

function Resolve-ProcessName {
    param([int]$ProcessId)
    try {
        (Get-Process -Id $ProcessId -ErrorAction Stop).ProcessName + '.exe'
    } catch {
        'Unknown'
    }
}

$interestingPorts = 22,23,53,90,135,139,389,445,636,1433,1521,3306,3389,5432,5900,5985,5986

$tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{
        Protocol = 'TCP'
        Local = "$($_.LocalAddress):$($_.LocalPort)"
        Remote = "$($_.RemoteAddress):$($_.RemotePort)"
        State = $_.State
        ProcessId = $_.OwningProcess
        Process = Resolve-ProcessName $_.OwningProcess
        Interesting = ($interestingPorts -contains $_.LocalPort) -or ($interestingPorts -contains $_.RemotePort)
    }
}

$udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{
        Protocol = 'UDP'
        Local = "$($_.LocalAddress):$($_.LocalPort)"
        Remote = '*'
        State = 'UDP'
        ProcessId = $_.OwningProcess
        Process = Resolve-ProcessName $_.OwningProcess
        Interesting = $interestingPorts -contains $_.LocalPort
    }
}

$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
$firewall = Get-NetFirewallProfile -ErrorAction SilentlyContinue |
    Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

[pscustomobject]@{
    CollectedAt = (Get-Date).ToString('s')
    Defender = [pscustomobject]@{
        AntivirusEnabled = $defender.AntivirusEnabled
        RealTimeProtectionEnabled = $defender.RealTimeProtectionEnabled
        NISEnabled = $defender.NISEnabled
        QuickScanEndTime = $defender.QuickScanEndTime
        FullScanEndTime = $defender.FullScanEndTime
    }
    FirewallProfiles = $firewall
    InterestingConnections = @($tcp + $udp | Where-Object Interesting | Select-Object -First $Top)
    SuspiciousProcesses = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match '^(powershell|pwsh|cmd|wscript|cscript|rundll32|regsvr32|mshta|bitsadmin|certutil|netsh|schtasks|sc|reg)\.exe$'
        } |
        Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine |
        Select-Object -First $Top)
} | ConvertTo-Json -Depth 5
