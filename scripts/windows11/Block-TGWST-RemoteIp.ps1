#requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$RemoteAddress,

    [string]$RulePrefix = 'TGWST Manual Remote Block'
)

$parsed = $null
if (-not [System.Net.IPAddress]::TryParse($RemoteAddress, [ref]$parsed)) {
    throw "RemoteAddress must be a concrete IP address."
}

foreach ($direction in 'Inbound','Outbound') {
    $name = "$RulePrefix $RemoteAddress $direction"
    if ($PSCmdlet.ShouldProcess($name, "Create firewall block rule")) {
        New-NetFirewallRule `
            -DisplayName $name `
            -Direction $direction `
            -Action Block `
            -RemoteAddress $RemoteAddress `
            -Profile Any `
            -Enabled True | Out-Null
    }
}

[pscustomobject]@{
    RemoteAddress = $RemoteAddress
    Action = 'Blocked inbound and outbound through Windows Defender Firewall'
    CreatedAt = (Get-Date).ToString('s')
}
