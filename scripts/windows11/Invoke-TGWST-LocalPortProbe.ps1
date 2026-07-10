[CmdletBinding()]
param(
    [int[]]$Ports = @(21,22,23,25,53,80,90,135,139,389,443,445,636,1433,1521,3306,3389,5432,5900,5985,5986),
    [int]$TimeoutMs = 350
)

$ErrorActionPreference = 'Continue'
$addresses = [System.Collections.Generic.HashSet[string]]::new()
[void]$addresses.Add('127.0.0.1')

Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -and $_.IPAddress -notlike '169.254*' } |
    ForEach-Object { [void]$addresses.Add($_.IPAddress) }

function Test-Port {
    param(
        [string]$Address,
        [int]$Port,
        [int]$Timeout
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $async = $client.BeginConnect($Address, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($Timeout, $false)) {
            return $null
        }

        $client.EndConnect($async)
        [pscustomobject]@{
            Address = $Address
            Port = $Port
            Status = 'OPEN'
            Risk = if ($Port -in @(21,22,23,90,135,139,445,3389,5900,5985,5986)) { 'HIGH' } elseif ($Port -lt 1024) { 'MEDIUM' } else { 'INFO' }
            Note = 'TCP connect probe succeeded locally'
        }
    } catch {
        $null
    } finally {
        $client.Dispose()
    }
}

foreach ($address in $addresses) {
    foreach ($port in $Ports) {
        Test-Port -Address $address -Port $port -Timeout $TimeoutMs
    }
}
