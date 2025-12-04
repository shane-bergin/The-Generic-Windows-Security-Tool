$ErrorActionPreference = 'Stop'
$env:WIX_BIN = Join-Path $PSScriptRoot 'installer\wix-bin'

try {
    & (Join-Path $PSScriptRoot 'installer\build-msi.ps1')
} catch {
    Write-Error "Build failed:`n$_"
    exit 1
}
