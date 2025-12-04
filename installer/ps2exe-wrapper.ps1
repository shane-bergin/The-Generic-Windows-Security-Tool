param(
    [string]$ScriptPath,
    [string]$OutputExe
)

$ErrorActionPreference = "Stop"

if (-not $ScriptPath) { $ScriptPath = Join-Path $PSScriptRoot "install-wizard.ps1" }
if (-not $OutputExe) { $OutputExe = Join-Path $PSScriptRoot "TGWST-Installer.exe" }

if (-not (Test-Path $ScriptPath)) { throw "Script not found: $ScriptPath" }

$ps2exe = Get-Command ps2exe.ps1 -ErrorAction SilentlyContinue
if (-not $ps2exe) {
    Write-Error "ps2exe.ps1 not found in PATH. Install via 'Install-Module ps2exe' or add ps2exe.ps1 to PATH."
    exit 1
}

Write-Host "Wrapping $ScriptPath into $OutputExe ..."
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $ps2exe.Path -inputFile $ScriptPath -outputFile $OutputExe -icon "$PSScriptRoot\..\src\TGWST.App\Assets\generic_windows_security_tool_icon.png" -noConsole

Write-Host "Done. Output: $OutputExe"
