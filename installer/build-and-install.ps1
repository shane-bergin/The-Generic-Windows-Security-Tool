$ErrorActionPreference = "Stop"

param(
    [string]$Project = "$PSScriptRoot\..\src\TGWST.App\TGWST.App.csproj",
    [string]$PublishDir = "C:\Tools\TGWST\publish",
    [string]$TargetDir = "$Env:ProgramFiles\TGWST",
    [string]$SignPfxPath = "",
    [string]$SignPfxPassword = "",
    [string]$SignToolPath = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

function Ensure-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Re-launching elevated..."
        Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`" @PSBoundParameters" -Verb RunAs
        exit
    }
}

function Publish-App {
    Write-Host "Publishing TGWST to $PublishDir"
    dotnet publish $Project -c Release -r win-x64 --self-contained false -o $PublishDir /p:PublishSingleFile=true /p:IncludeAllContentForSelfExtract=true
}

function Sign-App {
    param($exePath)
    if ([string]::IsNullOrWhiteSpace($SignPfxPath)) { return }
    $signtool = $SignToolPath
    if ([string]::IsNullOrWhiteSpace($signtool)) {
        $sdkGuess = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
        $signtool = Get-ChildItem $sdkGuess -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object { $_.FullName }
    }
    if (-not (Test-Path $signtool)) {
        Write-Warning "SignTool not found; skipping signing."
        return
    }
    Write-Host "Signing $exePath with $SignPfxPath"
    & $signtool sign /fd sha256 /f "$SignPfxPath" /p "$SignPfxPassword" /tr "$TimestampUrl" /td sha256 "$exePath"
}

function Install-App {
    & "$PSScriptRoot\install.ps1" -Source $PublishDir -Target $TargetDir
}

Ensure-Admin
Publish-App
$exe = Join-Path $PublishDir "TGWST.App.exe"
if (Test-Path $exe) { Sign-App -exePath $exe }
Install-App

Write-Host "Done. Launch from $TargetDir\TGWST.App.exe or Start Menu shortcut 'TGWST'."
