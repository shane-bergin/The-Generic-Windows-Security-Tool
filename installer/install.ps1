$ErrorActionPreference = "Stop"

param(
    [string]$Source = "$PSScriptRoot\..\src\TGWST.App\bin\Release\net8.0-windows\win-x64\publish",
    [string]$Target = "$Env:ProgramFiles\TGWST"
)

function Ensure-Admin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Run this installer in an elevated PowerShell session."
    }
}

function Copy-App {
    param($src, $dst)
    if (-not (Test-Path $src)) {
        Write-Error "Source path not found: $src"
    }
    if (-not (Test-Path $dst)) {
        New-Item -ItemType Directory -Path $dst | Out-Null
    }
    robocopy $src $dst *.* /E /NFL /NDL /NJH /NJS /NC /NS /XO | Out-Null
}

function Copy-ClamAv {
    param($src, $dst)
    if (-not (Test-Path $src)) { return }
    if (-not (Test-Path $dst)) { New-Item -ItemType Directory -Path $dst | Out-Null }
    robocopy $src $dst *.* /E /NFL /NDL /NJH /NJS /NC /NS /XO | Out-Null
}

function Create-Shortcut {
    param($exePath)
    $shell = New-Object -ComObject WScript.Shell
    $lnkPath = "$Env:ProgramData\Microsoft\Windows\Start Menu\Programs\TGWST.lnk"
    $lnk = $shell.CreateShortcut($lnkPath)
    $lnk.TargetPath = $exePath
    $lnk.WorkingDirectory = Split-Path $exePath
    $lnk.IconLocation = $exePath
    $lnk.Description = "The Generic Windows Security Tool"
    $lnk.Save()
}

try {
    Ensure-Admin
    Copy-App -src $Source -dst $Target
    $clamSrc = Join-Path $Source "ClamAV"
    $clamDst = Join-Path $Env:ProgramData "TGWST\ClamAV"
    Copy-ClamAv -src $clamSrc -dst $clamDst
    $exe = Join-Path $Target "TGWST.App.exe"
    if (-not (Test-Path $exe)) { Write-Error "Executable not found at $exe" }
    Create-Shortcut -exePath $exe
    Write-Host "Installed to $Target"
    Write-Host "Start Menu shortcut created: TGWST"
} catch {
    Write-Error $_
    exit 1
}
