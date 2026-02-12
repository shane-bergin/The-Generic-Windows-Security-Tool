[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [string]$RuntimeIdentifier = "win-x64",
    [string]$OutputDir = "$PSScriptRoot"
)

$ErrorActionPreference = "Stop"

if (-not $OutputDir) {
    $OutputDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}

function Get-WixTool {
    param([string]$name)

    $candidates = @(
        $env:WIX_BIN,
        $env:WIX,
        (Join-Path $PSScriptRoot "wix-bin"),
        "${env:ProgramFiles(x86)}\WiX Toolset v3.11\bin",
        "${env:ProgramFiles}\WiX Toolset v3.11\bin"
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($candidate in $candidates) {
        $toolPath = Join-Path $candidate $name
        if (Test-Path $toolPath) { return $toolPath }
    }

    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Path }

    throw "$name not found. Install WiX Toolset v3.11+ or set WIX_BIN/WIX to its bin folder."
}

function Ensure-CleanDir {
    param([string]$path)
    if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force
    }
    New-Item -ItemType Directory -Path $path | Out-Null
}

function Copy-Stage {
    param([string]$source, [string]$destination)
    Write-Host "Staging payload from $source to $destination ..."
    Ensure-CleanDir -path $destination
    if (-not (Test-Path $source)) {
        throw "Stage source path does not exist: $source"
    }

    $items = Get-ChildItem -Path $source -Force -ErrorAction Stop
    if ($items.Count -eq 0) {
        throw "Stage source path is empty: $source"
    }

    foreach ($item in $items) {
        Copy-Item -Path $item.FullName -Destination $destination -Recurse -Force
    }

    Get-ChildItem -Path $destination -Recurse -Filter *.pdb -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

    $stagedFileCount = (Get-ChildItem -Path $destination -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($stagedFileCount -eq 0) {
        throw "Staging produced no files in destination: $destination"
    }
}

function Get-DotNetExe {
    $cmd = Get-Command dotnet -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Path) { return $cmd.Path }

    $candidates = @(
        "/mnt/c/Program Files/dotnet/dotnet.exe",
        (Join-Path ${env:ProgramW6432} "dotnet\dotnet.exe"),
        (Join-Path ${env:ProgramFiles} "dotnet\dotnet.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "dotnet\dotnet.exe")
    ) | Where-Object { $_ -and (Test-Path $_) }

    if ($candidates.Count -gt 0) { return $candidates[0] }

    throw "dotnet CLI not found. Install .NET SDK/Runtime or add dotnet.exe to PATH."
}

function Get-GitCommitId {
    param([string]$repoRoot)
    try {
        $commit = git -C $repoRoot rev-parse --short HEAD 2>$null
        if ($LASTEXITCODE -eq 0) { return $commit.Trim() }
    } catch { }
    return ""
}

function Get-GitCommitCount {
    param([string]$repoRoot)
    try {
        $count = git -C $repoRoot rev-list --count HEAD 2>$null
        if ($LASTEXITCODE -eq 0 -and $count -match '^\d+$') { return [int]$count }
    } catch { }
    return $null
}

function Resolve-ProductVersion {
    param(
        [string]$rawVersion,
        [string]$repoRoot
    )

    $parsed = $null
    if (-not [Version]::TryParse($rawVersion, [ref]$parsed)) {
        $parsed = [Version]"1.0.0.0"
    }

    $build = $parsed.Build
    if ($build -lt 0) { $build = 0 }
    if ($build -gt 65000) { $build = 65000 }
    $revision = $parsed.Revision
    if ($revision -lt 0) { $revision = 0 }
    if ($revision -gt 65000) { $revision = 65000 }

    $commitCount = Get-GitCommitCount -repoRoot $repoRoot
    if ($commitCount -ne $null) {
        $revision = [Math]::Min($commitCount, 65000)
    } elseif ($revision -eq 0) {
        $revision = [int](Get-Date -UFormat %j)
    }

    return "{0}.{1}.{2}.{3}" -f $parsed.Major, $parsed.Minor, $build, $revision
}

function Write-BuildStamp {
    param(
        [string]$targetDir,
        [string]$version,
        [string]$commit
    )

    if (-not (Test-Path $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }

    $path = Join-Path $targetDir "build-info.txt"
    $lines = @(
        "Version=$version"
        "Commit=$commit"
        "BuildTimeUtc=$([DateTime]::UtcNow.ToString('o'))"
    )

    Set-Content -Path $path -Value $lines -Encoding ASCII
    return $path
}

try {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $project = Join-Path $repoRoot "src\TGWST.App\TGWST.App.csproj"
    $publishAppDir = Join-Path $OutputDir "publish_app"
    $publishUpdaterDir = Join-Path $OutputDir "publish_updater"
    $stageDir = Join-Path $OutputDir "_msi_stage"
    $objDir = Join-Path $OutputDir "obj"
    $harvestFile = Join-Path $objDir "HarvestedFiles.wxs"
    $msiOutput = Join-Path $OutputDir "TGWST.Setup.msi"
    $wxsFile = Join-Path $OutputDir "TGWST.Installer.wxs"
    $iconPath = Join-Path $repoRoot "src\TGWST.App\Assets\generic_windows_security_tool_icon.png"
    $licenseRtf = Join-Path $PSScriptRoot "MIT_LICENSE.rtf"
    $dotnetExe = Get-DotNetExe

    Ensure-CleanDir -path $publishAppDir
    Ensure-CleanDir -path $publishUpdaterDir
    Ensure-CleanDir -path $stageDir
    Ensure-CleanDir -path $objDir

    Write-Host "Using dotnet CLI at $dotnetExe"
    Write-Host "Publishing TGWST ($Configuration, $RuntimeIdentifier) ..."
    & $dotnetExe publish $project `
        -c $Configuration `
        -r $RuntimeIdentifier `
        --self-contained true `
        /p:PublishSingleFile=true `
        /p:IncludeAllContentForSelfExtract=true `
        /p:PublishTrimmed=false `
        -o $publishAppDir
    if ($null -eq $LASTEXITCODE) {
        throw "TGWST publish did not return an exit code. Run installer/build-msi.ps1 from Windows PowerShell where dotnet.exe can execute."
    }
    if ($LASTEXITCODE -ne 0) {
        $publishExit = $LASTEXITCODE
        throw "TGWST publish failed with exit code $publishExit"
    }

    Write-Host "Publishing TGWST Updater..."
    $updaterProject = Join-Path $repoRoot "src\TGWST.Updater\TGWST.Updater.csproj"
    & $dotnetExe publish $updaterProject `
        -c $Configuration `
        -r $RuntimeIdentifier `
        --self-contained true `
        /p:PublishSingleFile=true `
        /p:IncludeAllContentForSelfExtract=true `
        /p:PublishTrimmed=false `
        -o $publishUpdaterDir
    if ($null -eq $LASTEXITCODE) {
        throw "TGWST Updater publish did not return an exit code. Run installer/build-msi.ps1 from Windows PowerShell where dotnet.exe can execute."
    }
    if ($LASTEXITCODE -ne 0) {
        $publishExit = $LASTEXITCODE
        throw "TGWST Updater publish failed with exit code $publishExit"
    }

    Copy-Stage -source $publishAppDir -destination $stageDir
    Copy-Item -Path (Join-Path $publishUpdaterDir "*") -Destination $stageDir -Recurse -Force
    $wdacStage = Join-Path $stageDir "WDAC"
    if (-not (Test-Path $wdacStage)) {
        throw "WDAC payload missing from publish output ($wdacStage). Ensure Assets\WDAC content is copied during publish."
    }
    if (-not (Get-ChildItem $wdacStage -Filter *.xml -ErrorAction SilentlyContinue)) {
        throw "No WDAC XML files found in $wdacStage. Verify wdac-shipped-policies.json and XML assets are included."
    }
    if (-not (Test-Path (Join-Path $wdacStage "wdac-shipped-policies.json"))) {
        throw "wdac-shipped-policies.json not found in $wdacStage. WDAC shipped manifest is required in the staging payload."
    }
    Get-ChildItem $stageDir -Recurse -File | Unblock-File -ErrorAction SilentlyContinue

    $exePath = Join-Path $stageDir "TGWST.exe"
    $appExe = Join-Path $stageDir "TGWST.App.exe"
    if (-not (Test-Path $exePath)) {
        if (Test-Path $appExe) {
            Rename-Item -Path $appExe -NewName "TGWST.exe"
        } else {
            throw "No TGWST executable found in $stageDir"
        }
    }
    $exePath = Join-Path $stageDir "TGWST.exe"
    $exeName = [System.IO.Path]::GetFileName($exePath)

    if (-not (Test-Path $iconPath)) {
        throw "Icon not found at $iconPath"
    }

    $versionInfo = (Get-Item $exePath).VersionInfo
    $rawVersion = $versionInfo.FileVersion
    if (-not $rawVersion) { $rawVersion = $versionInfo.ProductVersion }
    if (-not $rawVersion) { $rawVersion = "1.0.0.0" }
    $rawVersion = ($rawVersion -split '[^0-9\.]')[0]
    $productVersion = Resolve-ProductVersion -rawVersion $rawVersion -repoRoot $repoRoot
    Write-Host "Using product version: $productVersion"

    $commitId = Get-GitCommitId -repoRoot $repoRoot
    if (-not $commitId) { $commitId = "unknown" }

    $stampPaths = @(
        Write-BuildStamp -targetDir $publishAppDir -version $productVersion -commit $commitId
        Write-BuildStamp -targetDir $publishUpdaterDir -version $productVersion -commit $commitId
        Write-BuildStamp -targetDir $stageDir -version $productVersion -commit $commitId
    )
    Write-Host "Build stamp written to: $($stampPaths -join ', ')"

    $heat = Get-WixTool "heat.exe"
    $candle = Get-WixTool "candle.exe"
    $light = Get-WixTool "light.exe"

    Write-Host "Harvesting staged files with heat..."
    & $heat dir $stageDir -cg HarvestedFiles -dr INSTALLFOLDER -srd -sreg -var var.StageDir -out $harvestFile -gg -platform x64 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        $heatExit = if ($null -eq $LASTEXITCODE) { "unknown" } else { $LASTEXITCODE }
        throw "WiX heat.exe failed with exit code $heatExit"
    }

    (Get-Content $harvestFile) -replace '<Component ', '<Component Win64="yes" ' | Set-Content $harvestFile

    Write-Host "Compiling WiX sources..."
    & $candle -nologo `
        -dStageDir="$stageDir" `
        -dProductVersion="$productVersion" `
        -dAppExeName="$exeName" `
        -dIconPath="$iconPath" `
        -dLicenseRtf="$licenseRtf" `
        -out "$objDir\" `
        $wxsFile `
        $harvestFile
    if ($LASTEXITCODE -ne 0) {
        $candleExit = if ($null -eq $LASTEXITCODE) { "unknown" } else { $LASTEXITCODE }
        throw "WiX candle.exe failed with exit code $candleExit"
    }

    Write-Host "Linking MSI..."
    & $light -nologo -ext WixUIExtension -ext WixUtilExtension -out $msiOutput "$objDir\TGWST.Installer.wixobj" "$objDir\HarvestedFiles.wixobj"
    if ($LASTEXITCODE -ne 0) {
        $lightExit = if ($null -eq $LASTEXITCODE) { "unknown" } else { $LASTEXITCODE }
        throw "WiX light.exe failed with exit code $lightExit"
    }

    if (Test-Path $msiOutput) {
        $signCert = $env:SIGN_CERT
        $signPwd = $env:SIGN_PWD
        $signtoolPath = $env:SIGNTOOL_PATH
        if (-not $signtoolPath) {
            $signtoolGuess = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
            $signtoolPath = Get-ChildItem $signtoolGuess -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object { $_.FullName }
        }
        if ($signCert -and $signPwd -and $signtoolPath) {
            $timestamp = if ($env:SIGN_TIMESTAMP) { $env:SIGN_TIMESTAMP } else { "http://timestamp.digicert.com" }
            Write-Host "Signing MSI with $signtoolPath ..."
            & $signtoolPath sign /fd sha256 /f "$signCert" /p "$signPwd" /tr "$timestamp" /td sha256 "$msiOutput"
            if ($LASTEXITCODE -ne 0) {
                $signExit = if ($null -eq $LASTEXITCODE) { "unknown" } else { $LASTEXITCODE }
                throw "MSI signing failed with exit code $signExit"
            }
        } else {
            Write-Host "Signing skipped (missing SIGN_CERT/SIGN_PWD or SIGNTOOL_PATH)."
        }
    } else {
        throw "MSI was not created at $msiOutput"
    }

    Write-Host "Done. MSI output: $msiOutput"

    $distDir = Join-Path $PSScriptRoot "..\INSTALL_FROM_HERE"
    if (Test-Path $msiOutput -PathType Leaf) {
        if (-not (Test-Path $distDir)) {
            New-Item -ItemType Directory -Path $distDir -Force | Out-Null
        }
        Copy-Item $msiOutput $distDir -Force
        Write-Host "Copied to $distDir"
    }
} catch {
    Write-Error $_
    exit 1
}
