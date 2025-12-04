[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [string]$RuntimeIdentifier = "win-x64",
    [string]$OutputDir = "$PSScriptRoot"
)

$ErrorActionPreference = "Stop"

function Get-WixTool {
    param([string]$name)

    $candidates = @(
        $env:WIX_BIN,
        $env:WIX,
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
    $robocopyArgs = @($source, $destination, "*.*", "/E", "/XF", "*.pdb", "/NFL", "/NDL", "/NJH", "/NJS", "/NC", "/NS", "/XO")
    & robocopy @robocopyArgs | Out-Null
    $exitCode = $LASTEXITCODE
    if ($exitCode -gt 3) {
        throw "robocopy failed with exit code $exitCode"
    }
}

function Ensure-ClamAvPayload {
    param(
        [string]$destDir,
        [string]$downloadCache = ""
    )

    $clamBin = Join-Path $destDir "bin"
    $clamDb = Join-Path $destDir "db"

    if (-not $downloadCache) { $downloadCache = Join-Path $PSScriptRoot "_downloads" }
    if (-not (Test-Path $downloadCache)) { New-Item -ItemType Directory -Path $downloadCache | Out-Null }

    if ((Test-Path (Join-Path $clamBin "clamscan.exe")) -and (Test-Path (Join-Path $clamBin "freshclam.exe"))) {
        Write-Host "ClamAV payload already present; skipping download."
    } else {
        Write-Host "Preparing portable ClamAV..."
        $zipUrl = "https://www.clamav.net/downloads/production/clamav-1.4.1.win.x64.zip"
        $zipPath = Join-Path $downloadCache "clamav-portable.zip"
        if (-not (Test-Path $zipPath)) {
            try {
                Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -ErrorAction Stop
            } catch {
                throw "Failed to download ClamAV payload. Place clamav-portable.zip at $zipPath and re-run. Error: $($_.Exception.Message)"
            }
        } else {
            Write-Host "Using cached ClamAV archive: $zipPath"
        }

        $tmp = Join-Path $downloadCache "clamav-extract"
        Ensure-CleanDir -path $tmp
        Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
        $clamscan = Get-ChildItem $tmp -Recurse -Filter clamscan.exe | Select-Object -First 1
        if (-not $clamscan) { throw "clamscan.exe not found in downloaded archive." }
        $clamDir = $clamscan.DirectoryName
        Ensure-CleanDir -path $clamBin
        Get-ChildItem $clamDir -Filter "*.exe" | ForEach-Object { Copy-Item $_.FullName -Destination $clamBin }
    }

    if (-not (Test-Path $clamDb)) { New-Item -ItemType Directory -Path $clamDb | Out-Null }

    $dbFiles = @("main.cvd","daily.cvd","bytecode.cvd")
    foreach ($db in $dbFiles) {
        $target = Join-Path $clamDb $db
        if (-not (Test-Path $target)) {
            Write-Host "Downloading signatures: $db"
            $url = "https://database.clamav.net/$db"
            try {
                Invoke-WebRequest -Uri $url -OutFile $target -ErrorAction Stop
            } catch {
                Write-Warning ("Failed to download {0}: {1}. Creating placeholder." -f $db, $_.Exception.Message)
                New-Item -ItemType File -Path $target -Force | Out-Null
            }
        }
    }

    $confPath = Join-Path $clamDb "freshclam.conf"
    if (-not (Test-Path $confPath)) {
        $programDataClam = "C:\ProgramData\TGWST\ClamAV\db"
        @"
DatabaseDirectory "$programDataClam"
UpdateLogFile "$programDataClam\freshclam.log"
LogTime yes
DatabaseMirror database.clamav.net
NotifyClamd false
"@ | Out-File -FilePath $confPath -Encoding ASCII -Force
    }
}

try {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $project = Join-Path $repoRoot "src\TGWST.App\TGWST.App.csproj"
    $publishDir = Join-Path $OutputDir "publish"
    $stageDir = Join-Path $OutputDir "_msi_stage"
    $clamavStage = Join-Path $OutputDir "_clamav_stage"
    $objDir = Join-Path $OutputDir "obj"
    $harvestFile = Join-Path $objDir "HarvestedFiles.wxs"
    $clamHarvest = Join-Path $objDir "HarvestedClam.wxs"
    $msiOutput = Join-Path $OutputDir "TGWST.Setup.msi"
    $wxsFile = Join-Path $OutputDir "TGWST.Installer.wxs"
    $iconPath = Join-Path $repoRoot "src\TGWST.App\Assets\generic_windows_security_tool_icon.png"
    $licenseRtf = Join-Path $PSScriptRoot "MIT_LICENSE.rtf"

    Ensure-CleanDir -path $publishDir
    Ensure-CleanDir -path $stageDir
    Ensure-CleanDir -path $clamavStage
    Ensure-CleanDir -path $objDir

    Write-Host "Publishing TGWST ($Configuration, $RuntimeIdentifier) ..."
    dotnet publish $project `
        -c $Configuration `
        -r $RuntimeIdentifier `
        --self-contained true `
        /p:PublishSingleFile=true `
        /p:IncludeAllContentForSelfExtract=true `
        /p:PublishTrimmed=false `
        -o $publishDir

    Copy-Stage -source $publishDir -destination $stageDir
    # Remove Mark-of-the-Web from all staged files
    Get-ChildItem $stageDir -Recurse -File | Unblock-File -ErrorAction SilentlyContinue

    Write-Host "Preparing ClamAV payload..."
    Ensure-ClamAvPayload -destDir $clamavStage
    Get-ChildItem $clamavStage -Recurse -File | Unblock-File -ErrorAction SilentlyContinue
    Copy-Stage -source $clamavStage -destination (Join-Path $publishDir "ClamAV")
    Get-ChildItem (Join-Path $publishDir "ClamAV") -Recurse -File | Unblock-File -ErrorAction SilentlyContinue

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
    $productVersion = $versionInfo.FileVersion
    if (-not $productVersion) { $productVersion = $versionInfo.ProductVersion }
    if (-not $productVersion) { $productVersion = "1.0.0.0" }
    $productVersion = ($productVersion -split '[^0-9\.]')[0]
    if (-not [Version]::TryParse($productVersion, [ref]([Version]::new()))) {
        $productVersion = "1.0.0.0"
    }

    $heat = Get-WixTool "heat.exe"
    $candle = Get-WixTool "candle.exe"
    $light = Get-WixTool "light.exe"

    Write-Host "Harvesting staged files with heat..."
    & $heat dir $stageDir -cg HarvestedFiles -dr INSTALLFOLDER -srd -sreg -var var.StageDir -out $harvestFile -gg -platform x64 | Out-Null
    & $heat dir $clamavStage -cg ClamAvFiles -dr CLAMAVDIR -srd -sreg -var var.ClamAvDir -out $clamHarvest -gg -platform x64 | Out-Null

    # Ensure binaries under ProgramFiles64Folder are marked Win64
    (Get-Content $harvestFile) -replace '<Component ', '<Component Win64="yes" ' | Set-Content $harvestFile

    # ------------------------------------------------------------------
    # FINAL VALIDATION: every native DLL that will ship MUST be harvested
    # ------------------------------------------------------------------
    Write-Host "`nValidating native DLL harvest..." -ForegroundColor Cyan

    $onDiskDlls = @(
        Get-ChildItem $stageDir    -Recurse -Filter *.dll -ErrorAction SilentlyContinue
        Get-ChildItem $clamavStage -Recurse -Filter *.dll -ErrorAction SilentlyContinue
    ) | Select-Object -ExpandProperty Name -Unique

    $harvestedDlls = @()

    if (Test-Path $harvestFile) {
        $harvestedDlls += Select-String -Path $harvestFile -Pattern 'Name="([^"]+\.dll)"' |
            ForEach-Object {
                $m = [regex]::Match($_.Line, 'Name="([^"]+\.dll)"')
                if ($m.Success) { $m.Groups[1].Value }
            }
    }

    if (Test-Path $clamHarvest) {
        $harvestedDlls += Select-String -Path $clamHarvest -Pattern 'Name="([^"]+\.dll)"' |
            ForEach-Object {
                $m = [regex]::Match($_.Line, 'Name="([^"]+\.dll)"')
                if ($m.Success) { $m.Groups[1].Value }
            }
    }

    $harvestedDlls = $harvestedDlls | Sort-Object -Unique

    $missing = $onDiskDlls | Where-Object { $harvestedDlls -notcontains $_ }

    if ($missing) {
        Write-Host "DLLs found on disk (will be installed):" -ForegroundColor Yellow
        $onDiskDlls | ForEach-Object { Write-Host "  $_" }

        Write-Host "`nDLLs actually harvested into .wxs:" -ForegroundColor Yellow
        $harvestedDlls | ForEach-Object { Write-Host "  $_" }

        Write-Error "`nFATAL: The following native DLLs exist on disk but were NOT harvested:"
        $missing | ForEach-Object { Write-Error "  $_" }
        throw "Harvest incomplete - native DLLs missing"
    }

    Write-Host "Harvest validation PASSED - all $($onDiskDlls.Count) native DLL(s) are correctly harvested:" -ForegroundColor Green
    $onDiskDlls | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGreen }

    Write-Host "Compiling WiX sources..."
    & $candle -nologo `
        -dStageDir="$stageDir" `
        -dClamAvDir="$clamavStage" `
        -dProductVersion="$productVersion" `
        -dAppExeName="$exeName" `
        -dIconPath="$iconPath" `
        -dLicenseRtf="$licenseRtf" `
        -out "$objDir\" `
        $wxsFile `
        $harvestFile `
        $clamHarvest

    Write-Host "Linking MSI..."
    & $light -nologo -ext WixUIExtension -ext WixUtilExtension -out $msiOutput "$objDir\TGWST.Installer.wixobj" "$objDir\HarvestedFiles.wixobj" "$objDir\HarvestedClam.wixobj"

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
        } else {
            Write-Host "Signing skipped (missing SIGN_CERT/SIGN_PWD or SIGNTOOL_PATH)."
        }
    } else {
        throw "MSI was not created at $msiOutput"
    }

    Write-Host "Done. MSI output: $msiOutput"
} catch {
    Write-Error $_
    exit 1
}



