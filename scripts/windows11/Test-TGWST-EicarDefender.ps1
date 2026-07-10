#requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [int]$WaitSeconds = 10,
    [string]$OutputPath,
    [switch]$OpenReport,
    [switch]$KeepTestDirectory
)

$ErrorActionPreference = 'Continue'
$results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param([string]$Area, [string]$Status, [string]$Detail)

    $results.Add([pscustomobject]@{
        Area = $Area
        Status = $Status
        Detail = $Detail
    })
}

function New-EicarString {
    $codes = @(
        88, 53, 79, 33, 80, 37, 64, 65, 80, 91, 52, 92, 80, 90, 88, 53,
        52, 40, 80, 94, 41, 55, 67, 67, 41, 55, 125, 36, 69, 73, 67, 65,
        82, 45, 83, 84, 65, 78, 68, 65, 82, 68, 45, 65, 78, 84, 73, 86,
        73, 82, 85, 83, 45, 84, 69, 83, 84, 45, 70, 73, 76, 69, 33, 36,
        72, 43, 72, 42
    )

    return -join ($codes | ForEach-Object { [char]$_ })
}

function Test-VersionAtLeast {
    param([string]$Current, [string]$Minimum)

    try {
        return ([version]$Current) -ge ([version]$Minimum)
    } catch {
        return $false
    }
}

function Get-RecentEicarDetection {
    param([datetime]$Since, [string]$TestPath)

    try {
        return @(Get-MpThreatDetection -ErrorAction Stop | Where-Object {
            ($_.ThreatName -match 'EICAR' -or ($_.Resources -join ';') -match [regex]::Escape($TestPath)) -and
            ($_.InitialDetectionTime -ge $Since -or $_.LastThreatStatusChangeTime -ge $Since)
        } | Select-Object -First 5 ThreatID, ThreatName, InitialDetectionTime, LastThreatStatusChangeTime, ActionSuccess, Resources)
    } catch {
        Add-Result 'ThreatDetection' 'Unavailable' $_.Exception.Message
        return @()
    }
}

$startedAt = Get-Date
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) "TGWST-EICAR-$([guid]::NewGuid().ToString('N'))"
$testFile = Join-Path $testRoot 'eicar.com.txt'
$defender = $null
$detections = @()
$created = $false
$remediated = $false
$scanRequested = $false
$safeToExerciseScanner = $false
$status = 'FAIL'
$summary = 'EICAR test file was not detected or remediated within the wait window.'

try {
    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue |
        Select-Object AMProductVersion, AMEngineVersion, AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled
} catch {
    Add-Result 'DefenderStatus' 'Unavailable' $_.Exception.Message
}

if ($defender) {
    Add-Result 'DefenderStatus' 'Observed' "AV=$($defender.AntivirusEnabled); realtime=$($defender.RealTimeProtectionEnabled); IOAV=$($defender.IoavProtectionEnabled); engine=$($defender.AMEngineVersion)"
    $engineFixed = Test-VersionAtLeast $defender.AMEngineVersion '1.1.26050.11'
    $platformFixed = Test-VersionAtLeast $defender.AMProductVersion '4.18.26050.15'
    $protectionsOn = $defender.AntivirusEnabled -eq $true -and $defender.RealTimeProtectionEnabled -eq $true -and $defender.IoavProtectionEnabled -eq $true

    if (-not $engineFixed) {
        Add-Result 'DefenderStatus' 'UnsafeToTest' "Defender engine $($defender.AMEngineVersion) is below the June 2026 baseline 1.1.26050.11, so TGWST will not create EICAR."
    }

    if (-not $platformFixed) {
        Add-Result 'DefenderStatus' 'UnsafeToTest' "Defender platform $($defender.AMProductVersion) is below the June 2026 baseline 4.18.26050.15, so TGWST will not create EICAR."
    }

    if (-not $protectionsOn) {
        Add-Result 'DefenderStatus' 'Warning' 'Microsoft Defender antivirus or realtime protection is not fully enabled.'
    }

    $safeToExerciseScanner = $engineFixed -and $platformFixed -and $protectionsOn
} else {
    Add-Result 'DefenderStatus' 'UnsafeToTest' 'Unable to confirm Defender version and realtime posture, so TGWST will not create EICAR.'
}

if (-not $safeToExerciseScanner) {
    $status = 'SKIPPED'
    $summary = 'EICAR was not created because Defender is not confirmed to be on June 2026 engine/platform builds with realtime and IOAV protection enabled.'
}

if ($safeToExerciseScanner -and $PSCmdlet.ShouldProcess($testFile, 'Create EICAR antivirus readiness test file after fixed-version preflight')) {
    try {
        New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
        Set-Content -LiteralPath $testFile -Value (New-EicarString) -Encoding ASCII -NoNewline -ErrorAction Stop
        $created = $true
        Add-Result 'EICAR' 'Created' "Test file was created at $testFile."
    } catch {
        $status = 'PASS'
        $summary = 'The EICAR test file was blocked during creation, which indicates antivirus enforcement is active.'
        Add-Result 'EICAR' 'Blocked' $_.Exception.Message
    }
}

if ($created -and (Test-Path -LiteralPath $testFile)) {
    try {
        Start-MpScan -ScanType CustomScan -ScanPath $testFile -ErrorAction SilentlyContinue
        $scanRequested = $true
        Add-Result 'DefenderScan' 'Requested' 'Custom scan was requested for the EICAR test file.'
    } catch {
        Add-Result 'DefenderScan' 'Unavailable' $_.Exception.Message
    }
}

if ($created) {
    for ($i = 0; $i -lt [Math]::Max(1, $WaitSeconds); $i++) {
        Start-Sleep -Seconds 1
        $detections = Get-RecentEicarDetection -Since $startedAt -TestPath $testFile
        if ($detections.Count -gt 0) {
            Add-Result 'ThreatDetection' 'Detected' "Defender reported $($detections.Count) EICAR detection record(s)."
            break
        }

        if (-not (Test-Path -LiteralPath $testFile)) {
            $remediated = $true
            Add-Result 'EICAR' 'Remediated' 'The EICAR test file no longer exists after Defender had time to inspect it.'
            break
        }
    }

    if ($detections.Count -gt 0 -or $remediated) {
        $status = 'PASS'
        $summary = 'Defender detected or remediated the EICAR antivirus readiness test.'
    } elseif (Test-Path -LiteralPath $testFile) {
        $status = 'FAIL'
        $summary = 'The EICAR test file remained present after the wait window.'
        Add-Result 'EICAR' 'NotDetected' 'The test file remained present after waiting for Defender response.'
    }
}

if (-not $KeepTestDirectory) {
    try {
        Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
        Add-Result 'Cleanup' 'Requested' 'Temporary EICAR test directory cleanup was requested.'
    } catch {
        Add-Result 'Cleanup' 'Failed' $_.Exception.Message
    }
}

$result = [pscustomobject]@{
    CollectedAt = (Get-Date).ToString('s')
    Status = $status
    Summary = $summary
    WaitSeconds = $WaitSeconds
    TestRoot = $testRoot
    TestFile = $testFile
    Created = $created
    CustomScanRequested = $scanRequested
    Remediated = $remediated
    SafeToExerciseScanner = $safeToExerciseScanner
    DefenderStatus = $defender
    EicarDetections = $detections
    Results = $results
    Notes = @(
        'EICAR is a harmless standard antivirus readiness test string, not malware, but it intentionally exercises the antivirus scanner path.',
        'TGWST refuses to create EICAR unless Defender is already on the June 2026 Windows Defender Antivirus engine and platform thresholds with realtime and IOAV protection enabled.',
        'The signature is assembled at runtime from character codes so source scanners do not flag the repository.',
        'A PASS means Defender blocked, detected, or remediated the test file. A FAIL means the file remained present until TGWST cleanup.'
    )
}

$json = $result | ConvertTo-Json -Depth 7

if ($OutputPath) {
    $parent = Split-Path -Parent $OutputPath
    if ($parent) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    Set-Content -LiteralPath $OutputPath -Value $json -Encoding UTF8
    if ($OpenReport) {
        Start-Process notepad.exe -ArgumentList $OutputPath
    }
}

$json
