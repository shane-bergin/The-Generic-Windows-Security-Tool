[CmdletBinding()]
param(
    [datetime]$StartDate = '2026-05-01',
    [datetime]$EndDate = '2026-06-22',
    [string]$OutputPath,
    [switch]$OpenReport
)

$ErrorActionPreference = 'Continue'

function New-Finding {
    param([string]$Severity, [string]$Area, [string]$Detail, [string]$Action)

    [pscustomobject]@{
        Severity = $Severity
        Area = $Area
        Detail = $Detail
        Action = $Action
    }
}

function Test-VersionAtLeast {
    param([string]$Current, [string]$Minimum)

    try {
        return ([version]$Current) -ge ([version]$Minimum)
    } catch {
        return $false
    }
}

function Get-NodeText {
    param($Node, [string]$XPath, $NamespaceManager)

    $target = $Node.SelectSingleNode($XPath, $NamespaceManager)
    if ($target) {
        return $target.InnerText.Trim()
    }

    return ''
}

function Test-WindowsCve {
    param([string]$Title, [string[]]$ProductNames, [string[]]$Tags)

    $combined = @($Title) + @($ProductNames) + @($Tags)
    $combinedText = $combined -join "`n"
    if ($combinedText -match 'Microsoft Edge|SQL Server|Mariner|CBL-Mariner|Azure Linux|golang\.org/x/sys/windows|github\.com/golang/sys/windows|Mako:|Panic in Dial') {
        return $false
    }

    if ($Title -match 'Windows|Win32k|Microsoft Defender|BitLocker|Secure Boot|Data Deduplication|Netlogon') {
        return $true
    }

    foreach ($tag in $Tags) {
        if ($tag -match 'Windows|Microsoft Defender|BitLocker|Secure Boot|Netlogon|Data Deduplication') {
            return $true
        }
    }

    foreach ($name in $ProductNames) {
        if ($name -match '^(Windows 10|Windows 11|Windows Server|Microsoft server operating system)') {
            return $true
        }
    }

    return $false
}

function Get-WinReInfo {
    $stdout = [System.IO.Path]::GetTempFileName()
    $stderr = [System.IO.Path]::GetTempFileName()

    try {
        $reagent = Join-Path $env:SystemRoot 'System32\reagentc.exe'
        $process = Start-Process -FilePath $reagent -ArgumentList '/info' -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr -ErrorAction Stop
        $output = @()
        if (Test-Path -LiteralPath $stdout) {
            $output += Get-Content -LiteralPath $stdout -ErrorAction SilentlyContinue
        }

        if ($process.ExitCode -ne 0 -and (Test-Path -LiteralPath $stderr)) {
            $output += Get-Content -LiteralPath $stderr -ErrorAction SilentlyContinue
        }

        return ($output -join [Environment]::NewLine).Trim()
    } catch {
        return ''
    } finally {
        Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
}

function Get-WindowsCvesFromCvrf {
    param([string]$CvrfUrl)

    $content = (Invoke-WebRequest -UseBasicParsing -Uri $CvrfUrl -ErrorAction Stop).Content
    [xml]$document = $content
    $ns = New-Object System.Xml.XmlNamespaceManager($document.NameTable)
    $ns.AddNamespace('prod', 'http://www.icasi.org/CVRF/schema/prod/1.1')
    $ns.AddNamespace('vuln', 'http://www.icasi.org/CVRF/schema/vuln/1.1')

    $products = @{}
    foreach ($product in $document.SelectNodes('//prod:FullProductName', $ns)) {
        $products[$product.ProductID] = $product.InnerText.Trim()
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($vulnerability in $document.GetElementsByTagName('Vulnerability', 'http://www.icasi.org/CVRF/schema/vuln/1.1')) {
        $cve = Get-NodeText $vulnerability 'vuln:CVE' $ns
        if ([string]::IsNullOrWhiteSpace($cve)) {
            continue
        }

        $title = Get-NodeText $vulnerability 'vuln:Title' $ns
        $productIds = @()
        foreach ($id in $vulnerability.SelectNodes('vuln:ProductStatuses/vuln:Status/vuln:ProductID', $ns)) {
            $productIds += $id.InnerText.Trim()
        }

        $productNames = @($productIds | Sort-Object -Unique | ForEach-Object { $products[$_] } | Where-Object { $_ })
        $tags = @()
        foreach ($note in $vulnerability.SelectNodes('vuln:Notes/vuln:Note[@Type="Tag"]', $ns)) {
            $tags += $note.InnerText.Trim()
        }

        if (-not (Test-WindowsCve -Title $title -ProductNames $productNames -Tags $tags)) {
            continue
        }

        $threats = @{}
        foreach ($threat in $vulnerability.SelectNodes('vuln:Threats/vuln:Threat', $ns)) {
            $type = $threat.Type
            $description = Get-NodeText $threat 'vuln:Description' $ns
            if ($description) {
                if (-not $threats.ContainsKey($type)) {
                    $threats[$type] = New-Object System.Collections.Generic.List[string]
                }

                if (-not $threats[$type].Contains($description)) {
                    $threats[$type].Add($description)
                }
            }
        }

        $maxScore = 0.0
        $scoreSeen = $false
        $vector = ''
        foreach ($scoreSet in $vulnerability.SelectNodes('vuln:CVSSScoreSets/vuln:ScoreSet', $ns)) {
            $scoreText = Get-NodeText $scoreSet 'vuln:BaseScore' $ns
            $score = 0.0
            if ([double]::TryParse($scoreText, [ref]$score) -and $score -gt $maxScore) {
                $scoreSeen = $true
                $maxScore = $score
                $vector = Get-NodeText $scoreSet 'vuln:Vector' $ns
            }
        }

        $exploitStatus = if ($threats.ContainsKey('Exploit Status')) { $threats['Exploit Status'] -join '; ' } else { '' }
        $impact = if ($threats.ContainsKey('Impact')) { $threats['Impact'] -join ', ' } else { '' }
        $severity = if ($threats.ContainsKey('Severity')) { $threats['Severity'] -join ', ' } else { '' }

        $rows.Add([pscustomobject]@{
            CVE = $cve
            Title = $title
            Component = if ($tags.Count -gt 0) { $tags[0] } else { ($title -replace ' Vulnerability$', '') }
            Severity = $severity
            Impact = $impact
            CVSS = if ($scoreSeen) { $maxScore } else { $null }
            Vector = $vector
            ExploitStatus = $exploitStatus
            PubliclyDisclosed = $exploitStatus -match 'Publicly Disclosed:Yes'
            Exploited = $exploitStatus -match 'Exploited:Yes'
            AffectedProductCount = $productNames.Count
            MSRC = "https://msrc.microsoft.com/update-guide/vulnerability/$cve"
        })
    }

    return $rows
}

$findings = New-Object System.Collections.Generic.List[object]
$releaseRows = @()
$windowsCves = New-Object System.Collections.Generic.List[object]

try {
    $updates = Invoke-RestMethod -Uri 'https://api.msrc.microsoft.com/cvrf/v3.0/updates' -ErrorAction Stop
    foreach ($release in $updates.value) {
        $released = [datetime]$release.InitialReleaseDate
        if ($released -lt $StartDate -or $released -gt $EndDate) {
            continue
        }

        $releaseRows += [pscustomobject]@{
            ID = $release.ID
            InitialReleaseDate = $release.InitialReleaseDate
            CurrentReleaseDate = $release.CurrentReleaseDate
            CvrfUrl = $release.CvrfUrl
        }

        foreach ($row in Get-WindowsCvesFromCvrf -CvrfUrl $release.CvrfUrl) {
            $windowsCves.Add($row)
        }
    }
} catch {
    $findings.Add((New-Finding 'WARN' 'MSRC' "Unable to retrieve MSRC CVRF data: $($_.Exception.Message)" 'Retry when internet connectivity is available.'))
}

$kevRows = @()
try {
    $kev = Invoke-RestMethod -Uri 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' -ErrorAction Stop
    $wanted = @($windowsCves | ForEach-Object CVE)
    $kevRows = @($kev.vulnerabilities | Where-Object { $wanted -contains $_.cveID } |
        Select-Object cveID, dateAdded, dueDate, vulnerabilityName, knownRansomwareCampaignUse)
} catch {
    $findings.Add((New-Finding 'WARN' 'CISA KEV' "Unable to retrieve CISA KEV data: $($_.Exception.Message)" 'Retry when internet connectivity is available.'))
}

$computerInfo = $null
$currentVersion = $null
$hotfixes = @()
$defender = $null
$preferences = $null
$bitlocker = @()
$winRe = ''
$domainRole = $null

try { $computerInfo = Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber, OsHardwareAbstractionLayer } catch {}
try { $currentVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue | Select-Object ProductName, DisplayVersion, CurrentBuildNumber, UBR } catch {}
try { $hotfixes = @(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 HotFixID, Description, InstalledOn, InstalledBy) } catch {}
try { $defender = Get-MpComputerStatus | Select-Object AMProductVersion, AMEngineVersion, AntivirusSignatureVersion, AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled, NISEnabled, QuickScanAge, FullScanAge } catch {}
try { $preferences = Get-MpPreference | Select-Object DisableRealtimeMonitoring, DisableIOAVProtection, DisableBehaviorMonitoring, DisableArchiveScanning, MAPSReporting, SubmitSamplesConsent, PUAProtection, AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions } catch {}
try { $bitlocker = @(Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage, KeyProtector) } catch {}
try { $winRe = Get-WinReInfo } catch {}
try { $domainRole = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).DomainRole } catch {}

$recentSecurityUpdate = @($hotfixes | Where-Object {
    $_.Description -match 'Security Update' -and $_.InstalledOn -and ([datetime]$_.InstalledOn) -ge [datetime]'2026-06-09'
})

$buildCurrent = $false
$buildNumber = 0
$ubr = -1
if ($currentVersion) {
    [void][int]::TryParse([string]$currentVersion.CurrentBuildNumber, [ref]$buildNumber)
    [void][int]::TryParse([string]$currentVersion.UBR, [ref]$ubr)
    if (($buildNumber -in 26100,26200 -and $ubr -ge 8655) -or ($buildNumber -eq 22631 -and $ubr -ge 7219)) {
        $buildCurrent = $true
    }
}

if ($recentSecurityUpdate.Count -eq 0 -and -not $buildCurrent) {
    $findings.Add((New-Finding 'CRITICAL' 'Windows Update' 'No installed Windows security update dated June 9, 2026 or newer was found, and the local build does not match the June 2026 Windows cumulative-update baseline where TGWST can determine it.' 'Run Windows Update and verify KB5094126 or KB5093998, or the applicable June 2026 cumulative/security update, installs successfully.'))
}

if ($defender) {
    if (-not (Test-VersionAtLeast $defender.AMEngineVersion '1.1.26050.11')) {
        $findings.Add((New-Finding 'CRITICAL' 'Microsoft Defender' "Malware Protection Engine $($defender.AMEngineVersion) is below the June 2026 Windows Defender Antivirus engine baseline 1.1.26050.11." 'Run Update-MpSignature or Windows Update immediately.'))
    }

    if (-not (Test-VersionAtLeast $defender.AMProductVersion '4.18.26050.15')) {
        $findings.Add((New-Finding 'CRITICAL' 'Microsoft Defender' "Antimalware Platform $($defender.AMProductVersion) is below the June 2026 Windows Defender Antivirus platform baseline 4.18.26050.15." 'Run Windows Update or Defender platform update immediately.'))
    }

    if ($defender.RealTimeProtectionEnabled -ne $true -or $defender.IoavProtectionEnabled -ne $true) {
        $findings.Add((New-Finding 'CRITICAL' 'Microsoft Defender' 'Realtime or downloaded-file inspection is not fully enabled.' 'Enable Defender realtime and IOAV protection.'))
    }
}

if ($domainRole -in 4,5) {
    $findings.Add((New-Finding 'CRITICAL' 'Windows Netlogon' 'This machine reports as a domain controller, so CVE-2026-41089 is high priority.' 'Verify May/June 2026 Windows Server security updates and restrict Netlogon exposure.'))
}

$winReEnabled = $winRe -match 'Windows RE status:\s+Enabled'
foreach ($volume in $bitlocker) {
    if ($volume.ProtectionStatus -eq 1 -and $winReEnabled) {
        $findings.Add((New-Finding 'WARN' 'BitLocker / WinRE' "BitLocker protection is on for $($volume.MountPoint) and WinRE is enabled." 'Apply Microsoft CVE-2026-45585 mitigation guidance or require a BitLocker startup PIN.'))
    } elseif ($volume.MountPoint -eq 'C:' -and $volume.ProtectionStatus -ne 1) {
        $findings.Add((New-Finding 'INFO' 'BitLocker' 'C: is not BitLocker-protected. CVE-2026-45585 does not bypass BitLocker protection here because BitLocker protection is absent, but data-at-rest protection is also absent.' 'Consider enabling BitLocker once CVE-2026-45585 mitigation is handled.'))
    }
}

if ($findings.Count -eq 0) {
    $findings.Add((New-Finding 'INFO' 'Posture' 'No critical local posture gaps were detected for the May/June 2026 Windows/Defender CVE set.' 'Keep Windows Update and Defender automatic updates enabled.'))
}

$result = [pscustomobject]@{
    CollectedAt = (Get-Date).ToString('s')
    Window = [pscustomobject]@{
        StartDate = $StartDate.ToString('yyyy-MM-dd')
        EndDate = $EndDate.ToString('yyyy-MM-dd')
    }
    Sources = [pscustomobject]@{
        MsrcUpdates = 'https://api.msrc.microsoft.com/cvrf/v3.0/updates'
        MsrcMayCvrf = 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-May'
        MsrcJuneCvrf = 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Jun'
        CisaKev = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    }
    Releases = $releaseRows
    WindowsCveCount = $windowsCves.Count
    WindowsCves = @($windowsCves | Sort-Object @{ Expression = 'Exploited'; Descending = $true }, @{ Expression = 'CVSS'; Descending = $true }, CVE)
    CisaKnownExploited = $kevRows
    LocalPosture = [pscustomobject]@{
        ComputerInfo = $computerInfo
        CurrentVersion = $currentVersion
        RecentHotfixes = $hotfixes
        DefenderStatus = $defender
        DefenderPreference = $preferences
        BitLockerVolumes = $bitlocker
        WinRE = $winRe
        DomainRole = $domainRole
    }
    Findings = $findings
}

$json = $result | ConvertTo-Json -Depth 9

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
