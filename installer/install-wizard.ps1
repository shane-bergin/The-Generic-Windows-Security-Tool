$ErrorActionPreference = "Stop"

Add-Type -AssemblyName PresentationFramework

function Get-DefaultSourcePath {
    $candidates = @(
        Join-Path $PSScriptRoot "publish",
        Join-Path $PSScriptRoot "payload",
        Join-Path (Split-Path -Parent $PSScriptRoot) "publish",
        Join-Path $PSScriptRoot "..\src\TGWST.App\bin\Release\net8.0-windows\win-x64\publish"
    ) | Get-Unique

    foreach ($candidate in $candidates) {
        try {
            if (Test-Path $candidate) {
                return (Resolve-Path $candidate).Path
            }
        } catch { }
    }

    return (Join-Path $PSScriptRoot "publish")
}

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="TGWST Installer" Height="400" Width="640" WindowStartupLocation="CenterScreen">
  <Grid Margin="14">
    <Grid.RowDefinitions>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <Grid x:Name="PageWelcome">
      <StackPanel>
        <TextBlock Text="Welcome to The Generic Windows Security Tool installer" FontSize="16" FontWeight="Bold" Margin="0,0,0,10"/>
        <TextBlock Text="This wizard installs TGWST under Program Files and can add a Start Menu shortcut. If no publish payload is found beside the installer, it will build one before copying files." TextWrapping="Wrap" Margin="0,0,0,6"/>
        <TextBlock Text="Click Next to review the install path. If no publish folder is provided, the wizard will build one for you." TextWrapping="Wrap" Margin="0,0,0,6"/>
        <TextBlock Text="Run as Administrator so we can write to Program Files and create Start Menu shortcuts." TextWrapping="Wrap" FontStyle="Italic"/>
      </StackPanel>
    </Grid>

    <Grid x:Name="PagePaths" Visibility="Collapsed">
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="*"/>
      </Grid.RowDefinitions>

      <StackPanel Margin="0,0,0,10">
        <TextBlock Text="Source (publish) folder" FontWeight="Bold"/>
        <TextBox x:Name="SourceBox" Margin="0,6,0,0"/>
        <TextBlock Text="Point this to a TGWST publish folder placed next to the installer. If it is empty, we'll run 'dotnet publish' automatically." FontStyle="Italic" FontSize="12" TextWrapping="Wrap" Margin="0,6,0,0"/>
      </StackPanel>

      <StackPanel Grid.Row="1" Margin="0,0,0,10">
        <TextBlock Text="Install to" FontWeight="Bold"/>
        <TextBox x:Name="TargetBox" Margin="0,6,0,0"/>
      </StackPanel>

      <StackPanel Grid.Row="2">
        <CheckBox x:Name="ShortcutCheck" IsChecked="True" Content="Create a Start Menu shortcut"/>
      </StackPanel>
    </Grid>

    <Grid x:Name="PageProgress" Visibility="Collapsed">
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="*"/>
      </Grid.RowDefinitions>
      <TextBlock Text="Installing..." FontWeight="Bold" Margin="0,0,0,8"/>
      <TextBox x:Name="LogBox" Grid.Row="1" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"/>
    </Grid>

    <StackPanel Grid.Row="1" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,14,0,0">
      <Button x:Name="BackBtn" Content="Back" Width="88" Margin="0,0,8,0"/>
      <Button x:Name="NextBtn" Content="Next" Width="88" Margin="0,0,8,0"/>
      <Button x:Name="FinishBtn" Content="Finish" Width="88" IsEnabled="False"/>
    </StackPanel>
  </Grid>
</Window>
"@

[xml]$xamlXml = $xaml
$reader = (New-Object System.Xml.XmlNodeReader $xamlXml)
$window = [Windows.Markup.XamlReader]::Load($reader)

$PageWelcome = $window.FindName("PageWelcome")
$PagePaths = $window.FindName("PagePaths")
$PageProgress = $window.FindName("PageProgress")
$BackBtn = $window.FindName("BackBtn")
$NextBtn = $window.FindName("NextBtn")
$FinishBtn = $window.FindName("FinishBtn")
$SourceBox = $window.FindName("SourceBox")
$TargetBox = $window.FindName("TargetBox")
$ShortcutCheck = $window.FindName("ShortcutCheck")
$LogBox = $window.FindName("LogBox")

$defaultPublish = Get-DefaultSourcePath
$SourceBox.Text = $defaultPublish
$TargetBox.Text = Join-Path $Env:ProgramFiles "TGWST"

$currentPage = 1
$installJob = $null
$jobTimer = $null
$lastResult = $null
$projectPath = Join-Path $PSScriptRoot "..\src\TGWST.App\TGWST.App.csproj"

function Ensure-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        [System.Windows.MessageBox]::Show("Run this installer as Administrator so we can write to Program Files.", "TGWST Installer", "OK", "Warning") | Out-Null
        return $false
    }
    return $true
}

function Show-Page($index) {
    $PageWelcome.Visibility = "Collapsed"
    $PagePaths.Visibility = "Collapsed"
    $PageProgress.Visibility = "Collapsed"

    switch ($index) {
        1 {
            $PageWelcome.Visibility = "Visible"
            $BackBtn.IsEnabled = $false
            $NextBtn.IsEnabled = $true
            $NextBtn.Content = "Next"
            $FinishBtn.IsEnabled = $false
        }
        2 {
            $PagePaths.Visibility = "Visible"
            $BackBtn.IsEnabled = $true
            $NextBtn.IsEnabled = $true
            $NextBtn.Content = "Install"
            $FinishBtn.IsEnabled = $false
        }
        3 {
            $PageProgress.Visibility = "Visible"
            $BackBtn.IsEnabled = $false
            $NextBtn.IsEnabled = $false
            $FinishBtn.IsEnabled = $false
            $LogBox.Clear()
        }
        4 {
            $PageProgress.Visibility = "Visible"
            $BackBtn.IsEnabled = $false
            $NextBtn.IsEnabled = $false
            $FinishBtn.IsEnabled = $true
            $LogBox.AppendText("Done.`r`n")
            $FinishBtn.Focus()
        }
    }

    $script:currentPage = $index
}

function Log($msg) {
    $LogBox.AppendText("$msg`r`n")
    $LogBox.ScrollToEnd()
}

function Start-InstallJob($src, $dst, $makeShortcut) {
    if ($script:installJob) {
        try { $script:installJob | Stop-Job -Force -ErrorAction SilentlyContinue } catch { }
        try { $script:installJob | Remove-Job -Force -ErrorAction SilentlyContinue } catch { }
    }
    if ($script:jobTimer) {
        $script:jobTimer.Stop()
        $script:jobTimer = $null
    }
    $script:lastResult = $null

    $scriptBlock = {
        param($projectPath, $src, $dst, $makeShortcut)
        $ErrorActionPreference = "Stop"

        function Emit {
            param($type, $message, $success = $null)
            if ($type -eq "Result") {
                return [pscustomobject]@{ Type = $type; Message = $message; Success = $success }
            }
            return [pscustomobject]@{ Type = $type; Message = $message }
        }

        function LogLine { param($msg) Write-Output (Emit -type "Log" -message $msg) }

        function Ensure-Publish {
            param($proj, $outputPath)
            LogLine "Building TGWST publish output..."
            if (-not (Test-Path $outputPath)) {
                New-Item -ItemType Directory -Path $outputPath | Out-Null
            }
            $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
            if (-not $dotnet) {
                throw "dotnet SDK is required to publish TGWST. Provide a pre-built publish folder instead."
            }
            dotnet publish $proj -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:IncludeAllContentForSelfExtract=true /p:PublishTrimmed=false -o $outputPath | Out-Null
            LogLine "Publish complete."
        }

        function Copy-AppFiles {
            param($sourcePath, $targetPath)
            if (-not (Test-Path $sourcePath)) {
                throw "Source path not found: $sourcePath"
            }
            if (-not (Test-Path $targetPath)) {
                New-Item -ItemType Directory -Path $targetPath | Out-Null
            }
            LogLine "Copying files to $targetPath ..."
            robocopy $sourcePath $targetPath *.* /E /NFL /NDL /NJH /NJS /NC /NS /XO | Out-Null
            LogLine "Copy complete."
        }

        function Copy-ClamAvPayload {
            param($sourcePath)
            $clamSrc = Join-Path $sourcePath "ClamAV"
            if (-not (Test-Path $clamSrc)) {
                LogLine "ClamAV payload not found at $clamSrc (skipping)."
                return
            }
            $clamDst = Join-Path $Env:ProgramData "TGWST\ClamAV"
            if (-not (Test-Path $clamDst)) { New-Item -ItemType Directory -Path $clamDst | Out-Null }
            LogLine "Copying ClamAV payload to $clamDst ..."
            robocopy $clamSrc $clamDst *.* /E /NFL /NDL /NJH /NJS /NC /NS /XO | Out-Null
            LogLine "ClamAV payload copied."
        }

        function Create-StartShortcut {
            param($exePath)
            $shell = New-Object -ComObject WScript.Shell
            $lnkPath = "$Env:ProgramData\Microsoft\Windows\Start Menu\Programs\TGWST.lnk"
            $lnk = $shell.CreateShortcut($lnkPath)
            $lnk.TargetPath = $exePath
            $lnk.WorkingDirectory = Split-Path $exePath
            $lnk.IconLocation = $exePath
            $lnk.Description = "The Generic Windows Security Tool"
            $lnk.Save()
            LogLine "Start Menu shortcut created."
        }

        try {
            $srcPath = [System.IO.Path]::GetFullPath($src)
            $dstPath = [System.IO.Path]::GetFullPath($dst)

            if (-not (Test-Path $srcPath)) {
                New-Item -ItemType Directory -Path $srcPath | Out-Null
            }
            if (-not (Test-Path $dstPath)) {
                New-Item -ItemType Directory -Path $dstPath | Out-Null
            }

            LogLine "Source: $srcPath"
            LogLine "Target: $dstPath"

            $publishedExe = Join-Path $srcPath "TGWST.exe"
            $legacyExe = Join-Path $srcPath "TGWST.App.exe"
            if (-not (Test-Path $publishedExe)) {
                if (Test-Path $legacyExe) {
                    Rename-Item -Path $legacyExe -NewName "TGWST.exe"
                    $publishedExe = Join-Path $srcPath "TGWST.exe"
                } else {
                    Ensure-Publish -proj $projectPath -outputPath $srcPath
                }
            } else {
                LogLine "Found existing publish output."
            }

            Copy-AppFiles -sourcePath $srcPath -targetPath $dstPath
            Copy-ClamAvPayload -sourcePath $srcPath

            $installedExe = Join-Path $dstPath "TGWST.exe"
            if (-not (Test-Path $installedExe)) {
                $installedLegacy = Join-Path $dstPath "TGWST.App.exe"
                if (Test-Path $installedLegacy) {
                    Rename-Item -Path $installedLegacy -NewName "TGWST.exe"
                    $installedExe = Join-Path $dstPath "TGWST.exe"
                }
            }
            if (-not (Test-Path $installedExe)) {
                throw "Install failed; $installedExe was not found after copy."
            }

            if ($makeShortcut) {
                Create-StartShortcut -exePath $installedExe
            }

            Write-Output (Emit -type "Result" -message "Installed to $dstPath" -success $true)
        } catch {
            Write-Output (Emit -type "Result" -message $_.Exception.Message -success $false)
        }
    }

    $script:installJob = Start-Job -ScriptBlock $scriptBlock -ArgumentList $projectPath, $src, $dst, $makeShortcut

    $script:jobTimer = New-Object Windows.Threading.DispatcherTimer
    $script:jobTimer.Interval = [TimeSpan]::FromMilliseconds(400)
    $script:jobTimer.Add_Tick({
        if (-not $script:installJob) { return }
        $entries = Receive-Job $script:installJob -Keep -ErrorAction SilentlyContinue
        foreach ($entry in $entries) {
            if ($entry -is [pscustomobject] -and $entry.PSObject.Properties.Name -contains "Type") {
                if ($entry.Type -eq "Log") { Log $entry.Message }
                elseif ($entry.Type -eq "Result") { $script:lastResult = $entry }
            } elseif ($entry) {
                Log "$entry"
            }
        }

        if ($script:installJob.State -in @("Completed", "Failed")) {
            if (-not $script:lastResult) {
                $script:lastResult = [pscustomobject]@{ Type = "Result"; Success = $false; Message = "Installer job ended unexpectedly." }
            }

            if ($script:lastResult.Success) {
                Log $script:lastResult.Message
                Show-Page 4
            } else {
                Log "Installation failed: $($script:lastResult.Message)"
                [System.Windows.MessageBox]::Show("Installation failed: $($script:lastResult.Message)", "TGWST Installer", "OK", "Error") | Out-Null
                Show-Page 2
            }

            try { $script:installJob | Remove-Job -Force -ErrorAction SilentlyContinue } catch { }
            $script:installJob = $null
            $script:lastResult = $null
            $script:jobTimer.Stop()
        }
    })

    $script:jobTimer.Start()
}

$BackBtn.Add_Click({
    if ($script:currentPage -gt 1) {
        Show-Page ($script:currentPage - 1)
    }
})

$NextBtn.Add_Click({
    if ($script:currentPage -eq 1) {
        Show-Page 2
        return
    }

    if ($script:currentPage -eq 2) {
        $sourceInput = if ([string]::IsNullOrWhiteSpace($SourceBox.Text)) { $defaultPublish } else { $SourceBox.Text }
        $targetInput = if ([string]::IsNullOrWhiteSpace($TargetBox.Text)) { Join-Path $Env:ProgramFiles "TGWST" } else { $TargetBox.Text }

        try { $source = [System.IO.Path]::GetFullPath($sourceInput) } catch { [System.Windows.MessageBox]::Show("Invalid source path: $sourceInput","TGWST Installer","OK","Error") | Out-Null; return }
        try { $target = [System.IO.Path]::GetFullPath($targetInput) } catch { [System.Windows.MessageBox]::Show("Invalid install path: $targetInput","TGWST Installer","OK","Error") | Out-Null; return }

        Show-Page 3
        $makeShortcut = [bool]$ShortcutCheck.IsChecked
        Start-InstallJob -src $source -dst $target -makeShortcut $makeShortcut
    }
})

$FinishBtn.Add_Click({ $window.Close() })

if (-not (Ensure-Admin)) { return }
Show-Page 1
$window.ShowDialog() | Out-Null
