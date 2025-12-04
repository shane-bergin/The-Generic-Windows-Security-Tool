$ErrorActionPreference = "Stop"

Add-Type -AssemblyName PresentationFramework

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="TGWST Installer" Height="380" Width="560" WindowStartupLocation="CenterScreen">
  <Grid Margin="12">
    <Grid.RowDefinitions>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <Grid x:Name="PageWelcome">
      <StackPanel>
        <TextBlock Text="Welcome to The Generic Windows Security Tool installer" FontSize="16" FontWeight="Bold" Margin="0,0,0,8"/>
        <TextBlock Text="This wizard will copy TGWST to Program Files and create a Start Menu shortcut." TextWrapping="Wrap"/>
      </StackPanel>
    </Grid>

    <Grid x:Name="PagePaths" Visibility="Collapsed">
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="Auto"/>
        <RowDefinition Height="*"/>
      </Grid.RowDefinitions>
      <StackPanel Margin="0,0,0,8">
        <TextBlock Text="Source (publish) folder:" FontWeight="Bold"/>
        <TextBox x:Name="SourceBox" Margin="0,4,0,0"/>
        <TextBlock Text="If the folder is empty, the wizard will run 'dotnet publish' automatically." FontStyle="Italic" FontSize="12" Margin="0,4,0,0"/>
      </StackPanel>
      <StackPanel Grid.Row="1" Margin="0,0,0,8">
        <TextBlock Text="Install to:" FontWeight="Bold"/>
        <TextBox x:Name="TargetBox" Margin="0,4,0,0"/>
      </StackPanel>
      <StackPanel Grid.Row="2">
        <CheckBox x:Name="ShortcutCheck" IsChecked="True" Content="Create Start Menu shortcut"/>
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

    <StackPanel Grid.Row="1" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0">
      <Button x:Name="BackBtn" Content="Back" Width="80" Margin="0,0,8,0"/>
      <Button x:Name="NextBtn" Content="Next" Width="80" Margin="0,0,8,0"/>
      <Button x:Name="FinishBtn" Content="Finish" Width="80" IsEnabled="False"/>
    </StackPanel>
  </Grid>
</Window>
"@

[xml]$xamlXml = $xaml
$reader = (New-Object System.Xml.XmlNodeReader $xamlXml)
$window = [Windows.Markup.XamlReader]::Load($reader)

# Controls
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

# Defaults
$exeDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$defaultPublish = Join-Path $exeDir "publish"
if (-not (Test-Path $defaultPublish)) {
    $defaultPublish = Join-Path $PSScriptRoot "..\src\TGWST.App\bin\Release\net8.0-windows\win-x64\publish"
}
$SourceBox.Text = $defaultPublish
$TargetBox.Text = Join-Path $Env:ProgramFiles "TGWST"

$currentPage = 1

function Ensure-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        [System.Windows.MessageBox]::Show("Please run this installer as Administrator.", "TGWST Installer", "OK", "Warning") | Out-Null
        throw "Not elevated"
    }
}

function Show-Page($index) {
    $PageWelcome.Visibility = "Collapsed"
    $PagePaths.Visibility = "Collapsed"
    $PageProgress.Visibility = "Collapsed"
    switch ($index) {
        1 { $PageWelcome.Visibility = "Visible"; $BackBtn.IsEnabled = $false; $NextBtn.IsEnabled = $true; $FinishBtn.IsEnabled = $false }
        2 { $PagePaths.Visibility = "Visible"; $BackBtn.IsEnabled = $true; $NextBtn.IsEnabled = $true; $FinishBtn.IsEnabled = $false }
        3 { $PageProgress.Visibility = "Visible"; $BackBtn.IsEnabled = $false; $NextBtn.IsEnabled = $false; $FinishBtn.IsEnabled = $false }
        4 { $PageProgress.Visibility = "Visible"; $BackBtn.IsEnabled = $false; $NextBtn.IsEnabled = $false; $FinishBtn.IsEnabled = $true; $LogBox.AppendText("Done.`r`n") }
    }
    $script:currentPage = $index
}

function Log($msg) { $LogBox.AppendText("$msg`r`n"); $LogBox.ScrollToEnd() }

function Publish-App($src) {
    if (Test-Path (Join-Path $src "TGWST.App.exe")) {
        Log "Publish output already present at $src"
        return
    }
    Log "Running dotnet publish to $src ..."
    dotnet publish "$PSScriptRoot\..\src\TGWST.App\TGWST.App.csproj" -c Release -r win-x64 --self-contained false -o $src /p:PublishSingleFile=true /p:IncludeAllContentForSelfExtract=true | Out-Null
    Log "Publish complete."
}

function Copy-App($src, $dst) {
    if (-not (Test-Path $dst)) { New-Item -ItemType Directory -Path $dst | Out-Null }
    Log "Copying files to $dst ..."
    robocopy $src $dst *.* /E /NFL /NDL /NJH /NJS /NC /NS /XO | Out-Null
    Log "Copy complete."
}

function Create-Shortcut($exePath) {
    $shell = New-Object -ComObject WScript.Shell
    $lnkPath = "$Env:ProgramData\Microsoft\Windows\Start Menu\Programs\TGWST.lnk"
    $lnk = $shell.CreateShortcut($lnkPath)
    $lnk.TargetPath = $exePath
    $lnk.WorkingDirectory = Split-Path $exePath
    $lnk.IconLocation = $exePath
    $lnk.Description = "The Generic Windows Security Tool"
    $lnk.Save()
    Log "Start Menu shortcut created."
}

$BackBtn.Add_Click({
    if ($script:currentPage -gt 1) { Show-Page ($script:currentPage - 1) }
})

$NextBtn.Add_Click({
    if ($script:currentPage -eq 1) { Show-Page 2; return }
    if ($script:currentPage -eq 2) {
        Show-Page 3
        Start-Job -Name "TGWSTInstall" -ScriptBlock {
            param($src,$dst,$makeShortcut,$logFile)
            Import-Module Microsoft.PowerShell.Utility
        } | Out-Null
        Start-Installation
    }
})

function Start-Installation {
    $sourceInput = if ([string]::IsNullOrWhiteSpace($SourceBox.Text)) { $defaultPublish } else { $SourceBox.Text }
    $targetInput = if ([string]::IsNullOrWhiteSpace($TargetBox.Text)) { Join-Path $Env:ProgramFiles "TGWST" } else { $TargetBox.Text }

    try { $source = [System.IO.Path]::GetFullPath($sourceInput) } catch { [System.Windows.MessageBox]::Show("Invalid source path: $sourceInput","TGWST Installer","OK","Error") | Out-Null; Show-Page 2; return }
    try { $target = [System.IO.Path]::GetFullPath($targetInput) } catch { [System.Windows.MessageBox]::Show("Invalid install path: $targetInput","TGWST Installer","OK","Error") | Out-Null; Show-Page 2; return }
    $makeShortcut = $ShortcutCheck.IsChecked

    Start-Job -ScriptBlock {
        param($src,$dst,$makeShortcut)
        try {
            Publish-App -src $src
            Copy-App -src $src -dst $dst
            $exe = Join-Path $dst "TGWST.App.exe"
            if ($makeShortcut -and (Test-Path $exe)) { Create-Shortcut -exePath $exe }
            return @{ Success = $true; Message = "Installed to $dst" }
        } catch {
            return @{ Success = $false; Message = $_.Exception.Message }
        }
    } -ArgumentList $source,$target,$makeShortcut | Receive-Job -Wait -AutoRemoveJob | ForEach-Object {
        if (-not $_.Success) {
            Log "Installation failed: $($_.Message)"
        } else {
            Log $_.Message
            Show-Page 4
        }
    }
}

$FinishBtn.Add_Click({ $window.Close() })

try { Ensure-Admin } catch { return }
Show-Page 1
$window.ShowDialog() | Out-Null
