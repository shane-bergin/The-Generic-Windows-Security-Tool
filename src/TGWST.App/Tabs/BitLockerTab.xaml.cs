using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using TGWST.Core.Security;

namespace TGWST.App.Tabs;

public partial class BitLockerTab : System.Windows.Controls.UserControl
{
    private readonly BitLockerEngine _engine = new();
    private readonly BitLockerViewModel _vm = new();

    public BitLockerTab()
    {
        InitializeComponent();
        DataContext = _vm;
        _vm.LoadDrives(_engine);
    }

    private void Status_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.SelectedDrive == null) return;
        try
        {
            _vm.OutputText = _engine.GetStatus();
        }
        catch (Exception ex)
        {
            _vm.OutputText = $"Status failed: {ex.Message}";
        }
    }

    private void EnableOs_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.SelectedDrive == null) return;
        try
        {
            _engine.EnableOsDrive(_vm.SelectedDrive.DriveLetter, _vm.Pin);
            _vm.OutputText = "OS drive encryption started.";
        }
        catch (Exception ex)
        {
            _vm.OutputText = $"Enable OS failed: {ex.Message}";
        }
    }

    private void EnableFixed_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.SelectedDrive == null) return;
        try
        {
            _engine.EnableFixed(_vm.SelectedDrive.DriveLetter);
            _vm.OutputText = "Fixed drive encryption started.";
        }
        catch (Exception ex)
        {
            _vm.OutputText = $"Enable fixed failed: {ex.Message}";
        }
    }

    private void EnableRemovable_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.SelectedDrive == null) return;
        try
        {
            _engine.EnableRemovable(_vm.SelectedDrive.DriveLetter, _vm.Pin);
            _vm.OutputText = "Removable drive encryption started.";
        }
        catch (Exception ex)
        {
            _vm.OutputText = $"Enable removable failed: {ex.Message}";
        }
    }

    private void Suspend_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.SelectedDrive == null) return;
        try
        {
            _engine.Suspend(_vm.SelectedDrive.DriveLetter);
            _vm.OutputText = "Suspended BitLocker protectors.";
        }
        catch (Exception ex)
        {
            _vm.OutputText = $"Suspend failed: {ex.Message}";
        }
    }

    private void Resume_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.SelectedDrive == null) return;
        try
        {
            _engine.Resume(_vm.SelectedDrive.DriveLetter);
            _vm.OutputText = "Resumed BitLocker protectors.";
        }
        catch (Exception ex)
        {
            _vm.OutputText = $"Resume failed: {ex.Message}";
        }
    }

    private void AddRecovery_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.SelectedDrive == null) return;
        try
        {
            var dir = string.IsNullOrWhiteSpace(_vm.RecoveryDirectory)
                ? Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                : _vm.RecoveryDirectory;
            _engine.AddRecoveryKey(_vm.SelectedDrive.DriveLetter, dir);
            _vm.OutputText = $"Recovery key written to {dir}.";
        }
        catch (Exception ex)
        {
            _vm.OutputText = $"Recovery key failed: {ex.Message}";
        }
    }
}

public sealed class BitLockerDriveInfoViewModel
{
    public string Label { get; }
    public string DriveLetter { get; }

    public BitLockerDriveInfoViewModel(string label, string driveLetter)
    {
        Label = label;
        DriveLetter = driveLetter;
    }
}

public sealed class BitLockerViewModel : INotifyPropertyChanged
{
    public ObservableCollection<BitLockerDriveInfoViewModel> Drives { get; } = new();

    private BitLockerDriveInfoViewModel? _selectedDrive;
    public BitLockerDriveInfoViewModel? SelectedDrive { get => _selectedDrive; set { _selectedDrive = value; OnPropertyChanged(); } }

    private string _pin = "";
    public string Pin { get => _pin; set { _pin = value; OnPropertyChanged(); } }

    private string _recoveryDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    public string RecoveryDirectory { get => _recoveryDirectory; set { _recoveryDirectory = value; OnPropertyChanged(); } }

    private string _outputText = "Ready";
    public string OutputText { get => _outputText; set { _outputText = value; OnPropertyChanged(); } }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    public void LoadDrives(BitLockerEngine engine)
    {
        Drives.Clear();
        var statusMap = ParseStatuses(engine);
        var systemDriveLetter = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))?.TrimEnd('\\');

        foreach (var drive in DriveInfo.GetDrives().Where(d => d.DriveType is DriveType.Fixed or DriveType.Removable && d.IsReady))
        {
            var letter = drive.Name.TrimEnd('\\');
            var typeLabel = string.Equals(letter, systemDriveLetter, StringComparison.OrdinalIgnoreCase) ? "OS" : drive.DriveType == DriveType.Fixed ? "Fixed" : "Removable";
            var status = statusMap.TryGetValue(letter, out var st) ? st : "Unknown";
            var label = $"{letter}: ({typeLabel}, {status})";
            Drives.Add(new BitLockerDriveInfoViewModel(label, letter));
        }

        SelectedDrive = Drives.FirstOrDefault(d => string.Equals(d.DriveLetter, systemDriveLetter, StringComparison.OrdinalIgnoreCase)) ?? Drives.FirstOrDefault();
    }

    private static Dictionary<string, string> ParseStatuses(BitLockerEngine engine)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var statusText = engine.GetStatus();
            var blocks = statusText.Split(new[] { "Volume " }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var block in blocks)
            {
                var lines = block.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                var first = lines.FirstOrDefault();
                if (string.IsNullOrWhiteSpace(first)) continue;
                var header = first.Trim();
                var letterPart = header.Split(' ', '\t').FirstOrDefault();
                if (string.IsNullOrWhiteSpace(letterPart)) continue;
                var letter = letterPart.TrimEnd(':');
                if (string.IsNullOrWhiteSpace(letter)) continue;
                var driveKey = $"{letter}:";
                var protectionLine = lines.FirstOrDefault(l => l.Contains("Protection Status", StringComparison.OrdinalIgnoreCase));
                var encryptionLine = lines.FirstOrDefault(l => l.Contains("Encryption Percentage", StringComparison.OrdinalIgnoreCase));
                var status = "Unknown";
                if (protectionLine?.IndexOf("On", StringComparison.OrdinalIgnoreCase) >= 0) status = "Encrypted";
                else if (protectionLine?.IndexOf("Off", StringComparison.OrdinalIgnoreCase) >= 0) status = "Not encrypted";
                else if (encryptionLine?.IndexOf("100", StringComparison.OrdinalIgnoreCase) >= 0) status = "Encrypted";
                else if (encryptionLine?.IndexOf("0", StringComparison.OrdinalIgnoreCase) >= 0) status = "Not encrypted";
                map[driveKey] = status;
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Failed to parse BitLocker status: {ex.Message}");
        }
        return map;
    }
}
