using TGWST.App.Services;
using TGWST.App.ViewModels;

namespace TGWST.Tests;

public sealed class ComputerCleaningServiceTests
{
    private static readonly Guid ProductCode = Guid.Parse("11111111-2222-3333-4444-555555555555");

    [Fact]
    public void BuildUninstallLaunch_RejectsShellCommand()
    {
        var app = CreateApp($"\"{Path.Combine(Environment.SystemDirectory, "cmd.exe")}\" /c whoami");

        Assert.Throws<InvalidOperationException>(() => ComputerCleaningService.BuildUninstallLaunch(app));
    }

    [Fact]
    public void BuildUninstallLaunch_NormalizesMsiInstallEntryToUninstall()
    {
        var app = CreateApp($"MsiExec.exe /I{{{ProductCode:D}}}");

        var launch = ComputerCleaningService.BuildUninstallLaunch(app);

        Assert.Equal(Path.Combine(Environment.SystemDirectory, "msiexec.exe"), launch.FileName);
        Assert.Equal(["/X", $"{{{ProductCode:D}}}"], launch.Arguments);
    }

    [Fact]
    public void BuildUninstallLaunch_ParsesQuotedExecutableWithoutShell()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"TGWST test {Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var executable = Path.Combine(directory, "uninstall.exe");
        File.WriteAllBytes(executable, []);

        try
        {
            var app = CreateApp($"\"{executable}\" /S /norestart");

            var launch = ComputerCleaningService.BuildUninstallLaunch(app);

            Assert.Equal(executable, launch.FileName);
            Assert.Equal(["/S", "/norestart"], launch.Arguments);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static InstalledAppRow CreateApp(string command)
    {
        return new InstalledAppRow(
            "Test App",
            "1.0",
            "Test",
            string.Empty,
            command,
            string.Empty,
            @"HKCU\Software\Test",
            "HKCU",
            "LOW",
            "test");
    }
}
