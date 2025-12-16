using System.CommandLine;
using TGWST.Core.Scan;
using TGWST.Core.Feeds;

class Program
{
    static async Task<int> Main(string[] args)
    {
        var rootCommand = new RootCommand("TGWST Updater - Updates security definitions");

        var quietOption = new Option<bool>("--quiet", "Run silently without console output");
        var clamavOption = new Option<bool>("--clamav", "Update only ClamAV signatures");
        var feedsOption = new Option<bool>("--feeds", "Update only threat feeds (YARA/IOC)");
        var allOption = new Option<bool>("--all", "Update everything (default)");

        rootCommand.AddOption(quietOption);
        rootCommand.AddOption(clamavOption);
        rootCommand.AddOption(feedsOption);
        rootCommand.AddOption(allOption);

        rootCommand.SetHandler(async (quiet, clamav, feeds, all) =>
        {
            try
            {
                var updater = new Updater(quiet);
                await updater.RunAsync(clamav, feeds, all);
            }
            catch (Exception ex)
            {
                if (!quiet)
                {
                    Console.Error.WriteLine($"ERROR: {ex.Message}");
                }
                Environment.ExitCode = 1;
            }
        }, quietOption, clamavOption, feedsOption, allOption);

        return await rootCommand.InvokeAsync(args);
    }
}

class Updater
{
    private readonly bool _quiet;
    private readonly ScanEngine _scanEngine = new();

    public Updater(bool quiet)
    {
        _quiet = quiet;
    }

    public async Task RunAsync(bool clamavOnly, bool feedsOnly, bool all)
    {
        if (!clamavOnly && !feedsOnly && !all)
        {
            all = true; // Default to update all
        }

        Log("TGWST Updater starting...");

        if (all || clamavOnly)
        {
            Log("Updating ClamAV signatures...");
            var progress = new Progress<string>(msg => Log(msg));
            await _scanEngine.UpdateSignaturesAsync(progress);
            Log("ClamAV signatures updated.");
        }

        if (all || feedsOnly)
        {
            Log("Reloading threat feeds...");
            var summary = await FeedManager.ReloadAsync();
            Log($"Feeds reloaded: {summary.YaraRuleCount} YARA rules, {summary.IocBundleCount} IOC bundles");
        }

        Log("Update complete.");
    }

    private void Log(string message)
    {
        if (!_quiet)
        {
            Console.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {message}");
        }
    }
}
