using TGWST.App.ViewModels;

namespace TGWST.App.Shell.Commands
{
    public sealed class HelpCommand : ICommandHandler
    {
        public string Name => "help";
        public string[] Aliases => new[] { "?" };

        public Task ExecuteAsync(string args, ShellViewModel vm)
        {
            vm.AddOutput(
                "Commands:\n" +
                "  help              Show this help\n" +
                "  clear             Clear screen\n" +
                "  quit              Exit\n" +
                "  wdac status       Show WDAC status\n" +
                "  wdac apply audit  Apply shipped WDAC audit policy\n" +
                "  wdac apply enforce Apply shipped WDAC enforced policy\n" +
                "  wdac remove [--system] Remove applied WDAC policy\n" +
                "  wdac revert        Revert to last WDAC snapshot\n" +
                "  wdac dev allow [path] [--base <policyId>]  Allow a dev binary via supplemental policy\n" +
                "  wdac dev remove [--id <policyId>] [--system]  Remove dev allow policy\n" +
                "  wdac dev status    Show last dev allow record\n" +
                "  asr apply <level>  Apply ASR baseline (balanced/strict/audit/revert)\n" +
                "  scan defender <quick|full>  Run Windows Defender scan\n" +
                "  scan sdk sigcheck <path>  Verify signatures on a target path\n" +
                "  network baseline          Capture network baseline\n" +
                "  network live              Live TCP connection monitor\n" +
                "  compliance snapshot [path] Capture compliance snapshot\n" +
                "  uninstall remnants <name|#> [--remove]  Uninstall and scan leftovers\n"
            );
            return Task.CompletedTask;
        }
    }
}
