using TGWST.App.ViewModels;

namespace TGWST.App.Shell.Commands
{
    public sealed class HelpCommand : ICommandHandler
    {
        public string Name => "help";
        public string[] Aliases => new[] { "?" };

        public Task ExecuteAsync(string args, ShellViewModel vm)
        {
            vm.AddOutput("╔═══════════════════════════════════════════════════════════════════════════╗\n");
            vm.AddOutput("║                          Available Commands                               ║\n");
            vm.AddOutput("╚═══════════════════════════════════════════════════════════════════════════╝\n\n");

            vm.AddOutput("┌─ General ─────────────────────────────────────────────────────────────────┐\n");
            vm.AddOutput("│ help                       Show this help message                         │\n");
            vm.AddOutput("│ clear                      Clear the output screen                        │\n");
            vm.AddOutput("│ quit                       Exit the application                           │\n");
            vm.AddOutput("└───────────────────────────────────────────────────────────────────────────┘\n\n");

            vm.AddOutput("┌─ WDAC (Windows Defender Application Control) ────────────────────────────┐\n");
            vm.AddOutput("│ wdac status                Show current WDAC policy status               │\n");
            vm.AddOutput("│ wdac apply audit           Apply WDAC in audit mode (logs only)          │\n");
            vm.AddOutput("│ wdac apply enforce         Apply enforced WDAC policy (blocks apps)      │\n");
            vm.AddOutput("│ wdac remove [--system]     Remove applied WDAC policy                    │\n");
            vm.AddOutput("│ wdac revert                Revert to last WDAC snapshot                  │\n");
            vm.AddOutput("│ wdac dev allow [path]      Allow dev binary via supplemental policy      │\n");
            vm.AddOutput("│ wdac dev remove            Remove dev allow policy                       │\n");
            vm.AddOutput("│ wdac dev status            Show last dev allow record                    │\n");
            vm.AddOutput("└───────────────────────────────────────────────────────────────────────────┘\n\n");

            vm.AddOutput("┌─ ASR (Attack Surface Reduction) ──────────────────────────────────────────┐\n");
            vm.AddOutput("│ asr apply balanced         Apply balanced ASR rules baseline             │\n");
            vm.AddOutput("│ asr apply strict           Apply strict ASR rules (aggressive)           │\n");
            vm.AddOutput("│ asr apply audit            Apply ASR in audit mode (logs only)           │\n");
            vm.AddOutput("│ asr apply revert           Revert to previous ASR snapshot               │\n");
            vm.AddOutput("└───────────────────────────────────────────────────────────────────────────┘\n\n");

            vm.AddOutput("┌─ Scanning ────────────────────────────────────────────────────────────────┐\n");
            vm.AddOutput("│ scan defender quick        Run Windows Defender quick scan               │\n");
            vm.AddOutput("│ scan defender full         Run Windows Defender full scan                │\n");
            vm.AddOutput("│ scan sdk sigcheck <path>   Verify digital signatures on files            │\n");
            vm.AddOutput("└───────────────────────────────────────────────────────────────────────────┘\n\n");

            vm.AddOutput("┌─ Network Monitoring ──────────────────────────────────────────────────────┐\n");
            vm.AddOutput("│ network board              BIOS-style ASCII feature control board         │\n");
            vm.AddOutput("│ network feature status     Show feature checkboxes/status                │\n");
            vm.AddOutput("│ network feature enable ... Enable a feature (hybrid/pihole)             │\n");
            vm.AddOutput("│ network feature disable... Disable a feature (hybrid/pihole)            │\n");
            vm.AddOutput("│ network quick              Recommended quick start for Tier-1 workflows │\n");
            vm.AddOutput("│ network setup              Full feature setup/status board               │\n");
            vm.AddOutput("│ network baseline           Capture firewall and port baseline            │\n");
            vm.AddOutput("│ network live               Real-time connection monitor (enhanced)       │\n");
            vm.AddOutput("│ network stats              Show historical network flow statistics       │\n");
            vm.AddOutput("│ network pihole status      Show Pi-hole DNS feature status               │\n");
            vm.AddOutput("│ network pihole top         Show top blocked domains from Pi-hole FTL     │\n");
            vm.AddOutput("│ network pihole enable      Turn Pi-hole blocking on                       │\n");
            vm.AddOutput("│ network pihole disable 5m  Pause Pi-hole blocking for a time window      │\n");
            vm.AddOutput("│ network pihole sync-dns    Point Windows DNS to current WSL distro IP    │\n");
            vm.AddOutput("│ network hybrid status      Show Linux-analysis feature status            │\n");
            vm.AddOutput("│ network hybrid enable      Enable Linux-analysis feature                 │\n");
            vm.AddOutput("│ network hybrid disable     Disable Linux-analysis feature                │\n");
            vm.AddOutput("└───────────────────────────────────────────────────────────────────────────┘\n\n");

            vm.AddOutput("┌─ Maintenance Operations ──────────────────────────────────────────────────┐\n");
            vm.AddOutput("│ maintenance               Open maintenance operations window              │\n");
            vm.AddOutput("│ maint                     Alias for maintenance                           │\n");
            vm.AddOutput("└───────────────────────────────────────────────────────────────────────────┘\n\n");

            vm.AddOutput("Tip: Use the menu system (↑/↓ arrows) for guided navigation.\n");
            vm.AddOutput("     Press → on a menu item to view detailed information.\n");
            vm.AddOutput("     Use the SETUP button to open the first-run bootstrap wizard.\n");
            return Task.CompletedTask;
        }
    }
}
