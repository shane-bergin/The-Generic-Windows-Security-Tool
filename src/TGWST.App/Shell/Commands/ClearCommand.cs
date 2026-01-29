using TGWST.App.ViewModels;

namespace TGWST.App.Shell.Commands
{
    public sealed class ClearCommand : ICommandHandler
    {
        public string Name => "clear";
        public string[] Aliases => new[] { "cls" };

        public Task ExecuteAsync(string args, ShellViewModel vm)
        {
            vm.ClearOutput();
            return Task.CompletedTask;
        }
    }
}
