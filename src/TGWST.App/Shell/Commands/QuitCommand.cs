using System.Windows;
using TGWST.App.ViewModels;

namespace TGWST.App.Shell.Commands
{
    public sealed class QuitCommand : ICommandHandler
    {
        public string Name => "quit";
        public string[] Aliases => new[] { "exit" };

        public Task ExecuteAsync(string args, ShellViewModel vm)
        {
            Application.Current.Shutdown();
            return Task.CompletedTask;
        }
    }
}
