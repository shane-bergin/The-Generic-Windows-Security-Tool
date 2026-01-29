using TGWST.App.ViewModels;

namespace TGWST.App.Shell
{
    public interface ICommandHandler
    {
        string Name { get; }
        string[] Aliases { get; }
        Task ExecuteAsync(string args, ShellViewModel vm);
    }
}
