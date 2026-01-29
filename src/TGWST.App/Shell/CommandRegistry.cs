namespace TGWST.App.Shell
{
    public sealed class CommandRegistry
    {
        private readonly Dictionary<string, ICommandHandler> _map;

        public CommandRegistry(IEnumerable<ICommandHandler> handlers)
        {
            _map = new Dictionary<string, ICommandHandler>(StringComparer.OrdinalIgnoreCase);
            foreach (var handler in handlers)
            {
                _map[handler.Name] = handler;
                foreach (var alias in handler.Aliases)
                {
                    _map[alias] = handler;
                }
            }
        }

        public async Task<bool> TryExecuteAsync(string line, ViewModels.ShellViewModel vm)
        {
            var (cmd, args) = Split(line);
            if (!_map.TryGetValue(cmd, out var handler))
            {
                return false;
            }

            await handler.ExecuteAsync(args, vm);
            return true;
        }

        private static (string cmd, string args) Split(string line)
        {
            var i = line.IndexOf(' ');
            return i < 0 ? (line, string.Empty) : (line[..i], line[(i + 1)..].Trim());
        }
    }
}
