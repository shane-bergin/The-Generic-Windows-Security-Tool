using System.Threading;
using TGWST.App.ViewModels;
using TGWST.App.Views;

namespace TGWST.App.Shell
{
    public sealed class TaskOutputService
    {
        public ProgressViewModel CreateAndShow(string title, bool acronymsExpanded = false)
        {
            var vm = new ProgressViewModel { Title = title };
            vm.SetAcronymMode(acronymsExpanded);
            var view = new ProgressView(vm);
            view.Show();
            return vm;
        }

        public TaskOutputSession CreateSession(string title, bool acronymsExpanded = false)
        {
            var vm = new ProgressViewModel { Title = title };
            vm.SetAcronymMode(acronymsExpanded);
            var view = new ProgressView(vm);
            var cts = new CancellationTokenSource();
            view.Closed += (_, _) => cts.Cancel();
            view.Show();
            return new TaskOutputSession(vm, view, cts);
        }
    }

    public sealed class TaskOutputSession
    {
        public TaskOutputSession(ProgressViewModel viewModel, ProgressView view, CancellationTokenSource cancellation)
        {
            ViewModel = viewModel;
            View = view;
            Cancellation = cancellation;
        }

        public ProgressViewModel ViewModel { get; }
        public ProgressView View { get; }
        public CancellationTokenSource Cancellation { get; }
    }
}
