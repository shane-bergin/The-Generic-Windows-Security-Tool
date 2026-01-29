using System.Threading;
using TGWST.App.ViewModels;

namespace TGWST.App.Shell
{
    public sealed class AttachedPaneSession
    {
        public AttachedPaneSession(ProgressViewModel viewModel, CancellationTokenSource cancellation)
        {
            ViewModel = viewModel;
            Cancellation = cancellation;
        }

        public ProgressViewModel ViewModel { get; }
        public CancellationTokenSource Cancellation { get; }
    }
}
