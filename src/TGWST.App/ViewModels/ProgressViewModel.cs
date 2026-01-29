using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using TGWST.App.Shell;

namespace TGWST.App.ViewModels
{
    public sealed class ProgressViewModel : ObservableObject
    {
        public ObservableCollection<OutputBlock> Output { get; } = new();

        private string _title = "Task Output";
        public string Title
        {
            get => _title;
            set => SetProperty(ref _title, value);
        }

        private string _status = "Running...";
        public string Status
        {
            get => _status;
            set => SetProperty(ref _status, value);
        }

        private bool _acronymsExpanded;

        public void Append(string text)
        {
            var display = _acronymsExpanded ? AcronymExpander.Expand(text) : text;
            var dispatcher = System.Windows.Application.Current?.Dispatcher;
            if (dispatcher?.CheckAccess() == true)
            {
                Output.Add(new OutputBlock(text, display, _acronymsExpanded));
                return;
            }

            dispatcher?.Invoke(() => Output.Add(new OutputBlock(text, display, _acronymsExpanded)));
        }

        public void ClearOutput()
        {
            var dispatcher = System.Windows.Application.Current?.Dispatcher;
            if (dispatcher?.CheckAccess() == true)
            {
                Output.Clear();
                return;
            }

            dispatcher?.Invoke(Output.Clear);
        }

        public void SetAcronymMode(bool expanded)
        {
            if (_acronymsExpanded == expanded) return;
            _acronymsExpanded = expanded;
            var dispatcher = System.Windows.Application.Current?.Dispatcher;
            void Apply()
            {
                foreach (var block in Output)
                {
                    block.DisplayText = expanded ? AcronymExpander.Expand(block.RawText) : block.RawText;
                    block.IsAcronymsExpanded = expanded;
                }
            }

            if (dispatcher?.CheckAccess() == true)
            {
                Apply();
                return;
            }

            dispatcher?.Invoke(Apply);
        }
    }
}
