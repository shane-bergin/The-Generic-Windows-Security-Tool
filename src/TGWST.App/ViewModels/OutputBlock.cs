using CommunityToolkit.Mvvm.ComponentModel;

namespace TGWST.App.ViewModels
{
    public sealed class OutputBlock : ObservableObject
    {
        private string _displayText;
        private bool _isAcronymsExpanded;

        public OutputBlock(string rawText, string displayText, bool isAcronymsExpanded = false)
        {
            RawText = rawText;
            _displayText = displayText;
            _isAcronymsExpanded = isAcronymsExpanded;
        }

        public string RawText { get; }

        public string DisplayText
        {
            get => _displayText;
            set => SetProperty(ref _displayText, value);
        }

        public bool IsAcronymsExpanded
        {
            get => _isAcronymsExpanded;
            set => SetProperty(ref _isAcronymsExpanded, value);
        }
    }
}
