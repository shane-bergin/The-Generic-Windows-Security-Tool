using CommunityToolkit.Mvvm.ComponentModel;

namespace TGWST.App.ViewModels
{
    public sealed class OutputBlock : ObservableObject
    {
        private string _displayText;
        private bool _isAcronymsExpanded;
        private readonly string _colorTag;

        public OutputBlock(string rawText, string displayText, bool isAcronymsExpanded = false)
        {
            RawText = rawText;
            _displayText = displayText;
            _isAcronymsExpanded = isAcronymsExpanded;
            _colorTag = DetectColorTag(rawText);
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

        public string ColorTag => _colorTag;

        private static string DetectColorTag(string text)
        {
            var trimmed = (text ?? string.Empty).TrimStart();
            if (trimmed.StartsWith("[✓]", System.StringComparison.Ordinal))
            {
                return "success";
            }

            if (trimmed.StartsWith("[X]", System.StringComparison.Ordinal) || trimmed.StartsWith("[x]", System.StringComparison.Ordinal))
            {
                return "error";
            }

            if (trimmed.StartsWith("[!]", System.StringComparison.Ordinal))
            {
                return "warning";
            }

            if (trimmed.StartsWith("[i]", System.StringComparison.OrdinalIgnoreCase))
            {
                return "info";
            }

            if (trimmed.StartsWith("[>]", System.StringComparison.Ordinal))
            {
                return "accent";
            }

            return "default";
        }
    }
}
