using System;
using TGWST.Core.Compliance;

namespace TGWST.App.Services;

public static class BaselineSelectionService
{
    private static ComplianceBaselineInfo? _selected;
    public static event Action<ComplianceBaselineInfo?>? SelectionChanged;

    public static ComplianceBaselineInfo? Selected
    {
        get => _selected;
        set
        {
            if (_selected == value) return;
            _selected = value;
            SelectionChanged?.Invoke(_selected);
        }
    }
}
