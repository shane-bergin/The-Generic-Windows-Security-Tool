using System;
using System.Collections.Generic;
using System.Windows;
using TGWST.Core.Compliance;

namespace TGWST.App.Tabs;

public partial class ComplianceTab : System.Windows.Controls.UserControl
{
    private readonly BaselineComplianceEngine _engine = new();

    public ComplianceTab()
    {
        InitializeComponent();
    }

    private void Evaluate_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var results = (IReadOnlyList<BaselineComplianceEngine.Result>)_engine.Evaluate(BaselinePathBox.Text);
            ResultsGrid.ItemsSource = results;
            var compliant = 0;
            foreach (var r in results) if (r.Compliant) compliant++;
            StatusText.Text = $"Compliant {compliant}/{results.Count}";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Evaluate failed: {ex.Message}";
        }
    }
}
