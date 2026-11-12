using Trowser.Accessibility;
using Xunit;

namespace Trowser.Tests.Accessibility;

public class TabOrderSummaryTests
{
    [Fact]
    public void Format_marks_backward_and_shift_checks_not_checked_when_skipped()
    {
        var result = new TabOrderResult
        {
            Url = "https://example.test/",
            ForwardCycleComplete = false,
            BackwardChecked = false,
            ShiftTabConsistencyChecked = false,
            BackwardCycleComplete = null,
            ShiftTabConsistent = null
        };

        var text = result.Format(includeSteps: false);
        Assert.Contains("not checked", text);
        Assert.DoesNotContain("Shift+Tab consistent with Tab: yes", text);
    }

    [Fact]
    public void Format_reports_shift_inconsistent_only_when_checked()
    {
        var result = new TabOrderResult
        {
            Url = "https://example.test/",
            ForwardCycleComplete = true,
            BackwardChecked = true,
            ShiftTabConsistencyChecked = true,
            BackwardCycleComplete = true,
            ShiftTabConsistent = false
        };

        var text = result.Format(includeSteps: false);
        Assert.Contains("Shift+Tab consistent with Tab: NO", text);
    }
}
