// @title Tab Order Check
// @shadow light
// @effects none
// Real Tab + Shift+Tab keyboard walk with modal auto-scoping.
// Open a modal first to verify scope; background focus leaks are reported as errors.

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Tab order check: {title}");
Log($"URL: {url}");
Log("");

Assert.Section("Keyboard tab order (real Tab keys)");
var result = await PrintTabOrderReport(new TabOrderOptions
{
    AutoDetectScope = true,
    StrictScope = true,
    CheckShiftTabConsistency = true,
    CheckReadingOrder = true,
    CheckSkipped = true,
    CheckFocusTrap = true,
    CheckPositiveTabIndex = true
});

Log($"Focus context: {result.FocusContextKind} — {result.FocusContextLabel}" +
    (result.ScopeAutoDetected ? " (auto-detected)" : ""));

if (result.ShiftTabConsistencyChecked)
    Assert.True(result.ShiftTabConsistent == true, "Shift+Tab should reverse the forward Tab order");
Assert.Equal(0, result.Issues.Count(i => i.Category is "modal-focus-leak" or "focus-escaped-scope"),
    "Tab should stay inside the active focus context (especially modals)");
Assert.Equal(0, result.Issues.Count(i => i.Severity == TabOrderSeverity.Error),
    "No tab-order errors (traps, skipped controls, scope leaks, Shift+Tab mismatch)");

Log("");
Log($"In-scope focusables: {result.FocusableCount}, Tab stops: {result.ForwardSteps.Count}");
Log("Tab order check complete.");
