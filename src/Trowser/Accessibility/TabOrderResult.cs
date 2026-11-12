namespace Trowser.Accessibility;

/// <summary>Severity of a tab-order finding.</summary>
public enum TabOrderSeverity
{
    Info,
    Warning,
    Error
}

/// <summary>Options for tab-order verification.</summary>
public sealed class TabOrderOptions
{
    /// <summary>CSS selector to scope the audit (null = auto-detect modal or full page).</summary>
    public string? Selector { get; init; }

    /// <summary>CSS selector or snapshot ref target to focus before walking (optional).</summary>
    public string? StartSelector { get; init; }

    /// <summary>When <see cref="Selector"/> is null, detect open modal dialogs and scope to them.</summary>
    public bool AutoDetectScope { get; init; } = true;

    /// <summary>Report an error when Tab lands outside the active scope (e.g. background under a modal).</summary>
    public bool StrictScope { get; init; } = true;

    /// <summary>Maximum Tab / Shift+Tab steps per direction (safety limit).</summary>
    public int MaxSteps { get; init; } = 150;

    /// <summary>Flag positive tabindex (&gt; 0) values.</summary>
    public bool CheckPositiveTabIndex { get; init; } = true;

    /// <summary>Flag in-scope focusable controls never reached by real Tab.</summary>
    public bool CheckSkipped { get; init; } = true;

    /// <summary>Flag large spatial jumps that may indicate illogical reading order.</summary>
    public bool CheckReadingOrder { get; init; } = true;

    /// <summary>Flag small Tab cycles when many in-scope focusables exist (keyboard trap).</summary>
    public bool CheckFocusTrap { get; init; } = true;

    /// <summary>Compare forward vs backward real Tab cycles after one round-trip.</summary>
    public bool CheckShiftTabConsistency { get; init; } = true;

    /// <summary>Expected focus labels/selectors/refs in order (assertion mode).</summary>
    public IReadOnlyList<string>? ExpectedOrder { get; init; }
}

/// <summary>A single stop in a Tab or Shift+Tab walk.</summary>
public sealed class TabOrderStep
{
    public int Index { get; init; }
    public string Direction { get; init; } = "forward";
    public string Signature { get; init; } = "";
    public string Selector { get; init; } = "";
    public string Label { get; init; } = "";
    public string Tag { get; init; } = "";
    public string Role { get; init; } = "";
    public int TabIndex { get; init; }
    public int? Ref { get; init; }
    public double X { get; init; }
    public double Y { get; init; }
    public double Width { get; init; }
    public double Height { get; init; }
    public string FrameUrl { get; init; } = "";
    /// <summary>Whether this stop is inside the active audit scope.</summary>
    public bool InScope { get; init; } = true;
    /// <summary>True when Tab / Shift+Tab returned to the walk anchor (full roundtrip).</summary>
    public bool RoundtripCompleted { get; init; }
}

/// <summary>A tab-order issue found during verification.</summary>
public sealed class TabOrderIssue
{
    public string Category { get; init; } = "";
    public TabOrderSeverity Severity { get; init; }
    public string Message { get; init; } = "";
    public string? Selector { get; init; }
    public string? Label { get; init; }
    public int? StepIndex { get; init; }
}

/// <summary>Result of tab-order verification on the current page.</summary>
public sealed class TabOrderResult
{
    public string Url { get; init; } = "";
    public string Title { get; init; } = "";
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    public string? ScopeSelector { get; init; }
    /// <summary>page, modal, or explicit (user selector).</summary>
    public string FocusContextKind { get; init; } = "page";
    public string FocusContextLabel { get; init; } = "";
    public bool ScopeAutoDetected { get; init; }
    public List<TabOrderStep> ForwardSteps { get; init; } = [];
    public List<TabOrderStep> BackwardSteps { get; init; } = [];
    public List<TabOrderIssue> Issues { get; init; } = [];
    public int FocusableCount { get; init; }
    public bool ForwardCycleComplete { get; init; }
    /// <summary>Null when the backward walk was not performed.</summary>
    public bool? BackwardCycleComplete { get; init; }
    /// <summary>Null when Shift+Tab consistency was not checked.</summary>
    public bool? ShiftTabConsistent { get; init; }
    public bool BackwardChecked { get; init; }
    public bool ShiftTabConsistencyChecked { get; init; }
    public bool ExpectedOrderMatched { get; init; } = true;

    public bool IsClean => Issues.Count == 0;

    public string Format(bool includeSteps = true)
    {
        var lines = new List<string>
        {
            "=== Tab Order Verification (keyboard walk) ===",
            $"URL: {Url}",
            $"Title: {Title}",
            $"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}"
        };

        if (!string.IsNullOrEmpty(FocusContextLabel))
            lines.Add($"Focus context: {FocusContextKind} — {FocusContextLabel}" +
                      (ScopeAutoDetected ? " (auto-detected)" : ""));

        if (!string.IsNullOrEmpty(ScopeSelector))
            lines.Add($"Scope: {ScopeSelector}");

        lines.Add("");
        lines.Add($"Forward Tab cycle: {ForwardSteps.Count} stop(s)" +
                  (ForwardCycleComplete ? " (complete)" : " (incomplete)"));
        lines.Add(BackwardChecked
            ? $"Backward Shift+Tab cycle: {BackwardSteps.Count} stop(s)" +
              (BackwardCycleComplete == true ? " (complete)" : " (incomplete)")
            : "Backward Shift+Tab cycle: not checked");
        lines.Add($"Focusable in scope: {FocusableCount}");
        lines.Add(ShiftTabConsistencyChecked
            ? $"Shift+Tab consistent with Tab: {(ShiftTabConsistent == true ? "yes" : "NO")}"
            : "Shift+Tab consistent with Tab: not checked");

        if (ExpectedOrderMatched == false)
            lines.Add("Expected order: MISMATCH");

        lines.Add("");

        if (Issues.Count == 0)
        {
            lines.Add("No tab-order issues found.");
        }
        else
        {
            lines.Add($"ISSUES: {Issues.Count}");
            foreach (var issue in Issues.OrderByDescending(i => i.Severity))
            {
                var sev = issue.Severity.ToString().ToUpperInvariant();
                var at = issue.StepIndex.HasValue ? $" [step {issue.StepIndex + 1}]" : "";
                var target = !string.IsNullOrEmpty(issue.Label)
                    ? $" \"{issue.Label}\""
                    : !string.IsNullOrEmpty(issue.Selector)
                        ? $" {issue.Selector}"
                        : "";
                lines.Add($"  [{sev}] {issue.Category}{at}: {issue.Message}{target}");
            }
        }

        if (includeSteps && ForwardSteps.Count > 0)
        {
            lines.Add("");
            lines.Add("--- Forward Tab order ---");
            foreach (var step in ForwardSteps)
                lines.Add(FormatStepLine(step));
        }

        if (includeSteps && BackwardSteps.Count > 0)
        {
            lines.Add("");
            lines.Add("--- Backward Shift+Tab order ---");
            foreach (var step in BackwardSteps)
                lines.Add(FormatStepLine(step));
        }

        lines.Add("================================================");
        return string.Join(Environment.NewLine, lines);
    }

    private static string FormatStepLine(TabOrderStep step)
    {
        var refPart = step.Ref.HasValue ? $" ref:{step.Ref}" : "";
        var label = string.IsNullOrEmpty(step.Label) ? step.Selector : step.Label;
        var scopeFlag = step.InScope ? "" : " [OUT OF SCOPE]";
        var roundtrip = step.RoundtripCompleted ? " (Roundtrip completed)" : "";
        return $"  {step.Index + 1}.{scopeFlag} {label} <{step.Tag}>{refPart} tabindex={step.TabIndex}{roundtrip}";
    }
}
