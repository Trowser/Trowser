using System.Text.Json;
using Microsoft.Web.WebView2.Wpf;

namespace Trowser.Accessibility;

/// <summary>
/// Verifies keyboard tab order with real Tab / Shift+Tab (CDP), auto-detects modal focus
/// contexts, and flags focus escaping the active scope (e.g. background under a dialog).
/// </summary>
public sealed class TabOrderChecker
{
    private readonly WebView2 _webView;
    private readonly Func<string, Task<string>> _executeScript;
    private readonly Func<bool, Task> _dispatchRealTab;

    public TabOrderChecker(
        WebView2 webView,
        Func<string, Task<string>> executeScript,
        Func<bool, Task>? dispatchRealTab = null)
    {
        _webView = webView ?? throw new ArgumentNullException(nameof(webView));
        _executeScript = executeScript ?? throw new ArgumentNullException(nameof(executeScript));
        _dispatchRealTab = dispatchRealTab ?? DefaultDispatchTabKeyAsync;
    }

    public async Task<TabOrderResult> RunAsync(
        TabOrderOptions options,
        Func<int, string?>? getSelectorByRef,
        Func<string, int?>? getRefBySelector,
        string url,
        string title)
    {
        options ??= new TabOrderOptions();
        if (options.MaxSteps < 1)
            throw new ArgumentOutOfRangeException(nameof(options), "MaxSteps must be >= 1.");

        var context = await ResolveContextAsync(options);
        var scopeSelector = context.ScopeSelector;
        var focusables = await CollectInScopeFocusablesAsync(scopeSelector);

        await EnsureWebViewFocusedAsync();
        await ResetFocusInScopeAsync(scopeSelector, options.StartSelector);
        await AdvanceToFirstTabStopAsync(scopeSelector, options.MaxSteps);

        var (forwardSteps, forwardComplete) = await WalkForwardAsync(
            scopeSelector, options.MaxSteps);

        List<TabOrderStep> backwardSteps = [];
        var backwardChecked = false;
        var backwardComplete = false;
        var shiftConsistent = false;

        MapRefs(forwardSteps, getRefBySelector);

        if (options.CheckShiftTabConsistency && forwardSteps.Count > 0 && forwardComplete)
        {
            backwardChecked = true;
            (backwardSteps, backwardComplete, shiftConsistent) = await VerifyBackwardAsync(
                forwardSteps, scopeSelector, options.MaxSteps, context.Kind);
        }

        MapRefs(backwardSteps, getRefBySelector);

        var issues = AnalyzeIssues(
            options,
            context,
            forwardSteps,
            backwardSteps,
            focusables,
            forwardComplete,
            backwardComplete,
            shiftConsistent,
            getSelectorByRef);

        return new TabOrderResult
        {
            Url = url,
            Title = title,
            Timestamp = DateTime.UtcNow,
            ScopeSelector = scopeSelector,
            FocusContextKind = context.Kind,
            FocusContextLabel = context.Label,
            ScopeAutoDetected = context.AutoDetected,
            ForwardSteps = forwardSteps,
            BackwardSteps = backwardSteps,
            Issues = issues,
            FocusableCount = focusables.Count,
            ForwardCycleComplete = forwardComplete,
            BackwardChecked = backwardChecked,
            ShiftTabConsistencyChecked = backwardChecked,
            BackwardCycleComplete = backwardChecked ? backwardComplete : null,
            ShiftTabConsistent = backwardChecked ? shiftConsistent : null,
            ExpectedOrderMatched = issues.All(i => i.Category != "expected-order-mismatch")
        };
    }

    private async Task<TabOrderContextInfo> ResolveContextAsync(TabOrderOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.Selector))
        {
            return new TabOrderContextInfo
            {
                ScopeSelector = options.Selector,
                Kind = "explicit",
                Label = options.Selector,
                AutoDetected = false
            };
        }

        if (!options.AutoDetectScope)
        {
            return new TabOrderContextInfo
            {
                ScopeSelector = null,
                Kind = "page",
                Label = "Full page",
                AutoDetected = false
            };
        }

        var json = await _executeScript(BuildScript("""
            var ctx = detectFocusContext();
            return JSON.stringify(ctx);
            """));

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var kind = root.TryGetProperty("kind", out var k) ? k.GetString() ?? "page" : "page";
        var selector = root.TryGetProperty("selector", out var sel) && sel.ValueKind == JsonValueKind.String
            ? sel.GetString()
            : null;
        var label = root.TryGetProperty("label", out var lbl) ? lbl.GetString() ?? "" : "";

        return new TabOrderContextInfo
        {
            ScopeSelector = selector,
            Kind = kind,
            Label = label,
            AutoDetected = kind is "modal" or "popover" or "inert-island"
        };
    }

    private async Task<List<FocusableItem>> CollectInScopeFocusablesAsync(string? scopeSelector)
    {
        var json = await _executeScript(BuildScript($@"
            var scopeSel = {JsonEscape(scopeSelector)};
            var scopeRoot = resolveScopeRoot(scopeSel);
            if (!scopeRoot) return JSON.stringify({{ items: [] }});
            var items = collectTabFocusables(scopeRoot).map(function(el) {{
                var rect = el.getBoundingClientRect();
                return {{
                    signature: getSelector(el) + '@' + Math.round(rect.x + rect.width / 2) + ',' + Math.round(rect.y + rect.height / 2),
                    selector: getSelector(el),
                    label: getLabel(el),
                    tabIndex: el.tabIndex || 0,
                    x: rect.x, y: rect.y, width: rect.width, height: rect.height
                }};
            }});
            return JSON.stringify({{ items: items }});
        "));

        var items = new List<FocusableItem>();
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("items", out var arr))
            return items;

        foreach (var el in arr.EnumerateArray())
        {
            items.Add(new FocusableItem
            {
                Signature = el.GetProperty("signature").GetString() ?? "",
                Selector = el.GetProperty("selector").GetString() ?? "",
                Label = el.GetProperty("label").GetString() ?? "",
                TabIndex = el.GetProperty("tabIndex").GetInt32(),
                X = el.GetProperty("x").GetDouble(),
                Y = el.GetProperty("y").GetDouble(),
                Width = el.TryGetProperty("width", out var w) ? w.GetDouble() : 0,
                Height = el.TryGetProperty("height", out var h) ? h.GetDouble() : 0
            });
        }

        return items;
    }

    private async Task EnsureWebViewFocusedAsync()
    {
        await _webView.Dispatcher.InvokeAsync(() => _webView.Focus());
        await Task.Delay(30);
    }

    private async Task ResetFocusInScopeAsync(string? scopeSelector, string? startSelector)
    {
        var scope = JsonEscape(scopeSelector);
        var start = JsonEscape(startSelector);
        var json = await _executeScript(BuildScript($@"
            var scopeSel = {scope};
            var startSel = {start};
            var root = resolveScopeRoot(scopeSel);
            if (!root) return JSON.stringify({{ error: 'Scope not found' }});

            if (startSel) {{
                var startEl = deepQuery(startSel);
                if (!startEl) return JSON.stringify({{ error: 'Start element not found' }});
                startEl.focus();
                return JSON.stringify({{ ok: true }});
            }}

            var ae = document.activeElement;
            if (ae && ae !== document.body && ae.blur) try {{ ae.blur(); }} catch(e) {{}}

            if (root === document.body || root === document.documentElement) {{
                document.body.setAttribute('tabindex', '-1');
                document.body.focus();
                document.body.removeAttribute('tabindex');
            }} else {{
                if (!root.hasAttribute('tabindex')) root.setAttribute('tabindex', '-1');
                root.focus();
            }}
            return JSON.stringify({{ ok: true }});
        "));

        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("error", out var err))
            throw new InvalidOperationException(err.GetString() ?? "Tab-order reset failed.");
    }

    private async Task AdvanceToFirstTabStopAsync(string? scopeSelector, int maxSteps)
    {
        for (var i = 0; i < Math.Min(8, maxSteps); i++)
        {
            var step = await DescribeActiveElementAsync(scopeSelector);
            if (step.Signature is not ("body" or "out-of-scope") && step.InScope &&
                step.Tag is not ("body" or "html"))
                return;

            await DispatchTabKeyAsync(shift: false);
            await Task.Delay(40);
        }
    }

    private async Task<(List<TabOrderStep> Steps, bool CycleComplete)> WalkForwardAsync(
        string? scopeSelector,
        int maxSteps)
    {
        var steps = new List<TabOrderStep>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var stuckCount = 0;
        var cycleComplete = false;
        string? prevSignature = null;
        string? anchorSignature = null;

        var initial = await DescribeActiveElementAsync(scopeSelector);
        initial = CopyStep(initial, index: 0, "forward");
        if (ShouldRecordStep(initial))
        {
            steps.Add(initial);
            prevSignature = initial.Signature;
            TrackForwardVisit(initial, seen);
            if (IsCycleStep(initial))
                anchorSignature = initial.Signature;
        }

        for (var i = steps.Count; i < maxSteps; i++)
        {
            await DispatchTabKeyAsync(shift: false);
            await Task.Delay(45);

            var step = CopyStep(await DescribeActiveElementAsync(scopeSelector), steps.Count, "forward");

            if (step.Signature == prevSignature)
            {
                stuckCount++;
                if (stuckCount >= 3)
                    break;
                continue;
            }

            stuckCount = 0;

            if (anchorSignature != null &&
                step.Signature == anchorSignature &&
                IsCycleStep(step) &&
                steps.Count >= 2)
            {
                steps.Add(CopyStep(step, steps.Count, "forward", roundtripCompleted: true));
                cycleComplete = true;
                // Landed on anchor via Tab; Shift+Tab back to the previous stop so backward
                // verification does not Shift+Tab from the post-cycle anchor (can escape modals).
                await DispatchTabKeyAsync(shift: true);
                await Task.Delay(60);
                break;
            }

            if (ShouldTrackVisit(step) && seen.Contains(step.Signature))
                break;

            steps.Add(step);
            prevSignature = step.Signature;
            TrackForwardVisit(step, seen);
            if (anchorSignature == null && IsCycleStep(step))
                anchorSignature = step.Signature;
        }

        return (steps, cycleComplete);
    }

    /// <summary>
    /// Replays Shift+Tab against the forward log from the last stop (not the anchor).
    /// Forward roundtrip leaves focus on the last stop after a priming Shift+Tab.
    /// </summary>
    private async Task<(List<TabOrderStep> Steps, bool Complete, bool Consistent)> VerifyBackwardAsync(
        IReadOnlyList<TabOrderStep> forwardSteps,
        string? scopeSelector,
        int maxSteps,
        string focusContextKind)
    {
        var replay = forwardSteps.Where(s => !s.RoundtripCompleted).ToList();
        if (replay.Count < 2)
            return ([], replay.Count > 0, true);

        var strictModal = focusContextKind is "modal" or "popover" or "inert-island";
        var steps = new List<TabOrderStep>();
        var consistent = true;
        var last = replay[^1];

        var initial = CopyStep(await DescribeActiveElementAsync(scopeSelector), 0, "backward");
        steps.Add(initial);
        if (!SameStop(initial, last))
            consistent = false;
        if (strictModal && !initial.InScope)
            return (steps, false, false);

        for (var fi = replay.Count - 2; fi >= 0; fi--)
        {
            if (steps.Count >= maxSteps)
                return (steps, false, false);

            await DispatchTabKeyAsync(shift: true);
            await Task.Delay(60);

            var step = CopyStep(await DescribeActiveElementAsync(scopeSelector), steps.Count, "backward");
            steps.Add(step);
            if (strictModal && !step.InScope)
                return (steps, false, false);
            if (!SameStop(step, replay[fi]))
                consistent = false;
        }

        if (steps.Count >= maxSteps)
            return (steps, false, consistent);

        await DispatchTabKeyAsync(shift: true);
        await Task.Delay(60);

        var roundtrip = CopyStep(await DescribeActiveElementAsync(scopeSelector), steps.Count, "backward", roundtripCompleted: true);
        steps.Add(roundtrip);

        if (strictModal && !roundtrip.InScope)
            return (steps, false, false);

        var complete = SameStop(roundtrip, last);
        if (!complete)
            consistent = false;

        return (steps, complete, consistent);
    }

    private static bool SameStop(TabOrderStep actual, TabOrderStep expected)
    {
        if (actual.Signature == expected.Signature)
            return true;
        if (expected.Ref.HasValue && actual.Ref.HasValue && expected.Ref == actual.Ref)
            return true;
        if (!string.IsNullOrWhiteSpace(expected.Label) &&
            actual.Label.Equals(expected.Label, StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    private static void TrackForwardVisit(TabOrderStep step, HashSet<string> seen)
    {
        if (ShouldTrackVisit(step))
            seen.Add(step.Signature);
    }

    private static bool ShouldRecordStep(TabOrderStep step) =>
        step.Signature is not ("body" or "out-of-scope") || step.InScope;

    private static bool ShouldTrackVisit(TabOrderStep step) => !IsTransientStop(step);

    private static bool IsTransientStop(TabOrderStep step) =>
        step.Signature is "body" or "out-of-scope" ||
        step.Tag is "body" or "html";

    private async Task<TabOrderStep> DescribeActiveElementAsync(string? scopeSelector)
    {
        var scope = JsonEscape(scopeSelector);
        var json = await _executeScript(BuildScript($@"
            var scopeSel = {scope};
            var scopeRoot = resolveScopeRoot(scopeSel);
            var el = document.activeElement;
            if (!el || el === document.body || el === document.documentElement) {{
                return JSON.stringify(describeElement(el, scopeRoot, true, 'body'));
            }}
            var inScope = elementInScope(el, scopeRoot);
            return JSON.stringify(describeElement(el, scopeRoot, inScope));
        "));

        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        return new TabOrderStep
        {
            Signature = root.GetProperty("signature").GetString() ?? "",
            Selector = root.GetProperty("selector").GetString() ?? "",
            Label = root.GetProperty("label").GetString() ?? "",
            Tag = root.GetProperty("tag").GetString() ?? "",
            Role = root.GetProperty("role").GetString() ?? "",
            TabIndex = root.GetProperty("tabIndex").GetInt32(),
            X = root.GetProperty("x").GetDouble(),
            Y = root.GetProperty("y").GetDouble(),
            Width = root.GetProperty("width").GetDouble(),
            Height = root.GetProperty("height").GetDouble(),
            InScope = root.TryGetProperty("inScope", out var ins) && ins.GetBoolean()
        };
    }

    private static List<TabOrderIssue> AnalyzeIssues(
        TabOrderOptions options,
        TabOrderContextInfo context,
        IReadOnlyList<TabOrderStep> forwardSteps,
        IReadOnlyList<TabOrderStep> backwardSteps,
        IReadOnlyList<FocusableItem> focusables,
        bool forwardComplete,
        bool backwardComplete,
        bool shiftConsistent,
        Func<int, string?>? getSelectorByRef)
    {
        var issues = new List<TabOrderIssue>();
        var strictScope = options.StrictScope && !string.IsNullOrEmpty(context.ScopeSelector);

        if (focusables.Count == 0 && forwardSteps.Count == 0)
        {
            issues.Add(new TabOrderIssue
            {
                Category = "no-focusables",
                Severity = TabOrderSeverity.Warning,
                Message = "No visible tab-focusable elements found in scope."
            });
            return issues;
        }

        for (var i = 0; i < forwardSteps.Count; i++)
        {
            var step = forwardSteps[i];
            if (!step.InScope && strictScope)
            {
                issues.Add(new TabOrderIssue
                {
                    Category = context.Kind is "modal" or "popover"
                        ? "modal-focus-leak"
                        : "focus-escaped-scope",
                    Severity = TabOrderSeverity.Error,
                    Message = context.Kind is "modal" or "popover"
                        ? "Tab moved focus to the page background while a modal is open"
                        : "Tab moved focus outside the audit scope",
                    Selector = step.Selector,
                    Label = step.Label,
                    StepIndex = i
                });
            }
        }

        if (!forwardComplete && forwardSteps.Count >= options.MaxSteps)
        {
            issues.Add(new TabOrderIssue
            {
                Category = "incomplete-cycle",
                Severity = TabOrderSeverity.Warning,
                Message = $"Forward Tab walk did not complete within {options.MaxSteps} steps."
            });
        }

        if (options.CheckShiftTabConsistency && backwardSteps.Count > 0 && !shiftConsistent)
        {
            issues.Add(new TabOrderIssue
            {
                Category = "shift-tab-inconsistency",
                Severity = TabOrderSeverity.Error,
                Message = "Shift+Tab backward order does not reverse the forward Tab order."
            });
        }

        if (options.CheckShiftTabConsistency && backwardSteps.Count > 0 && !backwardComplete)
        {
            issues.Add(new TabOrderIssue
            {
                Category = "incomplete-backward-cycle",
                Severity = TabOrderSeverity.Warning,
                Message = "Backward Shift+Tab walk did not return to the starting focus stop."
            });
        }

        if (options.CheckPositiveTabIndex)
        {
            foreach (var item in focusables.Where(f => f.TabIndex > 0))
            {
                issues.Add(new TabOrderIssue
                {
                    Category = "positive-tabindex",
                    Severity = TabOrderSeverity.Warning,
                    Message = $"Positive tabindex={item.TabIndex} disrupts natural focus order.",
                    Selector = item.Selector,
                    Label = item.Label
                });
            }
        }

        // Skipped controls: the forward keyboard walk is authoritative — no static inventory diff.
        if (options.CheckSkipped && !forwardComplete && forwardSteps.Count > 0)
        {
            issues.Add(new TabOrderIssue
            {
                Category = "skipped-focusable",
                Severity = TabOrderSeverity.Warning,
                Message = "Forward Tab did not complete a full roundtrip; some focusable controls may have been missed."
            });
        }

        if (options.CheckReadingOrder)
        {
            var inScopeSteps = forwardSteps.Where(s => s.InScope && s.Signature is not ("body" or "out-of-scope")).ToList();
            for (var i = 1; i < inScopeSteps.Count; i++)
            {
                var prev = inScopeSteps[i - 1];
                var cur = inScopeSteps[i];
                var prevCy = prev.Y + prev.Height / 2;
                var curCy = cur.Y + cur.Height / 2;
                var prevCx = prev.X + prev.Width / 2;
                var curCx = cur.X + cur.Width / 2;
                var rowTolerance = Math.Max(prev.Height, cur.Height) * 0.75;
                var onSameRow = Math.Abs(curCy - prevCy) <= rowTolerance;

                if (curCy + 40 < prevCy)
                {
                    issues.Add(new TabOrderIssue
                    {
                        Category = "reading-order",
                        Severity = TabOrderSeverity.Warning,
                        Message = "Focus jumped significantly upward on the page.",
                        Selector = cur.Selector,
                        Label = cur.Label,
                        StepIndex = cur.Index
                    });
                }
                else if (onSameRow && curCx + 20 < prevCx)
                {
                    issues.Add(new TabOrderIssue
                    {
                        Category = "reading-order",
                        Severity = TabOrderSeverity.Warning,
                        Message = "Focus moved right-to-left on the same row (LTR reading order).",
                        Selector = cur.Selector,
                        Label = cur.Label,
                        StepIndex = cur.Index
                    });
                }
            }
        }

        if (options.CheckFocusTrap && forwardSteps.Count >= 2)
        {
            var visited = forwardSteps
                .Where(s => s.InScope && !IsTransientStop(s) && !s.RoundtripCompleted)
                .Select(s => s.Signature)
                .Distinct(StringComparer.Ordinal)
                .Count();
            if (focusables.Count > visited + 2 && visited <= 5)
            {
                issues.Add(new TabOrderIssue
                {
                    Category = "focus-trap",
                    Severity = TabOrderSeverity.Error,
                    Message =
                        $"Tab cycles among only {visited} in-scope element(s) but {focusables.Count} focusable control(s) exist in scope."
                });
            }
        }

        if (strictScope && context.Kind is "modal" or "popover")
        {
            var escaped = forwardSteps.Any(s => !s.InScope);
            if (escaped && !issues.Any(i => i.Category is "modal-focus-leak" or "focus-escaped-scope"))
            {
                issues.Add(new TabOrderIssue
                {
                    Category = "modal-focus-leak",
                    Severity = TabOrderSeverity.Error,
                    Message = "Focus left the modal during Tab navigation."
                });
            }
        }

        if (options.ExpectedOrder is { Count: > 0 })
        {
            var actual = forwardSteps
                .Where(s => s.InScope && s.Signature is not ("body" or "out-of-scope"))
                .Select(s => NormalizeMatchKey(s.Label, s.Selector))
                .Where(s => !string.IsNullOrEmpty(s))
                .ToList();

            var expected = options.ExpectedOrder
                .Select(e => ResolveExpectedKey(e, getSelectorByRef))
                .Where(s => !string.IsNullOrEmpty(s))
                .ToList();

            if (expected.Count > 0 && !SequencesMatch(actual, expected))
            {
                issues.Add(new TabOrderIssue
                {
                    Category = "expected-order-mismatch",
                    Severity = TabOrderSeverity.Error,
                    Message =
                        $"Expected order [{string.Join(" → ", expected)}] but got [{string.Join(" → ", actual)}]."
                });
            }
        }

        return issues;
    }

    private static TabOrderStep? FirstCycleStep(IReadOnlyList<TabOrderStep> steps)
    {
        foreach (var step in steps)
        {
            if (IsCycleStep(step))
                return step;
        }

        return null;
    }

    private static bool IsCycleStep(TabOrderStep step) =>
        !step.RoundtripCompleted &&
        step.InScope &&
        step.Signature is not ("body" or "out-of-scope") &&
        step.Tag is not ("body" or "html");

    private static void MapRefs(List<TabOrderStep> steps, Func<string, int?>? getRefBySelector)
    {
        if (getRefBySelector == null)
            return;

        for (var i = 0; i < steps.Count; i++)
        {
            var r = getRefBySelector(steps[i].Selector);
            if (r.HasValue)
                steps[i] = CopyStep(steps[i], refValue: r);
        }
    }

    private static TabOrderStep CopyStep(
        TabOrderStep step,
        int? index = null,
        string? direction = null,
        int? refValue = null,
        bool? roundtripCompleted = null) => new()
    {
        Index = index ?? step.Index,
        Direction = direction ?? step.Direction,
        Signature = step.Signature,
        Selector = step.Selector,
        Label = step.Label,
        Tag = step.Tag,
        Role = step.Role,
        TabIndex = step.TabIndex,
        Ref = refValue ?? step.Ref,
        X = step.X,
        Y = step.Y,
        Width = step.Width,
        Height = step.Height,
        InScope = step.InScope,
        RoundtripCompleted = roundtripCompleted ?? step.RoundtripCompleted
    };

    private Task DispatchTabKeyAsync(bool shift) => _dispatchRealTab(shift);

    private async Task DefaultDispatchTabKeyAsync(bool shift)
    {
        await _webView.Dispatcher.InvokeAsync(async () =>
        {
            _webView.Focus();
            var modifiers = shift ? 8 : 0;
            var keyDown = JsonSerializer.Serialize(new
            {
                type = "keyDown",
                key = "Tab",
                code = "Tab",
                windowsVirtualKeyCode = 9,
                nativeVirtualKeyCode = 9,
                modifiers
            });
            var keyUp = JsonSerializer.Serialize(new
            {
                type = "keyUp",
                key = "Tab",
                code = "Tab",
                windowsVirtualKeyCode = 9,
                nativeVirtualKeyCode = 9,
                modifiers
            });

            await _webView.CoreWebView2.CallDevToolsProtocolMethodAsync("Input.dispatchKeyEvent", keyDown);
            await _webView.CoreWebView2.CallDevToolsProtocolMethodAsync("Input.dispatchKeyEvent", keyUp);
        });
    }

    private static string ResolveExpectedKey(string token, Func<int, string?>? getSelectorByRef)
    {
        token = token.Trim();
        if (int.TryParse(token, out var refNum) && getSelectorByRef != null)
        {
            var sel = getSelectorByRef(refNum);
            if (!string.IsNullOrEmpty(sel))
                return NormalizeMatchKey("", sel);
        }

        return NormalizeMatchKey(token, token);
    }

    private static string NormalizeMatchKey(string label, string selector)
    {
        var key = !string.IsNullOrWhiteSpace(label) ? label : selector;
        return key.Trim().ToLowerInvariant();
    }

    private static bool SequencesMatch(IReadOnlyList<string> actual, IReadOnlyList<string> expected)
    {
        if (actual.Count < expected.Count)
            return false;

        for (var offset = 0; offset <= actual.Count - expected.Count; offset++)
        {
            var ok = true;
            for (var i = 0; i < expected.Count; i++)
            {
                if (!MatchKey(actual[offset + i], expected[i]))
                {
                    ok = false;
                    break;
                }
            }

            if (ok)
                return true;
        }

        return false;
    }

    private static bool MatchKey(string actual, string expected)
        => actual.Contains(expected, StringComparison.OrdinalIgnoreCase)
           || expected.Contains(actual, StringComparison.OrdinalIgnoreCase);

    private static string BuildScript(string innerJs) =>
        "(function() {\n" + TabOrderJs + "\n" + innerJs + "\n})()";

    private static string JsonEscape(string? value)
        => value == null ? "null" : JsonSerializer.Serialize(value);

    private sealed class TabOrderContextInfo
    {
        public string? ScopeSelector { get; init; }
        public string Kind { get; init; } = "page";
        public string Label { get; init; } = "";
        public bool AutoDetected { get; init; }
    }

    private sealed class FocusableItem
    {
        public string Signature { get; init; } = "";
        public string Selector { get; init; } = "";
        public string Label { get; init; } = "";
        public int TabIndex { get; init; }
        public double X { get; init; }
        public double Y { get; init; }
        public double Width { get; init; }
        public double Height { get; init; }
    }

    private const string TabOrderJs = """
        function collectAll(root, sel) {
            var results = [];
            function walk(node, selector) {
                try { results = results.concat(Array.from(node.querySelectorAll(selector))); } catch(e) {}
                var all = node.querySelectorAll ? node.querySelectorAll('*') : [];
                for (var i = 0; i < all.length; i++) {
                    if (all[i].shadowRoot) walk(all[i].shadowRoot, selector);
                }
            }
            walk(root, sel);
            return results;
        }

        function deepQuery(sel) {
            if (!sel) return null;
            if (sel.indexOf(' >>> ') >= 0) {
                var parts = sel.split(' >>> ');
                var host = deepQuery(parts[0]);
                if (!host || !host.shadowRoot) return null;
                try { return host.shadowRoot.querySelector(parts.slice(1).join(' >>> ')); } catch(e) { return null; }
            }
            try { var el = document.querySelector(sel); if (el) return el; } catch(e) {}
            var hosts = document.querySelectorAll('*');
            for (var i = 0; i < hosts.length; i++) {
                if (!hosts[i].shadowRoot) continue;
                try { var found = hosts[i].shadowRoot.querySelector(sel); if (found) return found; } catch(e) {}
            }
            return null;
        }

        function resolveScopeRoot(scopeSel) {
            if (!scopeSel) return document.body;
            var el = deepQuery(scopeSel);
            if (!el) return null;
            return expandDialogScope(el);
        }

        function composedContains(ancestor, el) {
            if (!ancestor || !el) return false;
            if (ancestor === el) return true;
            var cur = el;
            while (cur) {
                if (cur === ancestor) return true;
                if (cur.parentElement) {
                    cur = cur.parentElement;
                } else {
                    var root = cur.getRootNode();
                    if (root instanceof ShadowRoot) {
                        cur = root.host;
                    } else {
                        break;
                    }
                }
            }
            return false;
        }

        /** Widen modal scope to the outer dialog / web-component host (shadow-aware). */
        function expandDialogScope(el) {
            if (!el) return el;
            var scope = el;
            var cur = el;
            while (cur) {
                var role = cur.getAttribute ? cur.getAttribute('role') : null;
                var ariaModal = cur.getAttribute ? cur.getAttribute('aria-modal') : null;
                var tag = cur.tagName ? cur.tagName.toLowerCase() : '';
                if (role === 'dialog' || role === 'alertdialog' || ariaModal === 'true' ||
                    tag === 'dialog' || tag.endsWith('-dialog')) {
                    scope = cur;
                }
                var root = cur.getRootNode();
                if (root instanceof ShadowRoot) {
                    cur = root.host;
                } else if (cur.parentElement) {
                    cur = cur.parentElement;
                } else {
                    break;
                }
            }
            cur = el;
            while (cur) {
                var root = cur.getRootNode();
                if (root instanceof ShadowRoot) {
                    var host = root.host;
                    var hostTag = host && host.tagName ? host.tagName.toLowerCase() : '';
                    if (hostTag.endsWith('-dialog') || host.getAttribute('role') === 'dialog') {
                        scope = host;
                    }
                    cur = host;
                } else {
                    break;
                }
            }
            return scope;
        }

        function elementInScope(el, scopeRoot) {
            if (!scopeRoot || scopeRoot === document.body || scopeRoot === document.documentElement) return true;
            if (!el || el === document.body || el === document.documentElement) return false;
            var scope = expandDialogScope(scopeRoot);
            if (el === scope) return true;
            return composedContains(scope, el);
        }

        function getLocalSelector(el, root) {
            if (el.id) {
                try {
                    var escaped = CSS.escape(el.id);
                    if (root.querySelectorAll('#' + escaped).length === 1) return '#' + escaped;
                } catch(e) {}
            }
            var testId = el.getAttribute('data-testid');
            if (testId) {
                var sel = '[data-testid="' + testId.replace(/"/g, '\\"') + '"]';
                try { if (root.querySelectorAll(sel).length === 1) return sel; } catch(e) {}
            }
            if (el.name) {
                var sel = '[name="' + el.name.replace(/"/g, '\\"') + '"]';
                try { if (root.querySelectorAll(sel).length === 1) return sel; } catch(e) {}
            }
            var parts = [];
            var cur = el;
            while (cur && cur !== root && cur.nodeType === 1) {
                if (cur.id) { parts.unshift('#' + CSS.escape(cur.id)); break; }
                var tag = cur.tagName.toLowerCase();
                var parent = cur.parentElement;
                if (parent) {
                    var siblings = Array.from(parent.children).filter(function(c) { return c.tagName === cur.tagName; });
                    if (siblings.length > 1) tag += ':nth-of-type(' + (siblings.indexOf(cur) + 1) + ')';
                }
                parts.unshift(tag);
                cur = cur.parentElement;
                if (parts.length >= 6) break;
            }
            return parts.join(' > ');
        }

        function getSelector(el) {
            if (!el || el === document.body) return 'body';
            var root = el.getRootNode();
            if (root instanceof ShadowRoot) {
                return getSelector(root.host) + ' >>> ' + getLocalSelector(el, root);
            }
            return getLocalSelector(el, document);
        }

        function getLabel(el) {
            if (!el || el === document.body) return '(page)';
            var aria = el.getAttribute('aria-label');
            if (aria) return aria.trim().substring(0, 100);
            var labelledBy = el.getAttribute('aria-labelledby');
            if (labelledBy) {
                var parts = labelledBy.split(/\s+/);
                for (var i = 0; i < parts.length; i++) {
                    var ref = document.getElementById(parts[i]);
                    if (ref) return (ref.innerText || ref.textContent || '').trim().substring(0, 100);
                }
            }
            if (el.id) {
                var lbl = document.querySelector('label[for="' + el.id + '"]');
                if (lbl) return (lbl.innerText || '').trim().substring(0, 100);
            }
            var text = (el.innerText || el.textContent || '').trim();
            if (text && text.length < 100) return text;
            if (text) return text.substring(0, 100);
            if (el.placeholder) return el.placeholder.trim().substring(0, 100);
            if (el.title) return el.title.trim().substring(0, 100);
            return '';
        }

        function isVisible(el) {
            if (!el || el === document.body) return false;
            if (el.getAttribute('aria-hidden') === 'true') return false;
            var cur = el;
            while (cur) {
                if (cur.nodeType !== 1) break;
                try {
                    var style = window.getComputedStyle(cur);
                    if (style.display === 'none' || style.visibility === 'hidden') return false;
                    if (parseFloat(style.opacity) === 0) return false;
                } catch(e) { break; }
                if (cur.parentElement) cur = cur.parentElement;
                else {
                    var root = cur.getRootNode();
                    cur = (root instanceof ShadowRoot) ? root.host : null;
                }
            }
            var rect = el.getBoundingClientRect();
            return rect.width > 0 && rect.height > 0;
        }

        function isTabFocusable(el) {
            if (!isVisible(el)) return false;
            if (el.disabled || el.getAttribute('aria-disabled') === 'true') return false;
            if (el.closest('[inert]')) return false;
            if (el.hasAttribute('tabindex') && el.tabIndex < 0) return false;
            var tag = el.tagName;
            if (tag === 'A' && el.hasAttribute('href')) return true;
            if (tag === 'AREA' && el.hasAttribute('href')) return true;
            if (tag === 'BUTTON' || tag === 'SELECT' || tag === 'TEXTAREA') return true;
            if (tag === 'INPUT' && (el.type || 'text').toLowerCase() !== 'hidden') return true;
            if (tag === 'SUMMARY') return true;
            if (tag === 'IFRAME' && el.tabIndex >= 0) return true;
            if (el.isContentEditable) return true;
            if (el.tabIndex >= 0) return true;
            return false;
        }

        function isBrowserTabCandidate(el) {
            if (!isTabFocusable(el)) return false;
            var tag = el.tagName;
            if (tag === 'A' || tag === 'AREA' || tag === 'BUTTON' || tag === 'SELECT' || tag === 'TEXTAREA' || tag === 'INPUT') return true;
            if (tag === 'SUMMARY') return true;
            if (tag === 'IFRAME' && el.tabIndex >= 0) return true;
            if (el.isContentEditable) return true;
            if (el.hasAttribute('tabindex') && el.tabIndex >= 0) return true;
            return false;
        }

        function collectTabFocusables(scopeRoot) {
            var scope = (!scopeRoot || scopeRoot === document.body || scopeRoot === document.documentElement)
                ? document.documentElement : expandDialogScope(scopeRoot);
            var selector = [
                'a[href]', 'area[href]', 'button:not([disabled])',
                'input:not([disabled]):not([type=hidden])', 'select:not([disabled])', 'textarea:not([disabled])',
                'summary', 'iframe[tabindex]:not([tabindex="-1"])', '[contenteditable="true"]',
                '[tabindex]:not([tabindex="-1"])',
                '[role="button"]:not([disabled])', '[role="link"][href]', '[role="tab"]',
                '[role="checkbox"]', '[role="radio"]', '[role="switch"]', '[role="combobox"]',
                '[role="menuitem"]', '[role="option"]', '[role="slider"]', '[role="spinbutton"]',
                '[role="textbox"]', '[role="searchbox"]'
            ].join(',');
            var seen = new Set();
            var out = [];
            function add(el) {
                if (!el || seen.has(el)) return;
                if (!elementInScope(el, scopeRoot)) return;
                if (!isBrowserTabCandidate(el)) return;
                seen.add(el);
                out.push(el);
            }
            collectTreeOrder(scope, scopeRoot).forEach(add);
            collectAll(scope === document.documentElement ? document : scope, selector).forEach(add);
            return out;
        }

        function collectTreeOrder(scopeRoot, filterRoot) {
            var found = [];
            var seen = new Set();
            function walk(node) {
                if (!node || node.nodeType !== 1) return;
                if (elementInScope(node, filterRoot) && isBrowserTabCandidate(node) && !seen.has(node)) {
                    seen.add(node); found.push(node);
                }
                if (node.shadowRoot) walkChildren(node.shadowRoot);
                walkChildren(node);
            }
            function walkChildren(parent) {
                if (!parent || !parent.firstElementChild) return;
                for (var c = parent.firstElementChild; c; c = c.nextElementSibling) walk(c);
            }
            walk(scopeRoot);
            return found;
        }

        function modalScore(el) {
            var style = window.getComputedStyle(el);
            var rect = el.getBoundingClientRect();
            var z = parseInt(style.zIndex, 10);
            if (isNaN(z)) z = 0;
            if (style.position === 'fixed' || style.position === 'sticky') z += 1000;
            return z * 100000 + rect.width * rect.height;
        }

        function detectFocusContext() {
            var candidates = [];
            var sels = [
                '[role="dialog"][aria-modal="true"]',
                '[role="alertdialog"]',
                'dialog[open]',
                '[popover]:popover-open',
                '[aria-modal="true"]'
            ];
            sels.forEach(function(sel) {
                try { document.querySelectorAll(sel).forEach(function(el) { candidates.push(el); }); } catch(e) {}
            });
            document.querySelectorAll('*').forEach(function(el) {
                if (!el.shadowRoot) return;
                sels.forEach(function(sel) {
                    try { el.shadowRoot.querySelectorAll(sel).forEach(function(n) { candidates.push(n); }); } catch(e) {}
                });
            });

            var visible = candidates.filter(function(el) {
                return isVisible(el) && (el.getAttribute('aria-modal') === 'true' || el.hasAttribute('open') || el.matches('[popover]:popover-open'));
            });

            if (visible.length > 0) {
                visible.sort(function(a, b) { return modalScore(b) - modalScore(a); });
                var top = visible[0];
                var scopeEl = expandDialogScope(top);
                var role = top.getAttribute('role') || 'dialog';
                return {
                    kind: role === 'alertdialog' ? 'modal' : (top.matches('[popover]:popover-open') ? 'popover' : 'modal'),
                    selector: getSelector(scopeEl),
                    label: getLabel(top) || getLabel(scopeEl) || (role + ' dialog')
                };
            }

            var inertRoots = Array.from(document.querySelectorAll('[inert]'));
            if (inertRoots.length > 0) {
                var islands = collectAll(document.documentElement, '*').filter(function(el) {
                    return isVisible(el) && !el.closest('[inert]') && el !== document.body &&
                        (el.getAttribute('role') === 'dialog' || el.classList.contains('modal') || el.hasAttribute('data-modal'));
                });
                if (islands.length > 0) {
                    islands.sort(function(a, b) { return modalScore(b) - modalScore(a); });
                    var island = islands[0];
                    return { kind: 'inert-island', selector: getSelector(island), label: getLabel(island) || 'Modal (inert background)' };
                }
            }

            return { kind: 'page', selector: null, label: 'Full page' };
        }

        function describeElement(el, scopeRoot, inScope, forcedSignature) {
            if (!el || el === document.body || el === document.documentElement || forcedSignature === 'body') {
                return {
                    signature: 'body', selector: 'body', label: '(page)', tag: 'body', role: '',
                    tabIndex: -1, x: 0, y: 0, width: 0, height: 0, inScope: inScope !== false
                };
            }
            var rect = el.getBoundingClientRect();
            return {
                signature: getSelector(el) + '@' + Math.round(rect.x + rect.width / 2) + ',' + Math.round(rect.y + rect.height / 2),
                selector: getSelector(el),
                label: getLabel(el),
                tag: (el.tagName || '').toLowerCase(),
                role: el.getAttribute('role') || el.type || '',
                tabIndex: el.tabIndex || 0,
                x: rect.x, y: rect.y, width: rect.width, height: rect.height,
                inScope: !!inScope
            };
        }
        """;
}
