using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Accessibility;
using Trowser.Compatibility;
using Trowser.HtmlValidation;
using Trowser.Performance;
using Trowser.ResourceUsage;
using Trowser.Robustness;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Orchestration;
using Trowser.EndpointProbe;
using Trowser.Seo;
using Trowser.Testing;

namespace Trowser.Automation;

public partial class AutomationContext
{
    #region Accessibility (WCAG)

    private AccessibilityChecker GetAccessibilityChecker() => new AccessibilityChecker(ActiveTab.WebView);

    public async Task<AccessibilityResult> CheckAccessibility(string? wcagLevel = "AA", string? selector = null)
    {
        using var linked = LinkCheckerCancellation();
        return await GetAccessibilityChecker().RunAsync(wcagLevel, selector, linked.Token);
    }

    public async Task<AccessibilityResult> PrintAccessibilityReport(
        string? wcagLevel = "AA", bool includeNodes = true, Impact? minImpact = null)
    {
        var result = await GetAccessibilityChecker().RunAsync(wcagLevel);
        var report = result.Format(includeNodes, minImpact);

        if (result.IsClean)
        {
            _logColored(report, "#4EC9B0");
        }
        else
        {
            var lines = report.Split(Environment.NewLine);
            foreach (var line in lines)
            {
                if (line.StartsWith("---") || line.Contains("[CRITICAL]") || line.Contains("[SERIOUS]"))
                    _logColored(line, "#F44747");
                else if (line.Contains("[MODERATE]"))
                    _logColored(line, "#CCA700");
                else if (line.Contains("[MINOR]"))
                    _logColored(line, "#569CD6");
                else if (line.StartsWith("===") || line.StartsWith("VIOLATIONS"))
                    _logColored(line, "#CCA700");
                else if (line.Contains("CRITICAL:") || line.Contains("SERIOUS:"))
                    _logColored(line, "#F44747");
                else
                    _logColored(line, "#CCCCCC");
            }
        }

        return result;
    }

    public async Task AssertAccessible(string? wcagLevel = "AA", Impact? minImpact = null, string? message = null)
    {
        _logColored("Accessibility audit powered by axe-core", "#888888");
        var result = await GetAccessibilityChecker().RunAsync(wcagLevel);

        var violations = minImpact.HasValue
            ? result.GetByMinImpact(minImpact.Value)
            : result.Violations;

        var desc = message ?? $"Page should be WCAG {wcagLevel ?? "all"} accessible";

        if (violations.Count == 0)
        {
            Assert.Pass($"{desc} ({result.PassCount} rules passed)");
        }
        else
        {
            Assert.Fail($"{desc}: {violations.Count} violation(s) found");
            foreach (var v in violations.OrderByDescending(v => v.Impact))
            {
                var impactLabel = v.Impact.ToString().ToUpper();
                var wcagInfo = v.WcagCriteria.Count > 0
                    ? $" WCAG {string.Join(", ", v.WcagCriteria)}"
                    : "";
                _logColored($"    [{impactLabel}]{wcagInfo} {v.RuleId}: {v.Help} ({v.Count} element(s))", "#F44747");
            }
        }
    }

    #endregion

    #region Tab Order

    /// <summary>
    /// Dispatches a real Tab or Shift+Tab key to the active page via CDP (same path as tab-order audit).
    /// </summary>
    public async Task DispatchRealTabKeyAsync(bool shift = false)
    {
        var webView = ActiveTab.WebView;
        await webView.Dispatcher.InvokeAsync(async () =>
        {
            webView.Focus();
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

            await webView.CoreWebView2.CallDevToolsProtocolMethodAsync("Input.dispatchKeyEvent", keyDown);
            await webView.CoreWebView2.CallDevToolsProtocolMethodAsync("Input.dispatchKeyEvent", keyUp);
        });
    }

    private TabOrderChecker GetTabOrderChecker() =>
        new(ActiveTab.WebView, RunJs, DispatchRealTabKeyAsync);

    public async Task<TabOrderResult> CheckTabOrder(TabOrderOptions? options = null)
    {
        options ??= new TabOrderOptions();
        await GetInteractiveElements();
        var resolved = await ResolveTabOrderOptionsAsync(options);
        return await GetTabOrderChecker().RunAsync(
            resolved,
            ActiveTab.GetSelectorByRef,
            ActiveTab.GetRefBySelector,
            await GetCurrentUrl(),
            await GetTitle());
    }

    public async Task<TabOrderResult> PrintTabOrderReport(TabOrderOptions? options = null, bool includeSteps = true)
    {
        var result = await CheckTabOrder(options);
        var report = result.Format(includeSteps);

        if (result.IsClean)
        {
            _logColored(report, "#4EC9B0");
        }
        else
        {
            foreach (var line in report.Split(Environment.NewLine))
            {
                if (line.Contains("[ERROR]") || line.Contains("NO") || line.Contains("MISMATCH"))
                    _logColored(line, "#F44747");
                else if (line.Contains("[WARNING]"))
                    _logColored(line, "#CCA700");
                else if (line.StartsWith("===") || line.StartsWith("---"))
                    _logColored(line, "#4EC9B0");
                else
                    _logColored(line, "#CCCCCC");
            }
        }

        return result;
    }

    public async Task AssertTabOrderClean(TabOrderOptions? options = null, string? message = null)
    {
        var result = await CheckTabOrder(options);
        var desc = message ?? "Tab order should have no keyboard navigation issues";

        if (result.IsClean)
        {
            var shiftNote = !result.ShiftTabConsistencyChecked
                ? "not checked"
                : result.ShiftTabConsistent == true ? "yes" : "no";
            Assert.Pass($"{desc} ({result.ForwardSteps.Count} Tab stops, Shift+Tab consistent: {shiftNote})");
        }
        else
        {
            Assert.Fail($"{desc}: {result.Issues.Count} issue(s)");
            foreach (var issue in result.Issues.OrderByDescending(i => i.Severity))
            {
                var sev = issue.Severity.ToString().ToUpperInvariant();
                var target = !string.IsNullOrEmpty(issue.Label) ? $" \"{issue.Label}\"" : "";
                _logColored($"    [{sev}] {issue.Category}: {issue.Message}{target}", "#F44747");
            }
        }
    }

    public Task AssertTabOrder(IReadOnlyList<string> expectedOrder, TabOrderOptions? options = null, string? message = null)
    {
        options ??= new TabOrderOptions();
        var merged = new TabOrderOptions
        {
            Selector = options.Selector,
            StartSelector = options.StartSelector,
            MaxSteps = options.MaxSteps,
            CheckPositiveTabIndex = options.CheckPositiveTabIndex,
            CheckSkipped = options.CheckSkipped,
            CheckReadingOrder = options.CheckReadingOrder,
            CheckFocusTrap = options.CheckFocusTrap,
            CheckShiftTabConsistency = options.CheckShiftTabConsistency,
            ExpectedOrder = expectedOrder
        };
        return AssertTabOrderClean(merged, message ?? "Tab order should match expected sequence");
    }

    private async Task<TabOrderOptions> ResolveTabOrderOptionsAsync(TabOrderOptions options)
    {
        var startSelector = options.StartSelector;
        if (!string.IsNullOrEmpty(startSelector))
        {
            if (int.TryParse(startSelector.Trim(), out var refNum))
            {
                var byRef = GetSelectorByRef(refNum);
                if (byRef != null)
                    startSelector = byRef;
            }
            else if (startSelector.StartsWith('@'))
            {
                startSelector = await WaitForActionable(startSelector, DefaultActionTimeout,
                    requireVisible: true, requireEnabled: false);
            }
        }

        IReadOnlyList<string>? expected = options.ExpectedOrder;
        if (expected is { Count: > 0 })
        {
            var resolved = new List<string>(expected.Count);
            foreach (var token in expected)
            {
                if (int.TryParse(token.Trim(), out var refNum))
                {
                    var sel = GetSelectorByRef(refNum);
                    resolved.Add(sel ?? token);
                }
                else
                    resolved.Add(token);
            }

            expected = resolved;
        }

        return new TabOrderOptions
        {
            Selector = options.Selector,
            StartSelector = startSelector,
            AutoDetectScope = options.AutoDetectScope,
            StrictScope = options.StrictScope,
            MaxSteps = options.MaxSteps,
            CheckPositiveTabIndex = options.CheckPositiveTabIndex,
            CheckSkipped = options.CheckSkipped,
            CheckReadingOrder = options.CheckReadingOrder,
            CheckFocusTrap = options.CheckFocusTrap,
            CheckShiftTabConsistency = options.CheckShiftTabConsistency,
            ExpectedOrder = expected
        };
    }

    #endregion

    #region Performance (Web Vitals)

    private PerformanceChecker GetPerformanceChecker() => new PerformanceChecker(ActiveTab.WebView);

    public async Task<PerformanceResult> CheckPerformance()
    {
        using var linked = LinkCheckerCancellation();
        return await GetPerformanceChecker().RunAsync(linked.Token);
    }

    public async Task<PerformanceResult> PrintPerformanceReport(
        bool includeNavigation = true, bool includeResources = true)
    {
        var result = await GetPerformanceChecker().RunAsync();
        var report = result.Format(includeNavigation, includeResources);

        var lines = report.Split(Environment.NewLine);
        foreach (var line in lines)
        {
            if (line.Contains("[POOR]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[NEEDS IMPROVEMENT]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[GOOD]"))
                _logColored(line, "#4EC9B0");
            else if (line.StartsWith("===") || line.StartsWith("ASSESSMENT"))
            {
                if (line.Contains("POOR"))
                    _logColored(line, "#F44747");
                else if (line.Contains("IMPROVEMENT"))
                    _logColored(line, "#CCA700");
                else
                    _logColored(line, "#4EC9B0");
            }
            else if (line.StartsWith("CORE WEB VITALS") || line.StartsWith("OTHER METRICS")
                     || line.StartsWith("NAVIGATION TIMING") || line.StartsWith("RESOURCES")
                     || line.StartsWith("SLOWEST RESOURCES"))
                _logColored(line, "#569CD6");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertPerformance(string? message = null)
    {
        _logColored("Performance measurement powered by web-vitals", "#888888");
        var result = await GetPerformanceChecker().RunAsync();
        var coreVitals = result.GetCoreWebVitals();
        var desc = message ?? "Core Web Vitals should be Good";

        var poor = coreVitals.Where(m => m.Rating == PerformanceRating.Poor).ToList();
        var needsWork = coreVitals.Where(m => m.Rating == PerformanceRating.NeedsImprovement).ToList();

        if (poor.Count == 0 && needsWork.Count == 0)
        {
            Assert.Pass($"{desc} ({coreVitals.Count} metric(s) all Good)");
        }
        else
        {
            var failedCount = poor.Count + needsWork.Count;
            Assert.Fail($"{desc}: {failedCount} metric(s) below threshold");
            foreach (var m in poor)
            {
                var formatted = m.Unit == "ms" ? $"{m.Value:F0}ms" : $"{m.Value:F3}";
                _logColored($"    [POOR] {m.Name}: {formatted}", "#F44747");
            }
            foreach (var m in needsWork)
            {
                var formatted = m.Unit == "ms" ? $"{m.Value:F0}ms" : $"{m.Value:F3}";
                _logColored($"    [NEEDS IMPROVEMENT] {m.Name}: {formatted}", "#CCA700");
            }
        }
    }

    public async Task AssertPerformanceMetric(string metricName, double maxValue, string? message = null)
    {
        var result = await GetPerformanceChecker().RunAsync();
        var metric = result.GetMetric(metricName);
        var desc = message ?? $"{metricName} should be <= {maxValue}";

        if (metric == null)
        {
            Assert.Fail($"{desc}: metric '{metricName}' not available (page may not have loaded fully)");
            return;
        }

        if (metric.Value <= maxValue)
            Assert.Pass($"{desc} (actual: {metric.Value:F1})");
        else
            Assert.Fail($"{desc} (actual: {metric.Value:F1}, limit: {maxValue})");
    }

    #endregion

    #region Resource Usage (memory / DOM leak probes)

    private ResourceSnapshot? _rememberedResourceBaseline;

    private ResourceProbe GetResourceProbe() => new ResourceProbe(this);

    /// <summary>Last baseline stored via <see cref="CheckResourceSnapshot"/> with rememberBaseline: true.</summary>
    public ResourceSnapshot? RememberedResourceBaseline => _rememberedResourceBaseline;

    public void ClearResourceBaseline() => _rememberedResourceBaseline = null;

    public async Task<ResourceSnapshot> CheckResourceSnapshot(bool rememberBaseline = false)
    {
        var snapshot = await GetResourceProbe().SnapshotAsync();
        if (rememberBaseline)
            _rememberedResourceBaseline = snapshot;
        return snapshot;
    }

    public async Task<ResourceProbeResult> RunResourceProbe(ResourceProbeOptions? options = null)
    {
        return await GetResourceProbe().RunAsync(options);
    }

    /// <summary>
    /// Compare a saved baseline to the current page. Pass the snapshot from
    /// <see cref="CheckResourceSnapshot"/> or omit to use <see cref="RememberedResourceBaseline"/>.
    /// </summary>
    public async Task<ResourceProbeResult> CompareResourceUsage(
        ResourceSnapshot? baseline = null,
        ResourceProbeOptions? options = null)
    {
        baseline ??= _rememberedResourceBaseline;
        if (baseline == null)
        {
            throw new InvalidOperationException(
                "No resource baseline. Capture one before your actions: " +
                "var baseline = await CheckResourceSnapshot(); … your steps … await CompareResourceUsage(baseline). " +
                "Or call CheckResourceSnapshot(rememberBaseline: true) then CompareResourceUsage() with no arguments.");
        }

        return await GetResourceProbe().CompareAsync(baseline, options);
    }

    public async Task<ResourceProbeResult> PrintResourceProbeReport(ResourceProbeOptions? options = null)
    {
        var result = await RunResourceProbe(options);
        LogResourceProbeResult(result);
        return result;
    }

    public async Task<ResourceProbeResult> PrintResourceComparisonReport(
        ResourceSnapshot? baseline = null,
        ResourceProbeOptions? options = null)
    {
        var result = await CompareResourceUsage(baseline, options);
        LogResourceProbeResult(result);
        return result;
    }

    private void LogResourceProbeResult(ResourceProbeResult result)
    {
        foreach (var line in result.Format().Split(Environment.NewLine))
        {
            if (line.Contains("[HIGH]") || line.Contains("POSSIBLE LEAK"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM]") || line.Contains("MINOR GROWTH"))
                _logColored(line, "#CCA700");
            else if (line.Contains("CLEAN") || line.Contains("[LOW]"))
                _logColored(line, "#4EC9B0");
            else if (line.StartsWith("===") || line.StartsWith("BASELINE") || line.StartsWith("FINAL") ||
                     line.StartsWith("DELTA") || line.StartsWith("FINDINGS"))
                _logColored(line, "#569CD6");
            else
                _logColored(line, "#CCCCCC");
        }
    }

    public async Task PrintResourceSnapshot()
    {
        var snapshot = await CheckResourceSnapshot();
        foreach (var line in ResourceSnapshotFormatter.Format(snapshot).Split(Environment.NewLine))
        {
            if (line.StartsWith("FLAGS:") || line.StartsWith("  •"))
                _logColored(line, "#CCA700");
            else if (line.StartsWith("==="))
                _logColored(line, "#569CD6");
            else
                _logColored(line, "#CCCCCC");
        }
    }

    public async Task AssertResourceClean(ResourceProbeOptions? options = null, Severity? maxSeverity = null)
    {
        options ??= new ResourceProbeOptions { ReloadBetweenIterations = true, Iterations = 5 };
        var result = await RunResourceProbe(options);
        AssertResourceProbeResult(result, maxSeverity, "reload probe");
    }

    public async Task AssertResourceCleanSince(
        ResourceSnapshot? baseline = null,
        ResourceProbeOptions? options = null,
        Severity? maxSeverity = null)
    {
        var result = await CompareResourceUsage(baseline, options);
        AssertResourceProbeResult(result, maxSeverity, "comparison");
    }

    private void AssertResourceProbeResult(ResourceProbeResult result, Severity? maxSeverity, string kind)
    {
        var limit = maxSeverity ?? Severity.Medium;
        var bad = result.Findings.Where(f => f.Severity >= limit).ToList();

        if (bad.Count == 0)
        {
            Assert.Pass($"No resource leak clues at or above {limit} severity ({kind})");
            return;
        }

        Assert.Fail($"Possible resource leak: {bad.Count} finding(s) at or above {limit} severity ({kind})");
        foreach (var f in bad)
            _logColored($"    [{f.Severity.ToString().ToUpper()}] {f.Title}: {f.Description}", "#F44747");
    }

    #endregion

    #region HTML Validation (html-validate)

    private HtmlValidateChecker GetHtmlValidateChecker() => new HtmlValidateChecker(ActiveTab.WebView);

    public async Task<HtmlValidateResult> CheckHtml()
    {
        using var linked = LinkCheckerCancellation();
        return await GetHtmlValidateChecker().RunAsync(linked.Token);
    }

    public async Task<HtmlValidateResult> PrintHtmlReport(bool includeDetails = true)
    {
        _logColored("HTML validation powered by html-validate", "#888888");

        var result = await GetHtmlValidateChecker().RunAsync();
        var report = result.Format(includeDetails);

        var lines = report.Split(Environment.NewLine);
        foreach (var line in lines)
        {
            if (line.Contains("[ERROR]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[WARN]"))
                _logColored(line, "#CCA700");
            else if (line.StartsWith("===") || line.StartsWith("ASSESSMENT"))
            {
                if (line.Contains("error(s) found"))
                    _logColored(line, "#F44747");
                else if (line.Contains("warning(s)"))
                    _logColored(line, "#CCA700");
                else
                    _logColored(line, "#4EC9B0");
            }
            else if (line.StartsWith("RESULTS") || line.StartsWith("---"))
                _logColored(line, "#569CD6");
            else if (line.Contains("No HTML validation issues"))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertHtmlValid(string? message = null)
    {
        _logColored("HTML validation powered by html-validate", "#888888");

        var result = await GetHtmlValidateChecker().RunAsync();
        var desc = message ?? "HTML markup should be valid";

        if (result.IsValid)
        {
            Assert.Pass($"{desc} ({result.TotalCount} warnings, 0 errors)");
        }
        else
        {
            Assert.Fail($"{desc}: {result.ErrorCount} error(s), {result.WarningCount} warning(s)");
            foreach (var msg in result.GetErrors().Take(10))
            {
                _logColored($"    line {msg.Line}:{msg.Column} {msg.Message} ({msg.RuleId})", "#F44747");
            }
            if (result.ErrorCount > 10)
                _logColored($"    ... and {result.ErrorCount - 10} more error(s)", "#F44747");
        }
    }

    #endregion

    #region Link Checking

    public async Task<LinkChecking.LinkCheckResult> CheckLinks(string scope = "anchors", bool external = true,
        int timeoutMs = 5000, int concurrency = 10, int delayMs = 100)
    {
        var checker = new LinkChecking.LinkChecker(this);
        return await checker.RunAsync(scope, external, timeoutMs, concurrency, delayMs);
    }

    public async Task<LinkChecking.LinkCheckResult> PrintLinkCheckReport(string scope = "anchors",
        bool external = true, int timeoutMs = 5000, int concurrency = 10, int delayMs = 100, bool includeDetails = true)
    {
        var checker = new LinkChecking.LinkChecker(this);
        var result = await checker.RunAsync(scope, external, timeoutMs, concurrency, delayMs);
        var report = result.Format(includeDetails);

        var lines = report.Split(Environment.NewLine);
        foreach (var line in lines)
        {
            if (line.Contains("BROKEN") || line.Contains("[BROKEN]") || line.Contains("[TIMEOUT]") || line.Contains("[ERROR]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[REDIRECT]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[SKIPPED]"))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("===") || line.StartsWith("ASSESSMENT"))
            {
                if (line.Contains("broken") && !line.Contains("No broken"))
                    _logColored(line, "#F44747");
                else
                    _logColored(line, "#4EC9B0");
            }
            else if (line.StartsWith("---"))
                _logColored(line, "#569CD6");
            else if (line.Contains("All links are valid") || line.Contains("No broken"))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertLinksValid(string scope = "anchors", bool external = true,
        int timeoutMs = 5000, int concurrency = 10, int delayMs = 100, string? message = null)
    {
        var checker = new LinkChecking.LinkChecker(this);
        var result = await checker.RunAsync(scope, external, timeoutMs, concurrency, delayMs);
        var desc = message ?? "All links should be valid";

        if (result.BrokenCount == 0)
        {
            Assert.Pass($"{desc} ({result.CheckedCount} links checked)");
        }
        else
        {
            Assert.Fail($"{desc}: {result.BrokenCount} broken link(s) found");
            foreach (var link in result.Broken)
            {
                var status = link.StatusCode.HasValue ? $"{link.StatusCode}" : link.Status.ToString();
                _logColored($"    [{status}] {link.Url}", "#F44747");
            }
        }
    }

    #endregion

    #region Structured Text Extraction

    private TextExtraction.StructuredTextExtractor GetStructuredTextExtractor() =>
        new TextExtraction.StructuredTextExtractor(ActiveTab.WebView);

    public async Task<TextExtraction.StructuredTextResult> GetStructuredText()
    {
        using var linked = LinkCheckerCancellation();
        return await GetStructuredTextExtractor().RunAsync(linked.Token);
    }

    public async Task<TextExtraction.StructuredTextResult> PrintStructuredText()
    {
        var result = await GetStructuredTextExtractor().RunAsync();
        var report = result.Format();

        var lines = report.Split(Environment.NewLine);
        foreach (var line in lines)
        {
            if (line.StartsWith("==="))
                _logColored(line, "#4EC9B0");
            else if (line.StartsWith("HEADINGS") || line.StartsWith("PARAGRAPHS") || line.StartsWith("LINK TEXTS") ||
                     line.StartsWith("BUTTON LABELS") || line.StartsWith("FORM LABELS") || line.StartsWith("IMAGES"))
                _logColored(line, "#569CD6");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    #endregion

    #region GUI Consistency

    private Consistency.ConsistencyChecker GetConsistencyChecker() =>
        new Consistency.ConsistencyChecker(ActiveTab.WebView);

    public async Task<Consistency.ConsistencyResult> CheckConsistency()
    {
        using var linked = LinkCheckerCancellation();
        return await GetConsistencyChecker().RunAsync(linked.Token);
    }

    public async Task<Consistency.ConsistencyResult> PrintConsistencyReport(bool includeDetails = true)
    {
        var result = await GetConsistencyChecker().RunAsync();
        var report = result.Format(includeDetails);

        var lines = report.Split(Environment.NewLine);
        foreach (var line in lines)
        {
            if (line.Contains("[WARNING]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[INFO]"))
                _logColored(line, "#888888");
            else if (line.StartsWith("===") || line.StartsWith("ASSESSMENT"))
            {
                if (line.Contains("warning"))
                    _logColored(line, "#CCA700");
                else
                    _logColored(line, "#4EC9B0");
            }
            else if (line.StartsWith("OVERVIEW") || line.StartsWith("WARNINGS") || line.StartsWith("---"))
                _logColored(line, "#569CD6");
            else if (line.Contains("No consistency issues"))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertConsistent(string? message = null)
    {
        var result = await GetConsistencyChecker().RunAsync();
        var desc = message ?? "GUI should be visually consistent";

        if (result.WarningCount == 0)
        {
            Assert.Pass($"{desc} (all metrics within thresholds)");
        }
        else
        {
            Assert.Fail($"{desc}: {result.WarningCount} consistency warning(s)");
            foreach (var f in result.Findings.Where(f => f.IsWarning))
            {
                _logColored($"    [WARNING] {f.Category}: {f.Description}", "#CCA700");
                foreach (var v in f.Values)
                    _logColored($"      • {v}", "#CCA700");
            }
        }
    }

    #endregion

    #region Backward Compatibility

    private CompatibilityChecker GetCompatibilityChecker() => new CompatibilityChecker(ActiveTab.WebView);

    public async Task<CompatibilityResult> CheckCompatibility(int? minIos = null, int? minAndroid = null)
    {
        using var linked = LinkCheckerCancellation();
        var targets = CompatibilityChecker.BuildTargets(minIos, minAndroid);
        return await GetCompatibilityChecker().RunAsync(targets, linked.Token);
    }

    public async Task<CompatibilityResult> PrintCompatibilityReport(
        bool includeDetails = true, int? minIos = null, int? minAndroid = null)
    {
        _logColored("Backward compatibility scan — analyzing JavaScript for modern features", "#888888");

        var targets = CompatibilityChecker.BuildTargets(minIos, minAndroid);
        var result = await GetCompatibilityChecker().RunAsync(targets);
        var report = result.Format(includeDetails);

        var lines = report.Split(Environment.NewLine);
        foreach (var line in lines)
        {
            if (line.Contains("[CRITICAL") || line.Contains("SYNTAX]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[HIGH") || line.Contains("won't work"))
                _logColored(line, "#F44747");
            else if (line.Contains("[MEDIUM") || line.Contains("moderate risk"))
                _logColored(line, "#CCA700");
            else if (line.Contains("[LOW") || line.Contains("API]"))
                _logColored(line, "#569CD6");
            else if (line.Contains("COMPATIBLE"))
                _logColored(line, "#4EC9B0");
            else if (line.StartsWith("===") || line.StartsWith("ASSESSMENT") || line.StartsWith("RECOMMENDATION"))
            {
                if (line.Contains("risk") || line.Contains("won't work"))
                    _logColored(line, "#F44747");
                else
                    _logColored(line, "#4EC9B0");
            }
            else if (line.StartsWith("MODERN FEATURES") || line.StartsWith("TARGET BROWSER") || line.StartsWith("---"))
                _logColored(line, "#569CD6");
            else if (line.Contains("No modern JavaScript features"))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertCompatible(
        int? minIos = null, int? minAndroid = null, string? message = null)
    {
        _logColored("Backward compatibility scan — analyzing JavaScript for modern features", "#888888");
        var targets = CompatibilityChecker.BuildTargets(minIos, minAndroid);
        var result = await GetCompatibilityChecker().RunAsync(targets);
        var desc = message ?? "No backward compatibility issues for target browsers";

        if (result.IsCompatible)
        {
            var targetNames = string.Join(", ", result.Targets.Select(t => t.Name));
            Assert.Pass($"{desc} ({result.Features.Count} feature(s) checked against {targetNames})");
        }
        else
        {
            var atRisk = result.Targets.Where(t => t.UnsupportedFeatures.Count > 0).ToList();
            var totalIssues = atRisk.Sum(t => t.UnsupportedFeatures.Count);
            Assert.Fail($"{desc}: {totalIssues} incompatible feature(s) found");

            foreach (var target in atRisk.OrderByDescending(t => t.RiskLevel))
            {
                var riskLabel = target.RiskLevel.ToString().ToUpper();
                _logColored($"    [{riskLabel}] {target.Name}: {target.UnsupportedFeatures.Count} unsupported feature(s)", "#F44747");
                foreach (var f in target.UnsupportedFeatures.Take(5))
                {
                    var catLabel = f.Category == FeatureCategory.Syntax ? "SYNTAX" : "API";
                    _logColored($"      [{catLabel}] {f.Name} (requires {target.Engine} {GetRequiredVersion(f, target.Engine)}+)", "#CCA700");
                }
                if (target.UnsupportedFeatures.Count > 5)
                    _logColored($"      ... and {target.UnsupportedFeatures.Count - 5} more", "#CCA700");
            }
        }
    }

    private static string GetRequiredVersion(DetectedFeature feature, string engine) =>
        engine.ToLowerInvariant() switch
        {
            "chrome" => feature.ChromeMin,
            "safari" => feature.SafariMin,
            "firefox" => feature.FirefoxMin,
            _ => "?"
        };

    #endregion

    #region Robustness (gremlins.js)

    private MonkeyTester GetMonkeyTester() => new MonkeyTester(ActiveTab.WebView);

    public async Task<MonkeyTestResult> RunMonkeyTest(MonkeyTestOptions? options = null)
    {
        var result = await RunMonkeyTestCore(options);
        await AssertLawsAfterStressAsync("monkey");
        return result;
    }

    public async Task<MonkeyTestResult> RunMonkeyTest(
        int actions = 500, int delay = 20, int? seed = null)
    {
        var result = await RunMonkeyTestCore(new MonkeyTestOptions
        {
            Actions = actions,
            Delay = delay,
            Seed = seed
        });
        await AssertLawsAfterStressAsync("monkey");
        return result;
    }

    private async Task<MonkeyTestResult> RunMonkeyTestCore(MonkeyTestOptions? options)
    {
        var netIdsBefore = new HashSet<int>(Network.FindErrors().Select(e => e.Id));
        var consoleIdsBefore = new HashSet<int>(GetConsoleErrors().Select(e => e.Id));
        using var linked = LinkCheckerCancellation();
        var raw = await GetMonkeyTester().RunAsync(options, linked.Token);
        return EnrichMonkeyResultWithCapturedErrors(raw, netIdsBefore, consoleIdsBefore);
    }

    private MonkeyTestResult EnrichMonkeyResultWithCapturedErrors(
        MonkeyTestResult raw,
        HashSet<int> netIdsBefore,
        HashSet<int> consoleIdsBefore)
    {
        var errors = new List<MonkeyTestError>(raw.Errors);
        foreach (var ne in Network.FindErrors().Where(e => !netIdsBefore.Contains(e.Id)))
        {
            errors.Add(new MonkeyTestError
            {
                Type = ne.StatusCode >= 500 ? "http-5xx" : "http-error",
                Message = $"HTTP {ne.StatusCode} {ne.ReasonPhrase}: {ne.Url}",
                Source = ne.Method
            });
        }

        foreach (var ce in GetConsoleErrors().Where(e => !consoleIdsBefore.Contains(e.Id)))
        {
            errors.Add(new MonkeyTestError
            {
                Type = "console",
                Message = ce.Message,
                Source = string.IsNullOrEmpty(ce.Source) ? null : ce.Source,
                Line = ce.Line > 0 ? ce.Line : null
            });
        }

        return new MonkeyTestResult
        {
            StartUrl = raw.StartUrl,
            EndUrl = raw.EndUrl,
            Navigated = raw.Navigated,
            Timestamp = raw.Timestamp,
            DurationSeconds = raw.DurationSeconds,
            ActionsPerformed = raw.ActionsPerformed,
            Seed = raw.Seed,
            Options = raw.Options,
            Errors = errors,
            NavigationAttempts = raw.NavigationAttempts,
            FpsDrops = raw.FpsDrops,
            LowestFps = raw.LowestFps,
            StoppedEarly = raw.StoppedEarly
        };
    }

    public async Task<MonkeyTestResult> PrintMonkeyTestReport(MonkeyTestOptions? options = null)
    {
        _logColored("Monkey testing powered by gremlins.js", "#888888");

        options ??= new MonkeyTestOptions();
        _logColored($"Running {options.Actions} random actions at {options.Delay}ms intervals (~{options.EstimatedDuration:F0}s)...", "#CCCCCC");

        var result = await RunMonkeyTestCore(options);
        await AssertLawsAfterStressAsync("monkey");
        var report = result.Format(includeDetails: true);

        var lines = report.Split(Environment.NewLine);
        foreach (var line in lines)
        {
            if (line.Contains("[ERROR]") || line.Contains("[GREMLIN]") || line.Contains("[HORDE]") || line.Contains("[SETUP]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[UNHANDLEDREJECTION]"))
                _logColored(line, "#CCA700");
            else if (line.StartsWith("WARNING"))
                _logColored(line, "#CCA700");
            else if (line.Contains("SURVIVED"))
                _logColored(line, "#4EC9B0");
            else if (line.Contains("ERRORS FOUND"))
                _logColored(line, "#F44747");
            else if (line.StartsWith("===") || line.StartsWith("RESULT"))
                _logColored(line, "#569CD6");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertRobust(MonkeyTestOptions? options = null, string? message = null)
    {
        _logColored("Monkey testing powered by gremlins.js", "#888888");

        options ??= new MonkeyTestOptions();
        _logColored($"Running {options.Actions} random actions...", "#CCCCCC");

        var result = await RunMonkeyTestCore(options);
        await AssertLawsAfterStressAsync("monkey");
        var desc = message ?? "Page should survive monkey testing";

        if (result.Survived)
        {
            Assert.Pass($"{desc} ({result.ActionsPerformed} actions, {result.DurationSeconds:F1}s, seed {result.Seed})");
        }
        else
        {
            var unique = result.UniqueErrors;
            Assert.Fail($"{desc}: {result.ErrorCount} error(s) in {result.ActionsPerformed} actions (seed {result.Seed} to reproduce)");
            foreach (var err in unique.Take(5))
            {
                var truncMsg = err.Length > 120 ? err[..117] + "..." : err;
                _logColored($"    {truncMsg}", "#F44747");
            }
            if (unique.Count > 5)
                _logColored($"    ... and {unique.Count - 5} more unique error(s)", "#F44747");
        }
    }

    // --- Monkey Trowser (smart robustness) ---

    private SmartTester GetSmartTester() => new SmartTester(this, _logColored);

    public async Task<SmartTestResult> RunSmartMonkey(SmartTestOptions options)
    {
        var result = await GetSmartTester().RunAsync(options);
        await AssertLawsAfterStressAsync("monkey-trowser");
        return result;
    }

    public async Task<SmartTestResult> RunSmartMonkey(
        int maxActions = 100, bool followLinks = true, int maxPages = 10)
    {
        var result = await GetSmartTester().RunAsync(new SmartTestOptions
        {
            MaxActionsPerPage = maxActions,
            FollowLinks = followLinks,
            MaxPages = maxPages
        });
        await AssertLawsAfterStressAsync("monkey-trowser");
        return result;
    }

    public async Task<SmartTestResult> PrintSmartMonkeyReport(
        int maxActions = 100, bool followLinks = true, int maxPages = 10)
    {
        var result = await RunSmartMonkey(maxActions, followLinks, maxPages);
        PrintSmartMonkeyReport(result);
        return result;
    }

    public void PrintSmartMonkeyReport(SmartTestResult result)
    {
        var report = result.Format(includeDetails: true);

        var lines = report.Split(Environment.NewLine);
        foreach (var line in lines)
        {
            if (line.Contains("[JS-ERROR]") || line.Contains("[HTTP-5XX]") || line.Contains("[NAVIGATION]")
                || line.Contains("[DEAD-LINK]") || line.Contains("[PAGE-ERROR]"))
                _logColored(line, "#F44747");
            else if (line.Contains("[NETWORK-ERROR]"))
                _logColored(line, "#CCA700");
            else if (line.Contains("ALL CLEAR"))
                _logColored(line, "#4EC9B0");
            else if (line.Contains("ISSUE(S) FOUND"))
                _logColored(line, "#F44747");
            else if (line.StartsWith("===") || line.StartsWith("RESULT"))
                _logColored(line, "#569CD6");
            else if (line.StartsWith("---"))
                _logColored(line, "#569CD6");
            else
                _logColored(line, "#CCCCCC");
        }
    }

    public async Task AssertSmartMonkey(SmartTestOptions options, string? message = null)
    {
        var result = await RunSmartMonkey(options);
        AssertSmartMonkey(result, message);
    }

    public async Task AssertSmartMonkey(
        int maxActions = 100, bool followLinks = true, int maxPages = 10, string? message = null)
    {
        var result = await RunSmartMonkey(maxActions, followLinks, maxPages);
        AssertSmartMonkey(result, message);
    }

    public void AssertSmartMonkey(SmartTestResult result, string? message = null)
    {
        var desc = message ?? "Page should pass smart robustness testing";

        if (result.Passed)
        {
            Assert.Pass($"{desc} ({result.ElementsTested} elements across {result.PagesVisited} page(s))");
        }
        else
        {
            Assert.Fail($"{desc}: {result.IssueCount} issue(s) found across {result.PagesVisited} page(s)");
            foreach (var issue in result.Issues.Take(10))
            {
                var truncIssue = issue.Issue.Length > 100 ? issue.Issue[..97] + "..." : issue.Issue;
                _logColored($"    [{issue.IssueType.ToUpper()}] {issue.Element} ({issue.Action}): {truncIssue}", "#F44747");
            }
            if (result.Issues.Count > 10)
                _logColored($"    ... and {result.Issues.Count - 10} more issue(s)", "#F44747");
        }
    }

    // --- TrowserInterrupter (fault injection) ---

    private InterrupterTester GetInterrupterTester() => new InterrupterTester(this, _logColored);

    public async Task<InterrupterResult> RunInterrupterTest(InterrupterOptions? options = null)
    {
        return await GetInterrupterTester().RunAsync(options);
    }

    /// <summary>Output an interrupter report with per-line color coding.</summary>
    public void PrintInterrupterReport(InterrupterResult result, bool includeDetails = true)
    {
        foreach (var line in result.Format(includeDetails).Split(Environment.NewLine))
        {
            var trimmed = line.TrimStart();

            if (string.IsNullOrWhiteSpace(line))
                _log("");
            else if (trimmed.StartsWith("===") || trimmed.StartsWith("---"))
                _logColored(line, "#569CD6");
            else if (trimmed.StartsWith("RESULT:") && trimmed.Contains("FAILED"))
                _logColored(line, "#F44747");
            else if (trimmed.StartsWith("RESULT:"))
                _logColored(line, "#4EC9B0");
            else if (trimmed.StartsWith("FAIL:"))
                _logColored(line, "#F44747");
            else if (trimmed.StartsWith("WARN:"))
                _logColored(line, "#CCA700");
            else if (trimmed.StartsWith("OK:") || trimmed.StartsWith("OK "))
                _logColored(line, "#4EC9B0");
            else if (trimmed.StartsWith("[") && trimmed.Contains("(warning)"))
                _logColored(line, "#CCA700");
            else if (trimmed.StartsWith("["))
                _logColored(line, "#F44747");
            else if (trimmed.StartsWith("Fault:"))
                _logColored(line, "#888888");
            else
                _logColored(line, "#CCCCCC");
        }
    }

    // --- Request Fuzzer ---

    private RequestFuzzer GetRequestFuzzer() => new RequestFuzzer(this, _logColored);

    public async Task<FuzzerResult> RunFuzzerTest(FuzzerOptions options)
    {
        return await GetRequestFuzzer().RunAsync(options);
    }

    private CsrfChecker GetCsrfChecker() => new CsrfChecker(this, _logColored);

    public async Task<CsrfResult> RunCsrfTest(int maxEndpoints = 5, int maxUnprotected = 10, bool includeGet = false,
        string? hostFilter = null, bool includeRefererBypass = true, int maxRefererEndpoints = 5,
        bool includeJsonApiProbing = true, int maxJsonApiProbes = 10,
        bool includeCustomHeaderProbes = true, int maxCustomHeaderProbes = 5,
        bool includeSameSiteAnalysis = true,
        bool includeCrossSiteProof = false, int maxCrossSiteProbes = 3, string attackerSite = "cross-site")
    {
        return await GetCsrfChecker().RunAsync(maxEndpoints, maxUnprotected, includeGet, hostFilter,
            includeRefererBypass, maxRefererEndpoints, includeJsonApiProbing, maxJsonApiProbes,
            includeCustomHeaderProbes, maxCustomHeaderProbes, includeSameSiteAnalysis,
            includeCrossSiteProof, maxCrossSiteProbes, attackerSite);
    }

    public async Task<ServiceWorkerAuditor.ServiceWorkerAuditResult> RunServiceWorkerAuditAsync(
        bool fetchScripts = true,
        int maxScriptBytes = 256_000)
    {
        return await new ServiceWorkerAuditor(this).RunAsync(fetchScripts, maxScriptBytes);
    }

    public async Task<PathTraversalResult> RunPathTraversalScan(PathTraversalOptions options)
    {
        return await new PathTraversalChecker(this, _logColored).RunAsync(options);
    }

    public async Task<WafBypassResult> RunWafBypassScan(WafBypassOptions options)
    {
        return await WafBypassProbe.RunAsync(this, options, _logColored, ScriptCancellation);
    }

    /// <summary>
    /// WAF bypass probe with simple parameters (see <see cref="WafBypassOptions"/> for full control).
    /// Sends a canonical attack payload, detects WAF block vs baseline, then tests bypass transforms.
    /// </summary>
    public Task<WafBypassResult> RunWafBypassScan(
        string? url = null,
        string? paramName = null,
        string method = "GET",
        string category = "sqli",
        string? probePayload = null,
        string baselineValue = "1",
        IReadOnlyList<string>? techniques = null,
        int timeoutMs = 15000,
        bool useBackendFetch = false,
        bool includeBrowserCookies = true,
        string? body = null,
        Dictionary<string, string>? headers = null) =>
        RunWafBypassScan(new WafBypassOptions
        {
            Url = url,
            ParamName = paramName,
            Method = method,
            Category = category,
            ProbePayload = probePayload,
            BaselineValue = baselineValue,
            Techniques = techniques?.ToList(),
            TimeoutMs = timeoutMs,
            UseBackendFetch = useBackendFetch,
            IncludeBrowserCookies = includeBrowserCookies,
            Body = body,
            Headers = headers,
        });

    public async Task<WafBypassResult> PrintWafBypassReport(
        bool includeDetails = true,
        string? url = null,
        string? paramName = null,
        string method = "GET",
        string category = "sqli",
        string? probePayload = null,
        string baselineValue = "1",
        IReadOnlyList<string>? techniques = null,
        int timeoutMs = 15000,
        bool useBackendFetch = false,
        bool includeBrowserCookies = true,
        string? body = null,
        Dictionary<string, string>? headers = null)
    {
        var result = await RunWafBypassScan(url, paramName, method, category, probePayload, baselineValue,
            techniques, timeoutMs, useBackendFetch, includeBrowserCookies, body, headers);

        foreach (var line in result.Format(includeDetails).Split(Environment.NewLine))
        {
            if (line.Contains("[bypassed]", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("  + ", StringComparison.Ordinal))
                _logColored(line, "#F44747");
            else if (line.Contains("[blocked]", StringComparison.OrdinalIgnoreCase))
                _logColored(line, "#888888");
            else if (line.Contains("WAF block detected: yes", StringComparison.OrdinalIgnoreCase)
                     || line.Contains("Usable bypasses", StringComparison.OrdinalIgnoreCase))
                _logColored(line, "#CCA700");
            else if (line.StartsWith("===") || line.StartsWith("---"))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    /// <summary>
    /// Defender regression: pass when a WAF block was detected and no bypass techniques succeeded.
    /// </summary>
    public async Task AssertWafBypassEffective(
        string? url = null,
        string? paramName = null,
        string category = "sqli",
        string? probePayload = null,
        IReadOnlyList<string>? techniques = null,
        int timeoutMs = 15000,
        string? message = null)
    {
        var result = await RunWafBypassScan(url, paramName, category: category, probePayload: probePayload,
            techniques: techniques, timeoutMs: timeoutMs);
        var desc = message ?? "WAF should block the canonical probe and resist bypass transforms";

        if (!result.WafBlockDetected)
        {
            Assert.Pass($"{desc} (inconclusive: no clear WAF block vs baseline on this injection point)");
            return;
        }

        if (result.UsableBypasses.Count == 0)
            Assert.Pass($"{desc} ({result.Techniques.Count} technique(s) tested)");
        else
        {
            Assert.Fail($"{desc}: {result.UsableBypasses.Count} bypass(es) — {string.Join(", ", result.UsableBypasses)}");
            foreach (var row in result.Techniques.Where(t => t.Verdict == "bypassed"))
                _logColored($"    {row.Technique}: HTTP {row.Status} — {row.Detail}", "#F44747");
        }
    }

    public async Task<SsrfResult> RunSsrfScan(SsrfOptions options)
    {
        return await new SsrfChecker(this, _logColored).RunAsync(options);
    }

    /// <summary>
    /// Lightweight SQLi scan at §marker§ / {{marker}} injection points (unified finding contract).
    /// </summary>
    public async Task<HttpSecurityProbes.SqliScanResult> RunSqliScan(
        string urlTemplate,
        string method = "GET",
        Dictionary<string, string>? headers = null,
        string? bodyTemplate = null,
        string baselineValue = "1",
        IReadOnlyList<string>? payloads = null,
        bool includeTimeBased = false,
        int timeoutMs = 15000,
        bool useBackendFetch = false,
        bool includeBrowserCookies = false,
        bool includeOrmClosurePayloads = false,
        string? depth = null,
        CancellationToken ct = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, ScriptCancellation, OperationCancellation);
        return await HttpSecurityProbes.RunSqliScanAsync(
            this, urlTemplate, method, headers, bodyTemplate, baselineValue, payloads,
            includeTimeBased, timeoutMs, maxBodyChars: 131072, useBackendFetch, includeBrowserCookies,
            includeOrmClosurePayloads, linked.Token, depth);
    }

    public async Task<SsrfOrchestrator.OrchestratorResult> RunSsrfOrchestrator(
        SsrfOrchestrator.OrchestratorOptions options,
        ChainPatternCatalog? chainCatalog = null,
        CancellationToken ct = default)
    {
        return await new SsrfOrchestrator(this, _logColored).RunAsync(options, chainCatalog, ct);
    }

    public async Task<OpenRedirectResult> RunOpenRedirectScan(
        OpenRedirectOptions options, CancellationToken ct = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, ScriptCancellation, OperationCancellation);
        return await new OpenRedirectChecker(this, _logColored).RunAsync(options, linked.Token);
    }

    public async Task<CacheDeceptionResult> RunCacheDeceptionScan(
        CacheDeceptionOptions options, CancellationToken ct = default)
    {
        return await new CacheDeceptionScanner(this, _logColored).RunAsync(options, ct);
    }

    public async Task<CachePoisonResult> RunCachePoisonScan(
        CachePoisonOptions options, CancellationToken ct = default)
    {
        return await new CachePoisonScanner(this, _logColored).RunAsync(options, ct);
    }

    public Task<CacheMapResult> RunCacheMapScan(CacheMapOptions? options = null, CancellationToken ct = default) =>
        CheckCacheMap(options, ct);

    public async Task<CacheMapResult> CheckCacheMap(CacheMapOptions? options = null, CancellationToken ct = default)
    {
        return await new CacheMapScanner(this, _logColored).RunAsync(options ?? new CacheMapOptions(), ct);
    }

    public async Task<CacheMapResult> PrintCacheMapReport(CacheMapOptions? options = null, bool includeDetails = true)
    {
        var result = await CheckCacheMap(options);
        PrintColoredReport(result.Format(includeDetails));
        return result;
    }

    public async Task AssertCacheMapClean(CacheMapOptions? options = null, string? message = null)
    {
        var result = await CheckCacheMap(options);
        var desc = message ?? "No confirmed unkeyed-reflected or cacheable-error cache-map findings";
        if (result.HasConfirmedIssue)
        {
            Assert.Fail($"{desc}: {string.Join("; ", result.Findings.Where(f => f.Confidence == "confirmed").Select(f => f.Title))}");
            return;
        }

        Assert.Pass($"{desc} (detected={result.Identify.Detected}, status={result.Identify.DocumentStatus})");
    }

    public Task<CachePollutionResult> RunCachePollutionScan(CachePollutionOptions? options = null, CancellationToken ct = default) =>
        CheckCachePollution(options, ct);

    public async Task<CachePollutionResult> CheckCachePollution(CachePollutionOptions? options = null, CancellationToken ct = default)
    {
        return await new CachePollutionScanner(this, _logColored).RunAsync(options ?? new CachePollutionOptions(), ct);
    }

    public async Task<CachePollutionResult> PrintCachePollutionReport(CachePollutionOptions? options = null, bool includeDetails = true)
    {
        var result = await CheckCachePollution(options);
        PrintColoredReport(result.Format(includeDetails));
        return result;
    }

    public async Task AssertCachePollutionClean(CachePollutionOptions? options = null, string? message = null)
    {
        var result = await CheckCachePollution(options);
        var desc = message ?? "No confirmed live-key cache error stored";
        if (result.HasConfirmedIssue)
        {
            Assert.Fail($"{desc}: {result.Message}");
            return;
        }

        Assert.Pass($"{desc} ({result.Message})");
    }

    private void PrintColoredReport(string report)
    {
        foreach (var line in report.Split(Environment.NewLine))
        {
            if (line.Contains("FLAG", StringComparison.Ordinal) || line.Contains("[high", StringComparison.OrdinalIgnoreCase)
                || line.Contains("cache-error-stored", StringComparison.Ordinal))
                _logColored(line, "#F44747");
            else if (line.StartsWith("WARNING", StringComparison.Ordinal) || line.StartsWith("NEXT", StringComparison.Ordinal))
                _logColored(line, "#CCA700");
            else if (line.StartsWith("===") || line.StartsWith("FINDINGS") || line.StartsWith("PHASE") || line.StartsWith("CACHE"))
                _logColored(line, "#569CD6");
            else
                _logColored(line, "#CCCCCC");
        }
    }

    public async Task<Trowser.Security.WebSocket.WebSocketFuzzResult> RunWebSocketFuzz(
        Trowser.Security.WebSocket.WebSocketFuzzOptions options, CancellationToken ct = default)
    {
        return await new Trowser.Security.WebSocket.WebSocketFuzzer(this, _logColored).RunAsync(options, ct);
    }

    public async Task<ParserProbe.ParserProbeResult> RunParserProbe(ParserProbe.ParserProbeOptions options, CancellationToken ct = default)
    {
        return await new ParserProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<CmdCanaryProbe.CmdCanaryResult> RunCmdCanary(CmdCanaryProbe.CmdCanaryOptions options, CancellationToken ct = default)
    {
        return await new CmdCanaryProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<NosqlScanProbe.NosqlScanResult> RunNosqlScan(NosqlScanProbe.NosqlScanOptions options, CancellationToken ct = default)
    {
        return await new NosqlScanProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<LdapScanProbe.LdapScanResult> RunLdapScan(LdapScanProbe.LdapScanOptions options, CancellationToken ct = default)
    {
        return await new LdapScanProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<SqliLoginSweep.SqliLoginSweepResult> RunSqliLoginSweep(SqliLoginSweep.SqliLoginSweepOptions options, CancellationToken ct = default)
    {
        return await new SqliLoginSweep(this, _logColored).RunAsync(options, ct);
    }

    public async Task<SstiScanRunner.SstiScanBatchResult> RunSstiScan(SstiScanRunner.SstiScanOptions options, CancellationToken ct = default)
    {
        return await new SstiScanRunner(this, _logColored).RunAsync(options, ct);
    }

    public async Task<SstiPolyglotScanProbe.SstiPolyglotScanResult> RunSstiPolyglotScan(
        SstiPolyglotScanProbe.SstiPolyglotScanOptions options, CancellationToken ct = default)
    {
        return await new SstiPolyglotScanProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<SstiStoredScanProbe.SstiStoredScanResult> RunSstiStoredScan(
        SstiStoredScanProbe.SstiStoredScanOptions options, CancellationToken ct = default)
    {
        return await new SstiStoredScanProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<PrototypePollutionScanProbe.PrototypePollutionScanResult> RunPrototypePollutionScan(
        PrototypePollutionScanProbe.PrototypePollutionScanOptions options, CancellationToken ct = default)
    {
        return await new PrototypePollutionScanProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<CstiScanRunner.CstiScanBatchResult> RunCstiScan(CstiScanRunner.CstiScanOptions options, CancellationToken ct = default)
    {
        return await new CstiScanRunner(this, _logColored).RunAsync(options, ct);
    }

    public async Task<XssScanRunner.XssScanBatchResult> RunXssScan(XssScanRunner.XssScanOptions options, CancellationToken ct = default)
    {
        return await new XssScanRunner(this, _logColored).RunAsync(options, ct);
    }

    public async Task<XssStoredScanProbe.XssStoredScanResult> RunXssStoredScan(
        XssStoredScanProbe.XssStoredScanOptions options, CancellationToken ct = default)
    {
        return await new XssStoredScanProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<Security.SupplyChain.SupplyChainScanResult> RunSupplyChainScan(
        Security.SupplyChain.SupplyChainScanOptions options, CancellationToken ct = default)
    {
        return await Security.SupplyChain.SupplyChainScanner.RunAsync(this, options, ct);
    }

    public async Task<DeserializationScanProbe.DeserializationScanResult> RunDeserializationScan(
        DeserializationScanProbe.DeserializationScanOptions options, CancellationToken ct = default)
    {
        return await new DeserializationScanProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<FileUploadScanProbe.FileUploadScanResult> RunFileUploadScan(
        FileUploadScanProbe.FileUploadScanOptions options, CancellationToken ct = default)
    {
        return await new FileUploadScanProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<NextJsRscScanProbe.NextJsRscScanResult> RunNextJsRscScan(
        NextJsRscScanProbe.NextJsRscScanOptions options, CancellationToken ct = default)
    {
        return await new NextJsRscScanProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<RaceConditionScanProbe.RaceConditionScanResult> RunRaceConditionScan(
        RaceConditionScanProbe.RaceConditionScanOptions options, CancellationToken ct = default)
    {
        return await new RaceConditionScanProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<RateLimitAuditProbe.RateLimitAuditResult> RunRateLimitAudit(
        RateLimitAuditProbe.RateLimitAuditOptions options, CancellationToken ct = default)
    {
        return await new RateLimitAuditProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<ReDoSScanProbe.ReDoSScanResult> RunReDoSScan(
        ReDoSScanProbe.ReDoSScanOptions options, CancellationToken ct = default)
    {
        return await new ReDoSScanProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<BodySizeLimitProbe.BodySizeLimitResult> RunBodySizeLimitScan(
        BodySizeLimitProbe.BodySizeLimitOptions options, CancellationToken ct = default)
    {
        return await new BodySizeLimitProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<CostlyOperationsProbe.CostlyOperationsResult> RunCostlyOperations(
        CostlyOperationsProbe.CostlyOperationsOptions options, CancellationToken ct = default)
    {
        return await new CostlyOperationsProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<SwaggeringOrchestrator.SwaggeringResult> RunSwaggering(
        SwaggeringOrchestrator.SwaggeringOptions options, CancellationToken ct = default)
    {
        return await new SwaggeringOrchestrator(this, _logColored).RunAsync(options, ct);
    }

    public async Task<CaptchaReplayScanProbe.CaptchaReplayScanResult> RunCaptchaReplayScan(
        CaptchaReplayScanProbe.CaptchaReplayScanOptions options, CancellationToken ct = default)
    {
        return await new CaptchaReplayScanProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<LlmRedTeamScanResult> RunLlmRedTeamScan(
        LlmRedTeamScanOptions options, CancellationToken ct = default)
    {
        return await new LlmRedTeamScanProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<LlmSurfaceSummary> RunLlmEndpointDiscover(CancellationToken ct = default)
    {
        var surface = await LlmEndpointDiscovery.DiscoverAsync(this);
        RedTeamWhisper?.UpdateLlmSurface(surface);
        return surface;
    }

    public async Task<LlmChatInteractResult> RunLlmChatInteract(
        string prompt,
        LlmChatUiTarget? target = null,
        CancellationToken ct = default)
    {
        return await LlmChatInteract.SendPromptAsync(this, prompt, target, ct);
    }

    public async Task<WorkflowSkipScanProbe.WorkflowSkipScanResult> RunWorkflowSkipScan(
        WorkflowSkipScanProbe.WorkflowSkipScanOptions options, CancellationToken ct = default)
    {
        return await new WorkflowSkipScanProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<SessionFixationScanProbe.ScanResult> RunSessionFixationScan(
        SessionFixationScanProbe.ScanOptions options, CancellationToken ct = default)
    {
        return await new SessionFixationScanProbe(this).RunAsync(options, ct);
    }

    public async Task<PasswordResetWeakScanProbe.ScanResult> RunPasswordResetWeakScan(
        PasswordResetWeakScanProbe.ScanOptions options, CancellationToken ct = default)
    {
        return await new PasswordResetWeakScanProbe(this).RunAsync(options, ct);
    }

    public async Task<AccountEnumerationScanProbe.ScanResult> RunAccountEnumerationScan(
        AccountEnumerationScanProbe.ScanOptions options, CancellationToken ct = default)
    {
        return await new AccountEnumerationScanProbe(this).RunAsync(options, ct);
    }

    public async Task<LogoutInvalidationProbe.ProbeResult> RunLogoutInvalidationProbe(
        LogoutInvalidationProbe.ProbeOptions options, CancellationToken ct = default)
    {
        return await new LogoutInvalidationProbe(this).RunAsync(options, ct);
    }

    public async Task<FailOpenScanProbe.ScanResult> RunFailOpenScan(
        FailOpenScanProbe.ScanOptions options, CancellationToken ct = default)
    {
        return await new FailOpenScanProbe(this, _logColored).RunAsync(options, ct);
    }

    /// <summary>
    /// Identify which cookies/headers/token fields actually gate captured requests
    /// by omitting and one-character-tampering each candidate.
    /// </summary>
    public async Task<AuthControlIdentifier.ScanResult> RunAuthControlIdentifier(
        AuthControlIdentifier.ProbeOptions options, CancellationToken ct = default)
    {
        var probe = new AuthControlIdentifier(this, _logColored);
        var result = await probe.RunAsync(options, ct);
        AuthControlIdentifier.LogMarkdownTable(_logColored, result);
        return result;
    }

    /// <summary>
    /// Convenience overload: probe one or more explicit requests.
    /// </summary>
    public async Task<AuthControlIdentifier.ScanResult> RunAuthControlIdentifier(
        IReadOnlyList<EndpointProbeItem> endpoints,
        bool allHeaders = false,
        int timeoutMs = 12_000,
        CancellationToken ct = default)
    {
        return await RunAuthControlIdentifier(new AuthControlIdentifier.ProbeOptions
        {
            Endpoints = endpoints,
            AllHeaders = allHeaders,
            TimeoutMs = timeoutMs
        }, ct);
    }

    public async Task<MissingParameterScanProbe.ScanResult> RunMissingParameterScan(
        MissingParameterScanProbe.ScanOptions options, CancellationToken ct = default)
    {
        return await new MissingParameterScanProbe(this, _logColored).RunAsync(options, ct);
    }

    public async Task<UploadXxeProbe.UploadXxeResult> RunUploadXxeScan(
        UploadXxeProbe.UploadXxeOptions options, CancellationToken ct = default)
    {
        return await UploadXxeProbe.RunAsync(this, options, _logColored, ct);
    }

    public async Task<CstiScanRunner.CstiScanBatchResult> PrintCstiScanReport(
        bool includeDetails = true,
        string? url = null,
        string? paramName = null,
        IReadOnlyList<string>? engines = null,
        IReadOnlyList<string>? sources = null,
        bool escalate = false,
        bool monitorSinks = true,
        int maxCandidates = 10,
        int timeoutMs = 10_000)
    {
        var result = await RunCstiScan(new CstiScanRunner.CstiScanOptions
        {
            Url = url,
            ParamName = paramName,
            Engines = engines?.ToList(),
            Sources = sources?.ToList(),
            Escalate = escalate,
            MonitorSinks = monitorSinks,
            MaxCandidates = maxCandidates,
            TimeoutMs = timeoutMs
        });

        foreach (var line in result.Format(includeDetails).Split(Environment.NewLine))
        {
            if (line.Contains("FINDINGS", StringComparison.OrdinalIgnoreCase) && line.Contains('('))
                _logColored(line, "#F44747");
            else if (line.StartsWith("  [CRITICAL]", StringComparison.OrdinalIgnoreCase)
                     || line.StartsWith("  [HIGH]", StringComparison.OrdinalIgnoreCase))
                _logColored(line, "#F44747");
            else if (line.StartsWith("  [MEDIUM]", StringComparison.OrdinalIgnoreCase))
                _logColored(line, "#CCA700");
            else if (line.StartsWith("===") || line.StartsWith("---"))
                _logColored(line, "#4EC9B0");
            else if (line.StartsWith("NO CSTI", StringComparison.OrdinalIgnoreCase))
                _logColored(line, "#4EC9B0");
            else
                _logColored(line, "#CCCCCC");
        }

        return result;
    }

    public async Task AssertCstiScanClean(
        string minSeverity = "medium",
        string? url = null,
        string? paramName = null,
        IReadOnlyList<string>? engines = null,
        IReadOnlyList<string>? sources = null,
        bool escalate = false,
        bool monitorSinks = true,
        int maxCandidates = 10,
        int timeoutMs = 10_000,
        string? message = null)
    {
        var result = await RunCstiScan(new CstiScanRunner.CstiScanOptions
        {
            Url = url,
            ParamName = paramName,
            Engines = engines?.ToList(),
            Sources = sources?.ToList(),
            Escalate = escalate,
            MonitorSinks = monitorSinks,
            MaxCandidates = maxCandidates,
            TimeoutMs = timeoutMs
        });

        var threshold = minSeverity.ToLowerInvariant() switch
        {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 2
        };

        var flagged = result.Findings.Where(f => SeverityRank(f.Severity) >= threshold).ToList();
        var desc = message ?? $"No CSTI findings at or above {minSeverity} severity";

        if (flagged.Count == 0)
            Assert.Pass($"{desc} ({result.CandidatesProbed} candidate(s) probed)");
        else
        {
            Assert.Fail($"{desc}: {flagged.Count} finding(s) — {string.Join("; ", flagged.Select(f => $"{f.Parameter} ({f.Engine}, {f.Severity})"))}");
            foreach (var f in flagged)
                _logColored($"    {f.Severity}: {f.Parameter} via {f.Source} — {f.BasicExpression} -> {f.EvaluatedToken}", "#F44747");
        }
    }

    private static int SeverityRank(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0
    };

    /// <summary>Output a fuzzer report with per-line color coding.</summary>
    public void PrintFuzzerReport(FuzzerResult result, bool includeDetails = true)
    {
        foreach (var line in result.Format(includeDetails).Split(Environment.NewLine))
        {
            var trimmed = line.TrimStart();

            if (string.IsNullOrWhiteSpace(line))
                _log("");
            else if (trimmed.StartsWith("==="))
                _logColored(line, "#569CD6");
            else if (trimmed.StartsWith("STOPPED EARLY"))
                _logColored(line, "#F44747");
            else if (trimmed.StartsWith("NO FLAGS"))
                _logColored(line, "#4EC9B0");
            else if (trimmed.StartsWith("FLAGGED"))
                _logColored(line, "#CCCC00");
            else if (trimmed.Contains("FLAGGED"))
                _logColored(line, "#CCCC00");
            else if (trimmed.StartsWith("Payload") || trimmed.StartsWith("Body:"))
                _logColored(line, "#888888");
            else
                _logColored(line, "#CCCCCC");
        }
    }

    #endregion
}
