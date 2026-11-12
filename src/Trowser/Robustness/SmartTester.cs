using Trowser;
using Trowser.Automation;

namespace Trowser.Robustness;

/// <summary>
/// Monkey Trowser: an intelligent robustness tester that systematically
/// interacts with every visible interactive element, fuzzes forms with
/// edge-case data, and follows links within scope.
///
/// Unlike gremlins.js which clicks random coordinates, Monkey Trowser uses
/// the page snapshot to understand structure and clicks real elements --
/// buttons, links, checkboxes, inputs, selects. When clicking a link causes
/// navigation within scope, it tests the new page too.
///
/// When no scope is configured, derives a temporary scope from the current page URL
/// (same registrable domain) for the duration of the run.
/// </summary>
public class SmartTester
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    private readonly List<SmartTestIssue> _issues = new();
    private readonly List<SmartTestPageSummary> _pageSummaries = new();
    private readonly HashSet<string> _visitedPages = new(StringComparer.OrdinalIgnoreCase);
    private int _totalElementsTested;
    private int _totalFormsFuzzed;
    private int _maxPages;
    private string _startUrl = "";

    private const int ActionTimeoutMs = 8000;
    private const int ActionDelayMs = 300;

    private static readonly string[] FuzzStrings =
    [
        "",
        new string('A', 500),
        "<script>alert(1)</script>",
        "'; DROP TABLE users;--",
        "test@test.com\"><img src=x onerror=alert(1)>",
        "-1",
        "0",
        "99999999999999999",
        "null",
        "undefined",
        "../../../etc/passwd",
        "\u0000\u0001\u0002",
        "🎉🔥💀",
        "   ",
        "Robert'); DROP TABLE Students;--",
    ];

    public SmartTester(AutomationContext context, Action<string, string> logColored)
    {
        _ctx = context ?? throw new ArgumentNullException(nameof(context));
        _log = logColored;
    }

    public async Task<SmartTestResult> RunAsync(SmartTestOptions? options = null)
    {
        options ??= new SmartTestOptions();
        _maxPages = options.MaxPages;
        var startTime = DateTime.UtcNow;

        NavigationGuard? previousGuard = null;
        var appliedTempScope = false;
        if (!string.IsNullOrWhiteSpace(options.Scope))
        {
            previousGuard = _ctx.NavigationGuard;
            _ctx.NavigationGuard = new NavigationGuard(options.Scope.Trim());
            appliedTempScope = true;
        }

        try
        {
        if (_ctx.NavigationGuard == null || !_ctx.NavigationGuard.IsRestricted)
        {
            var pageUrl = await _ctx.GetCurrentUrl();
            if (!NavigationGuard.TryBuildTemporaryScopeFromPageUrl(pageUrl, out var autoScope))
            {
                throw new InvalidOperationException(
                    "Monkey Trowser could not derive a navigation scope from the current page. " +
                    "Navigate to an http(s) page, pass \"scope\" in the request body, set scope in Settings, " +
                    "use POST /api/settings/scope, or --scope on the command line.");
            }

            previousGuard = _ctx.NavigationGuard;
            _ctx.NavigationGuard = new NavigationGuard(autoScope);
            appliedTempScope = true;
            _log($"Temporary navigation scope (from current page): {autoScope}", "#569CD6");
        }

        _startUrl = await _ctx.GetCurrentUrl();
        _visitedPages.Add(NormalizeUrl(_startUrl));

        _log($"Monkey Trowser starting on: {Truncate(_startUrl, 80)}", "#569CD6");
        await TestPage(_startUrl, options);

        // Return to starting page
        var finalUrl = await SafeGetUrl();
        if (finalUrl != null && NormalizeUrl(finalUrl) != NormalizeUrl(_startUrl))
        {
            _log($"Returning to start page...", "#569CD6");
            try { await _ctx.Navigate(_startUrl); } catch (Exception ex) { TrowserLog.Warn($"Monkey Trowser return navigation failed: {ex.Message}"); }
        }

        var elapsed = (DateTime.UtcNow - startTime).TotalSeconds;

        _log($"Monkey Trowser finished: {_totalElementsTested} elements, {_visitedPages.Count} page(s), {_issues.Count} issue(s), {elapsed:F1}s", "#569CD6");

        return new SmartTestResult
        {
            StartUrl = _startUrl,
            Timestamp = startTime,
            DurationSeconds = elapsed,
            PagesVisited = _visitedPages.Count,
            ElementsTested = _totalElementsTested,
            FormsFuzzed = _totalFormsFuzzed,
            Issues = _issues.ToList(),
            PageSummaries = _pageSummaries.ToList(),
            Options = options
        };
        }
        finally
        {
            if (appliedTempScope)
                _ctx.NavigationGuard = previousGuard;
        }
    }

    #region Page Testing

    private async Task TestPage(string pageUrl, SmartTestOptions options)
    {
        var pageIssuesBefore = _issues.Count;
        var pageElements = 0;
        var pageFuzzed = 0;

        _log($"--- Testing: {Truncate(pageUrl, 70)} ---", "#569CD6");

        List<Dictionary<string, object>> elements;
        try
        {
            elements = await _ctx.GetInteractiveElements();
        }
        catch (Exception ex)
        {
            _issues.Add(new SmartTestIssue
            {
                Page = pageUrl, Element = "(page)", Action = "snapshot",
                Issue = ex.Message, IssueType = "page-error"
            });
            _log($"  Failed to get elements: {Truncate(ex.Message, 80)}", "#F44747");
            return;
        }

        var visibleElements = elements.Where(e => IsVisible(e)).ToList();
        _log($"  Found {visibleElements.Count} visible element(s) (of {elements.Count} total)", "#CCCCCC");

        // Check for pre-existing page errors
        CheckPageErrors(pageUrl);

        // Click visible buttons and links
        var clickables = visibleElements
            .Where(IsClickable)
            .Take(options.MaxActionsPerPage)
            .ToList();

        if (clickables.Count > 0)
        {
            _log($"  Clicking {clickables.Count} element(s)...", "#4EC9B0");
        }

        foreach (var el in clickables)
        {
            var selector = GetSelector(el);
            var label = DescribeElement(el);
            if (string.IsNullOrEmpty(selector)) continue;

            var isNavLink = IsNavigationLink(el);
            var href = GetProp(el, "href");

            _log($"    Click: {label}", "#DCDCAA");

            var urlBefore = await SafeGetUrl() ?? pageUrl;
            var succeeded = await TryAction(pageUrl, label, "click", async () =>
            {
                await _ctx.Click(selector);
            });
            pageElements++;

            if (succeeded)
            {
                await Task.Delay(ActionDelayMs);

                // Did navigation happen?
                var urlAfter = await SafeGetUrl();
                if (urlAfter != null && NormalizeUrl(urlAfter) != NormalizeUrl(urlBefore))
                {
                    _log($"    → Navigated to: {Truncate(urlAfter, 70)}", "#569CD6");

                    if (options.FollowLinks && _visitedPages.Count < _maxPages &&
                        !_visitedPages.Contains(NormalizeUrl(urlAfter)))
                    {
                        _visitedPages.Add(NormalizeUrl(urlAfter));
                        await TestPage(urlAfter, options);
                    }

                    // Navigate back to continue testing this page
                    _log($"    ← Back to: {Truncate(pageUrl, 50)}", "#569CD6");
                    try
                    {
                        await _ctx.Navigate(pageUrl);
                        await Task.Delay(500);
                    }
                    catch (Exception ex)
                    {
                        _log($"    ← Failed to return: {Truncate(ex.Message, 60)}", "#F44747");
                        return;
                    }
                }
            }

            if (pageElements >= options.MaxActionsPerPage) break;
        }

        // Fuzz form inputs
        if (options.FuzzForms)
        {
            // Re-snapshot in case page changed from clicking
            try { elements = await _ctx.GetInteractiveElements(); }
            catch { elements = new List<Dictionary<string, object>>(); }

            var inputs = elements.Where(e => IsVisible(e) && IsTextInput(e)).ToList();
            var selects = elements.Where(e => IsVisible(e) && GetTag(e) == "select").ToList();

            if (inputs.Count > 0)
            {
                _log($"  Fuzzing {inputs.Count} input(s)...", "#4EC9B0");
            }

            foreach (var input in inputs)
            {
                var selector = GetSelector(input);
                var label = DescribeElement(input);
                if (string.IsNullOrEmpty(selector)) continue;

                foreach (var fuzz in FuzzStrings)
                {
                    var fuzzLabel = fuzz.Length == 0 ? "empty"
                        : fuzz.Length > 20 ? $"{fuzz[..17]}..."
                        : fuzz;

                    _log($"    Type into {label}: {fuzzLabel}", "#CE9178");

                    await TryAction(pageUrl, label, $"fuzz ({fuzzLabel})", async () =>
                    {
                        await _ctx.Type(selector, fuzz);
                    });

                    await Task.Delay(100);
                }

                pageFuzzed++;
                pageElements++;
            }

            // Actually interact with selects
            foreach (var sel in selects)
            {
                var selector = GetSelector(sel);
                var label = DescribeElement(sel);
                if (string.IsNullOrEmpty(selector)) continue;

                _log($"    Select: {label}", "#CE9178");

                await TryAction(pageUrl, label, "change selection", async () =>
                {
                    var js = $@"
                        (function() {{
                            var el = document.querySelector({System.Text.Json.JsonSerializer.Serialize(selector)});
                            if (!el || el.tagName !== 'SELECT') return 'SKIP';
                            if (el.options.length < 2) return 'SKIP';
                            var next = (el.selectedIndex + 1) % el.options.length;
                            el.selectedIndex = next;
                            el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                            return 'OK:' + el.options[next].text;
                        }})()
                    ";
                    var result = await _ctx.ExecuteJs(js);
                    if (result.StartsWith("OK:"))
                        _log($"      → Selected: {result[3..]}", "#CCCCCC");
                });

                await Task.Delay(ActionDelayMs);
                pageFuzzed++;
                pageElements++;
            }
        }

        _totalElementsTested += pageElements;
        _totalFormsFuzzed += pageFuzzed;

        var pageIssuesCount = _issues.Count - pageIssuesBefore;
        _pageSummaries.Add(new SmartTestPageSummary
        {
            Url = pageUrl,
            ElementsTested = pageElements,
            FormsFuzzed = pageFuzzed,
            IssuesFound = pageIssuesCount
        });

        var statusColor = pageIssuesCount > 0 ? "#CCA700" : "#4EC9B0";
        var statusText = pageIssuesCount > 0
            ? $"  ✗ {pageElements} elements, {pageIssuesCount} issue(s)"
            : $"  ✓ {pageElements} elements, all clear";
        _log(statusText, statusColor);
    }

    #endregion

    #region Error Detection

    private void CheckPageErrors(string pageUrl)
    {
        var loadErrors = _ctx.GetPageConsoleErrors();
        if (loadErrors.Count > 0)
        {
            _issues.Add(new SmartTestIssue
            {
                Page = pageUrl,
                Element = "(page load)",
                Action = "navigate",
                Issue = $"{loadErrors.Count} console error(s) on page load: {Truncate(loadErrors[0].Message, 100)}",
                IssueType = "js-error"
            });
        }

        var netErrors = _ctx.Network.FindPageErrors();
        foreach (var ne in netErrors)
        {
            _issues.Add(new SmartTestIssue
            {
                Page = pageUrl,
                Element = "(page load)",
                Action = "navigate",
                Issue = $"HTTP {ne.StatusCode} {ne.ReasonPhrase}: {Truncate(ne.Url, 100)}",
                IssueType = ne.StatusCode >= 500 ? "http-5xx" : "network-error"
            });
        }
    }

    private async Task<bool> TryAction(string pageUrl, string elementLabel, string action, Func<Task> act)
    {
        var consoleIdsBefore = new HashSet<int>(_ctx.GetConsoleErrors().Select(e => e.Id));
        var netIdsBefore = new HashSet<int>(_ctx.Network.FindErrors().Select(e => e.Id));

        try
        {
            var actionTask = act();
            var completed = await Task.WhenAny(actionTask, Task.Delay(ActionTimeoutMs));
            if (completed != actionTask)
            {
                _log($"      ⏱ Timed out after {ActionTimeoutMs / 1000}s", "#CCA700");
                return false;
            }
            await actionTask;
        }
        catch (Exception ex)
        {
            if (ex.Message.Contains("Navigation blocked", StringComparison.OrdinalIgnoreCase))
            {
                _issues.Add(new SmartTestIssue
                {
                    Page = pageUrl, Element = elementLabel, Action = action,
                    Issue = ex.Message, IssueType = "navigation"
                });
                _log($"      ✗ Navigation blocked: {Truncate(ex.Message, 80)}", "#F44747");
                return false;
            }

            if (!ex.Message.Contains("not found", StringComparison.OrdinalIgnoreCase) &&
                !ex.Message.Contains("not visible", StringComparison.OrdinalIgnoreCase) &&
                !ex.Message.Contains("blocked", StringComparison.OrdinalIgnoreCase))
            {
                if (ex.Message.Contains("timed out", StringComparison.OrdinalIgnoreCase))
                {
                    _log($"      ⏱ Element timed out", "#CCA700");
                }
                else
                {
                    _issues.Add(new SmartTestIssue
                    {
                        Page = pageUrl, Element = elementLabel, Action = action,
                        Issue = ex.Message, IssueType = "js-error"
                    });
                    _log($"      ✗ Error: {Truncate(ex.Message, 80)}", "#F44747");
                }
            }
            return false;
        }

        foreach (var ce in _ctx.GetConsoleErrors().Where(e => !consoleIdsBefore.Contains(e.Id)))
        {
            var src = string.IsNullOrEmpty(ce.Source) ? "" : $" ({ce.Source}:{ce.Line})";
            _issues.Add(new SmartTestIssue
            {
                Page = pageUrl, Element = elementLabel, Action = action,
                Issue = $"Console error{src}: {Truncate(ce.Message, 120)}",
                IssueType = "js-error"
            });
            _log($"      ✗ JS error: {Truncate(ce.Message, 60)}", "#F44747");
        }

        foreach (var ne in _ctx.Network.FindErrors().Where(e => !netIdsBefore.Contains(e.Id)))
        {
            var kind = ne.StatusCode >= 500 ? "http-5xx" : "network-error";
            var detail = $"HTTP {ne.StatusCode} {ne.ReasonPhrase}: {Truncate(ne.Url, 100)}";
            _issues.Add(new SmartTestIssue
            {
                Page = pageUrl, Element = elementLabel, Action = action,
                Issue = detail,
                IssueType = kind
            });
            _log($"      ✗ {detail}", ne.StatusCode >= 500 ? "#F44747" : "#CCA700");
        }

        return true;
    }

    #endregion

    #region Element Helpers

    private static bool IsVisible(Dictionary<string, object> el)
    {
        var visible = GetBoolProp(el, "visible", false);
        var refNum = GetIntProp(el, "ref", -1);
        return visible && refNum >= 0;
    }

    private static bool IsClickable(Dictionary<string, object> el)
    {
        var tag = GetTag(el);
        var type = GetProp(el, "type");
        var enabled = GetBoolProp(el, "enabled", true);

        if (!enabled) return false;

        return tag is "button" or "a" ||
               (tag == "input" && type is "button" or "submit" or "reset" or "checkbox" or "radio");
    }

    private static bool IsNavigationLink(Dictionary<string, object> el)
    {
        var tag = GetTag(el);
        if (tag != "a") return false;

        var href = GetProp(el, "href");
        if (string.IsNullOrEmpty(href)) return false;
        if (href.StartsWith("#") || href.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase))
            return false;

        return true;
    }

    private static bool IsTextInput(Dictionary<string, object> el)
    {
        var tag = GetTag(el);
        var type = GetProp(el, "type");
        var enabled = GetBoolProp(el, "enabled", true);

        if (!enabled) return false;

        if (tag == "textarea") return true;
        if (tag == "input")
        {
            return type is "" or "text" or "email" or "password" or "search" or "url" or "tel" or "number";
        }
        return false;
    }

    private static string DescribeElement(Dictionary<string, object> el)
    {
        var tag = GetTag(el);
        var label = GetProp(el, "label");
        var type = GetProp(el, "type");
        var href = GetProp(el, "href");

        var kindName = tag switch
        {
            "button" => "Button",
            "a" => "Link",
            "input" when type is "submit" => "Submit",
            "input" when type is "checkbox" => "Checkbox",
            "input" when type is "radio" => "Radio",
            "input" => $"Input[{type}]",
            "select" => "Select",
            "textarea" => "Textarea",
            _ => tag
        };

        if (!string.IsNullOrEmpty(label))
        {
            var desc = $"{kindName} '{Truncate(label, 30)}'";
            if (tag == "a" && !string.IsNullOrEmpty(href))
                desc += $" → {Truncate(href, 40)}";
            return desc;
        }

        var placeholder = GetProp(el, "placeholder");
        if (!string.IsNullOrEmpty(placeholder))
            return $"{kindName} ({Truncate(placeholder, 30)})";

        if (tag == "a" && !string.IsNullOrEmpty(href))
            return $"Link → {Truncate(href, 50)}";

        return kindName;
    }

    private static string? GetSelector(Dictionary<string, object> el)
    {
        if (el.TryGetValue("selector", out var s))
            return s?.ToString();
        return null;
    }

    private static string GetTag(Dictionary<string, object> el) =>
        GetProp(el, "tag").ToLowerInvariant();

    private static string GetProp(Dictionary<string, object> el, string key)
    {
        if (el.TryGetValue(key, out var v) && v != null)
            return v.ToString() ?? "";
        return "";
    }

    private static bool GetBoolProp(Dictionary<string, object> el, string key, bool defaultValue)
    {
        if (!el.TryGetValue(key, out var v) || v == null) return defaultValue;
        if (v is bool b) return b;
        if (v is System.Text.Json.JsonElement je)
        {
            if (je.ValueKind == System.Text.Json.JsonValueKind.True) return true;
            if (je.ValueKind == System.Text.Json.JsonValueKind.False) return false;
        }
        return bool.TryParse(v.ToString(), out var parsed) ? parsed : defaultValue;
    }

    private static int GetIntProp(Dictionary<string, object> el, string key, int defaultValue)
    {
        if (!el.TryGetValue(key, out var v) || v == null) return defaultValue;
        if (v is int i) return i;
        if (v is long l) return (int)l;
        if (v is System.Text.Json.JsonElement je && je.ValueKind == System.Text.Json.JsonValueKind.Number)
            return je.GetInt32();
        return int.TryParse(v.ToString(), out var parsed) ? parsed : defaultValue;
    }

    #endregion

    #region Utilities

    private async Task<string?> SafeGetUrl()
    {
        try { return await _ctx.GetCurrentUrl(); }
        catch (Exception ex) { TrowserLog.Warn($"SafeGetUrl failed: {ex.Message}"); return null; }
    }

    private static string NormalizeUrl(string url)
    {
        var idx = url.IndexOf('#');
        if (idx >= 0) url = url[..idx];
        return url.TrimEnd('/');
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..(max - 3)] + "...";

    #endregion
}
