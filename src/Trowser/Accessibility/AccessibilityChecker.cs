using System.IO;
using System.Reflection;
using System.Text.Json;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Automation;

namespace Trowser.Accessibility;

/// <summary>
/// Injects axe-core into the current page and runs automated WCAG accessibility analysis.
/// </summary>
public class AccessibilityChecker
{
    private readonly WebView2 _webView;
    private string? _axeScript;

    public AccessibilityChecker(WebView2 webView)
    {
        _webView = webView ?? throw new ArgumentNullException(nameof(webView));
    }

    /// <summary>
    /// Run an accessibility audit on the current page.
    /// </summary>
    /// <param name="wcagLevel">WCAG level filter: "A", "AA", "AAA", or null for all rules.</param>
    /// <param name="selector">CSS selector to limit the audit scope (null = entire page).</param>
    /// <param name="cancellationToken">Stops polling when Shadow navigates away.</param>
    public async Task<AccessibilityResult> RunAsync(string? wcagLevel = null, string? selector = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // Load axe-core script from embedded resource (cached after first load)
        var axeScript = await GetAxeScriptAsync();

        // Step 1: Inject axe-core into the page and verify it loaded
        var injectResult = await WebViewUiScript.RunAsync(_webView,
            axeScript + "\n; typeof axe !== 'undefined' ? 'OK' : 'FAIL'", cancellationToken,
            operationLabel: "Accessibility scan");

        if (injectResult != "OK")
        {
            throw new InvalidOperationException(
                $"Failed to inject axe-core into the page. Result: {injectResult}");
        }

        // Step 2: Build the axe.run() call with a unique callback ID
        var options = BuildOptions(wcagLevel);
        var context = selector != null ? $"'{EscapeJs(selector)}'" : "document";
        var callbackId = $"__trowser_axe_{Guid.NewGuid():N}";

        // Store result in a global variable since ExecuteScriptAsync
        // doesn't reliably resolve Promises in all WebView2 versions
        var runScript = $@"
            (function() {{
                window['{callbackId}'] = null;
                window['{callbackId}_done'] = false;
                axe.run({context}, {options}).then(function(results) {{
                    window['{callbackId}'] = JSON.stringify({{
                        violations: results.violations,
                        passes: results.passes,
                        incomplete: results.incomplete,
                        url: results.url,
                        timestamp: results.timestamp
                    }});
                    window['{callbackId}_done'] = true;
                }}).catch(function(err) {{
                    window['{callbackId}'] = JSON.stringify({{ error: err.message || String(err) }});
                    window['{callbackId}_done'] = true;
                }});
                return 'STARTED';
            }})()";

        var startResult = await WebViewUiScript.RunAsync(_webView, runScript, cancellationToken,
            operationLabel: "Accessibility scan");
        if (startResult != "STARTED")
        {
            throw new InvalidOperationException(
                $"Failed to start axe-core analysis. Result: {startResult}");
        }

        // Step 3: Poll for the result (axe.run is async)
        var deadline = DateTime.UtcNow.AddSeconds(30);
        string? json = null;

        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var doneCheck = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}_done']",
                cancellationToken, operationLabel: "Accessibility scan");
            if (doneCheck == "true")
            {
                json = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}']",
                    cancellationToken, operationLabel: "Accessibility scan");

                await WebViewUiScript.RunAsync(_webView,
                    $"delete window['{callbackId}']; delete window['{callbackId}_done']; 'OK'",
                    cancellationToken, operationLabel: "Accessibility scan");
                break;
            }
            await Task.Delay(100, cancellationToken);
        }

        if (json == null || json == "")
        {
            throw new TimeoutException("axe-core analysis did not complete within 30 seconds.");
        }

        return ParseResults(json);
    }

    #region Axe-core Script Loading

    private async Task<string> GetAxeScriptAsync()
    {
        if (_axeScript != null) return _axeScript;

        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream("Trowser.Resources.axe.min.js");

        if (stream == null)
        {
            throw new InvalidOperationException(
                "axe-core script not found as embedded resource. " +
                "Ensure axe.min.js is in Resources/ and marked as EmbeddedResource in the .csproj.");
        }

        using var reader = new StreamReader(stream);
        _axeScript = await reader.ReadToEndAsync();
        return _axeScript;
    }

    #endregion

    #region Options Builder

    private static string BuildOptions(string? wcagLevel)
    {
        if (wcagLevel == null)
        {
            return "{}";
        }

        // Map WCAG level to axe-core tags
        var tags = wcagLevel.ToUpperInvariant() switch
        {
            "A" => new[] { "wcag2a", "wcag21a" },
            "AA" => new[] { "wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa" },
            "AAA" => new[] { "wcag2a", "wcag2aa", "wcag2aaa", "wcag21a", "wcag21aa", "wcag22aa" },
            "BEST-PRACTICE" or "BEST_PRACTICE" => new[] { "best-practice" },
            _ => new[] { $"wcag2{wcagLevel.ToLowerInvariant()}" }
        };

        var tagsJson = JsonSerializer.Serialize(tags);
        return $"{{ runOnly: {{ type: 'tag', values: {tagsJson} }} }}";
    }

    #endregion

    #region Result Parsing

    private static AccessibilityResult ParseResults(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        // Check for error
        if (root.TryGetProperty("error", out var errorProp))
        {
            throw new InvalidOperationException($"axe-core error: {errorProp.GetString()}");
        }

        var url = root.TryGetProperty("url", out var urlProp) ? urlProp.GetString() ?? "" : "";

        return new AccessibilityResult
        {
            Url = url,
            Timestamp = DateTime.UtcNow,
            Violations = ParseViolations(root),
            Passes = ParsePasses(root),
            Incomplete = ParseIncomplete(root)
        };
    }

    private static List<AccessibilityViolation> ParseViolations(JsonElement root)
    {
        var violations = new List<AccessibilityViolation>();

        if (!root.TryGetProperty("violations", out var violationsArray))
            return violations;

        foreach (var v in violationsArray.EnumerateArray())
        {
            violations.Add(new AccessibilityViolation
            {
                RuleId = v.GetProperty("id").GetString() ?? "",
                Impact = ParseImpact(v.TryGetProperty("impact", out var imp) ? imp.GetString() : null),
                Description = v.TryGetProperty("description", out var desc) ? desc.GetString() ?? "" : "",
                Help = v.TryGetProperty("help", out var help) ? help.GetString() ?? "" : "",
                HelpUrl = v.TryGetProperty("helpUrl", out var helpUrl) ? helpUrl.GetString() ?? "" : "",
                Tags = ParseStringArray(v, "tags"),
                Nodes = ParseNodes(v)
            });
        }

        return violations;
    }

    private static List<AccessibilityNode> ParseNodes(JsonElement violation)
    {
        var nodes = new List<AccessibilityNode>();

        if (!violation.TryGetProperty("nodes", out var nodesArray))
            return nodes;

        foreach (var n in nodesArray.EnumerateArray())
        {
            nodes.Add(new AccessibilityNode
            {
                Html = n.TryGetProperty("html", out var html) ? html.GetString() ?? "" : "",
                Target = ParseStringArray(n, "target"),
                FailureSummary = n.TryGetProperty("failureSummary", out var fs) ? fs.GetString() ?? "" : ""
            });
        }

        return nodes;
    }

    private static List<AccessibilityPass> ParsePasses(JsonElement root)
    {
        var passes = new List<AccessibilityPass>();

        if (!root.TryGetProperty("passes", out var passesArray))
            return passes;

        foreach (var p in passesArray.EnumerateArray())
        {
            var nodeCount = 0;
            if (p.TryGetProperty("nodes", out var nodes))
            {
                nodeCount = nodes.GetArrayLength();
            }

            passes.Add(new AccessibilityPass
            {
                RuleId = p.GetProperty("id").GetString() ?? "",
                Description = p.TryGetProperty("description", out var desc) ? desc.GetString() ?? "" : "",
                Help = p.TryGetProperty("help", out var help) ? help.GetString() ?? "" : "",
                Tags = ParseStringArray(p, "tags"),
                NodeCount = nodeCount
            });
        }

        return passes;
    }

    private static List<AccessibilityIncomplete> ParseIncomplete(JsonElement root)
    {
        var incomplete = new List<AccessibilityIncomplete>();

        if (!root.TryGetProperty("incomplete", out var incompleteArray))
            return incomplete;

        foreach (var item in incompleteArray.EnumerateArray())
        {
            var nodeCount = 0;
            if (item.TryGetProperty("nodes", out var nodes))
            {
                nodeCount = nodes.GetArrayLength();
            }

            incomplete.Add(new AccessibilityIncomplete
            {
                RuleId = item.GetProperty("id").GetString() ?? "",
                Description = item.TryGetProperty("description", out var desc) ? desc.GetString() ?? "" : "",
                Help = item.TryGetProperty("help", out var help) ? help.GetString() ?? "" : "",
                Tags = ParseStringArray(item, "tags"),
                NodeCount = nodeCount
            });
        }

        return incomplete;
    }

    private static Impact ParseImpact(string? impact)
    {
        return impact?.ToLowerInvariant() switch
        {
            "critical" => Impact.Critical,
            "serious" => Impact.Serious,
            "moderate" => Impact.Moderate,
            "minor" => Impact.Minor,
            _ => Impact.Minor
        };
    }

    private static List<string> ParseStringArray(JsonElement element, string propertyName)
    {
        var list = new List<string>();
        if (element.TryGetProperty(propertyName, out var array))
        {
            foreach (var item in array.EnumerateArray())
            {
                var value = item.GetString();
                if (value != null) list.Add(value);
            }
        }
        return list;
    }

    #endregion

    #region Helpers
    private static string UnwrapJsonString(string jsonResult)
        => Trowser.Automation.WebViewScriptResult.UnwrapJsonString(jsonResult);


    private static string EscapeJs(string value)
    {
        return value
            .Replace("\\", "\\\\")
            .Replace("'", "\\'")
            .Replace("\"", "\\\"");
    }

    #endregion
}
