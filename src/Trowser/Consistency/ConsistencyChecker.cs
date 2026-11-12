using System.Text.Json;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Automation;

namespace Trowser.Consistency;

/// <summary>
/// Audits the page's visual consistency using getComputedStyle().
/// Checks font families, font sizes, text colors, background colors,
/// button/input heights, and spacing values.
///
/// All thresholds are advisory — warnings indicate potential design inconsistency,
/// not errors. Some variation is normal and expected.
/// </summary>
public class ConsistencyChecker
{
    private readonly WebView2 _webView;

    // Thresholds for warnings
    private const int MaxFontFamilies = 4;
    private const int MaxFontSizes = 8;
    private const int MaxTextColors = 10;
    private const int MaxBgColors = 8;
    private const int MaxButtonHeights = 3;
    private const int MaxInputHeights = 3;
    private const int MaxSpacingValues = 16;

    public ConsistencyChecker(WebView2 webView)
    {
        _webView = webView ?? throw new ArgumentNullException(nameof(webView));
    }

    /// <summary>
    /// Run the GUI consistency audit on the current page.
    /// </summary>
    public async Task<ConsistencyResult> RunAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var callbackId = $"__trowser_consistency_{Guid.NewGuid():N}";
        var scanScript = BuildScannerScript(callbackId);

        var startResult = await WebViewUiScript.RunAsync(_webView, scanScript, cancellationToken,
            operationLabel: "Consistency audit");
        if (startResult != "STARTED")
        {
            throw new InvalidOperationException(
                $"Failed to start consistency audit. Result: {startResult}");
        }

        var deadline = DateTime.UtcNow.AddSeconds(15);
        string? json = null;

        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var doneCheck = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}_done']",
                cancellationToken, operationLabel: "Consistency audit");
            if (doneCheck == "true")
            {
                json = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}']",
                    cancellationToken, operationLabel: "Consistency audit");
                await WebViewUiScript.RunAsync(_webView,
                    $"delete window['{callbackId}']; delete window['{callbackId}_done']; 'OK'",
                    cancellationToken, operationLabel: "Consistency audit");
                break;
            }
            await Task.Delay(100, cancellationToken);
        }

        if (string.IsNullOrEmpty(json))
        {
            throw new TimeoutException("Consistency audit did not complete within 15 seconds.");
        }

        return ParseResults(json);
    }

    #region Scanner JavaScript

    private static string BuildScannerScript(string callbackId)
    {
        return $@"
(function() {{
    window['{callbackId}'] = null;
    window['{callbackId}_done'] = false;

    try {{
        var fontFamilies = {{}};
        var fontSizes = {{}};
        var textColors = {{}};
        var bgColors = {{}};
        var buttonHeights = {{}};
        var inputHeights = {{}};
        var spacingValues = {{}};

        // Helper: normalize color to hex or rgba string
        function normalizeColor(c) {{
            if (!c || c === 'transparent' || c === 'rgba(0, 0, 0, 0)') return null;
            return c;
        }}

        // Helper: round px values to nearest integer
        function roundPx(val) {{
            var n = parseFloat(val);
            return isNaN(n) ? null : Math.round(n) + 'px';
        }}

        // Helper: normalize font-family (take first family, strip quotes)
        function normalizeFontFamily(ff) {{
            if (!ff) return null;
            var first = ff.split(',')[0].trim().replace(/[""']/g, '');
            return first || null;
        }}

        // Get all visible elements (sampling for performance)
        var allElements = document.body.querySelectorAll('*');
        var maxElements = Math.min(allElements.length, 2000);

        for (var i = 0; i < maxElements; i++) {{
            var el = allElements[i];

            // Skip invisible elements
            if (el.offsetWidth === 0 && el.offsetHeight === 0) continue;
            var tagName = el.tagName.toLowerCase();
            if (tagName === 'script' || tagName === 'style' || tagName === 'link' || tagName === 'meta' || tagName === 'noscript') continue;

            var style = window.getComputedStyle(el);

            // Font family (for elements with actual text)
            if (el.childNodes.length > 0) {{
                var hasTextNode = false;
                for (var j = 0; j < el.childNodes.length; j++) {{
                    if (el.childNodes[j].nodeType === 3 && el.childNodes[j].textContent.trim().length > 0) {{
                        hasTextNode = true;
                        break;
                    }}
                }}
                if (hasTextNode) {{
                    var ff = normalizeFontFamily(style.fontFamily);
                    if (ff) fontFamilies[ff] = (fontFamilies[ff] || 0) + 1;

                    var fs = roundPx(style.fontSize);
                    if (fs) fontSizes[fs] = (fontSizes[fs] || 0) + 1;

                    var tc = normalizeColor(style.color);
                    if (tc) textColors[tc] = (textColors[tc] || 0) + 1;
                }}
            }}

            // Background color (non-transparent only)
            var bg = normalizeColor(style.backgroundColor);
            if (bg) bgColors[bg] = (bgColors[bg] || 0) + 1;

            // Button heights
            if (tagName === 'button' || (tagName === 'input' && (el.type === 'submit' || el.type === 'button' || el.type === 'reset'))
                || (tagName === 'a' && el.getAttribute('role') === 'button')) {{
                var bh = roundPx(style.height);
                if (bh && bh !== '0px') buttonHeights[bh] = (buttonHeights[bh] || 0) + 1;
            }}

            // Input heights
            if ((tagName === 'input' && el.type !== 'hidden' && el.type !== 'submit' && el.type !== 'button' && el.type !== 'reset' && el.type !== 'checkbox' && el.type !== 'radio')
                || tagName === 'select' || tagName === 'textarea') {{
                var ih = roundPx(style.height);
                if (ih && ih !== '0px') inputHeights[ih] = (inputHeights[ih] || 0) + 1;
            }}

            // Spacing (margin and padding - only non-zero values)
            var spacingProps = ['marginTop', 'marginRight', 'marginBottom', 'marginLeft',
                               'paddingTop', 'paddingRight', 'paddingBottom', 'paddingLeft'];
            for (var j = 0; j < spacingProps.length; j++) {{
                var sv = roundPx(style[spacingProps[j]]);
                if (sv && sv !== '0px') spacingValues[sv] = (spacingValues[sv] || 0) + 1;
            }}
        }}

        // Convert to sorted arrays
        function toSortedArray(obj) {{
            var arr = [];
            for (var key in obj) arr.push({{ value: key, count: obj[key] }});
            arr.sort(function(a, b) {{ return b.count - a.count; }});
            return arr;
        }}

        // Image optimization audit
        var imageIssues = [];
        var imgs = document.querySelectorAll('img');
        var viewportHeight = window.innerHeight;
        for (var k = 0; k < imgs.length; k++) {{
            var img = imgs[k];
            if (!img.src || img.src.startsWith('data:')) continue;
            var nw = img.naturalWidth || 0;
            var nh = img.naturalHeight || 0;
            var dw = img.clientWidth || img.offsetWidth || 0;
            var dh = img.clientHeight || img.offsetHeight || 0;
            var shortSrc = img.src.length > 80 ? img.src.substring(0, 77) + '...' : img.src;

            // Oversized: natural dimensions > 2x displayed (only if both are known and displayed > 0)
            if (nw > 0 && dw > 0 && nw > dw * 2 && nh > 0 && dh > 0 && nh > dh * 2) {{
                imageIssues.push({{
                    src: img.src,
                    issueType: 'oversized',
                    description: 'Image is ' + nw + 'x' + nh + 'px but displayed at ' + dw + 'x' + dh + 'px (>' + Math.round(nw/dw) + 'x oversized)',
                    naturalWidth: nw, naturalHeight: nh, displayedWidth: dw, displayedHeight: dh
                }});
            }}

            // Missing explicit width/height attributes (causes CLS)
            if (!img.hasAttribute('width') && !img.hasAttribute('height')
                && !(img.style.width && img.style.height)
                && !(img.style.aspectRatio)) {{
                var parent = img.parentElement;
                var parentHasAspect = parent && (parent.style.aspectRatio || (parent.style.width && parent.style.height));
                if (!parentHasAspect && dw > 1 && dh > 1) {{
                    imageIssues.push({{
                        src: img.src,
                        issueType: 'missing-dimensions',
                        description: 'Image lacks width/height attributes — may cause layout shift (CLS)',
                        naturalWidth: nw, naturalHeight: nh, displayedWidth: dw, displayedHeight: dh
                    }});
                }}
            }}

            // Missing lazy loading on below-fold images
            var rect = img.getBoundingClientRect();
            if (rect.top > viewportHeight * 1.5 && img.getAttribute('loading') !== 'lazy' && dw > 1) {{
                imageIssues.push({{
                    src: img.src,
                    issueType: 'missing-lazy',
                    description: 'Below-fold image lacks loading=""lazy"" (top: ' + Math.round(rect.top) + 'px, viewport: ' + viewportHeight + 'px)',
                    naturalWidth: nw, naturalHeight: nh, displayedWidth: dw, displayedHeight: dh
                }});
            }}
        }}

        var results = {{
            url: location.href,
            timestamp: new Date().toISOString(),
            fontFamilies: toSortedArray(fontFamilies),
            fontSizes: toSortedArray(fontSizes),
            textColors: toSortedArray(textColors),
            bgColors: toSortedArray(bgColors),
            buttonHeights: toSortedArray(buttonHeights),
            inputHeights: toSortedArray(inputHeights),
            spacingValues: toSortedArray(spacingValues),
            imageIssues: imageIssues,
            elementsScanned: maxElements
        }};

        window['{callbackId}'] = JSON.stringify(results);
        window['{callbackId}_done'] = true;
    }} catch(e) {{
        window['{callbackId}'] = JSON.stringify({{ error: e.message || String(e) }});
        window['{callbackId}_done'] = true;
    }}

    return 'STARTED';
}})()";
    }

    #endregion

    #region Result Parsing

    private ConsistencyResult ParseResults(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (root.TryGetProperty("error", out var errorProp))
        {
            throw new InvalidOperationException($"Consistency audit error: {errorProp.GetString()}");
        }

        var url = root.TryGetProperty("url", out var urlProp) ? urlProp.GetString() ?? "" : "";

        var stats = new ConsistencyStats
        {
            FontFamilies = ParseValueCounts(root, "fontFamilies"),
            FontSizes = ParseValueCounts(root, "fontSizes"),
            TextColors = ParseValueCounts(root, "textColors"),
            BackgroundColors = ParseValueCounts(root, "bgColors"),
            ButtonHeights = ParseValueCounts(root, "buttonHeights"),
            InputHeights = ParseValueCounts(root, "inputHeights"),
            SpacingValues = ParseValueCounts(root, "spacingValues"),
            ImageIssues = ParseImageIssues(root)
        };

        var findings = GenerateFindings(stats);

        return new ConsistencyResult
        {
            Url = url,
            Timestamp = DateTime.UtcNow,
            Stats = stats,
            Findings = findings
        };
    }

    private static List<ValueCount> ParseValueCounts(JsonElement root, string property)
    {
        var list = new List<ValueCount>();
        if (root.TryGetProperty(property, out var array) && array.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in array.EnumerateArray())
            {
                list.Add(new ValueCount
                {
                    Value = item.TryGetProperty("value", out var val) ? val.GetString() ?? "" : "",
                    Count = item.TryGetProperty("count", out var cnt) ? cnt.GetInt32() : 0
                });
            }
        }
        return list;
    }

    private static List<ImageIssue> ParseImageIssues(JsonElement root)
    {
        var list = new List<ImageIssue>();
        if (root.TryGetProperty("imageIssues", out var array) && array.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in array.EnumerateArray())
            {
                list.Add(new ImageIssue
                {
                    Src = item.TryGetProperty("src", out var src) ? src.GetString() ?? "" : "",
                    IssueType = item.TryGetProperty("issueType", out var it) ? it.GetString() ?? "" : "",
                    Description = item.TryGetProperty("description", out var desc) ? desc.GetString() ?? "" : "",
                    NaturalWidth = item.TryGetProperty("naturalWidth", out var nw) ? nw.GetInt32() : 0,
                    NaturalHeight = item.TryGetProperty("naturalHeight", out var nh) ? nh.GetInt32() : 0,
                    DisplayedWidth = item.TryGetProperty("displayedWidth", out var dw) ? dw.GetInt32() : 0,
                    DisplayedHeight = item.TryGetProperty("displayedHeight", out var dh) ? dh.GetInt32() : 0
                });
            }
        }
        return list;
    }

    private List<ConsistencyFinding> GenerateFindings(ConsistencyStats stats)
    {
        var findings = new List<ConsistencyFinding>();

        // Typography
        AddFinding(findings, "typography", stats.FontFamilies, MaxFontFamilies,
            "font families", "Consider limiting to 2-3 font families for visual consistency.");

        AddFinding(findings, "typography", stats.FontSizes, MaxFontSizes,
            "font sizes", "Establish a typographic scale (e.g., 12, 14, 16, 20, 24, 32px).");

        // Colors
        AddFinding(findings, "colors", stats.TextColors, MaxTextColors,
            "text colors", "Define a color palette and stick to it for text.");

        AddFinding(findings, "colors", stats.BackgroundColors, MaxBgColors,
            "background colors", "Reduce the number of distinct background colors for a cleaner look.");

        // Sizing
        AddFinding(findings, "sizing", stats.ButtonHeights, MaxButtonHeights,
            "button heights", "Standardize button sizes (small, medium, large) for consistency.");

        AddFinding(findings, "sizing", stats.InputHeights, MaxInputHeights,
            "input heights", "Standardize input field heights to match button heights.");

        // Spacing
        AddFinding(findings, "spacing", stats.SpacingValues, MaxSpacingValues,
            "spacing values", "Use a spacing scale (e.g., 4, 8, 12, 16, 24, 32, 48px) for consistent rhythm.");

        // Images
        if (stats.ImageIssues.Count > 0)
        {
            var oversized = stats.ImageIssues.Count(i => i.IssueType == "oversized");
            var missingDims = stats.ImageIssues.Count(i => i.IssueType == "missing-dimensions");
            var missingLazy = stats.ImageIssues.Count(i => i.IssueType == "missing-lazy");

            var parts = new List<string>();
            if (oversized > 0) parts.Add($"{oversized} oversized");
            if (missingDims > 0) parts.Add($"{missingDims} missing dimensions");
            if (missingLazy > 0) parts.Add($"{missingLazy} missing lazy loading");

            findings.Add(new ConsistencyFinding
            {
                Category = "images",
                IsWarning = oversized > 0 || missingDims > 0,
                Description = $"{stats.ImageIssues.Count} image issue(s): {string.Join(", ", parts)}.",
                Values = stats.ImageIssues.Select(i => $"{i.Src}: {i.Description}").ToList()
            });
        }
        else
        {
            findings.Add(new ConsistencyFinding
            {
                Category = "images",
                IsWarning = false,
                Description = "No image optimization issues found.",
                Values = new List<string>()
            });
        }

        return findings;
    }

    private static void AddFinding(List<ConsistencyFinding> findings, string category,
        List<ValueCount> values, int threshold, string label, string advice)
    {
        if (values.Count == 0) return;

        var isWarning = values.Count > threshold;
        findings.Add(new ConsistencyFinding
        {
            Category = category,
            IsWarning = isWarning,
            Description = isWarning
                ? $"{values.Count} distinct {label} found (threshold: {threshold}). {advice}"
                : $"{values.Count} distinct {label} found (within threshold of {threshold}).",
            Values = values.Select(v => $"{v.Value} ({v.Count}x)").ToList()
        });
    }

    #endregion

}
