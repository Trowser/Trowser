using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Web.WebView2.Wpf;

namespace Trowser.Security;

/// <summary>
/// Finding from the source map / debug mode scan.
/// </summary>
public class SourceMapFinding
{
    public Severity Severity { get; init; }
    public string Category { get; init; } = "";
    public string Description { get; init; } = "";
    public string? Url { get; init; }
    public string? Detail { get; init; }
    public string? Recommendation { get; init; }
}

/// <summary>
/// Result of the source-map and debug-mode audit.
/// </summary>
public class SourceMapResult
{
    public string Url { get; init; } = "";
    public DateTime Timestamp { get; init; }
    public List<SourceMapFinding> Findings { get; init; } = new();

    public bool IsClean => Findings.Count == 0;
    public int FindingCount => Findings.Count;

    public string Format(bool includeDetails = true)
    {
        var lines = new List<string>();

        lines.Add("=== Source Map & Debug Mode Audit ===");
        lines.Add($"URL: {Url}");
        lines.Add($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss}");
        lines.Add("");

        if (IsClean)
        {
            lines.Add("No source maps or debug indicators found.");
            lines.Add("========================================");
            return string.Join(Environment.NewLine, lines);
        }

        lines.Add($"Findings: {FindingCount}");

        if (includeDetails)
        {
            foreach (var f in Findings.OrderByDescending(x => x.Severity))
            {
                var sev = f.Severity.ToString().ToUpper();
                lines.Add($"  [{sev}] {f.Category}: {f.Description}");
                if (f.Url != null) lines.Add($"    Source: {f.Url}");
                if (f.Detail != null) lines.Add($"    Detail: {f.Detail}");
                if (f.Recommendation != null) lines.Add($"    Recommendation: {f.Recommendation}");
            }
        }

        lines.Add("");
        lines.Add($"ASSESSMENT: {FindingCount} source map or debug indicator(s) found. " +
                  "Source maps expose original source code; debug mode is a separate production-build concern (not source maps).");
        lines.Add("========================================");
        return string.Join(Environment.NewLine, lines);
    }
}

/// <summary>
/// Checks the current page for source map references, accessible .map files,
/// and framework debug mode indicators that may leak information in production.
/// </summary>
public class SourceMapChecker
{
    private readonly WebView2 _webView;

    private static readonly HttpClient SharedClient = new(new HttpClientHandler
    {
        AllowAutoRedirect = false,
        ServerCertificateCustomValidationCallback = (_, _, _, _) => true
    })
    {
        Timeout = TimeSpan.FromSeconds(5)
    };

    private static readonly Regex SourceMapUrlRegex =
        new(@"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", RegexOptions.Compiled);

    private static readonly Regex CssSourceMapRegex =
        new(@"/\*[#@]\s*sourceMappingURL\s*=\s*(\S+)\s*\*/", RegexOptions.Compiled);

    internal const string SourceMapAccessRecommendation =
        "Remove source maps from production builds or restrict access via server configuration.";

    public SourceMapChecker(WebView2 webView)
    {
        _webView = webView ?? throw new ArgumentNullException(nameof(webView));
    }

    public async Task<SourceMapResult> RunAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var findings = new List<SourceMapFinding>();

        var pageUrl = await GetCurrentUrl();

        var (htmlSource, scriptUrls, cssUrls, debugIndicators) = await CollectPageData();

        ScanHtmlForSourceMaps(htmlSource, pageUrl, findings);

        ScanForDebugIndicators(debugIndicators, findings);

        var mapUrlsToProbe = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var scriptUrl in scriptUrls)
        {
            var mapUrl = scriptUrl + ".map";
            mapUrlsToProbe.Add(mapUrl);
        }

        foreach (var cssUrl in cssUrls)
        {
            var mapUrl = cssUrl + ".map";
            mapUrlsToProbe.Add(mapUrl);
        }

        var references = FindSourceMapReferences(htmlSource);
        foreach (var (refUrl, context) in references)
        {
            findings.Add(new SourceMapFinding
            {
                Severity = Severity.Medium,
                Category = "SourceMapReference",
                Description = $"Source map reference found in inline content: {refUrl}",
                Url = pageUrl,
                Detail = context,
                Recommendation = SourceMapAccessRecommendation
            });
            var resolved = ResolveUrl(pageUrl, refUrl);
            if (resolved != null) mapUrlsToProbe.Add(resolved);
        }

        await ProbeMapFiles(mapUrlsToProbe, findings, cancellationToken);

        return new SourceMapResult
        {
            Url = pageUrl,
            Timestamp = DateTime.UtcNow,
            Findings = findings
        };
    }

    private async Task<string> GetCurrentUrl()
    {
        var result = await _webView.Dispatcher.InvokeAsync(
            () => _webView.CoreWebView2.ExecuteScriptAsync("location.href"));
        var raw = await result;
        return UnwrapJsonString(raw);
    }

    private async Task<(string html, List<string> scripts, List<string> css, JsonElement? debug)> CollectPageData()
    {
        var script = @"
(function() {
    var scripts = [];
    var elems = document.querySelectorAll('script[src]');
    for (var i = 0; i < elems.length; i++) scripts.push(elems[i].src);
    try {
        var res = performance.getEntriesByType('resource');
        for (var i = 0; i < res.length; i++) {
            if (res[i].initiatorType === 'script' && scripts.indexOf(res[i].name) === -1)
                scripts.push(res[i].name);
        }
    } catch(e) {}

    var css = [];
    var links = document.querySelectorAll('link[rel=""stylesheet""][href]');
    for (var i = 0; i < links.length; i++) css.push(links[i].href);

    var debug = {};
    try { debug.ngProbe = !!window.ng && typeof window.ng.probe === 'function'; } catch(e) { debug.ngProbe = false; }
    try { debug.ngGetComponent = !!window.ng && typeof window.ng.getComponent === 'function'; } catch(e) { debug.ngGetComponent = false; }
    try { debug.reactDevtools = !!window.__REACT_DEVTOOLS_GLOBAL_HOOK__; } catch(e) { debug.reactDevtools = false; }
    try { debug.vueDevtools = !!window.__VUE_DEVTOOLS_GLOBAL_HOOK__; } catch(e) { debug.vueDevtools = false; }
    try {
        debug.angularJs1 = typeof angular !== 'undefined' && angular.version
            && /^1\\./.test(String(angular.version));
    } catch(e) { debug.angularJs1 = false; }
    try {
        debug.modernNg = typeof ng !== 'undefined'
            && (typeof ng.probe === 'function' || typeof ng.getComponent === 'function');
    } catch(e) { debug.modernNg = false; }
    try { debug.angularLegacyDebugApi = typeof window.getAllAngularRootElements === 'function'; } catch(e) { debug.angularLegacyDebugApi = false; }
    try { debug.reduxDevtools = !!window.__REDUX_DEVTOOLS_EXTENSION__; } catch(e) { debug.reduxDevtools = false; }

    return JSON.stringify({ scripts: scripts, css: css, debug: debug });
})()";

        var taskOfResult = await _webView.Dispatcher.InvokeAsync(
            () => _webView.CoreWebView2.ExecuteScriptAsync(script));
        var raw = await taskOfResult;
        var json = UnwrapJsonString(raw);

        var htmlTask = await _webView.Dispatcher.InvokeAsync(
            () => _webView.CoreWebView2.ExecuteScriptAsync("document.documentElement.outerHTML"));
        var htmlRaw = await htmlTask;
        var html = UnwrapJsonString(htmlRaw);

        var scriptUrls = new List<string>();
        var cssUrls = new List<string>();
        JsonElement? debugEl = null;

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.TryGetProperty("scripts", out var sarr))
                foreach (var s in sarr.EnumerateArray())
                    if (s.GetString() is { } sv) scriptUrls.Add(sv);
            if (root.TryGetProperty("css", out var carr))
                foreach (var c in carr.EnumerateArray())
                    if (c.GetString() is { } cv) cssUrls.Add(cv);
            if (root.TryGetProperty("debug", out var dEl))
                debugEl = dEl.Clone();
        }
        catch { /* parse failure — continue with empty lists */ }

        return (html, scriptUrls, cssUrls, debugEl);
    }

    private static void ScanHtmlForSourceMaps(string html, string pageUrl, List<SourceMapFinding> findings)
    {
        foreach (Match m in SourceMapUrlRegex.Matches(html))
        {
            findings.Add(new SourceMapFinding
            {
                Severity = Severity.Medium,
                Category = "SourceMapReference",
                Description = $"JavaScript sourceMappingURL directive found in page HTML: {m.Groups[1].Value}",
                Url = pageUrl,
                Detail = TruncateContext(m.Value, 120),
                Recommendation = SourceMapAccessRecommendation
            });
        }
        foreach (Match m in CssSourceMapRegex.Matches(html))
        {
            findings.Add(new SourceMapFinding
            {
                Severity = Severity.Medium,
                Category = "SourceMapReference",
                Description = $"CSS sourceMappingURL directive found in page HTML: {m.Groups[1].Value}",
                Url = pageUrl,
                Detail = TruncateContext(m.Value, 120),
                Recommendation = SourceMapAccessRecommendation
            });
        }
    }

    private static List<(string url, string context)> FindSourceMapReferences(string html)
    {
        var results = new List<(string, string)>();
        foreach (Match m in SourceMapUrlRegex.Matches(html))
            results.Add((m.Groups[1].Value, TruncateContext(m.Value, 80)));
        foreach (Match m in CssSourceMapRegex.Matches(html))
            results.Add((m.Groups[1].Value, TruncateContext(m.Value, 80)));
        return results;
    }

    private static void ScanForDebugIndicators(JsonElement? debug, List<SourceMapFinding> findings)
    {
        if (debug == null) return;

        Check("ngProbe",
            "Angular ng.probe() is accessible — debug mode is enabled (call enableProdMode() in production)",
            "Call enableProdMode() (or ship a production build) so Angular debug APIs are not exposed. This is not a source-map issue.");
        Check("ngGetComponent",
            "Angular ng.getComponent() is accessible — debug mode is enabled",
            "Call enableProdMode() (or ship a production build) so Angular debug APIs are not exposed. This is not a source-map issue.");
        Check("reactDevtools",
            "React DevTools global hook is present (__REACT_DEVTOOLS_GLOBAL_HOOK__)",
            "The React DevTools hook can come from a browser extension or a development build. Ship a production React build. This is not a source-map issue.");
        Check("vueDevtools",
            "Vue DevTools global hook is present (__VUE_DEVTOOLS_GLOBAL_HOOK__)",
            "The Vue DevTools hook can come from a browser extension or a development build. Ship a production Vue build. This is not a source-map issue.");
        var angularJs1 = debug.Value.TryGetProperty("angularJs1", out var aj1) && aj1.ValueKind == JsonValueKind.True;
        var modernNg = debug.Value.TryGetProperty("modernNg", out var mn) && mn.ValueKind == JsonValueKind.True;
        var legacyDebugApi = debug.Value.TryGetProperty("angularLegacyDebugApi", out var lda)
                             && lda.ValueKind == JsonValueKind.True;

        if (legacyDebugApi && angularJs1 && !modernNg)
        {
            CheckFlag(
                "AngularJS debug mode is enabled (getAllAngularRootElements is available on AngularJS 1.x)",
                "Disable debug info in production ($compileProvider.debugInfoEnabled(false)) or ship a production build. This is not a source-map issue.");
        }
        else if (legacyDebugApi && modernNg)
        {
            CheckFlag(
                "Angular debug APIs are exposed (getAllAngularRootElements / ng.probe — development build)",
                "Call enableProdMode() before bootstrap (or ship a production Angular build). This is not AngularJS 1.x and not a source-map issue.");
        }
        else if (legacyDebugApi)
        {
            CheckFlag(
                "Legacy Angular debug helper getAllAngularRootElements is present",
                "Ship a production Angular build or disable debug APIs in production. This is not a source-map issue.");
        }
        Check("reduxDevtools",
            "Redux DevTools extension hook is present (__REDUX_DEVTOOLS_EXTENSION__)",
            "The Redux DevTools hook can come from a browser extension. Omit it from production bundles. This is not a source-map issue.");

        void Check(string prop, string desc, string recommendation)
        {
            if (debug.Value.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.True)
                CheckFlag(desc, recommendation);
        }

        void CheckFlag(string desc, string recommendation)
        {
            findings.Add(new SourceMapFinding
            {
                Severity = Severity.Low,
                Category = "DebugMode",
                Description = desc,
                Recommendation = recommendation
            });
        }
    }

    private async Task ProbeMapFiles(HashSet<string> urls, List<SourceMapFinding> findings,
        CancellationToken cancellationToken)
    {
        var semaphore = new SemaphoreSlim(10);
        var tasks = urls.Select(async url =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.TryAddWithoutValidation("User-Agent", $"Trowser/{App.Version} Security Scanner");
                using var response = await SharedClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken);

                var status = (int)response.StatusCode;
                if (status < 200 || status >= 300)
                    return;

                var ct = response.Content.Headers.ContentType?.MediaType ?? "";
                var bodyPrefix = await ReadContentPrefixAsync(response.Content, 65536);
                var textPrefix = Encoding.UTF8.GetString(bodyPrefix);

                // SPA catch-all: .map URL returns the HTML shell, not application/json with mappings/sources.
                if (ct.Contains("text/html", StringComparison.OrdinalIgnoreCase) ||
                    SniffLooksLikeHtml(textPrefix) ||
                    !LooksLikeSourceMapBody(textPrefix, ct))
                    return;

                lock (findings)
                {
                    findings.Add(new SourceMapFinding
                    {
                        Severity = Severity.High,
                        Category = "AccessibleMapFile",
                        Description = $"Source map file is publicly accessible (HTTP {status})",
                        Url = url,
                        Detail = $"Content-Type: {ct}, body prefix starts with JSON/source-map fields (mappings/sources)",
                        Recommendation = SourceMapAccessRecommendation
                    });
                }
            }
            catch { /* timeout or connection error */ }
            finally
            {
                semaphore.Release();
            }
        }).ToArray();

        await Task.WhenAll(tasks);
    }

    private static async Task<byte[]> ReadContentPrefixAsync(HttpContent content, int maxBytes)
    {
        await using var stream = await content.ReadAsStreamAsync();
        var buffer = new byte[maxBytes];
        var total = 0;
        int read;
        while (total < maxBytes &&
               (read = await stream.ReadAsync(buffer.AsMemory(total, maxBytes - total))) > 0)
            total += read;
        if (total == buffer.Length) return buffer;
        return buffer.AsSpan(0, total).ToArray();
    }

    private static bool SniffLooksLikeHtml(string s)
    {
        var t = s.TrimStart();
        if (t.Length == 0) return false;
        if (t.StartsWith("<!DOCTYPE", StringComparison.OrdinalIgnoreCase)) return true;
        if (t.StartsWith("<html", StringComparison.OrdinalIgnoreCase)) return true;
        if (t.StartsWith("<head", StringComparison.OrdinalIgnoreCase)) return true;
        if (t.StartsWith("<body", StringComparison.OrdinalIgnoreCase)) return true;
        // Common SPA mount points
        if (t.Contains("<app-root", StringComparison.OrdinalIgnoreCase)) return true;
        return t.StartsWith("<", StringComparison.Ordinal) && t.Contains("<meta ", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// True when Content-Type or JSON body indicates a real source map (not an HTML error/shell page).
    /// </summary>
    private static bool LooksLikeSourceMapBody(string textPrefix, string mediaType)
    {
        if (mediaType.Contains("text/html", StringComparison.OrdinalIgnoreCase))
            return false;

        var t = textPrefix.TrimStart();
        if (t.StartsWith(")]}'", StringComparison.Ordinal))
        {
            var i = t.IndexOf('\n');
            if (i >= 0 && i + 1 < t.Length)
                t = t[(i + 1)..].TrimStart();
        }

        if (!t.StartsWith('{') && !t.StartsWith('['))
            return false;

        try
        {
            using var doc = JsonDocument.Parse(t.Length > 262144 ? t[..262144] : t);
            var root = doc.RootElement;
            if (root.ValueKind == JsonValueKind.Object)
            {
                if (root.TryGetProperty("sections", out _) &&
                    (root.TryGetProperty("version", out var ver) && ver.ValueKind == JsonValueKind.Number))
                    return true;
                if (root.TryGetProperty("mappings", out _) || root.TryGetProperty("sources", out _))
                    return true;
            }
        }
        catch (JsonException)
        {
            return false;
        }

        return false;
    }

    private static string? ResolveUrl(string baseUrl, string relative)
    {
        if (Uri.TryCreate(relative, UriKind.Absolute, out _))
            return relative;
        if (Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri) &&
            Uri.TryCreate(baseUri, relative, out var resolved))
            return resolved.ToString();
        return null;
    }

    private static string TruncateContext(string text, int maxLen)
    {
        return text.Length <= maxLen ? text : text[..maxLen] + "...";
    }

    private static string UnwrapJsonString(string raw)
        => Trowser.Automation.WebViewScriptResult.UnwrapJsonString(raw);
}
