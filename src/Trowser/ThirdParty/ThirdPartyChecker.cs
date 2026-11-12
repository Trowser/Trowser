using System.IO;
using System.Reflection;
using System.Text.Json;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Automation;

namespace Trowser.ThirdParty;

/// <summary>
/// Inventories all third-party resources loaded by the page (scripts, stylesheets,
/// iframes, fonts). Checks domains, transfer sizes, and SRI coverage.
/// </summary>
public class ThirdPartyChecker
{
    private readonly WebView2 _webView;
    private string? _tldtsScript;

    public ThirdPartyChecker(WebView2 webView)
    {
        _webView = webView ?? throw new ArgumentNullException(nameof(webView));
    }

    /// <summary>
    /// Run the third-party resource inventory on the current page.
    /// </summary>
    public async Task<ThirdPartyResult> RunAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var callbackId = $"__trowser_thirdparty_{Guid.NewGuid():N}";
        var tldtsScript = await GetTldtsScriptAsync();
        var scanScript = tldtsScript + "\n" + BuildScannerScript(callbackId);

        var startResult = await WebViewUiScript.RunAsync(_webView, scanScript, cancellationToken,
            operationLabel: "Third-party audit");
        if (startResult != "STARTED")
        {
            throw new InvalidOperationException(
                $"Failed to start third-party audit. Result: {startResult}");
        }

        var deadline = DateTime.UtcNow.AddSeconds(15);
        string? json = null;

        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var doneCheck = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}_done']",
                cancellationToken, operationLabel: "Third-party audit");
            if (doneCheck == "true")
            {
                json = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}']",
                    cancellationToken, operationLabel: "Third-party audit");
                await WebViewUiScript.RunAsync(_webView,
                    $"delete window['{callbackId}']; delete window['{callbackId}_done']; 'OK'",
                    cancellationToken, operationLabel: "Third-party audit");
                break;
            }
            await Task.Delay(100, cancellationToken);
        }

        if (string.IsNullOrEmpty(json))
        {
            throw new TimeoutException("Third-party audit did not complete within 15 seconds.");
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
        var pageHost = location.hostname;

        function isThirdParty(url) {{
            try {{
                var u = new URL(url, location.href);
                if (!u.hostname) return null;

                if (typeof tldts !== 'undefined' && typeof tldts.getDomain === 'function') {{
                    var pageDomain = tldts.getDomain(location.href);
                    var resourceDomain = tldts.getDomain(u.href);
                    if (resourceDomain && pageDomain !== resourceDomain)
                        return resourceDomain;
                    return null;
                }}

                // Fall back to hostname compare if tldts missing
                if (u.hostname === pageHost) return null;
                return u.hostname;
            }} catch(e) {{
                return null;
            }}
        }}

        // Primary source: Performance API — what was actually loaded
        var perfEntries = [];
        try {{
            perfEntries = performance.getEntriesByType('resource');
        }} catch(e) {{}}

        // Build a lookup from DOM elements for SRI and type info
        var domLookup = {{}};
        var selectors = 'script[src], link[rel=""stylesheet""][href], iframe[src], link[rel=""preload""][href]';
        var elements = document.querySelectorAll(selectors);
        for (var i = 0; i < elements.length; i++) {{
            var el = elements[i];
            var url = el.getAttribute('src') || el.getAttribute('href') || '';
            if (!url) continue;
            try {{
                var fullUrl = new URL(url, location.href).href;
                var tag = el.tagName.toLowerCase();
                var type = 'other';
                if (tag === 'script') type = 'script';
                else if (tag === 'link') {{
                    var rel = (el.getAttribute('rel') || '').toLowerCase();
                    if (rel === 'stylesheet') type = 'stylesheet';
                    else if (rel === 'preload') {{
                        var asAttr = (el.getAttribute('as') || '').toLowerCase();
                        if (asAttr === 'style') type = 'stylesheet';
                        else if (asAttr === 'script') type = 'script';
                        else if (asAttr === 'font') type = 'font';
                    }}
                }}
                else if (tag === 'iframe') type = 'iframe';

                var integrity = el.getAttribute('integrity') || '';
                domLookup[fullUrl] = {{
                    type: type,
                    hasSri: integrity.length > 0,
                    integrityHash: integrity || null
                }};
            }} catch(e) {{}}
        }}

        // Map initiatorType from Performance API to resource type
        function perfTypeToType(entry) {{
            var it = entry.initiatorType || '';
            if (it === 'script') return 'script';
            if (it === 'link' || it === 'css') return 'stylesheet';
            if (it === 'iframe') return 'iframe';
            // Check DOM lookup for more specific type
            var dom = domLookup[entry.name];
            if (dom) return dom.type;
            return 'other';
        }}

        // Detect fonts from Performance API (initiatorType 'css' or by file extension)
        function isFontEntry(entry) {{
            var name = entry.name.toLowerCase();
            return /\.(woff2?|ttf|otf|eot)(\?|#|$)/.test(name);
        }}

        var resources = [];
        var seen = {{}};

        for (var i = 0; i < perfEntries.length; i++) {{
            var entry = perfEntries[i];
            var url = entry.name;
            if (seen[url]) continue;

            var domain = isThirdParty(url);
            if (!domain) continue;

            seen[url] = true;
            var dom = domLookup[url];
            var type = isFontEntry(entry) ? 'font' : perfTypeToType(entry);

            var hostname = '';
            try {{ hostname = new URL(url, location.href).hostname; }} catch(e) {{}}

            resources.push({{
                url: url,
                domain: domain,
                hostname: hostname,
                etldPlus1: domain,
                type: type,
                sizeBytes: entry.transferSize || 0,
                hasSri: dom ? dom.hasSri : false,
                integrityHash: dom ? dom.integrityHash : null
            }});
        }}

        var results = {{
            url: location.href,
            timestamp: new Date().toISOString(),
            resources: resources
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

    #region tldts Script Loading

    private async Task<string> GetTldtsScriptAsync()
    {
        if (_tldtsScript != null) return _tldtsScript;

        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream("Trowser.Resources.tldts.umd.min.js");

        if (stream == null)
        {
            throw new InvalidOperationException(
                "tldts script not found as embedded resource. " +
                "Ensure tldts.umd.min.js is in Resources/ and marked as EmbeddedResource in the .csproj.");
        }

        using var reader = new StreamReader(stream);
        _tldtsScript = await reader.ReadToEndAsync();
        return _tldtsScript;
    }

    #endregion

    #region Result Parsing

    private ThirdPartyResult ParseResults(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (root.TryGetProperty("error", out var errorProp))
        {
            throw new InvalidOperationException($"Third-party audit error: {errorProp.GetString()}");
        }

        var url = root.TryGetProperty("url", out var urlProp) ? urlProp.GetString() ?? "" : "";

        var resources = new List<ThirdPartyResource>();
        if (root.TryGetProperty("resources", out var array) && array.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in array.EnumerateArray())
            {
                var domain = item.TryGetProperty("domain", out var d) ? d.GetString() ?? "" : "";
                resources.Add(new ThirdPartyResource
                {
                    Url = item.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "",
                    Domain = domain,
                    Hostname = item.TryGetProperty("hostname", out var hn) && hn.ValueKind == JsonValueKind.String
                        ? hn.GetString() ?? "" : "",
                    EtldPlus1 = item.TryGetProperty("etldPlus1", out var e1) && e1.ValueKind == JsonValueKind.String
                        ? e1.GetString() ?? domain : domain,
                    Type = item.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "",
                    SizeBytes = item.TryGetProperty("sizeBytes", out var s) ? s.GetInt64() : 0,
                    HasSri = item.TryGetProperty("hasSri", out var sri) && sri.GetBoolean(),
                    IntegrityHash = item.TryGetProperty("integrityHash", out var hash) && hash.ValueKind == JsonValueKind.String
                        ? hash.GetString() : null
                });
            }
        }

        return new ThirdPartyResult
        {
            Url = url,
            Timestamp = DateTime.UtcNow,
            Resources = resources
        };
    }

    #endregion

}
