using System.Text.Json;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Automation;

namespace Trowser.MixedContent;

/// <summary>
/// Scans the current page for mixed content: HTTP resources loaded on an HTTPS page.
/// Injects JavaScript via WebView2, polls for results, and parses the JSON response.
/// </summary>
public class MixedContentChecker
{
    private readonly WebView2 _webView;

    public MixedContentChecker(WebView2 webView)
    {
        _webView = webView ?? throw new ArgumentNullException(nameof(webView));
    }

    /// <summary>
    /// Run the mixed content audit on the current page.
    /// </summary>
    public async Task<MixedContentResult> RunAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var callbackId = $"__trowser_mixedcontent_{Guid.NewGuid():N}";
        var scanScript = BuildScannerScript(callbackId);

        var startResult = await WebViewUiScript.RunAsync(_webView, scanScript, cancellationToken,
            operationLabel: "Mixed content scan");
        if (startResult != "STARTED")
        {
            throw new InvalidOperationException(
                $"Failed to start mixed content audit. Result: {startResult}");
        }

        var deadline = DateTime.UtcNow.AddSeconds(10);
        string? json = null;

        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var doneCheck = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}_done']",
                cancellationToken, operationLabel: "Mixed content scan");
            if (doneCheck == "true")
            {
                json = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}']",
                    cancellationToken, operationLabel: "Mixed content scan");
                await WebViewUiScript.RunAsync(_webView,
                    $"delete window['{callbackId}']; delete window['{callbackId}_done']; 'OK'",
                    cancellationToken, operationLabel: "Mixed content scan");
                break;
            }
            await Task.Delay(50, cancellationToken);
        }

        if (string.IsNullOrEmpty(json))
        {
            throw new TimeoutException("Mixed content audit did not complete within 10 seconds.");
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
        var findings = [];

        var isHttps = location.protocol === 'https:';
        if (!isHttps) {{
            var result = {{
                url: location.href,
                isHttps: false,
                findings: []
            }};
            window['{callbackId}'] = JSON.stringify(result);
            window['{callbackId}_done'] = true;
            return 'STARTED';
        }}

        function isHttp(url) {{
            if (!url) return false;
            var trimmed = url.trim();
            return trimmed.indexOf('http://') === 0;
        }}

        function addFinding(tag, attr, url, severity, context) {{
            findings.push({{
                tag: tag,
                attribute: attr,
                url: url,
                severity: severity,
                context: context || null
            }});
        }}

        // High severity: scripts, iframes, objects, embeds
        var scripts = document.querySelectorAll('script[src]');
        for (var i = 0; i < scripts.length; i++) {{
            var src = scripts[i].getAttribute('src');
            if (isHttp(src)) addFinding('script', 'src', src, 'high', 'active mixed content — script');
        }}

        var iframes = document.querySelectorAll('iframe[src]');
        for (var i = 0; i < iframes.length; i++) {{
            var src = iframes[i].getAttribute('src');
            if (isHttp(src)) addFinding('iframe', 'src', src, 'high', 'active mixed content — iframe');
        }}

        var objects = document.querySelectorAll('object[data]');
        for (var i = 0; i < objects.length; i++) {{
            var data = objects[i].getAttribute('data');
            if (isHttp(data)) addFinding('object', 'data', data, 'high', 'active mixed content — object');
        }}

        var embeds = document.querySelectorAll('embed[src]');
        for (var i = 0; i < embeds.length; i++) {{
            var src = embeds[i].getAttribute('src');
            if (isHttp(src)) addFinding('embed', 'src', src, 'high', 'active mixed content — embed');
        }}

        // Medium severity: stylesheets
        var stylesheetLinks = document.querySelectorAll('link[rel=""stylesheet""][href]');
        for (var i = 0; i < stylesheetLinks.length; i++) {{
            var href = stylesheetLinks[i].getAttribute('href');
            if (isHttp(href)) addFinding('link', 'href', href, 'medium', 'stylesheet');
        }}

        // Medium severity: images
        var imgs = document.querySelectorAll('img[src]');
        for (var i = 0; i < imgs.length; i++) {{
            var src = imgs[i].getAttribute('src');
            if (isHttp(src)) addFinding('img', 'src', src, 'medium', 'image src');
        }}

        // Medium severity: img srcset
        var imgsSrcset = document.querySelectorAll('img[srcset]');
        for (var i = 0; i < imgsSrcset.length; i++) {{
            var srcset = imgsSrcset[i].getAttribute('srcset');
            if (srcset) {{
                var parts = srcset.split(',');
                for (var j = 0; j < parts.length; j++) {{
                    var url = parts[j].trim().split(/\s+/)[0];
                    if (isHttp(url)) addFinding('img', 'srcset', url, 'medium', 'image srcset');
                }}
            }}
        }}

        // Medium severity: video, audio, source
        var videos = document.querySelectorAll('video[src]');
        for (var i = 0; i < videos.length; i++) {{
            var src = videos[i].getAttribute('src');
            if (isHttp(src)) addFinding('video', 'src', src, 'medium', 'video src');
        }}

        var videoPosters = document.querySelectorAll('video[poster]');
        for (var i = 0; i < videoPosters.length; i++) {{
            var poster = videoPosters[i].getAttribute('poster');
            if (isHttp(poster)) addFinding('video', 'poster', poster, 'medium', 'video poster');
        }}

        var sources = document.querySelectorAll('source[src]');
        for (var i = 0; i < sources.length; i++) {{
            var src = sources[i].getAttribute('src');
            if (isHttp(src)) addFinding('source', 'src', src, 'medium', 'media source');
        }}

        var audios = document.querySelectorAll('audio[src]');
        for (var i = 0; i < audios.length; i++) {{
            var src = audios[i].getAttribute('src');
            if (isHttp(src)) addFinding('audio', 'src', src, 'medium', 'audio src');
        }}

        // Medium severity: form action
        var forms = document.querySelectorAll('form[action]');
        for (var i = 0; i < forms.length; i++) {{
            var action = forms[i].getAttribute('action');
            if (isHttp(action)) addFinding('form', 'action', action, 'medium', 'form action — submitting to HTTP leaks data');
        }}

        // Low severity: other link[href] (non-stylesheet)
        var otherLinks = document.querySelectorAll('link[href]');
        for (var i = 0; i < otherLinks.length; i++) {{
            var rel = (otherLinks[i].getAttribute('rel') || '').toLowerCase();
            if (rel === 'stylesheet') continue; // already handled above
            var href = otherLinks[i].getAttribute('href');
            if (isHttp(href)) addFinding('link', 'href', href, 'low', 'link rel=' + rel);
        }}

        var result = {{
            url: location.href,
            isHttps: true,
            findings: findings
        }};

        window['{callbackId}'] = JSON.stringify(result);
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

    private MixedContentResult ParseResults(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (root.TryGetProperty("error", out var errorProp))
        {
            throw new InvalidOperationException($"Mixed content audit error: {errorProp.GetString()}");
        }

        var url = root.TryGetProperty("url", out var urlProp) ? urlProp.GetString() ?? "" : "";
        var isHttps = root.TryGetProperty("isHttps", out var httpsProp) && httpsProp.GetBoolean();

        var findings = new List<MixedContentFinding>();
        if (root.TryGetProperty("findings", out var findingsArray) && findingsArray.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in findingsArray.EnumerateArray())
            {
                findings.Add(new MixedContentFinding
                {
                    Tag = item.TryGetProperty("tag", out var tag) ? tag.GetString() ?? "" : "",
                    Attribute = item.TryGetProperty("attribute", out var attr) ? attr.GetString() ?? "" : "",
                    Url = item.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "",
                    Severity = ParseSeverity(item.TryGetProperty("severity", out var sev) ? sev.GetString() ?? "" : ""),
                    Context = item.TryGetProperty("context", out var ctx) && ctx.ValueKind != JsonValueKind.Null
                        ? ctx.GetString()
                        : null
                });
            }
        }

        return new MixedContentResult
        {
            Url = url,
            Timestamp = DateTime.UtcNow,
            IsHttps = isHttps,
            Findings = findings
        };
    }

    private static MixedContentSeverity ParseSeverity(string severity)
    {
        return severity.ToLowerInvariant() switch
        {
            "high" => MixedContentSeverity.High,
            "medium" => MixedContentSeverity.Medium,
            "low" => MixedContentSeverity.Low,
            _ => MixedContentSeverity.Low
        };
    }

    #endregion

}
