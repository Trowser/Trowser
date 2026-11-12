using System.Text.Json;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Audits CORS configuration by sending cross-origin requests with various Origin headers
/// and analyzing the Access-Control-Allow-* response headers. Detects overly permissive
/// configurations that could enable CSRF and data theft attacks.
///
/// Probes tested:
/// - Evil origin (https://evil.com) -- arbitrary third-party
/// - Null origin -- sandboxed iframes, data: URIs
/// - Subdomain variants of the target -- e.g., attacker.target.com
/// - Scheme downgrade (http:// for https:// sites)
/// - The site's own origin (baseline)
/// </summary>
public class CorsChecker
{
    private readonly WebView2 _webView;

    public CorsChecker(WebView2 webView)
    {
        _webView = webView ?? throw new ArgumentNullException(nameof(webView));
    }

    public async Task<CorsResult> RunAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var callbackId = $"__trowser_cors_{Guid.NewGuid():N}";
        var url = await GetCurrentUrl();

        if (string.IsNullOrEmpty(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
            throw new InvalidOperationException("Cannot run CORS audit: no valid URL loaded.");

        var siteOrigin = $"{uri.Scheme}://{uri.Host}" +
                         (uri.IsDefaultPort ? "" : $":{uri.Port}");

        var probeOrigins = BuildProbeOrigins(uri, siteOrigin);
        var script = BuildCorsScript(callbackId, url, probeOrigins);

        var startResult = await WebViewUiScript.RunAsync(_webView, script, cancellationToken,
            operationLabel: "CORS audit");
        if (startResult != "STARTED")
            throw new InvalidOperationException($"Failed to start CORS audit. Result: {startResult}");

        var deadline = DateTime.UtcNow.AddSeconds(15);
        string? json = null;

        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var doneCheck = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}_done']",
                cancellationToken, operationLabel: "CORS audit");
            if (doneCheck == "true")
            {
                json = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}']",
                    cancellationToken, operationLabel: "CORS audit");
                await WebViewUiScript.RunAsync(_webView,
                    $"delete window['{callbackId}']; delete window['{callbackId}_done']; 'OK'",
                    cancellationToken, operationLabel: "CORS audit");
                break;
            }
            await Task.Delay(100, cancellationToken);
        }

        if (string.IsNullOrEmpty(json))
            throw new TimeoutException("CORS audit did not complete within 15 seconds.");

        return ParseResults(json, url, siteOrigin);
    }

    private static List<(string origin, string label)> BuildProbeOrigins(Uri uri, string siteOrigin)
    {
        var probes = new List<(string origin, string label)>
        {
            (siteOrigin, "same-origin"),
            ("https://evil.com", "arbitrary-origin"),
            ("null", "null-origin"),
        };

        // Subdomain attack: attacker.target.com
        probes.Add(($"https://attacker.{uri.Host}", "subdomain-attack"));

        // Scheme downgrade: http instead of https
        if (uri.Scheme == "https")
            probes.Add(($"http://{uri.Host}", "scheme-downgrade"));

        // Prefix/suffix attacks
        probes.Add(($"https://{uri.Host}.evil.com", "suffix-attack"));

        return probes;
    }

    private static string BuildCorsScript(string callbackId, string url,
        List<(string origin, string label)> probes)
    {
        var probeArray = string.Join(",",
            probes.Select(p => $"{{origin:'{EscapeJs(p.origin)}',label:'{EscapeJs(p.label)}'}}"));

        return $@"
(function() {{
    window['{callbackId}'] = null;
    window['{callbackId}_done'] = false;

    var probes = [{probeArray}];
    var results = [];
    var completed = 0;

    probes.forEach(function(probe) {{
        var xhr = new XMLHttpRequest();
        xhr.open('OPTIONS', '{EscapeJs(url)}', true);
        xhr.setRequestHeader('Origin', probe.origin);
        xhr.setRequestHeader('Access-Control-Request-Method', 'GET');
        xhr.setRequestHeader('Access-Control-Request-Headers', 'Content-Type, Authorization');

        xhr.onload = xhr.onerror = xhr.ontimeout = function() {{
            var acao = xhr.getResponseHeader('Access-Control-Allow-Origin') || '';
            var acac = xhr.getResponseHeader('Access-Control-Allow-Credentials') || '';
            var acam = xhr.getResponseHeader('Access-Control-Allow-Methods') || '';
            var acah = xhr.getResponseHeader('Access-Control-Allow-Headers') || '';

            results.push({{
                origin: probe.origin,
                label: probe.label,
                status: xhr.status,
                allowOrigin: acao,
                allowCredentials: acac.toLowerCase() === 'true',
                allowMethods: acam,
                allowHeaders: acah
            }});

            // Also try a simple GET with Origin header to test non-preflight
            var xhr2 = new XMLHttpRequest();
            xhr2.open('GET', '{EscapeJs(url)}', true);
            xhr2.setRequestHeader('Origin', probe.origin);
            xhr2.onload = xhr2.onerror = xhr2.ontimeout = function() {{
                var acao2 = xhr2.getResponseHeader('Access-Control-Allow-Origin') || '';
                var acac2 = xhr2.getResponseHeader('Access-Control-Allow-Credentials') || '';

                if (acao2 && acao2 !== acao) {{
                    results.push({{
                        origin: probe.origin,
                        label: probe.label + '-simple',
                        status: xhr2.status,
                        allowOrigin: acao2,
                        allowCredentials: acac2.toLowerCase() === 'true',
                        allowMethods: '',
                        allowHeaders: ''
                    }});
                }}

                completed++;
                if (completed >= probes.length) {{
                    window['{callbackId}'] = JSON.stringify(results);
                    window['{callbackId}_done'] = true;
                }}
            }};
            xhr2.timeout = 5000;
            xhr2.send();
        }};
        xhr.timeout = 5000;
        xhr.send();
    }});

    return 'STARTED';
}})()";
    }

    private static CorsResult ParseResults(string json, string url, string siteOrigin)
    {
        using var doc = JsonDocument.Parse(json);
        var findings = new List<CorsFinding>();

        foreach (var el in doc.RootElement.EnumerateArray())
        {
            var origin = el.GetProperty("origin").GetString() ?? "";
            var label = el.GetProperty("label").GetString() ?? "";
            var allowOrigin = el.GetProperty("allowOrigin").GetString() ?? "";
            var allowCredentials = el.GetProperty("allowCredentials").GetBoolean();
            var allowMethods = el.GetProperty("allowMethods").GetString();
            var allowHeaders = el.GetProperty("allowHeaders").GetString();

            var reflected = !string.IsNullOrEmpty(allowOrigin) &&
                            allowOrigin.Equals(origin, StringComparison.OrdinalIgnoreCase);
            var wildcard = allowOrigin == "*";
            var isSameOrigin = label == "same-origin" || label == "same-origin-simple";

            Severity? severity = null;
            string? description = null;

            if (isSameOrigin)
            {
                // Same-origin is expected, no issue
            }
            else if (reflected && origin == "null")
            {
                severity = Severity.High;
                description = "Server reflects 'null' origin. Sandboxed iframes and data: URIs can " +
                              "make cross-origin requests." +
                              (allowCredentials ? " Combined with Allow-Credentials: true, " +
                               "this enables authenticated attacks." : "");
            }
            else if (reflected && allowCredentials)
            {
                severity = Severity.High;
                description = $"Server reflects arbitrary origin '{origin}' with " +
                              "Access-Control-Allow-Credentials: true. Any website can make " +
                              "authenticated cross-origin requests and read the response.";
            }
            else if (reflected)
            {
                severity = Severity.Medium;
                description = $"Server reflects origin '{origin}' in Access-Control-Allow-Origin. " +
                              "While credentials are not allowed, this permits cross-origin data reads.";
            }
            else if (wildcard && allowCredentials)
            {
                // Browsers block this combination, but it indicates misconfiguration
                severity = Severity.Medium;
                description = "Access-Control-Allow-Origin: * with Allow-Credentials: true. " +
                              "Browsers reject this combination, but it indicates a misconfigured CORS policy.";
            }
            else if (wildcard && !isSameOrigin)
            {
                severity = Severity.Low;
                description = "Access-Control-Allow-Origin: * allows any origin to read responses. " +
                              "This is acceptable for public APIs but risky for authenticated endpoints.";
            }

            findings.Add(new CorsFinding
            {
                Origin = origin,
                Reflected = reflected,
                Wildcard = wildcard,
                AllowOrigin = string.IsNullOrEmpty(allowOrigin) ? null : allowOrigin,
                AllowCredentials = allowCredentials,
                AllowMethods = string.IsNullOrEmpty(allowMethods) ? null : allowMethods,
                AllowHeaders = string.IsNullOrEmpty(allowHeaders) ? null : allowHeaders,
                Severity = severity,
                Description = description
            });
        }

        return new CorsResult
        {
            Url = url,
            Timestamp = DateTime.UtcNow,
            Findings = findings
        };
    }

    private async Task<string> GetCurrentUrl()
    {
        return await _webView.Dispatcher.InvokeAsync(() => _webView.Source?.ToString() ?? "");
    }

    private static string EscapeJs(string s) =>
        s.Replace("\\", "\\\\").Replace("'", "\\'").Replace("\n", "\\n").Replace("\r", "\\r");
}
