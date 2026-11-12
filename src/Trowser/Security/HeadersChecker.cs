using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Analyzes HTTP response headers for security misconfigurations.
/// Checks are based on OWASP, Mozilla Observatory, and securityheaders.com best practices.
///
/// Design principles to avoid false positives:
/// - Only the main document response is checked (not subresources)
/// - HSTS is only expected on HTTPS pages
/// - X-Frame-Options is not flagged if CSP frame-ancestors is set
/// - unsafe-inline in style-src is NOT penalized (too common, low risk)
/// - COOP/COEP/CORP are not checked (too aggressive, breaks many sites)
/// - Deprecated headers (Expect-CT, HPKP) are only flagged if present, not if absent
/// - Security Shadow uses <see cref="AnalyzeFromHeaders"/> on the navigation response (no live HEAD/GET)
/// </summary>
public class HeadersChecker
{
    private readonly WebView2 _webView;

    public HeadersChecker(WebView2 webView)
    {
        _webView = webView ?? throw new ArgumentNullException(nameof(webView));
    }

    /// <summary>
    /// Analyze security headers for the current page via an in-page HEAD/GET probe.
    /// Prefer <see cref="AnalyzeFromHeaders"/> when the document response is already in the network log
    /// (Security Shadow) — live probes can rotate CSRF/session tokens on apps like DVWA.
    /// </summary>
    public async Task<HeadersResult> RunAsync(
        Action<string>? markSyntheticForPageUrl = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var pageUrl = await WebViewUiScript.RunAsync(_webView, "location.href", cancellationToken,
            operationLabel: "Security headers audit");
        if (!string.IsNullOrWhiteSpace(pageUrl))
            markSyntheticForPageUrl?.Invoke(pageUrl);

        var callbackId = $"__trowser_headers_{Guid.NewGuid():N}";
        var fetchScript = BuildFetchScript(callbackId);

        var startResult = await WebViewUiScript.RunAsync(_webView, fetchScript, cancellationToken,
            operationLabel: "Security headers audit");
        if (startResult != "STARTED")
        {
            return new HeadersResult
            {
                Url = "",
                Timestamp = DateTime.UtcNow,
                IsHttps = false,
                RawHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
                Findings = new List<HeaderFinding>(),
                FetchError = $"Failed to start headers analysis: {startResult}"
            };
        }

        var deadline = DateTime.UtcNow.AddSeconds(10);
        string? json = null;

        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var doneCheck = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}_done']",
                cancellationToken, operationLabel: "Security headers audit");
            if (doneCheck == "true")
            {
                json = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}']",
                    cancellationToken, operationLabel: "Security headers audit");
                await WebViewUiScript.RunAsync(_webView,
                    $"delete window['{callbackId}']; delete window['{callbackId}_done']; 'OK'",
                    cancellationToken, operationLabel: "Security headers audit");
                break;
            }
            await Task.Delay(50, cancellationToken);
        }

        if (string.IsNullOrEmpty(json))
        {
            return new HeadersResult
            {
                Url = "",
                Timestamp = DateTime.UtcNow,
                IsHttps = false,
                RawHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
                Findings = new List<HeaderFinding>(),
                FetchError = "Timed out waiting for headers (10s)."
            };
        }

        return await AnalyzeFromFetchResultAsync(json);
    }

    /// <summary>
    /// Optional csp-evaluator enrichment when CSP is present (network-log or live probe results).
    /// </summary>
    public async Task<HeadersResult> EnrichCspEvaluationAsync(
        HeadersResult result,
        CancellationToken cancellationToken = default)
    {
        if (!string.IsNullOrEmpty(result.FetchError))
            return result;

        if (!result.RawHeaders.TryGetValue("content-security-policy", out var csp)
            || string.IsNullOrWhiteSpace(csp))
            return result;

        try
        {
            var cspFindings = await CspEvaluatorChecker.EvaluateAsync(_webView, csp, cancellationToken);
            var otherFindings = result.Findings
                .Where(f => !f.Header.Equals("Content-Security-Policy", StringComparison.OrdinalIgnoreCase))
                .ToList();
            otherFindings.AddRange(cspFindings);

            return new HeadersResult
            {
                Url = result.Url,
                Timestamp = result.Timestamp,
                IsHttps = result.IsHttps,
                RawHeaders = result.RawHeaders,
                Findings = otherFindings
            };
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"csp-evaluator enrichment failed; using built-in CSP checks: {ex.Message}");
            return result;
        }
    }

    /// <summary>
    /// Parse fetch results and enrich CSP analysis with csp-evaluator when a WebView is available.
    /// </summary>
    private async Task<HeadersResult> AnalyzeFromFetchResultAsync(string json)
    {
        var result = ParseAndAnalyze(json);
        return await EnrichCspEvaluationAsync(result);
    }

    /// <summary>
    /// Analyze security headers from an already-captured response (no network I/O).
    /// Used by Security Shadow so ambient audits do not re-request the document.
    /// </summary>
    public static bool IsNonHttpDocumentUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return true;
        if (url.StartsWith("about:", StringComparison.OrdinalIgnoreCase)
            || url.StartsWith("data:", StringComparison.OrdinalIgnoreCase)
            || url.StartsWith("blob:", StringComparison.OrdinalIgnoreCase))
            return true;
        return !Uri.TryCreate(url, UriKind.Absolute, out var uri)
               || uri.Scheme is not ("http" or "https");
    }

    public static HeadersResult AnalyzeFromHeaders(
        string url,
        IReadOnlyDictionary<string, string>? headers)
    {
        if (IsNonHttpDocumentUrl(url))
        {
            return new HeadersResult
            {
                Url = url ?? "",
                Timestamp = DateTime.UtcNow,
                IsHttps = false,
                RawHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
                Findings = [],
                FetchError = "Skipped header audit for non-HTTP(S) document URL."
            };
        }

        if (headers == null || headers.Count == 0)
        {
            return new HeadersResult
            {
                Url = url ?? "",
                Timestamp = DateTime.UtcNow,
                IsHttps = (url ?? "").StartsWith("https://", StringComparison.OrdinalIgnoreCase),
                RawHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
                Findings = new List<HeaderFinding>(),
                FetchError = "No response headers available to analyze."
            };
        }

        var normalized = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in headers)
        {
            if (string.IsNullOrEmpty(kv.Key)) continue;
            normalized[kv.Key] = kv.Value ?? "";
        }

        return AnalyzeNormalized(url ?? "", normalized);
    }

    #region Fetch Script

    private static string BuildFetchScript(string callbackId)
    {
        return $@"
(function() {{
    window['{callbackId}'] = null;
    window['{callbackId}_done'] = false;

    var url = location.href;

    fetch(url, {{ method: 'HEAD', credentials: 'same-origin', cache: 'no-store' }})
    .then(function(response) {{
        if (response.status === 405)
            return fetch(url, {{ credentials: 'same-origin', cache: 'no-store' }});
        return response;
    }})
    .then(function(response) {{
        var headers = {{}};
        response.headers.forEach(function(value, name) {{
            headers[name.toLowerCase()] = value;
        }});
        window['{callbackId}'] = JSON.stringify({{
            url: url,
            status: response.status,
            headers: headers
        }});
        window['{callbackId}_done'] = true;
    }})
    .catch(function(err) {{
        window['{callbackId}'] = JSON.stringify({{ error: err.message || String(err) }});
        window['{callbackId}_done'] = true;
    }});

    return 'STARTED';
}})()";
    }

    #endregion

    #region Analysis Engine

    private static HeadersResult ParseAndAnalyze(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (root.TryGetProperty("error", out var errorProp))
        {
            var err = errorProp.GetString() ?? "Unknown error";
            return new HeadersResult
            {
                Url = "",
                Timestamp = DateTime.UtcNow,
                IsHttps = false,
                RawHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
                Findings = new List<HeaderFinding>(),
                FetchError = err
            };
        }

        var url = root.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (root.TryGetProperty("headers", out var headersObj))
        {
            foreach (var prop in headersObj.EnumerateObject())
                headers[prop.Name] = prop.Value.GetString() ?? "";
        }

        return AnalyzeNormalized(url, headers);
    }

    private static HeadersResult AnalyzeNormalized(string url, Dictionary<string, string> headers)
    {
        if (IsNonHttpDocumentUrl(url))
        {
            return new HeadersResult
            {
                Url = url,
                Timestamp = DateTime.UtcNow,
                IsHttps = false,
                RawHeaders = headers,
                Findings = []
            };
        }

        var isHttps = url.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        var findings = new List<HeaderFinding>();

        CheckContentSecurityPolicy(headers, findings);
        CheckStrictTransportSecurity(headers, findings, isHttps);
        CheckXContentTypeOptions(headers, findings);
        CheckFrameProtection(headers, findings);
        CheckReferrerPolicy(headers, findings);
        CheckPermissionsPolicy(headers, findings);
        CheckInformationLeakage(headers, findings);
        CheckDeprecatedHeaders(headers, findings);
        CheckDuplicateSecurityHeaders(headers, findings);

        return new HeadersResult
        {
            Url = url,
            Timestamp = DateTime.UtcNow,
            IsHttps = isHttps,
            RawHeaders = headers,
            Findings = findings
        };
    }

    /// <summary>
    /// Analyze headers from any response (document or API). When CSP is present,
    /// only emit findings for unsafe directives (skip "missing CSP").
    /// </summary>
    public static List<HeaderFinding> AnalyzeCspFromHeaders(IReadOnlyDictionary<string, string> headers)
    {
        var dict = new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase);
        var findings = new List<HeaderFinding>();
        if (!dict.TryGetValue("content-security-policy", out var csp)
            || string.IsNullOrWhiteSpace(csp))
            return findings;

        CheckContentSecurityPolicy(dict, findings);
        // Drop the "missing CSP" case (won't fire when CSP is present) and keep unsafe-* / wildcard hits.
        return findings
            .Where(f => f.Header.Equals("Content-Security-Policy", StringComparison.OrdinalIgnoreCase)
                        && !string.IsNullOrEmpty(f.CurrentValue))
            .ToList();
    }

    /// <summary>
    /// Pick the document navigation response whose headers Shadow should audit.
    /// Prefers a Document entry for <paramref name="pageUrl"/> from the current page window;
    /// never returns Trowser-generated or HEAD probes.
    /// </summary>
    public static NetworkEntry? FindNavigationDocumentEntry(
        IReadOnlyList<NetworkEntry> pageEntries,
        string pageUrl)
    {
        if (pageEntries == null || pageEntries.Count == 0 || string.IsNullOrWhiteSpace(pageUrl))
            return null;

        var target = NormalizeUrlForHeaderMatch(pageUrl);
        bool UrlMatches(NetworkEntry e) =>
            string.Equals(NormalizeUrlForHeaderMatch(e.Url), target, StringComparison.OrdinalIgnoreCase);

        bool IsCandidate(NetworkEntry e) =>
            !e.IsTrowserGenerated
            && !e.Method.Equals("HEAD", StringComparison.OrdinalIgnoreCase)
            && e.ResponseHeaders is { Count: > 0 }
            && UrlMatches(e);

        // Newest Document match first, then any non-HEAD match for the page URL.
        return pageEntries
            .Where(e => IsCandidate(e)
                        && e.ResourceType.Equals("Document", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(e => e.Id)
            .FirstOrDefault()
            ?? pageEntries
                .Where(IsCandidate)
                .OrderByDescending(e => e.Id)
                .FirstOrDefault();
    }

    private static string NormalizeUrlForHeaderMatch(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return (url ?? "").TrimEnd('#');
        // Strip fragment; keep query (CSRF pages often differ only by query).
        return uri.GetLeftPart(UriPartial.Query);
    }

    #endregion

    #region Individual Checks

    private static void CheckContentSecurityPolicy(
        Dictionary<string, string> headers, List<HeaderFinding> findings)
    {
        const string reference = "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html";

        if (!headers.TryGetValue("content-security-policy", out var csp))
        {
            // Check for report-only variant -- it's better than nothing but doesn't enforce
            if (headers.ContainsKey("content-security-policy-report-only"))
            {
                findings.Add(new HeaderFinding
                {
                    Header = "Content-Security-Policy",
                    Severity = Severity.Medium,
                    Description = "CSP is in report-only mode -- violations are reported but not blocked.",
                    Recommendation = "Switch from Content-Security-Policy-Report-Only to Content-Security-Policy to enforce the policy.",
                    CurrentValue = "report-only",
                    Reference = reference
                });
                return;
            }

            findings.Add(new HeaderFinding
            {
                Header = "Content-Security-Policy",
                Severity = Severity.Low,
                Description = "No Content-Security-Policy header. The page has no CSP protection against XSS and injection attacks.",
                Recommendation = "Add a Content-Security-Policy header. Start with: default-src 'self'; script-src 'self'",
                Reference = reference
            });
            return;
        }

        var cspLower = csp.ToLowerInvariant();

        // Check for unsafe-inline in script-src (defeats XSS protection purpose of CSP)
        // Only flag it in script-src or default-src (not style-src -- that's common and low risk)
        if (CspDirectiveContains(cspLower, "script-src", "'unsafe-inline'") ||
            (!HasCspDirective(cspLower, "script-src") &&
             CspDirectiveContains(cspLower, "default-src", "'unsafe-inline'")))
        {
            findings.Add(new HeaderFinding
            {
                Header = "Content-Security-Policy",
                Severity = Severity.Medium,
                Description = "CSP allows 'unsafe-inline' for scripts, which defeats XSS protection.",
                Recommendation = "Remove 'unsafe-inline' from script-src. Use nonce or hash-based CSP instead.",
                CurrentValue = csp,
                Reference = reference
            });
        }

        // Check for unsafe-eval in script-src
        if (CspDirectiveContains(cspLower, "script-src", "'unsafe-eval'") ||
            (!HasCspDirective(cspLower, "script-src") &&
             CspDirectiveContains(cspLower, "default-src", "'unsafe-eval'")))
        {
            findings.Add(new HeaderFinding
            {
                Header = "Content-Security-Policy",
                Severity = Severity.Medium,
                Description = "CSP allows 'unsafe-eval' for scripts, permitting eval() and similar dynamic code execution.",
                Recommendation = "Remove 'unsafe-eval' from script-src if possible. Some frameworks (e.g., Angular) may require it.",
                CurrentValue = csp,
                Reference = reference
            });
        }

        // Check for wildcard * in script-src or default-src
        if (CspDirectiveContains(cspLower, "script-src", "*") ||
            (!HasCspDirective(cspLower, "script-src") &&
             CspDirectiveContains(cspLower, "default-src", "*")))
        {
            findings.Add(new HeaderFinding
            {
                Header = "Content-Security-Policy",
                Severity = Severity.Medium,
                Description = "CSP uses wildcard '*' for script sources, allowing scripts from any origin.",
                Recommendation = "Replace '*' with specific trusted origins in script-src.",
                CurrentValue = csp,
                Reference = reference
            });
        }

        var tt = TrustedTypesPosture.ParseCsp(csp);
        if (tt.RequireTrustedTypesForScript || tt.RequireTrustedTypesForHtml)
        {
            var req = tt.RequireTrustedTypesForScript && tt.RequireTrustedTypesForHtml
                ? "'script' and 'html'"
                : tt.RequireTrustedTypesForScript ? "'script'" : "'html'";
            findings.Add(new HeaderFinding
            {
                Header = "Content-Security-Policy",
                Severity = Severity.Info,
                Description =
                    $"CSP enforces require-trusted-types-for {req}. DOM sinks must use Trusted Types policies — " +
                    "correlate with POST /api/security/dom-flows for legacy innerHTML/document.write chains.",
                Recommendation =
                    "Audit createPolicy usage; ensure default policy covers all markup sinks. " +
                    "TT bypass is sink-specific — review dom-flows exec/markup chains manually.",
                CurrentValue = csp,
                Reference = "https://w3c.github.io/webappsec-trusted-types/dist/spec/"
            });
        }
        else if (tt.TrustedTypePolicyNames.Count > 0)
        {
            findings.Add(new HeaderFinding
            {
                Header = "Content-Security-Policy",
                Severity = Severity.Info,
                Description =
                    $"CSP lists trusted-types policies ({string.Join(", ", tt.TrustedTypePolicyNames.Take(6))}) " +
                    "without require-trusted-types-for — policies are optional until enforcement is enabled.",
                Recommendation = "Add require-trusted-types-for 'script' when ready to enforce.",
                CurrentValue = csp,
                Reference = reference
            });
        }
    }

    private static void CheckStrictTransportSecurity(
        Dictionary<string, string> headers, List<HeaderFinding> findings, bool isHttps)
    {
        const string reference = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html";

        if (!isHttps) return; // HSTS is only meaningful over HTTPS

        if (!headers.TryGetValue("strict-transport-security", out var hsts))
        {
            findings.Add(new HeaderFinding
            {
                Header = "Strict-Transport-Security",
                Severity = Severity.Low,
                Description = "No HSTS header on HTTPS page. Browsers can be tricked into using HTTP.",
                Recommendation = "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains",
                Reference = reference
            });
            return;
        }

        // Check max-age value
        var maxAgeMatch = Regex.Match(hsts, @"max-age\s*=\s*(\d+)", RegexOptions.IgnoreCase);
        if (maxAgeMatch.Success && long.TryParse(maxAgeMatch.Groups[1].Value, out var maxAge))
        {
            if (maxAge < 31536000) // Less than 1 year
            {
                findings.Add(new HeaderFinding
                {
                    Header = "Strict-Transport-Security",
                    Severity = Severity.Low,
                    Description = $"HSTS max-age is {maxAge} seconds ({maxAge / 86400} days). Recommended minimum is 1 year (31536000).",
                    Recommendation = "Increase max-age to at least 31536000 (1 year), ideally 63072000 (2 years).",
                    CurrentValue = hsts,
                    Reference = reference
                });
            }
        }
    }

    private static void CheckXContentTypeOptions(
        Dictionary<string, string> headers, List<HeaderFinding> findings)
    {
        if (!headers.TryGetValue("x-content-type-options", out var xcto))
        {
            findings.Add(new HeaderFinding
            {
                Header = "X-Content-Type-Options",
                Severity = Severity.Low,
                Description = "Missing X-Content-Type-Options header. Browsers may MIME-sniff responses, potentially executing content as a different type.",
                Recommendation = "Add: X-Content-Type-Options: nosniff",
                Reference = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
            });
        }
        else if (!xcto.Trim().Equals("nosniff", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new HeaderFinding
            {
                Header = "X-Content-Type-Options",
                Severity = Severity.Low,
                Description = $"X-Content-Type-Options has unexpected value. Should be 'nosniff'.",
                Recommendation = "Set to: X-Content-Type-Options: nosniff",
                CurrentValue = xcto,
                Reference = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
            });
        }
    }

    private static void CheckFrameProtection(
        Dictionary<string, string> headers, List<HeaderFinding> findings)
    {
        var hasXfo = headers.ContainsKey("x-frame-options");
        var hasCspFrameAncestors = headers.TryGetValue("content-security-policy", out var csp)
                                   && csp.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase);

        // Only flag if NEITHER protection is present
        if (!hasXfo && !hasCspFrameAncestors)
        {
            findings.Add(new HeaderFinding
            {
                Header = "X-Frame-Options",
                Severity = Severity.Low,
                Description = "No clickjacking protection. Neither X-Frame-Options nor CSP frame-ancestors is set.",
                Recommendation = "Add: X-Frame-Options: DENY (or use CSP frame-ancestors directive).",
                Reference = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
            });
        }
    }

    private static void CheckReferrerPolicy(
        Dictionary<string, string> headers, List<HeaderFinding> findings)
    {
        if (!headers.TryGetValue("referrer-policy", out var rp))
        {
            findings.Add(new HeaderFinding
            {
                Header = "Referrer-Policy",
                Severity = Severity.Info,
                Description = "No Referrer-Policy header. Full URL (including query strings) may be sent as referrer to external sites.",
                Recommendation = "Add: Referrer-Policy: strict-origin-when-cross-origin",
                Reference = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
            });
            return;
        }

        // Flag unsafe referrer policies that leak full URLs
        var rpLower = rp.Trim().ToLowerInvariant();
        if (rpLower == "unsafe-url")
        {
            findings.Add(new HeaderFinding
            {
                Header = "Referrer-Policy",
                Severity = Severity.Medium,
                Description = "Referrer-Policy is 'unsafe-url' -- full URL (including path and query) is sent to all origins.",
                Recommendation = "Change to: Referrer-Policy: strict-origin-when-cross-origin",
                CurrentValue = rp,
                Reference = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
            });
        }
    }

    private static void CheckPermissionsPolicy(
        Dictionary<string, string> headers, List<HeaderFinding> findings)
    {
        if (!headers.ContainsKey("permissions-policy"))
        {
            findings.Add(new HeaderFinding
            {
                Header = "Permissions-Policy",
                Severity = Severity.Info,
                Description = "No Permissions-Policy header. Browser features (camera, microphone, geolocation, etc.) are not explicitly restricted.",
                Recommendation = "Add: Permissions-Policy: camera=(), microphone=(), geolocation=() (customize to your needs).",
                Reference = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
            });
        }
    }

    private static void CheckInformationLeakage(
        Dictionary<string, string> headers, List<HeaderFinding> findings)
    {
        // Server header with version info
        if (headers.TryGetValue("server", out var server))
        {
            if (Regex.IsMatch(server, @"\d+\.\d+"))
            {
                findings.Add(new HeaderFinding
                {
                    Header = "Server",
                    Severity = Severity.Info,
                    Description = "Server header reveals software version, aiding attackers in finding known vulnerabilities.",
                    Recommendation = "Remove version information from the Server header or remove it entirely.",
                    CurrentValue = server,
                    Reference = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
                });
            }
        }

        // X-Powered-By should never be present
        if (headers.TryGetValue("x-powered-by", out var poweredBy))
        {
            findings.Add(new HeaderFinding
            {
                Header = "X-Powered-By",
                Severity = Severity.Info,
                Description = "X-Powered-By header exposes server technology, aiding attacker reconnaissance.",
                Recommendation = "Remove the X-Powered-By header entirely.",
                CurrentValue = poweredBy,
                Reference = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
            });
        }

        // ASP.NET version headers
        if (headers.TryGetValue("x-aspnet-version", out var aspnet))
        {
            findings.Add(new HeaderFinding
            {
                Header = "X-AspNet-Version",
                Severity = Severity.Info,
                Description = "X-AspNet-Version header exposes the .NET version.",
                Recommendation = "Remove by adding <httpRuntime enableVersionHeader=\"false\" /> to web.config.",
                CurrentValue = aspnet,
                Reference = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
            });
        }

        if (headers.TryGetValue("x-aspnetmvc-version", out var aspnetMvc))
        {
            findings.Add(new HeaderFinding
            {
                Header = "X-AspNetMvc-Version",
                Severity = Severity.Info,
                Description = "X-AspNetMvc-Version header exposes the ASP.NET MVC version.",
                Recommendation = "Remove by setting MvcHandler.DisableMvcResponseHeader = true in Global.asax.",
                CurrentValue = aspnetMvc,
                Reference = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
            });
        }
    }

    private static void CheckDeprecatedHeaders(
        Dictionary<string, string> headers, List<HeaderFinding> findings)
    {
        // X-XSS-Protection set to 1 can actually create vulnerabilities
        if (headers.TryGetValue("x-xss-protection", out var xxss))
        {
            var value = xxss.Trim();
            if (value != "0" && !string.IsNullOrEmpty(value))
            {
                findings.Add(new HeaderFinding
                {
                    Header = "X-XSS-Protection",
                    Severity = Severity.Low,
                    Description = "X-XSS-Protection is enabled. OWASP recommends setting this to '0' as it can create XSS vulnerabilities in otherwise safe sites. Use CSP instead.",
                    Recommendation = "Set to: X-XSS-Protection: 0 (or remove the header entirely).",
                    CurrentValue = xxss,
                    Reference = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
                });
            }
        }

        // Deprecated headers that shouldn't be used
        if (headers.ContainsKey("expect-ct"))
        {
            findings.Add(new HeaderFinding
            {
                Header = "Expect-CT",
                Severity = Severity.Low,
                Description = "Expect-CT is deprecated. All major browsers now enforce Certificate Transparency by default.",
                Recommendation = "Remove the Expect-CT header.",
                CurrentValue = headers["expect-ct"],
                Reference = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT"
            });
        }

        if (headers.ContainsKey("public-key-pins") || headers.ContainsKey("public-key-pins-report-only"))
        {
            var key = headers.ContainsKey("public-key-pins") ? "public-key-pins" : "public-key-pins-report-only";
            findings.Add(new HeaderFinding
            {
                Header = "Public-Key-Pins",
                Severity = Severity.Low,
                Description = "HTTP Public Key Pinning (HPKP) is deprecated and no longer supported by browsers. Misconfiguration can lock users out.",
                Recommendation = "Remove the Public-Key-Pins header.",
                CurrentValue = headers[key],
                Reference = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins"
            });
        }
    }

    /// <summary>
    /// Detect duplicate security headers by checking for comma-separated repeated values.
    /// Browsers merge duplicate HTTP headers into a single comma-separated value.
    /// Duplicate security headers can cause unpredictable browser behavior.
    /// </summary>
    private static void CheckDuplicateSecurityHeaders(
        Dictionary<string, string> headers, List<HeaderFinding> findings)
    {
        string[] securityHeaders =
        [
            "x-frame-options", "x-content-type-options", "strict-transport-security",
            "content-security-policy", "referrer-policy", "permissions-policy",
            "x-xss-protection"
        ];

        foreach (var headerName in securityHeaders)
        {
            if (!headers.TryGetValue(headerName, out var value)) continue;
            if (string.IsNullOrEmpty(value)) continue;

            // X-Frame-Options and X-Content-Type-Options should never have commas
            // For these, a comma means the header was sent multiple times
            if (headerName is "x-frame-options" or "x-content-type-options" or "x-xss-protection")
            {
                if (value.Contains(','))
                {
                    var parts = value.Split(',', StringSplitOptions.TrimEntries);
                    var distinct = parts.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                    var displayName = headers.Keys
                        .FirstOrDefault(k => k.Equals(headerName, StringComparison.OrdinalIgnoreCase)) ?? headerName;

                    if (distinct.Count == 1)
                    {
                        findings.Add(new HeaderFinding
                        {
                            Header = displayName,
                            Severity = Severity.Low,
                            Description = $"{displayName} header is duplicated ({parts.Length}× with identical value \"{distinct[0]}\"). " +
                                "While functionally harmless, duplicate headers may indicate a misconfigured reverse proxy or web server.",
                            Recommendation = $"Ensure {displayName} is set only once in the response chain (check web server, reverse proxy, and application).",
                            CurrentValue = value,
                            Reference = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/" + displayName
                        });
                    }
                    else
                    {
                        findings.Add(new HeaderFinding
                        {
                            Header = displayName,
                            Severity = Severity.Medium,
                            Description = $"{displayName} header is duplicated with conflicting values ({string.Join(" vs ", distinct.Select(d => $"\"{d}\""))}). " +
                                "Browser behavior with conflicting values is unpredictable.",
                            Recommendation = $"Set {displayName} exactly once with a single consistent value.",
                            CurrentValue = value,
                            Reference = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/" + displayName
                        });
                    }
                }
            }
        }
    }

    /// <summary>
    /// Check whether the server accepts HTTP TRACE requests (Cross-Site Tracing / XST risk).
    /// Must be called separately from RunAsync since it requires a server-side HTTP request.
    /// </summary>
    public static async Task<HeaderFinding?> CheckTraceMethodAsync(string url)
    {
        if (string.IsNullOrEmpty(url) || !Uri.TryCreate(url, UriKind.Absolute, out _))
            return null;

        try
        {
            using var handler = new HttpClientHandler
            {
                AllowAutoRedirect = false,
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
            var (status, body, allowHeader) = await TraceMethodAnalyzer.ProbeTraceAsync(url, TimeSpan.FromSeconds(5));

            if (TraceMethodAnalyzer.IsTraceEnabled(status, body, url, allowHeader))
            {
                return new HeaderFinding
                {
                    Header = "HTTP TRACE Method",
                    Severity = Severity.Medium,
                    Description = "The server responds to HTTP TRACE with a reflected request echo. " +
                        "TRACE can be used in Cross-Site Tracing (XST) attacks to steal credentials " +
                        "and session tokens, especially when combined with XSS vulnerabilities.",
                    Recommendation = "Disable the TRACE method on the web server. " +
                        "Apache: use 'TraceEnable off'. IIS: block via Request Filtering. Nginx: return 405 for TRACE.",
                    CurrentValue = $"TRACE {url} → {status} (echo confirmed)",
                    Reference = "https://owasp.org/www-community/attacks/Cross_Site_Tracing"
                };
            }
        }
        catch
        {
            // TRACE check is best-effort — network errors are not findings
        }

        return null;
    }

    #endregion

    #region CSP Helpers

    /// <summary>
    /// Check if a CSP directive contains a specific value.
    /// Handles the case where the directive falls back to default-src.
    /// </summary>
    private static bool CspDirectiveContains(string cspLower, string directive, string value)
    {
        // Split CSP into directives (separated by ;)
        var directives = cspLower.Split(';', StringSplitOptions.TrimEntries);
        foreach (var d in directives)
        {
            if (d.StartsWith(directive, StringComparison.OrdinalIgnoreCase))
            {
                var sources = d[(directive.Length)..].Trim();
                // For wildcard *, only match standalone * (not *.example.com)
                if (value == "*")
                    return sources.Split(' ').Any(s => s == "*");
                return sources.Contains(value, StringComparison.OrdinalIgnoreCase);
            }
        }
        return false;
    }

    private static bool HasCspDirective(string cspLower, string directive)
    {
        var directives = cspLower.Split(';', StringSplitOptions.TrimEntries);
        return directives.Any(d =>
            d.StartsWith(directive, StringComparison.OrdinalIgnoreCase));
    }

    #endregion

}
