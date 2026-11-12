using System.Diagnostics;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Verifies session invalidation after logout — replay protected endpoint with pre-logout cookie.
/// </summary>
public sealed class LogoutInvalidationProbe
{
    private readonly AutomationContext _ctx;

    public LogoutInvalidationProbe(AutomationContext context) => _ctx = context;

    public sealed class ProbeOptions
    {
        public string? LogoutUrl { get; set; }
        public string? LogoutMethod { get; set; }
        public string? LogoutBody { get; set; }
        public string? LogoutContentType { get; set; }
        public string? ProtectedUrl { get; set; }
        public int TimeoutMs { get; set; } = 15000;
        public bool RegisterChainFindings { get; set; } = true;
    }

    public sealed class ProbeFinding
    {
        public string Category { get; init; } = "logout-invalidation";
        public string Severity { get; init; } = "high";
        public string Outcome { get; init; } = "SESSION_STILL_VALID";
        public string LogoutUrl { get; init; } = "";
        public string ProtectedUrl { get; init; } = "";
        public int PreLogoutStatus { get; init; }
        public int PostLogoutStatus { get; init; }
        public int LogoutHttpStatus { get; init; }
        public string Detail { get; init; } = "";
    }

    public sealed class ProbeResult
    {
        public string Message { get; init; } = "";
        public int ElapsedMs { get; init; }
        public List<ProbeFinding> Findings { get; init; } = [];
        public string? LogoutUrlUsed { get; init; }
        public string? LogoutMethodUsed { get; init; }
        public string? ProtectedUrlUsed { get; init; }
        public bool SessionInvalidated { get; init; }
        public bool LogoutPerformed { get; init; }
    }

    public async Task<ProbeResult> RunAsync(ProbeOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var pageUri))
            throw new InvalidOperationException("Navigate to a page while logged in before running logout-invalidation-probe.");

        var protectedUrl = ProtectedResourceOracle.SelectProtectedUrl(_ctx, pageUri, options.ProtectedUrl);
        var logoutAction = await ResolveLogoutActionAsync(pageUri, options, ct);

        if (string.IsNullOrEmpty(protectedUrl))
            throw new InvalidOperationException(
                "No protected URL found — pass protectedUrl or browse an authenticated page first (error/404 pages are excluded).");

        if (logoutAction == null)
            throw new InvalidOperationException("No logout URL found — pass logoutUrl or browse logout flow first.");

        logoutAction = ApplyLogoutOverrides(logoutAction, options);

        var logoutUrl = logoutAction.Url;
        var logoutMethod = logoutAction.Method;
        var logoutHeaders = logoutAction.Headers;
        var logoutBody = logoutAction.BodyTemplate;

        if (UrlsEquivalent(logoutUrl, protectedUrl))
        {
            return new ProbeResult
            {
                Message = "Logout and protected URLs are the same — cannot verify session invalidation. Pass distinct logoutUrl and protectedUrl after browsing a logged-in app.",
                ElapsedMs = (int)sw.ElapsedMilliseconds,
                ProtectedUrlUsed = protectedUrl,
                LogoutUrlUsed = logoutUrl,
                LogoutMethodUsed = logoutMethod
            };
        }

        if (Uri.TryCreate(protectedUrl, UriKind.Absolute, out var protectedUri)
            && AuthProbeDiscovery.LooksLikePublicHomepage(protectedUri)
            && !await HasSessionCookieForHostAsync(pageUri.Host))
        {
            return new ProbeResult
            {
                Message = "No session cookie on this host and protected URL looks like a public homepage — log in first, then rerun logout-invalidation-probe.",
                ElapsedMs = (int)sw.ElapsedMilliseconds,
                ProtectedUrlUsed = protectedUrl,
                LogoutUrlUsed = logoutUrl,
                LogoutMethodUsed = logoutMethod
            };
        }

        var pre = await SecurityProbeHttp.FetchAsync(_ctx, protectedUrl, "GET", null, null, options.TimeoutMs, true, ct);
        if (pre.Status is 401 or 403)
        {
            return new ProbeResult
            {
                Message = "Protected URL returns 401/403 — log in first, then rerun logout-invalidation-probe.",
                ElapsedMs = (int)sw.ElapsedMilliseconds,
                ProtectedUrlUsed = protectedUrl,
                LogoutUrlUsed = logoutUrl,
                LogoutMethodUsed = logoutMethod
            };
        }

        if (AuthAccessHeuristics.LooksLikeLoginPage(pre.Body))
        {
            return new ProbeResult
            {
                Message = "Protected URL shows a login page — log in first, then rerun logout-invalidation-probe.",
                ElapsedMs = (int)sw.ElapsedMilliseconds,
                ProtectedUrlUsed = protectedUrl,
                LogoutUrlUsed = logoutUrl,
                LogoutMethodUsed = logoutMethod
            };
        }

        var cookiesBefore = await AuthProbeDiscovery.GetSessionCookiesAsync(_ctx);
        // Intentional logout replay must reach the server — SecurityUrlPolicy blocks termination URLs by default.
        var logoutResult = await SecurityProbeHttp.FetchAsync(
            _ctx, logoutUrl, logoutMethod, logoutHeaders, logoutBody, options.TimeoutMs, true, ct,
            allowSessionTerminationUrls: true);

        if (ShouldRetryLogoutAsPost(logoutResult.Status, logoutMethod, logoutAction.Source))
        {
            logoutMethod = "POST";
            logoutResult = await SecurityProbeHttp.FetchAsync(
                _ctx, logoutUrl, logoutMethod, logoutHeaders, logoutBody, options.TimeoutMs, true, ct,
                allowSessionTerminationUrls: true);
        }

        if (!LogoutStepSucceeded(logoutResult, logoutAction.Source))
        {
            var hint = logoutAction.Source.Contains("hint", StringComparison.OrdinalIgnoreCase)
                ? " Logout URL came from a built-in path hint — verify logoutUrl/logoutMethod for this app."
                : "";
            return new ProbeResult
            {
                Message =
                    $"Logout step did not succeed (HTTP {logoutResult.Status} on {logoutMethod} {logoutUrl}) — " +
                    "session invalidation was not tested." + hint,
                ElapsedMs = (int)sw.ElapsedMilliseconds,
                ProtectedUrlUsed = protectedUrl,
                LogoutUrlUsed = logoutUrl,
                LogoutMethodUsed = logoutMethod,
                LogoutPerformed = false
            };
        }

        var cookiesAfter = await AuthProbeDiscovery.GetSessionCookiesAsync(_ctx);
        var post = await SecurityProbeHttp.FetchAsync(_ctx, protectedUrl, "GET", null, null, options.TimeoutMs, true, ct);

        if (SessionLooksInvalidated(pre, post)
            || SessionCookiesLookCleared(cookiesBefore, cookiesAfter))
        {
            return new ProbeResult
            {
                Message = "Session invalidated after logout — protected URL denied or redirected to login.",
                ElapsedMs = (int)sw.ElapsedMilliseconds,
                SessionInvalidated = true,
                LogoutPerformed = true,
                ProtectedUrlUsed = protectedUrl,
                LogoutUrlUsed = logoutUrl,
                LogoutMethodUsed = logoutMethod
            };
        }

        if (AuthAccessHeuristics.LooksLikeGrantedAccess(post.Body, pre.Body)
            && !ProtectedResourceOracle.IsUnreliableProtectedOracle(protectedUrl)
            && !AuthAccessHeuristics.LooksLikeGenericErrorPage(post.Body, protectedUrl))
        {
            var finding = new ProbeFinding
            {
                LogoutUrl = logoutUrl,
                ProtectedUrl = protectedUrl,
                PreLogoutStatus = pre.Status,
                PostLogoutStatus = post.Status,
                LogoutHttpStatus = logoutResult.Status,
                Detail =
                    $"Protected resource still accessible after logout (HTTP {post.Status} on {protectedUrl}; " +
                    $"logout {logoutMethod} {logoutUrl} returned HTTP {logoutResult.Status})."
            };

            if (options.RegisterChainFindings)
            {
                AuthProbeDiscovery.RegisterChainFinding(_ctx, finding.Category, finding.Severity,
                    finding.Detail, protectedUrl, "GET", finding.Detail);
            }

            return new ProbeResult
            {
                Message = finding.Detail,
                ElapsedMs = (int)sw.ElapsedMilliseconds,
                Findings = [finding],
                ProtectedUrlUsed = protectedUrl,
                LogoutUrlUsed = logoutUrl,
                LogoutMethodUsed = logoutMethod,
                LogoutPerformed = true
            };
        }

        return new ProbeResult
        {
            Message = "Inconclusive — post-logout response did not clearly grant or deny access.",
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            ProtectedUrlUsed = protectedUrl,
            LogoutUrlUsed = logoutUrl,
            LogoutMethodUsed = logoutMethod,
            LogoutPerformed = true
        };
    }

    /// <summary>
    /// Applies an explicit logout method or body to a discovered action. The method is honored
    /// even when the URL came from the page, the network log, or a path hint.
    /// </summary>
    public static AuthFormDiscovery.ResolvedForm ApplyLogoutOverrides(
        AuthFormDiscovery.ResolvedForm resolved,
        ProbeOptions options)
    {
        var method = string.IsNullOrWhiteSpace(options.LogoutMethod)
            ? resolved.Method
            : options.LogoutMethod.Trim().ToUpperInvariant();
        var body = options.LogoutBody ?? resolved.BodyTemplate;
        if (string.IsNullOrWhiteSpace(options.LogoutMethod)
            && !string.IsNullOrWhiteSpace(options.LogoutBody)
            && method is "GET" or "HEAD")
            method = "POST";

        Dictionary<string, string>? headers = resolved.Headers == null
            ? null
            : new Dictionary<string, string>(resolved.Headers, StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(options.LogoutContentType))
        {
            headers ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            headers["Content-Type"] = options.LogoutContentType!;
        }
        else if (method is "POST" or "PUT" or "PATCH" && !string.IsNullOrEmpty(body))
        {
            headers ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (!headers.ContainsKey("Content-Type"))
            {
                var trimmed = body.TrimStart();
                headers["Content-Type"] = trimmed.StartsWith('{') || trimmed.StartsWith('[')
                    ? "application/json"
                    : "application/x-www-form-urlencoded";
            }
        }

        var source = resolved.Source;
        if (!string.IsNullOrWhiteSpace(options.LogoutMethod)
            || !string.IsNullOrWhiteSpace(options.LogoutBody)
            || !string.IsNullOrWhiteSpace(options.LogoutContentType))
            source = string.IsNullOrEmpty(source) ? "override" : source + "+override";

        return new AuthFormDiscovery.ResolvedForm
        {
            Url = resolved.Url,
            Method = method,
            BodyTemplate = body,
            Headers = headers,
            Source = source
        };
    }

    /// <summary>Inferred GET logout that the server refuses is retried once as POST.</summary>
    public static bool ShouldRetryLogoutAsPost(int status, string method, string source) =>
        status == 405
        && method.Equals("GET", StringComparison.OrdinalIgnoreCase)
        && !source.Contains("override", StringComparison.OrdinalIgnoreCase);

    private static bool LogoutStepSucceeded(SecurityProbeHttp.FetchResult logoutResult, string source)
    {
        if (logoutResult.Status is 404 or 405 or 410)
            return false;
        if (logoutResult.Status >= 500)
            return false;
        if (logoutResult.Status is >= 200 and < 400)
            return true;
        return false;
    }

    private static bool SessionCookiesLookCleared(
        List<(string Name, string Value)> before,
        List<(string Name, string Value)> after)
    {
        if (before.Count == 0)
            return false;
        if (after.Count == 0)
            return true;

        foreach (var (name, value) in before)
        {
            var match = after.FirstOrDefault(c => c.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (match == default || !string.Equals(match.Value, value, StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    private static bool SessionLooksInvalidated(SecurityProbeHttp.FetchResult pre, SecurityProbeHttp.FetchResult post)
    {
        if (post.Status is 401 or 403)
            return true;

        if (AuthAccessHeuristics.LooksLikeDeniedAccess(post.Body, pre.Body))
            return true;

        if (pre.Status is 200 or 302 && post.Status is 302 or 401 or 403
            && AuthAccessHeuristics.LooksLikeLoginPage(post.Body))
            return true;

        return false;
    }

    private async Task<AuthFormDiscovery.ResolvedForm?> ResolveLogoutActionAsync(
        Uri pageUri,
        ProbeOptions options,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (!string.IsNullOrWhiteSpace(options.LogoutUrl))
        {
            var abs = options.LogoutUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                ? options.LogoutUrl
                : pageUri.GetLeftPart(UriPartial.Authority)
                  + (options.LogoutUrl.StartsWith('/') ? options.LogoutUrl : "/" + options.LogoutUrl);

            var dom = await AuthFormDiscovery.FindFormForUrlAsync(_ctx, abs, preferPost: true);
            if (dom != null)
            {
                return new AuthFormDiscovery.ResolvedForm
                {
                    Url = dom.Url,
                    Method = dom.Method,
                    BodyTemplate = dom.BodyTemplate,
                    Headers = dom.Headers,
                    Source = "explicit-url+dom"
                };
            }

            return new AuthFormDiscovery.ResolvedForm
            {
                Url = abs,
                Method = "GET",
                Source = "explicit-url"
            };
        }

        foreach (var form in await AuthFormDiscovery.DiscoverLogoutFormsAsync(_ctx))
            return form;

        var pageLinks = await AuthProbeDiscovery.DiscoverLogoutUrlsFromPageAsync(_ctx, ct);
        if (pageLinks.Count > 0)
        {
            return new AuthFormDiscovery.ResolvedForm
            {
                Url = pageLinks[0],
                Method = "GET",
                Source = "page-link"
            };
        }

        foreach (var e in _ctx.Network.Entries.OrderByDescending(x => x.Timestamp))
        {
            if (!AuthProbeDiscovery.LooksLikeLogoutPath(e.Url ?? ""))
                continue;
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var u)
                || !string.Equals(u.Host, pageUri.Host, StringComparison.OrdinalIgnoreCase))
                continue;

            return new AuthFormDiscovery.ResolvedForm
            {
                Url = e.Url,
                Method = e.Method.ToUpperInvariant(),
                BodyTemplate = e.RequestBody,
                Headers = e.RequestHeaders != null
                    ? new Dictionary<string, string>(e.RequestHeaders, StringComparer.OrdinalIgnoreCase)
                    : null,
                Source = "network-log"
            };
        }

        var hints = FilterLogoutHintsForPage(pageUri);
        var hinted = AuthProbeDiscovery.DiscoverPaths(
            _ctx, pageUri, hints,
            AuthProbeDiscovery.LooksLikeLogoutPath, 4).FirstOrDefault();

        return hinted == null
            ? null
            : new AuthFormDiscovery.ResolvedForm
            {
                Url = hinted,
                Method = "GET",
                Source = "path-hint"
            };
    }

    private static IEnumerable<string> FilterLogoutHintsForPage(Uri pageUri)
    {
        var path = pageUri.AbsolutePath;
        var pageUsesJsp = path.Contains(".jsp", StringComparison.OrdinalIgnoreCase);
        foreach (var hint in AuthProbeDiscovery.LogoutPathHints)
        {
            if (!pageUsesJsp && hint.Contains(".jsp", StringComparison.OrdinalIgnoreCase))
                continue;
            yield return hint;
        }
    }

    private static bool UrlsEquivalent(string a, string b)
    {
        if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase))
            return true;
        if (!Uri.TryCreate(a, UriKind.Absolute, out var ua) || !Uri.TryCreate(b, UriKind.Absolute, out var ub))
            return false;
        return string.Equals(ua.GetLeftPart(UriPartial.Path).TrimEnd('/'),
            ub.GetLeftPart(UriPartial.Path).TrimEnd('/'),
            StringComparison.OrdinalIgnoreCase)
               && string.Equals(ua.Host, ub.Host, StringComparison.OrdinalIgnoreCase);
    }

    private async Task<bool> HasSessionCookieForHostAsync(string host)
    {
        try
        {
            var cookies = await _ctx.GetCookies();
            return cookies.Any(c =>
            {
                var name = c.TryGetValue("name", out var n) ? n?.ToString() ?? "" : "";
                if (!SessionCookieDetector.IsSessionCookieName(name)) return false;
                var domain = c.TryGetValue("domain", out var d) ? d?.ToString()?.TrimStart('.') ?? "" : "";
                return domain.Equals(host, StringComparison.OrdinalIgnoreCase)
                       || host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);
            });
        }
        catch
        {
            return false;
        }
    }
}
