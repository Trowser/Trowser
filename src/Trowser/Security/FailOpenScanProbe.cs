using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Detects fail-open behavior: unauthenticated access and invalid token acceptance (OWASP A10 / CWE-636).
/// </summary>
public sealed class FailOpenScanProbe
{
    private const string InvalidJwt =
        "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0cm93c2VyLWZhaWwtb3BlbiJ9.";

    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public FailOpenScanProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class ScanOptions
    {
        public IReadOnlyList<string>? Urls { get; set; }
        public int MaxEndpoints { get; set; } = 10;
        public int TimeoutMs { get; set; } = 12_000;
        public bool IncludeUnauthenticated { get; set; } = true;
        public bool IncludeInvalidToken { get; set; } = true;
        /// <summary>Accepted for API compatibility; simulated post-500 retry was removed (client mock never reached the server).</summary>
        public bool IncludeAfterError { get; set; } = true;
        public bool SkipStaticAssets { get; set; } = true;
        public bool SkipAuthSurfaces { get; set; } = true;
        public bool SkipPublicEndpoints { get; set; } = true;
        public bool RegisterChainFindings { get; set; } = true;
    }

    public sealed class ScanFinding
    {
        public string Category { get; init; } = "";
        public string Severity { get; init; } = "high";
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public string Signal { get; init; } = "";
        public string Title { get; init; } = "";
        public string Detail { get; init; } = "";
        public int AuthStatus { get; init; }
        public int ProbeStatus { get; init; }
        public string? BodySnippet { get; init; }
    }

    public sealed class ScanResult
    {
        public List<ScanFinding> Findings { get; init; } = [];
        public List<string> Summary { get; init; } = [];
        public int EndpointsProbed { get; init; }
        public int EndpointsSkipped { get; init; }
        public bool IsClean => Findings.Count == 0;
    }

    public async Task<ScanResult> RunAsync(ScanOptions options, CancellationToken ct = default)
    {
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var pageUri))
            throw new InvalidOperationException("Navigate to a page before running fail-open-scan.");

        var origin = pageUri.GetLeftPart(UriPartial.Authority);
        var candidates = ExceptionalConditionDiscovery.DiscoverProtectedEndpoints(
            _ctx, origin, Math.Clamp(options.MaxEndpoints, 1, 25), options.Urls,
            options.SkipStaticAssets, options.SkipAuthSurfaces);

        var findings = new List<ScanFinding>();
        var probed = 0;
        var skipped = 0;

        _log($"FailOpenScan: {candidates.Count} candidate(s)", "#888888");

        foreach (var target in candidates)
        {
            ct.ThrowIfCancellationRequested();
            probed++;

            var headers = target.Headers != null
                ? new Dictionary<string, string>(target.Headers, StringComparer.OrdinalIgnoreCase)
                : null;

            var auth = await SecurityProbeHttp.FetchAsync(
                _ctx, target.Url, target.Method, headers, target.BodyTemplate,
                options.TimeoutMs, includeBrowserCookies: true, ct);

            var authSensitive = ExceptionalConditionHeuristics.LooksLikeSensitiveBody(
                auth.Body, target.ResponseContentType, target.ResponseContentEncoding, out var authDecodeDetail);
            if (!ExceptionalConditionHeuristics.IsSuccessStatus(auth.Status) || !authSensitive)
            {
                if (ExceptionalConditionHeuristics.IsSuccessStatus(auth.Status)
                    && authDecodeDetail == "body-not-decoded")
                {
                    AddFinding(findings, target, "fail-open-decode-skipped", "info",
                        "body-not-decoded",
                        "Authenticated baseline returned non-text or undecodable body — sensitive comparison skipped.",
                        auth.Status, auth.Status, auth.Body);
                }

                if (target.CallerListed
                    && options.IncludeUnauthenticated
                    && !(options.SkipAuthSurfaces && FailOpenEndpointFilters.IsAuthSurface(target.Url)))
                {
                    await TryAddExplicitUnauthenticatedFailOpenAsync(
                        findings, target, headers, options, ct);
                }

                skipped++;
                continue;
            }

            if (options.SkipStaticAssets && FailOpenEndpointFilters.ShouldSkipProbe(target.Url))
            {
                skipped++;
                continue;
            }

            if (options.IncludeUnauthenticated
                && !(options.SkipAuthSurfaces && FailOpenEndpointFilters.IsAuthSurface(target.Url))
                && !(options.SkipPublicEndpoints
                    && !target.CallerListed
                    && FailOpenEndpointFilters.ShouldSkipUnauthenticatedFailOpen(
                        target.Url, target.Method, target.HadAuthorizationHeader)))
            {
                var anon = await SecurityProbeHttp.FetchAsync(
                    _ctx, target.Url, target.Method, StripAuthHeaders(headers), target.BodyTemplate,
                    options.TimeoutMs, includeBrowserCookies: false, ct);

                if (ExceptionalConditionHeuristics.IsSuccessStatus(anon.Status)
                    && ExceptionalConditionHeuristics.LooksLikeSensitiveBody(
                        anon.Body, target.ResponseContentType, target.ResponseContentEncoding, out _)
                    && ExceptionalConditionHeuristics.BodiesSimilar(
                        auth.Body, anon.Body,
                        target.ResponseContentType, target.ResponseContentEncoding,
                        target.ResponseContentType, target.ResponseContentEncoding))
                {
                    AddFinding(findings, target, "fail-open-unauthenticated",
                        FailOpenEndpointFilters.ClassifyUnauthenticatedSeverity(target.Method),
                        "unauthenticated-access",
                        $"Unauthenticated request returned HTTP {anon.Status} with sensitive body similar to authenticated baseline.",
                        auth.Status, anon.Status, anon.Body);
                }
            }

            if (options.IncludeInvalidToken && (target.HadAuthorizationHeader || headers?.ContainsKey("Authorization") == true))
            {
                var badHeaders = headers != null
                    ? new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase)
                    : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                badHeaders["Authorization"] = InvalidJwt;

                var invalid = await SecurityProbeHttp.FetchAsync(
                    _ctx, target.Url, target.Method, badHeaders, target.BodyTemplate,
                    options.TimeoutMs, includeBrowserCookies: false, ct);

                if (ExceptionalConditionHeuristics.IsSuccessStatus(invalid.Status)
                    && ExceptionalConditionHeuristics.LooksLikeSensitiveBody(
                        invalid.Body, target.ResponseContentType, target.ResponseContentEncoding, out _)
                    && ExceptionalConditionHeuristics.BodiesSimilar(
                        auth.Body, invalid.Body,
                        target.ResponseContentType, target.ResponseContentEncoding,
                        target.ResponseContentType, target.ResponseContentEncoding))
                {
                    AddFinding(findings, target, "fail-open-invalid-token",
                        FailOpenEndpointFilters.ClassifyInvalidTokenSeverity(target.Method),
                        "invalid-token-accepted",
                        "Request with invalid JWT/ Bearer token returned sensitive data similar to authenticated baseline.",
                        auth.Status, invalid.Status, invalid.Body);
                }
            }

        }

        if (options.RegisterChainFindings)
        {
            foreach (var f in findings)
            {
                if (f.Severity.Equals("info", StringComparison.OrdinalIgnoreCase))
                    continue;
                AuthProbeDiscovery.RegisterChainFinding(_ctx, f.Category, f.Severity, f.Detail, f.Url, f.Method, f.Detail);
            }
        }

        var summary = new List<string>();
        if (findings.Count == 0)
            summary.Add("No fail-open signals detected on probed endpoints.");
        else
            summary.Add($"{findings.Count} fail-open finding(s) — review error-handling and authorization gates.");
        summary.Add($"Endpoints probed: {probed}, skipped (non-sensitive auth baseline): {skipped}.");

        return new ScanResult
        {
            Findings = findings,
            Summary = summary,
            EndpointsProbed = probed,
            EndpointsSkipped = skipped
        };
    }

    private async Task TryAddExplicitUnauthenticatedFailOpenAsync(
        List<ScanFinding> findings,
        ExceptionalConditionDiscovery.ProtectedEndpoint target,
        Dictionary<string, string>? headers,
        ScanOptions options,
        CancellationToken ct)
    {
        var anon = await SecurityProbeHttp.FetchAsync(
            _ctx, target.Url, target.Method, StripAuthHeaders(headers), target.BodyTemplate,
            options.TimeoutMs, includeBrowserCookies: false, ct);

        if (!ExceptionalConditionHeuristics.IsSuccessStatus(anon.Status)
            || !ExceptionalConditionHeuristics.LooksLikeSensitiveBody(
                anon.Body, target.ResponseContentType, target.ResponseContentEncoding, out _))
            return;

        AddFinding(findings, target, "fail-open-unauthenticated",
            FailOpenEndpointFilters.ClassifyUnauthenticatedSeverity(target.Method),
            "unauthenticated-access",
            "Explicit URL: unauthenticated request returned sensitive data (authenticated baseline was inconclusive — compare manually).",
            anon.Status, anon.Status, anon.Body);
    }

    private static void AddFinding(
        List<ScanFinding> findings,
        ExceptionalConditionDiscovery.ProtectedEndpoint target,
        string category,
        string severity,
        string signal,
        string detail,
        int authStatus,
        int probeStatus,
        string body)
    {
        findings.Add(new ScanFinding
        {
            Category = category,
            Severity = severity,
            Url = target.Url,
            Method = target.Method,
            Signal = signal,
            Title = $"Fail-open: {signal} on {target.Method} {target.Url}",
            Detail = detail,
            AuthStatus = authStatus,
            ProbeStatus = probeStatus,
            BodySnippet = ExceptionalConditionHeuristics.Truncate(
                body.Replace('\r', ' ').Replace('\n', ' '), 200)
        });
    }

    private static Dictionary<string, string>? StripAuthHeaders(Dictionary<string, string>? headers)
    {
        if (headers == null) return null;
        var copy = new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase);
        copy.Remove("Authorization");
        copy.Remove("Cookie");
        return copy;
    }

}
