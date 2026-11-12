namespace Trowser.Security;

/// <summary>
/// Lightweight correctness fixtures for XSS/SQLi verdict compilers.
/// Invoked from Quicktests or diagnostic endpoints — not a full unit-test host.
/// </summary>
public static class SecurityVerdictFixtures
{
    public sealed record FixtureResult(string Name, bool Passed, string Detail);

    public static List<FixtureResult> RunAll()
    {
        var results = new List<FixtureResult>();
        results.Add(XssImgOnerrorUnencodedInHtmlBody());
        results.Add(XssEncodedMarkupNotDangerous());
        results.Add(XssVerdictSummaryDoesNotClaimEncodedWhenFalse());
        results.Add(SqliIdenticalHashStripsContentOracleTypes());
        results.Add(NosqlRejectsSqliteErrorOracle());
        results.Add(FormatDisplayUrlDoesNotDoubleAbsolute());
        results.Add(StackTraceWerkzeugConsoleIsCritical());
        results.Add(SecretsPlaintextPasswordInJsonIsCritical());
        results.Add(TraceInputSelfReferentialUrlEchoNotConfirmedXss());
        results.Add(TraceInputDocumentUrlEncodingMismatchEcho());
        return results;
    }

    public static bool AllPassed() => RunAll().All(r => r.Passed);

    private static FixtureResult XssImgOnerrorUnencodedInHtmlBody()
    {
        const string name = "xss-img-onerror-unencoded";
        const string payload = """<img src=x onerror="window.__xss_proof=1">""";
        var body = $"""<html><body><span class="search-term">{payload}</span></body></html>""";
        var analysis = XssReflectionAnalyzer.AnalyzeReflection(body, payload, payload, encoded: false, "text/html");
        var ok = analysis is { Encoded: false, Dangerous: true }
                 && analysis.Context is "html-markup" or "event-handler";
        return new FixtureResult(name, ok,
            $"context={analysis.Context} dangerous={analysis.Dangerous} encoded={analysis.Encoded} reason={analysis.Reason}");
    }

    private static FixtureResult XssEncodedMarkupNotDangerous()
    {
        const string name = "xss-encoded-markup-safe";
        const string payload = "<img src=x onerror=alert(1)>";
        var encoded = System.Net.WebUtility.HtmlEncode(payload);
        var body = $"<html><body><span>{encoded}</span></body></html>";
        var analysis = XssReflectionAnalyzer.AnalyzeReflection(body, payload, encoded, encoded: true, "text/html");
        var ok = analysis is { Encoded: true, Dangerous: false };
        return new FixtureResult(name, ok,
            $"context={analysis.Context} dangerous={analysis.Dangerous}");
    }

    private static FixtureResult XssVerdictSummaryDoesNotClaimEncodedWhenFalse()
    {
        const string name = "xss-verdict-summary-encoded-consistency";
        // CompileVerdict is private; approximate with AnalyzeReflection + the known bad summary shape.
        const string payload = "<svg/onload=alert(1)>";
        var body = $"<html><body>{payload}</body></html>";
        var analysis = XssReflectionAnalyzer.AnalyzeReflection(body, payload, payload, encoded: false, "text/html");
        var ok = analysis.Dangerous && !analysis.Encoded
                 && (analysis.Reason == null
                     || !analysis.Reason.Contains("encoded", StringComparison.OrdinalIgnoreCase)
                     || analysis.Reason.Contains("Unencoded", StringComparison.OrdinalIgnoreCase));
        return new FixtureResult(name, ok, analysis.Reason ?? "(no reason)");
    }

    private static FixtureResult SqliIdenticalHashStripsContentOracleTypes()
    {
        const string name = "sqli-identical-stripped-hash";
        // Exercise the public evidence helper: identical bodies → identical excerpt marker.
        var a = "<html><body>login failed</body></html>";
        var b = "<html><body>login failed</body></html>";
        var ha = ResponseBodySecurityHeuristics.CanonicalSecurityEvidenceHash(a);
        var hb = ResponseBodySecurityHeuristics.CanonicalSecurityEvidenceHash(b);
        var excerpt = ResponseBodySecurityHeuristics.BuildShortSecurityBodyDiffExcerpt(a, b);
        var ok = string.Equals(ha, hb, StringComparison.Ordinal)
                 && excerpt.Contains("identical after framework-noise strip", StringComparison.OrdinalIgnoreCase);
        return new FixtureResult(name, ok, $"hashEqual={ha == hb}; excerpt={excerpt}");
    }

    private static FixtureResult NosqlRejectsSqliteErrorOracle()
    {
        const string name = "nosql-rejects-sqlite-error";
        const string body = "sqlite3.OperationalError: near \"admin\": syntax error";
        var nosql = InjectionProbeFilters.ResponseHasNosqlErrorEvidence(body);
        var sql = InjectionProbeFilters.ResponseHasRelationalSqlErrorEvidence(body);
        var ok = !nosql && sql;
        return new FixtureResult(name, ok, $"nosql={nosql} sql={sql}");
    }

    private static FixtureResult FormatDisplayUrlDoesNotDoubleAbsolute()
    {
        const string name = "format-display-url-no-double";
        var ep = new AttackSurfaceEndpoint
        {
            Url = "http://localhost:4280/login",
            UrlTemplate = "http://localhost:4280/login"
        };
        var display = AttackSurfaceMapper.FormatDisplayUrl(ep);
        var ok = !display.Contains("http://localhost:4280/http://", StringComparison.OrdinalIgnoreCase)
                 && display.StartsWith("http://localhost:4280/login", StringComparison.OrdinalIgnoreCase);
        return new FixtureResult(name, ok, display);
    }

    private static FixtureResult StackTraceWerkzeugConsoleIsCritical()
    {
        const string name = "forced-error-werkzeug-critical";
        const string probe = """
            <!DOCTYPE HTML>
            <html><body>
            <div class="debugger">
            <h1>Werkzeug Debugger</h1>
            <pre>SECRET = "abc123secret"</pre>
            </div></body></html>
            """;
        var classified = StackTraceHeuristics.ClassifyRelativeToBaseline(probe, "<html>ok</html>");
        var ok = classified is { Severity: "critical" };
        return new FixtureResult(name, ok, classified?.ToString() ?? "null");
    }

    private static FixtureResult SecretsPlaintextPasswordInJsonIsCritical()
    {
        const string name = "secrets-plaintext-password-json";
        const string json = """[{"email":"admin@example.com","password":"admin123"}]""";
        var hits = ResponseBodySecurityHeuristics.DetectCredentialExposure(json);
        var combo = hits.FirstOrDefault(h =>
            h.Kind.Contains("password", StringComparison.OrdinalIgnoreCase));
        var ok = combo != null;
        return new FixtureResult(name, ok,
            combo == null ? $"hits={hits.Count}" : $"{combo.Kind}:{combo.Snippet}");
    }

    private static FixtureResult TraceInputSelfReferentialUrlEchoNotConfirmedXss()
    {
        const string name = "trace-input-self-ref-url-echo";
        const string payload = "${alert(1)}";
        var page = "https://app.example/page#" + payload;
        var hits = new List<InputTraceResult.SinkHit>
        {
            new() { Sink = "a.href", ContainsPayload = true, Snippet = page },
            new() { Sink = "fetch", ContainsPayload = true, Snippet = page }
        };
        var echoOnly = XssReflectionAnalyzer.SinkHitsAreDocumentUrlEchoOnly(payload, page, hits);
        var trace = new InputTraceResult
        {
            Payload = payload,
            DocumentUrl = page,
            Injection = new InputTraceResult.InjectionTrace { SourceType = "url-hash", NavigatedUrl = page },
            Sinks = new InputTraceResult.SinkTrace { PayloadReachedSink = true, Hits = hits, HitCount = hits.Count }
        };
        var ok = echoOnly && !XssBypassProbes.IsConfirmedXss(trace);
        return new FixtureResult(name, ok, $"echoOnly={echoOnly}; confirmed={XssBypassProbes.IsConfirmedXss(trace)}");
    }

    private static FixtureResult TraceInputDocumentUrlEncodingMismatchEcho()
    {
        const string name = "trace-input-url-echo-encoding";
        const string payload = "${alert(1)}";
        var encodedPage = "https://app.example/page#" + Uri.EscapeDataString(payload);
        var decodedSnippet = "https://app.example/page#" + payload;
        var ok = XssReflectionAnalyzer.SnippetIsDocumentUrlEcho(payload, encodedPage, decodedSnippet);
        return new FixtureResult(name, ok, $"match={ok}; doc={encodedPage}; snip={decodedSnippet}");
    }
}
