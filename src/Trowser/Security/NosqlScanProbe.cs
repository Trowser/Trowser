using System.Diagnostics;
using System.IO;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// NoSQL injection — operator payloads on query strings and JSON login/search endpoints.
/// Oracles: true/false pair asymmetry vs baseline, auth-bypass signals, or NoSQL error markers absent from baseline.
/// Inspired by OWASP WSTG-INPV-05.6; also influenced by pentest-ai <c>web.nosql_fuzz</c>.
/// Trowser-specific: optional smart routing, scaffold when traffic is sparse, depth-capped payloads.
/// </summary>
public sealed class NosqlScanProbe
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public NosqlScanProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class NosqlScanOptions
    {
        public string? UrlTemplate { get; set; }
        public string? Method { get; set; }
        public Dictionary<string, string>? Headers { get; set; }
        public string? BodyTemplate { get; set; }
        public string? ParamName { get; set; }
        public int MaxCandidates { get; set; } = 10;
        public int TimeoutMs { get; set; } = 15000;
        public bool IncludeScaffold { get; set; } = true;
        public int SparseThreshold { get; set; } = InjectionScaffold.DefaultSparseThreshold;
        public bool IncludeBrowserCookies { get; set; } = true;
        public bool ExcludeTransportEndpoints { get; set; } = true;
        public bool UseSmartRouting { get; set; } = true;

        /// <summary>Scan depth: quick / standard / thorough (caps paired and error payloads).</summary>
        public string? ScanDepth { get; set; }

        /// <summary>Max paired probes per candidate (0 = depth default / unlimited for thorough).</summary>
        public int MaxPayloads { get; set; }

        /// <summary>Max error-oracle payloads per candidate (0 = depth default).</summary>
        public int MaxErrorPayloads { get; set; }

        /// <summary>Payload corpus breadth (default small).</summary>
        public PayloadProfile PayloadProfile { get; set; } = PayloadProfile.Small;
    }

    public sealed class NosqlFinding
    {
        public string Category { get; init; } = "nosql-injection";
        public string Severity { get; init; } = "high";
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public string ParamName { get; init; } = "";
        public string Payload { get; init; } = "";
        public int Status { get; init; }
        public string Detail { get; init; } = "";
        public string Source { get; init; } = "network";
    }

    public sealed class NosqlScanResult
    {
        public string Message { get; init; } = "";
        public int CandidatesProbed { get; init; }
        public int PayloadsSent { get; init; }
        public int ElapsedMs { get; init; }
        public List<NosqlFinding> Findings { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;
    }

    public async Task<NosqlScanResult> RunAsync(NosqlScanOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running nosql-scan.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        TechStackResult? stack = null;
        try { stack = await _ctx.CheckTechStack(); }
        catch { /* optional */ }

        var candidates = BuildCandidates(origin, options);
        if (!string.IsNullOrWhiteSpace(options.UrlTemplate) || options.BodyTemplate != null)
        {
            var urlTpl = options.UrlTemplate ?? origin;
            var markers = RequestMarkerSubstitute.ListMarkers(urlTpl, options.BodyTemplate);
            if (markers.Count == 0)
                throw new ArgumentException(InjectionRequestErrors.WithRequestExample(
                    "Explicit request must contain §INJECT§ or {{INJECT}} in url or body."));

            var cleanUrl = urlTpl;
            if (Uri.TryCreate(urlTpl, UriKind.Absolute, out var explicitUri))
                cleanUrl = explicitUri.GetLeftPart(UriPartial.Authority) + explicitUri.AbsolutePath;

            candidates =
            [
                new NosqlCandidate
                {
                    Url = cleanUrl,
                    Method = (options.Method ?? "POST").ToUpperInvariant(),
                    ParamName = options.ParamName ?? markers[0],
                    BodyTemplate = options.BodyTemplate,
                    Headers = options.Headers,
                    Source = "explicit"
                }
            ];
        }
        if (candidates.Count == 0)
        {
            return new NosqlScanResult
            {
                Message = "No NoSQL injection candidates. Browse the app or enable includeScaffold.",
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        var findings = new List<NosqlFinding>();
        var payloadsSent = 0;
        var seenTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pairs = NosqlInjectionPayloads.SelectPairs(options.ScanDepth, options.MaxPayloads, options.PayloadProfile).ToList();
        var errors = NosqlInjectionPayloads.SelectErrors(options.ScanDepth, options.MaxErrorPayloads, options.PayloadProfile).ToList();

        foreach (var candidate in candidates)
        {
            ct.ThrowIfCancellationRequested();
            if (options.UseSmartRouting
                && !InjectionParamClassifier.AllowsScanner(
                    InjectionParamClassifier.Classify(candidate.ParamName, candidate.Url),
                    "nosql",
                    InjectionParamClassifier.IsLoginEndpoint(candidate.Url)))
                continue;

            if (InjectionProbeFilters.ShouldExcludeTransportEndpoint(
                    candidate.Url, candidate.ParamName, options.ExcludeTransportEndpoints))
                continue;

            var targetKey = candidate.Url.Split('?', 2)[0];
            if (!seenTargets.Add(targetKey) && candidate.Source == "scaffold")
                continue;

            NosqlFinding? finding;
            int sent;
            if (candidate.Method == "GET")
            {
                (finding, sent) = await ProbeGetCandidateAsync(
                    candidate, pairs, errors, options, stack, targetKey, ct);
            }
            else if (candidate.BodyTemplate != null)
            {
                try
                {
                    if (IsJsonBody(candidate))
                        (finding, sent) = await ProbeJsonCandidateAsync(
                            candidate, pairs, errors, options, ct);
                    else if (IsFormBody(candidate))
                        (finding, sent) = await ProbeFormCandidateAsync(
                            candidate, pairs, errors, options, ct);
                    else
                        continue;
                }
                catch (JsonException)
                {
                    continue;
                }
            }
            else
                continue;

            payloadsSent += sent;

            if (finding != null)
                findings.Add(finding);
        }

        return new NosqlScanResult
        {
            Message = findings.Count > 0
                ? $"{findings.Count} NoSQL injection indicator(s) across {candidates.Count} candidate(s)."
                : $"No NoSQL indicators across {candidates.Count} candidate(s), {payloadsSent} payload(s).",
            CandidatesProbed = candidates.Count,
            PayloadsSent = payloadsSent,
            Findings = findings,
            ElapsedMs = (int)sw.ElapsedMilliseconds
        };
    }

    private async Task<(NosqlFinding? Finding, int PayloadsSent)> ProbeGetCandidateAsync(
        NosqlCandidate candidate,
        IReadOnlyList<NosqlInjectionPayloads.PayloadPair> pairs,
        IReadOnlyList<NosqlInjectionPayloads.ErrorPayload> errors,
        NosqlScanOptions options,
        TechStackResult? stack,
        string targetKey,
        CancellationToken ct)
    {
        var payloadsSent = 0;
        LoginInjectionHelpers.LoginProbeResponse? baseline = null;
        LoginInjectionHelpers.LoginProbeResponse? noParamBaseline = null;

        async Task<(LoginInjectionHelpers.LoginProbeResponse Baseline, LoginInjectionHelpers.LoginProbeResponse? NoParam)> EnsureBaselinesAsync()
        {
            if (baseline != null)
                return (baseline, noParamBaseline);

            var cleanUrl = candidate.Source == "scaffold-operator"
                ? candidate.Url
                : BuildQueryInjectionUrl(candidate.Url, candidate.ParamName, "nosql-baseline-clean");
            baseline = await LoginInjectionHelpers.SendAsync(
                _ctx, cleanUrl, "GET", null, null, options.TimeoutMs,
                followRedirects: true, options.IncludeBrowserCookies, ct);

            if (candidate.Source != "scaffold-operator")
            {
                var noParamUrl = BuildQueryUrlWithoutParam(candidate.Url, candidate.ParamName);
                noParamBaseline = await LoginInjectionHelpers.SendAsync(
                    _ctx, noParamUrl, "GET", null, null, options.TimeoutMs,
                    followRedirects: true, options.IncludeBrowserCookies, ct);
            }

            return (baseline, noParamBaseline);
        }

        if (candidate.Source == "scaffold-operator")
        {
            var (baseLine, _) = await EnsureBaselinesAsync();
            payloadsSent++;
            var attack = await LoginInjectionHelpers.SendAsync(
                _ctx, candidate.Url, "GET", null, null, options.TimeoutMs,
                followRedirects: true, options.IncludeBrowserCookies, ct);

            if (LoginInjectionHelpers.NosqlBypassSuspected(
                    attack, baseLine, candidate.PayloadTemplate, stack, noParamBaseline: noParamBaseline)
                || (LoginInjectionHelpers.NosqlErrorInjectionSuspected(attack)
                    && !LoginInjectionHelpers.NosqlErrorInjectionSuspected(baseLine)))
            {
                _log($"  FLAG NoSQL: {candidate.ParamName} on {targetKey}", "#F44747");
                return (BuildFinding(candidate, candidate.Url, candidate.PayloadTemplate ?? candidate.Url, attack,
                    "NoSQL operator scaffold response diverged from baseline."), payloadsSent);
            }

            return (null, payloadsSent);
        }

        foreach (var pair in pairs)
        {
            ct.ThrowIfCancellationRequested();
            if (pair.Kind == NosqlInjectionPayloads.PayloadKind.JsonPair)
                continue;

            var falseUrl = BuildQueryInjectionUrl(candidate.Url, candidate.ParamName, pair.FalsePayload);
            var trueUrl = BuildQueryInjectionUrl(candidate.Url, candidate.ParamName, pair.TruePayload);
            payloadsSent += 2;

            var falseSw = Stopwatch.StartNew();
            var falseResp = await LoginInjectionHelpers.SendAsync(
                _ctx, falseUrl, "GET", null, null, options.TimeoutMs,
                followRedirects: true, options.IncludeBrowserCookies, ct);
            falseSw.Stop();

            var trueSw = Stopwatch.StartNew();
            var trueResp = await LoginInjectionHelpers.SendAsync(
                _ctx, trueUrl, "GET", null, null, options.TimeoutMs,
                followRedirects: true, options.IncludeBrowserCookies, ct);
            trueSw.Stop();

            var (baseLine, noParam) = await EnsureBaselinesAsync();
            if (LoginInjectionHelpers.NosqlPairInjectionSuspected(
                    falseResp, trueResp, baseLine, noParam, falseSw.ElapsedMilliseconds, trueSw.ElapsedMilliseconds, pair.Kind))
            {
                _log($"  FLAG NoSQL: {candidate.ParamName} on {targetKey} ({pair.Kind})", "#F44747");
                return (BuildFinding(candidate, trueUrl, $"{pair.FalsePayload} / {pair.TruePayload}", trueResp,
                    $"Paired NoSQL probe ({pair.Kind}) diverged asymmetrically from baseline."), payloadsSent);
            }
        }

        foreach (var err in errors.Where(e => e.Kind is NosqlInjectionPayloads.PayloadKind.QueryBracketError
                                              or NosqlInjectionPayloads.PayloadKind.JsonError))
        {
            ct.ThrowIfCancellationRequested();
            var url = BuildQueryInjectionUrl(candidate.Url, candidate.ParamName, err.Payload);
            payloadsSent++;
            var attack = await LoginInjectionHelpers.SendAsync(
                _ctx, url, "GET", null, null, options.TimeoutMs,
                followRedirects: true, options.IncludeBrowserCookies, ct);

            if (!LoginInjectionHelpers.NosqlErrorInjectionSuspected(attack))
                continue;

            var (baseLine, _) = await EnsureBaselinesAsync();
            if (LoginInjectionHelpers.NosqlErrorInjectionSuspected(baseLine))
                continue;

            _log($"  FLAG NoSQL error: {candidate.ParamName} on {targetKey}", "#F44747");
            return (BuildFinding(candidate, url, err.Payload, attack,
                "NoSQL/Redis error oracle in response body.", severity: "medium"), payloadsSent);
        }

        foreach (var pair in pairs.Where(p => p.Kind == NosqlInjectionPayloads.PayloadKind.JsonPair))
        {
            ct.ThrowIfCancellationRequested();
            var falseUrl = BuildQueryInjectionUrl(candidate.Url, candidate.ParamName, pair.FalsePayload);
            var trueUrl = BuildQueryInjectionUrl(candidate.Url, candidate.ParamName, pair.TruePayload);
            payloadsSent += 2;

            var falseResp = await LoginInjectionHelpers.SendAsync(
                _ctx, falseUrl, "GET", null, null, options.TimeoutMs,
                followRedirects: true, options.IncludeBrowserCookies, ct);
            var trueResp = await LoginInjectionHelpers.SendAsync(
                _ctx, trueUrl, "GET", null, null, options.TimeoutMs,
                followRedirects: true, options.IncludeBrowserCookies, ct);

            var (baseLine, noParam) = await EnsureBaselinesAsync();
            if (LoginInjectionHelpers.NosqlPairInjectionSuspected(falseResp, trueResp, baseLine, noParam, kind: pair.Kind))
            {
                _log($"  FLAG NoSQL JSON-in-query: {candidate.ParamName} on {targetKey}", "#F44747");
                return (BuildFinding(candidate, trueUrl, $"{pair.FalsePayload} / {pair.TruePayload}", trueResp,
                    "Paired JSON operator probe diverged asymmetrically from baseline."), payloadsSent);
            }
        }

        return (null, payloadsSent);
    }

    private async Task<(NosqlFinding? Finding, int PayloadsSent)> ProbeJsonCandidateAsync(
        NosqlCandidate candidate,
        IReadOnlyList<NosqlInjectionPayloads.PayloadPair> pairs,
        IReadOnlyList<NosqlInjectionPayloads.ErrorPayload> errors,
        NosqlScanOptions options,
        CancellationToken ct)
    {
        var payloadsSent = 0;
        LoginInjectionHelpers.LoginProbeResponse? baseline = null;

        async Task<LoginInjectionHelpers.LoginProbeResponse> EnsureBaselineAsync()
        {
            if (baseline != null) return baseline;
            if (!TryInjectJsonStringField(candidate.BodyTemplate!, candidate.ParamName, "nosql-baseline", out var baseBody))
                throw new JsonException("Body template is not valid JSON.");
            baseline = await LoginInjectionHelpers.SendAsync(
                _ctx, candidate.Url, candidate.Method, candidate.Headers, baseBody,
                options.TimeoutMs, followRedirects: true, options.IncludeBrowserCookies, ct);
            return baseline;
        }

        foreach (var pair in pairs.Where(p => p.Kind is NosqlInjectionPayloads.PayloadKind.JsonPair
                                              or NosqlInjectionPayloads.PayloadKind.FunctionPair
                                              or NosqlInjectionPayloads.PayloadKind.TimePair))
        {
            ct.ThrowIfCancellationRequested();
            if (!TryInjectJsonStringField(candidate.BodyTemplate!, candidate.ParamName, pair.FalsePayload, out var falseBody)
                || !TryInjectJsonStringField(candidate.BodyTemplate!, candidate.ParamName, pair.TruePayload, out var trueBody))
                continue;
            payloadsSent += 2;

            var falseSw = Stopwatch.StartNew();
            var falseResp = await LoginInjectionHelpers.SendAsync(
                _ctx, candidate.Url, candidate.Method, candidate.Headers, falseBody,
                options.TimeoutMs, followRedirects: true, options.IncludeBrowserCookies, ct);
            falseSw.Stop();

            var trueSw = Stopwatch.StartNew();
            var trueResp = await LoginInjectionHelpers.SendAsync(
                _ctx, candidate.Url, candidate.Method, candidate.Headers, trueBody,
                options.TimeoutMs, followRedirects: true, options.IncludeBrowserCookies, ct);
            trueSw.Stop();

            var baseLine = await EnsureBaselineAsync();
            if (LoginInjectionHelpers.NosqlPairInjectionSuspected(
                    falseResp, trueResp, baseLine, falseElapsedMs: falseSw.ElapsedMilliseconds,
                    trueElapsedMs: trueSw.ElapsedMilliseconds, kind: pair.Kind))
            {
                _log($"  FLAG NoSQL JSON: {candidate.ParamName} on {candidate.Url}", "#F44747");
                return (BuildFinding(candidate, candidate.Url, $"{pair.FalsePayload} / {pair.TruePayload}", trueResp,
                    $"Paired NoSQL JSON probe ({pair.Kind}) diverged asymmetrically from baseline."), payloadsSent);
            }
        }

        foreach (var err in errors.Where(e => e.Kind == NosqlInjectionPayloads.PayloadKind.JsonError))
        {
            ct.ThrowIfCancellationRequested();
            if (!TryInjectJsonStringField(candidate.BodyTemplate!, candidate.ParamName, err.Payload, out var body))
                continue;
            payloadsSent++;
            var attack = await LoginInjectionHelpers.SendAsync(
                _ctx, candidate.Url, candidate.Method, candidate.Headers, body,
                options.TimeoutMs, followRedirects: true, options.IncludeBrowserCookies, ct);

            if (!LoginInjectionHelpers.NosqlErrorInjectionSuspected(attack))
                continue;

            var baseLine = await EnsureBaselineAsync();
            if (LoginInjectionHelpers.NosqlErrorInjectionSuspected(baseLine))
                continue;

            _log($"  FLAG NoSQL JSON error: {candidate.ParamName} on {candidate.Url}", "#F44747");
            return (BuildFinding(candidate, candidate.Url, err.Payload, attack,
                "NoSQL error oracle in JSON response body.", severity: "medium"), payloadsSent);
        }

        return (null, payloadsSent);
    }

    private async Task<(NosqlFinding? Finding, int PayloadsSent)> ProbeFormCandidateAsync(
        NosqlCandidate candidate,
        IReadOnlyList<NosqlInjectionPayloads.PayloadPair> pairs,
        IReadOnlyList<NosqlInjectionPayloads.ErrorPayload> errors,
        NosqlScanOptions options,
        CancellationToken ct)
    {
        var payloadsSent = 0;
        LoginInjectionHelpers.LoginProbeResponse? baseline = null;

        async Task<LoginInjectionHelpers.LoginProbeResponse> EnsureBaselineAsync()
        {
            if (baseline != null) return baseline;
            var baseBody = InjectionFormBody.ReplaceFormField(
                candidate.BodyTemplate!, candidate.ParamName, "nosql-baseline");
            baseline = await LoginInjectionHelpers.SendAsync(
                _ctx, candidate.Url, candidate.Method, candidate.Headers, baseBody,
                options.TimeoutMs, followRedirects: true, options.IncludeBrowserCookies, ct);
            return baseline;
        }

        foreach (var pair in pairs.Where(p => p.Kind != NosqlInjectionPayloads.PayloadKind.TimePair))
        {
            ct.ThrowIfCancellationRequested();
            var falseBody = InjectionFormBody.ReplaceFormField(
                candidate.BodyTemplate!, candidate.ParamName, pair.FalsePayload);
            var trueBody = InjectionFormBody.ReplaceFormField(
                candidate.BodyTemplate!, candidate.ParamName, pair.TruePayload);
            payloadsSent += 2;

            var falseSw = Stopwatch.StartNew();
            var falseResp = await LoginInjectionHelpers.SendAsync(
                _ctx, candidate.Url, candidate.Method, candidate.Headers, falseBody,
                options.TimeoutMs, followRedirects: true, options.IncludeBrowserCookies, ct);
            falseSw.Stop();

            var trueSw = Stopwatch.StartNew();
            var trueResp = await LoginInjectionHelpers.SendAsync(
                _ctx, candidate.Url, candidate.Method, candidate.Headers, trueBody,
                options.TimeoutMs, followRedirects: true, options.IncludeBrowserCookies, ct);
            trueSw.Stop();

            var baseLine = await EnsureBaselineAsync();
            if (LoginInjectionHelpers.NosqlPairInjectionSuspected(
                    falseResp, trueResp, baseLine, falseElapsedMs: falseSw.ElapsedMilliseconds,
                    trueElapsedMs: trueSw.ElapsedMilliseconds, kind: pair.Kind))
            {
                _log($"  FLAG NoSQL form: {candidate.ParamName} on {candidate.Url}", "#F44747");
                return (BuildFinding(candidate, candidate.Url, $"{pair.FalsePayload} / {pair.TruePayload}", trueResp,
                    $"Paired NoSQL form probe ({pair.Kind}) diverged asymmetrically from baseline."), payloadsSent);
            }
        }

        foreach (var err in errors)
        {
            ct.ThrowIfCancellationRequested();
            var body = InjectionFormBody.ReplaceFormField(
                candidate.BodyTemplate!, candidate.ParamName, err.Payload);
            payloadsSent++;
            var attack = await LoginInjectionHelpers.SendAsync(
                _ctx, candidate.Url, candidate.Method, candidate.Headers, body,
                options.TimeoutMs, followRedirects: true, options.IncludeBrowserCookies, ct);

            if (!LoginInjectionHelpers.NosqlErrorInjectionSuspected(attack))
                continue;

            var baseLine = await EnsureBaselineAsync();
            if (LoginInjectionHelpers.NosqlErrorInjectionSuspected(baseLine))
                continue;

            _log($"  FLAG NoSQL form error: {candidate.ParamName} on {candidate.Url}", "#F44747");
            return (BuildFinding(candidate, candidate.Url, err.Payload, attack,
                "NoSQL/Redis error oracle in form response body.", severity: "medium"), payloadsSent);
        }

        return (null, payloadsSent);
    }

    private static NosqlFinding BuildFinding(
        NosqlCandidate candidate,
        string url,
        string payload,
        LoginInjectionHelpers.LoginProbeResponse attack,
        string detail,
        string severity = "high") =>
        new()
        {
            Url = url,
            Method = candidate.Method,
            ParamName = candidate.ParamName,
            Payload = payload,
            Status = attack.Status,
            Detail = detail,
            Source = candidate.Source,
            Severity = severity
        };

    private sealed class NosqlCandidate
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public string ParamName { get; init; } = "email";
        public string? BodyTemplate { get; init; }
        public Dictionary<string, string>? Headers { get; init; }
        public string Source { get; init; } = "network";
        public string? PayloadTemplate { get; init; }
    }

    private List<NosqlCandidate> BuildCandidates(string origin, NosqlScanOptions options)
    {
        var list = new List<NosqlCandidate>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var pt in InjectionPointDiscovery.DiscoverFromNetwork(
                     _ctx, origin, options.MaxCandidates, jsonBodiesOnly: false))
        {
            if (pt.Method == "GET" && pt.UrlTemplate != null)
            {
                var key = pt.UrlTemplate.Split('?', 2)[0];
                if (seen.Add(key))
                {
                    list.Add(new NosqlCandidate
                    {
                        Url = pt.UrlTemplate.Replace("§INJECT§", "nosql-probe", StringComparison.Ordinal),
                        Method = "GET",
                        ParamName = pt.ParamName,
                        Source = pt.Source
                    });
                }
            }
            else if (pt.BodyTemplate != null)
            {
                var key = $"{pt.Method}|{pt.Url}|{pt.ParamName}";
                if (seen.Add(key))
                {
                    list.Add(new NosqlCandidate
                    {
                        Url = pt.Url,
                        Method = pt.Method,
                        ParamName = pt.ParamName,
                        BodyTemplate = pt.BodyTemplate.Replace("§INJECT§", "nosql-probe", StringComparison.Ordinal),
                        Headers = pt.Headers,
                        Source = pt.Source
                    });
                }
            }
        }

        var apiCount = InjectionScaffold.CountApiLikeNetworkEntries(_ctx.Network.Entries, origin);
        if (options.IncludeScaffold && InjectionScaffold.ShouldUseScaffold(apiCount, options.SparseThreshold))
        {
            foreach (var tpl in InjectionScaffold.EnumerateNosqlScaffold())
            {
                if (tpl.PathQueryTemplate.Contains('=') && !tpl.PathQueryTemplate.Contains("{marker}"))
                {
                    var url = InjectionScaffold.BuildUrl(origin, tpl.PathQueryTemplate, "");
                    if (seen.Add(url))
                    {
                        list.Add(new NosqlCandidate
                        {
                            Url = url,
                            Method = "GET",
                            ParamName = tpl.ParamName,
                            Source = "scaffold-operator",
                            PayloadTemplate = tpl.PathQueryTemplate
                        });
                    }
                }
                else
                {
                    var url = InjectionScaffold.BuildUrl(origin, tpl.PathQueryTemplate, "nosql-probe");
                    if (seen.Add(url.Split('?', 2)[0]))
                    {
                        list.Add(new NosqlCandidate
                        {
                            Url = url,
                            Method = "GET",
                            ParamName = tpl.ParamName,
                            Source = "scaffold"
                        });
                    }
                }
            }
        }

        return list.Take(Math.Max(options.MaxCandidates, 25)).ToList();
    }

    private static string BuildQueryInjectionUrl(string urlTemplate, string paramName, string payload)
    {
        if (!Uri.TryCreate(urlTemplate, UriKind.Absolute, out var uri))
            return urlTemplate;

        var basePath = uri.GetLeftPart(UriPartial.Path);
        if (payload.StartsWith('[') && payload.Contains('='))
            return $"{basePath}?{paramName}{payload}";

        var parts = new List<string>();
        var replaced = false;
        foreach (var part in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq < 0) { parts.Add(part); continue; }
            var key = Uri.UnescapeDataString(part[..eq]);
            if (key.Equals(paramName, StringComparison.OrdinalIgnoreCase))
            {
                parts.Add($"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(payload)}");
                replaced = true;
            }
            else parts.Add(part);
        }

        if (!replaced)
            parts.Add($"{Uri.EscapeDataString(paramName)}={Uri.EscapeDataString(payload)}");

        return $"{basePath}?{string.Join("&", parts)}";
    }

    /// <summary>Same path/query as template but without <paramref name="paramName"/> or bracketed variants (e.g. q[$ne]).</summary>
    private static string BuildQueryUrlWithoutParam(string urlTemplate, string paramName)
    {
        if (!Uri.TryCreate(urlTemplate, UriKind.Absolute, out var uri))
            return urlTemplate;

        var basePath = uri.GetLeftPart(UriPartial.Path);
        var parts = new List<string>();
        foreach (var part in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq < 0) { parts.Add(part); continue; }
            var key = Uri.UnescapeDataString(part[..eq]);
            if (key.Equals(paramName, StringComparison.OrdinalIgnoreCase)
                || key.StartsWith(paramName + "[", StringComparison.OrdinalIgnoreCase))
                continue;
            parts.Add(part);
        }

        return parts.Count == 0 ? basePath : $"{basePath}?{string.Join("&", parts)}";
    }

    private static bool IsJsonBody(NosqlCandidate candidate)
    {
        if (string.IsNullOrEmpty(candidate.BodyTemplate)) return false;
        if (candidate.Source.Contains("json", StringComparison.OrdinalIgnoreCase)) return true;
        var ct = GetContentType(candidate.Headers);
        if (ct.Contains("json", StringComparison.OrdinalIgnoreCase)) return true;
        return candidate.BodyTemplate.TrimStart().StartsWith('{');
    }

    private static bool IsFormBody(NosqlCandidate candidate)
    {
        if (string.IsNullOrEmpty(candidate.BodyTemplate)) return false;
        if (candidate.Source.Contains("form", StringComparison.OrdinalIgnoreCase)) return true;
        var ct = GetContentType(candidate.Headers);
        if (ct.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase)) return true;
        var body = candidate.BodyTemplate.Trim();
        if (body.StartsWith('{')) return false;
        return body.Contains('=') && (body.Contains('&') || body.IndexOf('=') > 0);
    }

    private static string GetContentType(Dictionary<string, string>? headers)
    {
        if (headers == null) return "";
        if (headers.TryGetValue("Content-Type", out var ct)) return ct;
        return headers.TryGetValue("content-type", out var ct2) ? ct2 : "";
    }

    private static bool TryInjectJsonStringField(string json, string fieldName, string value, out string body)
    {
        body = "";
        if (string.IsNullOrWhiteSpace(json) || !json.TrimStart().StartsWith('{'))
            return false;

        try
        {
            body = InjectJsonStringField(json, fieldName, value);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string InjectJsonStringField(string json, string fieldName, string value)
    {
        if (RequestMarkerSubstitute.ListMarkers(json, null).Count > 0)
            return InjectionJsonBody.SubstituteMarkers(json, value);

        using var doc = JsonDocument.Parse(json);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                writer.WritePropertyName(prop.Name);
                if (prop.Name.Equals(fieldName, StringComparison.OrdinalIgnoreCase))
                {
                    if (value.TrimStart().StartsWith('{') || value.TrimStart().StartsWith('['))
                    {
                        using var inner = JsonDocument.Parse(value);
                        inner.RootElement.WriteTo(writer);
                    }
                    else
                        writer.WriteStringValue(value);
                }
                else
                    prop.Value.WriteTo(writer);
            }

            writer.WriteEndObject();
        }

        return System.Text.Encoding.UTF8.GetString(stream.ToArray());
    }
}
