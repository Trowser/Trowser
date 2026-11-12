using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Probes redirect/URL-like parameters with external URLs using <c>redirect: manual</c>
/// and detects open redirects (CWE-601) via Location header analysis.
/// </summary>
public sealed class OpenRedirectChecker
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    private const int MaxAdaptivePayloadsPerCandidate = 80;
    private const int MaxValidationProbes = 5;

    public OpenRedirectChecker(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public async Task<OpenRedirectResult> RunAsync(OpenRedirectOptions options, CancellationToken ct = default)
    {
        var probeHost = string.IsNullOrWhiteSpace(options.ProbeHost)
            ? RedirectAnalysis.DefaultProbeHost
            : options.ProbeHost.Trim();

        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running open redirect tests.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var paramNames = new HashSet<string>(
            (options.ParamNames is { Count: > 0 } ? options.ParamNames : UrlLikeParamNames.RedirectLike.ToList())
            .Select(p => p.ToLowerInvariant()));

        var max = options.MaxCandidates > 0 ? options.MaxCandidates : 12;
        var hasExplicit =
            (options.ExplicitUrls is { Count: > 0 }) || (options.EndpointHints is { Count: > 0 });

        // Discover uncapped, merge DOM/forms, then prioritize — never skip DOM because scaffolds filled max.
        var pool = RedirectParamDiscovery.DiscoverAll(
            _ctx, origin, paramNames, max: 500,
            options.ExplicitUrls, options.EndpointHints,
            includeNetwork: true,
            includeScaffold: !hasExplicit || options.IncludeScaffoldWithExplicit);

        var seen = new HashSet<string>(pool.Select(Key), StringComparer.OrdinalIgnoreCase);
        void Merge(IEnumerable<RedirectParamDiscovery.InjectionPoint> extra)
        {
            foreach (var pt in extra)
            {
                if (!seen.Add(Key(pt))) continue;
                pool.Add(pt);
            }
        }

        if (options.IncludeDomDiscovery)
        {
            Merge(await RedirectParamDiscovery.DiscoverFromDomAsync(_ctx, origin, paramNames, 50));
            Merge(await RedirectParamDiscovery.DiscoverFromFormsAsync(_ctx, origin, paramNames, 50));
        }

        var points = RedirectParamDiscovery.PrioritizeAndCap(pool, max);

        if (points.Count == 0)
        {
            return new OpenRedirectResult
            {
                Message = "No open-redirect candidates found. Browse the app, click redirect links, pass explicit \"urls\" " +
                          "or \"endpointHints\", or ensure redirect-like parameters appear in page hrefs or network log.",
                CandidatesProbed = 0,
                PayloadsSent = 0
            };
        }

        var timeout = options.TimeoutMs > 0 ? options.TimeoutMs : 15000;
        var findings = new List<OpenRedirectFinding>();
        var observations = new List<OpenRedirectObservation>();
        var payloadsSent = 0;

        _log($"OpenRedirect: {points.Count} candidate(s) from {string.Join(", ", points.Select(p => p.Source).Distinct())}", "#888888");

        foreach (var pt in points)
        {
            ct.ThrowIfCancellationRequested();
            var sent = await ProbeInjectionPointAsync(
                pt, probeHost, origin, options, timeout, findings, observations, ct);
            payloadsSent += sent;
        }

        if (options.IncludeDomDiscovery)
        {
            try
            {
                var clientDom = await OpenRedirectClientDomProbe.ProbeAsync(_ctx, timeout, ct);
                foreach (var f in clientDom)
                {
                    if (findings.Any(x =>
                            x.ParamName.Equals(f.ParamName, StringComparison.OrdinalIgnoreCase)
                            && x.Category.Equals(f.Category, StringComparison.OrdinalIgnoreCase)))
                        continue;
                    findings.Add(f);
                }
            }
            catch (Exception ex)
            {
                _log($"OpenRedirect client-DOM probe skipped: {ex.Message}", "#888888");
            }
        }

        var result = BuildResult(findings, points.Count, payloadsSent, observations, discoveryOnly: !hasExplicit);
        var missed = DescribeUnprobedCallerTargets(options, points);
        if (missed.Count > 0)
        {
            result = new OpenRedirectResult
            {
                Message = result.Message + " WARNING: caller-supplied urls/endpointHints were not probed: "
                           + string.Join("; ", missed),
                CandidatesProbed = result.CandidatesProbed,
                PayloadsSent = result.PayloadsSent,
                Findings = result.Findings,
                Warnings = missed,
                Observations = result.Observations
            };
        }

        return result;
    }

    private static List<string> DescribeUnprobedCallerTargets(
        OpenRedirectOptions options,
        List<RedirectParamDiscovery.InjectionPoint> probed)
    {
        var warnings = new List<string>();

        bool PathProbed(string path, string? param = null) =>
            probed.Any(p =>
                string.Equals(p.BaseUri.GetLeftPart(UriPartial.Path), path, StringComparison.OrdinalIgnoreCase)
                && (param == null || p.ParamName.Equals(param, StringComparison.OrdinalIgnoreCase)));

        if (options.ExplicitUrls is { Count: > 0 })
        {
            foreach (var url in options.ExplicitUrls)
            {
                if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) continue;
                var path = uri.GetLeftPart(UriPartial.Path);
                if (!PathProbed(path))
                    warnings.Add($"url not probed: {url}");
            }
        }

        if (options.EndpointHints is { Count: > 0 })
        {
            foreach (var hint in options.EndpointHints)
            {
                if (!Uri.TryCreate(hint.Url, UriKind.Absolute, out var uri)) continue;
                var path = uri.GetLeftPart(UriPartial.Path);
                foreach (var param in hint.ParamNames.Where(p => !string.IsNullOrWhiteSpace(p)))
                {
                    if (!PathProbed(path, param))
                        warnings.Add($"endpointHint not probed: {path}?{param}=");
                }
            }
        }

        return warnings;
    }

    private async Task<int> ProbeInjectionPointAsync(
        RedirectParamDiscovery.InjectionPoint pt,
        string probeHost,
        string origin,
        OpenRedirectOptions options,
        int timeout,
        List<OpenRedirectFinding> findings,
        List<OpenRedirectObservation> observations,
        CancellationToken ct)
    {
        var baselineValue = pt.OriginalValue ?? "/";
        var baselineProbe = RedirectParamDiscovery.BuildProbeRequest(pt, baselineValue);
        var baselineFetch = await FetchManualAsync(baselineProbe, pt.Method, timeout);
        var baselineSignals = ToSignals(baselineFetch);

        var payloads = RedirectParamDiscovery.BuildPayloads(
            probeHost, pt.OriginalValue, options.IncludeAdaptiveBypasses, options.Payloads);

        var sent = 0;
        var openRedirectConfirmed = false;
        ProbeFilterState? filterState = null;
        var probeDirectBlocked = false;

        foreach (var payload in payloads)
        {
            ct.ThrowIfCancellationRequested();
            sent++;
            var probeReq = RedirectParamDiscovery.BuildProbeRequest(pt, payload);
            var fetch = await FetchManualAsync(probeReq, pt.Method, timeout);

            if (!Uri.TryCreate(probeReq.Url, UriKind.Absolute, out var requestUri))
                continue;

            filterState ??= new ProbeFilterState();
            filterState.Record(payload, fetch, requestUri, probeHost, baselineSignals);

            if (IsDirectProbeBlocked(payload, probeHost, fetch.Status))
                probeDirectBlocked = true;

            var filterEvidence = probeDirectBlocked || filterState.AllowlistRejectCount > 0;
            if (TryAddFinding(findings, pt, payload, fetch, baselineFetch, requestUri, probeHost, baselineSignals, filterEvidence))
            {
                _log($"  FLAG {findings[^1].Indicator} ({findings[^1].Confidence}): {pt.ParamName} ← {Truncate(payload, 80)}", "#F44747");
                openRedirectConfirmed = true;
            }
            else if (IsNullByteWhitelistBypass(payload, probeHost, fetch.Status, probeDirectBlocked))
            {
                _log($"  FLAG null-byte-whitelist-bypass: {pt.ParamName} ← {Truncate(payload, 80)}", "#F44747");
                findings.Add(MakeFinding(pt, payload, fetch, baselineFetch, fetch.Location ?? "",
                    "medium", "confirmed", "null-byte-whitelist-bypass"));
                openRedirectConfirmed = true;
            }
        }

        if (options.IncludeAdaptiveBypasses &&
            (probeDirectBlocked || filterState?.AllExternalBlocked == true))
        {
            var adaptiveSent = await RunAdaptiveBypassPhaseAsync(
                pt, probeHost, origin, baselineFetch, baselineSignals, timeout,
                probeDirectBlocked, payloads, findings, ct);
            sent += adaptiveSent;
            if (adaptiveSent > 0 && findings.Count > 0)
                openRedirectConfirmed = true;
        }

        if (options.IncludeAdaptiveBypasses && filterState != null)
            LogFilterInsights(pt, filterState);

        if (filterState != null)
            TryAddRedirectFilteredObservation(pt, filterState, observations);

        if (options.IncludeSsrfEscalationProbes && openRedirectConfirmed)
        {
            foreach (var payload in RedirectParamDiscovery.SsrfEscalationPayloads())
            {
                ct.ThrowIfCancellationRequested();
                sent++;
                var probeReq = RedirectParamDiscovery.BuildProbeRequest(pt, payload);
                var fetch = await FetchManualAsync(probeReq, pt.Method, timeout);
                if (!Uri.TryCreate(probeReq.Url, UriKind.Absolute, out var requestUri))
                    continue;

                if (IsSsrfEscalation(payload, fetch.Location, requestUri))
                {
                    _log($"  FLAG ssrf-via-open-redirect: {pt.ParamName} ← {Truncate(payload, 80)}", "#F44747");
                    findings.Add(MakeFinding(pt, payload, fetch, baselineFetch, fetch.Location ?? "",
                        "high", "confirmed", "ssrf-via-open-redirect"));
                }
            }
        }

        return sent;
    }

    private async Task<int> RunAdaptiveBypassPhaseAsync(
        RedirectParamDiscovery.InjectionPoint pt,
        string probeHost,
        string origin,
        RedirectAnalysis.FetchManualParseResult baselineFetch,
        RedirectAnalysis.OpenRedirectResponseSignals baselineSignals,
        int timeout,
        bool probeDirectBlocked,
        List<string> basePayloads,
        List<OpenRedirectFinding> findings,
        CancellationToken ct)
    {
        var prefixes = await CollectAllowlistedPrefixesAsync(pt, probeHost, origin);

        if (prefixes.Count == 0)
        {
            _log($"  adaptive: no allowlist prefix candidates found for {pt.ParamName}", "#888888");
            return 0;
        }

        var validated = await ValidateWhitelistPrefixesAsync(pt, prefixes, probeHost, timeout, ct);
        var orderedPrefixes = validated.Count > 0
            ? validated.Concat(prefixes.Where(p => !validated.Contains(p, StringComparer.OrdinalIgnoreCase))).Distinct(StringComparer.OrdinalIgnoreCase).ToList()
            : prefixes;

        _log($"  adaptive: {orderedPrefixes.Count} prefix candidates ({validated.Count} validated), probing bypasses", "#888888");

        var sent = 0;
        var cap = MaxAdaptivePayloadsPerCandidate;
        var foundBypass = false;

        foreach (var prefix in orderedPrefixes)
        {
            if (sent >= cap || foundBypass)
                break;
            ct.ThrowIfCancellationRequested();

            foreach (var payload in RedirectParamDiscovery.GenerateAllowlistBypassPayloads(prefix, probeHost))
            {
                if (sent >= cap || foundBypass)
                    break;
                ct.ThrowIfCancellationRequested();

                if (basePayloads.Contains(payload, StringComparer.OrdinalIgnoreCase)) continue;

                sent++;
                var probeReq = RedirectParamDiscovery.BuildProbeRequest(pt, payload);
                var fetch = await FetchManualAsync(probeReq, pt.Method, timeout);
                if (!Uri.TryCreate(probeReq.Url, UriKind.Absolute, out var requestUri))
                    continue;

                if (TryAddFinding(findings, pt, payload, fetch, baselineFetch, requestUri, probeHost, baselineSignals, filterEvidence: true))
                {
                    _log($"  FLAG allowlist-bypass ({findings[^1].Confidence}): {pt.ParamName} ← {Truncate(payload, 80)}", "#F44747");
                    foundBypass = true;
                }
                else if (TryAddAllowlistBypassFinding(
                             findings, pt, payload, fetch, baselineFetch, requestUri, probeHost, probeDirectBlocked))
                {
                    _log($"  FLAG allowlist-filter-bypass: {pt.ParamName} ← {Truncate(payload, 80)}", "#F44747");
                    foundBypass = true;
                }
                else if (IsNullByteWhitelistBypass(payload, probeHost, fetch.Status, probeDirectBlocked))
                {
                    _log($"  FLAG null-byte-whitelist-bypass: {pt.ParamName} ← {Truncate(payload, 80)}", "#F44747");
                    findings.Add(MakeFinding(pt, payload, fetch, baselineFetch, fetch.Location ?? "",
                        "medium", "confirmed", "null-byte-whitelist-bypass"));
                    foundBypass = true;
                }
            }
        }

        return sent;
    }

    private async Task<List<string>> CollectAllowlistedPrefixesAsync(
        RedirectParamDiscovery.InjectionPoint pt,
        string probeHost,
        string origin)
    {
        var prefixes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return;
            var v = value.Trim();
            if (!v.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !v.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                return;
            if (v.Contains(probeHost, StringComparison.OrdinalIgnoreCase))
                return;
            prefixes.Add(v);
        }

        Add(pt.OriginalValue);

        foreach (var val in RedirectParamDiscovery.CollectAllowlistedRedirectValues(
                     _ctx.Network.Entries, origin, pt.BaseUri, pt.ParamName))
            Add(val);

        foreach (var val in CollectRedirectParamValuesFromDom(pt, origin))
            Add(val);

        return prefixes.ToList();
    }

    /// <summary>
    /// Extracts URL values from same-origin page links that target the redirect endpoint.
    /// E.g. if page has <c>&lt;a href="/redirect?to=https://blockchain.info/..."&gt;</c>, extracts the to= value.
    /// </summary>
    private List<string> CollectRedirectParamValuesFromDom(
        RedirectParamDiscovery.InjectionPoint pt,
        string origin)
    {
        var values = new List<string>();
        var targetPath = pt.BaseUri.GetLeftPart(UriPartial.Path);

        foreach (var entry in _ctx.Network.Entries)
        {
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Path), targetPath, StringComparison.OrdinalIgnoreCase))
                continue;

            var qs = System.Web.HttpUtility.ParseQueryString(uri.Query);
            var val = qs[pt.ParamName];
            if (string.IsNullOrWhiteSpace(val)) continue;
            val = val.Trim();
            if (!val.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !val.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                continue;

            if (!values.Contains(val, StringComparer.OrdinalIgnoreCase))
                values.Add(val);
            if (values.Count >= 10) break;
        }

        return values;
    }

    private async Task<List<string>> ValidateWhitelistPrefixesAsync(
        RedirectParamDiscovery.InjectionPoint pt,
        List<string> candidates,
        string probeHost,
        int timeout,
        CancellationToken ct)
    {
        var validated = new List<string>();
        foreach (var candidate in candidates.Take(MaxValidationProbes))
        {
            ct.ThrowIfCancellationRequested();
            if (candidate.Contains(probeHost, StringComparison.OrdinalIgnoreCase))
                continue;

            var probeReq = RedirectParamDiscovery.BuildProbeRequest(pt, candidate);
            var fetch = await FetchManualAsync(probeReq, pt.Method, timeout);
            if (RedirectAnalysis.IsRedirectStatus(fetch.Status) || fetch.Status is >= 200 and < 300)
            {
                if (!validated.Contains(candidate, StringComparer.OrdinalIgnoreCase))
                    validated.Add(candidate);
            }
        }

        return validated;
    }

    /// <summary>
    /// Detects null-byte whitelist bypass: payload contains a null-byte separator and was accepted (302)
    /// when direct probes to the probe host were blocked.
    /// </summary>
    private static bool IsNullByteWhitelistBypass(string payload, string probeHost, int status, bool directProbeBlocked)
    {
        if (!directProbeBlocked) return false;
        if (!RedirectAnalysis.IsRedirectStatus(status)) return false;
        if (!payload.Contains('\0') && !payload.Contains("%00", StringComparison.OrdinalIgnoreCase))
            return false;
        return payload.Contains(probeHost, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDirectProbeBlocked(string payload, string probeHost, int status) =>
        payload.Contains(probeHost, StringComparison.OrdinalIgnoreCase) &&
        status is >= 400 and < 500;

    private static bool TryAddAllowlistBypassFinding(
        List<OpenRedirectFinding> findings,
        RedirectParamDiscovery.InjectionPoint pt,
        string payload,
        RedirectAnalysis.FetchManualParseResult fetch,
        RedirectAnalysis.FetchManualParseResult baselineFetch,
        Uri requestUri,
        string probeHost,
        bool directProbeBlocked)
    {
        if (!directProbeBlocked) return false;
        if (!RedirectAnalysis.IsRedirectStatus(fetch.Status)) return false;
        if (!payload.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !payload.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return false;

        var external = RedirectAnalysis.IsExternalRedirect(requestUri, fetch.Location, probeHost);
        var confidence = external ? "confirmed" : "likely";
        var severity = external ? "high" : "medium";

        findings.Add(MakeFinding(pt, payload, fetch, baselineFetch, fetch.Location ?? "",
            severity, confidence, "allowlist-filter-bypass"));
        return true;
    }

    private static bool TryAddFinding(
        List<OpenRedirectFinding> findings,
        RedirectParamDiscovery.InjectionPoint pt,
        string payload,
        RedirectAnalysis.FetchManualParseResult fetch,
        RedirectAnalysis.FetchManualParseResult baselineFetch,
        Uri requestUri,
        string probeHost,
        RedirectAnalysis.OpenRedirectResponseSignals baselineSignals,
        bool filterEvidence = false)
    {
        var probeSignals = ToSignals(fetch);
        if (!RedirectAnalysis.ShouldFlagOpenRedirect(requestUri, probeHost, probeSignals, baselineSignals))
            return false;

        var location = EffectiveRedirectEvidence(fetch);
        var (severity, indicator) = RedirectParamDiscovery.ClassifyFinding(
            payload, pt.OriginalValue, location, filterEvidence: filterEvidence);
        if (string.IsNullOrEmpty(fetch.Location)
            && !string.IsNullOrEmpty(RedirectAnalysis.TryExtractRefreshTarget(fetch.RefreshHeader, fetch.ResponseBody)))
            indicator = "html-meta-refresh-redirect";

        var dangerousScheme = RedirectAnalysis.IsDangerousRedirectScheme(fetch.Location);
        var confidence = dangerousScheme
                         || RedirectAnalysis.LocationPointsToProbe(requestUri, location, probeHost)
            ? "confirmed" : "likely";

        findings.Add(MakeFinding(pt, payload, fetch, baselineFetch, location ?? "", severity, confidence, indicator, filterEvidence));
        return true;
    }

    private static string? EffectiveRedirectEvidence(RedirectAnalysis.FetchManualParseResult fetch) =>
        !string.IsNullOrWhiteSpace(fetch.Location)
            ? fetch.Location
            : RedirectAnalysis.TryExtractRefreshTarget(fetch.RefreshHeader, fetch.ResponseBody);

    private static RedirectAnalysis.OpenRedirectResponseSignals ToSignals(RedirectAnalysis.FetchManualParseResult fetch) =>
        new(fetch.Location, fetch.RefreshHeader, fetch.ResponseBody);

    private static OpenRedirectFinding MakeFinding(
        RedirectParamDiscovery.InjectionPoint pt,
        string payload,
        RedirectAnalysis.FetchManualParseResult fetch,
        RedirectAnalysis.FetchManualParseResult baselineFetch,
        string location,
        string severity,
        string confidence,
        string indicator,
        bool filterEvidence = false)
    {
        var probeReq = RedirectParamDiscovery.BuildProbeRequest(pt, payload);
        return new OpenRedirectFinding
        {
            Title = $"Open redirect via '{pt.ParamName}' ({indicator})",
            Category = "open-redirect",
            Severity = severity,
            Confidence = confidence,
            Url = probeReq.Body != null ? probeReq.Url + " (body)" : probeReq.Url,
            Method = pt.Method,
            ParamName = pt.ParamName,
            Payload = payload,
            Status = fetch.Status,
            BaselineStatus = baselineFetch.Status,
            Location = location,
            Indicator = indicator,
            BypassTechnique = RedirectParamDiscovery.ClassifyBypassTechnique(
                payload, pt.OriginalValue, location, filterEvidence),
            Source = pt.Source,
            Snippet = Truncate(location, 240)
        };
    }

    private void LogFilterInsights(RedirectParamDiscovery.InjectionPoint pt, ProbeFilterState state)
    {
        if (state.HttpsBlocked && state.ProtocolRelativeWorks)
            _log($"  note {pt.ParamName}: https:// blocked but // works — partial protocol filtering bypassable", "#CCA700");
        else if (state.AllExternalBlocked && state.SubstringBypassWorks)
            _log($"  note {pt.ParamName}: external host blocked but substring bypass worked (strpos-style filter)", "#CCA700");
        else if (state.AllExternalBlocked)
            _log($"  note {pt.ParamName}: all external URL probes blocked — allowlist-prefix bypass phase will run", "#888888");
    }

    private static bool IsSsrfEscalation(string payload, string? location, Uri requestUri)
    {
        if (string.IsNullOrEmpty(location)) return false;

        if (payload.StartsWith("file:", StringComparison.OrdinalIgnoreCase) &&
            (location.Contains("/etc/", StringComparison.OrdinalIgnoreCase) ||
             location.StartsWith("file:", StringComparison.OrdinalIgnoreCase)))
            return true;

        if (payload.Contains("127.0.0.1", StringComparison.Ordinal) &&
            location.Contains("127.0.0.1", StringComparison.Ordinal))
            return true;

        if (payload.Contains("169.254.169.254", StringComparison.Ordinal) &&
            location.Contains("169.254.169.254", StringComparison.Ordinal))
            return true;

        if (payload.StartsWith("gopher:", StringComparison.OrdinalIgnoreCase) &&
            location.Contains("gopher:", StringComparison.OrdinalIgnoreCase))
            return true;

        return RedirectAnalysis.IsExternalRedirect(requestUri, location) &&
               (location.Contains("127.0.0.1", StringComparison.Ordinal) ||
                location.Contains("169.254.169.254", StringComparison.Ordinal) ||
                location.StartsWith("file:", StringComparison.OrdinalIgnoreCase));
    }

    private async Task<RedirectAnalysis.FetchManualParseResult> FetchManualAsync(
        RedirectParamDiscovery.ProbeRequest request, string method, int timeout)
    {
        try
        {
            var json = await _ctx.Fetch(request.Url, method, request.Headers, request.Body, timeout, "manual");
            return RedirectAnalysis.ParseFetchManualResponse(json);
        }
        catch (Exception ex)
        {
            _log($"  fetch failed {Truncate(request.Url, 100)}: {ex.Message}", "#CCA700");
            return new RedirectAnalysis.FetchManualParseResult(0, null, null, null);
        }
    }

    private static bool HostMatchesPayload(string? location, string payload, string probeHost) =>
        !string.IsNullOrEmpty(location) &&
        (location.Contains(probeHost, StringComparison.OrdinalIgnoreCase) ||
         payload.Contains(probeHost, StringComparison.OrdinalIgnoreCase));

    private static string Key(RedirectParamDiscovery.InjectionPoint pt) =>
        $"{pt.Method}|{pt.BaseUri.GetLeftPart(UriPartial.Path)}|{pt.ParamName}";

    private static void TryAddRedirectFilteredObservation(
        RedirectParamDiscovery.InjectionPoint pt,
        ProbeFilterState state,
        List<OpenRedirectObservation> observations)
    {
        if (!state.AllExternalBlocked || state.AllowlistRejectCount == 0)
            return;

        var detail = state.AllowlistRejectCount >= 2
            ? $"{state.AllowlistRejectCount} external URL probes returned HTTP 406 (or similar) without redirect — likely allowlist filtering on '{pt.ParamName}'."
            : $"External URL probe returned HTTP 406 without redirect — allowlist may block off-site targets on '{pt.ParamName}'.";

        observations.Add(new OpenRedirectObservation
        {
            Kind = "redirect-filtered",
            ParamName = pt.ParamName,
            Url = pt.BaseUri.GetLeftPart(UriPartial.Path),
            Method = pt.Method,
            Detail = detail
        });
    }

    private static OpenRedirectResult BuildResult(
        List<OpenRedirectFinding> findings,
        int candidates,
        int payloadsSent,
        List<OpenRedirectObservation> observations,
        bool discoveryOnly)
    {
        var deduped = findings
            .GroupBy(f => $"{f.Method}|{f.ParamName}|{f.Indicator}|{f.Location}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(f => SeverityRank(f.Severity)).First())
            .OrderByDescending(f => SeverityRank(f.Severity))
            .ToList();

        var msg = deduped.Count == 0
            ? $"No open redirects detected ({candidates} candidate(s), {payloadsSent} payload(s))."
            : $"Found {deduped.Count} open redirect(s) across {candidates} candidate(s).";

        var obs = observations
            .GroupBy(o => $"{o.Kind}|{o.ParamName}|{o.Url}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();

        if (discoveryOnly && deduped.Count == 0)
        {
            obs.Insert(0, new OpenRedirectObservation
            {
                Kind = "coverage",
                ParamName = "",
                Url = "",
                Method = "",
                Detail =
                    "Discovery-only run: results apply only to redirect-like parameters observed in the DOM/network log " +
                    "or generic scaffolds. Browse the flow that exposes the redirect parameter (e.g. post-login return URL) " +
                    "or pass explicit urls/endpointHints for full coverage."
            });
            msg += " Coverage note: discovery mode only probes parameters already visible in the session — not proof of absence for unvisited flows.";
        }

        return new OpenRedirectResult
        {
            Message = msg,
            CandidatesProbed = candidates,
            PayloadsSent = payloadsSent,
            Findings = deduped,
            Observations = obs
        };
    }

    private static int SeverityRank(string s) => s switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        _ => 1
    };

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";

    private sealed class ProbeFilterState
    {
        public bool HttpsBlocked { get; private set; }
        public bool ProtocolRelativeWorks { get; private set; }
        public bool AllExternalBlocked { get; private set; } = true;
        public bool SubstringBypassWorks { get; private set; }
        public int AllowlistRejectCount { get; private set; }

        public void Record(
            string payload,
            RedirectAnalysis.FetchManualParseResult fetch,
            Uri requestUri,
            string probeHost,
            RedirectAnalysis.OpenRedirectResponseSignals baseline)
        {
            var probe = new RedirectAnalysis.OpenRedirectResponseSignals(
                fetch.Location, fetch.RefreshHeader, fetch.ResponseBody);
            var works = RedirectAnalysis.ShouldFlagOpenRedirect(requestUri, probeHost, probe, baseline);

            var external = RedirectAnalysis.IsExternalRedirect(requestUri, fetch.Location, probeHost);
            if (!works && external && fetch.Status is 406 or 403 or 400)
                AllowlistRejectCount++;

            if (works)
            {
                AllExternalBlocked = false;
                if (payload.StartsWith("//", StringComparison.Ordinal))
                    ProtocolRelativeWorks = true;
                if (payload.Contains('/') && !payload.StartsWith($"https://{probeHost}", StringComparison.OrdinalIgnoreCase))
                    SubstringBypassWorks = true;
            }

            if (payload.StartsWith($"https://{probeHost}", StringComparison.OrdinalIgnoreCase) &&
                RedirectAnalysis.IsRedirectStatus(fetch.Status) && !works)
                HttpsBlocked = true;
        }
    }
}

public sealed class OpenRedirectOptions
{
    public List<string>? ExplicitUrls { get; init; }
    public List<EndpointParamHint>? EndpointHints { get; init; }
    public List<string>? ParamNames { get; init; }
    public List<string>? Payloads { get; init; }
    public string? ProbeHost { get; init; }
    public int MaxCandidates { get; init; } = 12;
    public int TimeoutMs { get; init; } = 15000;
    /// <summary>Scan page hrefs and current URL for redirect params (default on).</summary>
    public bool IncludeDomDiscovery { get; init; } = true;
    /// <summary>Include javascript:/data: payloads and log filter bypass insights (default on).</summary>
    public bool IncludeAdaptiveBypasses { get; init; } = true;
    /// <summary>After open redirect confirmed, probe file:// and internal IPs for SSRF escalation (default on).</summary>
    public bool IncludeSsrfEscalationProbes { get; init; } = true;
    /// <summary>
    /// When urls/endpointHints are set, scaffolds are skipped by default. Set true to also probe
    /// synthetic /redirect and /api/goto paths alongside caller targets.
    /// </summary>
    public bool IncludeScaffoldWithExplicit { get; init; }
}

public sealed class OpenRedirectResult
{
    public string Message { get; init; } = "";
    public int CandidatesProbed { get; init; }
    public int PayloadsSent { get; init; }
    public List<OpenRedirectFinding> Findings { get; init; } = [];
    /// <summary>Caller-supplied urls/endpointHints that did not make it into the probed set.</summary>
    public List<string> Warnings { get; init; } = [];
    /// <summary>Non-vulnerability signals (allowlist/406 filtering, etc.).</summary>
    public List<OpenRedirectObservation> Observations { get; init; } = [];
}

public sealed class OpenRedirectObservation
{
    public string Kind { get; init; } = "";
    public string ParamName { get; init; } = "";
    public string Url { get; init; } = "";
    public string Method { get; init; } = "";
    public string Detail { get; init; } = "";
}

public sealed class OpenRedirectFinding
{
    /// <summary>LLM-friendly summary title (aligned with other scanners' triage contract).</summary>
    public string Title { get; init; } = "";
    public string Severity { get; init; } = "medium";
    public string Confidence { get; init; } = "likely";
    public string Category { get; init; } = "open-redirect";
    public string Url { get; init; } = "";
    public string Method { get; init; } = "";
    public string ParamName { get; init; } = "";
    public string Payload { get; init; } = "";
    public int Status { get; init; }
    public int BaselineStatus { get; init; }
    public string Location { get; init; } = "";
    public string Indicator { get; init; } = "";
    public string? BypassTechnique { get; init; }
    public string Source { get; init; } = "";
    public string Snippet { get; init; } = "";
}
