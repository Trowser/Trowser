using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;
using Trowser.Security.CrossSite;

namespace Trowser.Security;

/// <summary>
/// Automated CSRF validation checker. Discovers state-changing endpoints from the network
/// log that use anti-CSRF tokens, then tests whether the server properly rejects requests
/// with missing or invalid tokens.
/// </summary>
public class CsrfChecker
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    private static readonly HashSet<string> SearchOnlyPathTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "search", "query", "filter", "list", "find", "browse"
    };

    private static readonly HashSet<string> SearchOnlyFieldTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "q", "query", "search", "s", "term", "keyword", "keywords", "page", "offset", "limit", "sort", "order", "dir"
    };

    private static readonly string[] SubmitMutationPhrases =
    [
        "change", "update", "delete", "save", "submit", "confirm", "send", "add", "remove", "create", "modify"
    ];

    /// <summary>
    /// Body fields that provide implicit CSRF protection through framework-level ViewState or
    /// equivalent mechanisms. Requests carrying these are not flagged as unprotected because
    /// the server validates them on postback (e.g. ASP.NET WebForms validates __VIEWSTATE MAC,
    /// JSF validates javax.faces.ViewState).
    /// </summary>
    private static readonly (string PrimaryField, string[] SupportingFields, string Framework)[] ImplicitCsrfProtectionPatterns =
    [
        ("__VIEWSTATE", ["__EVENTVALIDATION", "__VIEWSTATEGENERATOR"], "ASP.NET WebForms"),
        ("javax.faces.ViewState", [], "JSF (javax)"),
        ("jakarta.faces.ViewState", [], "JSF (jakarta)"),
    ];

    /// <summary>Keywords for form field / submit heuristics (broader than path-only GET hints).</summary>
    private static readonly HashSet<string> StateChangeKeywordSet = new(StringComparer.OrdinalIgnoreCase)
    {
        "delete", "create", "update", "save", "remove", "add", "modify", "submit",
        "newsnippet", "saveprofile", "deletesnippet", "snippet", "profile", "upload",
        "destroy", "edit", "toggle", "set", "put", "post",
        "password", "passwd", "change", "rename", "move", "transfer", "send", "approve",
        "reject", "confirm", "cancel", "enable", "disable", "upgrade", "downgrade",
        "admin", "role", "permission", "setting", "config", "subscribe", "unsubscribe",
    };

    /// <summary>
    /// Path/query tokens (split by / - _ .) that suggest GET-driven state changes.
    /// Whole-path substring matching is avoided so e.g. <c>/assets/...</c> does not match <c>set</c>.
    /// Excludes common page routes like profile/admin.
    /// </summary>
    private static readonly HashSet<string> PathMutationKeywordSet = new(StringComparer.OrdinalIgnoreCase)
    {
        "delete", "create", "update", "save", "remove", "add", "modify", "submit",
        "newsnippet", "saveprofile", "deletesnippet", "deletes", "upload",
        "destroy", "edit", "toggle", "set", "put", "post",
        "password", "passwd", "change", "rename", "move", "transfer", "send", "approve",
        "reject", "confirm", "cancel", "enable", "disable", "upgrade", "downgrade",
    };

    private static readonly HashSet<string> StaticResourceExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".mp4", ".webm", ".mp3", ".wav", ".ogg", ".pdf", ".zip", ".gz",
        ".css", ".js", ".mjs", ".map"
    };

    /// <summary>
    /// Path ends with <c>.css.xhtml</c> / <c>.svg.xhtml</c> (JSF resource URLs) or other static asset + framework suffix.
    /// </summary>
    private static readonly Regex StaticAssetPathSuffixRegex = new(
        @"\.(css|js|mjs|svg|png|jpe?g|gif|ico|woff2?|ttf|eot|map)(\.[a-z0-9._-]+)?$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public CsrfChecker(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    private List<NetworkEntry> SelectScopedNetworkEntries(List<NetworkEntry> allEntries, string? hostFilter)
    {
        if (hostFilter == null)
            return allEntries;

        // Use full session network log scoped by host — PageEntries only covers the current page
        // and drops earlier POSTs (login, register, logoff) needed for CSRF analysis.
        return allEntries.Where(e => SecurityHostScope.Matches(e.Host, hostFilter)).ToList();
    }

    public async Task<CsrfResult> RunAsync(int maxEndpoints = 5, int maxUnprotected = 10, bool includeGet = false,
        string? hostFilter = null, bool includeRefererBypass = true, int maxRefererEndpoints = 5,
        bool includeJsonApiProbing = true, int maxJsonApiProbes = 10,
        bool includeCustomHeaderProbes = true, int maxCustomHeaderProbes = 5,
        bool includeSameSiteAnalysis = true,
        bool includeCrossSiteProof = false, int maxCrossSiteProbes = 3, string attackerSite = "cross-site")
    {
        var allEntries = _ctx.Network.Entries;
        // Page-scoped + same-origin host matching for default scans; full session log when hostFilter is null (allHosts).
        var entries = SelectScopedNetworkEntries(allEntries, hostFilter);
        var getHints = CollectStateChangingGetHints(entries);

        var allTokenCandidates = DiscoverCsrfEndpoints(entries, includeGet);
        // Any captured request that carried a token marks its logical endpoint — independent of includeGet
        // and active-probe candidate selection (fixes GET ?user_token=… vs "none observed" contradictions).
        var tokenKeySet = BuildTokenBearerKeySet(entries);

        var (unprotected, implicitProtected) = DiscoverUnprotectedEndpoints(entries, tokenKeySet, maxUnprotected, includeGet);
        var plannedForms = CsrfDomFormPlanner.Plan(await FormProbeCloner.CaptureFormsAsync(_ctx), hostFilter);
        var formTokenCandidates = new List<CsrfCandidate>();
        // A captured POST with an empty or unrecognized body is not "no token" when the live form has a token field.
        unprotected.RemoveAll(u =>
        {
            var form = plannedForms.FirstOrDefault(p =>
                p.CsrfField != null && CsrfDomFormPlanner.SameEndpoint(u.Method, u.Url, p));
            if (form == null)
                return false;
            formTokenCandidates.Add(CandidateFromForm(form, u.OriginalStatus, u.RequestHeaders, u.RequestBody));
            return true;
        });
        foreach (var form in plannedForms)
        {
            var already = allTokenCandidates.Any(c => CsrfDomFormPlanner.SameEndpoint(c.Method, c.Url, form))
                || formTokenCandidates.Any(c => CsrfDomFormPlanner.SameEndpoint(c.Method, c.Url, form))
                || unprotected.Any(c => CsrfDomFormPlanner.SameEndpoint(c.Method, c.Url, form));
            if (already)
                continue;
            if (form.CsrfField != null)
                formTokenCandidates.Add(CandidateFromForm(form, 0, null, null));
            else if (unprotected.Count < maxUnprotected)
                unprotected.Add(CandidateFromForm(form, 0, null, null));
        }

        var passiveGetFindings = DiscoverPassiveGetFindings(entries, tokenKeySet, hostFilter, maxUnprotected);

        var candidates = formTokenCandidates.Concat(allTokenCandidates).ToList();
        if (candidates.Count > maxEndpoints)
            candidates = candidates.Take(maxEndpoints).ToList();

        var getFormScenarios = await AnalyzeGetFormsOnPageAsync(hostFilter);

        if (candidates.Count == 0 && unprotected.Count == 0 && implicitProtected.Count == 0
            && getFormScenarios.Count == 0 && passiveGetFindings.Count == 0)
        {
            var hintMsg = getHints.Count > 0
                ? $" Found {getHints.Count} GET request(s) with state-change-like paths or parameters in the network log."
                : "";
            return new CsrfResult
            {
                Message = "No suitable state-changing requests in the network log and no GET forms with state-change indicators on the current page. " +
                    "Browse the application and submit forms or API calls (POST/PUT/PATCH/DELETE) so successful traffic is captured first." + hintMsg,
                StateChangingGetHints = getHints,
                GetFormFindingsCount = 0,
            };
        }

        var scenarios = new List<CsrfScenario>();
        scenarios.AddRange(getFormScenarios);
        scenarios.AddRange(passiveGetFindings);

        // Endpoints already replayed with custom headers removed. The dedicated header prober should not do it again.
        var headerReplayKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var u in unprotected)
        {
            if (CsrfTokenHeuristics.CustomHeaderCsrfCandidates(u.RequestHeaders).Count > 0)
                headerReplayKeys.Add($"{u.Method}|{u.Url}");
            scenarios.Add(await ClassifyUnprotectedAsync(u));
        }

        foreach (var (ep, framework) in implicitProtected)
        {
            _log($"  [implicit CSRF: {framework}] {ep.Method} {ep.Path}", "#4EC9B0");
            scenarios.Add(new CsrfScenario
            {
                Url = ep.Url,
                Path = ep.Path,
                Method = ep.Method,
                TestType = "implicit-csrf-protection",
                Description =
                    $"No explicit anti-CSRF token, but {framework} implicit protection detected (e.g. __VIEWSTATE with MAC validation, " +
                    "ViewState). The framework validates these fields on postback, providing CSRF protection. " +
                    "Verify that ViewState MAC validation is enabled on the server (EnableViewStateMac = true).",
                OriginalStatus = ep.OriginalStatus,
                TestStatus = ep.OriginalStatus,
                Vulnerable = false,
                Error = null,
                TokenLocation = $"implicit: {framework}",
            });
        }

        if (candidates.Count > 0)
        {
            _log($"CsrfChecker: testing {candidates.Count} endpoint(s) with CSRF tokens", "#888888");

            foreach (var candidate in candidates)
            {
                _log($"  {candidate.Method} {candidate.Path}", "#888888");

                var missingResult = await TestWithoutToken(candidate);
                scenarios.Add(missingResult);

                // A fixed flag such as X-CSRF: 1 is enforced by presence. Substituting a fake secret
                // reports a false "invalid token accepted" when the server only checks that the header is there.
                if (!IsPresenceOnlyCsrfHeader(candidate))
                {
                    var invalidResult = await TestWithInvalidToken(candidate);
                    scenarios.Add(invalidResult);
                }
            }
        }

        scenarios = DeduplicateScenarios(scenarios);

        var refererFindings = new List<CsrfRefererFinding>();
        var refererBypassCount = 0;
        if (includeRefererBypass)
        {
            var refererEndpoints = DiscoverRefererEndpoints(entries, maxRefererEndpoints, includeGet);
            if (refererEndpoints.Count > 0)
            {
                _log($"CsrfChecker: Referer bypass analysis on {refererEndpoints.Count} endpoint(s)", "#888888");
                refererFindings = await RunRefererBypassAnalysisAsync(refererEndpoints);
                refererBypassCount = refererFindings.Sum(f => f.Probes.Count(p => p.Vulnerable));
            }
        }

        var jsonApiHints = new List<JsonApiCsrfProber.Hint>();
        var jsonApiProbesRun = 0;
        if (includeJsonApiProbing)
        {
            var jsonResult = await new JsonApiCsrfProber(_ctx, _log).RunAsync(
                entries,
                new JsonApiCsrfProber.ProbeOptions
                {
                    HostFilter = hostFilter,
                    MaxProbes = maxJsonApiProbes,
                });
            scenarios.AddRange(jsonResult.Scenarios);
            jsonApiHints = jsonResult.Hints;
            jsonApiProbesRun = jsonResult.ProbesRun;
        }

        scenarios = SuppressContradictoryNoTokenFindings(scenarios);
        scenarios = DeduplicateScenarios(scenarios);

        CsrfSameSiteAnalyzer.SameSiteContext? sameSiteContext = null;
        if (includeSameSiteAnalysis)
        {
            var pageUrl = await _ctx.GetCurrentUrl();
            sameSiteContext = await CsrfSameSiteAnalyzer.AnalyzeAsync(_ctx, pageUrl);
            foreach (var scenario in scenarios.Where(s => s.Vulnerable))
            {
                var baseline = string.IsNullOrEmpty(scenario.Severity)
                    ? CsrfSameSiteAnalyzer.DefaultNoTokenSeverity(
                        sameSiteContext, scenario.Method, scenario.TestType)
                    : scenario.Severity;
                scenario.Severity = CsrfSameSiteAnalyzer.AdjustSeverity(
                    baseline, sameSiteContext, scenario.Method);
            }
        }
        else
        {
            foreach (var scenario in scenarios.Where(s => s.Vulnerable && string.IsNullOrEmpty(s.Severity)))
            {
                scenario.Severity = CsrfSameSiteAnalyzer.DefaultNoTokenSeverity(
                    null, scenario.Method, scenario.TestType);
            }
        }

        // Downgrade login/auth CSRF — not equivalent to password-change CSRF.
        foreach (var scenario in scenarios.Where(s => s.Vulnerable
                     && LooksLikeLoginCsrfTarget(s.Url, s.Path, null)))
        {
            if (SeverityRankName(scenario.Severity) > SeverityRankName("low"))
                scenario.Severity = "info";
            if (!scenario.Description.Contains("Login/auth CSRF", StringComparison.OrdinalIgnoreCase))
            {
                scenario.Description +=
                    " Login/auth CSRF is typically lower impact than authenticated state-changing CSRF.";
            }
        }

        var customHeaderProbesRun = 0;
        if (includeCustomHeaderProbes && maxCustomHeaderProbes > 0)
        {
            var headerCandidates = BuildCustomHeaderCandidates(entries, candidates, unprotected, maxCustomHeaderProbes);
            if (headerCandidates.Count > 0)
            {
                var headerScenarios = await new CsrfCustomHeaderProber(_ctx, _log).RunAsync(
                    headerCandidates, maxCustomHeaderProbes, headerReplayKeys);
                customHeaderProbesRun = headerScenarios.Count;
                scenarios.AddRange(headerScenarios);
                scenarios = DeduplicateScenarios(scenarios);
            }
        }

        var vulnerable = scenarios.Count(s => s.Vulnerable);
        var tokenIssues = scenarios.Count(s => s.Vulnerable && s.TestType is "missing-token" or "invalid-token" or "json-api-missing-token");
        var unprotectedCount = scenarios.Count(s =>
            s.Vulnerable && s.TestType is "no-csrf-token" or "get-form-no-csrf-token" or "get-request-no-csrf-token");
        var getFormCount = scenarios.Count(s => s.TestType.StartsWith("get-form", StringComparison.OrdinalIgnoreCase)
            || s.TestType.StartsWith("get-request", StringComparison.OrdinalIgnoreCase));
        var implicitCount = scenarios.Count(s => s.TestType == "implicit-csrf-protection");
        var getSpecViolationCount = scenarios.Count(s => s.TestType is "get-form-csrf-spec-violation" or "get-request-csrf-spec-violation");
        var jsonApiVulnCount = scenarios.Count(s => s.Vulnerable && s.TestType.StartsWith("json-api", StringComparison.OrdinalIgnoreCase));

        string message;
        if (unprotectedCount > 0 && tokenIssues > 0)
            message = $"{unprotectedCount} endpoint(s) or GET form(s) show no CSRF protection; " +
                $"{tokenIssues} token-based test scenario(s) indicate the server may accept forged or tampered tokens.";
        else if (unprotectedCount > 0)
            message = $"{unprotectedCount} state-changing endpoint(s) or GET form(s) have no observable CSRF token — review for cookie-based CSRF risk.";
        else if (tokenIssues > 0)
            message = $"{tokenIssues} potential CSRF issue(s) — server may accept requests with missing or invalid anti-CSRF tokens.";
        else if (candidates.Count > 0)
            message = "All tested endpoints with CSRF tokens properly rejected missing or invalid token scenarios.";
        else if (getSpecViolationCount > 0)
            message = $"{getSpecViolationCount} GET state-change pattern(s) use CSRF tokens but violate HTTP semantics (GET must not mutate state).";
        else
            message = "No CSRF token-bearing endpoints were tested.";

        if (implicitCount > 0)
        {
            var frameworks = implicitProtected.Select(p => p.Framework).Distinct().ToList();
            message += $" {implicitCount} endpoint(s) use implicit framework CSRF protection ({string.Join(", ", frameworks)}) — not flagged as vulnerable. " +
                "Verify server-side MAC validation is enabled.";
        }

        var customEnforced = scenarios.Count(s => s.TestType == "custom-header-enforced");
        if (customEnforced > 0)
            message += $" {customEnforced} endpoint(s) rejected a replay with custom headers removed — not marked vulnerable. Confirm CORS does not allow an attacker origin to send those headers.";

        if (getHints.Count > 0 && getFormCount == 0)
            message += $" {getHints.Count} additional GET URL(s) matched state-change heuristics (see stateChangingGetHints).";

        if (getFormCount > 0 && includeGet == false && candidates.Count == 0)
            message += " Set includeGet: true to probe GET endpoints that already include CSRF tokens.";

        if (refererBypassCount > 0)
            message += $" {refererBypassCount} Referer bypass probe(s) succeeded — review Referer-based CSRF defenses.";
        else if (refererFindings.Any(f => f.RefererValidationDetected))
            message += " Referer validation detected on probed endpoints; no bypass variants succeeded.";

        if (jsonApiHints.Count > 0)
            message += $" JSON API scan found {jsonApiHints.Count} hint(s), ran {jsonApiProbesRun} probe(s).";
        if (jsonApiVulnCount > 0)
            message += $" {jsonApiVulnCount} JSON API CSRF probe(s) indicate missing token acceptance.";
        if (customHeaderProbesRun > 0)
            message += $" {customHeaderProbesRun} custom-header / simple Content-Type probe(s) executed.";
        if (sameSiteContext != null)
            message += $" SameSite cookie risk: {sameSiteContext.CrossSiteCookieRisk}.";

        CrossSiteCsrfProber.RunResult? crossSite = null;
        if (includeCrossSiteProof && maxCrossSiteProbes > 0)
        {
            var crossTargets = BuildCrossSiteTargets(candidates, unprotected, scenarios, maxCrossSiteProbes);
            if (crossTargets.Count > 0)
            {
                _log($"CsrfChecker: browser cross-site proof on {crossTargets.Count} target(s)", "#888888");
                crossSite = await new CrossSiteCsrfProber(_ctx, _log).RunAsync(
                    crossTargets, maxCrossSiteProbes, attackerSite);
                foreach (var proof in crossSite.Proofs)
                {
                    scenarios.Add(new CsrfScenario
                    {
                        Url = proof.Url,
                        Path = proof.Path,
                        Method = proof.Method,
                        TestType = $"cross-site-{proof.Technique}",
                        Severity = proof.Severity,
                        Description = proof.Description,
                        OriginalStatus = crossTargets.FirstOrDefault(t =>
                            string.Equals(t.Url, proof.Url, StringComparison.OrdinalIgnoreCase))?.OriginalStatus ?? 0,
                        TestStatus = proof.ObservedStatus ?? 0,
                        Vulnerable = proof.Vulnerable,
                        TokenLocation = $"attacker:{crossSite.AttackerOrigin}",
                    });
                }

                scenarios = DeduplicateScenarios(scenarios);
                vulnerable = scenarios.Count(s => s.Vulnerable);
                if (crossSite.Proofs.Any(p => p.Vulnerable))
                {
                    message += $" {crossSite.Proofs.Count(p => p.Vulnerable)} browser cross-site CSRF proof(s) succeeded.";
                }
                else if (crossSite.ProbesRun > 0)
                {
                    message += $" {crossSite.ProbesRun} browser cross-site probe(s) did not confirm CSRF (SameSite/CORS may block).";
                }
            }
        }

        return new CsrfResult
        {
            EndpointsTested = candidates.Count,
            UnprotectedCount = unprotectedCount,
            ImplicitProtectionCount = implicitCount,
            Scenarios = scenarios,
            VulnerableCount = vulnerable,
            Message = message.Trim(),
            StateChangingGetHints = getHints,
            GetFormFindingsCount = getFormCount,
            RefererFindings = refererFindings,
            RefererEndpointsTested = refererFindings.Count,
            RefererBypassCount = refererBypassCount,
            JsonApiHints = jsonApiHints,
            JsonApiProbesRun = jsonApiProbesRun,
            SameSiteContext = sameSiteContext,
            CustomHeaderProbesRun = customHeaderProbesRun,
            CrossSiteProof = crossSite,
        };
    }

    private static List<CrossSiteCsrfProber.Target> BuildCrossSiteTargets(
        List<CsrfCandidate> tokenCandidates,
        List<CsrfCandidate> unprotected,
        List<CsrfScenario> scenarios,
        int maxTargets)
    {
        var list = new List<CrossSiteCsrfProber.Target>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void TryAdd(CsrfCandidate c, bool stripToken)
        {
            var key = $"{c.Method}|{c.Url}";
            if (!seen.Add(key) || list.Count >= maxTargets)
                return;
            list.Add(ToCrossSiteTarget(c, stripToken));
        }

        foreach (var s in scenarios.Where(s => s.Vulnerable))
        {
            if (!IsCrossSiteSeedScenario(s.TestType))
                continue;

            var match = tokenCandidates.Concat(unprotected)
                .FirstOrDefault(c => string.Equals(c.Url, s.Url, StringComparison.OrdinalIgnoreCase)
                                     && string.Equals(c.Method, s.Method, StringComparison.OrdinalIgnoreCase));
            if (match != null)
                TryAdd(match, stripToken: match.CsrfHeaderName != null || match.CsrfBodyField != null || match.CsrfQueryParam != null);
        }

        foreach (var u in unprotected)
        {
            if (list.Count >= maxTargets) break;
            TryAdd(u, stripToken: false);
        }

        return list;
    }

    private static bool IsCrossSiteSeedScenario(string testType) =>
        testType is "missing-token" or "no-csrf-token" or "invalid-token"
            or "custom-header-omitted" or "simple-content-type-accepted"
        || testType.StartsWith("json-api", StringComparison.OrdinalIgnoreCase);

    private static CrossSiteCsrfProber.Target ToCrossSiteTarget(CsrfCandidate candidate, bool stripToken)
    {
        var headers = new Dictionary<string, string>(candidate.RequestHeaders, StringComparer.OrdinalIgnoreCase);
        var body = candidate.RequestBody;
        var url = candidate.Url;

        if (stripToken)
        {
            if (candidate.CsrfHeaderName != null)
                headers.Remove(candidate.CsrfHeaderName);
            if (candidate.CsrfBodyField != null && body != null)
                body = RemoveBodyField(body, candidate.CsrfBodyField);
            if (candidate.CsrfQueryParam != null)
                url = RemoveQueryParamFromUrl(url, candidate.CsrfQueryParam);
        }

        headers.TryGetValue("Content-Type", out var ct);
        if (string.IsNullOrWhiteSpace(ct))
            headers.TryGetValue("content-type", out ct);

        return new CrossSiteCsrfProber.Target
        {
            Url = url,
            Path = candidate.Path,
            Method = candidate.Method,
            Body = body,
            ContentType = ct,
            OriginalStatus = candidate.OriginalStatus,
            OriginalBody = null
        };
    }

    private static List<CsrfProbeCandidate> BuildCustomHeaderCandidates(
        List<NetworkEntry> entries,
        List<CsrfCandidate> tokenCandidates,
        List<CsrfCandidate> unprotected,
        int max)
    {
        var list = new List<CsrfProbeCandidate>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddFrom(CsrfCandidate c, string? bodySample)
        {
            var key = CandidateDedupKey(c);
            if (!seen.Add(key)) return;
            list.Add(new CsrfProbeCandidate
            {
                Url = c.Url,
                Path = c.Path,
                Method = c.Method,
                RequestHeaders = c.RequestHeaders,
                RequestBody = c.RequestBody,
                OriginalStatus = c.OriginalStatus,
                OriginalBody = bodySample,
            });
        }

        foreach (var c in tokenCandidates)
        {
            if (list.Count >= max) break;
            var body = entries.FirstOrDefault(e =>
                e.Method.Equals(c.Method, StringComparison.OrdinalIgnoreCase)
                && e.Url.Equals(c.Url, StringComparison.OrdinalIgnoreCase))?.ResponseBody;
            AddFrom(c, body);
        }

        foreach (var c in unprotected)
        {
            if (list.Count >= max) break;
            var body = entries.FirstOrDefault(e =>
                e.Method.Equals(c.Method, StringComparison.OrdinalIgnoreCase)
                && e.Url.Equals(c.Url, StringComparison.OrdinalIgnoreCase))?.ResponseBody;
            AddFrom(c, body);
        }

        return list.Take(max).ToList();
    }

    /// <summary>
    /// Logical endpoint key for deduplication (method + host + path).
    /// </summary>
    private static string EndpointLogicalKey(string method, string url) =>
        SecurityHostScope.LogicalEndpointKey(method, url);

    /// <summary>
    /// Stable field-set signature for POST bodies (and GET query strings) so two handlers on the same URL
    /// (e.g. different HTML forms posting to <c>/profile</c>) are not conflated.
    /// </summary>
    private static string BodyShapeSignature(NetworkEntry e)
    {
        if (string.Equals(e.Method, "GET", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var uri))
                return "";
            return QueryParamNamesSignature(uri.Query);
        }

        return BodyShapeSignatureFromContent(e.RequestBody);
    }

    private static string QueryParamNamesSignature(string? query)
    {
        if (string.IsNullOrEmpty(query))
            return "";
        var q = query.StartsWith('?') ? query[1..] : query;
        var names = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in q.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            var key = eq >= 0 ? part[..eq] : part;
            key = Uri.UnescapeDataString(key);
            if (!string.IsNullOrEmpty(key))
                names.Add(key);
        }

        return names.Count == 0 ? "" : string.Join(",", names);
    }

    private static string BodyShapeSignatureFromContent(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return "";

        var trimmed = body.TrimStart();
        if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
        {
            try
            {
                using var doc = JsonDocument.Parse(body);
                var names = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
                CollectJsonPropertyNames(doc.RootElement, names, depth: 0);
                return names.Count == 0 ? "json:empty" : "json:" + string.Join(",", names);
            }
            catch
            {
                return "json:parse-error";
            }
        }

        if (trimmed.StartsWith("--"))
            return "multipart";

        if (trimmed.Contains('=', StringComparison.Ordinal))
            return "form:" + QueryParamNamesSignature(trimmed.Replace('\n', '&').Replace('\r', '&'));

        return "opaque";
    }

    private static void CollectJsonPropertyNames(JsonElement el, SortedSet<string> names, int depth)
    {
        if (depth > 6) return;
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var p in el.EnumerateObject())
                {
                    names.Add(p.Name);
                    CollectJsonPropertyNames(p.Value, names, depth + 1);
                }
                break;
            case JsonValueKind.Array:
                var i = 0;
                foreach (var item in el.EnumerateArray())
                {
                    CollectJsonPropertyNames(item, names, depth + 1);
                    if (++i >= 20) break;
                }
                break;
        }
    }

    private static string CandidateDedupKey(CsrfCandidate c) =>
        $"{EndpointLogicalKey(c.Method, c.Url)}|{BodyShapeSignatureFromContent(c.RequestBody)}";

    private static string EntryDedupKey(NetworkEntry e) =>
        $"{EndpointLogicalKey(e.Method, e.Url)}|{BodyShapeSignature(e)}";

    private static string ScenarioDedupKey(CsrfScenario s) =>
        $"{s.Method}|{s.Path}|{s.TestType}";

    /// <summary>
    /// Drops contradictory network-log "none observed" findings when another network scenario on the same
    /// logical endpoint already saw a token. Live DOM form findings (get-form-*) are never suppressed.
    /// </summary>
    private static List<CsrfScenario> SuppressContradictoryNoTokenFindings(List<CsrfScenario> scenarios)
    {
        var tokenizedEndpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in scenarios)
        {
            if (s.TokenLocation.Contains("none observed", StringComparison.OrdinalIgnoreCase))
                continue;
            if (s.TestType.StartsWith("get-form", StringComparison.OrdinalIgnoreCase))
                continue;
            tokenizedEndpoints.Add(SecurityHostScope.LogicalEndpointKey(s.Method, s.Url));
        }

        if (tokenizedEndpoints.Count == 0)
            return scenarios;

        return scenarios.Where(s =>
        {
            if (!s.TokenLocation.Contains("none observed", StringComparison.OrdinalIgnoreCase))
                return true;
            if (s.TestType.StartsWith("get-form", StringComparison.OrdinalIgnoreCase))
                return true;
            return !tokenizedEndpoints.Contains(SecurityHostScope.LogicalEndpointKey(s.Method, s.Url));
        }).ToList();
    }

    private static List<CsrfScenario> DeduplicateScenarios(List<CsrfScenario> scenarios)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var deduped = new List<CsrfScenario>();
        foreach (var scenario in scenarios)
        {
            if (seen.Add(ScenarioDedupKey(scenario)))
                deduped.Add(scenario);
        }
        return deduped;
    }

    private const string GetFormDomScanJs = """
        (function(){
          try {
            var forms = [];
            document.querySelectorAll('form').forEach(function(f, idx) {
              var method = (f.getAttribute('method') || f.method || 'get').trim().toUpperCase();
              if (method && method !== 'GET') return;
              var action = f.action || location.href;
              var fields = [];
              f.querySelectorAll('input, select, textarea, button').forEach(function(el) {
                var tag = (el.tagName || '').toLowerCase();
                var type = (el.getAttribute('type') || el.type || '').toLowerCase();
                if (type === 'hidden' || type === 'text' || type === 'password' || type === 'email' ||
                    type === 'number' || type === 'tel' || type === 'url' || type === 'search' ||
                    type === 'submit' || type === 'button' || type === 'checkbox' || type === 'radio' ||
                    tag === 'select' || tag === 'textarea' || tag === 'button') {
                  fields.push({
                    name: el.getAttribute('name') || el.name || '',
                    type: type || tag,
                    value: (el.value || el.getAttribute('value') || '').substring(0, 120)
                  });
                }
              });
              forms.push({ index: idx, action: action, method: 'GET', fields: fields });
            });
            return JSON.stringify({ pageUrl: location.href, forms: forms });
          } catch (e) {
            return JSON.stringify({ error: e.message || String(e), forms: [] });
          }
        })()
        """;

    private async Task<List<CsrfScenario>> AnalyzeGetFormsOnPageAsync(string? hostFilter)
    {
        var scenarios = new List<CsrfScenario>();
        try
        {
            var json = await _ctx.ExecuteJs(GetFormDomScanJs);
            if (string.IsNullOrWhiteSpace(json))
                return scenarios;

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.TryGetProperty("error", out _))
                return scenarios;

            var pageUrl = root.TryGetProperty("pageUrl", out var pu) ? pu.GetString() ?? "" : "";
            if (hostFilter != null && Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri)
                && !SecurityHostScope.Matches(pageUri.Host, hostFilter))
                return scenarios;

            if (!root.TryGetProperty("forms", out var formsEl) || formsEl.ValueKind != JsonValueKind.Array)
                return scenarios;

            foreach (var formEl in formsEl.EnumerateArray())
            {
                var action = formEl.TryGetProperty("action", out var a) ? a.GetString() ?? pageUrl : pageUrl;
                if (!Uri.TryCreate(action, UriKind.Absolute, out var actionUri))
                    continue;
                if (hostFilter != null && !SecurityHostScope.Matches(actionUri.Host, hostFilter))
                    continue;

                var fields = ParseDomFormFields(formEl);
                if (IsSearchOnlyGetForm(actionUri, fields))
                    continue;

                var indicators = CollectMutationIndicators(actionUri, fields);
                if (indicators.Count == 0)
                    continue;

                var csrfFields = fields.Where(f => IsCsrfFieldName(f.Name, f.Type, f.Value)).Select(f => f.Name).Distinct().ToList();
                var hasCsrf = csrfFields.Count > 0;
                var fieldSummary = string.Join(", ", fields
                    .Where(f => !string.IsNullOrEmpty(f.Name) && !IsCsrfFieldName(f.Name, f.Type, f.Value))
                    .Select(f => string.IsNullOrEmpty(f.Value) ? f.Name : $"{f.Name}={f.Value}")
                    .Take(12));

                if (hasCsrf)
                {
                    _log($"  [GET form + CSRF token — HTTP spec] {actionUri.AbsolutePath}", "#569CD6");
                    scenarios.Add(new CsrfScenario
                    {
                        Url = action,
                        Path = actionUri.PathAndQuery,
                        Method = "GET",
                        TestType = "get-form-csrf-spec-violation",
                        Severity = "low",
                        Description =
                            "GET form appears to change state but includes an anti-CSRF token. " +
                            "GET must not be used for state changes per HTTP specification; prefer POST with CSRF protection.",
                        OriginalStatus = 0,
                        TestStatus = 0,
                        Vulnerable = false,
                        TokenLocation = $"form field: {string.Join(", ", csrfFields)}",
                        MutationIndicators = indicators,
                        FormFields = fieldSummary,
                    });
                }
                else
                {
                    _log($"  [GET form, no CSRF token] {actionUri.AbsolutePath}", "#CCA700");
                    scenarios.Add(new CsrfScenario
                    {
                        Url = action,
                        Path = actionUri.PathAndQuery,
                        Method = "GET",
                        TestType = "get-form-no-csrf-token",
                        Severity = "info",
                        Description =
                            "GET form appears to change state without CSRF protection (informational). " +
                            "Prefer POST for mutations; confirm cookie-session CSRF on state-changing methods.",
                        OriginalStatus = 0,
                        TestStatus = 0,
                        Vulnerable = true,
                        TokenLocation = "none observed in form",
                        MutationIndicators = indicators,
                        FormFields = fieldSummary,
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _log($"  [GET form DOM scan failed] {ex.Message}", "#888888");
        }

        return scenarios;
    }

    private static List<DomFormField> ParseDomFormFields(JsonElement formEl)
    {
        var list = new List<DomFormField>();
        if (!formEl.TryGetProperty("fields", out var fields) || fields.ValueKind != JsonValueKind.Array)
            return list;
        foreach (var f in fields.EnumerateArray())
        {
            list.Add(new DomFormField
            {
                Name = f.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "",
                Type = f.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "",
                Value = f.TryGetProperty("value", out var v) ? v.GetString() ?? "" : "",
            });
        }
        return list;
    }

    private List<CsrfScenario> DiscoverPassiveGetFindings(
        List<NetworkEntry> entries, HashSet<string> tokenizedKeys, string? hostFilter, int max)
    {
        var scenarios = new List<CsrfScenario>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries)
        {
            if (!string.Equals(entry.Method, "GET", StringComparison.OrdinalIgnoreCase))
                continue;
            if (entry.StatusCode < 200 || entry.StatusCode >= 400)
                continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri))
                continue;
            if (hostFilter != null && !SecurityHostScope.Matches(entry.Host, hostFilter))
                continue;
            if (!LooksLikeStateChangingGet(uri))
                continue;

            var key = EntryDedupKey(entry);
            if (!seen.Add(key))
                continue;

            TryExtractCsrfFromEntry(entry, out _, out _, out _, out var queryParam);
            var hasCsrf = queryParam != null
                || entry.RequestHeaders.Keys.Any(CsrfTokenHeuristics.IsCsrfHeaderName);

            if (hasCsrf)
            {
                scenarios.Add(new CsrfScenario
                {
                    Url = entry.Url,
                    Path = entry.Path,
                    Method = "GET",
                    TestType = "get-request-csrf-spec-violation",
                    Severity = "low",
                    Description =
                        "Captured GET request looks state-changing and carried a CSRF token. " +
                        "Prefer POST for mutations per HTTP specification.",
                    OriginalStatus = entry.StatusCode,
                    TestStatus = entry.StatusCode,
                    Vulnerable = false,
                    TokenLocation = queryParam != null ? $"query: {queryParam}" : "header",
                    MutationIndicators = CollectMutationIndicatorsFromUri(uri),
                });
            }
            else if (!tokenizedKeys.Contains(key))
            {
                scenarios.Add(new CsrfScenario
                {
                    Url = entry.Url,
                    Path = entry.Path,
                    Method = "GET",
                    TestType = "get-request-no-csrf-token",
                    Severity = "info",
                    Description =
                        "Captured GET request looks state-changing with no observable CSRF token. " +
                        "Informational only — GET CSRF is uncommon; prefer confirming state-changing POST/PUT/PATCH vectors.",
                    OriginalStatus = entry.StatusCode,
                    TestStatus = entry.StatusCode,
                    Vulnerable = true,
                    TokenLocation = "none observed",
                    MutationIndicators = CollectMutationIndicatorsFromUri(uri),
                });
            }

            if (scenarios.Count >= max)
                break;
        }

        return scenarios;
    }

    private static List<string> CollectMutationIndicators(Uri actionUri, List<DomFormField> fields)
    {
        var indicators = CollectMutationIndicatorsFromUri(actionUri);

        foreach (var field in fields)
        {
            if (string.IsNullOrEmpty(field.Name) && field.Type != "password")
                continue;
            if (IsCsrfFieldName(field.Name, field.Type, field.Value))
                continue;

            if (field.Type.Equals("password", StringComparison.OrdinalIgnoreCase)
                && !indicators.Any(i => i.Contains("password", StringComparison.OrdinalIgnoreCase)))
                indicators.Add("input type=password");

            foreach (var token in SplitSegmentIntoTokens(field.Name))
            {
                if (StateChangeKeywordSet.Contains(token))
                    indicators.Add($"field name \"{field.Name}\" (token: {token})");
            }

            if (field.Type is "submit" or "button")
            {
                foreach (var phrase in SubmitMutationPhrases)
                {
                    if ((field.Name.Contains(phrase, StringComparison.OrdinalIgnoreCase)
                         || field.Value.Contains(phrase, StringComparison.OrdinalIgnoreCase))
                        && !indicators.Any(i => i.Contains(phrase, StringComparison.OrdinalIgnoreCase)))
                        indicators.Add($"submit \"{field.Name}\" value \"{field.Value}\"");
                }
            }
        }

        return indicators.Distinct(StringComparer.OrdinalIgnoreCase).Take(8).ToList();
    }

    private static List<string> CollectMutationIndicatorsFromUri(Uri uri)
    {
        var indicators = new List<string>();
        foreach (var seg in uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (var token in SplitSegmentIntoTokens(Uri.UnescapeDataString(seg)))
            {
                if (StateChangeKeywordSet.Contains(token))
                    indicators.Add($"path segment \"{seg}\" (token: {token})");
            }
        }

        var query = uri.Query.TrimStart('?');
        if (!string.IsNullOrEmpty(query))
        {
            foreach (var part in query.Split('&', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var eq = part.IndexOf('=');
                var key = eq >= 0 ? Uri.UnescapeDataString(part[..eq]) : Uri.UnescapeDataString(part);
                foreach (var token in SplitSegmentIntoTokens(key))
                {
                    if (StateChangeKeywordSet.Contains(token))
                        indicators.Add($"query param \"{key}\" (token: {token})");
                }
            }
        }

        return indicators.Distinct(StringComparer.OrdinalIgnoreCase).Take(6).ToList();
    }

    private static bool IsSearchOnlyGetForm(Uri actionUri, List<DomFormField> fields)
    {
        if (PathTokensSuggestSearchOnly(actionUri.AbsolutePath))
        {
            var hasMutationField = fields.Any(f =>
                !IsCsrfFieldName(f.Name, f.Type, f.Value) && FieldSuggestsMutation(f));
            if (!hasMutationField)
                return true;
        }

        var meaningful = fields.Where(f =>
            !string.IsNullOrEmpty(f.Name) && !IsCsrfFieldName(f.Name, f.Type, f.Value)
            && f.Type is not ("submit" or "button" or "reset" or "image")).ToList();
        if (meaningful.Count == 0)
            return false;

        return meaningful.All(f =>
        {
            var tokens = SplitSegmentIntoTokens(f.Name).ToList();
            return tokens.Count > 0 && tokens.All(SearchOnlyFieldTokens.Contains);
        });
    }

    private static bool PathTokensSuggestSearchOnly(string absolutePath)
    {
        foreach (var seg in absolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (var token in SplitSegmentIntoTokens(Uri.UnescapeDataString(seg)))
            {
                if (SearchOnlyPathTokens.Contains(token))
                    return true;
            }
        }
        return false;
    }

    private static bool FieldSuggestsMutation(DomFormField field)
    {
        if (field.Type.Equals("password", StringComparison.OrdinalIgnoreCase))
            return true;
        if (SplitSegmentIntoTokens(field.Name).Any(StateChangeKeywordSet.Contains))
            return true;
        if (field.Type is "submit" or "button")
        {
            foreach (var phrase in SubmitMutationPhrases)
            {
                if (field.Name.Contains(phrase, StringComparison.OrdinalIgnoreCase)
                    || field.Value.Contains(phrase, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        return false;
    }

    private static bool IsCsrfFieldName(string name, string? fieldType = null, string? value = null) =>
        CsrfTokenHeuristics.IsCsrfFieldCandidate(name, fieldType, value);

    private sealed class DomFormField
    {
        public string Name { get; init; } = "";
        public string Type { get; init; } = "";
        public string Value { get; init; } = "";
    }

    private static List<CsrfGetStateChangeHint> CollectStateChangingGetHints(List<NetworkEntry> entries)
    {
        var list = new List<CsrfGetStateChangeHint>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            if (!string.Equals(entry.Method, "GET", StringComparison.OrdinalIgnoreCase))
                continue;
            if (entry.StatusCode < 200 || entry.StatusCode >= 400)
                continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri))
                continue;
            if (!LooksLikeStateChangingGet(uri))
                continue;
            if (!seen.Add(entry.Url))
                continue;
            list.Add(new CsrfGetStateChangeHint
            {
                Url = entry.Url,
                Reason = "Path or query parameter name contains a state-change keyword as its own token (not a substring of e.g. 'assets') — GET should not mutate server state."
            });
            if (list.Count >= 25)
                break;
        }
        return list;
    }

    private static bool LooksLikeStateChangingGet(Uri uri)
    {
        if (PathLooksLikeStaticResourceUrl(uri))
            return false;

        if (LastPathSegmentLooksLikeStaticFile(uri))
            return false;

        if (PathTokensSuggestStateChange(uri.AbsolutePath))
            return true;

        var query = uri.Query.TrimStart('?');
        if (string.IsNullOrEmpty(query))
            return false;

        if (QueryParameterNamesSuggestStateChange(query))
            return true;

        if (!query.Contains("action=", StringComparison.OrdinalIgnoreCase))
            return false;

        foreach (var part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq < 0) continue;
            var key = Uri.UnescapeDataString(part[..eq]);
            if (!key.Equals("action", StringComparison.OrdinalIgnoreCase)) continue;
            var val = Uri.UnescapeDataString(part[(eq + 1)..]).ToLowerInvariant();
            if (val is "update" or "delete" or "create" or "save" or "remove" or "add" or "modify" or "submit")
                return true;
        }

        return false;
    }

    /// <summary>
    /// Exclude CSS/JS/images and framework resource directories from GET state-change heuristics.
    /// </summary>
    private static bool PathLooksLikeStaticResourceUrl(Uri uri)
    {
        var path = uri.AbsolutePath;
        if (path.Contains("jakarta.faces.resource", StringComparison.OrdinalIgnoreCase))
            return true;

        foreach (var marker in new[]
                 {
                     "/static/", "/assets/", "/public/", "/dist/", "/media/",
                     "/_next/static/", "/.vite/", "/webpack/", "/build/static/"
                 })
        {
            if (path.Contains(marker, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return StaticAssetPathSuffixRegex.IsMatch(path);
    }

    private static bool LastPathSegmentLooksLikeStaticFile(Uri uri)
    {
        var path = uri.AbsolutePath;
        if (string.IsNullOrEmpty(path) || path.Length < 2) return false;
        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0) return false;
        var last = Uri.UnescapeDataString(segments[^1]);
        var ext = Path.GetExtension(last);
        return StaticResourceExtensions.Contains(ext);
    }

    private static bool PathTokensSuggestStateChange(string absolutePath)
    {
        foreach (var seg in absolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            var decoded = Uri.UnescapeDataString(seg);
            foreach (var token in SplitSegmentIntoTokens(decoded))
            {
                if (PathMutationKeywordSet.Contains(token))
                    return true;
            }
        }
        return false;
    }

    private static bool QueryParameterNamesSuggestStateChange(string query)
    {
        foreach (var part in query.Split('&', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = part.IndexOf('=');
            var keyPart = eq >= 0 ? part[..eq] : part;
            var key = Uri.UnescapeDataString(keyPart);
            foreach (var token in SplitSegmentIntoTokens(key))
            {
                if (PathMutationKeywordSet.Contains(token))
                    return true;
            }
        }
        return false;
    }

    private static IEnumerable<string> SplitSegmentIntoTokens(string segment)
    {
        foreach (var t in segment.Split(new[] { '-', '_', '.' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var x = t.ToLowerInvariant();
            if (x.Length > 0) yield return x;
        }
    }

    /// <summary>
    /// Logical endpoints where any captured request carried an explicit or implicit CSRF token.
    /// Uses method+host+path (query stripped) so a GET with ?user_token= marks the whole path.
    /// </summary>
    private static HashSet<string> BuildTokenBearerKeySet(List<NetworkEntry> entries)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            if (entry.StatusCode < 200 || entry.StatusCode >= 400)
                continue;
            if (TryExtractCsrfFromEntry(entry, out _, out _, out _, out _)
                || DetectImplicitCsrfFramework(entry) != null)
                set.Add(EntryDedupKey(entry));
        }
        return set;
    }

    /// <summary>
    /// Successful state-changing requests that do not appear to carry a CSRF token (not in the token-bearing set).
    /// Endpoints with implicit framework CSRF protection (e.g. __VIEWSTATE) are separated out.
    /// </summary>
    private (List<CsrfCandidate> Unprotected, List<(CsrfCandidate Endpoint, string Framework)> ImplicitProtected)
        DiscoverUnprotectedEndpoints(
            List<NetworkEntry> entries, HashSet<string> tokenizedKeys, int max, bool includeGet)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var unprotected = new List<CsrfCandidate>();
        var implicitProtected = new List<(CsrfCandidate, string)>();

        foreach (var entry in entries)
        {
            if (entry.StatusCode < 200 || entry.StatusCode >= 400)
                continue;
            if (!AuthAccessHeuristics.CapturedMutationLooksActionable(entry))
                continue;

            if (entry.Method is ("POST" or "PUT" or "PATCH" or "DELETE"))
            {
                var key = EntryDedupKey(entry);
                if (tokenizedKeys.Contains(key))
                    continue;
                if (TryExtractCsrfFromEntry(entry, out _, out _, out _, out _))
                    continue;
                if (!seen.Add(key))
                    continue;

                var candidate = new CsrfCandidate
                {
                    Url = entry.Url,
                    Path = entry.Path,
                    Method = entry.Method,
                    RequestHeaders = new Dictionary<string, string>(entry.RequestHeaders),
                    RequestBody = entry.RequestBody,
                    OriginalStatus = entry.StatusCode,
                    CsrfHeaderName = null,
                    CsrfHeaderValue = null,
                    CsrfBodyField = null,
                    CsrfQueryParam = null,
                };

                var framework = DetectImplicitCsrfFramework(entry);
                if (framework != null)
                    implicitProtected.Add((candidate, framework));
                else
                    unprotected.Add(candidate);

                if (unprotected.Count >= max)
                    break;
                continue;
            }

            if (includeGet && string.Equals(entry.Method, "GET", StringComparison.OrdinalIgnoreCase))
            {
                if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri) || !LooksLikeStateChangingGet(uri))
                    continue;
                var gKey = EntryDedupKey(entry);
                if (tokenizedKeys.Contains(gKey))
                    continue;
                if (TryExtractCsrfFromEntry(entry, out _, out _, out _, out _))
                    continue;
                if (!seen.Add(gKey))
                    continue;

                unprotected.Add(new CsrfCandidate
                {
                    Url = entry.Url,
                    Path = entry.Path,
                    Method = "GET",
                    RequestHeaders = new Dictionary<string, string>(entry.RequestHeaders),
                    RequestBody = null,
                    OriginalStatus = entry.StatusCode,
                    CsrfHeaderName = null,
                    CsrfHeaderValue = null,
                    CsrfBodyField = null,
                    CsrfQueryParam = null,
                });

                if (unprotected.Count >= max)
                    break;
            }
        }

        return (unprotected, implicitProtected);
    }

    private List<CsrfCandidate> DiscoverCsrfEndpoints(List<NetworkEntry> entries, bool includeGet)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var candidates = new List<CsrfCandidate>();

        foreach (var entry in entries)
        {
            if (entry.StatusCode < 200 || entry.StatusCode >= 400)
                continue;

            if (entry.Method is ("POST" or "PUT" or "PATCH" or "DELETE"))
            {
                var key = EntryDedupKey(entry);
                if (!seen.Add(key)) continue;

                if (!TryExtractCsrfFromEntry(entry, out var headerName, out var headerVal, out var bodyField, out var queryParam))
                    continue;

                candidates.Add(BuildCandidate(entry, headerName, headerVal, bodyField, queryParam));
            }
            else if (includeGet && string.Equals(entry.Method, "GET", StringComparison.OrdinalIgnoreCase))
            {
                var key = EntryDedupKey(entry);
                if (!seen.Add(key)) continue;

                if (!TryExtractCsrfFromEntry(entry, out var headerName, out var headerVal, out var bodyField, out var queryParam))
                    continue;

                candidates.Add(BuildCandidate(entry, headerName, headerVal, bodyField, queryParam));
            }
        }

        return candidates;
    }

    private static CsrfCandidate BuildCandidate(NetworkEntry entry, string? csrfHeaderName, string? csrfHeaderValue,
        string? csrfBodyField, string? csrfQueryParam) =>
        new()
        {
            Url = entry.Url,
            Path = entry.Path,
            Method = entry.Method,
            RequestHeaders = new Dictionary<string, string>(entry.RequestHeaders),
            RequestBody = entry.RequestBody,
            OriginalStatus = entry.StatusCode,
            CsrfHeaderName = csrfHeaderName,
            CsrfHeaderValue = csrfHeaderValue,
            CsrfBodyField = csrfBodyField,
            CsrfQueryParam = csrfQueryParam,
            PreferFormTokenOracle = csrfBodyField != null && IsFormEncodedBody(entry.RequestBody),
        };

    private static CsrfCandidate CandidateFromForm(
        CsrfDomFormPlanner.PlannedPost form,
        int originalStatus,
        Dictionary<string, string>? networkHeaders,
        string? networkBody)
    {
        var headers = networkHeaders != null
            ? new Dictionary<string, string>(networkHeaders, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var body = networkBody;
        if (form.CsrfField != null && (string.IsNullOrEmpty(body) || !CsrfTokenHeuristics.TryExtractFromBody(body, out _)))
            body = form.Body;
        else if (form.CsrfField == null)
            body ??= form.Body;

        if (!string.IsNullOrEmpty(body) && !headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = "application/x-www-form-urlencoded";

        return new CsrfCandidate
        {
            Url = form.Url,
            Path = form.Path,
            Method = form.Method,
            RequestHeaders = headers,
            RequestBody = body,
            OriginalStatus = originalStatus,
            CsrfBodyField = form.CsrfField,
            FromDomForm = true,
            PreferFormTokenOracle = form.CsrfField != null
        };
    }

    private static bool IsFormEncodedBody(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return false;
        var trimmed = body.TrimStart();
        // Multipart and HTML name="csrf" contain '=' but are not name=value pairs the field rewriter understands.
        if (trimmed.StartsWith('{') || trimmed.StartsWith('[') || trimmed.StartsWith("--")
            || trimmed.StartsWith('<') || trimmed.Contains('\n') || trimmed.Contains('\r'))
            return false;
        return trimmed.Contains('=');
    }

    private static bool TryExtractCsrfFromEntry(NetworkEntry entry,
        out string? csrfHeaderName, out string? csrfHeaderValue,
        out string? csrfBodyField, out string? csrfQueryParam)
    {
        csrfHeaderName = null;
        csrfHeaderValue = null;
        csrfBodyField = null;
        csrfQueryParam = null;

        foreach (var h in entry.RequestHeaders)
        {
            if (CsrfTokenHeuristics.IsCsrfHeaderName(h.Key))
            {
                csrfHeaderName = h.Key;
                csrfHeaderValue = h.Value;
                return true;
            }
        }

        if (CsrfTokenHeuristics.TryExtractFromBody(entry.RequestBody, out csrfBodyField))
            return true;

        if (Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)
            && CsrfTokenHeuristics.TryExtractFromQuery(uri.Query, out csrfQueryParam))
            return true;

        return false;
    }

    /// <summary>
    /// Detects framework-level implicit CSRF protection (e.g. ASP.NET WebForms __VIEWSTATE,
    /// JSF ViewState) in the request body.
    /// </summary>
    private static string? DetectImplicitCsrfFramework(NetworkEntry entry)
    {
        if (string.IsNullOrEmpty(entry.RequestBody))
            return null;

        foreach (var (primary, _, framework) in ImplicitCsrfProtectionPatterns)
        {
            if (BodyContainsField(entry.RequestBody, primary))
                return framework;
        }

        return null;
    }

    /// <summary>
    /// Header name looks like CSRF but the captured value is not a secret (for example <c>X-CSRF: 1</c>).
    /// The useful test is removing the header, not replacing the flag with a random string.
    /// </summary>
    private static bool IsPresenceOnlyCsrfHeader(CsrfCandidate candidate) =>
        candidate.CsrfHeaderName != null
        && candidate.CsrfBodyField == null
        && candidate.CsrfQueryParam == null
        && !CsrfTokenHeuristics.LooksLikeCsrfTokenValue(candidate.CsrfHeaderValue ?? "");

    /// <summary>
    /// A successful mutating request with no classic token. When it carried a custom header a simple
    /// cross-site form cannot set, replay once without those headers before calling it vulnerable.
    /// </summary>
    private async Task<CsrfScenario> ClassifyUnprotectedAsync(CsrfCandidate candidate)
    {
        var custom = CsrfTokenHeuristics.CustomHeaderCsrfCandidates(candidate.RequestHeaders);
        if (custom.Count == 0)
        {
            _log($"  [no CSRF token] {candidate.Method} {candidate.Path}", "#CCA700");
            return PassiveNoToken(candidate, extra: null, testStatus: null);
        }

        var names = FormatHeaderList(custom);
        var headers = new Dictionary<string, string>(candidate.RequestHeaders, StringComparer.OrdinalIgnoreCase);
        foreach (var name in custom)
            headers.Remove(name);
        headers.Remove("Cookie");
        headers.Remove("cookie");

        int status = 0;
        string? probeBody = null;
        string? error = null;
        try
        {
            var responseJson = await _ctx.Fetch(candidate.Url, candidate.Method, headers, candidate.RequestBody, 10000);
            ParseFetchStatusBody(responseJson, out status, out probeBody);
        }
        catch (Exception ex)
        {
            error = ex.Message;
        }

        if (error == null && CsrfProbeResponseEvaluator.CustomHeaderReplayRejected(status, probeBody))
        {
            _log($"  [custom header enforced] {candidate.Method} {candidate.Path} without {names} → {status}", "#4EC9B0");
            return new CsrfScenario
            {
                Url = candidate.Url,
                Path = candidate.Path,
                Method = candidate.Method,
                TestType = "custom-header-enforced",
                Severity = "info",
                Description =
                    $"Replay without custom header(s) {names} was rejected (HTTP {status}). " +
                    "A simple cross-site form cannot set these headers, so classic cookie CSRF is unlikely when the server requires them. " +
                    "Confirm the rejection is this check and that CORS does not allow an attacker origin to send the header.",
                OriginalStatus = candidate.OriginalStatus,
                TestStatus = status,
                Vulnerable = false,
                TokenLocation = "header: " + names,
            };
        }

        if (error == null && status is >= 200 and < 300)
        {
            _log($"  [no CSRF token; custom headers not required] {candidate.Method} {candidate.Path} → {status}", "#CCA700");
            return PassiveNoToken(
                candidate,
                $" Custom headers on the original request ({names}) were removed and the server still returned HTTP {status}, so they are not enforcing a header check.",
                status);
        }

        var note = error != null
            ? $" Confirmation replay without {names} failed: {error}."
            : $" Confirmation replay without {names} returned HTTP {status}, which is not a clear CSRF rejection.";
        _log($"  [no CSRF token] {candidate.Method} {candidate.Path} ({note.Trim()})", "#CCA700");
        return PassiveNoToken(candidate, note, error == null ? status : null);
    }

    private static CsrfScenario PassiveNoToken(CsrfCandidate candidate, string? extra, int? testStatus) =>
        new()
        {
            Url = candidate.Url,
            Path = candidate.Path,
            Method = candidate.Method,
            TestType = "no-csrf-token",
            Description = candidate.FromDomForm
                ? "State-changing form has no anti-CSRF token field. If authentication relies on cookies, the form may accept cross-site forged requests (CSRF)."
                  + (extra ?? "")
                : "Successful state-changing request has no observable anti-CSRF token or dedicated CSRF header in captured traffic. " +
                  "If authentication relies on cookies, the endpoint may accept cross-site forged requests (CSRF)."
                  + (extra ?? ""),
            OriginalStatus = candidate.OriginalStatus,
            TestStatus = testStatus ?? candidate.OriginalStatus,
            Vulnerable = true,
            Error = null,
            TokenLocation = candidate.FromDomForm ? "none observed in form" : "none observed",
        };

    private static string FormatHeaderList(IReadOnlyList<string> names)
    {
        if (names.Count <= 8)
            return string.Join(", ", names);
        return string.Join(", ", names.Take(8)) + $" (+{names.Count - 8} more)";
    }

    private async Task<CsrfScenario> TestWithoutToken(CsrfCandidate candidate)
    {
        var headers = new Dictionary<string, string>(candidate.RequestHeaders, StringComparer.OrdinalIgnoreCase);
        var body = candidate.RequestBody;
        var url = candidate.Url;

        if (candidate.CsrfHeaderName != null)
            headers.Remove(candidate.CsrfHeaderName);

        if (candidate.CsrfBodyField != null && body != null)
            body = RemoveBodyField(body, candidate.CsrfBodyField);

        if (candidate.CsrfQueryParam != null)
            url = RemoveQueryParamFromUrl(url, candidate.CsrfQueryParam);

        return await SendAndEvaluate(url, candidate, headers, body, "missing-token",
            "Request sent without CSRF token", IsPresenceOnlyCsrfHeader(candidate));
    }

    private async Task<CsrfScenario> TestWithInvalidToken(CsrfCandidate candidate)
    {
        var headers = new Dictionary<string, string>(candidate.RequestHeaders, StringComparer.OrdinalIgnoreCase);
        var body = candidate.RequestBody;
        var url = candidate.Url;

        if (candidate.CsrfHeaderName != null)
            headers[candidate.CsrfHeaderName] = "INVALID_CSRF_TOKEN_12345";

        if (candidate.CsrfBodyField != null && body != null)
            body = ReplaceBodyField(body, candidate.CsrfBodyField, "INVALID_CSRF_TOKEN_12345");

        if (candidate.CsrfQueryParam != null)
            url = ReplaceQueryParamInUrl(url, candidate.CsrfQueryParam, "INVALID_CSRF_TOKEN_12345");

        return await SendAndEvaluate(url, candidate, headers, body, "invalid-token",
            "Request sent with invalid CSRF token");
    }

    private async Task<CsrfScenario> SendAndEvaluate(
        string requestUrl, CsrfCandidate candidate, Dictionary<string, string> headers, string? body,
        string testType, string description, bool presenceOnlyHeader = false)
    {
        int status = 0;
        string? error = null;
        string? probeBody = null;
        var isLogin = LooksLikeLoginCsrfTarget(candidate.Url, candidate.Path, candidate.RequestBody);

        try
        {
            headers.Remove("Cookie");
            headers.Remove("cookie");

            var responseJson = await _ctx.Fetch(requestUrl, candidate.Method, headers, body, 10000);
            ParseFetchStatusBody(responseJson, out status, out probeBody);
        }
        catch (Exception ex)
        {
            error = ex.Message;
        }

        bool vulnerable;
        string severity;
        if (candidate.PreferFormTokenOracle && !string.IsNullOrEmpty(candidate.CsrfBodyField))
        {
            description = testType == "invalid-token"
                ? $"Form field \"{candidate.CsrfBodyField}\" is present; request sent with an invalid value"
                : testType == "missing-token"
                    ? $"Form field \"{candidate.CsrfBodyField}\" is present; request sent with that field removed"
                    : description;
        }
        string detail = description;
        if (error != null)
        {
            vulnerable = false;
            severity = "";
        }
        else
        {
            // JSON probes keep the strict oracle (HTTP 200 alone is not a bypass).
            // Form posts that already carry a token field use the form oracle: acceptance without a
            // CSRF rejection is "token present but not enforced", which is distinct from "no token".
            var eval = candidate.PreferFormTokenOracle
                ? CsrfProbeResponseEvaluator.EvaluateFormTokenProbe(status, probeBody)
                : CsrfProbeResponseEvaluator.EvaluateMissingTokenProbe(
                    candidate.OriginalStatus, null, status, probeBody);
            vulnerable = eval.Vulnerable;
            severity = eval.Severity;
            detail = $"{description}. {eval.Summary}";

            // Fixed flags (X-CSRF: 1) are a presence check. A 2xx without the header means the flag is not enforced,
            // even when the body has none of the success phrases the token oracle looks for.
            if (presenceOnlyHeader
                && !vulnerable
                && status is >= 200 and < 300
                && !InsecureDesignProbeSupport.LooksLikeCsrfRejection(status, probeBody))
            {
                vulnerable = true;
                if (SeverityRankName(severity) < SeverityRankName("medium"))
                    severity = "medium";
                detail += " The header value is a fixed flag, not a secret, and the server accepted the request without it.";
            }
            else if (presenceOnlyHeader && !vulnerable)
            {
                detail += " The header value is a fixed flag, not a secret. Rejection without the header is the control that matters.";
            }
        }

        // Login CSRF is a weaker finding class than password-change / state-mutating CSRF.
        if (vulnerable && isLogin)
        {
            severity = "info";
            detail += " Login/auth CSRF is typically lower impact than authenticated state-changing CSRF.";
        }

        var statusLabel = vulnerable ? "VULNERABLE" : "OK";
        var color = vulnerable ? "#F44747" : "#4EC9B0";
        _log($"    {statusLabel}: {testType} → {status}", color);

        var tokenLoc = candidate.CsrfHeaderName != null
            ? $"header: {candidate.CsrfHeaderName}"
            : candidate.CsrfQueryParam != null
                ? $"query: {candidate.CsrfQueryParam}"
                : $"body: {candidate.CsrfBodyField}";

        return new CsrfScenario
        {
            Url = candidate.Url,
            Path = candidate.Path,
            Method = candidate.Method,
            TestType = testType,
            Description = detail,
            OriginalStatus = candidate.OriginalStatus,
            TestStatus = status,
            Vulnerable = vulnerable,
            Severity = severity,
            Error = error,
            TokenLocation = tokenLoc,
        };
    }

    private static void ParseFetchStatusBody(string responseJson, out int status, out string? body)
    {
        status = 0;
        body = null;
        using var doc = System.Text.Json.JsonDocument.Parse(responseJson);
        if (doc.RootElement.TryGetProperty("status", out var s) && s.ValueKind == JsonValueKind.Number)
            status = s.GetInt32();
        if (doc.RootElement.TryGetProperty("body", out var b))
            body = b.ValueKind == JsonValueKind.String ? b.GetString() : b.GetRawText();
    }

    /// <summary>Login / auth endpoints — CSRF impact is usually limited to session fixation style issues.</summary>
    internal static bool LooksLikeLoginCsrfTarget(string? url, string? path, string? body)
    {
        var hay = $"{url} {path}".ToLowerInvariant();
        if (Regex.IsMatch(hay, @"/(login|signin|sign-in|logon|auth|authenticate|session|brute)(/|$|\?)",
                RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1)))
            return true;

        if (string.IsNullOrEmpty(body)) return false;
        var lower = body.ToLowerInvariant();
        var hasPassword = lower.Contains("password=") || lower.Contains("\"password\"")
                          || lower.Contains("passwd=") || lower.Contains("pwd=");
        var hasUser = lower.Contains("username=") || lower.Contains("\"username\"")
                      || lower.Contains("email=") || lower.Contains("\"email\"")
                      || lower.Contains("user=") || lower.Contains("\"user\"");
        return hasPassword && hasUser;
    }

    private static string RemoveQueryParamFromUrl(string url, string paramName)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url;
        var q = uri.Query.TrimStart('?');
        if (string.IsNullOrEmpty(q)) return url;
        var kept = q.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Where(p =>
            {
                var eq = p.IndexOf('=');
                var key = eq >= 0 ? Uri.UnescapeDataString(p[..eq]) : Uri.UnescapeDataString(p);
                return !key.Equals(paramName, StringComparison.OrdinalIgnoreCase);
            })
            .ToList();
        var qb = new StringBuilder();
        qb.Append(uri.GetLeftPart(UriPartial.Path));
        if (kept.Count > 0)
        {
            qb.Append('?');
            qb.Append(string.Join("&", kept));
        }
        if (!string.IsNullOrEmpty(uri.Fragment))
            qb.Append(uri.Fragment);
        return qb.ToString();
    }

    private static string ReplaceQueryParamInUrl(string url, string paramName, string newValue)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url;
        var q = uri.Query.TrimStart('?');
        if (string.IsNullOrEmpty(q)) return url;
        var parts = q.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p =>
            {
                var eq = p.IndexOf('=');
                var key = eq >= 0 ? Uri.UnescapeDataString(p[..eq]) : Uri.UnescapeDataString(p);
                return key.Equals(paramName, StringComparison.OrdinalIgnoreCase)
                    ? $"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(newValue)}"
                    : p;
            });
        var qb = new StringBuilder();
        qb.Append(uri.GetLeftPart(UriPartial.Path));
        qb.Append('?');
        qb.Append(string.Join("&", parts));
        if (!string.IsNullOrEmpty(uri.Fragment))
            qb.Append(uri.Fragment);
        return qb.ToString();
    }

    private static bool BodyContainsField(string body, string field) =>
        CsrfTokenHeuristics.BodyContainsField(body, field);

    private static string RemoveBodyField(string body, string fieldName)
    {
        // URL-encoded body
        if (body.Contains('=') && !body.TrimStart().StartsWith('{'))
        {
            var pairs = body.Split('&')
                .Where(p => !p.StartsWith(fieldName + "=", StringComparison.OrdinalIgnoreCase))
                .ToList();
            return string.Join("&", pairs);
        }
        // JSON body — remove the field
        if (body.TrimStart().StartsWith('{'))
        {
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(body);
                var dict = new Dictionary<string, System.Text.Json.JsonElement>();
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    if (!prop.Name.Equals(fieldName, StringComparison.OrdinalIgnoreCase))
                        dict[prop.Name] = prop.Value;
                }
                return System.Text.Json.JsonSerializer.Serialize(dict);
            }
            catch { return body; }
        }
        return body;
    }

    private static string ReplaceBodyField(string body, string fieldName, string newValue)
    {
        if (body.Contains('=') && !body.TrimStart().StartsWith('{'))
        {
            var pairs = body.Split('&').Select(p =>
            {
                var eq = p.IndexOf('=');
                if (eq < 0) return p;
                var key = p[..eq];
                return key.Equals(fieldName, StringComparison.OrdinalIgnoreCase)
                    ? $"{key}={Uri.EscapeDataString(newValue)}" : p;
            });
            return string.Join("&", pairs);
        }
        if (body.TrimStart().StartsWith('{'))
        {
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(body);
                var dict = new Dictionary<string, object?>();
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    dict[prop.Name] = prop.Name.Equals(fieldName, StringComparison.OrdinalIgnoreCase)
                        ? newValue
                        : prop.Value;
                }
                return System.Text.Json.JsonSerializer.Serialize(dict);
            }
            catch { return body; }
        }
        return body;
    }

    private List<CsrfCandidate> DiscoverRefererEndpoints(List<NetworkEntry> entries, int max, bool includeGet)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<CsrfCandidate>();

        foreach (var entry in entries)
        {
            if (entry.StatusCode < 200 || entry.StatusCode >= 400)
                continue;

            var isMutating = entry.Method is ("POST" or "PUT" or "PATCH" or "DELETE");
            var isGet = includeGet && string.Equals(entry.Method, "GET", StringComparison.OrdinalIgnoreCase);
            if (!isMutating && !isGet)
                continue;

            if (isGet && Uri.TryCreate(entry.Url, UriKind.Absolute, out var getUri) && !LooksLikeStateChangingGet(getUri))
                continue;

            var key = EntryDedupKey(entry);
            if (!seen.Add(key))
                continue;

            TryExtractCsrfFromEntry(entry, out var headerName, out var headerVal, out var bodyField, out var queryParam);
            list.Add(BuildCandidate(entry, headerName, headerVal, bodyField, queryParam));

            if (list.Count >= max)
                break;
        }

        return list;
    }

    private async Task<List<CsrfRefererFinding>> RunRefererBypassAnalysisAsync(List<CsrfCandidate> endpoints)
    {
        var findings = new List<CsrfRefererFinding>();

        foreach (var candidate in endpoints)
        {
            _log($"  Referer probes: {candidate.Method} {candidate.Path}", "#888888");

            if (!Uri.TryCreate(candidate.Url, UriKind.Absolute, out var uri))
                continue;

            var host = uri.Host;
            var legitimateReferer = candidate.RequestHeaders
                .FirstOrDefault(h => h.Key.Equals("Referer", StringComparison.OrdinalIgnoreCase)).Value
                ?? $"{uri.Scheme}://{host}/";

            var baseline = await SendRefererProbeAsync(candidate, legitimateReferer, omitReferer: false);
            if (baseline.Error != null)
            {
                findings.Add(new CsrfRefererFinding
                {
                    Url = candidate.Url,
                    Path = candidate.Path,
                    Method = candidate.Method,
                    HasCsrfToken = candidate.CsrfHeaderName != null || candidate.CsrfBodyField != null
                                   || candidate.CsrfQueryParam != null,
                    RefererValidationDetected = false,
                    Probes =
                    [
                        new CsrfRefererProbeResult
                        {
                            ProbeName = "baseline",
                            RefererValue = legitimateReferer,
                            Classification = "ERROR",
                            BaselineStatus = 0,
                            ProbeStatus = baseline.Status,
                            Vulnerable = false,
                            Severity = "",
                            Description = "Baseline request with legitimate Referer failed — cannot assess Referer validation.",
                            Error = baseline.Error,
                        }
                    ],
                });
                continue;
            }

            var crossOriginReferer = "https://evil.com/x";
            var crossOrigin = await SendRefererProbeAsync(candidate, crossOriginReferer, omitReferer: false);
            var validationDetected = baseline.Status is >= 200 and < 300
                                     && !ResponsesSimilar(baseline, crossOrigin);

            var probes = new List<CsrfRefererProbeResult>();
            var hasCsrfToken = candidate.CsrfHeaderName != null || candidate.CsrfBodyField != null
                               || candidate.CsrfQueryParam != null;

            if (validationDetected)
            {
                _log($"    Referer validation detected (cross-origin differs from baseline)", "#569CD6");
                probes.Add(new CsrfRefererProbeResult
                {
                    ProbeName = "validation-detected",
                    RefererValue = crossOriginReferer,
                    Classification = "BLOCKED",
                    BaselineStatus = baseline.Status,
                    ProbeStatus = crossOrigin.Status,
                    Vulnerable = false,
                    Severity = "info",
                    Description = "Server response differs based on Referer header — Referer validation appears present.",
                });

                foreach (var (probeName, refererValue, omit, label, remediation) in BuildRefererBypassProbes(host))
                {
                    var probe = await SendRefererProbeAsync(candidate, refererValue, omitReferer: omit);
                    var classification = ClassifyRefererProbe(baseline, probe);
                    var bypassed = classification == "BYPASSED";
                    var severity = bypassed ? (hasCsrfToken ? "medium" : "high") : "";

                    if (bypassed)
                        _log($"    VULNERABLE: Referer bypass ({label}) → {probe.Status}", "#F44747");
                    else if (classification == "ERROR")
                        _log($"    FINDING: {label} → {probe.Status} (server error)", "#CCA700");

                    probes.Add(new CsrfRefererProbeResult
                    {
                        ProbeName = probeName,
                        RefererValue = omit ? null : refererValue,
                        Classification = classification,
                        BaselineStatus = baseline.Status,
                        ProbeStatus = probe.Status,
                        Vulnerable = bypassed,
                        Severity = severity,
                        Description = BuildRefererProbeDescription(classification, label, probe, baseline, remediation),
                        Error = probe.Error,
                    });
                }
            }
            else if (baseline.Status is >= 200 and < 300)
            {
                _log($"    No Referer validation detected (cross-origin matches baseline)", "#888888");
            }

            if (probes.Count > 0 || validationDetected)
            {
                findings.Add(new CsrfRefererFinding
                {
                    Url = candidate.Url,
                    Path = candidate.Path,
                    Method = candidate.Method,
                    HasCsrfToken = hasCsrfToken,
                    RefererValidationDetected = validationDetected,
                    Probes = probes,
                });
            }
        }

        return findings;
    }

    private static IEnumerable<(string ProbeName, string? RefererValue, bool Omit, string Label, string Remediation)>
        BuildRefererBypassProbes(string host) =>
    [
        ("no-referer", null, true, "no Referer",
            "Handle missing Referer safely (reject or use token-based CSRF defense); do not assume Referer is always present."),
        ("empty-referer", "", false, "empty Referer",
            "Treat empty Referer the same as missing or invalid; prefer token-based CSRF defense."),
        ("cross-origin", "https://evil.com/x", false, "cross-origin Referer",
            "Parse Referer URL and compare hostname exactly. Prefer token-based CSRF defense."),
        ("hostname-in-path", $"https://evil.com/{host}/x", false, "hostname in path",
            "Server uses substring match on Referer. Parse Referer URL and compare hostname exactly. Prefer token-based CSRF defense."),
        ("hostname-subdomain", $"https://{host}.evil.com/x", false, "hostname as subdomain",
            "Unanchored hostname match on Referer. Compare parsed hostname exactly. Prefer token-based CSRF defense."),
        ("hostname-in-query", $"https://evil.com/x?ref={host}", false, "hostname in query",
            "Substring match in query string bypasses Referer check. Compare parsed hostname exactly. Prefer token-based CSRF defense."),
    ];

    private static string BuildRefererProbeDescription(
        string classification, string label, RefererProbeResponse probe,
        RefererProbeResponse baseline, string remediation)
    {
        return classification switch
        {
            "BYPASSED" =>
                $"Referer bypass: {label}. Probe response matches baseline ({probe.Status} vs baseline {baseline.Status}). {remediation}",
            "ERROR" =>
                $"Missing or malformed Referer causes server error ({label}). Response: {probe.Status}. {remediation}",
            "BLOCKED" => $"Referer check blocked this probe ({label}). Response: {probe.Status}.",
            _ => $"Inconclusive result for {label}. Baseline {baseline.Status}, probe {probe.Status}.",
        };
    }

    private static string ClassifyRefererProbe(RefererProbeResponse baseline, RefererProbeResponse probe)
    {
        if (probe.Error != null)
            return "ERROR";
        if (probe.Status >= 500)
            return "ERROR";
        if (ResponsesSimilar(baseline, probe))
            return "BYPASSED";
        if (probe.Status is 401 or 403 or 405)
            return "BLOCKED";
        if (baseline.Status is >= 200 and < 300 && probe.Status is >= 400 and < 500)
            return "BLOCKED";
        return "INCONCLUSIVE";
    }

    private static bool ResponsesSimilar(RefererProbeResponse baseline, RefererProbeResponse probe)
    {
        if (baseline.Status / 100 != probe.Status / 100)
            return false;
        if (baseline.Status is >= 200 and < 300)
        {
            var lenDiff = Math.Abs(baseline.Body.Length - probe.Body.Length);
            return lenDiff <= Math.Max(50, baseline.Body.Length / 10);
        }
        return baseline.Status == probe.Status;
    }

    private async Task<RefererProbeResponse> SendRefererProbeAsync(
        CsrfCandidate candidate, string? refererValue, bool omitReferer)
    {
        var headers = new Dictionary<string, string>(candidate.RequestHeaders, StringComparer.OrdinalIgnoreCase);
        headers.Remove("Cookie");
        headers.Remove("cookie");
        headers.Remove("Referer");
        headers.Remove("referer");

        if (!omitReferer && refererValue != null)
            headers["Referer"] = refererValue;

        try
        {
            var cookieHeader = await _ctx.GetCookieHeaderForUrl(candidate.Url);
            if (!string.IsNullOrEmpty(cookieHeader))
            {
                if (headers.TryGetValue("Cookie", out var existing) && !string.IsNullOrEmpty(existing))
                    headers["Cookie"] = existing + "; " + cookieHeader;
                else
                    headers["Cookie"] = cookieHeader;
            }

            var json = await ServerSideHttpAsFetchJsonAsync(
                candidate.Url, candidate.Method, headers, candidate.RequestBody, 10000);
            var parsed = ParseRefererFetchJson(json);
            return new RefererProbeResponse(parsed.Status, parsed.Body, null);
        }
        catch (Exception ex)
        {
            return new RefererProbeResponse(0, "", ex.Message);
        }
    }

    private static async Task<string> ServerSideHttpAsFetchJsonAsync(
        string url, string method, Dictionary<string, string>? headers, string? body, int timeoutMs)
    {
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        using var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromMilliseconds(Math.Clamp(timeoutMs, 500, 60_000))
        };
        using var msg = new HttpRequestMessage(new HttpMethod(method), url);
        if (body != null)
        {
            var trimmed = body.TrimStart();
            if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
                msg.Content = new StringContent(body, Encoding.UTF8, "application/json");
            else if (body.Contains('=') && !trimmed.StartsWith('{'))
                msg.Content = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded");
            else
                msg.Content = new StringContent(body, Encoding.UTF8);
        }

        if (headers != null)
        {
            foreach (var kv in headers)
            {
                if (!msg.Headers.TryAddWithoutValidation(kv.Key, kv.Value))
                    msg.Content?.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
            }
        }

        using var resp = await client.SendAsync(msg).ConfigureAwait(false);
        var text = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
        return JsonSerializer.Serialize(new
        {
            ok = resp.IsSuccessStatusCode,
            status = (int)resp.StatusCode,
            statusText = resp.ReasonPhrase ?? "",
            body = text
        });
    }

    private static (int Status, string Body) ParseRefererFetchJson(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var status = root.GetProperty("status").GetInt32();
        var body = root.TryGetProperty("body", out var b)
            ? b.ValueKind == JsonValueKind.String ? b.GetString() ?? "" : b.GetRawText()
            : "";
        return (status, body);
    }

    private sealed record RefererProbeResponse(int Status, string Body, string? Error);

    private static int SeverityRankName(string? severity) => (severity ?? "").ToLowerInvariant() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        "info" => 0,
        _ => 0
    };

    private class CsrfCandidate
    {
        public string Url { get; init; } = "";
        public string Path { get; init; } = "";
        public string Method { get; init; } = "";
        public Dictionary<string, string> RequestHeaders { get; init; } = new();
        public string? RequestBody { get; init; }
        public int OriginalStatus { get; init; }
        public string? CsrfHeaderName { get; init; }
        public string? CsrfHeaderValue { get; init; }
        public string? CsrfBodyField { get; init; }
        public string? CsrfQueryParam { get; init; }
        public bool FromDomForm { get; init; }
        public bool PreferFormTokenOracle { get; init; }
    }
}

public class CsrfScenario
{
    /// <summary>Full absolute URL of the captured request.</summary>
    public string Url { get; init; } = "";

    /// <summary>URL path and query (e.g. <c>/api/foo?x=1</c>).</summary>
    public string Path { get; init; } = "";

    public string Method { get; init; } = "";
    public string TestType { get; init; } = "";
    /// <summary>high, medium, low — used for GET form/request heuristics.</summary>
    public string Severity { get; set; } = "";
    public string Description { get; set; } = "";
    public int OriginalStatus { get; init; }
    public int TestStatus { get; init; }
    public bool Vulnerable { get; init; }
    public string? Error { get; init; }
    public string TokenLocation { get; init; } = "";
    /// <summary>Heuristic reasons the GET form/request was treated as state-changing.</summary>
    public List<string> MutationIndicators { get; init; } = new();
    /// <summary>Summary of form field names/values (DOM analysis only).</summary>
    public string FormFields { get; init; } = "";
}

public class CsrfResult
{
    /// <summary>Endpoints that used CSRF tokens and were probed with missing/invalid token requests.</summary>
    public int EndpointsTested { get; init; }

    /// <summary>Successful state-changing endpoints with no CSRF token observed in captured traffic.</summary>
    public int UnprotectedCount { get; init; }

    /// <summary>Endpoints with implicit framework CSRF protection (e.g. ASP.NET WebForms __VIEWSTATE, JSF ViewState).</summary>
    public int ImplicitProtectionCount { get; init; }

    public int VulnerableCount { get; init; }
    public string Message { get; init; } = "";
    public List<CsrfScenario> Scenarios { get; init; } = new();

    /// <summary>
    /// GET requests whose path or query looks like a state change (informational). Use <c>includeGet: true</c> to probe token-bearing GETs.
    /// </summary>
    public List<CsrfGetStateChangeHint> StateChangingGetHints { get; init; } = new();

    /// <summary>Count of GET form/request heuristic findings (DOM + passive network).</summary>
    public int GetFormFindingsCount { get; init; }

    /// <summary>State-changing endpoints probed for Referer validation and bypass variants.</summary>
    public int RefererEndpointsTested { get; init; }

    /// <summary>Referer bypass probes that matched the legitimate-Referer baseline response.</summary>
    public int RefererBypassCount { get; init; }

    /// <summary>Per-endpoint Referer validation and bypass probe results (server-side HttpClient).</summary>
    public List<CsrfRefererFinding> RefererFindings { get; init; } = new();

    /// <summary>Cross-tool correlation findings (CSRF vs secrets harvest, XSS, etc.).</summary>
    public List<SecurityFindingCorrelator.CorrelationFinding> Correlations { get; init; } = new();

    /// <summary>JSON API paths discovered from JS, view-source, or network log.</summary>
    public List<JsonApiCsrfProber.Hint> JsonApiHints { get; init; } = new();

    /// <summary>Number of JSON API CSRF probes executed.</summary>
    public int JsonApiProbesRun { get; init; }

    /// <summary>Session cookie SameSite analysis correlated with CSRF risk.</summary>
    public CsrfSameSiteAnalyzer.SameSiteContext? SameSiteContext { get; init; }

    /// <summary>Custom-header and simple Content-Type CSRF probes executed.</summary>
    public int CustomHeaderProbesRun { get; init; }

    /// <summary>Browser cross-site CSRF proof (mocked evil.trowser.test attacker origin).</summary>
    public CrossSiteCsrfProber.RunResult? CrossSiteProof { get; init; }
}

public class CsrfRefererFinding
{
    public string Url { get; init; } = "";
    public string Path { get; init; } = "";
    public string Method { get; init; } = "";
    public bool HasCsrfToken { get; init; }
    public bool RefererValidationDetected { get; init; }
    public List<CsrfRefererProbeResult> Probes { get; init; } = new();
}

public class CsrfRefererProbeResult
{
    public string ProbeName { get; init; } = "";
    /// <summary>Referer header value sent; null when the header was omitted.</summary>
    public string? RefererValue { get; init; }
    /// <summary>BLOCKED, BYPASSED, ERROR, or INCONCLUSIVE.</summary>
    public string Classification { get; init; } = "";
    public int BaselineStatus { get; init; }
    public int ProbeStatus { get; init; }
    public bool Vulnerable { get; init; }
    public string Severity { get; init; } = "";
    public string Description { get; init; } = "";
    public string? Error { get; init; }
}

public class CsrfGetStateChangeHint
{
    public string Url { get; init; } = "";
    public string Reason { get; init; } = "";
}
