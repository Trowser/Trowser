using System.Diagnostics;
using System.Text;
using Trowser.Automation;
using Trowser.Security.DomFlow;

namespace Trowser.Security;

/// <summary>
/// Standalone DOM/reflected XSS scan — discovers URL parameters from DOM/network log and probes with trace-input logic.
/// </summary>
public sealed class XssScanRunner
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public XssScanRunner(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class XssScanOptions
    {
        public string? Url { get; set; }
        public string? ParamName { get; set; }
        /// <summary>Optional explicit request template with §marker§ / {{marker}} (same shape as sqli-scan).</summary>
        public string? RequestUrlTemplate { get; set; }
        public string RequestMethod { get; set; } = "GET";
        public string? RequestBodyTemplate { get; set; }
        public Dictionary<string, string>? RequestHeaders { get; set; }
        public bool IncludeReflected { get; set; } = true;
        public bool IncludeDom { get; set; } = true;
        public bool IncludeStored { get; set; }
        public int MaxCandidates { get; set; } = 10;
        public int TimeoutMs { get; set; } = 10_000;
        public int MaxBypassAttempts { get; set; } = 6;
        /// <summary>quick | standard | deep</summary>
        public string? Depth { get; set; }

        /// <summary>Payload corpus breadth for XSS payload selection (default small).</summary>
        public PayloadProfile PayloadProfile { get; set; } = PayloadProfile.Small;

        /// <summary>When false, do not add common <c>/search</c> and <c>/api/products</c> scaffold URLs.</summary>
        public bool IncludeGenericScaffold { get; set; } = true;
    }

    public sealed class XssCandidate
    {
        public string BaseUrl { get; init; } = "";
        public string ParamName { get; init; } = "";
        public TraceSourceType Source { get; init; }
        public string Discovery { get; init; } = "";
        public string? UrlTemplate { get; init; }
        public string Method { get; init; } = "GET";
        public string? BodyTemplate { get; init; }
        public Dictionary<string, string>? Headers { get; init; }
        public bool Reflected { get; init; }
    }

    public sealed class XssScanBatchResult
    {
        public string Message { get; init; } = "";
        public string Depth { get; init; } = SecurityScanDepth.Standard;
        public int CandidatesProbed { get; init; }
        public int PayloadsSent { get; init; }
        public int ElapsedMs { get; init; }
        /// <summary>High-level phase lines (candidate start/end, DOM verify) for long runs.</summary>
        public List<string> Progress { get; init; } = [];
        public List<UnifiedSecurityFinding> Findings { get; init; } = [];
        public List<string> ZeroResultHints { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;

        public SecurityScanResult ToSecurityScanResult(IReadOnlyList<string>? extraSummary = null)
        {
            var details = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            if (Progress.Count > 0)
                details["progress"] = Progress;
            return new SecurityScanResult
            {
                Message = Message,
                Depth = Depth,
                CandidatesProbed = CandidatesProbed,
                PayloadsSent = PayloadsSent,
                ElapsedMs = ElapsedMs,
                Progress = Progress,
                Findings = Findings,
                Summary = BuildSummary(extraSummary),
                Details = details
            };
        }

        private List<string> BuildSummary(IReadOnlyList<string>? extraSummary)
        {
            var lines = Findings.Count > 0
                ? new List<string> { $"{Findings.Count} XSS finding(s)." }
                : new List<string> { "No XSS indicators." };
            if (extraSummary != null)
                lines.AddRange(extraSummary);
            return lines;
        }

        public string Format(bool includeDetails = true)
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== XSS Scan ===");
            sb.AppendLine(Message);
            sb.AppendLine($"Depth: {Depth}, Candidates: {CandidatesProbed}, Elapsed: {ElapsedMs}ms");
            sb.AppendLine();

            if (Findings.Count == 0)
            {
                sb.AppendLine("NO XSS INDICATORS");
                return sb.ToString();
            }

            foreach (var f in Findings)
            {
                sb.AppendLine($"  [{f.Severity.ToUpperInvariant()}/{f.Confidence}] {f.Category}: {f.Param} on {f.Endpoint}");
                sb.AppendLine($"    Payload: {f.Payload}");
                sb.AppendLine($"    {f.ProofHint ?? f.Title}");
            }

            return sb.ToString();
        }
    }

    public async Task<XssScanBatchResult> RunAsync(XssScanOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var depthProfile = InjectionScanDepth.Resolve(options.Depth, options.MaxCandidates);
        var maxBypass = options.MaxBypassAttempts > 0 ? options.MaxBypassAttempts : depthProfile.MaxBypassAttempts;
        var includeStored = options.IncludeStored || depthProfile.IncludeStoredXss;
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running xss-scan.");

        try
        {
            options.MaxCandidates = depthProfile.MaxCandidates;
            var candidates = await BuildCandidatesAsync(options, currentUrl, currentUri, ct);
            if (candidates.Count == 0)
            {
                return new XssScanBatchResult
                {
                    Message = "No XSS parameter candidates found. Browse the app or pass url + paramName.",
                    Depth = depthProfile.Name,
                    ElapsedMs = (int)sw.ElapsedMilliseconds,
                    Progress = [$"no candidates after discovery ({depthProfile.Name})"]
                };
            }

            var findings = new List<UnifiedSecurityFinding>();
            var payloadsSent = 0;
            var progress = new List<string>();
            _log($"XssScan: {candidates.Count} candidate(s) (depth={depthProfile.Name})", "#888888");
            progress.Add($"start: {candidates.Count} candidate(s), depth={depthProfile.Name}");

            var candidateIndex = 0;
            foreach (var candidate in candidates)
            {
                ct.ThrowIfCancellationRequested();
                candidateIndex++;
                progress.Add($"candidate {candidateIndex}/{candidates.Count}: {candidate.ParamName} on {TruncateProgressEndpoint(candidate.BaseUrl)} ({candidate.Discovery})");
                try
                {
                    if (candidate.Reflected && options.IncludeReflected && !string.IsNullOrEmpty(candidate.UrlTemplate))
                    {
                        var reflected = await XssScanner.RunAsync(
                            _ctx,
                            candidate.UrlTemplate,
                            candidate.Method,
                            candidate.Headers,
                            candidate.BodyTemplate,
                            options.TimeoutMs,
                            depth: depthProfile.Name,
                            payloadProfile: options.PayloadProfile,
                            runCharSurvival: depthProfile.RunCharSurvivalProbe,
                            ct: ct);
                        payloadsSent += reflected.Rows.Count(r => r.Dangerous);

                        foreach (var row in reflected.Rows.Where(r => r.Dangerous))
                        {
                            var domVerified = false;
                            var confidence = SecurityConfidence.Likely;
                            var severity = "high";
                            var detail = row.Reason ?? "Dangerous unencoded reflection in HTTP response.";

                            if (depthProfile.VerifyReflectedInDom)
                            {
                                progress.Add($"  dom-verify (reflected): {candidate.ParamName}");
                                var verify = await XssScanner.RunDomProbeAsync(
                                    _ctx, candidate.BaseUrl, candidate.Source, candidate.ParamName,
                                    options.TimeoutMs, maxBypass, ct);
                                var hit = verify.Rows.FirstOrDefault(r => r.Dangerous);
                                if (hit != null)
                                {
                                    domVerified = hit.DomVerified;
                                    severity = string.IsNullOrWhiteSpace(hit.Severity) ? "critical" : hit.Severity;
                                    confidence = (severity is "critical" or "high") && domVerified
                                        ? SecurityConfidence.Confirmed
                                        : SecurityConfidence.Likely;
                                    detail = hit.Reason
                                             ?? "Reflected XSS confirmed via live DOM / sink oracle.";
                                }
                                else
                                {
                                    confidence = SecurityConfidence.Tentative;
                                    severity = "medium";
                                    detail += " (response reflection only — DOM verify did not confirm execution)";
                                }
                            }

                            _log($"  FLAG reflected XSS ({confidence}): {candidate.ParamName} on {candidate.BaseUrl}", "#F44747");
                            findings.Add(UnifiedSecurityFinding.Create(
                                category: "xss-reflected",
                                title: "Reflected XSS",
                                severity: severity,
                                confidence: confidence,
                                endpoint: candidate.BaseUrl,
                                method: candidate.Method,
                                param: candidate.ParamName,
                                payload: row.Payload,
                                evidence: row.Surrounding,
                                proofHint: detail,
                                nextActions: SecurityNextActions.XssFollowUp(candidate.ParamName, candidate.BaseUrl)
                                    .Select(i => i.Summary).ToList(),
                                nextActionItems: SecurityNextActions.XssFollowUp(candidate.ParamName, candidate.BaseUrl),
                                extra: new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                                {
                                    ["context"] = row.Context,
                                    ["source"] = candidate.Discovery,
                                    ["domVerified"] = domVerified,
                                    ["charSurvival"] = reflected.CharSurvival?.SurvivingSpecials
                                }));
                        }
                    }

                    if (options.IncludeDom)
                    {
                        progress.Add($"  dom-probe: {candidate.ParamName} ({TraceInputOptions.SourceTypeName(candidate.Source)})");
                        var dom = await XssScanner.RunDomProbeAsync(
                            _ctx,
                            candidate.BaseUrl,
                            candidate.Source,
                            candidate.ParamName,
                            options.TimeoutMs,
                            maxBypass,
                            ct);
                        if (dom.Rows.Any(r => r.Dangerous))
                            payloadsSent++;

                        foreach (var row in dom.Rows.Where(r => r.Dangerous))
                        {
                            // UrlQuery / server-reflected candidates: DomProbe is a live-DOM oracle for
                            // reflected XSS. Reserve "DOM XSS" for client-side sources (url-hash, etc.).
                            var isClientDomSource = candidate.Source == TraceSourceType.UrlHash
                                || (!candidate.Reflected
                                    && candidate.Discovery is "dom-script" or "dom-script-hash" or "dom-script-query"
                                    or "current-hash-query" or "current-url-query");

                            if (!isClientDomSource)
                            {
                                if (findings.Any(f =>
                                        f.Category == "xss-reflected"
                                        && string.Equals(f.Param, candidate.ParamName, StringComparison.OrdinalIgnoreCase)
                                        && string.Equals(f.Endpoint, candidate.BaseUrl, StringComparison.OrdinalIgnoreCase)))
                                    continue;

                                var reflectedSev = string.IsNullOrWhiteSpace(row.Severity) ? "critical" : row.Severity;
                                var reflectedConfirmed = row.DomVerified
                                    && (reflectedSev is "critical" or "high");
                                _log($"  FLAG reflected XSS (DOM oracle): {candidate.ParamName} on {candidate.BaseUrl}", "#F44747");
                                findings.Add(UnifiedSecurityFinding.Create(
                                    category: "xss-reflected",
                                    title: "Reflected XSS",
                                    severity: reflectedSev,
                                    confidence: reflectedConfirmed
                                        ? SecurityConfidence.Confirmed
                                        : SecurityConfidence.Likely,
                                    endpoint: candidate.BaseUrl,
                                    method: candidate.Method,
                                    param: candidate.ParamName,
                                    payload: row.Payload,
                                    evidence: row.Surrounding,
                                    proofHint: row.Reason ?? "Reflected XSS confirmed via live DOM / sink oracle.",
                                    nextActions: SecurityNextActions.XssFollowUp(candidate.ParamName, candidate.BaseUrl)
                                        .Select(i => i.Summary).ToList(),
                                    nextActionItems: SecurityNextActions.XssFollowUp(candidate.ParamName, candidate.BaseUrl),
                                    extra: new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                                    {
                                        ["context"] = row.Context,
                                        ["source"] = candidate.Discovery,
                                        ["domVerified"] = row.DomVerified
                                    }));
                                continue;
                            }

                            var domSev = string.IsNullOrWhiteSpace(row.Severity) ? "critical" : row.Severity;
                            var domConfirmed = row.ConfirmedDomXss
                                               && row.DomVerified
                                               && (domSev is "critical" or "high");
                            _log($"  FLAG DOM XSS: {candidate.ParamName} ({candidate.Source}) on {candidate.BaseUrl}", "#F44747");
                            findings.Add(UnifiedSecurityFinding.Create(
                                category: "xss-dom",
                                title: "DOM XSS",
                                severity: domSev,
                                confidence: domConfirmed
                                    ? SecurityConfidence.Confirmed
                                    : SecurityConfidence.Likely,
                                endpoint: candidate.BaseUrl,
                                method: "GET",
                                param: candidate.ParamName,
                                payload: row.Payload,
                                evidence: row.Surrounding,
                                proofHint: row.Reason ?? "Payload rendered in DOM without adequate encoding.",
                                nextActions: SecurityNextActions.XssFollowUp(candidate.ParamName, candidate.BaseUrl)
                                    .Select(i => i.Summary).ToList(),
                                nextActionItems: SecurityNextActions.XssFollowUp(candidate.ParamName, candidate.BaseUrl),
                                extra: new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                                {
                                    ["context"] = row.Context,
                                    ["source"] = TraceInputOptions.SourceTypeName(candidate.Source),
                                    ["domVerified"] = row.DomVerified
                                }));
                        }
                    }
                }
                catch (Exception ex)
                {
                    _log($"  XSS skip {candidate.ParamName}: {ex.Message}", "#888888");
                }
            }

            if (includeStored)
            {
                progress.Add("stored-xss pass");
                try
                {
                    var stored = await new XssStoredScanProbe(_ctx, _log).RunAsync(
                        new XssStoredScanProbe.XssStoredScanOptions
                        {
                            MaxCandidates = options.MaxCandidates,
                            TimeoutMs = options.TimeoutMs
                        }, ct);
                    foreach (var f in stored.Findings)
                    {
                        findings.Add(UnifiedSecurityFinding.Create(
                            category: "xss-stored",
                            title: "Stored XSS",
                            severity: f.Severity,
                            confidence: SecurityConfidence.Likely,
                            endpoint: f.ReadUrl,
                            param: f.FieldName,
                            payload: f.Payload,
                            evidence: f.Evidence,
                            proofHint: f.Detail,
                            nextActions: [SecurityNextActions.VerifyWorkflow],
                            extra: new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                            {
                                ["context"] = "stored-readback",
                                ["source"] = f.Source
                            }));
                    }
                }
                catch (Exception ex)
                {
                    _log($"  XSS stored scan: {ex.Message}", "#888888");
                }
            }

            sw.Stop();
            var deduped = findings
                .GroupBy(f => $"{f.Category}|{f.Endpoint}|{f.Param}|{f.Payload}", StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .ToList();
            var collapsed = CollapseXssFindings(deduped);
            if (payloadsSent == 0)
                collapsed = DemoteUnprobedConfirmations(collapsed);
            var hints = BuildZeroFindingHints(currentUri, collapsed.Count, options);
            progress.Add($"done: {collapsed.Count} finding(s), {payloadsSent} payload round(s), {sw.ElapsedMilliseconds}ms");

            return new XssScanBatchResult
            {
                Message = collapsed.Count > 0
                    ? $"{collapsed.Count} XSS finding(s) across {candidates.Count} candidate(s)."
                    : $"No XSS indicators across {candidates.Count} candidate(s).",
                Depth = depthProfile.Name,
                CandidatesProbed = candidates.Count,
                PayloadsSent = payloadsSent,
                Progress = progress,
                Findings = collapsed,
                ElapsedMs = (int)sw.ElapsedMilliseconds,
                ZeroResultHints = hints
            };
        }
        finally
        {
            await RestoreBrowserUrlAsync(currentUrl);
        }
    }

    private static List<UnifiedSecurityFinding> CollapseXssFindings(IReadOnlyList<UnifiedSecurityFinding> findings)
    {
        if (findings.Count <= 1) return findings.ToList();

        var groups = new Dictionary<string, UnifiedSecurityFinding>(StringComparer.OrdinalIgnoreCase);
        var order = new List<string>();
        foreach (var f in findings)
        {
            var key = $"{f.Category}|{f.Endpoint}|{f.Param}".ToLowerInvariant();
            if (!groups.TryGetValue(key, out var existing))
            {
                groups[key] = f;
                order.Add(key);
                continue;
            }

            var payloads = new List<string>();
            if (!string.IsNullOrEmpty(existing.Payload)) payloads.Add(existing.Payload);
            if (!string.IsNullOrEmpty(f.Payload) && !payloads.Contains(f.Payload, StringComparer.Ordinal))
                payloads.Add(f.Payload!);

            var extra = new Dictionary<string, object?>(existing.Extra, StringComparer.OrdinalIgnoreCase);
            extra["payloads"] = payloads;
            extra["payloadCount"] = payloads.Count;

            var severity = SeverityRank(f.Severity) > SeverityRank(existing.Severity) ? f.Severity : existing.Severity;
            var confidence = SecurityConfidence.Rank(f.Confidence) > SecurityConfidence.Rank(existing.Confidence)
                ? f.Confidence
                : existing.Confidence;

            groups[key] = UnifiedSecurityFinding.Create(
                category: existing.Category,
                title: existing.Title,
                severity: severity,
                confidence: confidence,
                endpoint: existing.Endpoint,
                method: existing.Method,
                param: existing.Param,
                payload: payloads.Count > 0 ? payloads[0] : existing.Payload,
                evidence: existing.Evidence,
                proofHint: existing.ProofHint,
                nextActions: existing.NextActions,
                extra: extra,
                id: existing.Id);
        }

        return order.Select(k => groups[k]).ToList();
    }

    private static List<UnifiedSecurityFinding> DemoteUnprobedConfirmations(IReadOnlyList<UnifiedSecurityFinding> findings)
    {
        var list = new List<UnifiedSecurityFinding>(findings.Count);
        foreach (var f in findings)
        {
            if (f.Confidence != SecurityConfidence.Confirmed)
            {
                list.Add(f);
                continue;
            }

            list.Add(UnifiedSecurityFinding.Create(
                category: f.Category,
                title: f.Title,
                severity: f.Severity is "critical" ? "high" : f.Severity,
                confidence: SecurityConfidence.Likely,
                endpoint: f.Endpoint,
                method: f.Method,
                param: f.Param,
                payload: f.Payload,
                evidence: f.Evidence,
                proofHint: (f.ProofHint ?? "") + " (payloadsSent=0 — not confirmed; re-run after active probes)",
                tier: f.Tier,
                nextActions: f.NextActions,
                extra: f.Extra,
                id: f.Id));
        }
        return list;
    }

    private static int SeverityRank(string? severity) => (severity ?? "").Trim().ToLowerInvariant() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0
    };

    private static List<string> BuildZeroFindingHints(Uri currentUri, int findingCount, XssScanOptions options)
    {
        if (findingCount > 0) return [];

        var hints = new List<string>();
        var queryParams = ParseQueryPairs(currentUri.Query).ToList();
        if (queryParams.Count == 0 && string.IsNullOrWhiteSpace(currentUri.Fragment))
            return hints;

        hints.Add(
            "xss-scan probes reflected HTTP + optional DOM navigation — it is not the same as trace-input " +
            "(source→network→DOM causality with sink hooks). For query/hash parameters with no static sinks, " +
            "run POST /api/security/trace-input with monitorSinks:true and autoBypass:true on the live page.");
        if (queryParams.Count > 0 && options.IncludeDom)
        {
            hints.Add(
                $"Current URL has query parameter(s) [{string.Join(", ", queryParams.Take(6))}] — " +
                "if xss-scan returned clean, use trace-input on those names before treating DOM XSS as ruled out.");
        }

        return hints;
    }

    private async Task RestoreBrowserUrlAsync(string baselineUrl)
    {
        if (string.IsNullOrWhiteSpace(baselineUrl)) return;
        try
        {
            var now = await _ctx.GetCurrentUrl();
            if (string.Equals(now, baselineUrl, StringComparison.OrdinalIgnoreCase))
                return;
            await _ctx.Navigate(baselineUrl);
            await Task.Delay(300);
        }
        catch
        {
            // Best-effort — scan results are still valid if restore fails.
        }
    }

    private async Task<List<XssCandidate>> BuildCandidatesAsync(
        XssScanOptions options,
        string currentUrl,
        Uri currentUri,
        CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(options.RequestUrlTemplate)
            && RequestMarkerSubstitute.ListMarkers(options.RequestUrlTemplate, options.RequestBodyTemplate).Count > 0)
        {
            var markers = RequestMarkerSubstitute.ListMarkers(options.RequestUrlTemplate, options.RequestBodyTemplate);
            var param = !string.IsNullOrWhiteSpace(options.ParamName) ? options.ParamName! : markers[0];
            var baseUrl = SpaRouteBase(options.RequestUrlTemplate!.Split('?', '#')[0]);
            return
            [
                new XssCandidate
                {
                    BaseUrl = baseUrl,
                    ParamName = param,
                    Source = TraceSourceType.UrlQuery,
                    Discovery = "explicit-request",
                    UrlTemplate = options.RequestUrlTemplate,
                    Method = string.IsNullOrWhiteSpace(options.RequestMethod) ? "GET" : options.RequestMethod,
                    BodyTemplate = options.RequestBodyTemplate,
                    Headers = options.RequestHeaders,
                    Reflected = true
                }
            ];
        }

        if (!string.IsNullOrWhiteSpace(options.Url) && !string.IsNullOrWhiteSpace(options.ParamName))
        {
            return
            [
                BuildCandidate(options.Url!, options.ParamName!, TraceSourceType.UrlQuery, "explicit", reflected: true),
                BuildCandidate(options.Url!, options.ParamName!, TraceSourceType.UrlHash, "explicit", reflected: false)
            ];
        }

        var max = options.MaxCandidates > 0 ? options.MaxCandidates : 10;
        var originHost = currentUri.Host;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var candidates = new List<XssCandidate>();

        void TryAdd(XssCandidate candidate)
        {
            if (string.IsNullOrWhiteSpace(candidate.ParamName)) return;
            var key = $"{candidate.Reflected}|{candidate.Source}|{candidate.BaseUrl}|{candidate.ParamName}";
            if (!seen.Add(key)) return;
            candidates.Add(candidate);
        }

        foreach (var pair in ParseQueryPairs(currentUri.Query))
            TryAdd(BuildCandidate(SpaRouteBase(currentUrl), pair, TraceSourceType.UrlQuery, "current-url-query", reflected: false));

        var hashRouteBase = SpaRouteBase(currentUrl);
        foreach (var pair in ParseHashQueryPairs(currentUri.Fragment))
            TryAdd(BuildCandidate(hashRouteBase, pair, TraceSourceType.UrlQuery, "current-hash-query", reflected: false));

        // Prefer XSS-likely query params from the network log (API endpoints), not only SPA document params.
        var networkCandidates = new List<XssCandidate>();
        foreach (var entry in _ctx.Network.Entries)
        {
            ct.ThrowIfCancellationRequested();
            if (!string.Equals(entry.Method, "GET", StringComparison.OrdinalIgnoreCase)) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (!SecurityHostScope.MatchesHostFilter(uri.Host, originHost)
                && !string.Equals(uri.GetLeftPart(UriPartial.Authority),
                    currentUri.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase))
                continue;

            foreach (var pair in ParseQueryPairs(uri.Query))
            {
                var c = BuildCandidate(entry.Url, pair, TraceSourceType.UrlQuery, "network-log", reflected: true);
                if (!string.IsNullOrWhiteSpace(c.ParamName))
                    networkCandidates.Add(c);
            }
        }

        foreach (var c in networkCandidates
                     .OrderByDescending(c => InjectionParamClassifier.XssLikelihoodScore(c.ParamName)))
        {
            TryAdd(c);
            if (candidates.Count >= max) return PrioritizeCandidates(candidates, max);
        }

        await _ctx.Navigate(UrlPayloadInjector.StripFragment(currentUrl));
        await Task.Delay(300, ct);
        var discovered = await DomUrlParamDiscovery.DiscoverAsync(_ctx);
        if (discovered != null)
        {
            if (!string.IsNullOrEmpty(discovered.PreferredQueryParam))
                TryAdd(BuildCandidate(hashRouteBase, discovered.PreferredQueryParam, TraceSourceType.UrlQuery, "dom-script-query", reflected: false));
            if (!string.IsNullOrEmpty(discovered.PreferredHashParam))
                TryAdd(BuildCandidate(hashRouteBase, discovered.PreferredHashParam, TraceSourceType.UrlHash, "dom-script-hash", reflected: false));

            foreach (var name in discovered.ParamNames)
            {
                TryAdd(BuildCandidate(hashRouteBase, name, TraceSourceType.UrlHash, "dom-script", reflected: false));
                TryAdd(BuildCandidate(hashRouteBase, name, TraceSourceType.UrlQuery, "dom-script", reflected: false));
                if (candidates.Count >= max) return PrioritizeCandidates(candidates, max);
            }

            if (discovered.UsesRawHashFragment && !DomFlowSpaProbe.IsHashRouterUrl(currentUrl))
            {
                TryAdd(new XssCandidate
                {
                    BaseUrl = hashRouteBase,
                    ParamName = "",
                    Source = TraceSourceType.UrlHash,
                    Discovery = "raw-hash-fragment",
                    Method = "GET",
                    Reflected = false
                });
            }
        }

        if (candidates.Count == 0
            && !DomFlowSpaProbe.IsHashRouterUrl(currentUrl)
            && !string.IsNullOrWhiteSpace(currentUri.Fragment.TrimStart('#')))
        {
            TryAdd(new XssCandidate
            {
                BaseUrl = hashRouteBase,
                ParamName = "",
                Source = TraceSourceType.UrlHash,
                Discovery = "current-raw-hash",
                Method = "GET",
                Reflected = false
            });
        }

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var appBase = InjectionScaffold.InferAppBasePath(currentUri.ToString());
        var pageEntries = _ctx.GetPageNetworkLog();
        if (options.IncludeGenericScaffold)
        {
            foreach (var tpl in InjectionScaffold.EnumerateXssScaffold())
            {
                var prefixed = InjectionScaffold.ApplyAppBasePrefix(appBase, tpl.PathQueryTemplate);
                if (pageEntries.Count > 0
                    && !InjectionScaffoldFindingPolicy.IsPathObservedInTraffic(pageEntries, prefixed, origin))
                    continue;

                var url = InjectionScaffold.BuildUrl(origin, tpl.PathQueryTemplate, "probe", appBase);
                TryAdd(new XssCandidate
                {
                    BaseUrl = SpaRouteBase(url),
                    ParamName = tpl.ParamName,
                    Source = TraceSourceType.UrlQuery,
                    Discovery = "scaffold",
                    UrlTemplate = tpl.PathQueryTemplate.Contains('#') ? null : url.Replace("probe", "§xss§", StringComparison.Ordinal),
                    Method = tpl.Method,
                    Reflected = !tpl.PathQueryTemplate.Contains('#')
                });
                if (candidates.Count >= max) break;
            }

            // Do not blindly probe q/search/query on hash routes — that fabricates DOM XSS when the app
            // only uses form/API search (see dom-script / current-url / network-log candidates above).
        }

        return PrioritizeCandidates(candidates, max);
    }

    private static List<XssCandidate> PrioritizeCandidates(List<XssCandidate> candidates, int max) =>
        candidates
            .OrderByDescending(c => c.Discovery == "network-log" || c.Discovery == "explicit" || c.Discovery == "explicit-request" ? 1 : 0)
            .ThenByDescending(c => InjectionParamClassifier.XssLikelihoodScore(c.ParamName))
            .Take(max)
            .ToList();

    private static XssCandidate BuildCandidate(
        string url,
        string paramName,
        TraceSourceType source,
        string discovery,
        bool reflected)
    {
        if (!CstiCandidateDiscovery.IsProbeableParam(paramName))
            return new XssCandidate();

        var baseUrl = SpaRouteBase(url);
        var markerUrl = AppendMarkerToUrl(baseUrl, paramName);
        return new XssCandidate
        {
            BaseUrl = baseUrl,
            ParamName = paramName,
            Source = source,
            Discovery = discovery,
            UrlTemplate = reflected ? markerUrl : null,
            Method = "GET",
            Reflected = reflected && markerUrl.Contains('§')
        };
    }

    internal static string SpaRouteBase(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return UrlPayloadInjector.StripFragment(url);

        var fragment = uri.Fragment.TrimStart('#');
        if (!UrlPayloadInjector.IsSpaHashRoute(fragment))
        {
            var builder = new UriBuilder(uri) { Query = "", Fragment = "" };
            return builder.Uri.ToString();
        }

        var route = fragment;
        var qIdx = route.IndexOf('?');
        if (qIdx >= 0)
            route = route[..qIdx];

        var routeBuilder = new UriBuilder(uri) { Query = "", Fragment = route };
        return routeBuilder.Uri.ToString();
    }

    private static string AppendMarkerToUrl(string url, string paramName)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url;

        var fragment = uri.Fragment.TrimStart('#');
        if (UrlPayloadInjector.IsSpaHashRoute(fragment))
        {
            var injected = UrlPayloadInjector.Build(uri.ToString(), new UrlInjectionSpec
            {
                Part = UrlInjectionPart.Query,
                Param = paramName,
                Encode = UrlPayloadEncodeMode.Component
            }, "§xss§");
            return injected.Replace("§xss§", "§xss§", StringComparison.Ordinal);
        }

        var sep = string.IsNullOrEmpty(uri.Query) ? "?" : "&";
        return url + sep + Uri.EscapeDataString(paramName) + "=§xss§";
    }

    private static IEnumerable<string> ParseQueryPairs(string query)
    {
        foreach (var pair in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq <= 0) continue;
            yield return Uri.UnescapeDataString(pair[..eq]);
        }
    }

    private static IEnumerable<string> ParseHashQueryPairs(string fragment)
    {
        var hash = fragment.TrimStart('#');
        var qIdx = hash.IndexOf('?');
        if (qIdx < 0) yield break;
        foreach (var pair in hash[(qIdx + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq <= 0) continue;
            yield return Uri.UnescapeDataString(pair[..eq]);
        }
    }

    private static string TruncateProgressEndpoint(string url, int max = 96)
    {
        if (string.IsNullOrEmpty(url)) return url;
        return url.Length <= max ? url : url[..max] + "…";
    }
}
