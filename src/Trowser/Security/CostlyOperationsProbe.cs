using System.Diagnostics;
using Trowser.Automation;
using Trowser.Security.ChainEngine;
using Trowser.Security.Orchestration;

namespace Trowser.Security;

/// <summary>
/// Passive-first scan for single-request cost risks (large responses, weak paging, heavy routes, etc.).
/// Optional bounded confirms when safety mode allows probes.
/// </summary>
public sealed class CostlyOperationsProbe
{
    public static readonly IReadOnlyList<string> PassiveCheckIds =
    [
        "large-response", "pagination", "heavy-route", "slow-sync", "bulk-input",
        "expansion", "upload-surface", "traffic-shape",
        "compose-graphql", "compose-llm", "compose-ssrf-fetch", "compose-redos", "compose-spec-unbounded",
        "nested-payload", "recipient-fanout", "date-range", "filter-depth", "spec-limits"
    ];

    public static readonly IReadOnlyList<string> ConfirmCheckIds =
    [
        "confirm-page-size", "confirm-image-edge", "confirm-multi-id"
    ];

    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public CostlyOperationsProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class CostlyOperationsOptions
    {
        public SafetyMode SafetyMode { get; set; } = SafetyMode.Passive;
        public IReadOnlyList<string>? Checks { get; set; }
        public int MaxCandidates { get; set; } = 24;
        public int TimeoutMs { get; set; } = 15000;
        public int MaxResponseBytes { get; set; } = 2_097_152;
        public int SlowThresholdMs { get; set; } = 3000;
        public bool IncludeSpaDom { get; set; } = true;
        public bool IncludeBrowserCookies { get; set; } = true;
        public bool RespectRateLimits { get; set; } = true;
        public bool RegisterChainFindings { get; set; } = true;
        public IReadOnlyList<string>? Urls { get; set; }
        /// <summary>Analyze OpenAPI/GraphQL schema bodies from captured traffic (same origin).</summary>
        public bool IncludeSpecsFromNetwork { get; set; } = true;
        /// <summary>When set, only these spec document URLs from the network log are analyzed.</summary>
        public IReadOnlyList<string>? SpecUrls { get; set; }
    }

    public sealed class CostlyFinding
    {
        public string Category { get; init; } = "costly-risk";
        public string Severity { get; init; } = "medium";
        public string Title { get; init; } = "";
        public string Endpoint { get; init; } = "";
        public string Method { get; init; } = "GET";
        public string? Parameter { get; init; }
        public string Detail { get; init; } = "";
        public string? Evidence { get; init; }
        public string Remediation { get; init; } = "";
        public string Confidence { get; init; } = "inferred";
        public string CheckId { get; init; } = "";
        public string? RelatedProbe { get; init; }
        /// <summary>Network log entry that triggered this finding (correlate with GET /api/network).</summary>
        public int? NetworkEntryId { get; init; }
    }

    public sealed class CostlyOperationsResult
    {
        public string Message { get; init; } = "";
        public string SafetyMode { get; init; } = "passive";
        public int EntriesExamined { get; init; }
        public int ProbesSent { get; init; }
        public int ElapsedMs { get; init; }
        public List<CostlyFinding> Findings { get; init; } = [];
        public List<CostlyFinding> InferredLeads { get; init; } = [];
        public List<string> ChecksRun { get; init; } = [];
        public bool HasFindings => Findings.Count > 0 || InferredLeads.Count > 0;
    }

    public async Task<CostlyOperationsResult> RunAsync(CostlyOperationsOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running costly-operations scan.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var allEntries = _ctx.Network.Entries;
        if (allEntries.Count == 0)
        {
            return new CostlyOperationsResult
            {
                Message = "No network traffic captured. Browse key flows first.",
                SafetyMode = options.SafetyMode.ToLabel(),
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        var entries = CostlyOperationsRules.FilterEntries(allEntries, origin, options.Urls);
        if (entries.Count == 0)
        {
            return new CostlyOperationsResult
            {
                Message = "No same-origin API entries in the network log after filtering.",
                SafetyMode = options.SafetyMode.ToLabel(),
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        var mapper = new AttackSurfaceMapper();
        var surface = mapper.Analyze(entries, includeParameters: true, includeAuth: true, includeResponsePatterns: true);

        SpaRuntimeSurface? spa = null;
        if (options.IncludeSpaDom)
        {
            var interactive = await _ctx.GetInteractiveElements().ConfigureAwait(false);
            var formCount = await _ctx.GetHtmlFormCountAsync().ConfigureAwait(false);
            var title = await _ctx.GetTitle().ConfigureAwait(false);
            spa = AttackSurfaceMapper.BuildSpaRuntimeSurface(interactive, formCount, currentUrl, title);
        }

        var specDocs = CostlyOperationsSpecAnalyzer.CollectFromNetwork(
            allEntries, origin, options.SpecUrls, options.IncludeSpecsFromNetwork);

        var ctx = new CostlyOperationsRules.ScanContext(
            entries, surface, spa, origin, options.SlowThresholdMs, options.MaxCandidates, specDocs, options.Urls);

        var enabledChecks = ResolveEnabledChecks(options);
        var dedupe = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var findings = new List<CostlyFinding>();
        var leads = new List<CostlyFinding>();

        void Emit(CostlyFinding f)
        {
            var key = $"{f.CheckId}|{f.Method}|{CostlyOperationsRules.NormalizeUrlKey(f.Endpoint)}|{f.Parameter}";
            if (!dedupe.Add(key)) return;
            if (f.Confidence == "inferred")
                leads.Add(f);
            else
                findings.Add(f);
        }

        foreach (var checkId in enabledChecks.Passive)
        {
            ct.ThrowIfCancellationRequested();
            foreach (var f in CostlyOperationsRules.RunCheck(checkId, ctx))
                Emit(f);
            foreach (var f in CostlyOperationsCompose.RunCheck(checkId, ctx))
                Emit(f);
            if (string.Equals(checkId, "spec-limits", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var f in CostlyOperationsSpecAnalyzer.Analyze(ctx.SpecDocuments, options.MaxCandidates))
                    Emit(f);
            }
        }

        var probesSent = 0;
        if (enabledChecks.Confirms.Count > 0 && options.SafetyMode.AllowsProbes())
        {
            var respectState = new RateLimitRespectHelper.RespectState();
            probesSent += await RunConfirmsAsync(
                enabledChecks.Confirms, ctx, options, respectState, Emit, ct).ConfigureAwait(false);
        }

        if (options.RegisterChainFindings)
            RegisterFindings(findings);

        var checksRun = enabledChecks.Passive.Concat(enabledChecks.Confirms).ToList();
        _log($"CostlyOperations: {findings.Count} finding(s), {leads.Count} lead(s), {probesSent} confirm probe(s)", "#888888");

        return new CostlyOperationsResult
        {
            Message = findings.Count > 0
                ? $"{findings.Count} costly-operation finding(s) ({leads.Count} inferred lead(s))."
                : leads.Count > 0
                    ? $"No high-confidence findings; {leads.Count} inferred lead(s) for manual review."
                    : $"No costly-operation signals in {entries.Count} captured request(s).",
            SafetyMode = options.SafetyMode.ToLabel(),
            EntriesExamined = entries.Count,
            ProbesSent = probesSent,
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            Findings = findings,
            InferredLeads = leads,
            ChecksRun = checksRun
        };
    }

    private static (List<string> Passive, List<string> Confirms) ResolveEnabledChecks(CostlyOperationsOptions options)
    {
        if (options.Checks is { Count: > 0 })
        {
            var passive = new List<string>();
            var confirms = new List<string>();
            foreach (var id in options.Checks.Where(c => !string.IsNullOrWhiteSpace(c)))
            {
                var t = id.Trim();
                if (ConfirmCheckIds.Contains(t, StringComparer.OrdinalIgnoreCase))
                    confirms.Add(t);
                else
                    passive.Add(t);
            }

            return (passive, confirms);
        }

        return (PassiveCheckIds.ToList(), []);
    }

    private async Task<int> RunConfirmsAsync(
        IReadOnlyList<string> confirmIds,
        CostlyOperationsRules.ScanContext ctx,
        CostlyOperationsOptions options,
        RateLimitRespectHelper.RespectState respectState,
        Action<CostlyFinding> emit,
        CancellationToken ct)
    {
        var sent = 0;
        foreach (var id in confirmIds)
        {
            ct.ThrowIfCancellationRequested();
            switch (id.ToLowerInvariant())
            {
                case "confirm-page-size":
                    sent += await ConfirmPageSizeAsync(ctx, options, respectState, emit, ct);
                    break;
                case "confirm-image-edge":
                    sent += await ConfirmImageEdgeAsync(ctx, options, respectState, emit, ct);
                    break;
                case "confirm-multi-id":
                    sent += await ConfirmMultiIdAsync(ctx, options, respectState, emit, ct);
                    break;
            }
        }

        return sent;
    }

    private async Task<int> ConfirmPageSizeAsync(
        CostlyOperationsRules.ScanContext ctx,
        CostlyOperationsOptions options,
        RateLimitRespectHelper.RespectState respectState,
        Action<CostlyFinding> emit,
        CancellationToken ct)
    {
        var sent = 0;
        foreach (var candidate in CostlyOperationsRules.PageSizeConfirmCandidates(ctx).Take(options.MaxCandidates))
        {
            ct.ThrowIfCancellationRequested();
            if (candidate.Method is "POST" or "PUT" or "PATCH" or "DELETE"
                && !options.SafetyMode.AllowsWriteVerbs())
                continue;

            var prepared = await InsecureDesignProbeSupport.PrepareRequestAsync(
                _ctx, candidate.BodyTemplate, candidate.Headers, candidate.Url,
                injectCsrfIfMissing: candidate.Method is "POST" or "PUT" or "PATCH", ct);

            var baseline = await RateLimitRespectHelper.FetchTimedAsync(
                _ctx, candidate.BaselineUrl, candidate.Method, prepared.Headers, prepared.Body,
                options.TimeoutMs, options.IncludeBrowserCookies, options.RespectRateLimits, respectState, ct);
            sent++;

            if (baseline.Result.Status is < 200 or >= 300) continue;

            var probe = await RateLimitRespectHelper.FetchTimedAsync(
                _ctx, candidate.ProbeUrl, candidate.Method, prepared.Headers, prepared.Body,
                options.TimeoutMs, options.IncludeBrowserCookies, options.RespectRateLimits, respectState, ct);
            sent++;

            if (probe.Result.Status is < 200 or >= 300) continue;
            if (probe.Result.Body.Length > options.MaxResponseBytes) continue;

            var baseLen = baseline.Result.Body.Length;
            var probeLen = probe.Result.Body.Length;
            var baseSec = baseline.ElapsedSeconds.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture);
            var probeSec = probe.ElapsedSeconds.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture);

            if (candidate.Kind == "inject")
            {
                if (probeLen < baseLen * 0.8)
                {
                    emit(new CostlyFinding
                    {
                        CheckId = "confirm-page-size",
                        Category = "costly-missing-pagination",
                        Severity = "medium",
                        Confidence = "confirmed",
                        Title = "Unpaged list shrank when limit=50 was added",
                        Endpoint = candidate.ProbeUrl,
                        Method = candidate.Method,
                        Parameter = "limit",
                        Detail = $"Captured call returned ~{baseLen} B. GET with limit=50 returned ~{probeLen} B ({baseSec}s → {probeSec}s). The server can page; the captured request did not ask it to.",
                        Evidence = candidate.Evidence,
                        Remediation = "Send a bounded limit by default and enforce a server-side maximum.",
                        NetworkEntryId = candidate.SourceNetworkEntryId
                    });
                }
                else if (probeLen > baseLen * 0.9)
                {
                    emit(new CostlyFinding
                    {
                        CheckId = "confirm-page-size",
                        Category = "costly-missing-pagination",
                        Severity = "medium",
                        Confidence = "confirmed",
                        Title = "Adding limit=50 did not shrink the list",
                        Endpoint = candidate.ProbeUrl,
                        Method = candidate.Method,
                        Parameter = "limit",
                        Detail = $"Captured call returned ~{baseLen} B. The same GET with limit=50 returned ~{probeLen} B. The server did not apply that page size.",
                        Evidence = candidate.Evidence,
                        Remediation = "Require a paging parameter and reject unlimited list reads.",
                        NetworkEntryId = candidate.SourceNetworkEntryId
                    });
                }

                continue;
            }

            if (probeLen <= baseLen * 1.25)
                continue;

            emit(new CostlyFinding
            {
                CheckId = "confirm-page-size",
                Category = "costly-page-size-honored",
                Severity = "medium",
                Confidence = "confirmed",
                Title = $"Larger {candidate.ParamName} accepted ({candidate.BaselineValue} → {candidate.ProbeValue})",
                Endpoint = candidate.ProbeUrl,
                Method = candidate.Method,
                Parameter = candidate.ParamName,
                Detail = $"Raising {candidate.ParamName} from {candidate.BaselineValue} to {candidate.ProbeValue} grew the body from ~{baseLen} B to ~{probeLen} B ({baseSec}s → {probeSec}s). Observed only up to {candidate.ProbeValue}; a higher maximum may still exist.",
                Evidence = $"baseline={candidate.BaselineValue}, probe={candidate.ProbeValue}",
                Remediation = "Enforce a server-side maximum page size and a safe default.",
                NetworkEntryId = candidate.SourceNetworkEntryId
            });
        }

        return sent;
    }

    private async Task<int> ConfirmImageEdgeAsync(
        CostlyOperationsRules.ScanContext ctx,
        CostlyOperationsOptions options,
        RateLimitRespectHelper.RespectState respectState,
        Action<CostlyFinding> emit,
        CancellationToken ct)
    {
        var sent = 0;
        foreach (var candidate in CostlyOperationsRules.ImageEdgeConfirmCandidates(ctx).Take(options.MaxCandidates))
        {
            ct.ThrowIfCancellationRequested();
            var baseline = await RateLimitRespectHelper.FetchTimedAsync(
                _ctx, candidate.BaselineUrl, "GET", null, null,
                options.TimeoutMs, options.IncludeBrowserCookies, options.RespectRateLimits, respectState, ct);
            sent++;
            if (baseline.Result.Status is < 200 or >= 300) continue;

            var probe = await RateLimitRespectHelper.FetchTimedAsync(
                _ctx, candidate.ProbeUrl, "GET", null, null,
                options.TimeoutMs, options.IncludeBrowserCookies, options.RespectRateLimits, respectState, ct);
            sent++;
            if (probe.Result.Status is < 200 or >= 300) continue;
            if (probe.Result.Body.Length > options.MaxResponseBytes) continue;

            if (probe.Result.Body.Length <= baseline.Result.Body.Length * 1.5) continue;

            emit(new CostlyFinding
            {
                CheckId = "confirm-image-edge",
                Category = "costly-image-dimensions",
                Severity = "high",
                Confidence = "confirmed",
                Title = $"Image dimensions scale output bytes ({candidate.ParamName})",
                Endpoint = candidate.ProbeUrl,
                Method = "GET",
                Parameter = candidate.ParamName,
                Detail = $"Modest edge step ({candidate.BaselineValue}→{candidate.ProbeValue}) increased body ~{baseline.Result.Body.Length} B to ~{probe.Result.Body.Length} B.",
                Remediation = "Cap maximum width/height/DPI server-side; reject oversized dimension requests.",
                NetworkEntryId = candidate.SourceNetworkEntryId
            });
        }

        return sent;
    }

    private async Task<int> ConfirmMultiIdAsync(
        CostlyOperationsRules.ScanContext ctx,
        CostlyOperationsOptions options,
        RateLimitRespectHelper.RespectState respectState,
        Action<CostlyFinding> emit,
        CancellationToken ct)
    {
        var sent = 0;
        foreach (var candidate in CostlyOperationsRules.MultiIdConfirmCandidates(ctx).Take(options.MaxCandidates))
        {
            ct.ThrowIfCancellationRequested();
            if (candidate.Method is "POST" or "PUT" or "PATCH" or "DELETE"
                && !options.SafetyMode.AllowsWriteVerbs())
                continue;

            var baseline = await RateLimitRespectHelper.FetchTimedAsync(
                _ctx, candidate.BaselineUrl, candidate.Method, candidate.Headers, null,
                options.TimeoutMs, options.IncludeBrowserCookies, options.RespectRateLimits, respectState, ct);
            sent++;
            if (baseline.Result.Status is < 200 or >= 300) continue;

            var probe = await RateLimitRespectHelper.FetchTimedAsync(
                _ctx, candidate.ProbeUrl, candidate.Method, candidate.Headers, null,
                options.TimeoutMs, options.IncludeBrowserCookies, options.RespectRateLimits, respectState, ct);
            sent++;
            if (probe.Result.Status is < 200 or >= 300) continue;
            if (probe.Result.Body.Length > options.MaxResponseBytes) continue;

            if (probe.Result.Body.Length <= baseline.Result.Body.Length * 1.2
                && probe.ElapsedSeconds <= baseline.ElapsedSeconds * 1.4)
                continue;

            emit(new CostlyFinding
            {
                CheckId = "confirm-multi-id",
                Category = "costly-bulk-input",
                Severity = "high",
                Confidence = "confirmed",
                Title = "Multi-id request accepted with larger response",
                Endpoint = candidate.ProbeUrl,
                Method = candidate.Method,
                Parameter = candidate.ParamName,
                Detail = "Adding a second id increased response size or latency — bulk id cap may be missing.",
                Evidence = candidate.Evidence,
                Remediation = "Limit the number of ids per request and enforce server-side batch size caps.",
                NetworkEntryId = candidate.SourceNetworkEntryId
            });
        }

        return sent;
    }

    private void RegisterFindings(IEnumerable<CostlyFinding> findings)
    {
        foreach (var f in findings.Where(x => x.Confidence is "observed" or "confirmed"))
        {
            var tags = new List<string> { $"confidence:{f.Confidence}" };
            if (!string.IsNullOrEmpty(f.RelatedProbe))
                tags.Add($"related:{f.RelatedProbe}");

            _ctx.AddManualChainFinding(new ChainableFinding
            {
                Id = $"costly-{Math.Abs($"{f.CheckId}|{f.Endpoint}".GetHashCode(StringComparison.Ordinal))}",
                Source = "scan",
                Category = f.Category,
                Severity = f.Severity,
                Title = f.Title,
                Endpoint = f.Endpoint,
                Method = f.Method,
                Parameter = f.Parameter,
                Detail = f.Detail,
                Evidence = f.Evidence,
                Remediation = f.Remediation,
                Tags = tags
            });
        }
    }
}
