using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;
using Trowser.Security.ChainEngine;

// ReSharper disable MemberCanBePrivate.Global

namespace Trowser.Security;

/// <summary>
/// Orchestrates attack-surface mapping followed by targeted scanner execution.
/// Runs attack-surface analysis, then selects and invokes relevant scanners
/// (SQLi, IDOR, CSRF, path-traversal, mass-assignment) against discovered endpoints.
/// </summary>
public class AutoScanPipeline
{
    public sealed class AutoScanOptions
    {
        public string? Host { get; set; }

        /// <summary>When true (default), ignore third-party hosts (CDN, widgets) relative to scope host.</summary>
        public bool ExcludeThirdParty { get; set; } = true;

        /// <summary>When set, only scan endpoints matching this URL (and optional <see cref="TargetMethod"/>).</summary>
        public string? TargetUrl { get; set; }

        /// <summary>HTTP method filter used with <see cref="TargetUrl"/>.</summary>
        public string? TargetMethod { get; set; }

        public int MaxEndpointsPerScanner { get; set; } = 5;
        public int TimeoutMs { get; set; } = 15000;
        public bool IncludeSqli { get; set; } = true;
        public bool IncludeIdor { get; set; } = true;
        public bool IncludeCsrf { get; set; } = true;
        public bool IncludePathTraversal { get; set; } = true;
        public bool IncludeMassAssignment { get; set; } = true;
        public bool IncludeSsrf { get; set; } = true;
        public bool IncludeOpenRedirect { get; set; } = true;
        public bool IncludeCacheDeception { get; set; } = true;
        /// <summary>Run cache-map indication (identify + busted key mapping). Default true. Pollution/poison stay out of auto-scan.</summary>
        public bool IncludeCacheMap { get; set; } = true;
        public bool IncludeSsti { get; set; } = true;
        /// <summary>Run CSTI (client-side template) scan. null = auto when JS template framework detected.</summary>
        public bool? IncludeCsti { get; set; }

        /// <summary>Run reflected XSS scan on injectable query/body parameters. Default true.</summary>
        public bool IncludeXss { get; set; } = true;

        /// <summary>Run DOM XSS probes via browser navigation (url-query/hash). Default true.</summary>
        public bool IncludeXssDom { get; set; } = true;

        /// <summary>POST comment/message fields then read back for stored XSS. Default true when ConfirmBackend.</summary>
        public bool IncludeXssStored { get; set; } = true;
        /// <summary>Run parser-probe when true, or when null and ConfirmBackend with JSON endpoints (see RunAsync).</summary>
        public bool? IncludeParserProbe { get; set; }

        /// <summary>When true, auto-scan runs active probes (always required at API layer).</summary>
        public bool ConfirmBackend { get; set; }

        /// <summary>Run deserialization-scan on JSON sinks + fixed paths. Default true when ConfirmBackend.</summary>
        public bool IncludeDeserializationScan { get; set; } = true;

        /// <summary>Run file-upload-scan (validation + optional XXE). Default true when ConfirmBackend.</summary>
        public bool IncludeFileUploadScan { get; set; } = true;

        /// <summary>Run Next.js RSC scan when Next.js detected. null = auto.</summary>
        public bool? IncludeNextJsRscScan { get; set; }

        /// <summary>Run cmd-canary (error-based shell/SSTI indicators) on injectable params. Default true.</summary>
        public bool IncludeCmdCanary { get; set; } = true;

        /// <summary>Run NoSQL operator injection scan on login/search endpoints. Default true.</summary>
        public bool IncludeNosql { get; set; } = true;

        /// <summary>Run LDAP filter injection scan on login endpoints. Default true.</summary>
        public bool IncludeLdap { get; set; } = true;

        /// <summary>Fast GET polyglot SSTI probe (${7*7}{{7*7}} etc.). Default true.</summary>
        public bool IncludeSstiPolyglot { get; set; } = true;

        /// <summary>POST profile field then GET readback for stored SSTI. Default true.</summary>
        public bool IncludeSstiStored { get; set; } = true;

        /// <summary>Server-side prototype pollution POST+GET verification. Default true.</summary>
        public bool IncludePrototypePollution { get; set; } = true;

        /// <summary>Run SQLi login bypass sweep on common login paths. Default true.</summary>
        public bool IncludeSqliLoginSweep { get; set; } = true;

        /// <summary>When attack-surface endpoint count is below this, also probe ALWAYS_PROBED injection templates.</summary>
        public int SparseInjectionThreshold { get; set; } = InjectionScaffold.DefaultSparseThreshold;

        /// <summary>
        /// When false, scanners stay on the discovered surface and do not add generic paths
        /// such as <c>/rest/products/search</c>. Swaggering turns this off.
        /// </summary>
        public bool AllowGenericScaffold { get; set; } = true;

        /// <summary>Route injection scanners by parameter semantics and use tiered/funnel probes (default on).</summary>
        public bool UseSmartInjectionRouting { get; set; } = true;

        internal InjectionScanPlan? InjectionPlan { get; set; }
        internal SstiEscalationTracker? SstiEscalation { get; set; }
        internal bool UnifiedScaffoldRan { get; set; }

        /// <summary>
        /// Scan breadth: <c>quick</c> (fewer probes, tight polyglot cap),
        /// <c>standard</c> (default — balanced),
        /// <c>thorough</c> (full polyglot scaffold + higher per-scanner caps).
        /// Aliases: fast/light, normal/balanced, deep/full.
        /// </summary>
        public string ScanDepth { get; set; } = AutoScanDepthProfile.Standard;

        /// <summary>Payload corpus breadth: built-in catalogs (default) or extended corpora subsets.</summary>
        public PayloadProfile PayloadProfile { get; set; } = PayloadProfile.Small;

        /// <summary>Resolved limits from <see cref="ScanDepth"/>; set at pipeline start.</summary>
        internal AutoScanDepthProfile.Resolved? DepthProfile { get; set; }

        /// <summary>
        /// When true (default), quick/standard depth disables slow niche scanners unless overridden via REST
        /// or <see cref="RunAutoScanWithOptions"/> with explicit flags and this set to false.
        /// </summary>
        public bool ApplyDepthScannerPresets { get; set; } = true;
        /// <summary>Merge OpenAPI/JS bundle hints into attack surface before scanning (default on).</summary>
        public bool IncludeApiEnrichment { get; set; } = true;
        public string? MinPriority { get; set; }
        public List<CustomProbe>? CustomProbes { get; set; }

        /// <summary>Also probes PUT/PATCH/DELETE for IDOR (destructive). Default false.</summary>
        public bool IncludeIdorMutatingProbes { get; set; }

        /// <summary>IDOR probes use only GET/HEAD/OPTIONS.</summary>
        public bool IdorReadOnlyProbes { get; set; }

        /// <summary>Probe GET forms and network traffic for POST application/json CSRF variants.</summary>
        public bool IncludeJsonApiProbing { get; set; } = true;

        /// <summary>Cross-reference CSRF results with secrets harvest and XSS after CSRF scan.</summary>
        public bool IncludeCsrfCorrelations { get; set; } = true;

        /// <summary>Run chain-analyze after scanners complete and attach results to the response.</summary>
        public bool IncludeChainAnalysis { get; set; }

        /// <summary>Minimum chained severity when <see cref="IncludeChainAnalysis"/> is true.</summary>
        public string? MinChainedSeverity { get; set; }

        /// <summary>Include partial chains with suggested next steps (default true).</summary>
        public bool IncludePartialChains { get; set; } = true;

        /// <summary>Merge findings into chain feed: append (default) or replace prior auto-scan findings.</summary>
        public string FindingsMode { get; set; } = "append";

        /// <summary>Merge findings with same scanner/endpoint/title (default true).</summary>
        public bool SummarizeFindings { get; set; } = true;

        /// <summary>JWT alg:none + missing-auth sweep on authenticated attack-surface endpoints.</summary>
        public bool IncludeJwtAcceptanceSweep { get; set; }

        /// <summary>Probe common REST scaffold paths for unauthenticated leaks.</summary>
        public bool IncludeRestScaffold { get; set; }

        /// <summary>
        /// When false, sparse-surface auto REST scaffold is disabled (playbooks that call DisableAllScanners).
        /// </summary>
        public bool AllowAutoRestScaffoldOnSparseSurface { get; set; } = true;

        /// <summary>Run REST scaffold automatically when network log has fewer than this many API endpoints.</summary>
        public int RestScaffoldSparseThreshold { get; set; } = 3;

        /// <summary>Path-filter bypass (NUL/double-encoding) on static file bases.</summary>
        public bool IncludePathFilterBypass { get; set; }

        /// <summary>Retest endpoints with captured token after weak-auth/SQLi signals.</summary>
        public bool IncludeAuthBypassPivot { get; set; }

        /// <summary>
        /// Pre-discovered attack surface from a prior step. When set, the pipeline skips
        /// its own network-log discovery and uses these endpoints directly.
        /// </summary>
        public AttackSurfaceResult? PreDiscoveredSurface { get; set; }

        /// <summary>Re-fetch resource after mass-assignment inject to verify persistence.</summary>
        public bool MassAssignmentVerifyPersistence { get; set; }

        /// <summary>PATCH/PUT self-promote mass-assignment probe on /api/me-style endpoints.</summary>
        public bool IncludeMassAssignmentPatch { get; set; }

        /// <summary>Registration scaffold mass-assignment (creates accounts — destructive-low).</summary>
        public bool IncludeMassAssignmentRegister { get; set; }

        /// <summary>POST/PUT admin-shape endpoints with current session (BFLA).</summary>
        public bool IncludeBflaAdminProbe { get; set; } = true;

        /// <summary>Shared playbook budget — when exhausted, remaining scanners are skipped.</summary>
        public Orchestration.BudgetTracker? Budget { get; set; }

        /// <summary>
        /// Max wall-clock seconds for this pipeline run (reserves capacity for later playbook steps).
        /// When 0, <see cref="AutoScanDepthProfile"/> applies a depth-based default so standalone
        /// auto-scan never leaves the API gate busy indefinitely.
        /// </summary>
        public int MaxStepSeconds { get; set; }

        /// <summary>
        /// Passive recall over captured network responses (SQL error signatures / stored XSS).
        /// Disabled by <see cref="DisableAllScanners"/> so focused playbook steps do not mis-label
        /// unrelated passive hits as the step's category (e.g. sqli-login-bypass).
        /// </summary>
        public bool IncludePassiveNetworkRecall { get; set; } = true;

        /// <summary>Disable every optional scanner (playbooks enable only what they need).</summary>
        public void DisableAllScanners()
        {
            IncludeSqli = false;
            IncludeIdor = false;
            IncludeCsrf = false;
            IncludePathTraversal = false;
            IncludeMassAssignment = false;
            IncludeSsrf = false;
            IncludeOpenRedirect = false;
            IncludeCacheDeception = false;
            IncludeCacheMap = false;
            IncludeSsti = false;
            IncludeCsti = false;
            IncludeXss = false;
            IncludeXssDom = false;
            IncludeXssStored = false;
            IncludeParserProbe = false;
            IncludeDeserializationScan = false;
            IncludeFileUploadScan = false;
            IncludeNextJsRscScan = false;
            IncludeCmdCanary = false;
            IncludeNosql = false;
            IncludeLdap = false;
            IncludeSstiPolyglot = false;
            IncludeSstiStored = false;
            IncludePrototypePollution = false;
            IncludeSqliLoginSweep = false;
            IncludeApiEnrichment = false;
            IncludeIdorMutatingProbes = false;
            IncludeJsonApiProbing = false;
            IncludeCsrfCorrelations = false;
            IncludeChainAnalysis = false;
            IncludeJwtAcceptanceSweep = false;
            IncludeRestScaffold = false;
            AllowAutoRestScaffoldOnSparseSurface = false;
            IncludePathFilterBypass = false;
            IncludeAuthBypassPivot = false;
            MassAssignmentVerifyPersistence = false;
            IncludeMassAssignmentPatch = false;
            IncludeMassAssignmentRegister = false;
            IncludeBflaAdminProbe = false;
            IncludePassiveNetworkRecall = false;
        }
    }

    /// <summary>
    /// User-defined probe for domain-specific vulnerability checks that generic scanners
    /// can't detect (CAPTCHA bypass, JWT algorithm confusion, null byte traversal, etc.).
    /// Each probe fires a request and checks the response against expected/unexpected conditions.
    /// </summary>
    public sealed class CustomProbe
    {
        public string Name { get; set; } = "";
        public string Url { get; set; } = "";
        public string Method { get; set; } = "GET";
        public Dictionary<string, string>? Headers { get; set; }
        public string? Body { get; set; }
        public string Severity { get; set; } = "medium";

        /// <summary>Expected HTTP status; mismatch is a finding.</summary>
        public int? ExpectStatus { get; set; }
        /// <summary>If the response body contains this string, it's a finding (vulnerability confirmed).</summary>
        public string? FailIfBodyContains { get; set; }
        /// <summary>If the response body does NOT contain this string, it's a finding.</summary>
        public string? FailIfBodyMissing { get; set; }
        /// <summary>If response status is in this range, it's a finding (e.g. "200-299" means access was granted).</summary>
        public string? FailIfStatusRange { get; set; }
    }

    public sealed class AutoScanFinding
    {
        public string Scanner { get; set; } = "";
        public string Severity { get; set; } = "info";
        public string Endpoint { get; set; } = "";
        public string Method { get; set; } = "";
        public string Title { get; set; } = "";
        public string Detail { get; set; } = "";

        /// <summary>Alias for <see cref="Endpoint"/> — consistent with shadow/chain finding shape.</summary>
        public string Url
        {
            get => Endpoint;
            set => Endpoint = value;
        }

        /// <summary>Alias for <see cref="Detail"/> — consistent with shadow/chain finding shape.</summary>
        public string Description
        {
            get => Detail;
            set => Detail = value;
        }

        /// <summary>Optional compact rationale for findings (noise-stripped hashes, short excerpt diffs).</summary>
        public string? Evidence { get; set; }

        /// <summary>When &gt; 1, identical findings were merged by auto-scan deduplication.</summary>
        public int Occurrences { get; set; } = 1;

        /// <summary>Suggested follow-ups (verify-workflow stubs, retest hints) for LLM/script consumers.</summary>
        public List<string> NextActions { get; set; } = [];
    }

    public sealed class SkippedEndpointInfo
    {
        public string Endpoint { get; set; } = "";
        public string Scanner { get; set; } = "";
        public string Reason { get; set; } = "";
    }

    public sealed class AutoScanResult
    {
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public int EndpointsDiscovered { get; set; }
        public int InjectableEndpointsDiscovered { get; set; }
        public int EndpointsScanned { get; set; }
        public List<string> ScannersRun { get; set; } = [];
        public List<string> ScannersSkipped { get; set; } = [];
        public List<AutoScanFinding> Findings { get; set; } = [];
        /// <summary>Lower-severity / arbitrated duplicates kept out of the primary findings list.</summary>
        public List<AutoScanFinding> SuppressedFindings { get; set; } = [];
        public List<SkippedEndpointInfo> SkippedEndpoints { get; set; } = [];
        public int ElapsedMs { get; set; }
        public string ScanDepth { get; set; } = AutoScanDepthProfile.Standard;
        public AttackSurfaceSummary? AttackSurfaceSummary { get; set; }
        public List<string> Errors { get; set; } = [];
        public List<SecurityFindingCorrelator.CorrelationFinding> Correlations { get; set; } = [];
        public ChainAnalysisResult? ChainAnalysis { get; set; }
        /// <summary>True when the scan stopped early because playbook or step time budget was exhausted.</summary>
        public bool BudgetExhausted { get; set; }

        /// <summary>
        /// True when results are incomplete (budget cancel, mid-scanner stop). Findings already
        /// collected are still present — never silently omitted.
        /// </summary>
        public bool Partial { get; set; }

        /// <summary>Human/agent notes (sparse scaffold, budget hints, etc.).</summary>
        public List<string> AgentNotes { get; set; } = [];

        /// <summary>True when generic LFI path scaffold ran because injectable surface was sparse.</summary>
        public bool SparseInjectionScaffold { get; set; }

        public bool IsClean => Findings.Count == 0;
        public int FindingsCount => Findings.Count;

        public List<AutoScanFinding> GetByMinSeverity(string minSeverity)
        {
            var minRank = SeverityRank(minSeverity);
            return Findings.Where(f => SeverityRank(f.Severity) >= minRank).ToList();
        }

        private static int SeverityRank(string s) => s switch
        {
            "critical" => 4, "high" => 3, "medium" => 2, "low" => 1, _ => 0
        };

        public string Format(bool includeDetails = true)
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== Auto-Scan Results ===");
            sb.AppendLine($"Time: {Timestamp:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine($"Scan depth: {ScanDepth}");
            sb.AppendLine($"Endpoints discovered: {EndpointsDiscovered}");
            sb.AppendLine($"Injectable endpoints: {InjectableEndpointsDiscovered}");
            sb.AppendLine($"Endpoints scanned: {EndpointsScanned}");
            sb.AppendLine($"Scanners run: {(ScannersRun.Count > 0 ? string.Join(", ", ScannersRun) : "(none)")}");
            if (ScannersSkipped.Count > 0)
                sb.AppendLine($"Scanners skipped: {string.Join(", ", ScannersSkipped)}");
            sb.AppendLine($"Findings: {Findings.Count}");
            sb.AppendLine($"Elapsed: {ElapsedMs}ms");

            if (Errors.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("--- Errors ---");
                foreach (var err in Errors)
                    sb.AppendLine($"  ! {err}");
            }

            if (includeDetails && Findings.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine(new string('─', 80));

                foreach (var f in Findings)
                {
                    sb.AppendLine();
                    sb.AppendLine($"[{f.Severity.ToUpper()}] [{f.Scanner}] {f.Title}");
                    sb.AppendLine($"  Endpoint: {f.Endpoint}");
                    if (!string.IsNullOrEmpty(f.Method))
                        sb.AppendLine($"  Method: {f.Method}");
                    if (!string.IsNullOrEmpty(f.Evidence))
                        sb.AppendLine($"  Evidence: {f.Evidence}");
                    if (!string.IsNullOrEmpty(f.Detail))
                        sb.AppendLine($"  Detail: {f.Detail}");
                }
            }
            else if (Findings.Count == 0)
            {
                sb.AppendLine();
                sb.AppendLine("No findings — all scanned endpoints clean.");
            }

            if (includeDetails && Correlations.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("--- Cross-Tool Correlations ---");
                foreach (var c in Correlations)
                {
                    sb.AppendLine();
                    sb.AppendLine($"[{c.Severity.ToUpper()}] {c.Title}");
                    sb.AppendLine($"  {c.Description}");
                    if (c.FieldName != null)
                        sb.AppendLine($"  Field: {c.FieldName}");
                    if (c.RelatedTools.Length > 0)
                        sb.AppendLine($"  Tools: {string.Join(", ", c.RelatedTools)}");
                }
            }

            return sb.ToString().TrimEnd();
        }
    }

    private static readonly HashSet<string> NoisePaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "socket.io", "sockjs-node", "sockjs", "ws", "websocket",
        "hot-update", "webpack-hmr", "__webpack_hmr",
        "browser-sync", "livereload", "_blazor"
    };

    /// <summary>Last segment names we skip when inferring <c>/api/&#123;resource&#125;/&#123;id&#125;</c> IDOR templates from collection URLs.</summary>
    private static readonly HashSet<string> IdorInferBlockedResources = new(StringComparer.OrdinalIgnoreCase)
    {
        "health", "healthz", "status", "metrics", "graphql", "docs", "swagger", "openapi",
        "static", "assets", "favicon", "robots", "sitemap", "version", "ping", "ready", "live",
        "debug", "trace"
    };

    private static bool IsNoiseEndpoint(AttackSurfaceEndpoint ep)
    {
        var path = ep.UrlTemplate.ToLowerInvariant();
        if (NoisePaths.Any(n => path.Contains(n)))
            return true;
        if (path.Contains("/socket.io/"))
            return true;
        if (ep.Url.Contains("transport=polling", StringComparison.OrdinalIgnoreCase) ||
            ep.Url.Contains("transport=websocket", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    private static int PriorityRank(string priority) => priority switch
    {
        "critical" => 4, "high" => 3, "medium" => 2, "low" => 1, "info" => 0, _ => 0
    };

    public static async Task<AutoScanResult> RunAsync(
        AutomationContext ctx,
        AutoScanOptions options,
        CancellationToken ct = default,
        ChainPatternCatalog? chainCatalog = null)
    {
        var sw = Stopwatch.StartNew();
        var stepSw = Stopwatch.StartNew();
        var scanBudgetStopped = false;
        var result = new AutoScanResult();
        options.DepthProfile = AutoScanDepthProfile.Resolve(options);
        AutoScanDepthProfile.ApplyScriptPresets(options);
        result.ScanDepth = options.DepthProfile.Name;

        // Fail closed: depth profile supplies a hard wall-clock budget when the caller omitted one.
        if (options.MaxStepSeconds <= 0 && options.DepthProfile.DefaultMaxStepSeconds > 0)
            options.MaxStepSeconds = options.DepthProfile.DefaultMaxStepSeconds;

        // Client-side audits and follow-up API calls expect the SPA document the operator
        // was viewing — probes (CSTI/SSTI/DOM) may navigate away; restore best-effort.
        var baselineUrl = await ctx.GetCurrentUrl();
        await SecurityScanHygiene.PrepareActiveScanAsync(ctx);

        // Enforce MaxStepSeconds / playbook budget inside long scanners (not only between them).
        var timeoutSeconds = 0;
        if (options.MaxStepSeconds > 0)
            timeoutSeconds = options.MaxStepSeconds;
        if (options.Budget != null && options.Budget.RemainingSeconds > 0)
        {
            timeoutSeconds = timeoutSeconds > 0
                ? Math.Min(timeoutSeconds, options.Budget.RemainingSeconds)
                : options.Budget.RemainingSeconds;
        }

        CancellationTokenSource? timeoutCts = null;
        var effectiveCt = ct;
        if (timeoutSeconds > 0)
        {
            timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            // int.MaxValue seconds (Endpoint Probe "unlimited" budget) overflows
            // CancelAfter(TimeSpan) — ArgumentOutOfRangeException parameter 'delay'.
            ScanTimeout.CancelAfterSeconds(timeoutCts, Math.Max(5, timeoutSeconds));
            effectiveCt = timeoutCts.Token;
        }

        try
        {
            return await RunAsyncCore(ctx, options, result, sw, stepSw, scanBudgetStopped, effectiveCt, chainCatalog, baselineUrl);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            result.BudgetExhausted = true;
            result.Partial = true;
            result.ElapsedMs = (int)sw.ElapsedMilliseconds;
            // Dedup/arbitrate first so the error count matches findingsCount (no silent drop).
            if (options.SummarizeFindings)
                result.Findings = AutoScanFindingDedup.Summarize(result.Findings, result.SuppressedFindings);
            else
                result.Findings = AutoScanFindingDedup.ApplyClassArbitration(result.Findings, result.SuppressedFindings);
            result.Errors.Add(
                timeoutSeconds > 0
                    ? $"Scan cancelled after ~{timeoutSeconds}s step/playbook budget — returning partial results ({result.ScannersRun.Count} scanner(s), {result.Findings.Count} finding(s))."
                    : $"Scan cancelled by budget — returning partial results ({result.ScannersRun.Count} scanner(s), {result.Findings.Count} finding(s)).");
            return result;
        }
        finally
        {
            timeoutCts?.Dispose();
            // Bound restore so budget expiry cannot hang waiting on navigation.
            try
            {
                await RestoreBrowserUrlAsync(ctx, baselineUrl)
                    .WaitAsync(TimeSpan.FromSeconds(8));
            }
            catch
            {
                // Best-effort — partial scan results remain valid.
            }
        }
    }

    private static async Task RestoreBrowserUrlAsync(AutomationContext ctx, string? baselineUrl)
    {
        if (string.IsNullOrWhiteSpace(baselineUrl)) return;
        try
        {
            var now = await ctx.GetCurrentUrl();
            if (string.Equals(now, baselineUrl, StringComparison.OrdinalIgnoreCase))
                return;
            await ctx.Navigate(baselineUrl);
            await Task.Delay(300);
        }
        catch
        {
            // Best-effort — scan results remain valid if restore fails.
        }
    }

    private static async Task<AutoScanResult> RunAsyncCore(
        AutomationContext ctx,
        AutoScanOptions options,
        AutoScanResult result,
        Stopwatch sw,
        Stopwatch stepSw,
        bool scanBudgetStopped,
        CancellationToken ct,
        ChainPatternCatalog? chainCatalog,
        string? baselineUrl)
    {
        var entries = ctx.Network.Entries;

        if (string.IsNullOrWhiteSpace(options.Host))
        {
            var navForHost = await ctx.GetCurrentUrl();
            options.Host = SecurityHostScope.ResolveScopeHost(null, navForHost);
        }

        var scopeHost = SecurityHostScope.ResolveScopeHost(options.Host, await ctx.GetCurrentUrl());

        AttackSurfaceResult surface;
        if (options.PreDiscoveredSurface != null)
        {
            surface = options.PreDiscoveredSurface;
        }
        else
        {
            if (entries.Count == 0)
            {
                result.Errors.Add("No network traffic captured. Browse the target application first.");
                result.ElapsedMs = (int)sw.ElapsedMilliseconds;
                return result;
            }

            var preflight = SecurityPreflight.Assess(entries);
            if (preflight.NavigationOnly && preflight.Recommendation != null)
                result.Errors.Add($"Preflight: {preflight.Message} {preflight.Recommendation}");

            var mapper = new AttackSurfaceMapper();
            surface = mapper.Analyze(entries, true, true, true, options.Host);

            if (options.IncludeApiEnrichment)
            {
                try
                {
                    var navUrl = await ctx.GetCurrentUrl();
                    await AttackSurfaceEnrichment.RunAsync(
                        surface,
                        ctx,
                        entries,
                        navUrl,
                        AutoScanDepthProfile.EnrichmentOptions(options.ScanDepth),
                        ct);
                }
                catch (Exception ex)
                {
                    result.Errors.Add($"api-enrichment: {ex.Message}");
                }
            }
        }

        if (options.IncludePassiveNetworkRecall
            && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "passive-network-recall", ct))
        {
            var passiveFindings = PassiveNetworkResponseScanner.Scan(entries, new PassiveNetworkResponseScanner.Options
            {
                HostFilter = options.Host,
                ScopeHost = scopeHost,
                ExcludeThirdParty = options.ExcludeThirdParty
            });
            if (passiveFindings.Count > 0)
            {
                result.Findings.AddRange(passiveFindings);
                result.ScannersRun.Add("passive-network-recall");
            }
        }
        else if (!options.IncludePassiveNetworkRecall)
            result.ScannersSkipped.Add("passive-network-recall");

        if (!string.IsNullOrWhiteSpace(options.TargetUrl))
        {
            surface = Orchestration.PlaybookScopeFilter.Apply(
                surface,
                new Orchestration.PlaybookScope
                {
                    TargetUrl = options.TargetUrl,
                    TargetMethod = options.TargetMethod
                });
            options.MaxEndpointsPerScanner = Math.Min(options.MaxEndpointsPerScanner, 1);
            options.IncludeApiEnrichment = false;
        }

        result.AttackSurfaceSummary = surface.Summary;
        result.EndpointsDiscovered = surface.Endpoints.Count;

        var minRank = PriorityRank(options.MinPriority ?? "low");
        var allEndpoints = surface.Endpoints
            .Where(ep => PriorityRank(ep.TestPriority) >= minRank)
            .OrderByDescending(ep => PriorityRank(ep.TestPriority))
            .ToList();

        foreach (var ep in surface.Endpoints.Where(ep => PriorityRank(ep.TestPriority) < minRank))
        {
            result.SkippedEndpoints.Add(new SkippedEndpointInfo
            {
                Endpoint = AttackSurfaceMapper.FormatDisplayUrl(ep),
                Scanner = "all",
                Reason = $"below minimum priority (endpoint={ep.TestPriority}, min={options.MinPriority})"
            });
        }

        var endpoints = allEndpoints.Where(ep => !IsNoiseEndpoint(ep)).ToList();
        result.InjectableEndpointsDiscovered = CountInjectableEndpoints(endpoints);
        foreach (var ep in allEndpoints.Where(IsNoiseEndpoint))
        {
            result.SkippedEndpoints.Add(new SkippedEndpointInfo
            {
                Endpoint = AttackSurfaceMapper.FormatDisplayUrl(ep),
                Scanner = "all",
                Reason = "websocket/long-polling/HMR endpoint (noise)"
            });
        }

        if (endpoints.Count == 0)
        {
            result.Errors.Add($"No scannable endpoints found (discovered {surface.Endpoints.Count}, " +
                $"all filtered by priority or noise rules).");
            result.ElapsedMs = (int)sw.ElapsedMilliseconds;
            return result;
        }

        if (options.UseSmartInjectionRouting)
        {
            options.InjectionPlan = InjectionPlanBuilder.Build(
                endpoints, Depth(options).EffectiveMaxEndpointsPerScanner);
            options.SstiEscalation = new SstiEscalationTracker();
        }

        if (options.UseSmartInjectionRouting
            && ShouldRunInjectionScaffold(result.InjectableEndpointsDiscovered, options, Depth(options).RunSqliScaffoldWhenSparse)
            && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "unified-scaffold", ct))
        {
            var currentUrl = await ctx.GetCurrentUrl();
            if (!string.IsNullOrEmpty(currentUrl) && Uri.TryCreate(currentUrl, UriKind.Absolute, out var originUri))
            {
                await RunUnifiedScaffoldScan(ctx, originUri.GetLeftPart(UriPartial.Authority), options, result, ct);
                options.UnifiedScaffoldRan = true;
            }
        }

        // Injection-first when the surface has injectable params — avoids CSRF/cache starving SQLi/XSS on short budgets.
        scanBudgetStopped = await RunInjectionPriorityScannersAsync(
            ctx, endpoints, options, result, stepSw, scanBudgetStopped, baselineUrl, ct);

        // Access-control and auth probes next — often skipped when budget expired after slow ancillary scans.
        if (options.IncludeIdor && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "idor", ct))
            await RunIdorScan(ctx, endpoints, options, result, ct);
        else if (!options.IncludeIdor) result.ScannersSkipped.Add("idor");

        if (options.IncludeMassAssignment && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "mass-assignment", ct))
            await RunMassAssignmentScan(ctx, endpoints, options, result, ct);
        else if (!options.IncludeMassAssignment) result.ScannersSkipped.Add("mass-assignment");

        if (options.IncludeMassAssignmentPatch && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "mass-assignment-patch", ct))
            await RunMassAssignmentPatchScan(ctx, options, result, ct);
        else if (!options.IncludeMassAssignmentPatch) result.ScannersSkipped.Add("mass-assignment-patch");

        if (options.IncludeMassAssignmentRegister && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "mass-assignment-register", ct))
            await RunMassAssignmentRegisterScan(ctx, options, result, ct);
        else if (!options.IncludeMassAssignmentRegister) result.ScannersSkipped.Add("mass-assignment-register");

        if (options.IncludeBflaAdminProbe && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "bfla-admin", ct))
            await RunBflaAdminScan(ctx, endpoints, options, result, ct);
        else if (!options.IncludeBflaAdminProbe) result.ScannersSkipped.Add("bfla-admin");

        if (options.IncludeNosql && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "nosql", ct))
            await RunNosqlScan(ctx, options, result, ct);
        else if (!options.IncludeNosql) result.ScannersSkipped.Add("nosql");

        if (options.IncludeLdap && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "ldap", ct))
            await RunLdapScan(ctx, options, result, ct);
        else if (!options.IncludeLdap) result.ScannersSkipped.Add("ldap");

        if (options.IncludeSqliLoginSweep && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "sqli-login-sweep", ct))
            await RunSqliLoginSweepScan(ctx, options, result, ct);
        else if (!options.IncludeSqliLoginSweep) result.ScannersSkipped.Add("sqli-login-sweep");

        if (options.IncludeCsrf && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "csrf", ct))
            await RunCsrfScan(ctx, options, result, ct);
        else if (!options.IncludeCsrf) result.ScannersSkipped.Add("csrf");

        if (options.IncludePathTraversal && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "path-traversal", ct))
            await RunPathTraversalScan(ctx, endpoints, options, result, ct);
        else if (!options.IncludePathTraversal) result.ScannersSkipped.Add("path-traversal");

        if (options.IncludeSsrf && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "ssrf", ct))
            await RunSsrfScan(ctx, endpoints, options, result, ct);
        else if (!options.IncludeSsrf) result.ScannersSkipped.Add("ssrf");

        if (options.IncludeOpenRedirect && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "open-redirect", ct))
            await RunOpenRedirectScan(ctx, endpoints, options, result, ct);
        else if (!options.IncludeOpenRedirect) result.ScannersSkipped.Add("open-redirect");

        if (options.IncludeSsti && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "ssti", ct))
        {
            if (options.IncludeSstiPolyglot)
                await RunSstiPolyglotScan(ctx, options, result, ct);
            await RunSstiScan(ctx, endpoints, options, result, ct);
            if (options.IncludeSstiStored)
                await RunSstiStoredScan(ctx, options, result, ct);
        }
        else
        {
            result.ScannersSkipped.Add("ssti");
            if (options.IncludeSstiPolyglot)
                result.ScannersSkipped.Add("ssti-polyglot (ssti disabled)");
            if (options.IncludeSstiStored)
                result.ScannersSkipped.Add("ssti-stored (ssti disabled)");
        }

        if (options.IncludePrototypePollution && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "prototype-pollution", ct))
            await RunPrototypePollutionScan(ctx, options, result, ct);
        else if (!options.IncludePrototypePollution) result.ScannersSkipped.Add("prototype-pollution");

        if (await ShouldRunCstiAsync(ctx, options)
            && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "csti", ct))
            await RunCstiScan(ctx, options, result, ct);
        else if (options.IncludeCsti == false)
            result.ScannersSkipped.Add("csti");
        else if (!await ShouldRunCstiAsync(ctx, options))
            result.ScannersSkipped.Add("csti (no client framework)");

        if (options.IncludeCacheMap && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "cache-map", ct))
            await RunCacheMapScan(ctx, options, result, ct);
        else if (!options.IncludeCacheMap) result.ScannersSkipped.Add("cache-map");

        if (options.IncludeCacheDeception && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "cache-deception", ct))
            await RunCacheDeceptionScan(ctx, endpoints, options, result, ct);
        else if (!options.IncludeCacheDeception) result.ScannersSkipped.Add("cache-deception");

        if (await ShouldRunParserProbeAsync(ctx, options)
            && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "parser-probe", ct))
            await RunParserProbeScan(ctx, options, result, ct);
        else if (!await ShouldRunParserProbeAsync(ctx, options))
            result.ScannersSkipped.Add("parser-probe");

        if (options.IncludeDeserializationScan && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "deserialization-scan", ct))
            await RunDeserializationScan(ctx, options, result, ct);
        else if (!options.IncludeDeserializationScan) result.ScannersSkipped.Add("deserialization-scan");

        if (options.IncludeFileUploadScan && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "file-upload-scan", ct))
            await RunFileUploadScan(ctx, options, result, ct);
        else if (!options.IncludeFileUploadScan) result.ScannersSkipped.Add("file-upload-scan");

        if (await ShouldRunNextJsRscScanAsync(ctx, options)
            && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "nextjs-rsc-scan", ct))
            await RunNextJsRscScan(ctx, options, result, ct);
        else if (!await ShouldRunNextJsRscScanAsync(ctx, options))
            result.ScannersSkipped.Add("nextjs-rsc-scan");

        if ((options.IncludeRestScaffold
             || (options.AllowAutoRestScaffoldOnSparseSurface && endpoints.Count < options.RestScaffoldSparseThreshold))
            && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "rest-scaffold", ct))
            await RunRestScaffoldScan(ctx, options, result, ct);
        else if (!options.IncludeRestScaffold
                 && (!options.AllowAutoRestScaffoldOnSparseSurface || endpoints.Count >= options.RestScaffoldSparseThreshold))
            result.ScannersSkipped.Add("rest-scaffold");

        if (options.IncludeJwtAcceptanceSweep && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "jwt-acceptance-sweep", ct))
            await RunJwtAcceptanceSweep(ctx, options, result, ct);
        else if (!options.IncludeJwtAcceptanceSweep) result.ScannersSkipped.Add("jwt-acceptance-sweep");

        if (options.IncludePathFilterBypass && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "path-filter-bypass", ct))
            await RunPathFilterBypassScan(ctx, options, result, ct);
        else if (!options.IncludePathFilterBypass) result.ScannersSkipped.Add("path-filter-bypass");

        if (options.IncludeAuthBypassPivot && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "auth-bypass-pivot", ct))
            await RunAuthBypassPivotScan(ctx, options, result, ct);
        else if (!options.IncludeAuthBypassPivot) result.ScannersSkipped.Add("auth-bypass-pivot");

        if (options.CustomProbes is { Count: > 0 }
            && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "custom-probes", ct))
            await RunCustomProbes(ctx, options.CustomProbes, options, result, ct);

        result.Findings = result.Findings
            .OrderByDescending(f => SeverityRank(f.Severity))
            .ThenBy(f => f.Endpoint)
            .ToList();

        if (options.SummarizeFindings)
            result.Findings = AutoScanFindingDedup.Summarize(result.Findings, result.SuppressedFindings);
        else
            result.Findings = AutoScanFindingDedup.ApplyClassArbitration(result.Findings, result.SuppressedFindings);

        if (options.FindingsMode.Equals("replace", StringComparison.OrdinalIgnoreCase))
            ctx.SetAutoScanFindingsForChain(result.Findings);
        else
            ctx.AppendAutoScanFindingsForChain(result.Findings);

        if (options.IncludeChainAnalysis)
        {
            if (chainCatalog == null)
            {
                result.Errors.Add("chain-analysis: pattern catalog not available");
            }
            else
            {
                try
                {
                    var chainFindings = ChainAnalysisService.CollectFindings(ctx);
                    result.ChainAnalysis = ChainAnalysisService.Analyze(
                        chainCatalog,
                        chainFindings,
                        new ChainAnalysisService.AnalyzeOptions(
                            options.MinChainedSeverity,
                            options.IncludePartialChains));
                }
                catch (Exception ex)
                {
                    result.Errors.Add($"chain-analysis: {ex.Message}");
                }
            }
        }

        await SecurityScanHygiene.TryClearBlockingDialogAsync(ctx);

        result.ElapsedMs = (int)sw.ElapsedMilliseconds;
        return result;
    }

    /// <summary>SQLi/XSS/cmd-canary before CSRF/cache so short auto-scan budgets still hit injection labs.</summary>
    private static async Task<bool> RunInjectionPriorityScannersAsync(
        AutomationContext ctx,
        List<AttackSurfaceEndpoint> endpoints,
        AutoScanOptions options,
        AutoScanResult result,
        Stopwatch stepSw,
        bool scanBudgetStopped,
        string? baselineUrl,
        CancellationToken ct)
    {
        if (options.IncludeCmdCanary && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "cmd-canary", ct))
            await RunCmdCanaryScan(ctx, endpoints, options, result, ct);
        else if (!options.IncludeCmdCanary) result.ScannersSkipped.Add("cmd-canary");

        if (options.IncludeSqli && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "sqli", ct))
            await RunSqliScan(ctx, endpoints, options, result, ct);
        else if (!options.IncludeSqli) result.ScannersSkipped.Add("sqli");

        if (options.IncludeXss && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "xss", ct))
            await RunXssScan(ctx, endpoints, options, result, ct);
        else if (!options.IncludeXss) result.ScannersSkipped.Add("xss");

        if (options.IncludeXssDom && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "xss-dom", ct))
        {
            await RestoreBrowserUrlAsync(ctx, baselineUrl);
            await RunXssDomScan(ctx, options, result, ct);
        }
        else if (!options.IncludeXssDom) result.ScannersSkipped.Add("xss-dom");

        if (options.IncludeXssStored && options.ConfirmBackend
            && TryContinueScan(options, result, stepSw, ref scanBudgetStopped, "xss-stored", ct))
            await RunXssStoredScan(ctx, options, result, ct);
        else if (!options.IncludeXssStored)
            result.ScannersSkipped.Add("xss-stored");
        else
            result.ScannersSkipped.Add("xss-stored (requires active mode)");

        return scanBudgetStopped;
    }

    private static int SeverityRank(string s) => s switch
    {
        "critical" => 4, "high" => 3, "medium" => 2, "low" => 1, "info" => 0, _ => 0
    };

    private static bool TryContinueScan(
        AutoScanOptions options,
        AutoScanResult result,
        Stopwatch stepSw,
        ref bool stopped,
        string scanner,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (stopped)
        {
            result.ScannersSkipped.Add($"{scanner} (budget)");
            return false;
        }

        if (IsScanBudgetExhausted(options, result, stepSw))
        {
            stopped = true;
            result.ScannersSkipped.Add($"{scanner} (budget)");
            return false;
        }

        return true;
    }

    private static bool IsScanBudgetExhausted(AutoScanOptions options, AutoScanResult result, Stopwatch stepSw)
    {
        if (options.MaxStepSeconds > 0 && stepSw.Elapsed.TotalSeconds >= options.MaxStepSeconds)
        {
            if (options.Budget?.Adaptive == true &&
                options.Budget.TryExtendForProgress(
                    "Auto-scan step time",
                    result.ScannersRun.Count + result.EndpointsScanned))
            {
                return false;
            }

            if (!result.BudgetExhausted)
            {
                result.BudgetExhausted = true;
                result.Partial = true;
                result.Errors.Add(
                    $"Step time budget ({options.MaxStepSeconds}s) exhausted — remaining scanners skipped.");
            }
            return true;
        }

        if (options.Budget?.IsExhausted == true)
        {
            if (options.Budget.Adaptive &&
                options.Budget.TryExtendForProgress(
                    "Auto-scan progressing",
                    result.ScannersRun.Count + result.EndpointsScanned))
            {
                return false;
            }

            if (!result.BudgetExhausted)
            {
                result.BudgetExhausted = true;
                result.Partial = true;
                result.Errors.Add("Playbook budget exhausted — remaining scanners skipped.");
            }
            return true;
        }

        return false;
    }

    private static async Task RunCsrfScan(
        AutomationContext ctx, AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        try
        {
            ct.ThrowIfCancellationRequested();
            var csrfResult = await ctx.RunCsrfTest(
                maxEndpoints: 10,
                maxUnprotected: 20,
                includeGet: false,
                includeJsonApiProbing: options.IncludeJsonApiProbing);
            result.ScannersRun.Add("csrf");

            if (options.IncludeCsrfCorrelations)
            {
                var correlations = await SecurityFindingCorrelator.CorrelateForCsrfScanAsync(ctx, csrfResult);
                result.Correlations.AddRange(correlations);
                foreach (var c in correlations)
                {
                    result.Findings.Add(new AutoScanFinding
                    {
                        Scanner = "correlation",
                        Severity = c.Severity,
                        Endpoint = c.Url ?? "",
                        Title = c.Title,
                        Detail = c.Description,
                        Evidence = string.Join(", ", c.RelatedTools),
                    });
                }
            }

            var seenFindings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var s in csrfResult.Scenarios.Where(s => s.Vulnerable))
            {
                if (IsNoiseCsrfUrl(s.Url))
                {
                    result.SkippedEndpoints.Add(new SkippedEndpointInfo
                    {
                        Endpoint = s.Url, Scanner = "csrf",
                        Reason = "websocket/long-polling endpoint (not a meaningful CSRF vector)"
                    });
                    continue;
                }

                var dedupKey = $"{s.Method}|{s.Path}|{s.TestType}";
                if (!seenFindings.Add(dedupKey))
                    continue;

                // Passive "no CSRF token" on JSON/API traffic is often cookie+SameSite or Bearer auth —
                // not a confirmed CSRF exploit. Keep confirmed json-api probe failures louder.
                var severity = ResolveCsrfAutoScanSeverity(s.TestType, s.Severity);
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "csrf",
                    Severity = severity,
                    Endpoint = s.Url,
                    Method = s.Method,
                    Title = $"CSRF: {s.TestType}",
                    Detail = s.Description
                });
            }
            result.EndpointsScanned += csrfResult.EndpointsTested + csrfResult.JsonApiProbesRun;
        }
        catch (Exception ex)
        {
            result.Errors.Add($"csrf: {ex.Message}");
            result.ScannersSkipped.Add("csrf (error)");
        }
    }

    private static string ResolveCsrfAutoScanSeverity(string testType, string? scenarioSeverity)
    {
        if (!string.IsNullOrEmpty(scenarioSeverity))
            return scenarioSeverity;

        if (testType.StartsWith("json-api", StringComparison.OrdinalIgnoreCase))
            return "high"; // active probe confirmed missing-token acceptance

        if (testType.Equals("no-csrf-token", StringComparison.OrdinalIgnoreCase)
            || testType.Equals("get-request-no-csrf-token", StringComparison.OrdinalIgnoreCase)
            || testType.StartsWith("get-form", StringComparison.OrdinalIgnoreCase)
            || testType.StartsWith("get-", StringComparison.OrdinalIgnoreCase))
            return "info"; // GET CSRF is informational; dedicated CSRF scanner aligns

        return "medium";
    }

    private static bool IsNoiseCsrfUrl(string url)
    {
        var lower = url.ToLowerInvariant();
        return lower.Contains("socket.io") ||
               lower.Contains("sockjs") ||
               lower.Contains("transport=polling") ||
               lower.Contains("transport=websocket") ||
               lower.Contains("hot-update") ||
               lower.Contains("webpack-hmr") ||
               lower.Contains("__webpack_hmr") ||
               lower.Contains("browser-sync") ||
               lower.Contains("livereload") ||
               lower.Contains("_blazor");
    }

    private static async Task RunPathTraversalScan(
        AutomationContext ctx, List<AttackSurfaceEndpoint> endpoints,
        AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        var candidates = endpoints
            .Where(ep => ep.Parameters.Query.Count > 0 || ep.Parameters.Path.Count > 0)
            .Take(MaxEp(options))
            .ToList();

        foreach (var ep in endpoints.Where(ep => ep.Parameters.Query.Count == 0 && ep.Parameters.Path.Count == 0))
        {
            result.SkippedEndpoints.Add(new SkippedEndpointInfo
            {
                Endpoint = AttackSurfaceMapper.FormatDisplayUrl(ep), Scanner = "path-traversal",
                Reason = "no query or path parameters"
            });
        }

        var trafficUrls = new List<string>();
        foreach (var ep in candidates)
        {
            var url = ep.Url;
            if (string.IsNullOrWhiteSpace(url)) continue;
            // Ensure at least one path-like query param exists for PathTraversalChecker discovery.
            if (!url.Contains('?', StringComparison.Ordinal)
                && ep.Parameters.Query.Count > 0)
            {
                var p = ep.Parameters.Query.FirstOrDefault(pn => PathTraversalParamNames.IsPathLikeParamName(pn))
                         ?? ep.Parameters.Query.First();
                url = url.TrimEnd('/') + $"?{Uri.EscapeDataString(p)}=readme.md";
            }
            trafficUrls.Add(url);
        }

        var scaffoldUrls = new List<string>();
        var injectableCount = candidates.Count;
        var sparseScaffold = options.AllowGenericScaffold
                             && injectableCount < options.SparseInjectionThreshold;
        if (sparseScaffold)
        {
            try
            {
                var origin = await ResolveOriginAsync(ctx);
                if (!string.IsNullOrEmpty(origin))
                {
                    foreach (var path in PathTraversalChecker.AlwaysProbedLfiPaths)
                        scaffoldUrls.Add(origin.TrimEnd('/') + path);
                    result.SparseInjectionScaffold = true;
                    result.AgentNotes.Add(
                        $"Sparse injectable surface ({injectableCount} endpoint(s) < threshold {options.SparseInjectionThreshold}) — " +
                        "probed generic LFI paths (AlwaysProbedLfiPaths). Disable with allowGenericScaffold:false or browse more API traffic.");
                }
            }
            catch
            {
                // Best-effort scaffold only.
            }
        }

        trafficUrls = trafficUrls
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(Math.Max(MaxEp(options) * 2, 8))
            .ToList();
        scaffoldUrls = scaffoldUrls
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(Math.Max(MaxEp(options), 4))
            .ToList();

        if (trafficUrls.Count == 0 && scaffoldUrls.Count == 0)
        {
            result.ScannersSkipped.Add("path-traversal (no query/path params)");
            return;
        }

        try
        {
            var ptOptions = new PathTraversalOptions
            {
                Mode = "query",
                ExplicitUrls = trafficUrls.Count > 0 ? trafficUrls : null,
                ScaffoldUrls = scaffoldUrls.Count > 0 ? scaffoldUrls : null,
                MaxCandidates = Math.Max(trafficUrls.Count, 1) + (scaffoldUrls.Count > 0 ? Math.Min(4, scaffoldUrls.Count) : 0),
                TimeoutMs = options.TimeoutMs
            };

            var ptResult = await ctx.RunPathTraversalScan(ptOptions);
            result.ScannersRun.Add("path-traversal");
            result.EndpointsScanned += ptResult.CandidatesProbed;

            foreach (var f in ptResult.Findings)
            {
                if (!PathTraversalChecker.ShouldPromoteToAutoScanFinding(f))
                    continue;

                var promo = PathTraversalChecker.ResolveAutoScanPromotion(f);
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "path-traversal",
                    Severity = promo.Severity,
                    Endpoint = f.Url,
                    Method = f.Method,
                    Title = $"{promo.TitlePrefix}Path traversal / LFI: {f.Payload}",
                    Detail = $"Parameter '{f.ParamName}' — indicator: {f.Indicator}. Snippet: {f.Snippet}",
                    Evidence = f.Snippet
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"path-traversal: {ex.Message}");
            result.ScannersSkipped.Add("path-traversal (error)");
        }
    }

    private static async Task<string?> ResolveOriginAsync(AutomationContext ctx)
    {
        var current = await ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(current) || !Uri.TryCreate(current, UriKind.Absolute, out var uri))
            return null;
        return uri.GetLeftPart(UriPartial.Authority);
    }

    private static readonly HashSet<string> SsrfParamHints = UrlLikeParamNames.DefaultSet;

    private static bool HasUrlLikeParam(IEnumerable<string> paramNames) =>
        paramNames.Any(UrlLikeParamNames.IsUrlLikeParamName);

    private static bool HasUrlLikeParamInBodySample(AttackSurfaceEndpoint ep)
    {
        if (string.IsNullOrWhiteSpace(ep.Parameters.RequestBodySample)) return false;
        var sample = ep.Parameters.RequestBodySample;
        if (sample.TrimStart().StartsWith('{'))
        {
            try
            {
                using var doc = JsonDocument.Parse(sample);
                if (doc.RootElement.ValueKind == JsonValueKind.Object)
                    return doc.RootElement.EnumerateObject().Any(p => UrlLikeParamNames.IsUrlLikeParamName(p.Name));
            }
            catch { /* fall through */ }
        }

        if (sample.Contains('='))
        {
            var qs = System.Web.HttpUtility.ParseQueryString(sample);
            foreach (string? key in qs)
            {
                if (key != null && UrlLikeParamNames.IsUrlLikeParamName(key))
                    return true;
            }
        }

        return false;
    }

    private static bool IsSsrfCandidateEndpoint(AttackSurfaceEndpoint ep) =>
        HasUrlLikeParam(ep.Parameters.Query) ||
        HasUrlLikeParam(ep.Parameters.Body) ||
        HasUrlLikeParamInBodySample(ep);

    private static bool IsOpenRedirectCandidate(AttackSurfaceEndpoint ep) =>
        HasRedirectLikeParam(ep) ||
        ep.ResponsePatterns.Keys.Any(k => int.TryParse(k, out var code) && code is >= 300 and < 400);

    private static bool HasRedirectLikeParam(AttackSurfaceEndpoint ep) =>
        ep.Parameters.Query.Concat(ep.Parameters.Body).Any(UrlLikeParamNames.IsRedirectLikeName);

    private static List<EndpointParamHint> BuildSsrfEndpointHints(IEnumerable<AttackSurfaceEndpoint> endpoints) =>
        endpoints
            .SelectMany(ep =>
            {
                var method = ep.Methods.FirstOrDefault(m =>
                    m.Equals("POST", StringComparison.OrdinalIgnoreCase) ||
                    m.Equals("PUT", StringComparison.OrdinalIgnoreCase) ||
                    m.Equals("PATCH", StringComparison.OrdinalIgnoreCase))
                    ?? ep.Methods.FirstOrDefault() ?? "GET";

                Dictionary<string, string>? headers = null;
                if (!string.IsNullOrEmpty(ep.Parameters.RequestContentType))
                    headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["Content-Type"] = ep.Parameters.RequestContentType
                    };

                return ep.Parameters.Query.Concat(ep.Parameters.Body)
                    .Where(UrlLikeParamNames.IsUrlLikeParamName)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Select(param => new EndpointParamHint
                    {
                        Url = ep.Url,
                        Method = method,
                        ParamNames = [param],
                        RequestBodySample = method is "POST" or "PUT" or "PATCH"
                            ? ep.Parameters.RequestBodySample
                            : null,
                        Headers = headers
                    });
            })
            .ToList();

    private static List<EndpointParamHint> BuildEndpointHints(IEnumerable<AttackSurfaceEndpoint> endpoints) =>
        endpoints
            .SelectMany(ep =>
            {
                var method = ep.Methods.FirstOrDefault(m =>
                    m.Equals("POST", StringComparison.OrdinalIgnoreCase) ||
                    m.Equals("PUT", StringComparison.OrdinalIgnoreCase) ||
                    m.Equals("PATCH", StringComparison.OrdinalIgnoreCase))
                    ?? ep.Methods.FirstOrDefault() ?? "GET";

                Dictionary<string, string>? headers = null;
                if (!string.IsNullOrEmpty(ep.Parameters.RequestContentType))
                    headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["Content-Type"] = ep.Parameters.RequestContentType
                    };

                return ep.Parameters.Query.Concat(ep.Parameters.Body)
                    .Where(UrlLikeParamNames.IsRedirectLikeName)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Select(param => new EndpointParamHint
                    {
                        Url = ep.Url,
                        Method = method,
                        ParamNames = [param],
                        RequestBodySample = method is "POST" or "PUT" or "PATCH"
                            ? ep.Parameters.RequestBodySample
                            : null,
                        Headers = headers
                    });
            })
            .ToList();

    private static async Task RunSsrfScan(
        AutomationContext ctx, List<AttackSurfaceEndpoint> endpoints,
        AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        var candidates = endpoints
            .Where(IsSsrfCandidateEndpoint)
            .Take(MaxEp(options))
            .ToList();

        foreach (var ep in endpoints.Except(candidates))
        {
            if (!IsSsrfCandidateEndpoint(ep))
            {
                result.SkippedEndpoints.Add(new SkippedEndpointInfo
                {
                    Endpoint = AttackSurfaceMapper.FormatDisplayUrl(ep), Scanner = "ssrf",
                    Reason = "no URL-like query or body parameters"
                });
            }
        }

        if (candidates.Count == 0)
        {
            result.ScannersSkipped.Add("ssrf (no URL-like params)");
            return;
        }

        try
        {
            var endpointHints = BuildSsrfEndpointHints(candidates);
            var ssrfOptions = new SsrfOptions
            {
                EndpointHints = endpointHints.Count > 0 ? endpointHints : null,
                MaxCandidates = MaxEp(options),
                TimeoutMs = options.TimeoutMs,
                IncludeCallbackProbes = true,
                // Auto-scan defaults to likely — tentative connection-error noise overwhelms confirmed SSRF.
                MinConfidence = "likely"
            };

            var ssrfResult = await ctx.RunSsrfScan(ssrfOptions);
            result.ScannersRun.Add("ssrf");
            result.EndpointsScanned += ssrfResult.CandidatesProbed;

            foreach (var f in ssrfResult.Findings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "ssrf",
                    Severity = f.Severity,
                    Endpoint = f.Url,
                    Method = f.Method,
                    Title = $"SSRF ({f.Type}): {f.Indicator} via '{f.ParamName}'",
                    Detail = $"Payload: {f.Payload}. HTTP {f.Status}. Confidence: {f.Confidence}. {f.Snippet}",
                    Evidence = f.CorrelationId != null ? $"correlation: {f.CorrelationId}" : $"confidence: {f.Confidence}, status: {f.Status}"
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"ssrf: {ex.Message}");
            result.ScannersSkipped.Add("ssrf (error)");
        }
    }

    private static async Task RunOpenRedirectScan(
        AutomationContext ctx, List<AttackSurfaceEndpoint> endpoints,
        AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        // Prefer endpoints with redirect-like params over bare 3xx response patterns so
        // MaxEp caps do not crowd out real open-redirect sinks (e.g. ?url= / ?next=).
        var candidates = endpoints
            .Where(IsOpenRedirectCandidate)
            .OrderByDescending(HasRedirectLikeParam)
            .ThenByDescending(ep => SeverityRank(ep.TestPriority))
            .Take(MaxEp(options))
            .ToList();

        foreach (var ep in endpoints.Except(candidates))
        {
            if (!IsOpenRedirectCandidate(ep))
            {
                result.SkippedEndpoints.Add(new SkippedEndpointInfo
                {
                    Endpoint = AttackSurfaceMapper.FormatDisplayUrl(ep), Scanner = "open-redirect",
                    Reason = "no redirect-like parameters or redirect response pattern"
                });
            }
        }

        if (candidates.Count == 0)
        {
            result.ScannersSkipped.Add("open-redirect (no candidates)");
            return;
        }

        try
        {
            var orOptions = new OpenRedirectOptions
            {
                ExplicitUrls = candidates.Select(ep => ep.Url).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                EndpointHints = BuildEndpointHints(candidates),
                MaxCandidates = MaxEp(options),
                TimeoutMs = options.TimeoutMs
            };

            var orResult = await ctx.RunOpenRedirectScan(orOptions, ct);
            result.ScannersRun.Add("open-redirect");
            result.EndpointsScanned += orResult.CandidatesProbed;

            foreach (var f in orResult.Findings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "open-redirect",
                    Severity = f.Severity,
                    Endpoint = f.Url,
                    Method = f.Method,
                    Title = $"Open redirect via '{f.ParamName}' ({f.Indicator})",
                    Detail = $"Payload: {f.Payload}. HTTP {f.Status} → Location: {f.Location}. " +
                               $"Bypass: {f.BypassTechnique ?? "n/a"}. Source: {f.Source}. Confidence: {f.Confidence}.",
                    Evidence = $"location: {f.Location}, confidence: {f.Confidence}"
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"open-redirect: {ex.Message}");
            result.ScannersSkipped.Add("open-redirect (error)");
        }
    }

    private static async Task RunCacheMapScan(
        AutomationContext ctx, AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        try
        {
            var mapOptions = new CacheMapOptions
            {
                MaxTargets = Math.Min(options.MaxEndpointsPerScanner, 2),
                TimeoutMs = options.TimeoutMs,
                IncludeBrowserCookies = true,
                IncludeHeaderProbes = false,
                IncludeFatGet = false
            };
            var map = await ctx.RunCacheMapScan(mapOptions, ct);
            result.ScannersRun.Add("cache-map");
            result.EndpointsScanned += map.ProbesRun;
            foreach (var f in map.Findings)
            {
                if (f.Indicator is "key-explosion-possible")
                    continue;
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "cache-map",
                    Severity = CacheMapPresentation.ReportingSeverity(f.Indicator, f.Confidence, f.Severity),
                    Endpoint = f.Url,
                    Method = "GET",
                    Title = f.Title,
                    Detail = $"{f.Indicator} ({f.Confidence}). {f.Detail}",
                    Evidence = f.HeaderName
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"cache-map: {ex.Message}");
            result.ScannersSkipped.Add("cache-map (error)");
        }
    }

    private static async Task RunCacheDeceptionScan(
        AutomationContext ctx, List<AttackSurfaceEndpoint> endpoints,
        AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        try
        {
            var currentUrl = await ctx.GetCurrentUrl();
            if (string.IsNullOrEmpty(currentUrl))
            {
                result.ScannersSkipped.Add("cache-deception (no page)");
                return;
            }

            if (!Uri.TryCreate(currentUrl, UriKind.Absolute, out var uri))
            {
                result.ScannersSkipped.Add("cache-deception (invalid url)");
                return;
            }

            var origin = uri.GetLeftPart(UriPartial.Authority);
            var cookieHeader = await ctx.GetCookieHeaderForUrl(origin);
            if (string.IsNullOrWhiteSpace(cookieHeader))
            {
                result.ScannersSkipped.Add("cache-deception (no session cookies)");
                return;
            }

            var authPaths = endpoints
                .Where(ep => ep.Auth.Required || ep.Url.Contains("/me", StringComparison.OrdinalIgnoreCase)
                    || ep.Url.Contains("/account", StringComparison.OrdinalIgnoreCase)
                    || ep.Url.Contains("/profile", StringComparison.OrdinalIgnoreCase))
                .Select(ep => Uri.TryCreate(ep.Url, UriKind.Absolute, out var u) ? u.AbsolutePath : ep.Url)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(MaxEp(options))
                .ToList();

            var cdOptions = new CacheDeceptionOptions
            {
                Paths = authPaths.Count > 0 ? authPaths : null,
                EndpointHints = BuildEndpointHints(endpoints.Take(MaxEp(options)).ToList()),
                MaxCandidates = Math.Min(options.MaxEndpointsPerScanner * 2, 12),
                TimeoutMs = options.TimeoutMs
            };

            var cdResult = await ctx.RunCacheDeceptionScan(cdOptions, ct);
            result.ScannersRun.Add("cache-deception");
            result.EndpointsScanned += cdResult.CandidatesProbed;

            foreach (var f in cdResult.Findings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "cache-deception",
                    Severity = f.Severity,
                    Endpoint = f.Url,
                    Method = "GET",
                    Title = $"Web cache deception ({f.Indicator})",
                    Detail = $"Variant {f.VariantPath}: auth-delta on base + anon variant≈authed body ({f.BodyLength} bytes, {f.Confidence}). {f.CacheHeaders}",
                    Evidence = f.BodySnippet
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"cache-deception: {ex.Message}");
            result.ScannersSkipped.Add("cache-deception (error)");
        }
    }

    private static async Task RunSqliScan(
        AutomationContext ctx, List<AttackSurfaceEndpoint> endpoints,
        AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        var injectable = endpoints
            .Where(HasInjectableSurface)
            .OrderByDescending(MaxSqliScore)
            .ToList();
        var candidates = TakeWithLoginSearchReserves(injectable, MaxEp(options));

        foreach (var ep in endpoints.Except(candidates))
        {
            if (!HasInjectableSurface(ep))
            {
                result.SkippedEndpoints.Add(new SkippedEndpointInfo
                {
                    Endpoint = AttackSurfaceMapper.FormatDisplayUrl(ep), Scanner = "sqli",
                    Reason = "no injectable parameters (no query, body, headers, or JSON string fields)"
                });
            }
        }

        result.ScannersRun.Add("sqli");
        var scanned = 0;
        var seenSqliFindings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (!options.UnifiedScaffoldRan
            && ShouldRunInjectionScaffold(candidates.Count, options, Depth(options).RunSqliScaffoldWhenSparse))
        {
            var currentUrl = await ctx.GetCurrentUrl();
            if (!string.IsNullOrEmpty(currentUrl) && Uri.TryCreate(currentUrl, UriKind.Absolute, out var originUri))
            {
                scanned += await RunSqliScaffoldScanAsync(
                    ctx, originUri.GetLeftPart(UriPartial.Authority), options, result, seenSqliFindings, ct);
            }
        }

        if (candidates.Count == 0 && scanned == 0)
        {
            result.ScannersSkipped.Add("sqli (no injectable params)");
            return;
        }

        foreach (var ep in candidates)
        {
            ct.ThrowIfCancellationRequested();

            var probes = BuildSqliProbes(ep)
                .OrderByDescending(p => InjectionParamClassifier.SqliLikelihoodScore(p.ParamName))
                .ToList();
            if (probes.Count == 0)
            {
                result.SkippedEndpoints.Add(new SkippedEndpointInfo
                {
                    Endpoint = AttackSurfaceMapper.FormatDisplayUrl(ep), Scanner = "sqli",
                    Reason = "could not auto-generate marker template"
                });
                continue;
            }

            foreach (var probe in probes)
            {
                if (!ShouldProbeParam(options, ep, probe.ParamName, "sqli"))
                    continue;

                ct.ThrowIfCancellationRequested();
                try
                {
                    var urlTemplate = probe.UrlTemplate;
                    if (string.Equals(probe.Method, "GET", StringComparison.OrdinalIgnoreCase)
                        && string.IsNullOrEmpty(probe.BodyTemplate))
                    {
                        urlTemplate = await FormProbeCloner.MergeGetFormSiblingsAsync(
                            ctx, urlTemplate, probe.ParamName, ct);
                    }

                    // GET/HEAD query probes: prefer backend fetch (avoids Zone.js / GET-with-body failures).
                    // Mutating POSTs keep browser fetch so cookies/CORS match the session.
                    var preferBackend = PreferBackendInjectionFetch(probe.Method, probe.BodyTemplate);
                    var sqliResult = options.UseSmartInjectionRouting
                        ? await HttpSecurityProbes.RunSqliScanTieredAsync(
                            ctx, urlTemplate, probe.Method, probe.Headers, probe.BodyTemplate,
                            baselineMarkerValue: "1", includeTimeBased: false, timeoutMs: options.TimeoutMs,
                            maxBodyChars: 32768, useBackendFetch: preferBackend,
                            includeBrowserCookies: preferBackend, includeOrmClosurePayloads: false, ct: ct,
                            payloadProfile: options.PayloadProfile)
                        : await HttpSecurityProbes.RunSqliScanAsync(
                            ctx, urlTemplate, probe.Method, probe.Headers, probe.BodyTemplate,
                            baselineMarkerValue: "1", customPayloads: null,
                            includeTimeBased: false, timeoutMs: options.TimeoutMs,
                            maxBodyChars: 32768, useBackendFetch: preferBackend,
                            includeBrowserCookies: preferBackend, includeOrmClosurePayloads: false,
                            ct: ct, payloadProfile: options.PayloadProfile);

                    scanned++;

                    foreach (var row in sqliResult.Rows.Where(r => r.Types.Count > 0))
                    {
                        var endpointKey = AttackSurfaceMapper.FormatDisplayUrl(ep);
                        foreach (var sqliType in row.Types.Distinct(StringComparer.OrdinalIgnoreCase))
                        {
                            if (!ShouldPromoteSqliTypeToFinding(sqliType, row))
                                continue;

                            // Refuse promotion when noise-stripped bodies are identical — no content oracle.
                            if (!string.IsNullOrEmpty(sqliResult.BaselineStrippedHash)
                                && !string.IsNullOrEmpty(row.ProbeStrippedHash)
                                && string.Equals(sqliResult.BaselineStrippedHash, row.ProbeStrippedHash,
                                    StringComparison.Ordinal)
                                && !sqliType.Contains("time-based", StringComparison.OrdinalIgnoreCase))
                                continue;

                            var dedupKey = SqliFindingDedupKey(endpointKey, probe.Method, probe.ParamName, sqliType);
                            if (!seenSqliFindings.Add(dedupKey))
                                continue;

                            var evidence = BuildSqliEvidenceBundle(sqliResult, row);
                            var sevRow = ResolveSqliSeverityForType(sqliType, row);
                            var deferred = DeferredInjectionHints.LooksLikeDeferredSetter(
                                probe.Method, endpointKey, probe.ParamName);
                            result.Findings.Add(new AutoScanFinding
                            {
                                Scanner = "sqli",
                                Severity = sevRow.Severity,
                                Endpoint = endpointKey,
                                Method = probe.Method,
                                Title =
                                    $"{sevRow.TitlePrefix}SQL injection ({sqliType}) via '{probe.ParamName}'",
                                Detail = $"Payload: {row.Payload}. Status: {row.Status}, length: {row.BodyLength}.",
                                Evidence = evidence,
                                NextActions = deferred
                                    ?
                                    [
                                        SecurityNextActions.VerifyWorkflow,
                                        SecurityNextActions.SqliRetestTruthyFalsy(probe.ParamName),
                                        SecurityNextActions.VerifyDeferredInjectionStub(
                                            endpointKey, probe.Method, probe.ParamName,
                                            DeferredInjectionHints.SuggestReadUrl(endpointKey, endpoints))
                                    ]
                                    :
                                    [
                                        SecurityNextActions.VerifyWorkflow,
                                        SecurityNextActions.SqliRetestTruthyFalsy(probe.ParamName)
                                    ]
                            });
                        }
                    }

                    // Setter with no in-response SQLi hit — still emit a deferred-injection hint.
                    if (sqliResult.Rows.All(r => r.Types.Count == 0)
                        && DeferredInjectionHints.LooksLikeDeferredSetter(
                            probe.Method, AttackSurfaceMapper.FormatDisplayUrl(ep), probe.ParamName))
                    {
                        var setUrl = AttackSurfaceMapper.FormatDisplayUrl(ep);
                        var hintKey = $"deferred|{setUrl}|{probe.ParamName}";
                        if (seenSqliFindings.Add(hintKey))
                        {
                            result.Findings.Add(DeferredInjectionHints.BuildHintFinding(
                                setUrl,
                                probe.Method,
                                probe.ParamName,
                                DeferredInjectionHints.SuggestReadUrl(setUrl, endpoints)));
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    result.Partial = true;
                    throw;
                }
                catch (Exception ex)
                {
                    result.Errors.Add($"sqli on {AttackSurfaceMapper.FormatDisplayUrl(ep)} param '{probe.ParamName}': {ex.Message}");
                }
            }
        }

        result.EndpointsScanned += scanned;
    }

    private static async Task RunXssScan(
        AutomationContext ctx, List<AttackSurfaceEndpoint> endpoints,
        AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        var candidates = TakeWithLoginSearchReserves(
            endpoints.Where(HasInjectableSurface).OrderByDescending(MaxXssScore),
            MaxEp(options));

        result.ScannersRun.Add("xss");
        var scanned = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (!options.UnifiedScaffoldRan
            && ShouldRunInjectionScaffold(candidates.Count, options, Depth(options).RunSqliScaffoldWhenSparse))
        {
            var currentUrl = await ctx.GetCurrentUrl();
            if (!string.IsNullOrEmpty(currentUrl) && Uri.TryCreate(currentUrl, UriKind.Absolute, out var originUri))
            {
                scanned += await RunXssScaffoldScanAsync(
                    ctx, originUri.GetLeftPart(UriPartial.Authority), options, result, seen, ct);
            }
        }

        if (candidates.Count == 0 && scanned == 0)
        {
            result.ScannersSkipped.Add("xss (no injectable params)");
            return;
        }

        foreach (var ep in candidates)
        {
            ct.ThrowIfCancellationRequested();
            var inventoriedParams = new HashSet<string>(
                ep.Parameters.Query.Concat(ep.Parameters.Body),
                StringComparer.OrdinalIgnoreCase);
            var confirmedInventoriedParams = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var probe in BuildXssProbes(ep)
                         .OrderByDescending(p => InjectionParamClassifier.XssLikelihoodScore(p.ParamName)))
            {
                if (!ShouldProbeParam(options, ep, probe.ParamName, "xss"))
                    continue;

                ct.ThrowIfCancellationRequested();
                try
                {
                    var xssResult = await XssScanner.RunAsync(
                        ctx, probe.UrlTemplate, probe.Method, probe.Headers, probe.BodyTemplate,
                        options.TimeoutMs, payloadProfile: options.PayloadProfile, ct: ct);
                    scanned++;

                    foreach (var row in xssResult.Rows.Where(r => r.Dangerous))
                    {
                        var endpointKey = AttackSurfaceMapper.FormatDisplayUrl(ep);
                        var isSiblingOnly = inventoriedParams.Count > 0
                                            && !inventoriedParams.Contains(probe.ParamName);
                        // Collapse sibling-param XSS unless that sibling independently reflects
                        // (and no inventoried param on this endpoint already confirmed).
                        if (isSiblingOnly && confirmedInventoriedParams.Count > 0)
                            continue;
                        if (isSiblingOnly && !ReflectionLooksParamCausal(row.Surrounding, probe.ParamName))
                            continue;

                        var dedupKey = $"{endpointKey}|{probe.Method}|{probe.ParamName}|{row.Context}";
                        if (!seen.Add(dedupKey))
                        {
                            var existing = result.Findings.LastOrDefault(f =>
                                f.Scanner.Contains("xss", StringComparison.OrdinalIgnoreCase)
                                && string.Equals(f.Endpoint, endpointKey, StringComparison.OrdinalIgnoreCase)
                                && f.Title.Contains($"'{probe.ParamName}'", StringComparison.OrdinalIgnoreCase));
                            if (existing != null)
                            {
                                existing.Occurrences++;
                                if (!existing.Detail.Contains(row.Payload, StringComparison.Ordinal))
                                    existing.Detail += $"; payload: {row.Payload}";
                            }

                            continue;
                        }

                        if (inventoriedParams.Contains(probe.ParamName))
                            confirmedInventoriedParams.Add(probe.ParamName);

                        var xssClass = ClassifyXssFindingLabel(probe.Method, ep);
                        result.Findings.Add(new AutoScanFinding
                        {
                            Scanner = xssClass == "stored" ? "xss-stored" : "xss",
                            Severity = "high",
                            Endpoint = endpointKey,
                            Method = probe.Method,
                            Title = $"{(xssClass == "stored" ? "Stored" : "Reflected")} XSS via '{probe.ParamName}' ({row.Context})",
                            Detail = $"Payload: {row.Payload}. HTTP {row.Status}. {row.Reason}",
                            Evidence = row.Surrounding,
                            NextActions =
                            [
                                SecurityNextActions.VerifyWorkflow,
                                SecurityNextActions.TraceInput(probe.ParamName)
                            ]
                        });
                    }
                }
                catch (OperationCanceledException)
                {
                    result.Partial = true;
                    throw;
                }
                catch (Exception ex)
                {
                    result.Errors.Add($"xss on {AttackSurfaceMapper.FormatDisplayUrl(ep)} param '{probe.ParamName}': {ex.Message}");
                }
            }
        }

        result.EndpointsScanned += scanned;
    }

    private static async Task<int> RunXssScaffoldScanAsync(
        AutomationContext ctx,
        string origin,
        AutoScanOptions options,
        AutoScanResult result,
        HashSet<string> seenFindings,
        CancellationToken ct)
    {
        var scanned = 0;
        foreach (var tpl in InjectionScaffold.EnumerateXssScaffold().Take(Depth(options).SqliScaffoldCap))
        {
            ct.ThrowIfCancellationRequested();
            if (tpl.PathQueryTemplate.Contains('#')) continue;

            var urlTemplate = InjectionScaffold.BuildUrl(origin, tpl.PathQueryTemplate, "§xss§");
            try
            {
                var xssResult = await XssScanner.RunAsync(
                    ctx, urlTemplate, tpl.Method, null, null, options.TimeoutMs,
                    payloadProfile: options.PayloadProfile, ct: ct);
                scanned++;

                foreach (var row in xssResult.Rows.Where(r => r.Dangerous))
                {
                    var dedupKey = $"{urlTemplate}|{tpl.ParamName}|{row.Payload}";
                    if (!seenFindings.Add(dedupKey)) continue;

                    var endpoint = urlTemplate.Split('?', 2)[0];
                    var observed = InjectionScaffoldFindingPolicy.IsPathObservedInTraffic(
                        ctx.Network.Entries, endpoint, origin);
                    var (scaffoldSev, scaffoldPrefix, scaffoldSuffix) =
                        InjectionScaffoldFindingPolicy.AdjustScaffoldInjectionSeverity("high", "", observed);

                    result.Findings.Add(new AutoScanFinding
                    {
                        Scanner = "xss",
                        Severity = scaffoldSev,
                        Endpoint = endpoint,
                        Method = tpl.Method,
                        Title = $"{scaffoldPrefix}Reflected XSS scaffold via '{tpl.ParamName}' ({row.Context})",
                        Detail = $"Sparse-traffic scaffold template. Payload: {row.Payload}. HTTP {row.Status}. {row.Reason}.{scaffoldSuffix ?? ""}",
                        Evidence = row.Surrounding
                    });
                }
            }
            catch (Exception ex)
            {
                result.Errors.Add($"xss scaffold {tpl.PathQueryTemplate}: {ex.Message}");
            }
        }

        return scanned;
    }

    private static async Task RunXssDomScan(
        AutomationContext ctx, AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        result.ScannersRun.Add("xss-dom");
        try
        {
            var scanResult = await ctx.RunXssScan(new XssScanRunner.XssScanOptions
            {
                IncludeReflected = false,
                IncludeDom = true,
                IncludeStored = false,
                MaxCandidates = MaxEp(options),
                TimeoutMs = Math.Min(options.TimeoutMs, 12_000),
                MaxBypassAttempts = Depth(options).Name == AutoScanDepthProfile.Quick ? 4 : 8,
                PayloadProfile = options.PayloadProfile,
                IncludeGenericScaffold = options.AllowGenericScaffold
            }, ct);

            result.EndpointsScanned += scanResult.CandidatesProbed;
            foreach (var f in scanResult.Findings)
            {
                var source = f.Extra.TryGetValue("source", out var src) ? src?.ToString() ?? "" : "";
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "xss-dom",
                    Severity = f.Severity,
                    Endpoint = f.Endpoint ?? "",
                    Method = f.Method ?? "GET",
                    Title = $"DOM XSS via '{f.Param}' ({source})",
                    Detail = f.ProofHint ?? f.Title,
                    Evidence = f.Evidence
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"xss-dom: {ex.Message}");
            result.ScannersSkipped.Add("xss-dom (error)");
        }
    }

    private static async Task RunXssStoredScan(
        AutomationContext ctx, AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        result.ScannersRun.Add("xss-stored");
        try
        {
            var scanResult = await ctx.RunXssStoredScan(new XssStoredScanProbe.XssStoredScanOptions
            {
                MaxCandidates = Math.Min(MaxEp(options), 8),
                TimeoutMs = options.TimeoutMs
            }, ct);

            result.EndpointsScanned += scanResult.CandidatesProbed;
            foreach (var f in scanResult.Findings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "xss-stored",
                    Severity = f.Severity,
                    Endpoint = f.ReadUrl,
                    Method = "POST",
                    Title = $"Stored XSS via '{f.FieldName}'",
                    Detail = f.Detail,
                    Evidence = f.Evidence
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"xss-stored: {ex.Message}");
        }
    }

    private static async Task RunSstiScan(
        AutomationContext ctx, List<AttackSurfaceEndpoint> endpoints,
        AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        var candidates = endpoints
            .Where(HasInjectableSurface)
            .Take(MaxEp(options))
            .ToList();

        result.ScannersRun.Add("ssti");
        var scanned = 0;
        var seenSstiFindings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (!options.UnifiedScaffoldRan
            && ShouldRunInjectionScaffold(candidates.Count, options, Depth(options).RunSstiScaffoldWhenSparse))
        {
            var currentUrl = await ctx.GetCurrentUrl();
            if (!string.IsNullOrEmpty(currentUrl) && Uri.TryCreate(currentUrl, UriKind.Absolute, out var originUri))
            {
                scanned += await RunSstiScaffoldScanAsync(
                    ctx, originUri.GetLeftPart(UriPartial.Authority), options, result, seenSstiFindings, ct);
            }
        }

        if (candidates.Count == 0 && scanned == 0)
        {
            result.ScannersSkipped.Add("ssti (no injectable params)");
            return;
        }

        foreach (var ep in candidates)
        {
            ct.ThrowIfCancellationRequested();
            var probes = BuildSqliProbes(ep);
            if (probes.Count == 0) continue;

            foreach (var probe in probes.Take(2))
            {
                if (options.UseSmartInjectionRouting
                    && options.InjectionPlan != null
                    && !options.InjectionPlan.AllowsFullSsti(ep, probe.ParamName, options.SstiEscalation))
                    continue;

                ct.ThrowIfCancellationRequested();
                try
                {
                    var sstiResult = await SstiScanner.RunAsync(
                        ctx, probe.UrlTemplate, probe.Method, probe.Headers, probe.BodyTemplate,
                        probe.ParamName, options.TimeoutMs, ct, payloadProfile: options.PayloadProfile);
                    scanned++;

                    foreach (var row in sstiResult.Rows)
                    {
                        var kind = row.ReflectedArithmetic ? "arithmetic reflection (49/56)"
                            : row.TemplateError ? $"template error ({row.Indicator})"
                            : "suspicious";
                        var dedupKey = $"{AttackSurfaceMapper.FormatDisplayUrl(ep)}|{probe.ParamName}|{row.Payload}";
                        if (!seenSstiFindings.Add(dedupKey))
                            continue;
                        result.Findings.Add(new AutoScanFinding
                        {
                            Scanner = "ssti",
                            Severity = row.ReflectedArithmetic ? "high" : "medium",
                            Endpoint = AttackSurfaceMapper.FormatDisplayUrl(ep),
                            Method = probe.Method,
                            Title = $"SSTI suspected ({kind}) via '{probe.ParamName}'",
                            Detail = $"Payload: {row.Payload}. HTTP {row.Status}."
                        });
                    }
                }
                catch (Exception ex)
                {
                    result.Errors.Add($"ssti {AttackSurfaceMapper.FormatDisplayUrl(ep)}: {ex.Message}");
                }
            }
        }

        result.EndpointsScanned += scanned;
    }

    private static async Task<int> RunSstiScaffoldScanAsync(
        AutomationContext ctx,
        string origin,
        AutoScanOptions options,
        AutoScanResult result,
        HashSet<string> seenSstiFindings,
        CancellationToken ct)
    {
        var scanned = 0;
        var seenTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var tpl in InjectionScaffold.EnumerateSstiScaffold().Take(Depth(options).SstiScaffoldCap))
        {
            ct.ThrowIfCancellationRequested();
            var urlTemplate = InjectionScaffold.BuildUrl(origin, tpl.PathQueryTemplate, "§ssti§");
            var targetId = urlTemplate.Split('?', 2)[0];
            if (!seenTargets.Add(targetId))
                continue;

            try
            {
                var sstiResult = await SstiScanner.RunAsync(
                    ctx, urlTemplate, tpl.Method, null, null,
                    tpl.ParamName, options.TimeoutMs, ct, payloadProfile: options.PayloadProfile);
                scanned++;

                foreach (var row in sstiResult.Rows)
                {
                    var kind = row.ReflectedArithmetic ? "arithmetic reflection (49/56)"
                        : row.TemplateError ? $"template error ({row.Indicator})"
                        : "suspicious";
                    var dedupKey = $"{targetId}|{tpl.ParamName}|{row.Payload}|scaffold";
                    if (!seenSstiFindings.Add(dedupKey))
                        continue;

                    result.Findings.Add(new AutoScanFinding
                    {
                        Scanner = "ssti",
                        Severity = row.ReflectedArithmetic ? "high" : "medium",
                        Endpoint = targetId,
                        Method = tpl.Method,
                        Title = $"SSTI suspected ({kind}) via '{tpl.ParamName}' (scaffold)",
                        Detail = $"Sparse-traffic ALWAYS_PROBED template. Payload: {row.Payload}. HTTP {row.Status}."
                    });
                }
            }
            catch (Exception ex)
            {
                result.Errors.Add($"ssti-scaffold {targetId}: {ex.Message}");
            }
        }

        return scanned;
    }

    private static AutoScanDepthProfile.Resolved Depth(AutoScanOptions options) =>
        options.DepthProfile ?? AutoScanDepthProfile.Resolve(options);

    private static int MaxEp(AutoScanOptions options) =>
        Depth(options).EffectiveMaxEndpointsPerScanner;

    /// <summary>
    /// Keep login + primary search endpoints in the top-N even when testPriority ranks them low.
    /// </summary>
    private static List<AttackSurfaceEndpoint> TakeWithLoginSearchReserves(
        IEnumerable<AttackSurfaceEndpoint> ordered,
        int max)
    {
        var list = ordered.ToList();
        if (max <= 0 || list.Count == 0) return [];
        if (list.Count <= max) return list;

        var taken = new List<AttackSurfaceEndpoint>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void TryAdd(AttackSurfaceEndpoint ep)
        {
            var key = AttackSurfaceMapper.FormatDisplayUrl(ep) + "|" + string.Join(",", ep.Methods);
            if (!seen.Add(key)) return;
            if (taken.Count >= max) return;
            taken.Add(ep);
        }

        var login = list.FirstOrDefault(ep =>
        {
            var path = string.IsNullOrEmpty(ep.UrlTemplate) ? ep.Url : ep.UrlTemplate;
            return InjectionParamClassifier.IsLoginEndpoint(path);
        });
        var search = list.FirstOrDefault(ep =>
        {
            var path = string.IsNullOrEmpty(ep.UrlTemplate) ? ep.Url : ep.UrlTemplate;
            return LooksLikeInjectableSearchPath(path)
                   || ep.Parameters.Query.Any(p => InjectionParamClassifier.XssLikelihoodScore(p) >= 2
                                                   || InjectionParamClassifier.SqliLikelihoodScore(p) >= 2);
        });

        if (login != null) TryAdd(login);
        if (search != null) TryAdd(search);
        foreach (var ep in list)
            TryAdd(ep);

        return taken;
    }

    private static string ClassifyXssFindingLabel(string method, AttackSurfaceEndpoint ep)
    {
        var m = (method ?? "").Trim().ToUpperInvariant();
        if (m is "POST" or "PUT" or "PATCH")
            return "stored";
        var path = (ep.UrlTemplate ?? ep.Url ?? "").ToLowerInvariant();
        if (path.Contains("comment") || path.Contains("review") || path.Contains("message")
            || path.Contains("guestbook") || path.Contains("feedback"))
            return "stored";
        return "reflected";
    }

    private static bool ReflectionLooksParamCausal(string? surrounding, string paramName)
    {
        if (string.IsNullOrWhiteSpace(surrounding) || string.IsNullOrWhiteSpace(paramName))
            return false;
        // Reflection evidence should mention the probed param (name=value, "name":, ?name=, etc.).
        return surrounding.Contains(paramName + "=", StringComparison.OrdinalIgnoreCase)
               || surrounding.Contains("\"" + paramName + "\"", StringComparison.OrdinalIgnoreCase)
               || surrounding.Contains("'" + paramName + "'", StringComparison.OrdinalIgnoreCase)
               || surrounding.Contains("name=\"" + paramName + "\"", StringComparison.OrdinalIgnoreCase)
               || surrounding.Contains("name='" + paramName + "'", StringComparison.OrdinalIgnoreCase);
    }

    private static int MaxSqliScore(AttackSurfaceEndpoint ep)
    {
        var paramScore = ep.Parameters.Query.Concat(ep.Parameters.Body)
            .Select(InjectionParamClassifier.SqliLikelihoodScore)
            .DefaultIfEmpty(0)
            .Max();
        // Header-only sinks (e.g. x-product-name) must compete for top-N slots.
        var headerScore = ep.Parameters.Headers.Count > 0 ? 2 : 0;
        var rawBodyScore = LooksLikeRawBodyTemplateSink(ep) ? 2 : 0;
        return Math.Max(paramScore, Math.Max(headerScore, rawBodyScore));
    }

    private static int MaxXssScore(AttackSurfaceEndpoint ep) =>
        ep.Parameters.Query.Concat(ep.Parameters.Body)
            .Select(InjectionParamClassifier.XssLikelihoodScore)
            .DefaultIfEmpty(0)
            .Max();

    /// <summary>
    /// Prefer server-side HTTP for idempotent GET/HEAD probes (reliable classification, no GET+body).
    /// Keep browser fetch for body-bearing mutating methods so session cookies/CORS stay aligned.
    /// </summary>
    private static bool PreferBackendInjectionFetch(string method, string? bodyTemplate)
    {
        if (method.Equals("GET", StringComparison.OrdinalIgnoreCase)
            || method.Equals("HEAD", StringComparison.OrdinalIgnoreCase))
            return true;
        return string.IsNullOrEmpty(bodyTemplate);
    }

    private static int CountInjectableEndpoints(IEnumerable<AttackSurfaceEndpoint> endpoints) =>
        endpoints.Count(HasInjectableSurface);

    private static bool ShouldRunInjectionScaffold(
        int injectableEndpointCount,
        AutoScanOptions options,
        bool enabledByDepth) =>
        options.AllowGenericScaffold
        && string.IsNullOrWhiteSpace(options.TargetUrl)
        && enabledByDepth
        && injectableEndpointCount < options.SparseInjectionThreshold;

    private static bool ShouldProbeParam(
        AutoScanOptions options, AttackSurfaceEndpoint ep, string paramName, string scanner)
    {
        if (!options.UseSmartInjectionRouting || options.InjectionPlan == null)
            return true;
        return options.InjectionPlan.AllowsProbe(ep, paramName, scanner);
    }

    /// <summary>Single sparse-traffic scaffold pass with per-param scanner routing.</summary>
    private static async Task RunUnifiedScaffoldScan(
        AutomationContext ctx,
        string origin,
        AutoScanOptions options,
        AutoScanResult result,
        CancellationToken ct)
    {
        var plan = options.InjectionPlan!;
        var cap = Depth(options).SqliScaffoldCap;
        var seenSqli = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenXss = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenSsti = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var scanned = 0;

        result.ScannersRun.Add("unified-scaffold");

        foreach (var entry in InjectionScaffold.EnumerateUnifiedScaffold(cap))
        {
            ct.ThrowIfCancellationRequested();
            var targetId = InjectionScaffold.BuildUrl(origin, entry.PathQueryTemplate, "baseline")
                .Split('?', '#')[0];

            if (options.IncludeSqli && plan.AllowsScaffoldScanner(entry.ParamKind, "sqli"))
            {
                var sqliTemplate = InjectionScaffold.BuildUrl(origin, entry.PathQueryTemplate, "§sqli§");
                try
                {
                    var sqliResult = options.UseSmartInjectionRouting
                        ? await HttpSecurityProbes.RunSqliScanTieredAsync(
                            ctx, sqliTemplate, entry.Method, null, null, "1",
                            includeTimeBased: false, timeoutMs: options.TimeoutMs,
                            maxBodyChars: 32768, useBackendFetch: true, includeBrowserCookies: true, ct: ct,
                            payloadProfile: options.PayloadProfile)
                        : await HttpSecurityProbes.RunSqliScanAsync(
                            ctx, sqliTemplate, entry.Method, null, null, "1", null,
                            includeTimeBased: false, timeoutMs: options.TimeoutMs,
                            maxBodyChars: 32768, useBackendFetch: true, includeBrowserCookies: true,
                            includeOrmClosurePayloads: false, ct: ct, payloadProfile: options.PayloadProfile);
                    scanned++;
                    foreach (var row in sqliResult.Rows.Where(r => r.Types.Count > 0))
                    {
                        foreach (var sqliType in row.Types.Distinct(StringComparer.OrdinalIgnoreCase))
                        {
                            if (!ShouldPromoteSqliTypeToFinding(sqliType, row))
                                continue;

                            var dedupKey = SqliFindingDedupKey(targetId, entry.Method, entry.ParamName, sqliType);
                            if (!seenSqli.Add(dedupKey)) continue;
                            var sevRow = ResolveSqliSeverityForType(sqliType, row);
                            var observed = InjectionScaffoldFindingPolicy.IsPathObservedInTraffic(
                                ctx.Network.Entries, targetId, origin);
                            var (scaffoldSev, scaffoldPrefix, scaffoldSuffix) =
                                InjectionScaffoldFindingPolicy.AdjustScaffoldInjectionSeverity(
                                    sevRow.Severity, sevRow.TitlePrefix, observed);
                            result.Findings.Add(new AutoScanFinding
                            {
                                Scanner = "sqli",
                                Severity = scaffoldSev,
                                Endpoint = targetId,
                                Method = entry.Method,
                                Title = $"{scaffoldPrefix}SQL injection scaffold ({sqliType}) via '{entry.ParamName}'",
                                Detail = $"Unified scaffold. Payload: {row.Payload}.{scaffoldSuffix ?? ""}",
                                Evidence = BuildSqliEvidenceBundle(sqliResult, row)
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    result.Errors.Add($"unified-scaffold sqli {targetId}: {ex.Message}");
                }
            }

            if (options.IncludeXss && plan.AllowsScaffoldScanner(entry.ParamKind, "xss"))
            {
                var xssTemplate = InjectionScaffold.BuildUrl(origin, entry.PathQueryTemplate, "§xss§");
                try
                {
                    var xssResult = await XssScanner.RunAsync(
                        ctx, xssTemplate, entry.Method, null, null, options.TimeoutMs,
                        payloadProfile: options.PayloadProfile, ct: ct);
                    scanned++;
                    foreach (var row in xssResult.Rows.Where(r => r.Dangerous))
                    {
                        var dedupKey = $"{targetId}|{entry.ParamName}|{row.Payload}";
                        if (!seenXss.Add(dedupKey)) continue;
                        var observed = InjectionScaffoldFindingPolicy.IsPathObservedInTraffic(
                            ctx.Network.Entries, targetId, origin);
                        var (scaffoldSev, scaffoldPrefix, scaffoldSuffix) =
                            InjectionScaffoldFindingPolicy.AdjustScaffoldInjectionSeverity("high", "", observed);
                        result.Findings.Add(new AutoScanFinding
                        {
                            Scanner = "xss",
                            Severity = scaffoldSev,
                            Endpoint = targetId,
                            Method = entry.Method,
                            Title = $"{scaffoldPrefix}XSS scaffold via '{entry.ParamName}'",
                            Detail = $"Unified scaffold. Payload: {row.Payload}. Context: {row.Context}.{scaffoldSuffix ?? ""}"
                        });
                    }
                }
                catch (Exception ex)
                {
                    result.Errors.Add($"unified-scaffold xss {targetId}: {ex.Message}");
                }
            }

            if (options.IncludeSsti && plan.AllowsScaffoldScanner(entry.ParamKind, "ssti-polyglot"))
            {
                var baselineUrl = InjectionScaffold.BuildUrl(origin, entry.PathQueryTemplate, SstiPolyglotScanProbe.Canary);
                var polyglotTemplate = InjectionScaffold.BuildUrl(origin, entry.PathQueryTemplate, SstiPolyglotScanProbe.Polyglot);
                try
                {
                    var baseline = await LoginInjectionHelpers.SendAsync(
                        ctx, baselineUrl, entry.Method, null, null, options.TimeoutMs, followRedirects: true, true, ct);
                    var attack = await LoginInjectionHelpers.SendAsync(
                        ctx, polyglotTemplate, entry.Method, null, null, options.TimeoutMs, followRedirects: true, true, ct);
                    scanned++;
                    var severity = SstiPolyglotScanProbe.Classify(baseline.Body, attack.Body);
                    if (severity != null)
                    {
                        options.SstiEscalation?.Record(targetId, entry.ParamName);
                        var dedupKey = $"{targetId}|{entry.ParamName}|polyglot";
                        if (seenSsti.Add(dedupKey))
                        {
                            result.Findings.Add(new AutoScanFinding
                            {
                                Scanner = "ssti-polyglot",
                                Severity = severity,
                                Endpoint = polyglotTemplate,
                                Method = entry.Method,
                                Title = $"SSTI polyglot scaffold via '{entry.ParamName}'",
                                Detail = "Unified scaffold polyglot probe."
                            });
                        }

                        if (InjectionParamClassifier.AllowsFullSsti(entry.ParamKind, polyglotEscalated: true))
                        {
                            var sstiTemplate = InjectionScaffold.BuildUrl(origin, entry.PathQueryTemplate, "§ssti§");
                            var sstiResult = await SstiScanner.RunAsync(
                                ctx, sstiTemplate, entry.Method, null, null, entry.ParamName, options.TimeoutMs, ct,
                                payloadProfile: options.PayloadProfile);
                            scanned++;
                            foreach (var row in sstiResult.Rows)
                            {
                                var kind = row.ReflectedArithmetic ? "arithmetic reflection (49/56)"
                                    : row.TemplateError ? $"template error ({row.Indicator})"
                                    : "suspicious";
                                var sstiDedup = $"{targetId}|{entry.ParamName}|{row.Payload}";
                                if (!seenSsti.Add(sstiDedup)) continue;
                                result.Findings.Add(new AutoScanFinding
                                {
                                    Scanner = "ssti",
                                    Severity = row.ReflectedArithmetic ? "high" : "medium",
                                    Endpoint = targetId,
                                    Method = entry.Method,
                                    Title = $"SSTI scaffold ({kind}) via '{entry.ParamName}'",
                                    Detail = $"Payload: {row.Payload}. HTTP {row.Status}."
                                });
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    result.Errors.Add($"unified-scaffold ssti {targetId}: {ex.Message}");
                }
            }
        }

        result.EndpointsScanned += scanned;
    }

    private static async Task RunSstiPolyglotScan(
        AutomationContext ctx,
        AutoScanOptions options,
        AutoScanResult result,
        CancellationToken ct)
    {
        if (!options.IncludeSstiPolyglot)
            return;

        var depth = Depth(options);
        if (!depth.PolyglotEnabled)
        {
            result.ScannersSkipped.Add("ssti-polyglot (disabled by scan depth profile)");
            return;
        }

        result.ScannersRun.Add("ssti-polyglot");
        try
        {
            var scanResult = await ctx.RunSstiPolyglotScan(new SstiPolyglotScanProbe.SstiPolyglotScanOptions
            {
                MaxCandidates = depth.PolyglotMaxPaths > 0 ? depth.PolyglotMaxPaths : int.MaxValue,
                MaxProbes = depth.PolyglotMaxProbes,
                MaxParams = depth.PolyglotMaxParams,
                IncludeScaffold = depth.PolyglotIncludeScaffold,
                TimeoutMs = Math.Min(options.TimeoutMs, depth.Name == AutoScanDepthProfile.Quick ? 8000 : 12_000)
            }, ct);

            result.EndpointsScanned += scanResult.CandidatesProbed;

            foreach (var f in scanResult.Findings)
            {
                options.SstiEscalation?.RecordPolyglot(f.Url, f.ParamName);
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "ssti-polyglot",
                    Severity = f.Severity,
                    Endpoint = f.Url,
                    Method = "GET",
                    Title = $"SSTI polyglot via '{f.ParamName}'",
                    Detail = f.Detail
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"ssti-polyglot: {ex.Message}");
        }
    }

    private static async Task RunSstiStoredScan(
        AutomationContext ctx,
        AutoScanOptions options,
        AutoScanResult result,
        CancellationToken ct)
    {
        result.ScannersRun.Add("ssti-stored");
        try
        {
            var scanResult = await ctx.RunSstiStoredScan(new SstiStoredScanProbe.SstiStoredScanOptions
            {
                MaxCandidates = Depth(options).SstiStoredMaxCandidates,
                TimeoutMs = options.TimeoutMs
            }, ct);

            result.EndpointsScanned += scanResult.CandidatesProbed;

            foreach (var f in scanResult.Findings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "ssti-stored",
                    Severity = f.Severity,
                    Endpoint = f.ReadUrl,
                    Method = "POST",
                    Title = $"Stored SSTI ({f.Syntax}) via '{f.FieldName}'",
                    Detail = f.Detail
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"ssti-stored: {ex.Message}");
        }
    }

    private static async Task RunPrototypePollutionScan(
        AutomationContext ctx,
        AutoScanOptions options,
        AutoScanResult result,
        CancellationToken ct)
    {
        result.ScannersRun.Add("prototype-pollution");
        try
        {
            var scanResult = await ctx.RunPrototypePollutionScan(
                new PrototypePollutionScanProbe.PrototypePollutionScanOptions
                {
                    MaxCandidates = Depth(options).PrototypePollutionMaxCandidates,
                    TimeoutMs = options.TimeoutMs
                }, ct);

            result.EndpointsScanned += scanResult.CandidatesProbed;

            foreach (var f in scanResult.Findings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "prototype-pollution",
                    Severity = f.Severity,
                    Endpoint = f.PostUrl,
                    Method = "POST",
                    Title = $"Prototype pollution canary {f.Canary}",
                    Detail = $"{f.Detail} Verified at {f.VerifyUrl}."
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"prototype-pollution: {ex.Message}");
        }
    }

    private static async Task<bool> ShouldRunCstiAsync(AutomationContext ctx, AutoScanOptions options)
    {
        if (options.IncludeCsti == false) return false;
        if (options.IncludeCsti == true) return true;

        TechStackResult? stack = null;
        try { stack = await ctx.CheckTechStack(); }
        catch { /* fall through to DOM */ }

        if (CstiProbes.HasCstiRelevantFramework(stack))
            return true;

        var domEngines = await CstiProbes.DetectEnginesFromDomAsync(ctx);
        return domEngines.Count > 0;
    }

    private static async Task RunCstiScan(
        AutomationContext ctx, AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        result.ScannersRun.Add("csti");
        try
        {
            var scanResult = await ctx.RunCstiScan(new CstiScanRunner.CstiScanOptions
            {
                MaxCandidates = MaxEp(options) * 2,
                TimeoutMs = Math.Min(options.TimeoutMs, 10_000),
                MonitorSinks = true,
                Escalate = false
            }, ct);

            foreach (var f in scanResult.Findings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "csti-confirmed",
                    Severity = f.Severity,
                    Endpoint = f.Url,
                    Method = "GET",
                    Title = $"CSTI ({f.Engine}) via '{f.Parameter}' ({f.Source})",
                    Detail = $"Expression {f.BasicExpression} evaluated to {f.EvaluatedToken} in rendered DOM."
                        + (f.CodeExecution ? " Code execution indicators present." : "")
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"csti: {ex.Message}");
        }
        finally
        {
            try { await ctx.PurgeNonAsciiCookiesAsync(); }
            catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }
        }
    }

    private static async Task<bool> ShouldRunParserProbeAsync(AutomationContext ctx, AutoScanOptions options)
    {
        if (options.IncludeParserProbe == false) return false;
        if (options.IncludeParserProbe == true) return true;
        if (!options.ConfirmBackend) return false;
        var currentUrl = await ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var uri))
            return false;
        return UploadProbeSupport.CountJsonPostEndpoints(ctx, uri.GetLeftPart(UriPartial.Authority)) > 0;
    }

    private static async Task<bool> ShouldRunNextJsRscScanAsync(AutomationContext ctx, AutoScanOptions options)
    {
        if (options.IncludeNextJsRscScan == false) return false;
        if (options.IncludeNextJsRscScan == true) return true;
        try
        {
            var stack = await ctx.CheckTechStack();
            if (stack.Detections.Any(d => d.Name.Contains("Next.js", StringComparison.OrdinalIgnoreCase)))
                return true;
        }
        catch { /* optional */ }

        var currentUrl = await ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var uri))
            return false;
        var origin = uri.GetLeftPart(UriPartial.Authority);
        var root = await SecurityProbeHttp.FetchAsync(ctx, origin + "/", "GET", null, null, 8000, true);
        return NextJsRscScanProbe.LooksLikeNextJs(null, root.Body, root.ResponseHeaders);
    }

    private static async Task RunDeserializationScan(
        AutomationContext ctx, AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        result.ScannersRun.Add("deserialization-scan");
        try
        {
            var scan = await ctx.RunDeserializationScan(new DeserializationScanProbe.DeserializationScanOptions
            {
                MaxCandidates = MaxEp(options) + 3,
                TimeoutMs = options.TimeoutMs,
                IncludeFixedSinks = options.AllowGenericScaffold
            }, ct);

            foreach (var f in scan.Findings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = f.Category,
                    Severity = f.Severity,
                    Endpoint = f.Url,
                    Method = f.Method,
                    Title = $"Deserialization: {f.Signal} ({f.Variant})",
                    Detail = f.Detail,
                    Evidence = f.Variant
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"deserialization-scan: {ex.Message}");
        }
    }

    private static async Task RunFileUploadScan(
        AutomationContext ctx, AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        result.ScannersRun.Add("file-upload-scan");
        try
        {
            var scan = await ctx.RunFileUploadScan(new FileUploadScanProbe.FileUploadScanOptions
            {
                MaxCandidates = MaxEp(options) + 5,
                TimeoutMs = options.TimeoutMs,
                IncludeXxe = true
            }, ct);

            foreach (var f in scan.Findings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = f.Category,
                    Severity = f.Severity,
                    Endpoint = f.Url,
                    Method = "POST",
                    Title = $"File upload: {f.Variant}",
                    Detail = f.Detail
                });
            }

            foreach (var f in scan.XxeFindings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = f.Category,
                    Severity = f.Severity,
                    Endpoint = f.Url,
                    Method = "POST",
                    Title = $"Upload XXE: {f.Signal} ({f.Shape})",
                    Detail = f.Detail
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"file-upload-scan: {ex.Message}");
        }
    }

    private static async Task RunNextJsRscScan(
        AutomationContext ctx, AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        result.ScannersRun.Add("nextjs-rsc-scan");
        try
        {
            var scan = await ctx.RunNextJsRscScan(new NextJsRscScanProbe.NextJsRscScanOptions
            {
                TimeoutMs = Math.Min(options.TimeoutMs, 8000),
                RequireNextJsFingerprint = true
            }, ct);

            foreach (var f in scan.Findings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = f.Category,
                    Severity = f.Severity,
                    Endpoint = f.Url,
                    Method = "POST",
                    Title = $"Next.js RSC: {f.Variant}",
                    Detail = f.Detail
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"nextjs-rsc-scan: {ex.Message}");
        }
    }

    private static async Task RunParserProbeScan(
        AutomationContext ctx, AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        result.ScannersRun.Add("parser-probe");
        try
        {
            var probeResult = await ctx.RunParserProbe(new ParserProbe.ParserProbeOptions
            {
                MaxCandidates = MaxEp(options),
                TimeoutMs = options.TimeoutMs
            }, ct);

            foreach (var f in probeResult.Findings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = f.Category,
                    Severity = f.Severity,
                    Endpoint = f.Url,
                    Method = f.Method,
                    Title = $"Parser probe: {f.Signal} ({f.ProbeKind})",
                    Detail = f.Detail,
                    Evidence = f.ContentType ?? f.BodyVariant
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"parser-probe: {ex.Message}");
        }
    }

    private static async Task RunCmdCanaryScan(
        AutomationContext ctx,
        List<AttackSurfaceEndpoint> endpoints,
        AutoScanOptions options,
        AutoScanResult result,
        CancellationToken ct)
    {
        result.ScannersRun.Add("cmd-canary");
        try
        {
            var canaryOpts = new CmdCanaryProbe.CmdCanaryOptions
            {
                MaxCandidates = MaxEp(options),
                TimeoutMs = options.TimeoutMs,
                IncludeSstiTier = !options.UseSmartInjectionRouting,
                RestrictToCmdParams = options.UseSmartInjectionRouting && string.IsNullOrWhiteSpace(options.TargetUrl),
                IncludeCallback = false,
                IncludeTiming = false
            };

            // When targetUrl is set, always probe that endpoint's injectable params with cmd canaries
            // (id / whoami / ;id) — do not rediscover unrelated surfaces from the network log.
            if (!string.IsNullOrWhiteSpace(options.TargetUrl)
                && TryBuildCmdCanaryTemplate(endpoints, options, out var tpl))
            {
                canaryOpts.UrlTemplate = tpl.UrlTemplate;
                canaryOpts.BodyTemplate = tpl.BodyTemplate;
                canaryOpts.Method = tpl.Method;
                canaryOpts.ParamName = tpl.ParamName;
                canaryOpts.Headers = tpl.Headers;
                canaryOpts.RestrictToCmdParams = false;
            }

            var canaryResult = await ctx.RunCmdCanary(canaryOpts, ct);

            result.EndpointsScanned += canaryResult.CandidatesProbed;

            foreach (var f in canaryResult.Findings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = f.Category,
                    Severity = f.Severity,
                    Endpoint = f.Url,
                    Method = f.Method,
                    Title = $"Cmd canary ({f.Tier}): '{f.ParamName}' — {f.Indicator}",
                    Detail = $"{f.Detail} Payload: {f.Payload}. HTTP {f.Status}.",
                    NextActions = f.Category is "command-injection" or "rce-indicator"
                        ?
                        [
                            SecurityNextActions.VerifyWorkflow,
                            SecurityNextActions.VerifyCmdCanaryStub(f.Url, f.ParamName, f.Payload)
                        ]
                        : []
                });
            }

            if (canaryResult.Partial)
            {
                result.Partial = true;
                result.BudgetExhausted = true;
                result.Errors.Add(
                    $"cmd-canary: partial results flushed ({canaryResult.Findings.Count} finding(s)) after budget/cancel.");
            }
        }
        catch (OperationCanceledException)
        {
            result.Partial = true;
            throw;
        }
        catch (Exception ex)
        {
            result.Errors.Add($"cmd-canary: {ex.Message}");
        }
    }

    private static bool TryBuildCmdCanaryTemplate(
        List<AttackSurfaceEndpoint> endpoints,
        AutoScanOptions options,
        out (string UrlTemplate, string? BodyTemplate, string Method, string ParamName, Dictionary<string, string>? Headers) tpl)
    {
        tpl = default;
        var ep = endpoints.FirstOrDefault();
        if (ep == null && !string.IsNullOrWhiteSpace(options.TargetUrl))
        {
            // Synthesize a minimal endpoint from the explicit target URL.
            ep = new AttackSurfaceEndpoint
            {
                Url = options.TargetUrl!.Trim(),
                Methods = string.IsNullOrWhiteSpace(options.TargetMethod)
                    ? new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "GET" }
                    : new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    {
                        options.TargetMethod!.Trim().ToUpperInvariant()
                    }
            };
            if (Uri.TryCreate(ep.Url, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Query))
            {
                foreach (var key in System.Web.HttpUtility.ParseQueryString(uri.Query).AllKeys)
                {
                    if (!string.IsNullOrEmpty(key))
                        ep.Parameters.Query.Add(key);
                }
            }
        }

        if (ep == null) return false;

        // Prefer cmd-hint params, then any query/body param.
        var preferred = ep.Parameters.Query
            .Concat(ep.Parameters.Body)
            .OrderByDescending(p => InjectionPointDiscovery.CmdParamHintSet.Contains(p) ? 1 : 0)
            .FirstOrDefault();

        if (preferred != null && ep.Parameters.Query.Contains(preferred))
        {
            tpl = (
                AppendMarkerToUrl(ep.Url, preferred).Replace("§sqli§", "§INJECT§", StringComparison.Ordinal),
                null,
                ep.Methods.Contains("GET") ? "GET" : ep.Methods.FirstOrDefault() ?? "GET",
                preferred,
                null);
            return true;
        }

        if (preferred != null && ep.Parameters.Body.Contains(preferred))
        {
            var method = ep.Methods.FirstOrDefault(m => m is "POST" or "PUT" or "PATCH")
                         ?? ep.Methods.FirstOrDefault() ?? "POST";
            var body = BuildBodyTemplateWithMarker(ep, preferred).Replace("§sqli§", "§INJECT§", StringComparison.Ordinal);
            Dictionary<string, string>? headers = null;
            if (IsFormBodyEndpoint(ep))
                headers = new Dictionary<string, string> { ["Content-Type"] = "application/x-www-form-urlencoded" };
            else
                headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" };

            tpl = (ep.Url, body, method, preferred, headers);
            return true;
        }

        if (Uri.TryCreate(ep.Url, UriKind.Absolute, out var targetUri))
        {
            // No discovered params — inject a synthetic command=§INJECT§ query param.
            var sep = string.IsNullOrEmpty(targetUri.Query) ? "?" : "&";
            tpl = (
                ep.Url + sep + "command=§INJECT§",
                null,
                ep.Methods.Contains("GET") ? "GET" : ep.Methods.FirstOrDefault() ?? "GET",
                "command",
                null);
            return true;
        }

        return false;
    }

    private static async Task RunNosqlScan(
        AutomationContext ctx, AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        result.ScannersRun.Add("nosql");
        try
        {
            var scanResult = await ctx.RunNosqlScan(new NosqlScanProbe.NosqlScanOptions
            {
                MaxCandidates = MaxEp(options),
                TimeoutMs = options.TimeoutMs,
                SparseThreshold = options.SparseInjectionThreshold,
                UseSmartRouting = options.UseSmartInjectionRouting,
                ScanDepth = options.ScanDepth,
                MaxPayloads = Depth(options).Name == AutoScanDepthProfile.Quick ? 8 : 0,
                PayloadProfile = options.PayloadProfile,
                IncludeScaffold = options.AllowGenericScaffold
            }, ct);

            result.EndpointsScanned += scanResult.CandidatesProbed;

            foreach (var f in scanResult.Findings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "nosql",
                    Severity = f.Severity,
                    Endpoint = f.Url,
                    Method = f.Method,
                    Title = $"NoSQL injection via '{f.ParamName}'",
                    Detail = $"{f.Detail} Payload: {f.Payload}. HTTP {f.Status}."
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"nosql: {ex.Message}");
        }
    }

    private static async Task RunLdapScan(
        AutomationContext ctx, AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        result.ScannersRun.Add("ldap");
        try
        {
            var scanResult = await ctx.RunLdapScan(new LdapScanProbe.LdapScanOptions
            {
                MaxCandidates = MaxEp(options),
                TimeoutMs = options.TimeoutMs,
                IncludeScaffold = options.AllowGenericScaffold
            }, ct);

            result.EndpointsScanned += scanResult.CandidatesProbed;

            foreach (var f in scanResult.Findings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "ldap",
                    Severity = f.Severity,
                    Endpoint = f.Url,
                    Method = "POST",
                    Title = "LDAP injection auth bypass suspected",
                    Detail = f.Detail
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"ldap: {ex.Message}");
        }
    }

    private static async Task RunSqliLoginSweepScan(
        AutomationContext ctx, AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        result.ScannersRun.Add("sqli-login-sweep");
        try
        {
            var sweepResult = await ctx.RunSqliLoginSweep(new SqliLoginSweep.SqliLoginSweepOptions
            {
                MaxLoginUrls = MaxEp(options) + 4,
                TimeoutMs = options.TimeoutMs,
                IncludeScaffold = options.AllowGenericScaffold
            }, ct);

            foreach (var f in sweepResult.Findings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "sqli-login-sweep",
                    Severity = f.Severity,
                    Endpoint = f.Url,
                    Method = "POST",
                    Title = $"SQLi login bypass ({f.Signal}) via '{f.UsernameField}'",
                    Detail = $"{f.Evidence} Payload: {f.Payload} ({f.Shape})."
                });
            }

            result.EndpointsScanned += sweepResult.LoginUrlsProbed;
        }
        catch (Exception ex)
        {
            result.Errors.Add($"sqli-login-sweep: {ex.Message}");
        }
    }

    private static async Task<int> RunSqliScaffoldScanAsync(
        AutomationContext ctx,
        string origin,
        AutoScanOptions options,
        AutoScanResult result,
        HashSet<string> seenSqliFindings,
        CancellationToken ct)
    {
        var scanned = 0;
        var seenTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var tpl in InjectionScaffold.EnumerateSqliScaffold().Take(Depth(options).SqliScaffoldCap))
        {
            ct.ThrowIfCancellationRequested();
            var urlTemplate = InjectionScaffold.BuildUrl(origin, tpl.PathQueryTemplate, "§sqli§");
            var targetId = urlTemplate.Split('?', 2)[0];
            if (!seenTargets.Add(targetId)) continue;

            try
            {
                var sqliResult = await HttpSecurityProbes.RunSqliScanAsync(
                    ctx, urlTemplate, tpl.Method, null, null,
                    baselineMarkerValue: "1", customPayloads: null,
                    includeTimeBased: false, timeoutMs: options.TimeoutMs,
                    maxBodyChars: 32768, useBackendFetch: true,
                    includeBrowserCookies: true, includeOrmClosurePayloads: false, ct,
                    payloadProfile: options.PayloadProfile);

                scanned++;
                foreach (var row in sqliResult.Rows.Where(r => r.Types.Count > 0))
                {
                    foreach (var sqliType in row.Types.Distinct(StringComparer.OrdinalIgnoreCase))
                    {
                        if (!ShouldPromoteSqliTypeToFinding(sqliType, row))
                            continue;

                        var dedupKey = SqliFindingDedupKey(targetId, tpl.Method, tpl.ParamName, sqliType);
                        if (!seenSqliFindings.Add(dedupKey)) continue;

                        var sevRow = ResolveSqliSeverityForType(sqliType, row);
                        var observed = InjectionScaffoldFindingPolicy.IsPathObservedInTraffic(
                            ctx.Network.Entries, targetId, origin);
                        var (scaffoldSev, scaffoldPrefix, scaffoldSuffix) =
                            InjectionScaffoldFindingPolicy.AdjustScaffoldInjectionSeverity(
                                sevRow.Severity, sevRow.TitlePrefix, observed);
                        result.Findings.Add(new AutoScanFinding
                        {
                            Scanner = "sqli",
                            Severity = scaffoldSev,
                            Endpoint = targetId,
                            Method = tpl.Method,
                            Title = $"{scaffoldPrefix}SQL injection scaffold ({sqliType}) via '{tpl.ParamName}'",
                            Detail = $"Sparse-traffic ALWAYS_PROBED template. Payload: {row.Payload}.{scaffoldSuffix ?? ""}",
                            Evidence = BuildSqliEvidenceBundle(sqliResult, row)
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                result.Errors.Add($"sqli-scaffold {targetId}: {ex.Message}");
            }
        }

        return scanned;
    }

    private sealed class SqliProbe
    {
        public string UrlTemplate { get; init; } = "";
        public string? BodyTemplate { get; init; }
        public string Method { get; init; } = "GET";
        public string ParamName { get; init; } = "";
        public Dictionary<string, string>? Headers { get; init; }
    }

    private static readonly string[] SqliSiblingQueryParams =
    [
        "query", "q", "search", "id", "count", "filter", "name", "term", "keyword", "s",
        // Common alias amplification when traffic only shows one param name
        "cmd", "command", "path", "url", "template", "file"
    ];

    /// <summary>
    /// Sibling spray for XSS only — search/reflection aliases.
    /// Excludes cmd/path/file/url/template which produce sibling-param attribution FPs
    /// ("XSS via path" when only <c>q</c> reflects).
    /// </summary>
    private static readonly string[] XssSiblingQueryParams =
    [
        "query", "q", "search", "filter", "name", "term", "keyword", "s", "text", "message", "comment"
    ];

    /// <summary>
    /// Common header sinks to try when traffic has few/no custom headers but the endpoint
    /// looks API-like. Does not hardcode app-specific names — only widely reused proxies/identity headers.
    /// </summary>
    private static readonly string[] CommonInjectableHeaderAliases =
    [
        "x-forwarded-for", "x-real-ip", "x-user", "x-user-id", "x-original-url", "x-rewrite-url"
    ];

    private static bool LooksLikeInjectableSearchPath(string pathHint)
    {
        if (string.IsNullOrWhiteSpace(pathHint)) return false;
        var p = pathHint.ToLowerInvariant();
        return p.Contains("/search", StringComparison.Ordinal)
               || p.Contains("/products", StringComparison.Ordinal)
               || p.Contains("/lookup", StringComparison.Ordinal)
               || p.Contains("/find", StringComparison.Ordinal)
               || p.Contains("/api/", StringComparison.Ordinal);
    }

    private static List<SqliProbe> BuildSqliProbes(AttackSurfaceEndpoint ep) =>
        BuildInjectionProbes(ep, forXss: false);

    private static List<SqliProbe> BuildXssProbes(AttackSurfaceEndpoint ep) =>
        BuildInjectionProbes(ep, forXss: true);

    private static List<SqliProbe> BuildInjectionProbes(AttackSurfaceEndpoint ep, bool forXss)
    {
        var probes = new List<SqliProbe>();
        const int maxProbesPerEndpoint = 5;

        var pathHint = string.IsNullOrEmpty(ep.UrlTemplate) ? ep.Url : ep.UrlTemplate;
        // Reserve slots for inventoried custom headers BEFORE sibling query spray fills the budget
        // (otherwise /api/* paths never reach x-*-class header sinks under a05a).
        var inventoriedHeaders = ep.Parameters.Headers
            .Where(h => !h.Equals("content-type", StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var reservedHeaderSlots = Math.Min(2, inventoriedHeaders.Count > 0 ? inventoriedHeaders.Count : 0);
        var queryBudget = Math.Max(1, maxProbesPerEndpoint - reservedHeaderSlots);

        // Sibling-param mutation only when the endpoint already has query params or looks searchable —
        // avoid spraying every /api/* path when headers/body are the real sinks.
        var seedParams = ep.Parameters.Query.AsEnumerable();
        var allowSiblings = ep.Parameters.Query.Count > 0
            || (LooksLikeInjectableSearchPath(pathHint)
                && inventoriedHeaders.Count == 0
                && ep.Parameters.Body.Count == 0
                && !LooksLikeRawBodyTemplateSink(ep));
        if (allowSiblings)
            seedParams = seedParams.Concat(forXss ? XssSiblingQueryParams : SqliSiblingQueryParams);

        var scanner = forXss ? "xss" : "sqli";
        var queryParams = seedParams
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(p => InjectionParamClassifier.AllowsScanner(
                InjectionParamClassifier.Classify(p, pathHint), scanner,
                InjectionParamClassifier.IsLoginEndpoint(pathHint)))
            .OrderByDescending(p => forXss
                ? InjectionParamClassifier.XssLikelihoodScore(p)
                : InjectionParamClassifier.SqliLikelihoodScore(p))
            .Take(queryBudget)
            .ToList();

        foreach (var param in queryParams)
        {
            var url = AppendMarkerToUrl(ep.Url, param);
            var probe = new SqliProbe
            {
                UrlTemplate = url,
                Method = ep.Methods.Contains("GET") ? "GET" : ep.Methods.First(),
                ParamName = param
            };
            if (ProbeHasInjectionMarker(probe))
                probes.Add(probe);
        }

        // Inventoried headers next (guaranteed reserved slots).
        AppendHeaderProbes(ep, probes, inventoriedHeaders, maxProbesPerEndpoint);

        if (probes.Count >= maxProbesPerEndpoint)
            return probes;

        if (IsFormBodyEndpoint(ep) && ep.Parameters.Body.Count > 0)
        {
            var method = ep.Methods.FirstOrDefault(m => m is "POST" or "PUT" or "PATCH") ?? ep.Methods.First();
            var (headers, bodyBuilder) = ResolveBodyFormat(ep);

            foreach (var param in ep.Parameters.Body.Take(maxProbesPerEndpoint - probes.Count))
            {
                var body = bodyBuilder(ep, param);
                var probe = new SqliProbe
                {
                    UrlTemplate = ep.Url,
                    BodyTemplate = body,
                    Method = method,
                    ParamName = param,
                    Headers = headers
                };
                if (ProbeHasInjectionMarker(probe))
                    probes.Add(probe);
            }
        }
        else if (HasJsonStringFields(ep) && !string.IsNullOrEmpty(ep.Parameters.RequestBodySample))
        {
            var method = ep.Methods.FirstOrDefault(m => m is "POST" or "PUT" or "PATCH") ?? ep.Methods.First();
            var headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" };
            var jsonFields = GetJsonStringFieldNames(ep.Parameters.RequestBodySample);

            foreach (var field in jsonFields.Take(maxProbesPerEndpoint - probes.Count))
            {
                var body = BuildJsonBodyWithMarker(ep.Parameters.RequestBodySample, field);
                if (body != null)
                {
                    var probe = new SqliProbe
                    {
                        UrlTemplate = ep.Url,
                        BodyTemplate = body,
                        Method = method,
                        ParamName = field,
                        Headers = headers
                    };
                    if (ProbeHasInjectionMarker(probe))
                        probes.Add(probe);
                }
            }
        }
        else if (ep.Parameters.Body.Count > 0)
        {
            var method = ep.Methods.FirstOrDefault(m => m is "POST" or "PUT" or "PATCH") ?? ep.Methods.First();
            var (headers, bodyBuilder) = ResolveBodyFormat(ep);

            foreach (var param in ep.Parameters.Body.Take(maxProbesPerEndpoint - probes.Count))
            {
                var body = bodyBuilder(ep, param);
                var probe = new SqliProbe
                {
                    UrlTemplate = ep.Url,
                    BodyTemplate = body,
                    Method = method,
                    ParamName = param,
                    Headers = headers
                };
                if (ProbeHasInjectionMarker(probe))
                    probes.Add(probe);
            }
        }

        // Raw text/plain (or empty CT) body on template-like paths — SSTI/cmd sinks often accept the whole body.
        if (probes.Count < maxProbesPerEndpoint && LooksLikeRawBodyTemplateSink(ep)
            && !probes.Any(p => p.ParamName.Equals("body", StringComparison.OrdinalIgnoreCase)
                                && !string.IsNullOrEmpty(p.BodyTemplate)))
        {
            var method = ep.Methods.FirstOrDefault(m => m is "POST" or "PUT" or "PATCH") ?? "POST";
            var probe = new SqliProbe
            {
                UrlTemplate = ep.Url.Split('?', 2)[0],
                BodyTemplate = "§sqli§",
                Method = method,
                ParamName = "body",
                Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Content-Type"] = "text/plain"
                }
            };
            if (ProbeHasInjectionMarker(probe))
                probes.Add(probe);
        }

        // Common header aliases only after real inventory + body probes.
        if (probes.Count < maxProbesPerEndpoint
            && (LooksLikeInjectableSearchPath(pathHint) || inventoriedHeaders.Count > 0))
        {
            AppendHeaderProbes(ep, probes, CommonInjectableHeaderAliases, maxProbesPerEndpoint);
        }

        return probes;
    }

    private static void AppendHeaderProbes(
        AttackSurfaceEndpoint ep,
        List<SqliProbe> probes,
        IEnumerable<string> headerNames,
        int maxProbesPerEndpoint)
    {
        if (probes.Count >= maxProbesPerEndpoint) return;
        var method = ep.Methods.Contains("GET") && !ep.Methods.Any(m => m is "POST" or "PUT" or "PATCH")
            ? "GET"
            : (ep.Methods.FirstOrDefault(m => m is "GET" or "POST" or "PUT" or "PATCH") ?? ep.Methods.First());
        var seen = new HashSet<string>(
            probes.Where(p => p.Headers != null).Select(p => p.ParamName),
            StringComparer.OrdinalIgnoreCase);

        foreach (var headerName in headerNames)
        {
            if (probes.Count >= maxProbesPerEndpoint) break;
            if (string.IsNullOrWhiteSpace(headerName)) continue;
            if (headerName.Equals("content-type", StringComparison.OrdinalIgnoreCase)) continue;
            if (!seen.Add(headerName)) continue;

            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [headerName] = "§sqli§"
            };
            var probe = new SqliProbe
            {
                UrlTemplate = ep.Url.Split('?', 2)[0],
                Method = method,
                ParamName = headerName,
                Headers = headers
            };
            if (ProbeHasInjectionMarker(probe))
                probes.Add(probe);
        }
    }

    private static bool LooksLikeRawBodyTemplateSink(AttackSurfaceEndpoint ep)
    {
        var pathHint = string.IsNullOrEmpty(ep.UrlTemplate) ? ep.Url : ep.UrlTemplate;
        if (!InjectionParamClassifier.LooksLikeTemplateEndpoint(pathHint))
            return false;

        var ct = ep.Parameters.RequestContentType ?? "";
        if (ct.Contains("json", StringComparison.OrdinalIgnoreCase)
            || ct.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase)
            || ct.Contains("multipart", StringComparison.OrdinalIgnoreCase))
        {
            // Still allow when sample looks like a bare template string.
            var sample = ep.Parameters.RequestBodySample?.TrimStart() ?? "";
            if (sample.StartsWith('{') || sample.StartsWith('[') || sample.Contains('='))
                return false;
        }

        return ep.Methods.Any(m => m is "POST" or "PUT" or "PATCH")
               || !string.IsNullOrEmpty(ep.Parameters.RequestBodySample);
    }

    private static bool ProbeHasInjectionMarker(SqliProbe probe) =>
        RequestMarkerSubstitute.ListMarkers(probe.UrlTemplate, probe.BodyTemplate, probe.Headers).Count > 0;

    private static bool IsFormBodyEndpoint(AttackSurfaceEndpoint ep)
    {
        var ct = ep.Parameters.RequestContentType ?? "";
        if (ct.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase))
            return true;
        return LooksLikeFormUrlEncodedSample(ep.Parameters.RequestBodySample);
    }

    private static bool LooksLikeFormUrlEncodedSample(string? sample)
    {
        if (string.IsNullOrWhiteSpace(sample)) return false;
        var trimmed = sample.TrimStart();
        if (trimmed.StartsWith('{') || trimmed.StartsWith('[')) return false;
        if (trimmed.StartsWith("--", StringComparison.Ordinal)) return false;
        if (!trimmed.Contains('=')) return false;

        foreach (var part in trimmed.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part.IndexOf('=') <= 0)
                return false;
        }

        return true;
    }

    private static (Dictionary<string, string>? headers, Func<AttackSurfaceEndpoint, string, string> builder)
        ResolveBodyFormat(AttackSurfaceEndpoint ep)
    {
        var ct = ep.Parameters.RequestContentType ?? "";
        if (ct.Contains("json", StringComparison.OrdinalIgnoreCase) &&
            LooksLikeFormUrlEncodedSample(ep.Parameters.RequestBodySample))
            ct = "application/x-www-form-urlencoded";

        if (ct.Contains("json", StringComparison.OrdinalIgnoreCase))
            return (new Dictionary<string, string> { ["Content-Type"] = "application/json" }, BuildBodyTemplateWithMarker);

        if (ct.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase) ||
            LooksLikeFormUrlEncodedSample(ep.Parameters.RequestBodySample))
            return (new Dictionary<string, string> { ["Content-Type"] = "application/x-www-form-urlencoded" },
                BuildFormEncodedBodyWithMarker);

        // text/plain / template raw body — whole body is the injection point (SSTI Content-Type matrix expands).
        if (ct.Contains("text/plain", StringComparison.OrdinalIgnoreCase)
            || ct.Contains("text/template", StringComparison.OrdinalIgnoreCase)
            || LooksLikeRawBodyTemplateSink(ep)
            || ep.Parameters.Body.Any(b => b.Equals("body", StringComparison.OrdinalIgnoreCase)))
        {
            return (new Dictionary<string, string> { ["Content-Type"] = "text/plain" },
                static (_, _) => "§sqli§");
        }

        return (null, BuildBodyTemplateWithMarker);
    }

    private static string BuildFormEncodedBodyWithMarker(AttackSurfaceEndpoint ep, string paramName)
    {
        if (!string.IsNullOrEmpty(ep.Parameters.RequestBodySample))
        {
            var qs = System.Web.HttpUtility.ParseQueryString(ep.Parameters.RequestBodySample);
            var parts = new List<string>();
            var replaced = false;
            foreach (string? key in qs)
            {
                if (key == null) continue;
                if (key.Equals(paramName, StringComparison.OrdinalIgnoreCase))
                {
                    parts.Add($"{Uri.EscapeDataString(key)}=§sqli§");
                    replaced = true;
                }
                else
                {
                    parts.Add($"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(qs[key] ?? "")}");
                }
            }
            if (!replaced)
                parts.Add($"{Uri.EscapeDataString(paramName)}=§sqli§");
            return string.Join("&", parts);
        }

        return $"{Uri.EscapeDataString(paramName)}=§sqli§";
    }

    private static bool HasJsonStringFields(AttackSurfaceEndpoint ep)
    {
        if (string.IsNullOrEmpty(ep.Parameters.RequestBodySample))
            return false;
        if (string.IsNullOrEmpty(ep.Parameters.RequestContentType) ||
            !ep.Parameters.RequestContentType.Contains("json", StringComparison.OrdinalIgnoreCase))
            return false;
        return GetJsonStringFieldNames(ep.Parameters.RequestBodySample).Count > 0;
    }

    private static bool HasInjectableSurface(AttackSurfaceEndpoint ep) =>
        ep.Parameters.Query.Count > 0
        || ep.Parameters.Body.Count > 0
        || ep.Parameters.Headers.Count > 0
        || HasJsonStringFields(ep)
        || LooksLikeRawBodyTemplateSink(ep);

    private static List<string> GetJsonStringFieldNames(string jsonBody)
    {
        var fields = new List<string>();
        try
        {
            using var doc = JsonDocument.Parse(jsonBody);
            if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    if (prop.Value.ValueKind == JsonValueKind.String)
                        fields.Add(prop.Name);
                }
            }
        }
        catch { }
        return fields;
    }

    private static string? BuildJsonBodyWithMarker(string jsonBody, string fieldName)
    {
        try
        {
            using var doc = JsonDocument.Parse(jsonBody);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return null;

            var dict = new Dictionary<string, object>();
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (prop.Name.Equals(fieldName, StringComparison.OrdinalIgnoreCase))
                    dict[prop.Name] = "§sqli§";
                else
                    dict[prop.Name] = JsonElementToObject(prop.Value);
            }
            if (!dict.ContainsKey(fieldName))
                dict[fieldName] = "§sqli§";
            return JsonSerializer.Serialize(dict);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// When traffic only shows a REST collection URL (for example <c>/api/widgets</c>) without a numeric child segment,
    /// synthesize <c>/api/widgets/§id§</c> so IDOR probes can still run.
    /// </summary>
    private static string? TryInferCollectionIdorTemplate(AttackSurfaceEndpoint ep)
    {
        if (!Uri.TryCreate(ep.Url, UriKind.Absolute, out var uri))
            return null;

        var path = uri.AbsolutePath.TrimEnd('/');
        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length != 2)
            return null;

        if (!segments[0].Equals("api", StringComparison.OrdinalIgnoreCase) &&
            !segments[0].Equals("rest", StringComparison.OrdinalIgnoreCase))
            return null;

        var resource = segments[1];
        if (!Regex.IsMatch(resource, @"^[\w-]+$"))
            return null;

        if (IdorInferBlockedResources.Contains(resource))
            return null;

        var newPath = path + "/§id§";
        return uri.GetLeftPart(UriPartial.Authority) + newPath + uri.Query;
    }

    private static async Task RunIdorScan(
        AutomationContext ctx, List<AttackSurfaceEndpoint> endpoints,
        AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        var documentRoot = SpaShellGuard.FindDocumentRootEndpoint(endpoints);
        SpaShellGuard.ShellFingerprint? originShell = null;
        try
        {
            var pageUrl = await ctx.GetCurrentUrl();
            if (Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri))
                originShell = await SpaShellGuard.CaptureOriginShellAsync(
                    ctx, pageUri.GetLeftPart(UriPartial.Authority), options.TimeoutMs);
        }
        catch
        {
            // Best-effort — IDOR still runs without shell fingerprint.
        }

        bool IsSpaFallbackCandidate(AttackSurfaceEndpoint ep) =>
            SpaShellGuard.IsAttackSurfaceSpaFallback(ep, documentRoot)
            || SpaShellGuard.IsScannerProbeArtifact(ep.Url);

        var pathOrdered = endpoints
            .Where(ep => ep.Parameters.Path.Count > 0 && !IsSpaFallbackCandidate(ep))
            .OrderByDescending(ep => PriorityRank(ep.TestPriority))
            .ToList();

        var inferredOrdered = endpoints
            .Where(ep => ep.Parameters.Path.Count == 0
                         && TryInferCollectionIdorTemplate(ep) != null
                         && !IsSpaFallbackCandidate(ep))
            .OrderByDescending(ep => PriorityRank(ep.TestPriority))
            .ToList();

        var candidates = new List<AttackSurfaceEndpoint>();
        foreach (var ep in pathOrdered)
        {
            if (candidates.Count >= MaxEp(options))
                break;
            candidates.Add(ep);
        }

        foreach (var ep in inferredOrdered)
        {
            if (candidates.Count >= MaxEp(options))
                break;
            candidates.Add(ep);
        }

        foreach (var ep in endpoints.Where(ep => ep.Parameters.Path.Count == 0))
        {
            if (TryInferCollectionIdorTemplate(ep) != null)
            {
                if (IsSpaFallbackCandidate(ep))
                {
                    result.SkippedEndpoints.Add(new SkippedEndpointInfo
                    {
                        Endpoint = AttackSurfaceMapper.FormatDisplayUrl(ep),
                        Scanner = "idor",
                        Reason = "SPA catch-all HTML shell or scanner probe artifact — not an ID-bearing API"
                    });
                }
                continue;
            }

            result.SkippedEndpoints.Add(new SkippedEndpointInfo
            {
                Endpoint = AttackSurfaceMapper.FormatDisplayUrl(ep), Scanner = "idor",
                Reason =
                    "no path parameters and URL does not match inferred REST collection pattern (/api/{resource} or /rest/{resource})"
            });
        }

        if (candidates.Count == 0)
        {
            result.ScannersSkipped.Add("idor (no path params)");
            return;
        }

        result.ScannersRun.Add("idor");
        var scanned = 0;

        foreach (var ep in candidates)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var urlTemplate = ReplacePathParamWithMarker(ep.Url);
                var templateInferredFromCollection = false;
                if (!urlTemplate.Contains("§id§"))
                {
                    var inferred = TryInferCollectionIdorTemplate(ep);
                    if (inferred != null)
                    {
                        urlTemplate = inferred;
                        templateInferredFromCollection = true;
                    }
                }

                if (!urlTemplate.Contains("§id§"))
                {
                    result.SkippedEndpoints.Add(new SkippedEndpointInfo
                    {
                        Endpoint = AttackSurfaceMapper.FormatDisplayUrl(ep), Scanner = "idor",
                        Reason = "could not locate numeric/GUID segment or infer /api/{resource}/{id} template"
                    });
                    continue;
                }

                var method = ep.Methods.Contains("GET") ? "GET" : ep.Methods.First();

                var idorResult = await HttpSecurityProbes.RunIdorScanAsync(
                    ctx, urlTemplate, method, null, null,
                    ids: ["1", "2", "999999", "0"],
                    timeoutMs: options.TimeoutMs,
                    methods: null,
                    inferMethodsFromNetwork: true,
                    includeMutatingProbes: options.IncludeIdorMutatingProbes,
                    readOnlyProbes: options.IdorReadOnlyProbes,
                    dryRun: false,
                    retainResponseBodiesForEvidence: true);

                scanned++;

                var distinctFingerprints = idorResult.Rows
                    .Select(r => r.Fingerprint)
                    .Distinct()
                    .Count();

                var ok200Rows = idorResult.Rows.Where(r => r.Status == 200).ToList();
                var distinctStrippedAmong200 = ok200Rows
                    .Select(r => r.StrippedEvidenceHash)
                    .Distinct()
                    .Count();

                var hasAuthDenial = idorResult.Rows.Any(r => r.Status is 401 or 403);
                var allProbesReturned200 = idorResult.Rows.Count > 0 &&
                    idorResult.Rows.All(r => r.Status == 200);

                var suppressInferredPublicResource =
                    templateInferredFromCollection && allProbesReturned200 && distinctFingerprints > 1;

                var suppressFrameworkNoiseOnly =
                    templateInferredFromCollection
                    && ok200Rows.Count >= 2
                    && distinctFingerprints > 1
                    && distinctStrippedAmong200 == 1;

                if (suppressInferredPublicResource || suppressFrameworkNoiseOnly)
                {
                    result.SkippedEndpoints.Add(new SkippedEndpointInfo
                    {
                        Endpoint = AttackSurfaceMapper.FormatDisplayUrl(ep),
                        Scanner = "idor",
                        Reason = suppressFrameworkNoiseOnly
                            ? "inferred /api/{collection}/{id}: raw fingerprints diverge but stripped-hash matches Next.js-flight-style noise suppression"
                            : "inferred collection ID path (/api/{resource}/{id}); all synthesized IDs returned HTTP 200 with different payloads (expected for many public resources — not flagged as IDOR)"
                    });
                    continue;
                }

                if (SpaShellGuard.AllIdorRowsAreSpaShell(idorResult.Rows, originShell))
                {
                    result.SkippedEndpoints.Add(new SkippedEndpointInfo
                    {
                        Endpoint = AttackSurfaceMapper.FormatDisplayUrl(ep),
                        Scanner = "idor",
                        Reason = "all ID probe responses are the SPA HTML shell (catch-all route), not distinct API resources"
                    });
                    continue;
                }

                if (distinctFingerprints > 1 && idorResult.Rows.Any(r => r.Status is >= 200 and < 300))
                {
                    var evidence = BuildIdorEvidenceBundle(idorResult);
                    result.Findings.Add(new AutoScanFinding
                    {
                        Scanner = "idor",
                        Severity = templateInferredFromCollection && !hasAuthDenial ? "medium" : "high",
                        Endpoint = AttackSurfaceMapper.FormatDisplayUrl(ep),
                        Method = method,
                        Title = templateInferredFromCollection && !hasAuthDenial
                            ? "Possible IDOR (inferred id segment): different responses for different IDs"
                            : "Potential IDOR: different responses for different IDs",
                        Detail = string.Join("; ", idorResult.Summary),
                        Evidence = evidence
                    });
                }
            }
            catch (Exception ex)
            {
                result.Errors.Add($"idor on {AttackSurfaceMapper.FormatDisplayUrl(ep)}: {ex.Message}");
            }
        }

        result.EndpointsScanned += scanned;
    }

    private static bool IsMassAssignmentContentType(string? contentType) =>
        !string.IsNullOrEmpty(contentType)
        && (contentType.Contains("json", StringComparison.OrdinalIgnoreCase)
            || contentType.Contains("x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase));

    private static async Task RunMassAssignmentScan(
        AutomationContext ctx, List<AttackSurfaceEndpoint> endpoints,
        AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        var candidates = endpoints
            .Where(ep =>
                ep.Methods.Any(m => m is "POST" or "PUT" or "PATCH") &&
                IsMassAssignmentContentType(ep.Parameters.RequestContentType) &&
                !string.IsNullOrEmpty(ep.Parameters.RequestBodySample))
            .Take(MaxEp(options))
            .ToList();

        foreach (var ep in endpoints.Except(candidates))
        {
            string reason;
            if (!ep.Methods.Any(m => m is "POST" or "PUT" or "PATCH"))
                reason = "no state-changing method (POST/PUT/PATCH)";
            else if (!IsMassAssignmentContentType(ep.Parameters.RequestContentType))
                reason = "not a JSON or form-urlencoded content-type";
            else if (string.IsNullOrEmpty(ep.Parameters.RequestBodySample))
                reason = "no captured request body sample";
            else
                reason = "exceeded maxEndpointsPerScanner limit";

            result.SkippedEndpoints.Add(new SkippedEndpointInfo
            {
                Endpoint = AttackSurfaceMapper.FormatDisplayUrl(ep), Scanner = "mass-assignment", Reason = reason
            });
        }

        if (candidates.Count == 0)
        {
            result.ScannersSkipped.Add("mass-assignment (no JSON or form-urlencoded POST/PUT/PATCH endpoints with body)");
            return;
        }

        result.ScannersRun.Add("mass-assignment");
        var scanned = 0;

        foreach (var ep in candidates)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var method = ep.Methods.FirstOrDefault(m => m is "POST" or "PUT" or "PATCH") ?? "POST";
                var jsonBody = ep.Parameters.RequestBodySample!;
                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Content-Type"] = ep.Parameters.RequestContentType ?? "application/json"
                };

                var maResult = await MassAssignmentProbes.RunAsync(
                    ctx, ep.Url, method, headers, jsonBody,
                    extraPrivilegedFields: null, timeoutMs: options.TimeoutMs,
                    verifyPersistence: options.MassAssignmentVerifyPersistence);

                scanned++;

                foreach (var probe in maResult.Probes.Where(p => p.ValueReflected || p.ValuePersisted == true))
                {
                    var persisted = probe.ValuePersisted == true;
                    result.Findings.Add(new AutoScanFinding
                    {
                        Scanner = "mass-assignment",
                        Severity = persisted ? "critical" : "high",
                        Endpoint = AttackSurfaceMapper.FormatDisplayUrl(ep),
                        Method = method,
                        Title = persisted
                            ? $"Mass assignment: '{probe.Field}' persisted after re-fetch"
                            : $"Mass assignment: '{probe.Field}' reflected",
                        Detail = persisted
                            ? $"Injected value persisted (verify GET {probe.VerifyFetchUrl}). Status: {probe.Status}."
                            : $"Injected value reflected in response. Status: {probe.Status}. Snippet: {probe.BodySnippet}"
                    });
                }
            }
            catch (Exception ex)
            {
                result.Errors.Add($"mass-assignment on {AttackSurfaceMapper.FormatDisplayUrl(ep)}: {ex.Message}");
            }
        }

        result.EndpointsScanned += scanned;
    }

    private static async Task RunMassAssignmentPatchScan(
        AutomationContext ctx, AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        try
        {
            var patch = await MassAssignmentExtendedProbes.RunPrivilegeEscalationPatchAsync(
                ctx, new MassAssignmentExtendedProbes.PatchProbeOptions
                {
                    TimeoutMs = options.TimeoutMs,
                    MaxFields = 8
                }, ct);
            result.ScannersRun.Add("mass-assignment-patch");
            foreach (var row in patch.Probes.Where(p => p.ValuePersisted))
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "mass-assignment-patch",
                    Severity = row.Severity,
                    Endpoint = row.Url,
                    Method = row.Method,
                    Title = $"Mass assignment persisted: {row.Field}",
                    Detail = $"PATCH/PUT accepted {row.Field}={row.InjectedValue}; verified via GET {row.VerifyUrl}."
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"mass-assignment-patch: {ex.Message}");
            result.ScannersSkipped.Add("mass-assignment-patch (error)");
        }
    }

    private static async Task RunMassAssignmentRegisterScan(
        AutomationContext ctx, AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        try
        {
            var reg = await MassAssignmentExtendedProbes.RunRegistrationScaffoldAsync(
                ctx, new MassAssignmentExtendedProbes.RegisterScaffoldOptions
                {
                    TimeoutMs = options.TimeoutMs,
                    MaxPaths = 4
                }, ct);
            result.ScannersRun.Add("mass-assignment-register");
            foreach (var row in reg.Findings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "mass-assignment-register",
                    Severity = row.Severity,
                    Endpoint = row.Url,
                    Method = "POST",
                    Title = $"Registration mass assignment: {row.Field}",
                    Detail = row.ValuePersisted == true
                        ? $"Field {row.Field} persisted after registration at {row.Url}."
                        : $"Field {row.Field} reflected in registration response."
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"mass-assignment-register: {ex.Message}");
            result.ScannersSkipped.Add("mass-assignment-register (error)");
        }
    }

    private static async Task RunBflaAdminScan(
        AutomationContext ctx, List<AttackSurfaceEndpoint> endpoints,
        AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        try
        {
            var bfla = await BflaAdminProbe.RunAsync(ctx, new BflaAdminProbe.ProbeOptions
            {
                TimeoutMs = options.TimeoutMs,
                MaxEndpoints = MaxEp(options) * 2,
                Endpoints = endpoints,
                DiscoverFromAttackSurface = true
            }, ct);
            result.ScannersRun.Add("bfla-admin");
            foreach (var row in bfla.Findings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "bfla-admin",
                    Severity = row.Severity,
                    Endpoint = row.Url,
                    Method = row.Method,
                    Title = "BFLA: admin endpoint accepted current session",
                    Detail = $"HTTP {row.Status} on {row.Method} {row.Url}. Body: {row.BodySnippet}"
                });
            }
            result.EndpointsScanned += bfla.EndpointsProbed.Count;
        }
        catch (Exception ex)
        {
            result.Errors.Add($"bfla-admin: {ex.Message}");
            result.ScannersSkipped.Add("bfla-admin (error)");
        }
    }

    private static string AppendMarkerToUrl(string url, string paramName)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url;

        var baseUrl = uri.GetLeftPart(UriPartial.Path);
        var qs = System.Web.HttpUtility.ParseQueryString(uri.Query);
        qs.Remove(paramName);

        var markerPart = $"{Uri.EscapeDataString(paramName)}=§sqli§";
        var existing = qs.ToString();
        return string.IsNullOrEmpty(existing)
            ? $"{baseUrl}?{markerPart}"
            : $"{baseUrl}?{existing}&{markerPart}";
    }

    private static string BuildBodyTemplateWithMarker(AttackSurfaceEndpoint ep, string paramName)
    {
        if (!string.IsNullOrEmpty(ep.Parameters.RequestBodySample))
        {
            var result = BuildJsonBodyWithMarker(ep.Parameters.RequestBodySample, paramName);
            if (result != null) return result;
        }
        return JsonSerializer.Serialize(new Dictionary<string, string> { [paramName] = "§sqli§" });
    }

    private static object JsonElementToObject(JsonElement el) => el.ValueKind switch
    {
        JsonValueKind.String => el.GetString() ?? "",
        JsonValueKind.Number => el.TryGetInt64(out var l) ? l : el.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null => "",
        _ => el.GetRawText()
    };

    private static string ReplacePathParamWithMarker(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url;

        var path = uri.AbsolutePath;
        path = Regex.Replace(
            path, @"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "§id§", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
        path = Regex.Replace(
            path, @"(?<=/)(\d+)(?=/|$)",
            "§id§", RegexOptions.None, TimeSpan.FromSeconds(1));

        return uri.GetLeftPart(UriPartial.Authority) + path + uri.Query;
    }

    private static string? BuildIdorEvidenceBundle(HttpSecurityProbes.IdorScanResult idorResult)
    {
        var baseline = idorResult.Rows.Where(r => r.Status is >= 200 and < 300).ToList();
        if (baseline.Count < 2) return null;

        HttpSecurityProbes.IdorRow? first = null;
        HttpSecurityProbes.IdorRow? second = null;
        foreach (var r in baseline)
        {
            if (first == null)
            {
                first = r;
                continue;
            }

            if (r.Fingerprint != first.Fingerprint)
            {
                second = r;
                break;
            }
        }

        if (first == null || second == null)
        {
            var a = baseline[0];
            var b = baseline.FirstOrDefault(x => x.Fingerprint != a.Fingerprint) ?? baseline[1];
            return
                $"{a.StrippedEvidenceHash}!={b.StrippedEvidenceHash} (stripped); raw {a.Fingerprint} vs {b.Fingerprint}. Response bodies truncated or unavailable for excerpt.";
        }

        var rawDiffHint =
            $"{first.StrippedEvidenceHash}!={second.StrippedEvidenceHash} (stripped) | raw {first.Fingerprint} vs {second.Fingerprint}";
        if (string.IsNullOrEmpty(first.BodySample) || string.IsNullOrEmpty(second.BodySample))
            return rawDiffHint + " (no retained body samples for diff excerpt)";
        var excerpt =
            ResponseBodySecurityHeuristics.BuildShortSecurityBodyDiffExcerpt(
                first.BodySample!, second.BodySample!);

        return rawDiffHint + "; excerpt: " + excerpt;
    }

    private static string SqliFindingDedupKey(string endpoint, string method, string paramName, string sqliType) =>
        $"{endpoint}|{method}|{paramName}|{sqliType}";

    /// <summary>
    /// Align auto-scan / playbook promotion with sqli-scan API: tentative blind-boolean stays in summary/rows only.
    /// </summary>
    internal static bool ShouldPromoteSqliTypeToFinding(string sqliType, HttpSecurityProbes.SqliScanRow row)
    {
        if (sqliType.Equals("blind-boolean-suspected", StringComparison.OrdinalIgnoreCase)
            && !row.Types.Contains("blind-boolean-confirmed", StringComparer.OrdinalIgnoreCase))
            return false;
        return true;
    }

    internal static (string Severity, string TitlePrefix) ResolveSqliSeverityForType(
        string sqliType, HttpSecurityProbes.SqliScanRow row)
    {
        // Keep parity with HttpSecurityProbes.BuildSqliFindings confidence gates:
        // unconfirmed boolean/time stay medium; only error/union/confirmed escalate hard.
        if (sqliType.Equals("blind-boolean-suspected", StringComparison.OrdinalIgnoreCase)
            && !row.Types.Contains("blind-boolean-confirmed", StringComparer.OrdinalIgnoreCase))
            return ("medium", "Suspected ");

        if (sqliType.Equals("time-based-suspected", StringComparison.OrdinalIgnoreCase))
            return ("medium", "Suspected ");

        if (sqliType.Equals("error-based", StringComparison.OrdinalIgnoreCase)
            || sqliType.Equals("union-leak-suspected", StringComparison.OrdinalIgnoreCase))
            return ("critical", "");

        // Length-diff alone is not CRITICAL. UNION stays critical only with a corroborating
        // signal (SQL error, leaked markers, or a row-count change reflection cannot explain).
        if (sqliType.Equals("union-based", StringComparison.OrdinalIgnoreCase))
        {
            if (row.LengthDeltaExplainedByReflection
                && row.SqlHits.Count == 0
                && !row.DataRowCountDiverged
                && !row.Types.Contains("union-leak-suspected", StringComparer.OrdinalIgnoreCase))
                return ("low", "Payload reflection explains the length delta — ");
            return ("critical", "");
        }

        // Confirmed boolean matches BuildSqliFindings (high), not CRITICAL.
        if (sqliType.Equals("blind-boolean-confirmed", StringComparison.OrdinalIgnoreCase)
            || sqliType.Equals("auth-bypass-suspected", StringComparison.OrdinalIgnoreCase))
            return ("high", "");

        if (sqliType.EndsWith("-suspected", StringComparison.OrdinalIgnoreCase))
        {
            var sample = string.IsNullOrEmpty(row.ProbeEvidenceSample)
                ? (row.Body ?? "")
                : row.ProbeEvidenceSample;
            if (ResponseBodySecurityHeuristics.BodySuggestsNextJsRscFlight(sample))
                return ("medium", "Heuristic-only on Next.js flight-like shell — ");
            return ("medium", "Suspected ");
        }

        return ("high", "");
    }

    private static string? BuildSqliEvidenceBundle(
        HttpSecurityProbes.SqliScanResult sqli, HttpSecurityProbes.SqliScanRow row)
    {
        if (string.IsNullOrEmpty(sqli.BaselineEvidenceSample) && string.IsNullOrEmpty(row.ProbeEvidenceSample))
            return null;

        var hashPart =
            $"strippedHash baseline={sqli.BaselineStrippedHash} probe={row.ProbeStrippedHash}";
        var excerpt = ResponseBodySecurityHeuristics.BuildShortSecurityBodyDiffExcerpt(
            sqli.BaselineEvidenceSample, row.ProbeEvidenceSample);
        return hashPart + "; excerpt: " + excerpt;
    }

    private static async Task RunCustomProbes(
        AutomationContext ctx, List<CustomProbe> probes,
        AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        result.ScannersRun.Add("custom-probes");
        int scanned = 0;

        foreach (var probe in probes)
        {
            ct.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(probe.Url) || string.IsNullOrWhiteSpace(probe.Name))
            {
                result.Errors.Add($"Custom probe skipped: missing 'name' or 'url'.");
                continue;
            }

            try
            {
                var json = await ctx.Fetch(probe.Url, probe.Method, probe.Headers, probe.Body, options.TimeoutMs);
                using var doc = JsonDocument.Parse(json);
                var status = doc.RootElement.TryGetProperty("status", out var s) ? s.GetInt32() : 0;
                var bodyText = doc.RootElement.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
                scanned++;

                var triggered = false;
                var details = new List<string>();

                if (probe.ExpectStatus.HasValue && status != probe.ExpectStatus.Value)
                {
                    triggered = true;
                    details.Add($"Expected status {probe.ExpectStatus.Value}, got {status}");
                }

                if (probe.FailIfBodyContains != null &&
                    bodyText.Contains(probe.FailIfBodyContains, StringComparison.OrdinalIgnoreCase))
                {
                    triggered = true;
                    details.Add($"Response contains '{probe.FailIfBodyContains}'");
                }

                if (probe.FailIfBodyMissing != null &&
                    !bodyText.Contains(probe.FailIfBodyMissing, StringComparison.OrdinalIgnoreCase))
                {
                    triggered = true;
                    details.Add($"Response missing expected '{probe.FailIfBodyMissing}'");
                }

                if (probe.FailIfStatusRange != null)
                {
                    var parts = probe.FailIfStatusRange.Split('-');
                    if (parts.Length == 2 && int.TryParse(parts[0], out var lo) && int.TryParse(parts[1], out var hi))
                    {
                        if (status >= lo && status <= hi)
                        {
                            triggered = true;
                            details.Add($"Status {status} is in fail range {probe.FailIfStatusRange}");
                        }
                    }
                }

                if (triggered)
                {
                    result.Findings.Add(new AutoScanFinding
                    {
                        Scanner = "custom-probe",
                        Severity = probe.Severity,
                        Endpoint = probe.Url,
                        Method = probe.Method,
                        Title = probe.Name,
                        Detail = string.Join("; ", details)
                    });
                }
            }
            catch (Exception ex)
            {
                result.Errors.Add($"Custom probe '{probe.Name}' on {probe.Url}: {ex.Message}");
            }
        }

        result.EndpointsScanned += scanned;
    }

    private static async Task RunRestScaffoldScan(
        AutomationContext ctx, AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        result.ScannersRun.Add("rest-scaffold");
        try
        {
            var scaffold = await RestScaffoldProbes.RunAsync(ctx, new RestScaffoldProbes.ScaffoldOptions
            {
                TimeoutMs = options.TimeoutMs
            }, ct);
            foreach (var row in scaffold.Findings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "rest-scaffold",
                    Severity = row.Severity,
                    Endpoint = row.Url,
                    Method = row.Method,
                    Title = row.Finding == "UNAUTH_USER_ENUM"
                        ? "Unauthenticated user enumeration via REST scaffold"
                        : "REST resource leaks without authentication",
                    Detail = row.Detail ?? row.Finding
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"rest-scaffold: {ex.Message}");
            result.ScannersSkipped.Add("rest-scaffold (error)");
        }
    }

    private static async Task RunJwtAcceptanceSweep(
        AutomationContext ctx, AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        result.ScannersRun.Add("jwt-acceptance-sweep");
        try
        {
            var sweep = await JwtAcceptanceSweep.RunAsync(ctx, new JwtAcceptanceSweep.SweepOptions
            {
                Host = options.Host,
                MaxEndpoints = MaxEp(options) * 3,
                TimeoutMs = options.TimeoutMs,
                ExcludeThirdParty = options.ExcludeThirdParty
            }, ct);
            foreach (var row in sweep.Rows.Where(r => r.Finding is "JWT_ALG_NONE_ACCEPTED" or "JWT_ALG_VARIANT_ACCEPTED" or "MISSING_AUTH"))
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "jwt-acceptance-sweep",
                    Severity = row.Severity,
                    Endpoint = row.Url,
                    Method = row.Method,
                    Title = row.Finding switch
                    {
                        "JWT_ALG_NONE_ACCEPTED" => "JWT alg:none accepted on protected endpoint",
                        "JWT_ALG_VARIANT_ACCEPTED" => $"JWT alg variant accepted ({row.VariantName})",
                        _ => "Sensitive endpoint reachable without authentication"
                    },
                    Detail = row.Detail ?? row.Finding
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"jwt-acceptance-sweep: {ex.Message}");
            result.ScannersSkipped.Add("jwt-acceptance-sweep (error)");
        }
    }

    private static async Task RunPathFilterBypassScan(
        AutomationContext ctx, AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        result.ScannersRun.Add("path-filter-bypass");
        try
        {
            var bypass = await PathFilterBypassChecker.RunAsync(ctx, new PathFilterBypassChecker.BypassOptions
            {
                TimeoutMs = options.TimeoutMs
            }, ct);
            foreach (var f in bypass.Findings)
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "path-filter-bypass",
                    Severity = "high",
                    Endpoint = f.BypassUrl,
                    Method = "GET",
                    Title = $"Path-filter bypass: {f.Payload}",
                    Detail = $"{f.Indicator} — baseline {f.BaselineStatus}, bypass {f.BypassStatus}"
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"path-filter-bypass: {ex.Message}");
            result.ScannersSkipped.Add("path-filter-bypass (error)");
        }
    }

    private static async Task RunAuthBypassPivotScan(
        AutomationContext ctx, AutoScanOptions options, AutoScanResult result, CancellationToken ct)
    {
        result.ScannersRun.Add("auth-bypass-pivot");
        try
        {
            var pivot = await AuthenticatedPivotService.RunAsync(ctx, new AuthenticatedPivotService.PivotOptions
            {
                Host = options.Host,
                MaxEndpoints = MaxEp(options) * 4,
                TimeoutMs = options.TimeoutMs
            }, ct);
            foreach (var row in pivot.Rows.Where(r => r.Outcome == "UNLOCKED"))
            {
                result.Findings.Add(new AutoScanFinding
                {
                    Scanner = "auth-bypass-pivot",
                    Severity = row.Severity,
                    Endpoint = row.Url,
                    Method = "GET",
                    Title = "Authenticated pivot unlocked protected endpoint",
                    Detail = row.Detail ?? row.Finding
                });
            }
        }
        catch (Exception ex)
        {
            result.Errors.Add($"auth-bypass-pivot: {ex.Message}");
            result.ScannersSkipped.Add("auth-bypass-pivot (error)");
        }
    }
}
