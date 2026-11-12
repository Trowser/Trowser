using System.Globalization;
using Trowser.Automation;
using Trowser.Security;

namespace Trowser.Security.Orchestration;

/// <summary>
/// Computes playbook budgets from static tier tables, attack-surface metrics,
/// and network-log size. Used by dry-run previews and runtime budget floors.
/// </summary>
public static class PlaybookBudgetPlanner
{
    private const int LargeSurfaceEndpointThreshold = 20;
    private const int ClientTimeoutBufferPercent = 25;

    private sealed record BudgetTier(
        int StandardSeconds,
        int StandardRequests,
        int LargeSurfaceSeconds,
        int LargeSurfaceRequests,
        bool ScalesWithSurface = true);

    private static readonly Dictionary<string, BudgetTier> Tiers = new(StringComparer.OrdinalIgnoreCase)
    {
        ["a01-access"] = new(360, 800, 600, 1500),
        ["a02-misconfig"] = new(180, 800, 300, 1200),
        ["a03-supplychain"] = new(480, 1500, 720, 2200),
        ["a04-crypto"] = new(180, 800, 180, 800, ScalesWithSurface: false),
        ["a05-injection"] = new(1800, 3500, 2700, 5000),
        // Split A05 for LLM/agent sessions — same coverage when run as a series.
        ["a05a-injection-core"] = new(300, 800, 450, 1200),
        ["a05b-injection-templates"] = new(600, 1500, 900, 2200),
        ["a05c-injection-advanced"] = new(600, 1500, 900, 2200),
        ["a06-design"] = new(300, 1000, 450, 1500),
        ["a07-authn"] = new(600, 1800, 900, 2500),
        ["a09-opsec"] = new(180, 800, 300, 1200),
        ["a11-ssrf"] = new(180, 800, 300, 1200),
        ["a12-availability"] = new(300, 1000, 450, 1500),
        ["a13-llm"] = new(300, 800, 450, 1200),
        ["a14-other"] = new(600, 1500, 900, 2000),
        ["full"] = new(2400, 10000, 3600, 15000),
        ["quick"] = new(180, 900, 180, 900, ScalesWithSurface: false)
    };

    /// <summary>Snapshot of attack surface and network log used for dynamic budget sizing.</summary>
    public sealed class SurfaceSnapshot
    {
        public int NetworkLogEntries { get; init; }
        public int EndpointCount { get; init; }
        public int InjectableEndpointCount { get; init; }
        public int InjectableParamCount { get; init; }
        public double AverageResponseMs { get; init; }
        public double ComplexityScore { get; init; }
        public bool NetworkLogEmpty { get; init; }
    }

    public sealed class StepEstimate
    {
        public required string Name { get; init; }
        public int EstimatedSeconds { get; init; }
        public int EstimatedRequests { get; init; }
        public bool IncludedInTotal { get; init; } = true;
    }

    public sealed class BudgetPlan
    {
        public required BudgetLimits BaseRecommended { get; init; }
        public required BudgetLimits AdjustedRecommended { get; init; }
        public SurfaceSnapshot Surface { get; init; } = new();
        public int EstimatedCompletionSeconds { get; init; }
        public int SuggestedClientTimeoutSeconds { get; init; }
        public List<StepEstimate> StepEstimates { get; init; } = [];
        public List<string> Notes { get; init; } = [];
    }

    public static SurfaceSnapshot AnalyzeSurface(
        IReadOnlyList<NetworkEntry> networkEntries,
        string host,
        PlaybookScope scope)
    {
        var mapper = new AttackSurfaceMapper();
        var surface = mapper.Analyze(networkEntries.ToList(), includeAuth: true, hostFilter: host);
        surface = PlaybookScopeFilter.Apply(surface, scope);

        var endpoints = surface.Endpoints;
        var injectableEndpoints = CountInjectableEndpoints(endpoints);
        var injectableParams = CountInjectableParams(endpoints);
        var avgMs = ComputeAverageResponseMs(networkEntries, host);

        var complexity = Math.Max(1,
            endpoints.Count * Math.Max(1, injectableParams) * Math.Max(0.1, avgMs / 1000.0));

        return new SurfaceSnapshot
        {
            NetworkLogEntries = networkEntries.Count,
            EndpointCount = endpoints.Count,
            InjectableEndpointCount = injectableEndpoints,
            InjectableParamCount = injectableParams,
            AverageResponseMs = avgMs,
            ComplexityScore = complexity,
            NetworkLogEmpty = networkEntries.Count == 0 || surface.NetworkLogEmpty
        };
    }

    public static BudgetLimits GetBaseRecommended(string playbookId, PlaybookDepth depth)
    {
        var tier = ResolveTier(playbookId);
        return ScaleForDepth(new BudgetLimits
        {
            MaxSeconds = tier.StandardSeconds,
            MaxRequests = tier.StandardRequests
        }, depth);
    }

    public static BudgetPlan BuildPlan(
        string playbookId,
        PlaybookDepth depth,
        PlaybookRequest request,
        IReadOnlyList<DryRunStep> steps,
        SurfaceSnapshot? surface = null)
    {
        surface ??= new SurfaceSnapshot();
        var tier = ResolveTier(playbookId);
        var baseRecommended = GetBaseRecommended(playbookId, depth);
        var notes = new List<string>();

        var targetSeconds = baseRecommended.MaxSeconds;
        var targetRequests = baseRecommended.MaxRequests;

        if (tier.ScalesWithSurface && surface.EndpointCount >= LargeSurfaceEndpointThreshold)
        {
            var large = ScaleForDepth(new BudgetLimits
            {
                MaxSeconds = tier.LargeSurfaceSeconds,
                MaxRequests = tier.LargeSurfaceRequests
            }, depth);
            targetSeconds = Math.Max(targetSeconds, large.MaxSeconds);
            targetRequests = Math.Max(targetRequests, large.MaxRequests);
            notes.Add(
                $"Large attack surface ({surface.EndpointCount} endpoints): budget raised to large-site tier.");
        }
        else if (tier.ScalesWithSurface && surface.EndpointCount > 0)
        {
            var large = ScaleForDepth(new BudgetLimits
            {
                MaxSeconds = tier.LargeSurfaceSeconds,
                MaxRequests = tier.LargeSurfaceRequests
            }, depth);
            var t = Math.Clamp((surface.EndpointCount - 5.0) / (LargeSurfaceEndpointThreshold - 5.0), 0, 1);
            targetSeconds = (int)(targetSeconds + t * (large.MaxSeconds - targetSeconds));
            targetRequests = (int)(targetRequests + t * (large.MaxRequests - targetRequests));
            if (t > 0.05)
                notes.Add(
                    $"Attack surface ({surface.EndpointCount} endpoints, {surface.InjectableParamCount} injectable params): " +
                    $"budget scaled {t.ToString("P0", CultureInfo.InvariantCulture)} toward large-site tier.");
        }

        if (tier.ScalesWithSurface)
        {
            var responseFactor = Math.Clamp(surface.AverageResponseMs / 500.0, 0.75, 2.5);
            var paramFactor = Math.Clamp(surface.InjectableParamCount / 12.0, 0.85, 2.0);
            var complexityFactor = Math.Clamp(1.0 + Math.Log10(1.0 + surface.ComplexityScore / 50.0) * 0.15, 1.0, 1.5);
            var combined = responseFactor * paramFactor * complexityFactor;
            if (combined > 1.05)
            {
                targetSeconds = (int)(targetSeconds * combined);
                targetRequests = (int)(targetRequests * Math.Min(combined, 1.8));
                // ASCII-only + InvariantCulture: avoid locale commas (2,25) and × mojibake (�).
                notes.Add(
                    $"Dynamic surface factor {combined.ToString("F2", CultureInfo.InvariantCulture)}x " +
                    $"(avg response {surface.AverageResponseMs.ToString("F0", CultureInfo.InvariantCulture)}ms, " +
                    $"complexity {surface.ComplexityScore.ToString("F0", CultureInfo.InvariantCulture)}).");
            }
        }

        if (surface.NetworkLogEmpty)
        {
            notes.Add(
                request.IncludeCrawl
                    ? "Network log is empty — crawl-light will run first to populate traffic."
                    : "Network log is empty and crawl=false — browse key flows first for accurate dry-run estimates.");
        }
        else if (surface.NetworkLogEntries >= 500)
        {
            targetRequests = (int)(targetRequests * 1.25);
            notes.Add($"Large network log ({surface.NetworkLogEntries} entries): request budget +25%.");
        }
        else if (surface.NetworkLogEntries >= 200)
        {
            targetRequests = (int)(targetRequests * 1.15);
            notes.Add($"Moderate network log ({surface.NetworkLogEntries} entries): request budget +15%.");
        }

        var depthProfile = PlaybookDepthProfile.Resolve(depth);
        var stepEstimates = EstimateSteps(steps, depthProfile, surface, tier.ScalesWithSurface);
        var estimatedSeconds = stepEstimates.Where(s => s.IncludedInTotal).Sum(s => s.EstimatedSeconds);

        var adjusted = new BudgetLimits
        {
            MaxSeconds = Math.Max(Math.Max(baseRecommended.MaxSeconds, targetSeconds), estimatedSeconds),
            MaxRequests = Math.Max(baseRecommended.MaxRequests, targetRequests),
            Adaptive = request.Budget.Adaptive
        };

        estimatedSeconds = Math.Max(estimatedSeconds, adjusted.MaxSeconds);

        return new BudgetPlan
        {
            BaseRecommended = baseRecommended,
            AdjustedRecommended = adjusted,
            Surface = surface,
            EstimatedCompletionSeconds = estimatedSeconds,
            SuggestedClientTimeoutSeconds = estimatedSeconds +
                Math.Max(30, estimatedSeconds * ClientTimeoutBufferPercent / 100),
            StepEstimates = stepEstimates,
            Notes = notes
        };
    }

    public static List<DryRunStep> EnrichSteps(
        IReadOnlyList<DryRunStep> steps,
        IReadOnlyList<StepEstimate> estimates,
        BudgetLimits callerBudget)
    {
        var byName = estimates.ToDictionary(e => e.Name, StringComparer.OrdinalIgnoreCase);
        var enriched = new List<DryRunStep>(steps.Count);
        var cumulativeSeconds = 0;

        foreach (var step in steps)
        {
            byName.TryGetValue(step.Name, out var est);
            var skipped = step.SkippedByCurrentSafetyMode;
            var estSeconds = est?.EstimatedSeconds ?? 0;
            var estRequests = est?.EstimatedRequests ?? 0;

            if (!skipped)
                cumulativeSeconds += estSeconds;

            var skippedByBudget = !skipped &&
                                  cumulativeSeconds > callerBudget.MaxSeconds &&
                                  callerBudget.MaxSeconds > 0;

            enriched.Add(new DryRunStep
            {
                Name = step.Name,
                Description = step.Description,
                HttpVerbs = step.HttpVerbs,
                WritesSideEffects = step.WritesSideEffects,
                SkippedByCurrentSafetyMode = step.SkippedByCurrentSafetyMode,
                SkipReason = step.SkipReason,
                EstimatedSeconds = skipped ? 0 : estSeconds,
                EstimatedRequests = skipped ? 0 : estRequests,
                SkippedByBudget = skippedByBudget
            });
        }

        return enriched;
    }

    private static List<StepEstimate> EstimateSteps(
        IReadOnlyList<DryRunStep> steps,
        PlaybookDepthProfile depthProfile,
        SurfaceSnapshot surface,
        bool scalesWithSurface)
    {
        var surfaceScale = scalesWithSurface
            ? Math.Clamp(0.6 + surface.EndpointCount / 25.0, 0.6, 2.5)
            : 1.0;
        var depthScale = depthProfile.Depth switch
        {
            PlaybookDepth.Quick => 0.45,
            PlaybookDepth.Llm => 0.35,
            PlaybookDepth.Deep => 2.0,
            _ => 1.0
        };

        var list = new List<StepEstimate>(steps.Count);
        foreach (var step in steps)
        {
            var (baseSec, baseReq, scales) = StepProfile(step.Name);
            var sec = baseSec;
            var req = baseReq;

            if (step.Name == "crawl-light")
            {
                sec = Math.Max(20, (int)(depthProfile.MaxCrawlPages * 3.0));
                req = depthProfile.MaxCrawlPages;
            }
            else if (scales && scalesWithSurface)
            {
                sec = (int)(sec * surfaceScale * depthScale);
                req = (int)(req * surfaceScale * depthScale);
            }
            else
            {
                sec = (int)(sec * depthScale);
                req = (int)(req * depthScale);
            }

            list.Add(new StepEstimate
            {
                Name = step.Name,
                EstimatedSeconds = Math.Max(step.SkippedByCurrentSafetyMode ? 0 : 1, sec),
                EstimatedRequests = step.SkippedByCurrentSafetyMode ? 0 : req,
                IncludedInTotal = !step.SkippedByCurrentSafetyMode
            });
        }

        return list;
    }

    private static (int seconds, int requests, bool scalesWithSurface) StepProfile(string name) =>
        name switch
        {
            "crawl-light" => (45, 15, false),
            "attack-surface" => (3, 0, false),
            "client-surface" => (12, 2, false),
            "dom-xss-audit" => (25, 5, false),
            "dom-flows" => (20, 4, false),
            "storage-indexeddb" => (12, 0, false),
            "xs-leaks" => (45, 12, false),
            "trace-input" => (35, 8, false),
            "csti-scan" => (45, 15, true),
            "client-prototype-pollution" => (50, 20, false),
            "postmessage" => (20, 0, false),
            "firewall-test" => (15, 0, false),
            "security-headers" => (8, 3, false),
            "cookie-audit" => (5, 0, false),
            "source-maps" => (15, 20, false),
            "csrf-scan" => (40, 60, true),
            "idor-scan" => (120, 350, true),
            "mass-assignment-scan" => (60, 150, true),
            "bfla-admin-probe" => (30, 40, true),
            "authz-diff" => (90, 120, true),
            "authz-boundary" => (60, 80, true),
            "injection-scan" => (360, 900, true),
            "sqli-login-sweep" => (45, 80, true),
            "deserialization-scan" => (60, 100, true),
            "cors-sweep" => (40, 80, true),
            "endpoint-discover" => (90, 200, true),
            "http-methods" => (30, 50, true),
            "smuggling-passive" => (10, 5, false),
            "smuggling-active" => (120, 80, false),
            "host-header-scan" => (90, 60, true),
            "host-header-injection" => (90, 60, true),
            "open-redirect-scan" => (45, 60, true),
            "open-redirect" => (45, 60, true),
            "ssrf-scan" => (90, 120, true),
            "supply-chain-scan" => (120, 150, true),
            "secrets-harvest" => (60, 100, true),
            "firewall-sri" => (20, 15, false),
            "cache-identify" => (8, 0, false),
            "cache-map" => (30, 40, true),
            "cache-pollution" => (45, 50, true),
            "cache-poison-scan" => (60, 80, true),
            "cache-poison" => (60, 80, true),
            "cache-deception-scan" => (45, 60, true),
            "cache-deception" => (45, 60, true),
            "websocket-audit" => (30, 40, true),
            "sse-audit" => (15, 25, true),
            "jwt-analyze" => (20, 10, false),
            "oidc-analyze" => (45, 30, false),
            "oauth-flow-test" => (60, 40, true),
            "session-id-audit" => (15, 5, false),
            "graphql-analyze" => (90, 120, true),
            "rate-limit-probe" => (45, 80, true),
            "load-shape-probe" => (60, 100, true),
            "llm-prompt-injection" => (45, 30, true),
            "llm-discover" => (8, 0, false),
            "llm-redteam" => (180, 40, false),
            "rag-poison" => (90, 10, false),
            "unbounded-consumption" => (90, 20, false),
            "output-sink-trace" => (120, 15, false),
            "chain-correlate" => (10, 0, false),
            _ when name.StartsWith("playbook-", StringComparison.OrdinalIgnoreCase) => (180, 400, true),
            _ => (20, 30, true)
        };

    private static BudgetTier ResolveTier(string playbookId) =>
        Tiers.TryGetValue(playbookId, out var tier)
            ? tier
            : new BudgetTier(180, 800, 300, 1200);

    private static BudgetLimits ScaleForDepth(BudgetLimits standard, PlaybookDepth depth) => depth switch
    {
        PlaybookDepth.Quick => new BudgetLimits
        {
            MaxSeconds = Math.Max(30, standard.MaxSeconds * 2 / 5),
            MaxRequests = Math.Max(100, standard.MaxRequests * 7 / 20)
        },
        // Agent sessions: keep wall-clock in the 120–300s band for large playbooks.
        PlaybookDepth.Llm => new BudgetLimits
        {
            MaxSeconds = Math.Clamp(standard.MaxSeconds / 6, 120, 300),
            MaxRequests = Math.Clamp(standard.MaxRequests / 8, 80, 400)
        },
        PlaybookDepth.Deep => new BudgetLimits
        {
            MaxSeconds = standard.MaxSeconds * 5 / 2,
            MaxRequests = standard.MaxRequests * 2
        },
        _ => standard
    };

    private static int CountInjectableEndpoints(IEnumerable<AttackSurfaceEndpoint> endpoints) =>
        endpoints.Count(ep =>
            ep.Parameters.Query.Count > 0 ||
            ep.Parameters.Body.Count > 0 ||
            ep.Parameters.Headers.Count > 0 ||
            ep.Parameters.Path.Count > 0 ||
            InjectionParamClassifier.LooksLikeTemplateEndpoint(
                string.IsNullOrEmpty(ep.UrlTemplate) ? ep.Url : ep.UrlTemplate));

    private static int CountInjectableParams(IEnumerable<AttackSurfaceEndpoint> endpoints) =>
        endpoints.Sum(ep =>
            ep.Parameters.Query.Count +
            ep.Parameters.Body.Count +
            ep.Parameters.Headers.Count +
            ep.Parameters.Path.Count);

    private static double ComputeAverageResponseMs(IReadOnlyList<NetworkEntry> entries, string host)
    {
        var durations = entries
            .Where(e => e.DurationMs.HasValue && e.DurationMs.Value > 0)
            .Where(e => string.IsNullOrEmpty(host) ||
                        string.Equals(e.Host, host, StringComparison.OrdinalIgnoreCase))
            .Where(e => e.ResourceType is "Fetch" or "XHR" or "Document" or "Other")
            .Select(e => e.DurationMs!.Value)
            .ToList();

        if (durations.Count == 0)
        {
            durations = entries
                .Where(e => e.DurationMs.HasValue && e.DurationMs.Value > 0)
                .Select(e => e.DurationMs!.Value)
                .ToList();
        }

        return durations.Count > 0 ? durations.Average() : 300;
    }
}
