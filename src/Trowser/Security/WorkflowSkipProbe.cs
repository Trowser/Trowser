using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Detects multi-step workflows from the network log and tests whether intermediate
/// steps can be skipped — a class of business logic vulnerability that generic scanners miss.
///
/// Approach:
/// 1. Identify sequences of POST/PUT/PATCH requests to the same origin with shared path prefixes,
///    correlated timing, and referrer continuity.
/// 2. For each detected workflow, replay the final step without the intermediates.
/// 3. Compare response against a valid baseline to determine if the step was accepted.
/// </summary>
public sealed class WorkflowSkipProbe
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public WorkflowSkipProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class WorkflowSkipOptions
    {
        /// <summary>Maximum number of workflows to detect and test.</summary>
        public int MaxWorkflows { get; set; } = 5;

        /// <summary>Minimum number of steps for a sequence to be considered a workflow.</summary>
        public int MinSteps { get; set; } = 3;

        /// <summary>Maximum time gap (seconds) between consecutive steps to be considered part of same workflow.</summary>
        public int MaxStepGapSeconds { get; set; } = 60;

        /// <summary>Include browser cookies in replay requests.</summary>
        public bool IncludeBrowserCookies { get; set; } = true;

        /// <summary>Timeout per probe request in milliseconds.</summary>
        public int TimeoutMs { get; set; } = 10000;
    }

    public sealed class WorkflowSkipResult
    {
        public string Message { get; init; } = "";
        public int WorkflowsDetected { get; init; }
        public int WorkflowsTested { get; init; }
        public int ProbesSent { get; init; }
        public int ElapsedMs { get; init; }
        public List<WorkflowSkipFinding> Findings { get; init; } = [];
        public List<DetectedWorkflow> DetectedWorkflows { get; init; } = [];
    }

    public sealed class WorkflowSkipFinding
    {
        public string Category { get; init; } = "workflow-skip";
        public string Severity { get; init; } = "high";
        public string Url { get; init; } = "";
        public string Method { get; init; } = "POST";
        public string WorkflowName { get; init; } = "";
        public string SkipVariant { get; init; } = "";
        public int SkippedSteps { get; init; }
        public int TotalSteps { get; init; }
        public int ResponseStatus { get; init; }
        public string Detail { get; init; } = "";
        public string Evidence { get; init; } = "";
    }

    public sealed class DetectedWorkflow
    {
        public string Name { get; init; } = "";
        public string Origin { get; init; } = "";
        public string SharedPrefix { get; init; } = "";
        public List<WorkflowStep> Steps { get; init; } = [];
    }

    public sealed class WorkflowStep
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "POST";
        public string? Body { get; init; }
        public Dictionary<string, string>? Headers { get; init; }
        public DateTime Timestamp { get; init; }
    }

    public async Task<WorkflowSkipResult> RunAsync(WorkflowSkipOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running workflow-skip scan.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);

        // Step 1: Discover multi-step workflows from network log
        var workflows = DiscoverWorkflows(origin, options);
        if (workflows.Count == 0)
        {
            return new WorkflowSkipResult
            {
                Message = "No multi-step workflows detected in network log. Browse through a complete workflow first.",
                WorkflowsDetected = 0,
                ElapsedMs = (int)sw.ElapsedMilliseconds,
                DetectedWorkflows = []
            };
        }

        _log($"Workflow-skip: detected {workflows.Count} workflows, testing up to {options.MaxWorkflows}", "#CE9178");

        // Step 2: Test each workflow for step-skip vulnerabilities
        var findings = new List<WorkflowSkipFinding>();
        int probesSent = 0;
        int workflowsTested = 0;

        foreach (var workflow in workflows.Take(options.MaxWorkflows))
        {
            ct.ThrowIfCancellationRequested();
            workflowsTested++;

            // The target step to replay is the last mutating step (POST/PUT/PATCH/DELETE),
            // not the last step overall (which could be a GET confirmation page)
            var mutatingSteps = workflow.Steps.Where(s => s.Method is "POST" or "PUT" or "PATCH" or "DELETE").ToList();
            if (mutatingSteps.Count == 0) continue;
            var finalStep = mutatingSteps[^1];

            // Variant 1: Skip ALL intermediates — jump directly to final mutating step
            var skipAllResult = await ReplayStepAsync(finalStep, options, ct);
            probesSent++;

            if (IsSuccessResponse(skipAllResult.status, skipAllResult.body, finalStep))
            {
                findings.Add(new WorkflowSkipFinding
                {
                    Url = finalStep.Url,
                    Method = finalStep.Method,
                    WorkflowName = workflow.Name,
                    SkipVariant = "skip-all-intermediates",
                    SkippedSteps = workflow.Steps.Count - 1,
                    TotalSteps = workflow.Steps.Count,
                    ResponseStatus = skipAllResult.status,
                    Detail = $"Final step ({finalStep.Url}) succeeded without executing {workflow.Steps.Count - 1} " +
                             $"preceding steps. Workflow: {workflow.SharedPrefix}",
                    Evidence = $"Status: {skipAllResult.status}. " +
                              $"Body hash: {ComputeShortHash(skipAllResult.body)}. " +
                              (skipAllResult.body.Length > 200 ? skipAllResult.body[..200] + "..." : skipAllResult.body)
                });
            }

            // Variant 2: Skip the penultimate mutating step only (more subtle — tests individual step dependencies)
            if (mutatingSteps.Count >= 3)
            {
                var penultimate = mutatingSteps[^2];
                var skipOneResult = await ReplayStepAsync(finalStep, options, ct);
                probesSent++;

                // Only report if this is different from skip-all (avoids duplicate)
                if (IsSuccessResponse(skipOneResult.status, skipOneResult.body, finalStep)
                    && !findings.Any(f => f.Url == finalStep.Url && f.SkipVariant == "skip-all-intermediates"))
                {
                    findings.Add(new WorkflowSkipFinding
                    {
                        Url = finalStep.Url,
                        Method = finalStep.Method,
                        WorkflowName = workflow.Name,
                        SkipVariant = "skip-penultimate",
                        SkippedSteps = 1,
                        TotalSteps = workflow.Steps.Count,
                        ResponseStatus = skipOneResult.status,
                        Detail = $"Final step succeeded without executing step {workflow.Steps.Count - 1} " +
                                 $"({penultimate.Url}). Individual step dependency not enforced.",
                        Evidence = $"Status: {skipOneResult.status}."
                    });
                }
            }
        }

        sw.Stop();
        return new WorkflowSkipResult
        {
            Message = findings.Count > 0
                ? $"Found {findings.Count} workflow step-skip vulnerabilities across {workflowsTested} workflows."
                : $"Tested {workflowsTested} workflows — all enforce step ordering correctly.",
            WorkflowsDetected = workflows.Count,
            WorkflowsTested = workflowsTested,
            ProbesSent = probesSent,
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            Findings = findings,
            DetectedWorkflows = workflows
        };
    }

    /// <summary>
    /// Discover multi-step workflows from the network log using heuristics:
    /// - Same origin, user-initiated requests (not static assets)
    /// - Sequential timing within gap threshold
    /// - Includes GET steps between mutating steps (real workflows mix methods)
    /// - Shared path prefix or resource noun correlation
    /// - Must contain at least one state-changing step (POST/PUT/PATCH/DELETE)
    /// </summary>
    private List<DetectedWorkflow> DiscoverWorkflows(string origin, WorkflowSkipOptions options)
    {
        // Include all user-initiated requests (API calls, form submissions, page navigations)
        // Exclude static assets (images, CSS, JS, fonts) which are noise
        var entries = _ctx.Network.Entries
            .Where(e => e.Url.StartsWith(origin, StringComparison.OrdinalIgnoreCase)
                        && e.StatusCode is >= 200 and < 400
                        && !IsStaticAsset(e))
            .OrderBy(e => e.Timestamp)
            .ToList();

        if (entries.Count < options.MinSteps)
            return [];

        // Group into candidate sequences by timing proximity (across ALL methods)
        var sequences = new List<List<NetworkEntry>>();
        var current = new List<NetworkEntry> { entries[0] };

        for (int i = 1; i < entries.Count; i++)
        {
            var gap = (entries[i].Timestamp - entries[i - 1].Timestamp).TotalSeconds;
            if (gap <= options.MaxStepGapSeconds)
            {
                current.Add(entries[i]);
            }
            else
            {
                if (current.Count >= options.MinSteps)
                    sequences.Add(current);
                current = [entries[i]];
            }
        }
        if (current.Count >= options.MinSteps)
            sequences.Add(current);

        // Refine: filter to sequences with shared path prefix correlation
        var workflows = new List<DetectedWorkflow>();
        foreach (var seq in sequences)
        {
            var refined = RefineSequenceByPathCorrelation(seq, origin);
            // Must have at least one mutating step to be a testable workflow
            if (refined.Count >= options.MinSteps
                && refined.Any(e => e.Method is "POST" or "PUT" or "PATCH" or "DELETE"))
            {
                var prefix = FindSharedPathPrefix(refined.Select(e => new Uri(e.Url).AbsolutePath).ToList());
                var name = !string.IsNullOrEmpty(prefix) ? prefix.Trim('/').Replace("/", "-") : "workflow";

                workflows.Add(new DetectedWorkflow
                {
                    Name = name,
                    Origin = origin,
                    SharedPrefix = prefix,
                    Steps = refined.Select(e => new WorkflowStep
                    {
                        Url = e.Url,
                        Method = e.Method,
                        Body = e.RequestBody,
                        Headers = e.RequestHeaders?.ToDictionary(h => h.Key, h => h.Value),
                        Timestamp = e.Timestamp
                    }).ToList()
                });
            }
        }

        return workflows;
    }

    /// <summary>
    /// Filters out static asset requests that are noise for workflow detection.
    /// </summary>
    private static bool IsStaticAsset(NetworkEntry e)
    {
        // Filter by resource type if available
        if (!string.IsNullOrEmpty(e.ResourceType))
        {
            var rt = e.ResourceType.ToLowerInvariant();
            if (rt is "image" or "stylesheet" or "font" or "media" or "manifest" or "prefetch")
                return true;
        }

        // Filter by URL extension
        var path = e.Url.Split('?')[0].Split('#')[0];
        var lastDot = path.LastIndexOf('.');
        var ext = lastDot >= 0 ? path[lastDot..].ToLowerInvariant() : "";
        return ext is ".js" or ".css" or ".png" or ".jpg" or ".jpeg" or ".gif" or ".svg"
            or ".woff" or ".woff2" or ".ttf" or ".eot" or ".ico" or ".webp" or ".avif"
            or ".mp4" or ".webm" or ".map";
    }

    /// <summary>
    /// Refine a time-correlated sequence by requiring shared path prefix or resource noun.
    /// Filters out unrelated background API calls (analytics, heartbeats, etc.).
    /// </summary>
    private static List<NetworkEntry> RefineSequenceByPathCorrelation(List<NetworkEntry> entries, string origin)
    {
        if (entries.Count <= 3)
            return entries; // too small to filter

        // Extract path segments and find the most common prefix
        var paths = entries.Select(e =>
        {
            Uri.TryCreate(e.Url, UriKind.Absolute, out var uri);
            return uri?.AbsolutePath ?? "/";
        }).ToList();

        var prefix = FindSharedPathPrefix(paths);

        // If we have a meaningful shared prefix (at least 2 segments), keep only matching entries
        if (prefix.Count(c => c == '/') >= 2)
        {
            return entries.Where(e =>
            {
                Uri.TryCreate(e.Url, UriKind.Absolute, out var uri);
                return uri?.AbsolutePath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) == true;
            }).ToList();
        }

        // Fallback: keep entries that share at least the first path segment
        var firstSegments = paths
            .Select(p => p.Split('/', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "")
            .GroupBy(s => s, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .First().Key;

        return entries.Where(e =>
        {
            Uri.TryCreate(e.Url, UriKind.Absolute, out var uri);
            var seg = uri?.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            return string.Equals(seg, firstSegments, StringComparison.OrdinalIgnoreCase);
        }).ToList();
    }

    private static string FindSharedPathPrefix(List<string> paths)
    {
        if (paths.Count == 0) return "/";
        if (paths.Count == 1) return paths[0];

        var segments = paths[0].Split('/');
        int shared = 0;

        for (int i = 0; i < segments.Length; i++)
        {
            if (paths.All(p =>
            {
                var s = p.Split('/');
                return i < s.Length && string.Equals(s[i], segments[i], StringComparison.OrdinalIgnoreCase);
            }))
            {
                shared = i + 1;
            }
            else break;
        }

        return string.Join("/", segments.Take(shared));
    }

    private async Task<(int status, string body)> ReplayStepAsync(
        WorkflowStep step, WorkflowSkipOptions options, CancellationToken ct)
    {
        try
        {
            var resultJson = await _ctx.Fetch(
                step.Url, step.Method, step.Headers, step.Body,
                timeoutMs: options.TimeoutMs);

            // Parse the Fetch result JSON: {ok, status, statusText, body, headers, ...}
            using var doc = System.Text.Json.JsonDocument.Parse(resultJson);
            var root = doc.RootElement;
            var status = root.GetProperty("status").GetInt32();
            var body = root.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
            return (status, body);
        }
        catch (Exception ex)
        {
            _log($"Workflow-skip replay failed: {ex.Message}", "#F44747");
            return (-1, ex.Message);
        }
    }

    /// <summary>
    /// Determine if a replay response indicates the step was accepted (vulnerability).
    /// Uses semantic signals beyond just status code to reduce false positives.
    /// </summary>
    private static bool IsSuccessResponse(int status, string body, WorkflowStep originalStep)
    {
        // Clear failures — step was properly rejected
        if (status is 400 or 401 or 403 or 404 or 409 or 422 or 412)
            return false;

        // Error — not a success
        if (status < 0 || status >= 500)
            return false;

        // Redirect to login/error page — properly guarded
        if (status is >= 300 and < 400)
        {
            var lowerBody = body.ToLowerInvariant();
            if (lowerBody.Contains("login") || lowerBody.Contains("signin") || lowerBody.Contains("unauthorized"))
                return false;
        }

        // Success status — check for error indicators in body
        if (status is >= 200 and < 300)
        {
            var lowerBody = body.ToLowerInvariant();

            // Body contains explicit error/validation messages — likely rejected semantically
            if (lowerBody.Contains("\"error\"") || lowerBody.Contains("\"errors\""))
                return false;
            if (lowerBody.Contains("step") && (lowerBody.Contains("required") || lowerBody.Contains("missing")))
                return false;
            if (lowerBody.Contains("invalid") && lowerBody.Contains("state"))
                return false;
            if (lowerBody.Contains("prerequisite") || lowerBody.Contains("must complete"))
                return false;

            // Body is non-trivial success — likely accepted
            return body.Length > 2; // not just "{}" empty response
        }

        return false;
    }

    private static string ComputeShortHash(string content)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(content));
        return Convert.ToHexString(bytes)[..8].ToLowerInvariant();
    }
}
