using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Multi-endpoint CORS sweep using server-side probes (session cookies optional).
/// Complements single-page <see cref="CorsChecker"/> (in-browser XHR preflight).
/// </summary>
public static class CorsSweep
{
    public const string AttackerOrigin = "https://evil-cors-probe.trowser.test";

    public sealed class SweepOptions
    {
        public IReadOnlyList<string>? Urls { get; set; }
        public bool IncludeAttackSurfaceUrls { get; set; } = true;
        public bool IncludeDefaultCandidates { get; set; } = true;
        public int MaxUrls { get; set; } = 14;
        public int TimeoutMs { get; set; } = 12_000;
        public bool IncludeBrowserCookies { get; set; } = true;
        public bool IncludeCredentialsProbe { get; set; } = true;
        /// <summary>Wall-clock budget for the sweep (0 = no limit).</summary>
        public int MaxSeconds { get; set; }
    }

    public sealed class EndpointCorsResult
    {
        public string Url { get; init; } = "";
        public bool IsDocumentBaseline { get; init; }
        public bool IsSensitiveEndpoint { get; init; }
        public List<CorsFinding> Findings { get; init; } = [];
        public List<CorsFinding> Issues => Findings.Where(f => f.Severity.HasValue).ToList();
        public bool IsClean => Issues.Count == 0;
    }

    public sealed class SweepResult
    {
        public string DocumentUrl { get; init; } = "";
        public List<EndpointCorsResult> Endpoints { get; init; } = [];
        public List<CorsDivergence> Divergences { get; init; } = [];
        public List<CorsFinding> AllIssues { get; init; } = [];
        /// <summary>Issues grouped by root cause (policy signature) to reduce duplicate noise.</summary>
        public List<GroupedCorsIssue> GroupedIssues { get; init; } = [];
        public int UrlsSwept => Endpoints.Count(e => !e.IsDocumentBaseline);
        public List<object> SweepResults => Endpoints
            .Where(e => !e.IsDocumentBaseline)
            .Select(e => (object)new
            {
                url = e.Url,
                isSensitiveEndpoint = e.IsSensitiveEndpoint,
                isClean = e.IsClean,
                issueCount = e.Issues.Count,
                findings = e.Issues
            })
            .ToList();
        public bool IsClean => AllIssues.Count == 0;
        public int IssueCount => AllIssues.Count;
        public int NetworkUrlsIncluded { get; init; }
        public int ScaffoldUrlsIncluded { get; init; }
        public Dictionary<string, int> Sources { get; init; } = new();
        public bool BudgetExhausted { get; init; }
        public List<string> Warnings { get; init; } = [];
        public int CrossOriginNetworkUrlsIncluded { get; init; }
        public int SkippedDueToMaxUrls { get; init; }
    }

    public sealed class CorsDivergence
    {
        public string Url { get; init; } = "";
        public string Description { get; init; } = "";
        public string? DocumentSeverity { get; init; }
        public string? EndpointSeverity { get; init; }
    }

    public sealed record GroupedCorsIssue
    {
        public string RootCause { get; init; } = "";
        public string IssueType { get; init; } = "";
        public string? AllowOrigin { get; init; }
        public bool AllowCredentials { get; init; }
        public string Severity { get; init; } = "medium";
        public List<string> AffectedUrls { get; init; } = [];
        public int AffectedCount => AffectedUrls.Count;
    }

    private static readonly string[] SensitivePathTokens =
    [
        "login", "auth", "token", "whoami", "profile", "account", "user", "session", "me", "oauth"
    ];

    private static readonly System.Text.RegularExpressions.Regex JwtPattern =
        new(@"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.", System.Text.RegularExpressions.RegexOptions.Compiled,
            matchTimeout: TimeSpan.FromSeconds(1));

    internal static readonly string[] DefaultCandidatePaths =
    [
        "/",
        "/api/",
        "/api/users",
        "/api/me",
        "/api/profile",
        "/api/Users",
        "/rest/user/whoami",
        "/rest/user/login",
        "/api/account",
        "/me",
        "/whoami",
        "/graphql",
        "/api/v1/users",
        "/api/v2/users",
    ];

    public static async Task<SweepResult> RunAsync(
        AutomationContext ctx,
        CorsChecker documentChecker,
        SweepOptions options,
        CancellationToken ct = default)
    {
        var documentUrl = await ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(documentUrl) || !Uri.TryCreate(documentUrl, UriKind.Absolute, out var pageUri))
            throw new InvalidOperationException("Navigate to a page before running CORS sweep.");

        var origin = pageUri.GetLeftPart(UriPartial.Authority);
        var documentResult = await documentChecker.RunAsync();
        var endpoints = new List<EndpointCorsResult>
        {
            new()
            {
                Url = documentResult.Url,
                IsDocumentBaseline = true,
                Findings = documentResult.Findings
            }
        };

        var resolved = CorsSweepUrlResolver.Resolve(ctx, options, origin, documentUrl);
        var urls = resolved.Urls;
        var networkCount = resolved.NetworkUrlsIncluded;
        var scaffoldCount = resolved.ScaffoldUrlsIncluded;
        var sweepSw = System.Diagnostics.Stopwatch.StartNew();
        var budgetExhausted = false;
        foreach (var url in urls)
        {
            ct.ThrowIfCancellationRequested();
            if (options.MaxSeconds > 0 && sweepSw.Elapsed.TotalSeconds >= options.MaxSeconds)
            {
                budgetExhausted = true;
                break;
            }

            if (string.Equals(url, documentUrl, StringComparison.OrdinalIgnoreCase))
                continue;

            var (findings, isSensitive) = await ProbeUrlAsync(ctx, url, pageUri, options, ct);
            endpoints.Add(new EndpointCorsResult
            {
                Url = url,
                IsSensitiveEndpoint = isSensitive,
                Findings = findings
            });
        }

        var divergences = BuildDivergences(documentResult, endpoints);
        var allIssues = endpoints.SelectMany(e => e.Issues).ToList();
        var groupedIssues = GroupIssuesByRootCause(endpoints);

        return new SweepResult
        {
            DocumentUrl = documentUrl,
            Endpoints = endpoints,
            Divergences = divergences,
            AllIssues = allIssues,
            GroupedIssues = groupedIssues,
            NetworkUrlsIncluded = networkCount,
            ScaffoldUrlsIncluded = scaffoldCount,
            Sources = new Dictionary<string, int>
            {
                ["network"] = networkCount,
                ["scaffold"] = scaffoldCount,
                ["crossOriginNetwork"] = resolved.CrossOriginNetworkUrlsIncluded
            },
            BudgetExhausted = budgetExhausted,
            Warnings = resolved.Warnings,
            CrossOriginNetworkUrlsIncluded = resolved.CrossOriginNetworkUrlsIncluded,
            SkippedDueToMaxUrls = resolved.SkippedDueToMaxUrls
        };
    }

    public static async Task<(List<CorsFinding> Findings, bool IsSensitive)> ProbeUrlAsync(
        AutomationContext ctx,
        string url,
        Uri pageUri,
        SweepOptions options,
        CancellationToken ct)
    {
        var findings = new List<CorsFinding>();
        string? sampleBody = null;
        var probeOrigins = new (string Origin, string Label)[]
        {
            (AttackerOrigin, "arbitrary-origin"),
            ("null", "null-origin"),
            ($"https://attacker.{pageUri.Host}", "subdomain-attack"),
        };

        foreach (var httpMethod in new[] { "GET", "POST" })
        {
            foreach (var (origin, label) in probeOrigins)
            {
                ct.ThrowIfCancellationRequested();
                var resp = await SecurityProbeHttp.FetchAsync(
                    ctx, url, httpMethod,
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Origin"] = origin },
                    httpMethod == "POST" ? "" : null,
                    options.TimeoutMs, options.IncludeBrowserCookies, ct);

                if (resp.Status == 0) continue;
                sampleBody ??= resp.Body ?? "";

                var acao = SecurityProbeHttp.GetResponseHeader(resp, "Access-Control-Allow-Origin") ?? "";
                var acac = (SecurityProbeHttp.GetResponseHeader(resp, "Access-Control-Allow-Credentials") ?? "")
                    .Equals("true", StringComparison.OrdinalIgnoreCase);
                var reflected = !string.IsNullOrEmpty(acao)
                    && acao.Equals(origin, StringComparison.OrdinalIgnoreCase);
                var wildcard = acao == "*";
                var sensitive = IsSensitiveEndpoint(url, resp.Body);

                Severity? severity = null;
                string? description = null;

                if (reflected && origin == "null")
                {
                    severity = sensitive ? Severity.High : Severity.High;
                    description = $"Server reflects 'null' origin on API endpoint ({httpMethod}).";
                }
                else if (reflected && acac)
                {
                    severity = Severity.Critical;
                    description = $"Server reflects origin '{origin}' with Allow-Credentials on {url} ({httpMethod}).";
                }
                else if (reflected)
                {
                    severity = sensitive ? Severity.High : Severity.Medium;
                    description = $"Server reflects origin '{origin}' on {url} ({httpMethod}).";
                }
                else if (wildcard && !string.IsNullOrEmpty(acao))
                {
                    severity = ClassifyWildcardSeverity(url, resp.Body, options.IncludeBrowserCookies);
                    description = sensitive
                        ? $"Wildcard CORS on sensitive endpoint {url} ({httpMethod}) — may expose tokens or user data cross-origin."
                        : $"Wildcard CORS on {url} ({httpMethod}).";
                }

                findings.Add(new CorsFinding
                {
                    Origin = origin,
                    Reflected = reflected,
                    Wildcard = wildcard,
                    AllowOrigin = string.IsNullOrEmpty(acao) ? null : acao,
                    AllowCredentials = acac,
                    Severity = severity,
                    Description = description
                });
            }
        }

        if (options.IncludeCredentialsProbe)
        {
            ct.ThrowIfCancellationRequested();
            var credResp = await SecurityProbeHttp.FetchAsync(
                ctx, url, "GET",
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Origin"] = AttackerOrigin },
                null, options.TimeoutMs, includeBrowserCookies: true, ct);

            if (credResp.Status != 0)
            {
                var acao = SecurityProbeHttp.GetResponseHeader(credResp, "Access-Control-Allow-Origin") ?? "";
                var acac = (SecurityProbeHttp.GetResponseHeader(credResp, "Access-Control-Allow-Credentials") ?? "")
                    .Equals("true", StringComparison.OrdinalIgnoreCase);
                var reflected = acao.Equals(AttackerOrigin, StringComparison.OrdinalIgnoreCase);
                var sensitive = IsSensitiveEndpoint(url, credResp.Body);

                Severity? severity = null;
                string? description = null;
                if (reflected && acac)
                {
                    severity = Severity.Critical;
                    description = $"Credentials probe: reflected origin with Access-Control-Allow-Credentials on {url}.";
                }
                else if (reflected)
                {
                    severity = sensitive ? Severity.High : Severity.Medium;
                    description = $"Credentials probe: reflected origin with session cookies on {url}.";
                }
                else if (acao == "*" && sensitive)
                {
                    severity = Severity.High;
                    description = $"Credentials probe: wildcard CORS on sensitive endpoint {url} with session cookies.";
                }

                if (severity != null)
                {
                    findings.Add(new CorsFinding
                    {
                        Origin = AttackerOrigin,
                        Reflected = reflected,
                        Wildcard = acao == "*",
                        AllowOrigin = string.IsNullOrEmpty(acao) ? null : acao,
                        AllowCredentials = acac,
                        Severity = severity,
                        Description = description
                    });
                }
            }
        }

        return (findings, IsSensitiveEndpoint(url, sampleBody));
    }

    private static Severity ClassifyWildcardSeverity(string url, string? body, bool withCookies)
    {
        if (IsSensitiveEndpoint(url, body))
            return Severity.High;
        if (withCookies && BodyLooksSensitive(body))
            return Severity.Medium;
        return Severity.Low;
    }

    private static bool IsSensitiveEndpoint(string url, string? body)
    {
        var lower = url.ToLowerInvariant();
        if (SensitivePathTokens.Any(t => lower.Contains(t, StringComparison.Ordinal)))
            return true;
        return BodyLooksSensitive(body);
    }

    private static bool BodyLooksSensitive(string? body)
    {
        if (string.IsNullOrEmpty(body)) return false;
        var lower = body.ToLowerInvariant();
        if (JwtPattern.IsMatch(body)) return true;
        return lower.Contains("\"token\"") || lower.Contains("authentication")
               || lower.Contains("password") || lower.Contains("apikey")
               || lower.Contains("authorization") || lower.Contains("secret");
    }

    private static List<CorsDivergence> BuildDivergences(
        CorsResult document,
        List<EndpointCorsResult> endpoints)
    {
        var docMax = document.Issues.Count == 0
            ? null
            : document.Issues.Max(f => f.Severity)?.ToString().ToLower();
        var divergences = new List<CorsDivergence>();

        foreach (var ep in endpoints.Where(e => !e.IsDocumentBaseline))
        {
            if (ep.IsClean && document.IsClean) continue;
            if (ep.IsClean != document.IsClean || ep.Issues.Count != document.Issues.Count)
            {
                divergences.Add(new CorsDivergence
                {
                    Url = ep.Url,
                    Description = ep.IsClean
                        ? "Stricter CORS than document baseline"
                        : "CORS misconfiguration on API endpoint not seen on document URL",
                    DocumentSeverity = docMax,
                    EndpointSeverity = ep.Issues.Count == 0
                        ? null
                        : ep.Issues.Max(f => f.Severity)?.ToString().ToLower()
                });
            }
        }

        return divergences;
    }

    /// <summary>
    /// Collapse per-endpoint CORS issues into root-cause groups (e.g. one global wildcard policy).
    /// </summary>
    public static List<GroupedCorsIssue> GroupIssuesByRootCause(IEnumerable<EndpointCorsResult> endpoints)
    {
        var groups = new Dictionary<string, (GroupedCorsIssue Issue, HashSet<string> Urls)>(StringComparer.Ordinal);

        foreach (var ep in endpoints)
        {
            foreach (var issue in ep.Issues.Where(i => i.Severity.HasValue))
            {
                var issueType = ClassifyIssueType(issue);
                var key = $"{issueType}|{issue.AllowOrigin ?? ""}|{issue.AllowCredentials}";

                if (!groups.TryGetValue(key, out var group))
                {
                    group = (new GroupedCorsIssue
                    {
                        IssueType = issueType,
                        AllowOrigin = issue.AllowOrigin,
                        AllowCredentials = issue.AllowCredentials,
                        Severity = issue.Severity!.Value.ToString().ToLowerInvariant(),
                        RootCause = BuildRootCauseTitle(issueType, issue)
                    }, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                    groups[key] = group;
                }

                group.Urls.Add(ep.Url);

                var currentSev = group.Issue.Severity;
                var newSev = issue.Severity!.Value.ToString().ToLowerInvariant();
                if (SeverityRank(newSev) > SeverityRank(currentSev))
                    groups[key] = (group.Issue with { Severity = newSev }, group.Urls);
            }
        }

        return groups.Values
            .Select(g => g.Issue with { AffectedUrls = g.Urls.OrderBy(u => u, StringComparer.OrdinalIgnoreCase).ToList() })
            .OrderByDescending(g => SeverityRank(g.Severity))
            .ThenByDescending(g => g.AffectedCount)
            .ToList();
    }

    private static string ClassifyIssueType(CorsFinding issue)
    {
        if (issue.Wildcard || issue.AllowOrigin == "*")
            return "wildcard-cors";

        var desc = issue.Description ?? "";
        if (desc.StartsWith("Credentials probe:", StringComparison.OrdinalIgnoreCase))
        {
            if (issue.Reflected && issue.AllowCredentials) return "reflected-with-credentials";
            if (issue.Reflected) return "reflected-with-session-cookies";
            return "credentials-probe-other";
        }

        if (issue.Origin.Equals("null", StringComparison.OrdinalIgnoreCase) && issue.Reflected)
            return "reflected-null-origin";
        if (issue.Reflected && issue.AllowCredentials)
            return "reflected-with-credentials";
        if (issue.Reflected)
            return "reflected-origin";

        return "other";
    }

    private static string BuildRootCauseTitle(string issueType, CorsFinding issue)
    {
        return issueType switch
        {
            "wildcard-cors" => issue.AllowOrigin == "*"
                ? "Global wildcard CORS policy (Access-Control-Allow-Origin: *)"
                : $"Wildcard CORS policy ({issue.AllowOrigin})",
            "reflected-null-origin" => "Server reflects null Origin (Access-Control-Allow-Origin: null)",
            "reflected-with-credentials" =>
                "Server reflects arbitrary Origin with Access-Control-Allow-Credentials: true",
            "reflected-with-session-cookies" =>
                "Server reflects arbitrary Origin with session cookies",
            "reflected-origin" => "Server reflects arbitrary Origin in Access-Control-Allow-Origin",
            _ => issue.Description ?? "CORS misconfiguration"
        };
    }

    private static int SeverityRank(string severity) => severity switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0
    };
}
