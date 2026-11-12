using Trowser.Automation;

namespace Trowser.Security;

internal static class CostlyOperationsCompose
{
    public static IEnumerable<CostlyOperationsProbe.CostlyFinding> RunCheck(
        string checkId,
        CostlyOperationsRules.ScanContext ctx)
    {
        return checkId.ToLowerInvariant() switch
        {
            "compose-graphql" => ComposeGraphql(ctx),
            "compose-llm" => ComposeLlm(ctx),
            "compose-ssrf-fetch" => ComposeSsrfFetch(ctx),
            "compose-redos" => ComposeRedos(ctx),
            "compose-spec-unbounded" => ComposeSpecUnbounded(ctx),
            _ => []
        };
    }

    private static IEnumerable<CostlyOperationsProbe.CostlyFinding> ComposeGraphql(CostlyOperationsRules.ScanContext ctx)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in ctx.Entries.Where(x => x.IsSuccess))
        {
            if (!CostlyOperationsRules.LooksLikeGraphQl(e)) continue;
            if (!seen.Add(e.Url)) continue;
            yield return ComposeFinding(
                "compose-graphql", "costly-compose-graphql", "medium", "observed",
                "GraphQL endpoint — use dedicated query-cost analysis",
                e, null,
                "GraphQL single requests can be expensive (depth, aliases, batching).",
                e.Url,
                "Run graphql-analyze for depth, batching, and limit probes.",
                "graphql-analyze");
        }
    }

    private static IEnumerable<CostlyOperationsProbe.CostlyFinding> ComposeLlm(CostlyOperationsRules.ScanContext ctx)
    {
        foreach (var e in ctx.Entries.Where(x => x.IsSuccess))
        {
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var uri)) continue;
            if (!CostlyOperationsRules.LooksLikeLlmRoute(uri.AbsolutePath)) continue;
            var body = e.RequestBody ?? "";
            if (body.Contains("max_tokens", StringComparison.OrdinalIgnoreCase)
                || body.Contains("maxTokens", StringComparison.OrdinalIgnoreCase)
                || body.Contains("max_length", StringComparison.OrdinalIgnoreCase))
                continue;

            yield return ComposeFinding(
                "compose-llm", "costly-compose-llm", "medium", "inferred",
                "LLM route without max_tokens in captured body",
                e, null,
                "Completion/embed routes may allow unbounded token consumption per request.",
                uri.AbsolutePath,
                "Run llm-redteam-scan (consumption) with explicit caps in production.",
                "llm-redteam-scan");
        }
    }

    private static IEnumerable<CostlyOperationsProbe.CostlyFinding> ComposeSsrfFetch(CostlyOperationsRules.ScanContext ctx)
    {
        foreach (var e in ctx.Entries.Where(x => x.IsSuccess))
        {
            foreach (var (name, _) in ParseQuery(e.Url))
            {
                if (!CostlyOperationsRules.LooksLikeSsrfFetchParam(name)) continue;
                yield return ComposeFinding(
                    "compose-ssrf-fetch", "costly-compose-ssrf-fetch", "medium", "inferred",
                    "Server-side fetch parameter (cost and SSRF risk)",
                    e, name,
                    $"Parameter {name} may trigger upstream fetches — large responses per request.",
                    name,
                    "Validate URL allowlists and cap upstream bytes/time; see ssrf-scan.",
                    "ssrf-scan");
            }
        }
    }

    private static IEnumerable<CostlyOperationsProbe.CostlyFinding> ComposeRedos(CostlyOperationsRules.ScanContext ctx)
    {
        foreach (var ep in ctx.Surface.Endpoints)
        {
            var patternParams = ep.Parameters.Query
                .Concat(ep.Parameters.Body)
                .Where(p => p.Contains("regex", StringComparison.OrdinalIgnoreCase)
                            || p.Contains("pattern", StringComparison.OrdinalIgnoreCase)
                            || p.Equals("glob", StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (patternParams.Count == 0) continue;

            var rep = ctx.Entries.FirstOrDefault(x => x.Url == ep.Url)
                      ?? new NetworkEntry { Url = ep.Url, Method = "GET", StatusCode = 200 };
            yield return ComposeFinding(
                "compose-redos", "costly-compose-redos", "low", "inferred",
                "User-supplied pattern field (server may compile)",
                rep, patternParams[0],
                "Pattern parameters can be expensive when compiled or matched server-side.",
                string.Join(", ", patternParams),
                "Audit pattern handling; run redos-scan on injectable search fields.",
                "redos-scan");
        }
    }

    private static IEnumerable<CostlyOperationsProbe.CostlyFinding> ComposeSpecUnbounded(CostlyOperationsRules.ScanContext ctx)
    {
        var count = 0;
        foreach (var e in ctx.Entries.Where(x => x.IsSuccess && x.ResponseBody is { Length: > 100 }))
        {
            if (count >= ctx.MaxCandidates) yield break;
            if (!CostlyOperationsRules.OpenApiBodyLooksUnbounded(e.ResponseBody)) continue;
            count++;
            yield return ComposeFinding(
                "compose-spec-unbounded", "costly-spec-unbounded", "medium", "inferred",
                "Captured API spec lists arrays without maxItems",
                e, null,
                "OpenAPI/JSON Schema in traffic shows unbounded array fields — single requests may grow large.",
                Trunc(e.Url, 120),
                "Add maxItems/maxLength/maximum in API contracts and enforce server-side.",
                relatedProbe: null);
        }
    }

    private static CostlyOperationsProbe.CostlyFinding ComposeFinding(
        string checkId,
        string category,
        string severity,
        string confidence,
        string title,
        NetworkEntry e,
        string? parameter,
        string detail,
        string? evidence,
        string remediation,
        string? relatedProbe) => new()
    {
        CheckId = checkId,
        Category = category,
        Severity = severity,
        Confidence = confidence,
        Title = title,
        Endpoint = e.Url,
        Method = e.Method,
        Parameter = parameter,
        Detail = detail,
        Evidence = evidence,
        Remediation = remediation,
        RelatedProbe = relatedProbe,
        NetworkEntryId = e.Id
    };

    private static IEnumerable<KeyValuePair<string, string>> ParseQuery(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Query))
            yield break;
        foreach (var segment in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = segment.IndexOf('=');
            var name = eq >= 0 ? Uri.UnescapeDataString(segment[..eq]) : Uri.UnescapeDataString(segment);
            var value = eq >= 0 ? Uri.UnescapeDataString(segment[(eq + 1)..]) : "";
            yield return new KeyValuePair<string, string>(name, value);
        }
    }

    private static string Trunc(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
