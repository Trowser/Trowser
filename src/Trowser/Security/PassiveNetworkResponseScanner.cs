using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Passive recall pass over captured network responses — SQL error signatures and stored XSS in HTML.
/// No outbound probes; registers findings for auto-scan and chain analysis.
/// </summary>
public static class PassiveNetworkResponseScanner
{
    public sealed class Options
    {
        public string? HostFilter { get; set; }
        public string? ScopeHost { get; set; }
        public bool ExcludeThirdParty { get; set; } = true;
    }

    public static List<AutoScanPipeline.AutoScanFinding> Scan(
        IReadOnlyList<NetworkEntry> entries,
        Options options)
    {
        var findings = new List<AutoScanPipeline.AutoScanFinding>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var scopeHost = options.ScopeHost ?? options.HostFilter;

        foreach (var entry in entries)
        {
            if (entry.ResponseBody == null || entry.ResponseBody.Length == 0)
                continue;
            if (entry.ResourceType is not ("Document" or "Fetch" or "XHR"))
                continue;
            if (!SecurityHostScope.EntryInScope(entry, options.HostFilter, scopeHost, options.ExcludeThirdParty))
                continue;

            var url = entry.Url;
            var queryParams = ExtractQueryParamNames(url);

            foreach (var sqlHit in ResponseBodySecurityHeuristics.DetectSqlErrorSignatures(entry.ResponseBody))
            {
                var key = $"sqli|{url}|{sqlHit.Pattern}";
                if (!seen.Add(key)) continue;

                var paramHint = queryParams.Count > 0
                    ? $" Parameter(s): {string.Join(", ", queryParams)}."
                    : "";
                findings.Add(new AutoScanPipeline.AutoScanFinding
                {
                    Scanner = "passive-network-recall",
                    Severity = entry.StatusCode >= 500 ? "high" : "medium",
                    Endpoint = url,
                    Method = entry.Method,
                    Title = $"SQL error signature in response ({sqlHit.Engine})",
                    Detail = $"Detected '{sqlHit.Pattern}' in captured response.{paramHint}",
                    Evidence = sqlHit.Snippet
                });
            }

            if (!entry.ContentType.Contains("html", StringComparison.OrdinalIgnoreCase)
                && entry.ResourceType != "Document")
                continue;

            foreach (var xssHit in ResponseBodySecurityHeuristics.DetectStoredXssInHtml(entry.ResponseBody))
            {
                var key = $"stored-xss|{url}|{xssHit.Pattern}";
                if (!seen.Add(key)) continue;

                findings.Add(new AutoScanPipeline.AutoScanFinding
                {
                    Scanner = "passive-network-recall",
                    Severity = "medium",
                    Endpoint = url,
                    Method = entry.Method,
                    Title = "Stored XSS indicator in HTML response (passive recall — confirm with DOM/stored XSS scan)",
                    Detail = $"Unencoded active content in {xssHit.Context} ({xssHit.Pattern}). Passive recall only — not a confirmed stored XSS finding.",
                    Evidence = xssHit.Snippet,
                    NextActions = [SecurityNextActions.VerifyWorkflow]
                });
            }
        }

        return findings;
    }

    private static List<string> ExtractQueryParamNames(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Query))
            return [];

        return uri.Query.TrimStart('?')
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=')[0])
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
