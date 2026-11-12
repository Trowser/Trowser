using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Collects session-ID samples from network Set-Cookie history before entropy analysis.
/// </summary>
public static class SessionIdSampleCollector
{
    public sealed class CollectOptions
    {
        public string? CookieName { get; set; }
        public int MinSamples { get; set; } = 2;
        public bool PageNetworkOnly { get; set; }
        public IReadOnlyList<string>? ExtraSamples { get; set; }
    }

    public sealed class CollectResult
    {
        public SessionIdAnalysisResult Analysis { get; init; } = new();
        public int MinSamplesRequired { get; init; }
        public bool MinSamplesMet { get; init; }
        public int NetworkSampleCount { get; init; }
        public int TotalSampleCount { get; init; }
        public List<string> SampleSources { get; init; } = [];
        public List<string> Recommendations { get; init; } = [];
    }

    public static async Task<CollectResult> CollectAndAnalyzeAsync(
        AutomationContext ctx,
        CollectOptions options,
        CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var url = await ctx.GetCurrentUrl();
        var cookies = await ctx.GetCookies();
        Security.CookieAuditChecker.MergeNetworkSetCookies(url, cookies, ctx.Network.Entries);

        IEnumerable<Automation.NetworkEntry> networkEntries = options.PageNetworkOnly
            ? ctx.Network.PageEntries
            : ctx.Network.Entries;

        var sessionCookies = cookies
            .Where(c => SessionCookieDetector.IsSessionCookieName(
                c.TryGetValue("name", out var n) ? n?.ToString() ?? "" : ""))
            .ToList();

        if (!string.IsNullOrWhiteSpace(options.CookieName))
        {
            sessionCookies = sessionCookies
                .Where(c =>
                {
                    var name = c.TryGetValue("name", out var n) ? n?.ToString() ?? "" : "";
                    return name.Equals(options.CookieName, StringComparison.OrdinalIgnoreCase);
                })
                .ToList();
        }

        var historicalByCookie = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var sources = new List<string>();

        foreach (var cookie in sessionCookies)
        {
            var name = cookie.TryGetValue("name", out var n) ? n?.ToString() ?? "" : "";
            if (string.IsNullOrEmpty(name)) continue;

            var cookieHistorical = new List<string>();
            var fromNet = SessionIdAnalyzer.CollectHistoricalValuesFromNetwork(networkEntries, name);
            if (fromNet.Count > 0)
                sources.Add($"network Set-Cookie ({name}): {fromNet.Count} value(s)");
            cookieHistorical.AddRange(fromNet);

            var current = cookie.TryGetValue("value", out var v) ? v?.ToString() : null;
            if (!string.IsNullOrEmpty(current))
                cookieHistorical.Add(current);

            historicalByCookie[name] = cookieHistorical.Distinct(StringComparer.Ordinal).ToList();
        }

        var networkCount = historicalByCookie.Values.SelectMany(v => v).Distinct(StringComparer.Ordinal).Count();

        if (options.ExtraSamples is { Count: > 0 })
        {
            var targetName = options.CookieName;
            if (string.IsNullOrWhiteSpace(targetName) && sessionCookies.Count > 0)
            {
                targetName = sessionCookies[0].TryGetValue("name", out var firstName)
                    ? firstName?.ToString()
                    : null;
            }

            if (!string.IsNullOrWhiteSpace(targetName))
            {
                if (!historicalByCookie.TryGetValue(targetName, out var extraList))
                {
                    extraList = [];
                    historicalByCookie[targetName] = extraList;
                }

                extraList.AddRange(options.ExtraSamples.Where(s => !string.IsNullOrWhiteSpace(s)));
                historicalByCookie[targetName] = extraList.Distinct(StringComparer.Ordinal).ToList();
            }

            sources.Add($"extraSamples: {options.ExtraSamples.Count}");
        }

        var totalSamples = historicalByCookie.Values.SelectMany(v => v).Distinct(StringComparer.Ordinal).Count();
        var minRequired = Math.Max(1, options.MinSamples);
        var minMet = totalSamples >= minRequired;

        var displayHints = CollectDisplayHints(cookies, networkEntries);

        var analysis = new SessionIdAnalyzer().Analyze(
            url,
            cookies,
            [],
            minSamplesForPattern: minRequired,
            targetCookieName: options.CookieName,
            historicalByCookieName: historicalByCookie.ToDictionary(
                kvp => kvp.Key,
                kvp => (IReadOnlyList<string>)kvp.Value),
            knownDisplayValues: displayHints);

        var recommendations = new List<string>();
        if (!minMet)
        {
            recommendations.Add(
                $"Only {totalSamples} distinct session sample(s) — need {minRequired} for reliable predictability analysis. " +
                "Browse through logout/login cycles or pass samples[] / extraSamples in the request.");
        }

        return new CollectResult
        {
            Analysis = analysis,
            MinSamplesRequired = minRequired,
            MinSamplesMet = minMet,
            NetworkSampleCount = networkCount,
            TotalSampleCount = totalSamples,
            SampleSources = sources,
            Recommendations = recommendations
        };
    }

    private static List<string> CollectDisplayHints(
        List<Dictionary<string, object>> cookies,
        IEnumerable<Automation.NetworkEntry> networkEntries)
    {
        var hints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in cookies)
        {
            var name = c.TryGetValue("name", out var n) ? n?.ToString() ?? "" : "";
            if (name.Contains("user", StringComparison.OrdinalIgnoreCase)
                || name.Contains("username", StringComparison.OrdinalIgnoreCase))
            {
                var val = c.TryGetValue("value", out var v) ? v?.ToString() : null;
                if (!string.IsNullOrEmpty(val))
                    hints.Add(val);
            }
        }

        foreach (var entry in networkEntries)
        {
            var body = entry.ResponseBody;
            if (string.IsNullOrEmpty(body) || body.Length > 50000) continue;
            if (!body.Contains("username", StringComparison.OrdinalIgnoreCase)
                && !body.Contains("userName", StringComparison.OrdinalIgnoreCase))
                continue;
            TryExtractJsonStringField(body, "username", hints);
            TryExtractJsonStringField(body, "userName", hints);
        }

        return hints.ToList();
    }

    private static void TryExtractJsonStringField(string json, string field, HashSet<string> hints)
    {
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty(field, out var el) && el.ValueKind == System.Text.Json.JsonValueKind.String)
            {
                var s = el.GetString();
                if (!string.IsNullOrEmpty(s))
                    hints.Add(s);
            }
        }
        catch
        {
            // ignore non-JSON bodies
        }
    }
}
