using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Collects password-reset / verification tokens from network traffic and analyzes entropy.
/// </summary>
public static class ResetTokenSampleCollector
{
    private static readonly Regex ResetUrlPattern = new(
        @"(?i)(reset.?password|password.?reset|forgot.?password|recover.?password|/reset|magic.?link|verify.?email|/recover|reset.?token|change.?password)",
        RegexOptions.Compiled);

    private static readonly Regex TokenQueryPattern = new(
        @"(?i)(?:^|[?&])(?:token|reset[_-]?token|code|otp|pin|verification[_-]?code)=([^&]{4,256})",
        RegexOptions.Compiled);

    private static readonly string[] TokenJsonFields =
    [
        "token", "resetToken", "reset_token", "verificationToken", "verification_token",
        "code", "otp", "pin", "resetCode", "reset_code", "magicToken", "magic_token"
    ];

    public sealed class CollectOptions
    {
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
        public List<string> ResetEndpointsSeen { get; init; } = [];
        public List<string> Recommendations { get; init; } = [];
    }

    public static async Task<CollectResult> CollectAndAnalyzeAsync(
        AutomationContext ctx,
        CollectOptions options,
        CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var url = await ctx.GetCurrentUrl();
        IEnumerable<NetworkEntry> networkEntries = options.PageNetworkOnly
            ? ctx.Network.PageEntries
            : ctx.Network.Entries;

        var historical = new List<string>();
        var sources = new List<string>();
        var endpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in networkEntries)
        {
            ct.ThrowIfCancellationRequested();
            if (!IsResetRelated(entry.Url, entry.Path)) continue;
            endpoints.Add(entry.Url);

            foreach (Match m in TokenQueryPattern.Matches(entry.Url))
            {
                var v = Uri.UnescapeDataString(m.Groups[1].Value);
                if (!string.IsNullOrWhiteSpace(v))
                {
                    historical.Add(v);
                    sources.Add($"query param on {entry.Path}");
                }
            }

            ExtractFromBody(entry.ResponseBody, historical, sources, entry.Path, response: true);
            ExtractFromBody(entry.RequestBody, historical, sources, entry.Path, response: false);

            if (entry.ResponseHeaders != null)
            {
                foreach (var h in entry.ResponseHeaders.Where(h =>
                             h.Key.Equals("set-cookie", StringComparison.OrdinalIgnoreCase)))
                {
                    foreach (var parsed in SetCookieHeaderParser.ParseHeaderValue(h.Value))
                    {
                        var name = parsed["name"]?.ToString() ?? "";
                        if (!IsResetTokenCookieName(name)) continue;
                        var v = parsed["value"]?.ToString();
                        if (!string.IsNullOrWhiteSpace(v))
                        {
                            historical.Add(v);
                            sources.Add($"Set-Cookie {name}");
                        }
                    }
                }
            }
        }

        if (options.ExtraSamples is { Count: > 0 })
        {
            historical.AddRange(options.ExtraSamples.Where(s => !string.IsNullOrWhiteSpace(s)));
            sources.Add($"extraSamples: {options.ExtraSamples.Count}");
        }

        historical = historical.Distinct(StringComparer.Ordinal).ToList();
        var minRequired = Math.Max(1, options.MinSamples);
        var minMet = historical.Count >= minRequired;
        var networkCount = historical.Count;

        var syntheticCookie = new Dictionary<string, object>
        {
            ["name"] = "resetToken",
            ["value"] = historical.FirstOrDefault() ?? ""
        };

        var analysis = new SessionIdAnalyzer().Analyze(
            url,
            [syntheticCookie],
            historical,
            minSamplesForPattern: minRequired,
            targetCookieName: "resetToken");

        var recommendations = new List<string>();
        if (historical.Count == 0)
        {
            recommendations.Add(
                "No reset/verification tokens found in the network log. Browse through forgot-password / reset flows first, or pass samples[] in the request.");
        }
        else if (!minMet)
        {
            recommendations.Add(
                $"Only {historical.Count} reset token sample(s) — need {minRequired} for reliable predictability analysis. Trigger multiple reset requests or pass samples[].");
        }

        return new CollectResult
        {
            Analysis = analysis,
            MinSamplesRequired = minRequired,
            MinSamplesMet = minMet,
            NetworkSampleCount = networkCount,
            TotalSampleCount = historical.Count,
            SampleSources = sources.Distinct(StringComparer.Ordinal).ToList(),
            ResetEndpointsSeen = endpoints.Take(12).ToList(),
            Recommendations = recommendations
        };
    }

    private static bool IsResetRelated(string url, string? path)
    {
        var text = $"{url} {path}";
        return ResetUrlPattern.IsMatch(text);
    }

    private static bool IsResetTokenCookieName(string name)
    {
        var lower = name.ToLowerInvariant();
        return lower.Contains("reset") || lower.Contains("verify") || lower.Contains("otp")
               || lower.Contains("magic") || lower is "token" or "code";
    }

    private static void ExtractFromBody(
        string? body,
        List<string> historical,
        List<string> sources,
        string? path,
        bool response)
    {
        if (string.IsNullOrWhiteSpace(body) || !body.TrimStart().StartsWith('{')) return;
        try
        {
            using var doc = JsonDocument.Parse(body.Length > 131_072 ? body[..131_072] : body);
            ExtractTokenFields(doc.RootElement, historical, sources, path, response);
        }
        catch { /* ignore */ }
    }

    private static void ExtractTokenFields(
        JsonElement el,
        List<string> historical,
        List<string> sources,
        string? path,
        bool response,
        string prefix = "")
    {
        if (el.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in el.EnumerateObject())
            {
                var name = prop.Name;
                var full = string.IsNullOrEmpty(prefix) ? name : $"{prefix}.{name}";
                if (TokenJsonFields.Any(f => name.Equals(f, StringComparison.OrdinalIgnoreCase))
                    && prop.Value.ValueKind == JsonValueKind.String)
                {
                    var v = prop.Value.GetString();
                    if (!string.IsNullOrWhiteSpace(v) && v.Length >= 4)
                    {
                        historical.Add(v);
                        sources.Add($"{(response ? "response" : "request")} JSON {full} on {path}");
                    }
                }
                else if (prop.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array)
                    ExtractTokenFields(prop.Value, historical, sources, path, response, full);
            }
        }
        else if (el.ValueKind == JsonValueKind.Array)
        {
            var i = 0;
            foreach (var item in el.EnumerateArray())
            {
                ExtractTokenFields(item, historical, sources, path, response, $"{prefix}[{i}]");
                i++;
            }
        }
    }
}
