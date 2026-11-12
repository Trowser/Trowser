using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using Trowser.Automation;
using Trowser.Robustness;

namespace Trowser.Security;

/// <summary>
/// Safe differential probes for content-type confusion and parser disagreement on JSON endpoints.
/// </summary>
public sealed class ParserProbe
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public ParserProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class ParserProbeOptions
    {
        public string? Url { get; set; }
        public string? Method { get; set; }
        public Dictionary<string, string>? Headers { get; set; }
        public string? Body { get; set; }
        public int MaxCandidates { get; set; } = 5;
        public int TimeoutMs { get; set; } = 15000;
        public bool IncludeContentTypeMatrix { get; set; } = true;
        public bool IncludeBodyShapeMatrix { get; set; } = true;
        /// <summary>When null, browser cookies are sent only if the jar has cookies for the target host.</summary>
        public bool? IncludeBrowserCookies { get; set; }
    }

    public sealed class ParserProbeFinding
    {
        public string Category { get; init; } = "";
        public string Severity { get; init; } = "medium";
        public string Signal { get; init; } = "";
        public string Url { get; init; } = "";
        public string Method { get; init; } = "";
        public string ProbeKind { get; init; } = "";
        public string? ContentType { get; init; }
        public string? BodyVariant { get; init; }
        public int BaselineStatus { get; init; }
        public int ProbeStatus { get; init; }
        public string Detail { get; init; } = "";
        public int VariantCount { get; init; } = 1;
        public List<string>? Variants { get; init; }
    }

    public sealed class ParserProbeResult
    {
        public string Message { get; init; } = "";
        public int CandidatesProbed { get; init; }
        public int ProbesSent { get; init; }
        public int ElapsedMs { get; init; }
        public int SkippedNoSession { get; init; }
        public List<ParserProbeFinding> Findings { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;
    }

    public async Task<ParserProbeResult> RunAsync(ParserProbeOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running parser-probe.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var candidates = BuildCandidates(options, origin);
        if (candidates.Count == 0)
        {
            return new ParserProbeResult
            {
                Message = "No JSON POST/PUT/PATCH candidates found. Browse the app or pass url/method/body explicitly.",
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        var findings = new List<ParserProbeFinding>();
        var probesSent = 0;
        var skippedNoSession = 0;
        _log($"ParserProbe: {candidates.Count} candidate(s)", "#888888");

        foreach (var candidate in candidates)
        {
            ct.ThrowIfCancellationRequested();
            var (sent, skipped) = await ProbeCandidateAsync(candidate, options, findings, ct);
            probesSent += sent;
            skippedNoSession += skipped;
        }

        var message = findings.Count > 0
            ? $"{findings.Count} parser differential finding(s) across {candidates.Count} endpoint(s)."
            : $"No parser differentials detected across {candidates.Count} endpoint(s), {probesSent} probe(s).";
        if (skippedNoSession > 0)
            message += $" Skipped {skippedNoSession} endpoint(s) with HTTP 401/403 and no session cookies or Authorization.";

        return new ParserProbeResult
        {
            Message = message,
            CandidatesProbed = candidates.Count,
            ProbesSent = probesSent,
            SkippedNoSession = skippedNoSession,
            Findings = ConsolidateLowSeverityFindings(findings),
            ElapsedMs = (int)sw.ElapsedMilliseconds
        };
    }

    private static List<ParserProbeFinding> ConsolidateLowSeverityFindings(List<ParserProbeFinding> findings)
    {
        if (findings.Count <= 1) return findings;

        var kept = new List<ParserProbeFinding>();
        var lowGroups = new Dictionary<string, List<ParserProbeFinding>>(StringComparer.OrdinalIgnoreCase);

        foreach (var f in findings)
        {
            if (f.Category.Equals("parser-differential", StringComparison.OrdinalIgnoreCase)
                && f.Severity.Equals("low", StringComparison.OrdinalIgnoreCase)
                && f.Signal.Equals("body-diff-same-status", StringComparison.OrdinalIgnoreCase))
            {
                var key = $"{f.Url}|{f.Method}|{f.Category}|{f.Signal}";
                if (!lowGroups.TryGetValue(key, out var list))
                {
                    list = [];
                    lowGroups[key] = list;
                }
                list.Add(f);
            }
            else
            {
                kept.Add(f);
            }
        }

        foreach (var group in lowGroups.Values)
        {
            if (group.Count == 1)
            {
                kept.Add(group[0]);
                continue;
            }

            var first = group[0];
            var variants = group
                .Select(g => FormatVariantLabel(g))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            kept.Add(new ParserProbeFinding
            {
                Category = first.Category,
                Severity = first.Severity,
                Signal = first.Signal,
                Url = first.Url,
                Method = first.Method,
                ProbeKind = "content-type-and-body-matrix",
                BaselineStatus = first.BaselineStatus,
                ProbeStatus = first.ProbeStatus,
                VariantCount = group.Count,
                Variants = variants,
                Detail = $"Same HTTP {first.ProbeStatus} but response body differs for {group.Count} alternate parser(s): "
                         + string.Join("; ", variants.Take(8))
                         + (variants.Count > 8 ? $" (+{variants.Count - 8} more)" : "")
            });
        }

        return kept
            .OrderByDescending(f => SeverityRank(f.Severity))
            .ThenBy(f => f.Url, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string FormatVariantLabel(ParserProbeFinding f)
    {
        if (!string.IsNullOrEmpty(f.ContentType) && !string.IsNullOrEmpty(f.BodyVariant))
            return $"{f.ContentType} / {f.BodyVariant}";
        if (!string.IsNullOrEmpty(f.ContentType)) return f.ContentType;
        if (!string.IsNullOrEmpty(f.BodyVariant)) return f.BodyVariant;
        return f.ProbeKind;
    }

    private static int SeverityRank(string s) => s switch
    {
        "critical" => 4, "high" => 3, "medium" => 2, "low" => 1, _ => 0
    };

    private List<ParserCandidate> BuildCandidates(ParserProbeOptions options, string origin)
    {
        if (!string.IsNullOrWhiteSpace(options.Url) && !string.IsNullOrWhiteSpace(options.Body))
        {
            var headers = options.Headers != null
                ? new Dictionary<string, string>(options.Headers, StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (!headers.ContainsKey("Content-Type"))
                headers["Content-Type"] = "application/json";

            return
            [
                new ParserCandidate
                {
                    Url = options.Url!,
                    Method = (options.Method ?? "POST").ToUpperInvariant(),
                    Headers = headers,
                    JsonBody = options.Body!
                }
            ];
        }

        var max = options.MaxCandidates > 0 ? options.MaxCandidates : 5;
        return InjectionPointDiscovery.DiscoverJsonEndpoints(_ctx, origin, max)
            .Select(p => new ParserCandidate
            {
                Url = p.Url,
                Method = p.Method,
                Headers = p.Headers ?? new Dictionary<string, string> { ["Content-Type"] = "application/json" },
                JsonBody = p.BodyTemplate ?? "{}"
            })
            .ToList();
    }

    private async Task<(int ProbesSent, int SkippedNoSession)> ProbeCandidateAsync(
        ParserCandidate candidate,
        ParserProbeOptions options,
        List<ParserProbeFinding> findings,
        CancellationToken ct)
    {
        var timeout = options.TimeoutMs > 0 ? options.TimeoutMs : 15000;
        var baseHeaders = CopyHeaders(candidate.Headers);
        var baseCt = baseHeaders.GetValueOrDefault("Content-Type", "application/json");
        baseHeaders["Content-Type"] = baseCt;

        var includeJar = await ResolveIncludeBrowserCookiesAsync(candidate.Url, baseHeaders, options);
        var baseline = await ProbeFetchAsync(candidate.Url, candidate.Method, baseHeaders, candidate.JsonBody, timeout, includeJar);
        ct.ThrowIfCancellationRequested();

        if (baseline.Error != null)
        {
            _log($"  SKIP fetch error: {candidate.Url} ({baseline.Error})", "#888888");
            return (0, 0);
        }

        var baseStatus = baseline.Status;
        var baseBody = baseline.Body ?? "";

        if (baseStatus is 401 or 403 && !RequestHadSession(baseHeaders, baseline.CookiesSent))
        {
            _log($"  SKIP no session: {candidate.Url} baseline HTTP {baseStatus} (cookiesSent empty)", "#888888");
            return (0, 1);
        }

        var sent = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (options.IncludeContentTypeMatrix)
        {
            foreach (var variant in ContentTypeVariants(candidate.JsonBody))
            {
                ct.ThrowIfCancellationRequested();
                var headers = CopyHeaders(candidate.Headers);
                headers["Content-Type"] = variant.ContentType;

                var probe = await ProbeFetchAsync(candidate.Url, candidate.Method, headers, variant.Body, timeout, includeJar);
                sent++;
                if (probe.Error != null) continue;

                var match = ParserProbeHeuristics.Evaluate(
                    baseStatus, baseBody, probe.Status, probe.Body ?? "",
                    "content-type-matrix", variant.ContentType, variant.Label);
                if (match != null && seen.Add($"{match.Category}|{variant.ContentType}|{variant.Label}"))
                {
                    AddFinding(findings, candidate, match, "content-type-matrix", variant.ContentType, variant.Label,
                        baseStatus, probe.Status);
                    _log($"  FLAG {match.Signal}: {candidate.Url} CT={variant.ContentType}", "#F44747");
                }
            }
        }

        if (options.IncludeBodyShapeMatrix)
        {
            foreach (var bodyVariant in BodyShapeVariants(candidate.JsonBody).Take(12))
            {
                ct.ThrowIfCancellationRequested();
                var headers = CopyHeaders(candidate.Headers);
                headers["Content-Type"] = "application/json";

                var probe = await ProbeFetchAsync(candidate.Url, candidate.Method, headers, bodyVariant.Body, timeout, includeJar);
                sent++;
                if (probe.Error != null) continue;

                var match = ParserProbeHeuristics.Evaluate(
                    baseStatus, baseBody, probe.Status, probe.Body ?? "",
                    "body-shape-matrix", "application/json", bodyVariant.Label);
                if (match != null && seen.Add($"{match.Category}|body|{bodyVariant.Label}"))
                {
                    AddFinding(findings, candidate, match, "body-shape-matrix", "application/json", bodyVariant.Label,
                        baseStatus, probe.Status);
                    _log($"  FLAG {match.Signal}: {candidate.Url} body={bodyVariant.Label}", "#F44747");
                }
            }
        }

        return (sent, 0);
    }

    private async Task<bool> ResolveIncludeBrowserCookiesAsync(
        string url,
        Dictionary<string, string> headers,
        ParserProbeOptions options)
    {
        if (options.IncludeBrowserCookies is bool explicitJar)
            return explicitJar;

        var snapshot = await _ctx.GetBrowserCookieSnapshotForUrl(url);
        return !string.IsNullOrWhiteSpace(snapshot.Header);
    }

    private async Task<DirectFetchHelper.DirectFetchResult> ProbeFetchAsync(
        string url,
        string method,
        Dictionary<string, string> headers,
        string body,
        int timeoutMs,
        bool includeBrowserCookies) =>
        await DirectFetchHelper.FetchAsync(_ctx, url, method, headers, body, timeoutMs, allowAutoRedirect: true,
            includeBrowserCookies);

    private static bool RequestHadSession(
        Dictionary<string, string> headers,
        IReadOnlyList<string> cookiesSent)
    {
        if (cookiesSent.Count > 0)
            return true;

        foreach (var kv in headers)
        {
            if (kv.Key.Equals("Authorization", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(kv.Value))
                return true;
        }

        return false;
    }

    private static void AddFinding(
        List<ParserProbeFinding> findings,
        ParserCandidate candidate,
        ParserProbeHeuristics.HeuristicMatch match,
        string probeKind,
        string? contentType,
        string? bodyVariant,
        int baselineStatus,
        int probeStatus)
    {
        findings.Add(new ParserProbeFinding
        {
            Category = match.Category,
            Severity = match.Severity,
            Signal = match.Signal,
            Url = candidate.Url,
            Method = candidate.Method,
            ProbeKind = probeKind,
            ContentType = contentType,
            BodyVariant = bodyVariant,
            BaselineStatus = baselineStatus,
            ProbeStatus = probeStatus,
            Detail = match.Detail
        });
    }

    private sealed class ParserCandidate
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "POST";
        public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        public string JsonBody { get; init; } = "";
    }

    private sealed record BodyVariant(string Label, string Body);
    private sealed record ContentTypeVariant(string Label, string ContentType, string Body);

    private static IEnumerable<ContentTypeVariant> ContentTypeVariants(string jsonBody)
    {
        var xmlBody = JsonToMinimalXml(jsonBody);
        yield return new ContentTypeVariant("application/xml", "application/xml", xmlBody);
        yield return new ContentTypeVariant("text/xml", "text/xml", xmlBody);
        yield return new ContentTypeVariant("form-urlencoded", "application/x-www-form-urlencoded", JsonToFormEncoded(jsonBody));
        yield return new ContentTypeVariant("multipart-valid", "multipart/form-data; boundary=trowserprobe",
            "--trowserprobe\r\nContent-Disposition: form-data; name=\"data\"\r\n\r\n" + jsonBody + "\r\n--trowserprobe--");
        yield return new ContentTypeVariant("multipart-no-boundary", "multipart/form-data", jsonBody);
        yield return new ContentTypeVariant("multipart/mixed", "multipart/mixed; boundary=trowsermix",
            "--trowsermix\r\nContent-Type: application/json\r\n\r\n" + jsonBody + "\r\n--trowsermix--");
        yield return new ContentTypeVariant("java-serialized", "application/x-java-serialized-object",
            Convert.ToBase64String([0xAC, 0xED, 0x00, 0x05]));
        yield return new ContentTypeVariant("text/plain", "text/plain", jsonBody);
        yield return new ContentTypeVariant("json-utf7", "application/json; charset=utf-7", jsonBody);
    }

    private static IEnumerable<BodyVariant> BodyShapeVariants(string jsonBody)
    {
        yield return new BodyVariant("duplicate-keys", InsertDuplicateKey(jsonBody));
        yield return new BodyVariant("type-confusion-id-string", ReplaceFirstNumericWithString(jsonBody));
        yield return new BodyVariant("trailing-content", jsonBody.TrimEnd() + " trailing-garbage");
        yield return new BodyVariant("proto-pollution", "{\"__proto__\":{\"isAdmin\":true}}");

        foreach (var payload in FuzzerPayloads.BuiltIn["json-breaking"].Take(8))
            yield return new BodyVariant($"json-breaking:{Truncate(payload, 40)}", payload);
    }

    private static string JsonToMinimalXml(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return $"<root>{EscapeXml(json)}</root>";

            var sb = new StringBuilder("<root>");
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                sb.Append('<').Append(prop.Name).Append('>');
                sb.Append(EscapeXml(prop.Value.ToString()));
                sb.Append("</").Append(prop.Name).Append('>');
            }
            sb.Append("</root>");
            return sb.ToString();
        }
        catch
        {
            return "<root><data>" + EscapeXml(json) + "</data></root>";
        }
    }

    private static string JsonToFormEncoded(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return $"data={Uri.EscapeDataString(json)}";

            var parts = new List<string>();
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                var val = prop.Value.ValueKind == JsonValueKind.String
                    ? prop.Value.GetString() ?? prop.Value.GetRawText()
                    : prop.Value.GetRawText();
                parts.Add($"{Uri.EscapeDataString(prop.Name)}={Uri.EscapeDataString(val)}");
            }
            return string.Join("&", parts);
        }
        catch
        {
            return $"data={Uri.EscapeDataString(json)}";
        }
    }

    private static string InsertDuplicateKey(string json)
    {
        if (!json.TrimStart().StartsWith('{')) return json;
        var trimmed = json.Trim();
        return trimmed.Insert(1, "\"duplicate\":1,\"duplicate\":2,");
    }

    private static string ReplaceFirstNumericWithString(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            using var stream = new MemoryStream();
            var replaced = false;
            using (var writer = new Utf8JsonWriter(stream))
            {
                WriteWithFirstNumberAsString(doc.RootElement, writer, ref replaced);
            }
            return Encoding.UTF8.GetString(stream.ToArray());
        }
        catch
        {
            return json;
        }
    }

    private static void WriteWithFirstNumberAsString(JsonElement el, Utf8JsonWriter writer, ref bool replaced)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var prop in el.EnumerateObject())
                {
                    writer.WritePropertyName(prop.Name);
                    WriteWithFirstNumberAsString(prop.Value, writer, ref replaced);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in el.EnumerateArray())
                    WriteWithFirstNumberAsString(item, writer, ref replaced);
                writer.WriteEndArray();
                break;
            case JsonValueKind.Number when !replaced:
                writer.WriteStringValue(el.GetRawText());
                replaced = true;
                break;
            default:
                el.WriteTo(writer);
                break;
        }
    }

    private static Dictionary<string, string> CopyHeaders(Dictionary<string, string> source)
    {
        var copy = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in source)
        {
            if (kv.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
            copy[kv.Key] = kv.Value;
        }
        return copy;
    }

    private static string EscapeXml(string text) =>
        text.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
