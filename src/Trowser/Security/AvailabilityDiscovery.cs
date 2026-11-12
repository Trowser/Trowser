using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Traffic-driven discovery for A12 availability probes (rate limits, ReDoS, body-size tiers).
/// </summary>
public static class AvailabilityDiscovery
{
    public sealed class EndpointCandidate
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public string? BodyTemplate { get; init; }
        public Dictionary<string, string>? Headers { get; init; }
        public string Kind { get; init; } = "generic";
        public string MatchReason { get; init; } = "";
        public string? InjectableParam { get; init; }
        public string ParamLocation { get; init; } = "query";

        public EndpointCandidate WithKind(string kind, string matchReason) => new()
        {
            Url = Url,
            Method = Method,
            BodyTemplate = BodyTemplate,
            Headers = Headers,
            Kind = kind,
            MatchReason = matchReason,
            InjectableParam = InjectableParam,
            ParamLocation = ParamLocation
        };
    }

    private static readonly string[] LoginPathSegments =
    [
        "login", "signin", "sign-in", "auth", "token", "session", "oauth"
    ];

    private static readonly string[] LoginBodyFields =
    [
        "password", "pass", "passw", "passwd", "pwd"
    ];

    private static readonly string[] OtpBodyFields =
    [
        "otp", "code", "pin", "token", "verification", "verify", "mfa", "totp"
    ];

    private static readonly string[] SearchPathSegments =
    [
        "search", "query", "find", "filter", "lookup", "autocomplete", "suggest"
    ];

    private static readonly string[] SearchQueryParams =
    [
        "q", "query", "search", "term", "filter", "keyword", "name", "email"
    ];

    private static readonly string[] ExportPathSegments =
    [
        "export", "download", "csv", "report", "dump"
    ];

    private static readonly string[] CouponPathSegments =
    [
        "coupon", "redeem", "voucher", "promo", "claim"
    ];

    private static readonly string[] StaticPathPrefixes =
    [
        "/resources/", "/static/", "/assets/", "/dist/", "/build/", "/public/", "/media/", "/fonts/"
    ];

    private static readonly string[] StaticFileExtensions =
    [
        ".js", ".css", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".map", ".wasm"
    ];

    private static readonly HashSet<string> StaticResourceTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "Script", "Stylesheet", "Image", "Font", "Media"
    };

    private static readonly Regex SixDigitField =
        new(@"""?(otp|code|pin|token|verification|verify)""?\s*[:=]\s*""?\d{4,8}""?",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static List<EndpointCandidate> DiscoverRateLimitCandidates(
        AutomationContext ctx,
        string origin,
        int maxCandidates,
        IReadOnlyList<string>? explicitUrls = null)
    {
        if (HasExplicitUrls(explicitUrls))
            return DiscoverExplicitOnly(ctx, origin, maxCandidates, explicitUrls!, (c, o, u) =>
                BuildExplicitCandidate(c, o, u, "generic"));

        var list = new List<EndpointCandidate>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in ctx.Network.Entries)
        {
            if (entry.StatusCode is < 200 or >= 500) continue;
            if (IsStaticAsset(entry)) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            var candidate = ClassifyNetworkEntry(entry);
            if (candidate == null) continue;
            if (!TryAddCandidate(list, seen, candidate)) continue;
            if (list.Count >= maxCandidates) return list;
        }

        if (list.Count == 0)
        {
            foreach (var hint in AuthProbeDiscovery.LoginPathHints.Take(3))
            {
                var built = BuildExplicitCandidate(ctx, origin, origin.TrimEnd('/') + hint, "login");
                if (built != null && TryAddCandidate(list, seen, built))
                {
                    if (list.Count >= maxCandidates) break;
                }
            }
        }

        return list;
    }

    public static List<EndpointCandidate> DiscoverReDoSCandidates(
        AutomationContext ctx,
        string origin,
        int maxCandidates,
        IReadOnlyList<string>? explicitUrls = null)
    {
        if (HasExplicitUrls(explicitUrls))
            return DiscoverExplicitReDoSOnly(explicitUrls!, maxCandidates);

        var list = new List<EndpointCandidate>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in ctx.Network.Entries)
        {
            if (entry.Method is not ("GET" or "POST")) continue;
            if (entry.StatusCode is < 200 or >= 500) continue;
            if (IsStaticAsset(entry)) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            foreach (var param in ExtractInjectableParams(entry))
            {
                var candidate = new EndpointCandidate
                {
                    Url = NormalizeRepresentativeUrl(entry.Url),
                    Method = entry.Method.ToUpperInvariant(),
                    BodyTemplate = entry.RequestBody,
                    Headers = CopyHeaders(entry.RequestHeaders),
                    Kind = "redos",
                    MatchReason = $"injectable-{param.Location}",
                    InjectableParam = param.Name,
                    ParamLocation = param.Location
                };
                if (!TryAddReDoSCandidate(list, seen, candidate)) continue;
                if (list.Count >= maxCandidates) return list;
            }
        }

        return list;
    }

    public static List<EndpointCandidate> DiscoverBodySizeCandidates(
        AutomationContext ctx,
        string origin,
        int maxCandidates,
        IReadOnlyList<string>? explicitUrls = null)
    {
        if (HasExplicitUrls(explicitUrls))
        {
            return DiscoverExplicitOnly(ctx, origin, maxCandidates, explicitUrls!, (c, o, u) =>
                BuildExplicitCandidate(c, o, u, "body-size")?.WithKind("body-size", "explicit-url"));
        }

        var list = new List<EndpointCandidate>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in ctx.Network.Entries)
        {
            if (entry.Method is not ("POST" or "PUT" or "PATCH")) continue;
            if (entry.StatusCode is < 200 or >= 500) continue;
            if (IsStaticAsset(entry)) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            var candidate = new EndpointCandidate
            {
                Url = NormalizeRepresentativeUrl(entry.Url),
                Method = entry.Method.ToUpperInvariant(),
                BodyTemplate = entry.RequestBody ?? "{}",
                Headers = CopyHeaders(entry.RequestHeaders),
                Kind = "body-size",
                MatchReason = "state-changing-post"
            };
            if (!TryAddCandidate(list, seen, candidate)) continue;
            if (list.Count >= maxCandidates) return list;
        }

        return list;
    }

    private static bool HasExplicitUrls(IReadOnlyList<string>? explicitUrls) =>
        explicitUrls != null && explicitUrls.Any(u => !string.IsNullOrWhiteSpace(u));

    private static List<EndpointCandidate> DiscoverExplicitOnly(
        AutomationContext ctx,
        string origin,
        int maxCandidates,
        IReadOnlyList<string> explicitUrls,
        Func<AutomationContext, string, string, EndpointCandidate?> builder)
    {
        var list = new List<EndpointCandidate>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var url in explicitUrls.Where(u => !string.IsNullOrWhiteSpace(u)))
        {
            var built = builder(ctx, origin, url.Trim());
            if (built != null && TryAddCandidate(list, seen, built))
            {
                if (list.Count >= maxCandidates) break;
            }
        }

        return list;
    }

    private static List<EndpointCandidate> DiscoverExplicitReDoSOnly(
        IReadOnlyList<string> explicitUrls,
        int maxCandidates)
    {
        var list = new List<EndpointCandidate>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var url in explicitUrls.Where(u => !string.IsNullOrWhiteSpace(u)))
        {
            var built = BuildExplicitReDoSCandidate(url.Trim());
            if (built != null && TryAddReDoSCandidate(list, seen, built))
            {
                if (list.Count >= maxCandidates) break;
            }
        }

        return list;
    }

    private static EndpointCandidate? ClassifyNetworkEntry(NetworkEntry entry)
    {
        if (IsStaticAsset(entry)) return null;
        if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) return null;
        var path = uri.AbsolutePath;
        var body = entry.RequestBody ?? "";
        var method = entry.Method.ToUpperInvariant();

        if (method is "POST" or "PUT" or "PATCH")
        {
            if (LoginBodyFields.Any(f => BodyContainsField(body, f))
                || LoginPathSegments.Any(s => PathHasSegment(path, s)))
            {
                return BuildFromEntry(entry, "login", "login-surface");
            }

            if (OtpBodyFields.Any(f => BodyContainsField(body, f)) || SixDigitField.IsMatch(body))
            {
                return BuildFromEntry(entry, "otp", "otp-field");
            }

            if (CouponPathSegments.Any(s => PathHasSegment(path, s))
                || new[] { "code", "coupon", "voucher", "promo", "token" }.Any(h => BodyContainsField(body, h)))
            {
                return BuildFromEntry(entry, "coupon", "coupon-redeem");
            }
        }

        if (ExportPathSegments.Any(s => PathHasSegment(path, s)))
            return BuildFromEntry(entry, "export", "export-path");

        if (method is "GET" or "HEAD")
        {
            if (HasSearchQuery(uri) || SearchPathSegments.Any(s => PathHasSegment(path, s)))
                return BuildFromEntry(entry, "search", "search-surface");
        }

        if (method is "POST" or "PUT" or "PATCH")
            return BuildFromEntry(entry, "write-api", "state-changing");

        return null;
    }

    private static EndpointCandidate BuildFromEntry(NetworkEntry entry, string kind, string reason)
    {
        var headers = CopyHeaders(entry.RequestHeaders);
        if (!headers.ContainsKey("Content-Type") && !string.IsNullOrEmpty(entry.RequestBody))
        {
            headers["Content-Type"] = entry.RequestBody!.TrimStart().StartsWith('{')
                ? "application/json"
                : "application/x-www-form-urlencoded";
        }

        return new EndpointCandidate
        {
            Url = NormalizeRepresentativeUrl(entry.Url),
            Method = entry.Method.ToUpperInvariant(),
            BodyTemplate = entry.RequestBody,
            Headers = headers,
            Kind = kind,
            MatchReason = reason
        };
    }

    internal static EndpointCandidate? BuildExplicitCandidate(
        AutomationContext ctx,
        string origin,
        string url,
        string kind = "generic")
    {
        var abs = url.StartsWith("http", StringComparison.OrdinalIgnoreCase)
            ? url
            : origin.TrimEnd('/') + (url.StartsWith('/') ? url : "/" + url);

        var networkMatch = AuthFormDiscovery.PickBestNetworkEntryForExplicitUrl(ctx.Network.Entries, abs);

        if (networkMatch != null)
        {
            var classified = ClassifyNetworkEntry(networkMatch) ?? BuildFromEntry(networkMatch, kind, "explicit-url");
            var method = ResolveExplicitMethod(abs, networkMatch);
            var useBody = method is "POST" or "PUT" or "PATCH";
            return new EndpointCandidate
            {
                Url = abs,
                Method = method,
                BodyTemplate = useBody ? classified.BodyTemplate : null,
                Headers = useBody ? classified.Headers : null,
                Kind = classified.Kind,
                MatchReason = "explicit-url"
            };
        }

        var fallbackMethod = abs.Contains('?', StringComparison.Ordinal) ? "GET" : "POST";
        return new EndpointCandidate
        {
            Url = abs,
            Method = fallbackMethod,
            BodyTemplate = fallbackMethod == "POST" ? "{}" : null,
            Headers = fallbackMethod == "POST" ? JsonHeaders() : null,
            Kind = kind,
            MatchReason = "explicit-url"
        };
    }

    private static string ResolveExplicitMethod(string explicitUrl, NetworkEntry networkMatch)
    {
        if (UrlsMatchForMethod(explicitUrl, networkMatch.Url))
            return networkMatch.Method.ToUpperInvariant();

        if (Uri.TryCreate(explicitUrl, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Query))
            return "GET";

        return networkMatch.Method.ToUpperInvariant();
    }

    private static bool UrlsMatchForMethod(string explicitUrl, string networkUrl)
    {
        if (string.Equals(explicitUrl, networkUrl, StringComparison.OrdinalIgnoreCase))
            return true;

        if (!Uri.TryCreate(explicitUrl, UriKind.Absolute, out var explicitUri)
            || !Uri.TryCreate(networkUrl, UriKind.Absolute, out var networkUri))
            return false;

        return string.Equals(explicitUri.AbsolutePath, networkUri.AbsolutePath, StringComparison.OrdinalIgnoreCase)
               && string.Equals(explicitUri.Query, networkUri.Query, StringComparison.OrdinalIgnoreCase);
    }

    private static EndpointCandidate? BuildExplicitReDoSCandidate(string url)
    {
        if (IsStaticAssetUrl(url)) return null;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return null;
        var param = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=')[0])
            .FirstOrDefault(p => !string.IsNullOrEmpty(p) && IsInjectableName(Uri.UnescapeDataString(p)));
        if (string.IsNullOrEmpty(param))
        {
            param = uri.Query.TrimStart('?').Split('&').FirstOrDefault()?.Split('=').FirstOrDefault();
            if (string.IsNullOrEmpty(param)) param = "q";
        }

        return new EndpointCandidate
        {
            Url = url,
            Method = "GET",
            Kind = "redos",
            MatchReason = "explicit-url",
            InjectableParam = Uri.UnescapeDataString(param),
            ParamLocation = "query"
        };
    }

    private static bool TryAddCandidate(List<EndpointCandidate> list, HashSet<string> seen, EndpointCandidate candidate)
    {
        var key = CandidateDedupeKey(candidate.Method, candidate.Url);
        if (!seen.Add(key)) return false;
        list.Add(candidate);
        return true;
    }

    private static bool TryAddReDoSCandidate(List<EndpointCandidate> list, HashSet<string> seen, EndpointCandidate candidate)
    {
        var key = $"{CandidateDedupeKey(candidate.Method, candidate.Url)}|{candidate.InjectableParam}";
        if (!seen.Add(key)) return false;
        list.Add(candidate);
        return true;
    }

    internal static string CandidateDedupeKey(string method, string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return $"{method}|{url}";

        return $"{method.ToUpperInvariant()}|{uri.AbsolutePath.ToLowerInvariant()}";
    }

    internal static string NormalizeRepresentativeUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url;

        if (string.IsNullOrEmpty(uri.Query))
            return uri.GetLeftPart(UriPartial.Path);

        var firstParam = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return string.IsNullOrEmpty(firstParam)
            ? uri.GetLeftPart(UriPartial.Path)
            : $"{uri.GetLeftPart(UriPartial.Path)}?{firstParam.Split('=')[0]}=";
    }

    internal static bool IsStaticAsset(NetworkEntry entry)
    {
        if (StaticResourceTypes.Contains(entry.ResourceType))
            return true;

        if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri))
            return false;

        var path = uri.AbsolutePath;
        var lowerPath = path.ToLowerInvariant();

        if (StaticPathPrefixes.Any(p => lowerPath.Contains(p, StringComparison.Ordinal)))
            return true;

        if (StaticFileExtensions.Any(ext => lowerPath.EndsWith(ext, StringComparison.Ordinal)))
            return true;

        var contentType = entry.ContentType.ToLowerInvariant();
        if (string.IsNullOrEmpty(contentType))
            return false;

        if (contentType.Contains("javascript", StringComparison.Ordinal)
            || contentType.Contains("ecmascript", StringComparison.Ordinal)
            || contentType.StartsWith("image/", StringComparison.Ordinal)
            || contentType.StartsWith("font/", StringComparison.Ordinal)
            || contentType.StartsWith("audio/", StringComparison.Ordinal)
            || contentType.StartsWith("video/", StringComparison.Ordinal)
            || contentType.Contains("text/css", StringComparison.Ordinal)
            || contentType.Contains("application/wasm", StringComparison.Ordinal))
            return true;

        return false;
    }

    internal static bool IsStaticAssetUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;

        var lowerPath = uri.AbsolutePath.ToLowerInvariant();
        if (StaticPathPrefixes.Any(p => lowerPath.Contains(p, StringComparison.Ordinal)))
            return true;

        return StaticFileExtensions.Any(ext => lowerPath.EndsWith(ext, StringComparison.Ordinal));
    }

    private sealed record InjectableParam(string Name, string Location);

    private static IEnumerable<InjectableParam> ExtractInjectableParams(NetworkEntry entry)
    {
        if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri))
            return [];

        var results = new List<InjectableParam>();

        foreach (var segment in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = segment.IndexOf('=');
            var name = eq >= 0 ? Uri.UnescapeDataString(segment[..eq]) : Uri.UnescapeDataString(segment);
            if (IsInjectableName(name))
                results.Add(new InjectableParam(name, "query"));
        }

        if (string.IsNullOrEmpty(entry.RequestBody) || !entry.RequestBody.TrimStart().StartsWith('{'))
            return results;

        try
        {
            using var doc = JsonDocument.Parse(entry.RequestBody);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return results;

            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (IsInjectableName(prop.Name))
                    results.Add(new InjectableParam(prop.Name, "json-body"));
            }
        }
        catch (JsonException)
        {
            // ignore malformed JSON bodies
        }

        return results;
    }

    private static bool IsInjectableName(string name)
    {
        var lower = name.ToLowerInvariant();
        return SearchQueryParams.Any(p => lower.Equals(p, StringComparison.Ordinal))
               || lower.Contains("email", StringComparison.Ordinal)
               || lower.Contains("filter", StringComparison.Ordinal)
               || lower.Contains("regex", StringComparison.Ordinal);
    }

    private static bool HasSearchQuery(Uri uri)
    {
        foreach (var segment in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = segment.IndexOf('=');
            var name = eq >= 0 ? Uri.UnescapeDataString(segment[..eq]) : Uri.UnescapeDataString(segment);
            if (SearchQueryParams.Any(p => name.Equals(p, StringComparison.OrdinalIgnoreCase)))
                return true;
        }

        return false;
    }

    internal static string BuildOtpProbeBody(string? template, int attemptIndex)
    {
        var wrongCode = (attemptIndex % 10).ToString("D6");
        if (string.IsNullOrEmpty(template))
            return $$"""{"otp":"{{wrongCode}}","code":"{{wrongCode}}"}""";

        var body = template;
        foreach (var field in OtpBodyFields)
        {
            if (!BodyContainsField(body, field)) continue;
            body = ReplaceJsonStringField(body, field, wrongCode);
            body = ReplaceFormField(body, field, wrongCode);
        }

        return body;
    }

    internal static string InjectReDoSPayload(string url, string? body, string param, string location, string payload)
    {
        if (location == "query")
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return url;
            var baseUrl = uri.GetLeftPart(UriPartial.Path);
            var query = uri.Query.TrimStart('?');
            var pairs = query.Split('&', StringSplitOptions.RemoveEmptyEntries).ToList();
            var replaced = false;
            for (var i = 0; i < pairs.Count; i++)
            {
                var eq = pairs[i].IndexOf('=');
                var name = eq >= 0 ? pairs[i][..eq] : pairs[i];
                if (!name.Equals(param, StringComparison.OrdinalIgnoreCase)) continue;
                pairs[i] = $"{name}={Uri.EscapeDataString(payload)}";
                replaced = true;
            }

            if (!replaced)
                pairs.Add($"{param}={Uri.EscapeDataString(payload)}");

            return pairs.Count > 0 ? $"{baseUrl}?{string.Join("&", pairs)}" : baseUrl;
        }

        if (string.IsNullOrEmpty(body) || !body.TrimStart().StartsWith('{'))
            return body ?? "{}";

        return ReplaceJsonStringField(body, param, payload);
    }

    internal static byte[] BuildTierBody(string? template, int tierBytes)
    {
        tierBytes = Math.Clamp(tierBytes, 256, 1_048_576);
        if (string.IsNullOrEmpty(template) || !template.TrimStart().StartsWith('{'))
        {
            var padding = new string('A', Math.Max(0, tierBytes - 2));
            return System.Text.Encoding.UTF8.GetBytes($"{{\"data\":\"{padding}\"}}");
        }

        try
        {
            using var doc = JsonDocument.Parse(template);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return System.Text.Encoding.UTF8.GetBytes(template);

            var padLen = Math.Max(0, tierBytes - template.Length);
            var node = JsonNode.Parse(template)!.AsObject();
            node["_trowserPad"] = new string('A', padLen);
            return System.Text.Encoding.UTF8.GetBytes(node.ToJsonString());
        }
        catch (JsonException)
        {
            return System.Text.Encoding.UTF8.GetBytes(template);
        }
    }

    private static string ReplaceJsonStringField(string json, string field, string value)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return json;
            var node = JsonNode.Parse(json)!.AsObject();
            node[field] = value;
            return node.ToJsonString();
        }
        catch (JsonException)
        {
            return json;
        }
    }

    private static string ReplaceFormField(string body, string field, string value)
    {
        if (!body.Contains('=')) return body;
        var parts = body.Split('&').Select(part =>
        {
            var eq = part.IndexOf('=');
            if (eq < 0) return part;
            var name = part[..eq];
            return name.Equals(field, StringComparison.OrdinalIgnoreCase)
                ? $"{name}={Uri.EscapeDataString(value)}"
                : part;
        });
        return string.Join("&", parts);
    }

    private static bool PathHasSegment(string path, string segment) =>
        path.Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Any(part => part.Equals(segment, StringComparison.OrdinalIgnoreCase));

    private static bool BodyContainsField(string body, string field) =>
        body.Contains($"\"{field}\"", StringComparison.OrdinalIgnoreCase)
        || body.Contains($"'{field}'", StringComparison.OrdinalIgnoreCase)
        || body.Contains($"{field}=", StringComparison.OrdinalIgnoreCase);

    internal static bool UrlPathMatches(string entryUrl, string targetUrl)
    {
        if (string.Equals(entryUrl, targetUrl, StringComparison.OrdinalIgnoreCase))
            return true;
        if (!Uri.TryCreate(entryUrl, UriKind.Absolute, out var entryUri)
            || !Uri.TryCreate(targetUrl, UriKind.Absolute, out var targetUri))
            return false;
        return string.Equals(entryUri.AbsolutePath, targetUri.AbsolutePath, StringComparison.OrdinalIgnoreCase);
    }

    private static Dictionary<string, string> JsonHeaders() =>
        new(StringComparer.OrdinalIgnoreCase) { ["Content-Type"] = "application/json" };

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
}
