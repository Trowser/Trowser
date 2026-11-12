using System.IO;
using System.Text;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Traffic-driven endpoint discovery for fail-open and missing-parameter probes.
/// </summary>
public static class ExceptionalConditionDiscovery
{
    public sealed class JsonPostTarget
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "POST";
        public string BodyTemplate { get; init; } = "{}";
        public Dictionary<string, string>? Headers { get; init; }
        public List<string> TopLevelFields { get; init; } = [];
    }

    public sealed class ProtectedEndpoint
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public Dictionary<string, string>? Headers { get; init; }
        public string? BodyTemplate { get; init; }
        public bool HadAuthorizationHeader { get; init; }
        public string? ResponseContentType { get; init; }
        public string? ResponseContentEncoding { get; init; }
        public bool CallerListed { get; init; }
    }

    public static List<ProtectedEndpoint> DiscoverProtectedEndpoints(
        AutomationContext ctx,
        string origin,
        int maxCandidates,
        IReadOnlyList<string>? explicitUrls = null,
        bool skipStaticAssets = true,
        bool skipAuthSurfaces = true)
    {
        var list = new List<ProtectedEndpoint>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (explicitUrls is { Count: > 0 })
        {
            foreach (var u in explicitUrls.Where(x => !string.IsNullOrWhiteSpace(x)))
            {
                var abs = ToAbsolute(origin, u.Trim());
                if (abs == null) continue;
                if (skipStaticAssets && FailOpenEndpointFilters.ShouldSkipProbe(abs)) continue;
                if (skipAuthSurfaces && FailOpenEndpointFilters.IsAuthSurface(abs)) continue;

                var entry = FailOpenEndpointFilters.FindNetworkEntry(ctx, abs);
                var method = entry?.Method.ToUpperInvariant() ?? "GET";
                var key = $"{method}|{abs}";
                if (!seen.Add(key)) continue;

                var headers = entry != null ? CopyHeaders(entry.RequestHeaders) : null;
                list.Add(new ProtectedEndpoint
                {
                    Url = abs,
                    Method = method,
                    Headers = headers,
                    BodyTemplate = entry?.RequestBody,
                    HadAuthorizationHeader = entry?.RequestHeaders.ContainsKey("Authorization") ?? false,
                    ResponseContentType = entry?.ContentType,
                    ResponseContentEncoding = GetContentEncoding(entry),
                    CallerListed = true
                });
                if (list.Count >= maxCandidates) return list;
            }

            return list;
        }

        foreach (var entry in ctx.Network.Entries)
        {
            if (entry.Method is not ("GET" or "POST" or "PUT" or "PATCH")) continue;
            if (entry.StatusCode is < 200 or >= 300) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;
            if (skipStaticAssets && FailOpenEndpointFilters.IsStaticAsset(entry.Url, entry.ContentType, entry.ResourceType))
                continue;
            if (skipAuthSurfaces && FailOpenEndpointFilters.IsAuthSurface(entry.Url))
                continue;

            var body = entry.ResponseBody ?? "";
            if (!ExceptionalConditionHeuristics.LooksLikeSensitiveBody(body)
                && entry.ResponseBody?.Length is not (> 150)) continue;

            var key = $"{entry.Method}|{entry.Url}";
            if (!seen.Add(key)) continue;

            var headers = CopyHeaders(entry.RequestHeaders);
            list.Add(new ProtectedEndpoint
            {
                Url = entry.Url,
                Method = entry.Method.ToUpperInvariant(),
                Headers = headers,
                BodyTemplate = entry.RequestBody,
                HadAuthorizationHeader = headers.ContainsKey("Authorization"),
                ResponseContentType = entry.ContentType,
                ResponseContentEncoding = GetContentEncoding(entry)
            });

            if (list.Count >= maxCandidates) break;
        }

        return list;
    }

    public static List<JsonPostTarget> DiscoverJsonPostTargets(
        AutomationContext ctx,
        string origin,
        int maxCandidates,
        IReadOnlyList<string>? explicitUrls = null)
    {
        var list = new List<JsonPostTarget>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (explicitUrls is { Count: > 0 })
        {
            foreach (var u in explicitUrls.Where(x => !string.IsNullOrWhiteSpace(x)))
            {
                var target = BuildFromExplicit(origin, u.Trim());
                if (target == null || target.TopLevelFields.Count == 0) continue;
                var key = $"{target.Method}|{target.Url}";
                if (!seen.Add(key)) continue;
                list.Add(target);
                if (list.Count >= maxCandidates) return list;
            }
        }

        foreach (var entry in ctx.Network.Entries)
        {
            if (entry.Method is not ("POST" or "PUT" or "PATCH")) continue;
            if (entry.StatusCode is < 200 or >= 400) continue;
            if (string.IsNullOrWhiteSpace(entry.RequestBody)) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;

            var ct = entry.ContentType ?? entry.RequestHeaders.GetValueOrDefault("Content-Type") ?? "";
            if (!ct.Contains("json", StringComparison.OrdinalIgnoreCase)
                && !entry.RequestBody.TrimStart().StartsWith('{')) continue;

            var fields = ExtractTopLevelFields(entry.RequestBody);
            if (fields.Count == 0) continue;

            var key = $"{entry.Method}|{entry.Url}";
            if (!seen.Add(key)) continue;

            var headers = CopyHeaders(entry.RequestHeaders);
            if (!headers.ContainsKey("Content-Type"))
                headers["Content-Type"] = "application/json";

            list.Add(new JsonPostTarget
            {
                Url = entry.Url,
                Method = entry.Method.ToUpperInvariant(),
                BodyTemplate = entry.RequestBody,
                Headers = headers,
                TopLevelFields = fields
            });

            if (list.Count >= maxCandidates) break;
        }

        return list;
    }

    public static string OmitTopLevelField(string json, string fieldName)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return json;

            using var stream = new MemoryStream();
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartObject();
                foreach (var prop in doc.RootElement.EnumerateObject())
                {
                    if (prop.Name.Equals(fieldName, StringComparison.Ordinal)) continue;
                    writer.WritePropertyName(prop.Name);
                    prop.Value.WriteTo(writer);
                }
                writer.WriteEndObject();
            }

            return Encoding.UTF8.GetString(stream.ToArray());
        }
        catch (JsonException)
        {
            return json;
        }
    }

    private static JsonPostTarget? BuildFromExplicit(string origin, string urlOrPath)
    {
        var abs = ToAbsolute(origin, urlOrPath);
        if (abs == null) return null;

        return new JsonPostTarget
        {
            Url = abs,
            Method = "POST",
            BodyTemplate = "{}",
            Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Content-Type"] = "application/json"
            },
            TopLevelFields = []
        };
    }

    private static List<string> ExtractTopLevelFields(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return [];
            return doc.RootElement.EnumerateObject()
                .Select(p => p.Name)
                .Where(n => !string.IsNullOrWhiteSpace(n))
                .Take(20)
                .ToList();
        }
        catch (JsonException)
        {
            return [];
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

    private static string? ToAbsolute(string origin, string urlOrPath)
    {
        if (Uri.TryCreate(urlOrPath, UriKind.Absolute, out var abs)) return abs.ToString();
        if (urlOrPath.StartsWith('/')) return origin.TrimEnd('/') + urlOrPath;
        return null;
    }

    private static string? GetContentEncoding(NetworkEntry? entry)
    {
        if (entry?.ResponseHeaders == null) return null;
        foreach (var h in entry.ResponseHeaders)
        {
            if (h.Key.Equals("Content-Encoding", StringComparison.OrdinalIgnoreCase))
                return h.Value;
        }
        return null;
    }
}
