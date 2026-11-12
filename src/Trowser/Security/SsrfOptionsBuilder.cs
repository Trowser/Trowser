using System.Text.Json;
using Trowser.Api;

namespace Trowser.Security;

/// <summary>Shared parsing for SSRF scan options from REST and MCP request bodies.</summary>
internal static class SsrfOptionsBuilder
{
    public static List<EndpointParamHint>? ParseEndpointHints(JsonElement? arr)
    {
        if (arr is not { ValueKind: JsonValueKind.Array })
            return null;

        var hints = new List<EndpointParamHint>();
        foreach (var item in arr.Value.EnumerateArray())
        {
            var hint = new EndpointParamHint
            {
                Url = item.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "",
                Method = item.TryGetProperty("method", out var m) ? m.GetString() ?? "GET" : "GET",
            };
            if (item.TryGetProperty("paramNames", out var pn) && pn.ValueKind == JsonValueKind.Array)
            {
                foreach (var p in pn.EnumerateArray())
                    if (p.ValueKind == JsonValueKind.String)
                        hint.ParamNames.Add(p.GetString() ?? "");
            }
            else if (item.TryGetProperty("paramName", out var single))
                hint.ParamNames.Add(single.GetString() ?? "");

            string? bodySample = null;
            if (item.TryGetProperty("requestBodySample", out var bodySampleEl))
                bodySample = bodySampleEl.GetString();
            else if (item.TryGetProperty("bodySample", out var bodySample2))
                bodySample = bodySample2.GetString();

            Dictionary<string, string>? headers = null;
            if (item.TryGetProperty("headers", out var hdrs) && hdrs.ValueKind == JsonValueKind.Object)
            {
                headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var p in hdrs.EnumerateObject())
                    headers[p.Name] = p.Value.GetString() ?? p.Value.ToString();
            }

            if (!string.IsNullOrEmpty(hint.Url) && hint.ParamNames.Count > 0)
            {
                hints.Add(new EndpointParamHint
                {
                    Url = hint.Url,
                    Method = hint.Method,
                    ParamNames = hint.ParamNames,
                    RequestBodySample = bodySample,
                    Headers = headers
                });
            }
        }

        return hints.Count > 0 ? hints : null;
    }

    public static List<EndpointParamHint>? ParseEndpointHints(JsonBody body)
    {
        if (!body.HasProperty("endpointHints"))
            return null;
        return ParseEndpointHints(body.GetJsonElement("endpointHints"));
    }

    public static (List<string>? allowedHosts, List<string>? scopeUrls) ParseScope(JsonBody body)
    {
        List<string>? allowedHosts = body.GetStringList("allowedHosts")
            ?? body.GetStringArray("allowedHosts")?.ToList();
        List<string>? scopeUrls = null;

        if (body.HasProperty("scope"))
        {
            var scopeObj = body.GetObject("scope");
            if (scopeObj != null)
            {
                var scope = new JsonBody(scopeObj);
                var host = scope.GetString("host");
                if (!string.IsNullOrWhiteSpace(host))
                {
                    allowedHosts ??= [];
                    allowedHosts.Add(host);
                }

                scopeUrls = scope.GetStringList("urls") ?? scope.GetStringArray("urls")?.ToList();
                var includePaths = scope.GetStringList("includePaths") ?? scope.GetStringArray("includePaths")?.ToList();
                if (includePaths is { Count: > 0 })
                {
                    scopeUrls ??= [];
                    foreach (var path in includePaths)
                    {
                        if (string.IsNullOrWhiteSpace(path)) continue;
                        if (path.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                            path.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                            scopeUrls.Add(path);
                    }
                }
            }
        }

        return (allowedHosts, scopeUrls);
    }

    public static (List<string>? allowedHosts, List<string>? scopeUrls) ParseScope(JsonElement args)
    {
        List<string>? allowedHosts = null;
        if (args.TryGetProperty("allowedHosts", out var hostsEl) && hostsEl.ValueKind == JsonValueKind.Array)
        {
            allowedHosts = [];
            foreach (var h in hostsEl.EnumerateArray())
                if (h.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(h.GetString()))
                    allowedHosts.Add(h.GetString()!);
        }

        List<string>? scopeUrls = null;
        if (args.TryGetProperty("scope", out var scopeEl) && scopeEl.ValueKind == JsonValueKind.Object)
        {
            if (scopeEl.TryGetProperty("host", out var hostEl) && hostEl.ValueKind == JsonValueKind.String)
            {
                allowedHosts ??= [];
                var host = hostEl.GetString();
                if (!string.IsNullOrWhiteSpace(host))
                    allowedHosts.Add(host);
            }

            if (scopeEl.TryGetProperty("urls", out var urlsEl) && urlsEl.ValueKind == JsonValueKind.Array)
            {
                scopeUrls = [];
                foreach (var u in urlsEl.EnumerateArray())
                    if (u.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(u.GetString()))
                        scopeUrls.Add(u.GetString()!);
            }
        }

        return (allowedHosts, scopeUrls);
    }

    public static List<string>? MergeUrls(List<string>? primary, List<string>? secondary)
    {
        if (primary is not { Count: > 0 } && secondary is not { Count: > 0 })
            return primary ?? secondary;
        var merged = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var list in new[] { primary, secondary })
        {
            if (list == null) continue;
            foreach (var item in list)
            {
                if (string.IsNullOrWhiteSpace(item)) continue;
                if (seen.Add(item.Trim()))
                    merged.Add(item.Trim());
            }
        }
        return merged.Count > 0 ? merged : null;
    }
}
