using System.Text.Json;
using System.Text.RegularExpressions;
using System.Web;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Harvests object IDs from network traffic and DOM for authz/boundary testing.
/// </summary>
public static class ObjectIdHarvester
{
    public sealed class HarvestOptions
    {
        public string? Host { get; set; }
        public int MaxIdsPerKind { get; set; } = 12;
        public bool IncludeDom { get; set; } = true;
    }

    public sealed class HarvestedId
    {
        public string Kind { get; init; } = "";
        /// <summary>Alias for API consumers expecting <c>type</c>.</summary>
        public string Type => Kind;
        public string Value { get; init; } = "";
        public string Source { get; init; } = "";
        public string? ContextUrl { get; init; }
        public string? SuggestedParam { get; init; }
        /// <summary>Alias for API consumers expecting <c>paramName</c>.</summary>
        public string? ParamName => SuggestedParam;
        public bool Sequential { get; init; }
    }

    public sealed class BoundarySuggestion
    {
        public string UrlTemplate { get; init; } = "";
        public string? Parameter { get; init; }
        public List<string> AuthorizedValues { get; init; } = [];
        public List<string> UnauthorizedValues { get; init; } = [];
        public string? Method { get; init; }
        public string Reason { get; init; } = "";
    }

    public sealed class HarvestResult
    {
        public List<HarvestedId> Ids { get; init; } = [];
        public List<BoundarySuggestion> SuggestedBoundaryTests { get; init; } = [];
        public List<string> Summary { get; init; } = [];
    }

    private static readonly Regex NumericPathId = new(@"(?<=/)(\d{1,12})(?=/|$|\?)", RegexOptions.Compiled);
    private static readonly Regex GuidId = new(@"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex HexToken = new(@"(?<=/)([0-9a-f]{16,64})(?=/|$|\?)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex JsonIdField = new(@"""(?<field>[a-zA-Z_][\w]*)"":\s*(""(?<str>[^""]{1,80})""|(?<num>\d+))", RegexOptions.Compiled);

    private static readonly HashSet<string> StaticExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map", ".webp", ".avif"
    };

    private static readonly HashSet<string> IdParamNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "id", "userid", "user_id", "orderid", "order_id", "productid", "product_id", "postid", "post_id",
        "accountid", "account_id", "basketid", "basket_id", "documentid", "document_id", "itemid", "item_id",
        "artist", "cat", "category", "album", "pic", "photo", "image", "page", "ref", "slug", "uid", "gid", "pid", "nid", "tid", "bid", "sku"
    };

    private static readonly HashSet<string> NonObjectQueryParams = new(StringComparer.OrdinalIgnoreCase)
    {
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid", "msclkid",
        "ver", "version", "v", "cache", "cb", "t", "ts", "_", "rand", "nocache"
    };

    /// <summary>Names that end in Id but are not object identifiers for authz/boundary.</summary>
    private static readonly HashSet<string> NonObjectIdFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "operationId", "requestId", "traceId", "spanId", "correlationId", "sessionId"
    };

    public static async Task<HarvestResult> RunAsync(
        AutomationContext ctx,
        HarvestOptions options,
        CancellationToken ct = default)
    {
        var ids = new List<HarvestedId>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string kind, string value, string source, string? url, string? param)
        {
            if (string.IsNullOrWhiteSpace(value)) return;
            if (value.Length > 80) return;
            if (LooksLikeInjectionOrFuzzPayload(value)) return;
            var key = $"{kind}|{param}|{value}";
            if (!seen.Add(key)) return;
            ids.Add(new HarvestedId
            {
                Kind = kind,
                Value = value,
                Source = source,
                ContextUrl = url,
                SuggestedParam = param
            });
        }

        string? pageUrl = null;
        try { pageUrl = await ctx.GetCurrentUrl(); }
        catch { /* scope falls back to an explicit host */ }
        var scopeHost = SecurityHostScope.ResolveScopeHost(options.Host, pageUrl);

        var entries = SelectHarvestEntries(ctx.Network.Entries, options, scopeHost);

        foreach (var entry in entries)
        {
            ct.ThrowIfCancellationRequested();
            CollectFromEntry(entry, Add);
        }

        if (options.IncludeDom)
        {
            try
            {
                var domJson = await ctx.ExecuteJs(
                    """
                    (function(){
                      var out = [];
                      document.querySelectorAll('[data-id],[data-user-id],[data-order-id],[data-product-id]').forEach(function(el){
                        var id = el.getAttribute('data-id') || el.getAttribute('data-user-id') || el.getAttribute('data-order-id') || el.getAttribute('data-product-id');
                        if (id) out.push({kind:'dom-attr', value:id, param: el.getAttribute('data-product-id')?'productId':(el.getAttribute('data-user-id')?'userId':'id')});
                      });
                      document.querySelectorAll('input[type=hidden][name]').forEach(function(el){
                        var n = (el.getAttribute('name')||'').toLowerCase();
                        if (/id$/.test(n) || n.indexOf('userid')>=0 || n.indexOf('productid')>=0) {
                          var v = el.value||'';
                          if (v.length>0 && v.length<80) out.push({kind:'dom-hidden', value:v, param: el.getAttribute('name'), href: location.href});
                        }
                      });
                      return JSON.stringify(out.slice(0,40));
                    })()
                    """);
                using var doc = JsonDocument.Parse(domJson);
                foreach (var el in doc.RootElement.EnumerateArray())
                {
                    var kind = el.TryGetProperty("kind", out var k) ? k.GetString() ?? "dom" : "dom";
                    var value = el.TryGetProperty("value", out var v) ? v.GetString() ?? "" : "";
                    var param = el.TryGetProperty("param", out var p) ? p.GetString() : "id";
                    var href = el.TryGetProperty("href", out var h) ? h.GetString() : await ctx.GetCurrentUrl();
                    Add(kind, value, "dom", href, param);
                }
            }
            catch
            {
                // DOM harvest is best-effort
            }
        }

        MarkSequential(ids);
        ids = CapIds(ids, options.MaxIdsPerKind);

        var suggestions = BuildBoundarySuggestions(ids, entries);
        var summary = new List<string>();
        if (ids.Count > 0)
            summary.Add($"Harvested {ids.Count} object identifier(s) from network/DOM.");
        if (suggestions.Count > 0)
            summary.Add($"Generated {suggestions.Count} suggested authz/boundary test(s).");
        if (ids.Count == 0)
            summary.Add("No object IDs found — browse API/product pages or interact with parameterized URLs first.");

        return new HarvestResult
        {
            Ids = ids,
            SuggestedBoundaryTests = suggestions,
            Summary = summary
        };
    }

    /// <summary>Network-log harvest without DOM. Used by <see cref="RunAsync"/> and tests.</summary>
    internal static HarvestResult HarvestNetwork(IReadOnlyList<NetworkEntry> source, HarvestOptions options, string? scopeHost)
    {
        var ids = new List<HarvestedId>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(string kind, string value, string sourceName, string? url, string? param)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length > 80) return;
            if (LooksLikeInjectionOrFuzzPayload(value)) return;
            if (!seen.Add($"{kind}|{param}|{value}")) return;
            ids.Add(new HarvestedId
            {
                Kind = kind,
                Value = value,
                Source = sourceName,
                ContextUrl = url,
                SuggestedParam = param
            });
        }

        var entries = SelectHarvestEntries(source, options, scopeHost);
        foreach (var entry in entries)
            CollectFromEntry(entry, Add);

        MarkSequential(ids);
        ids = CapIds(ids, options.MaxIdsPerKind);
        var suggestions = BuildBoundarySuggestions(ids, entries);
        var summary = new List<string>();
        if (ids.Count > 0)
            summary.Add($"Harvested {ids.Count} object identifier(s) from network/DOM.");
        if (suggestions.Count > 0)
            summary.Add($"Generated {suggestions.Count} suggested authz/boundary test(s).");
        if (ids.Count == 0)
            summary.Add("No object IDs found — browse API/product pages or interact with parameterized URLs first.");

        return new HarvestResult
        {
            Ids = ids,
            SuggestedBoundaryTests = suggestions,
            Summary = summary
        };
    }

    internal static List<NetworkEntry> SelectHarvestEntries(
        IEnumerable<NetworkEntry> entries, HarvestOptions options, string? scopeHost) =>
        entries
            .Where(e => IsUsefulNetworkUrl(e.Url))
            .Where(e => SecurityHostScope.MatchesHostFilter(e.Host, options.Host))
            .Where(e => !SecurityHostScope.IsOutsideApplicationScope(e.Host, scopeHost))
            .ToList();

    private static void CollectFromEntry(NetworkEntry entry, Action<string, string, string, string?, string?> add)
    {
        if (entry.StatusCode is <= 0 or >= 400) return;
        if (entry.ResourceType is "Image" or "Script" or "Stylesheet" or "Font" or "Media") return;
        if (IsOpenApiDocument(entry)) return;

        if (Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri))
        {
            var qs = HttpUtility.ParseQueryString(uri.Query);
            foreach (string? key in qs.AllKeys)
            {
                if (string.IsNullOrWhiteSpace(key)) continue;
                var val = qs[key];
                if (!LooksLikeIdParam(key, val)) continue;
                add(ClassifyValue(val), val!, "query-param", StripQuery(entry.Url), key);
            }
        }

        if (!IsLikelyStaticAssetPath(entry.Path))
        {
            foreach (Match m in NumericPathId.Matches(entry.Path))
            {
                if (!IsLikelyResourceSegment(entry.Path, m.Groups[1].Value)) continue;
                add("numeric", m.Groups[1].Value, "network-path", entry.Url, InferParamFromPath(entry.Path));
            }
        }

        foreach (Match m in GuidId.Matches(entry.Url))
            add("guid", m.Value, "network-path", entry.Url, "id");

        foreach (Match m in HexToken.Matches(entry.Path))
            add("hex-token", m.Groups[1].Value, "network-path", entry.Url, "token");

        var body = entry.ResponseBody ?? "";
        if (body.Length is > 0 and < 500_000 && !body.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
        {
            foreach (Match m in JsonIdField.Matches(body))
            {
                var field = m.Groups["field"].Value;
                if (!DefaultPrivilegedField(field)) continue;
                var raw = m.Groups["str"].Success ? m.Groups["str"].Value : m.Groups["num"].Value;
                add(ClassifyValue(raw), raw, "network-json", entry.Url, field);
            }
        }
    }

    internal static bool IsOpenApiDocument(NetworkEntry entry)
    {
        var url = entry.Url ?? "";
        if (url.Contains("swagger", StringComparison.OrdinalIgnoreCase)
            || url.Contains("openapi", StringComparison.OrdinalIgnoreCase)
            || url.Contains("api-docs", StringComparison.OrdinalIgnoreCase))
            return true;

        var body = entry.ResponseBody;
        if (string.IsNullOrEmpty(body)) return false;
        var head = body.Length > 500 ? body[..500] : body;
        return OpenApiKeyRegex.IsMatch(head);
    }

    private static readonly Regex OpenApiKeyRegex = new(
        "\"(?:openapi|swagger)\"\\s*:",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static int SourcePriority(string source) => source switch
    {
        "network-path" => 0,
        "query-param" => 1,
        "network-json" => 2,
        "dom" or "dom-attr" or "dom-hidden" => 3,
        _ => 9
    };

    private static List<HarvestedId> CapIds(List<HarvestedId> ids, int maxPerKind)
    {
        var take = Math.Max(1, maxPerKind);
        return ids
            .GroupBy(i => i.Kind, StringComparer.OrdinalIgnoreCase)
            .SelectMany(g => g.OrderBy(i => SourcePriority(i.Source)).ThenBy(i => i.Value, StringComparer.Ordinal).Take(take))
            .ToList();
    }

    private static bool IsUsefulNetworkUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return false;
        if (url.StartsWith("data:", StringComparison.OrdinalIgnoreCase)) return false;
        return Uri.TryCreate(url, UriKind.Absolute, out var u) && u.Scheme is "http" or "https";
    }

    private static string StripQuery(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var u) ? $"{u.Scheme}://{u.Host}{u.AbsolutePath}" : url;

    private static bool IsLikelyStaticAssetPath(string path)
    {
        var ext = System.IO.Path.GetExtension(path);
        return !string.IsNullOrEmpty(ext) && StaticExtensions.Contains(ext);
    }

    private static bool IsLikelyResourceSegment(string path, string value)
    {
        if (IsLikelyStaticAssetPath(path)) return false;
        var lower = path.ToLowerInvariant();
        if (lower.Contains("/image/", StringComparison.Ordinal) || lower.Contains("/images/", StringComparison.Ordinal))
            return false;
        if (lower.Contains("/blog/posts/", StringComparison.Ordinal) && int.TryParse(value, out var n) && n < 1000)
            return false;
        return true;
    }

    private static bool LooksLikeIdParam(string key, string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        if (value.Length > 80) return false;
        var k = key.Trim();
        if (IdParamNames.Contains(k)) return true;
        if (k.EndsWith("Id", StringComparison.OrdinalIgnoreCase) || k.EndsWith("_id", StringComparison.OrdinalIgnoreCase))
            return true;
        return LooksLikeNumericObjectRef(k, value);
    }

    /// <summary>Short query keys with small integer values (e.g. artist=1, cat=2) on dynamic pages.</summary>
    private static bool LooksLikeNumericObjectRef(string key, string value)
    {
        if (NonObjectQueryParams.Contains(key)) return false;
        if (key.Length is < 2 or > 24) return false;
        if (!value.All(char.IsDigit)) return false;
        if (value.Length is 0 or > 12) return false;
        if (!int.TryParse(value, out var n) || n < 0) return false;
        return true;
    }

    private static bool DefaultPrivilegedField(string field)
    {
        if (NonObjectIdFields.Contains(field)) return false;
        return IdParamNames.Contains(field) || field.EndsWith("Id", StringComparison.OrdinalIgnoreCase);
    }

    private static string ClassifyValue(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "string-id";
        if (Guid.TryParse(value, out _)) return "guid";
        if (value.All(char.IsDigit)) return "numeric";
        if (Regex.IsMatch(value, @"^[0-9a-f]{16,64}$", RegexOptions.IgnoreCase)) return "hex-token";
        return "string-id";
    }

    private static string? InferParamFromPath(string path)
    {
        var lower = path.ToLowerInvariant();
        if (lower.Contains("/user")) return "userId";
        if (lower.Contains("/order")) return "orderId";
        if (lower.Contains("/product")) return "productId";
        if (lower.Contains("/post")) return "postId";
        if (lower.Contains("/basket") || lower.Contains("/cart")) return "basketId";
        if (lower.Contains("/account")) return "accountId";
        return "id";
    }

    private static void MarkSequential(List<HarvestedId> ids)
    {
        var numerics = ids
            .Where(i => i.Kind == "numeric" && int.TryParse(i.Value, out _))
            .Select(i => int.Parse(i.Value))
            .OrderBy(v => v)
            .ToList();
        if (numerics.Count < 3) return;
        var sequential = numerics.Zip(numerics.Skip(1), (a, b) => b - a).All(d => d is 1 or 0);
        if (!sequential) return;

        for (var i = 0; i < ids.Count; i++)
        {
            if (ids[i].Kind != "numeric") continue;
            var old = ids[i];
            ids[i] = new HarvestedId
            {
                Kind = old.Kind,
                Value = old.Value,
                Source = old.Source,
                ContextUrl = old.ContextUrl,
                SuggestedParam = old.SuggestedParam,
                Sequential = true
            };
        }
    }

    private static List<BoundarySuggestion> BuildBoundarySuggestions(
        List<HarvestedId> ids,
        List<NetworkEntry> entries)
    {
        var suggestions = new List<BoundarySuggestion>();

        foreach (var group in ids.Where(i => i.Source == "query-param" && i.SuggestedParam != null).GroupBy(i => i.SuggestedParam!, StringComparer.OrdinalIgnoreCase))
        {
            var values = group.Select(g => g.Value).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (values.Count < 2) continue;
            var sample = group.First();
            var template = BuildQueryTemplate(sample.ContextUrl ?? "", group.Key);
            if (string.IsNullOrWhiteSpace(template)) continue;

            suggestions.Add(new BoundarySuggestion
            {
                UrlTemplate = AttackSurfaceMapper.DecodeTemplateBraces(template),
                Parameter = group.Key,
                Method = "GET",
                AuthorizedValues = values.Take(2).ToList(),
                UnauthorizedValues = SuggestUnauthorized(values),
                Reason = $"Observed {group.Key} values {string.Join(", ", values.Take(4))} in query strings — test horizontal access via authz/boundary."
            });
        }

        AddPathIdSuggestions(suggestions, entries);
        return suggestions;
    }

    /// <summary>
    /// One boundary test per 2xx path template, including a single observed id
    /// (<c>/api/users/id/1</c> → <c>/api/users/id/{id}</c>).
    /// </summary>
    private static void AddPathIdSuggestions(List<BoundarySuggestion> suggestions, List<NetworkEntry> entries)
    {
        var groups = new Dictionary<string, PathIdGroup>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            if (entry.StatusCode is < 200 or >= 300) continue;
            if (IsOpenApiDocument(entry) || IsLikelyStaticAssetPath(entry.Path)) continue;
            if (entry.ResourceType is "Image" or "Script" or "Stylesheet" or "Font" or "Media") continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;

            var matches = NumericPathId.Matches(uri.AbsolutePath);
            if (matches.Count == 0) continue;
            var last = matches[^1];
            var id = last.Value;
            if (!IsLikelyResourceSegment(uri.AbsolutePath, id)) continue;

            var templatePath = string.Concat(uri.AbsolutePath.AsSpan(0, last.Index), "{id}", uri.AbsolutePath.AsSpan(last.Index + last.Length));
            var authority = uri.IsDefaultPort ? uri.Host : $"{uri.Host}:{uri.Port}";
            var template = $"{uri.Scheme}://{authority}{templatePath}";
            var key = $"{entry.Method}|{template}";
            if (!groups.TryGetValue(key, out var group))
            {
                group = new PathIdGroup(template, string.IsNullOrEmpty(entry.Method) ? "GET" : entry.Method);
                groups[key] = group;
            }
            if (!group.Ids.Contains(id))
                group.Ids.Add(id);
        }

        foreach (var group in groups.Values)
        {
            suggestions.Add(new BoundarySuggestion
            {
                UrlTemplate = AttackSurfaceMapper.DecodeTemplateBraces(group.Template),
                Parameter = "id",
                Method = group.Method,
                AuthorizedValues = group.Ids.Take(2).ToList(),
                UnauthorizedValues = SuggestUnauthorized(group.Ids),
                Reason = group.Ids.Count == 1
                    ? $"Numeric path id {group.Ids[0]} returned 2xx — test horizontal access via authz/boundary."
                    : $"Numeric path ids {string.Join(", ", group.Ids.Take(4))} returned 2xx — test horizontal access via authz/boundary."
            });
        }
    }

    private sealed class PathIdGroup(string template, string method)
    {
        public string Template { get; } = template;
        public string Method { get; } = method;
        public List<string> Ids { get; } = [];
    }

    /// <summary>scheme://host[:port]/path — preserves non-default ports (e.g. :4280).</summary>
    private static string FormatOriginAndPath(Uri uri)
    {
        var authority = uri.IsDefaultPort ? uri.Host : $"{uri.Host}:{uri.Port}";
        return $"{uri.Scheme}://{authority}{uri.AbsolutePath}";
    }

    private static string? BuildQueryTemplate(string contextUrl, string paramName)
    {
        if (!Uri.TryCreate(contextUrl, UriKind.Absolute, out var uri)) return null;
        var placeholder = "{" + paramName + "}";
        var qs = HttpUtility.ParseQueryString(uri.Query);
        var parts = new List<string>();
        var paramSeen = false;

        foreach (string? key in qs.AllKeys)
        {
            if (string.IsNullOrWhiteSpace(key)) continue;
            var encodedKey = Uri.EscapeDataString(key);
            if (key.Equals(paramName, StringComparison.OrdinalIgnoreCase))
            {
                parts.Add($"{encodedKey}={placeholder}");
                paramSeen = true;
            }
            else
            {
                var val = qs[key] ?? "";
                parts.Add($"{encodedKey}={Uri.EscapeDataString(val)}");
            }
        }

        if (!paramSeen)
            parts.Add($"{Uri.EscapeDataString(paramName)}={placeholder}");

        var originPath = FormatOriginAndPath(uri);
        return parts.Count == 0
            ? originPath
            : $"{originPath}?{string.Join("&", parts)}";
    }

    /// <summary>Reject scanner/fuzz payloads mistakenly harvested as object IDs.</summary>
    internal static bool LooksLikeInjectionOrFuzzPayload(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        if (value.Contains('\'') || value.Contains('"') || value.Contains('<') || value.Contains('>'))
            return true;
        if (value.Contains('§') || value.Contains("{{", StringComparison.Ordinal))
            return true;
        if (value.Contains("--") || value.Contains("/*") || value.Contains("*/"))
            return true;
        if (Regex.IsMatch(value, @"\b(AND|OR)\b.*=", RegexOptions.IgnoreCase))
            return true;
        if (Regex.IsMatch(value, @"\b(UNION|SELECT|SLEEP|WAITFOR|BENCHMARK)\b", RegexOptions.IgnoreCase))
            return true;
        if (value.Contains("alert(", StringComparison.OrdinalIgnoreCase)
            || value.Contains("onerror=", StringComparison.OrdinalIgnoreCase)
            || value.Contains("javascript:", StringComparison.OrdinalIgnoreCase))
            return true;
        if (value.Contains("%27", StringComparison.OrdinalIgnoreCase)
            || value.Contains("%22", StringComparison.OrdinalIgnoreCase)
            || value.Contains("%3c", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    private static List<string> SuggestUnauthorized(IReadOnlyList<string> observed)
    {
        var set = new HashSet<string>(observed, StringComparer.OrdinalIgnoreCase);
        var extras = new List<string>();
        if (observed.All(v => int.TryParse(v, out _)))
        {
            var max = observed.Select(int.Parse).DefaultIfEmpty(0).Max();
            foreach (var candidate in new[] { (max + 1).ToString(), (max + 999).ToString(), "0", "999999" })
                if (set.Add(candidate)) extras.Add(candidate);
        }
        else
        {
            extras.Add("999999");
            extras.Add("invalid-id-test");
        }
        return extras.Take(4).ToList();
    }
}
