using System.Text.Json;
using System.Text.Json.Nodes;
using Trowser.Automation;

namespace Trowser.EndpointProbe;

/// <summary>
/// Single-fault request probes for the Endpoint Probe dialog.
/// Each probe changes one thing (field, query value, or header) so a 500 names a cause.
/// Bodies are raw strings: a duplicated JSON key is not rewritten by a JSON serializer.
/// </summary>
internal static class EndpointProbeFuzzer
{
    public const int MaxProbes = 80;
    public const int MaxFields = 8;
    public const int MaxBodyChars = 64_000;

    internal sealed class FuzzProbe
    {
        public required string Fault { get; init; }
        public required string Method { get; init; }
        public required string Url { get; init; }
        public required Dictionary<string, string> Headers { get; init; }
        public string? Body { get; init; }

        /// <summary>When set, a response that contains this text is logged as a reflection note.</summary>
        public string? ReflectNeedle { get; init; }
    }

    /// <summary>
    /// Active safety mode: structural faults, naughty strings, Content-Type matrix, forwarding and Range headers.
    /// Aggressive (<paramref name="includeInjection"/>): those, plus technology injection on the first string field or query parameter.
    /// Header probes always replay captured headers. Body and query probes honor <paramref name="useCapturedHeaders"/>.
    /// </summary>
    public static List<FuzzProbe> BuildProbes(EndpointProbeItem endpoint, bool includeInjection, bool useCapturedHeaders)
    {
        var probes = new List<FuzzProbe>();
        var json = LooksLikeJson(endpoint) && !endpoint.Method.Equals("GET", StringComparison.OrdinalIgnoreCase)
            && !endpoint.Method.Equals("HEAD", StringComparison.OrdinalIgnoreCase);
        var bodyTooBig = (endpoint.RequestBody?.Length ?? 0) > MaxBodyChars;

        if (json && !bodyTooBig && endpoint.RequestBody != null)
            AddJsonProbes(endpoint, includeInjection, useCapturedHeaders, probes);

        if (endpoint.Method.Equals("GET", StringComparison.OrdinalIgnoreCase)
            && Uri.TryCreate(endpoint.Url, UriKind.Absolute, out var uri)
            && uri.Query.Length > 1)
            AddQueryProbes(endpoint, uri, includeInjection, useCapturedHeaders, probes);

        if (json && !bodyTooBig)
            AddContentTypeProbes(endpoint, probes);

        AddTransportHeaderProbes(endpoint, probes);
        return probes;
    }

    public static bool LooksLikeJson(EndpointProbeItem endpoint)
    {
        if (string.IsNullOrEmpty(endpoint.RequestBody)) return false;
        var body = endpoint.RequestBody.TrimStart();
        if (body.StartsWith('{') || body.StartsWith('[')) return true;
        return endpoint.RequestHeaders.Values.Any(v =>
            v.Contains("json", StringComparison.OrdinalIgnoreCase));
    }

    private static void AddJsonProbes(EndpointProbeItem endpoint, bool includeInjection, bool useCapturedHeaders, List<FuzzProbe> probes)
    {
        JsonNode? root;
        try { root = JsonNode.Parse(endpoint.RequestBody!); }
        catch { return; }
        if (root == null) return;

        var headers = HeadersFor(endpoint, useCapturedHeaders, forceJson: true);
        var stringPaths = new List<List<Seg>>();
        var fieldCount = 0;

        void Add(string fault, string? body, string? needle = null)
        {
            if (probes.Count >= MaxProbes || body == null) return;
            probes.Add(new FuzzProbe
            {
                Fault = fault,
                Method = endpoint.Method,
                Url = endpoint.Url,
                Headers = headers,
                Body = body,
                ReflectNeedle = needle
            });
        }

        if (root is JsonObject obj)
        {
            var extra = JsonNode.Parse(obj.ToJsonString())!.AsObject();
            var extraName = extra.ContainsKey("__fuzz_extra") ? "__fuzz_extra_2" : "__fuzz_extra";
            extra[extraName] = "unexpected";
            Add($"add unexpected field {extraName}", extra.ToJsonString());

            var dup = DuplicateFirstKey(obj);
            if (dup != null) Add("send the first JSON key twice", dup);

            Walk(root);
        }
        else if (root is JsonArray)
        {
            Add("send a string where the JSON body is an array", "\"not-an-array\"");
            Walk(root);
        }

        if (stringPaths.Count > 0)
            AddNaughty(stringPaths[0]);
        if (includeInjection && stringPaths.Count > 0)
            AddInjection(stringPaths[0]);
        for (var i = 1; i < stringPaths.Count && probes.Count < MaxProbes; i++)
            AddNaughty(stringPaths[i]);

        void Walk(JsonNode node, List<Seg>? path = null)
        {
            path ??= new List<Seg>();
            if (fieldCount >= MaxFields) return;

            if (node is JsonObject o)
            {
                foreach (var kv in o.ToList())
                {
                    if (fieldCount >= MaxFields) return;
                    var child = new List<Seg>(path) { new(false, kv.Key, 0) };
                    if (kv.Value == null)
                    {
                        fieldCount++;
                        Leaf(child, JsonValue.Create(0)!, isString: false);
                    }
                    else Walk(kv.Value, child);
                }
                return;
            }

            if (node is JsonArray a)
            {
                if (a.Count > 0 && a[0] != null)
                    Walk(a[0]!, new List<Seg>(path) { new(true, "", 0) });
                if (path.Count > 0)
                {
                    fieldCount++;
                    var label = FormatPath(path);
                    Add($"type change at {label} (array to string)", Rewrite(root, path, JsonValue.Create("not-an-array"), omit: false));
                    Add($"null at {label}", Rewrite(root, path, JsonNode.Parse("null"), omit: false));
                }
                return;
            }

            fieldCount++;
            var isString = node is JsonValue jv && jv.GetValueKind() == JsonValueKind.String;
            Leaf(path, node, isString);
        }

        void Leaf(List<Seg> path, JsonNode node, bool isString)
        {
            if (path.Count == 0) return;
            var label = FormatPath(path);
            Add($"type change at {label}", Rewrite(root, path, Swapped(node), omit: false));
            Add($"null at {label}", Rewrite(root, path, JsonNode.Parse("null"), omit: false));
            if (!path[^1].IsIndex)
                Add($"omit {label}", Rewrite(root, path, null, omit: true));
            if (isString) stringPaths.Add(path);
        }

        void AddNaughty(List<Seg> path)
        {
            var label = FormatPath(path);
            Add($"empty string at {label}", Rewrite(root, path, JsonValue.Create(""), omit: false));
            Add($"whitespace at {label}", Rewrite(root, path, JsonValue.Create("   "), omit: false));
            foreach (var (name, value, needle) in NaughtyStrings())
            {
                if (probes.Count >= MaxProbes) break;
                Add($"naughty {name} at {label}", Rewrite(root, path, JsonValue.Create(value), omit: false), needle);
            }
        }

        void AddInjection(List<Seg> path)
        {
            var label = FormatPath(path);
            foreach (var (cat, name, payload) in InjectionPayloads)
            {
                if (probes.Count >= MaxProbes) break;
                Add($"injection {cat}:{name} at {label}", Rewrite(root, path, JsonValue.Create(payload), omit: false), payload);
            }
        }
    }

    private static void AddQueryProbes(EndpointProbeItem endpoint, Uri uri, bool includeInjection, bool useCapturedHeaders, List<FuzzProbe> probes)
    {
        var pairs = ParseQuery(uri.Query);
        if (pairs.Count == 0) return;
        var headers = HeadersFor(endpoint, useCapturedHeaders, forceJson: false);

        void Add(string fault, string url, string? needle = null)
        {
            if (probes.Count >= MaxProbes) return;
            probes.Add(new FuzzProbe
            {
                Fault = fault,
                Method = "GET",
                Url = url,
                Headers = headers,
                ReflectNeedle = needle
            });
        }

        var withExtra = pairs.ToList();
        withExtra.Add(new QPair("__fuzz", "1"));
        Add("add unexpected query param __fuzz", BuildUrl(uri, withExtra));

        var limit = Math.Min(pairs.Count, 3);
        for (var i = 0; i < limit; i++)
        {
            var key = pairs[i].Key;
            Add($"omit query param {key}", BuildUrl(uri, Without(pairs, i)));
            Add($"empty query param {key}", BuildUrl(uri, ReplaceAt(pairs, i, "")));
            Add($"whitespace query param {key}", BuildUrl(uri, ReplaceAt(pairs, i, "   ")));
            Add($"very long query param {key}", BuildUrl(uri, ReplaceAt(pairs, i, new string('A', 4096))));
        }

        if (!includeInjection) return;
        foreach (var (cat, name, payload) in InjectionPayloads)
        {
            if (probes.Count >= MaxProbes) break;
            Add($"injection {cat}:{name} in query {pairs[0].Key}", BuildUrl(uri, ReplaceAt(pairs, 0, payload)), payload);
        }
    }

    private static void AddContentTypeProbes(EndpointProbeItem endpoint, List<FuzzProbe> probes)
    {
        foreach (var (name, ct) in ContentTypes)
        {
            if (probes.Count >= MaxProbes) return;
            var headers = HeadersFor(endpoint, useCaptured: true, forceJson: false);
            headers["Content-Type"] = ct;
            probes.Add(new FuzzProbe
            {
                Fault = $"Content-Type {name} ({(ct.Length == 0 ? "empty" : ct)}) with the original JSON body",
                Method = endpoint.Method,
                Url = endpoint.Url,
                Headers = headers,
                Body = endpoint.RequestBody
            });
        }
    }

    private static void AddTransportHeaderProbes(EndpointProbeItem endpoint, List<FuzzProbe> probes)
    {
        void One(string fault, string name, string value)
        {
            if (probes.Count >= MaxProbes) return;
            var headers = HeadersFor(endpoint, useCaptured: true, forceJson: LooksLikeJson(endpoint));
            headers[name] = value;
            probes.Add(new FuzzProbe
            {
                Fault = fault,
                Method = endpoint.Method,
                Url = endpoint.Url,
                Headers = headers,
                Body = string.IsNullOrEmpty(endpoint.RequestBody) ? null : endpoint.RequestBody
            });
        }

        One("unsatisfiable Accept", "Accept", "application/x-does-not-exist");
        One("oversized X-Fuzz-Overflow header", "X-Fuzz-Overflow", new string('A', 8192));
        One("X-Forwarded-For extreme", "X-Forwarded-For", "999999999999");
        One("X-Forwarded-Host", "X-Forwarded-Host", "127.0.0.1");
        One("X-Original-URL traversal", "X-Original-URL", "/../../etc/passwd");
        One("Range extreme", "Range", "bytes=0-999999999999");
    }

    private static Dictionary<string, string> HeadersFor(EndpointProbeItem endpoint, bool useCaptured, bool forceJson)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (useCaptured)
        {
            foreach (var kv in endpoint.RequestHeaders)
            {
                if (SkipHeader(kv.Key)) continue;
                headers[kv.Key] = kv.Value;
            }
        }
        if (forceJson)
            headers["Content-Type"] = "application/json";
        return headers;
    }

    private static bool SkipHeader(string name)
    {
        var n = name.ToLowerInvariant();
        if (n.StartsWith("sec-", StringComparison.Ordinal) || n.StartsWith("proxy-", StringComparison.Ordinal))
            return true;
        return n is "cookie" or "host" or "content-length" or "connection" or "accept-encoding"
            or "origin" or "referer" or "transfer-encoding" or "keep-alive" or "te" or "upgrade"
            or "content-encoding" or "trailer";
    }

    private static string? DuplicateFirstKey(JsonObject obj)
    {
        KeyValuePair<string, JsonNode?>? firstPair = null;
        var parts = new List<string>();
        foreach (var kv in obj)
        {
            firstPair ??= kv;
            parts.Add(JsonSerializer.Serialize(kv.Key) + ":" + (kv.Value?.ToJsonString() ?? "null"));
        }
        if (firstPair == null) return null;
        var first = firstPair.Value;
        string dupJson;
        if (first.Value is JsonValue jv && jv.GetValueKind() == JsonValueKind.String)
            dupJson = JsonSerializer.Serialize(jv.GetValue<string>() + "-dup");
        else
            dupJson = "\"__duplicate__\"";
        parts.Add(JsonSerializer.Serialize(first.Key) + ":" + dupJson);
        return "{" + string.Join(",", parts) + "}";
    }

    private static JsonNode Swapped(JsonNode node)
    {
        if (node is JsonObject) return JsonValue.Create("not-an-object")!;
        if (node is JsonArray) return JsonValue.Create("not-an-array")!;
        if (node is JsonValue v)
        {
            var k = v.GetValueKind();
            if (k == JsonValueKind.String) return JsonValue.Create(123456)!;
            if (k == JsonValueKind.Number) return JsonValue.Create("not-a-number")!;
            if (k is JsonValueKind.True or JsonValueKind.False) return JsonValue.Create("not-a-bool")!;
        }
        return JsonValue.Create("x")!;
    }

    private static string? Rewrite(JsonNode root, List<Seg> path, JsonNode? replacement, bool omit)
    {
        var clone = JsonNode.Parse(root.ToJsonString());
        if (clone == null || path.Count == 0) return null;
        var parent = clone;
        for (var i = 0; i < path.Count - 1; i++)
        {
            var next = Step(parent, path[i]);
            if (next == null) return null;
            parent = next;
        }
        var last = path[^1];
        if (omit)
        {
            if (!last.IsIndex && parent is JsonObject o)
                o.Remove(last.Prop);
            return clone.ToJsonString();
        }
        if (!last.IsIndex && parent is JsonObject po)
            po[last.Prop] = replacement;
        else if (last.IsIndex && parent is JsonArray a && last.Index >= 0 && last.Index < a.Count)
            a[last.Index] = replacement;
        else
            return null;
        return clone.ToJsonString();
    }

    private static JsonNode? Step(JsonNode node, Seg seg)
    {
        if (!seg.IsIndex && node is JsonObject o) return o[seg.Prop];
        if (seg.IsIndex && node is JsonArray a && seg.Index >= 0 && seg.Index < a.Count) return a[seg.Index];
        return null;
    }

    private static string FormatPath(List<Seg> path)
    {
        var sb = new System.Text.StringBuilder();
        foreach (var seg in path)
        {
            if (seg.IsIndex) sb.Append('[').Append(seg.Index).Append(']');
            else
            {
                if (sb.Length > 0) sb.Append('.');
                sb.Append(seg.Prop);
            }
        }
        return sb.Length == 0 ? "(body)" : sb.ToString();
    }

    private static List<QPair> ParseQuery(string query)
    {
        var list = new List<QPair>();
        var q = query.TrimStart('?');
        if (q.Length == 0) return list;
        foreach (var part in q.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0) continue;
            var key = Uri.UnescapeDataString(part[..eq].Replace('+', ' '));
            var val = eq < part.Length - 1 ? Uri.UnescapeDataString(part[(eq + 1)..].Replace('+', ' ')) : "";
            list.Add(new QPair(key, val));
        }
        return list;
    }

    private static List<QPair> ReplaceAt(List<QPair> pairs, int index, string value)
    {
        var copy = pairs.ToList();
        copy[index] = new QPair(copy[index].Key, value);
        return copy;
    }

    private static List<QPair> Without(List<QPair> pairs, int index)
    {
        var copy = pairs.ToList();
        copy.RemoveAt(index);
        return copy;
    }

    private static string BuildUrl(Uri uri, List<QPair> pairs)
    {
        var q = string.Join("&", pairs.Select(p => Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(p.Value)));
        return uri.GetLeftPart(UriPartial.Path) + (q.Length > 0 ? "?" + q : "");
    }

    private static readonly (string Name, string Value)[] ContentTypes =
    {
        ("multipart-mixed", "multipart/mixed"),
        ("multipart-form", "multipart/form-data"),
        ("text-plain", "text/plain"),
        ("xml", "application/xml"),
        ("java-serialized", "application/x-java-serialized-object"),
        ("empty", ""),
        ("wildcard", "*/*"),
        ("bad-charset", "application/json; charset=not-a-charset"),
    };

    private static IEnumerable<(string Name, string Value, string? Needle)> NaughtyStrings()
    {
        yield return ("emoji", "😍👩🏽‍💻🏳️‍🌈", "😍");
        yield return ("rtl-override", "\u202etxet desrever", "txet desrever");
        yield return ("zalgo", "Z\u0361\u0362a\u0334\u0356g\u0334o", null);
        yield return ("zero-width", "a\u200bb\u200cc\u200dd\ufeff", null);
        yield return ("format-string", "%s%s%s%n%x%x", "%s%s%s%n%x%x");
        yield return ("fullwidth", "１２３４５", "１２３４５");
        yield return ("reserved-word", "NaN", null);
        yield return ("bignum-string", new string('9', 300), null);
        yield return ("null-char", "a\u0000b", null);
        yield return ("mixed-newlines", "a\r\nb\nc\rd", null);
        yield return ("quotes", "'\"`", null);
        yield return ("brace-soup", "${{{}}}", "${{{}}}");
        yield return ("huge", new string('A', 20000), null);
    }

    private static readonly (string Cat, string Name, string Payload)[] InjectionPayloads =
    {
        ("sql", "or-1-1", "' OR '1'='1"),
        ("sql", "comment", "'--"),
        ("nosql", "ne-null", "{\"$ne\":null}"),
        ("nosql", "gt-empty", "{\"$gt\":\"\"}"),
        ("command", "semicolon", "; id"),
        ("command", "subshell", "$(id)"),
        ("xss", "script", "<script>alert(1)</script>"),
        ("xss", "img-onerror", "\"><img src=x onerror=alert(1)>"),
        ("traversal", "etc-passwd", "../../../../etc/passwd"),
        ("template", "mustache", "{{7*7}}"),
        ("template", "dollar", "${7*7}"),
        ("ldap", "wildcard", "*)(uid=*"),
        ("xxe", "entity", "<!DOCTYPE a [<!ENTITY e \"x\">]><a>&e;</a>"),
    };

    private readonly record struct Seg(bool IsIndex, string Prop, int Index);
    private readonly record struct QPair(string Key, string Value);
}
