// @title Request Fuzzer
// @shadow never
// @effects mutates
#nullable enable
// Request Fuzzer: single-fault 500 hunt against calls already in the network log.
// Browser fetch — cookies, CSRF, and session travel with every probe.
//
// fuzzLevel:
//   basic      structural JSON/query faults only (extra field, duplicate key, type, null, omit)
//   standard   + naughty strings, Content-Type matrix, forwarding / Range headers  (default)
//   aggressive + injection probes limited to injectionTechnologies
//
// A 4xx is a clean reject. The test fails on HTTP 5xx and on a dropped connection.
// Each failing probe is logged with method, URL, headers, body, and a curl.exe line.
string fuzzLevel = "standard";
var injectionTechnologies = new List<string> { "sql", "nosql", "command", "xss", "traversal", "template", "ldap", "xxe" };

const int MaxJsonEndpoints = 3;
const int MaxGetEndpoints = 2;
const int MaxCasesPerEndpoint = 80;
const int MaxFields = 8;
const int TimeoutMs = 8000;

var level = fuzzLevel.Trim().ToLowerInvariant();
if (level is not ("basic" or "standard" or "aggressive")) level = "standard";
var techFilter = new HashSet<string>(injectionTechnologies.Select(t => t.Trim().ToLowerInvariant()), StringComparer.OrdinalIgnoreCase);

var url = await GetCurrentUrl();
var title = await GetTitle();
Log($"Request Fuzzer Test: {title}");
Log($"URL: {url}");
Log($"Level: {level} — fails only on HTTP 5xx and dropped connections.");
if (level == "basic")
    Log("Probes: unexpected field, duplicate JSON key, type swap, null, omit.");
else if (level == "standard")
    Log("Probes: structural faults, naughty strings, Content-Type matrix (multipart/mixed and others), forwarding and Range headers.");
else
    Log($"Probes: standard set, plus injection ({string.Join(", ", techFilter)}).");
Log("Reproduction: each 5xx includes method/URL/headers/body and a curl.exe line (cookies are not embedded).");
Log("");

await WaitForIdle(1000, 10000);

var networkEntries = GetNetworkLog();
Log($"Network log: {networkEntries.Count} request(s) captured");
Log("");

if (networkEntries.Count == 0)
{
    Log("No network traffic captured yet.");
    Log("Tip: browse the site and interact with forms first to populate the network log, then re-run this test.");
    Assert.Fail("No network traffic — cannot discover endpoints for fuzzing");
    return;
}

if (!Uri.TryCreate(url, UriKind.Absolute, out var pageUri))
{
    Assert.Fail("Current page URL is not absolute — cannot scope same-origin discovery");
    return;
}

var pageHost = pageUri.Host;

var jsonEndpoints = networkEntries
    .Where(e => SameHost(e, pageHost) && IsApiLike(e) && !LooksLikeStaticAsset(e))
    .Where(e => e.Method is "POST" or "PUT" or "PATCH" or "QUERY")
    .Where(EntryHasJsonBody)
    .GroupBy(e => $"{e.Method}|{PathOf(e.Url)}")
    .Select(g => g.First())
    .Take(MaxJsonEndpoints)
    .ToList();

var getEndpoints = networkEntries
    .Where(e => SameHost(e, pageHost) && IsApiLike(e) && !LooksLikeStaticAsset(e))
    .Where(e => string.Equals(e.Method, "GET", StringComparison.OrdinalIgnoreCase))
    .Where(e => Uri.TryCreate(e.Url, UriKind.Absolute, out var u) && u.Query.Length > 1)
    .GroupBy(e => $"GET|{PathOf(e.Url)}|{QueryParamKeySignature(e.Url)}")
    .Select(g => g.First())
    .Take(MaxGetEndpoints)
    .ToList();

if (jsonEndpoints.Count == 0 && getEndpoints.Count == 0)
{
    Log("No fuzzable endpoints found in the network log.");
    Log("Supported: POST/PUT/PATCH/QUERY with a JSON body, or GET with query parameters.");
    Log("Tip: trigger API calls or searches that hit your backend, then re-run.");
    Assert.Fail("No fuzzable endpoints discovered");
    return;
}

Log($"Discovered {jsonEndpoints.Count} JSON write(s) and {getEndpoints.Count} GET query call(s).");
Log("");

var findings = new List<Hit>();
var totalSent = 0;
var totalSkippedBrowser = 0;
var endpointsTested = 0;

foreach (var ep in jsonEndpoints)
{
    var probes = BuildJsonProbes(ep, level, techFilter);
    await RunEndpoint(ep, probes);
}

foreach (var ep in getEndpoints)
{
    var probes = BuildGetProbes(ep, level, techFilter);
    await RunEndpoint(ep, probes);
}

if (findings.Count > 0)
{
    Log("=== Reproduction ===", "#569CD6");
    Log("");
    var shown = 0;
    foreach (var hit in findings)
    {
        if (shown++ >= 20)
        {
            Log($"  ... and {findings.Count - 20} more (see the per-request lines above).");
            break;
        }
        LogRepro(hit);
    }
}

var serverErrors = findings.Count(f => f.Kind == "5xx");
var drops = findings.Count(f => f.Kind == "drop");
Log("=== Summary ===", "#569CD6");
Log($"  Endpoints:       {endpointsTested}");
Log($"  Probes sent:     {totalSent}");
Log($"  Server 5xx:      {serverErrors}");
Log($"  Dropped:         {drops}");
if (totalSkippedBrowser > 0)
    Log($"  Browser refused: {totalSkippedBrowser} (illegal header — not a server result)");

if (findings.Count > 0)
{
    Log("");
    Assert.Fail($"{findings.Count} reliability failure(s): {serverErrors} server 5xx, {drops} dropped connection(s)");
}
else
{
    Log("");
    Assert.Pass($"All {totalSent} probe(s) across {endpointsTested} endpoint(s) were rejected cleanly or handled");
}

// ---------- endpoint run ----------

async Task RunEndpoint(NetworkEntry ep, List<Probe> probes)
{
    endpointsTested++;
    var path = PathAndQuery(ep.Url);
    Log($"=== {ep.Method} {path} — {probes.Count} probe(s) ===", "#569CD6");

    var baseline = await Send(new Probe
    {
        Fault = "baseline (captured request)",
        Method = ep.Method,
        Url = ep.Url,
        Headers = HeadersFromEntry(ep, forceJson: EntryHasJsonBody(ep)),
        Body = string.IsNullOrEmpty(ep.RequestBody) ? null : ep.RequestBody,
    });
    totalSent++;

    if (baseline.Status >= 500 || baseline.Dropped)
    {
        var hit = HitFrom(ep, new Probe
        {
            Fault = "baseline (captured request)",
            Method = ep.Method,
            Url = ep.Url,
            Headers = HeadersFromEntry(ep, forceJson: EntryHasJsonBody(ep)),
            Body = ep.RequestBody,
        }, baseline);
        findings.Add(hit);
        Log($"  Baseline already failed ({Describe(baseline)}) — mutations skipped so they are not double-counted.", "#F44747");
        Log("");
        return;
    }

    Log($"  Baseline {baseline.Status} — sending {probes.Count} single-fault probe(s)");
    foreach (var probe in probes)
    {
        var sent = await Send(probe);
        if (sent.BrowserRefused)
        {
            totalSkippedBrowser++;
            continue;
        }
        totalSent++;
        if (sent.Status >= 500 || sent.Dropped)
        {
            var hit = HitFrom(ep, probe, sent);
            findings.Add(hit);
            var col = sent.Status >= 500 ? "#F44747" : "#CCCC00";
            Log($"  {Describe(sent)} — {probe.Fault}", col);
        }
    }
    Log("");
}

// ---------- probe builders ----------

List<Probe> BuildJsonProbes(NetworkEntry ep, string lvl, HashSet<string> techs)
{
    var probes = new List<Probe>();
    var headers = HeadersFromEntry(ep, forceJson: true);
    if (ep.RequestBody!.Length > 64000)
    {
        Log($"  Skip {ep.Method} {PathOf(ep.Url)} — JSON body is over 64 KB");
        return probes;
    }

    System.Text.Json.Nodes.JsonNode? root;
    try { root = System.Text.Json.Nodes.JsonNode.Parse(ep.RequestBody); }
    catch { return probes; }
    if (root == null) return probes;

    var stringPaths = new List<List<Seg>>();
    var fieldCount = 0;

    void Add(string fault, string? body, Dictionary<string, string>? headerOverride = null)
    {
        if (probes.Count >= MaxCasesPerEndpoint || body == null && headerOverride == null) return;
        probes.Add(new Probe
        {
            Fault = fault,
            Method = ep.Method,
            Url = ep.Url,
            Headers = headerOverride ?? headers,
            Body = body ?? ep.RequestBody,
        });
    }

    if (root is System.Text.Json.Nodes.JsonObject obj)
    {
        var extra = System.Text.Json.Nodes.JsonNode.Parse(obj.ToJsonString())!.AsObject();
        var extraName = extra.ContainsKey("__fuzz_extra") ? "__fuzz_extra_2" : "__fuzz_extra";
        extra[extraName] = "unexpected";
        Add($"add unexpected field {extraName}", extra.ToJsonString());

        var dup = DuplicateFirstKey(obj);
        if (dup != null) Add("send the first JSON key twice", dup);

        Walk(root, new List<Seg>(), canOmit: false);
    }
    else if (root is System.Text.Json.Nodes.JsonArray)
    {
        Add("send a string where the JSON body is an array", "\"not-an-array\"");
        Walk(root, new List<Seg>(), canOmit: false);
    }

    if (lvl != "basic")
    {
        foreach (var (name, ct) in FuzzCatalog.ContentTypes)
        {
            var h = CopyHeaders(headers);
            h["Content-Type"] = ct;
            Add($"Content-Type {name} ({(ct.Length == 0 ? "empty" : ct)}) with the original JSON body", ep.RequestBody, h);
        }
        AddHeaderProbes(ep, headers, hasBody: true, Add);
        if (stringPaths.Count > 0)
            AddNaughty(stringPaths[0]);
        if (lvl == "aggressive" && stringPaths.Count > 0)
            AddInjection(stringPaths[0]);
        for (var si = 1; si < stringPaths.Count && probes.Count < MaxCasesPerEndpoint; si++)
            AddNaughty(stringPaths[si]);
    }

    return probes;

    void Walk(System.Text.Json.Nodes.JsonNode node, List<Seg> path, bool canOmit)
    {
        if (fieldCount >= MaxFields) return;
        if (node is System.Text.Json.Nodes.JsonObject o)
        {
            foreach (var kv in o.ToList())
            {
                if (fieldCount >= MaxFields) return;
                var child = new List<Seg>(path) { new Seg(false, kv.Key, 0) };
                if (kv.Value == null)
                {
                    fieldCount++;
                    Leaf(child, System.Text.Json.Nodes.JsonValue.Create(0), isString: false);
                }
                else Walk(kv.Value, child, canOmit: true);
            }
            return;
        }
        if (node is System.Text.Json.Nodes.JsonArray a)
        {
            if (a.Count > 0 && a[0] != null)
                Walk(a[0]!, new List<Seg>(path) { new Seg(true, "", 0) }, canOmit: false);
            if (path.Count > 0)
            {
                fieldCount++;
                Add($"type change at {FormatPath(path)} (array to string)", Rewrite(root, path, System.Text.Json.Nodes.JsonValue.Create("not-an-array"), omit: false));
                Add($"null at {FormatPath(path)}", Rewrite(root, path, System.Text.Json.Nodes.JsonNode.Parse("null"), omit: false));
            }
            return;
        }
        fieldCount++;
        var isString = node is System.Text.Json.Nodes.JsonValue jv && jv.GetValueKind() == System.Text.Json.JsonValueKind.String;
        Leaf(path, node, isString);
    }

    void Leaf(List<Seg> path, System.Text.Json.Nodes.JsonNode node, bool isString)
    {
        if (path.Count == 0) return;
        var label = FormatPath(path);
        Add($"type change at {label}", Rewrite(root, path, Swapped(node), omit: false));
        Add($"null at {label}", Rewrite(root, path, System.Text.Json.Nodes.JsonNode.Parse("null"), omit: false));
        if (path.Count > 0 && !path[^1].IsIndex)
            Add($"omit {label}", Rewrite(root, path, null, omit: true));
        if (isString) stringPaths.Add(path);
    }

    void AddNaughty(List<Seg> path)
    {
        var label = FormatPath(path);
        Add($"empty string at {label}", Rewrite(root, path, System.Text.Json.Nodes.JsonValue.Create(""), omit: false));
        Add($"whitespace at {label}", Rewrite(root, path, System.Text.Json.Nodes.JsonValue.Create("   "), omit: false));
        foreach (var (n, value) in FuzzCatalog.NaughtyStrings())
        {
            if (probes.Count >= MaxCasesPerEndpoint) break;
            Add($"naughty {n} at {label}", Rewrite(root, path, System.Text.Json.Nodes.JsonValue.Create(value), omit: false));
        }
    }

    void AddInjection(List<Seg> path)
    {
        var label = FormatPath(path);
        foreach (var (cat, name, payload) in FuzzCatalog.InjectionPayloads)
        {
            if (!techs.Contains(cat)) continue;
            if (probes.Count >= MaxCasesPerEndpoint) break;
            Add($"injection {cat}:{name} at {label}", Rewrite(root, path, System.Text.Json.Nodes.JsonValue.Create(payload), omit: false));
        }
    }
}

List<Probe> BuildGetProbes(NetworkEntry ep, string lvl, HashSet<string> techs)
{
    var probes = new List<Probe>();
    var headers = HeadersFromEntry(ep, forceJson: false);
    if (!Uri.TryCreate(ep.Url, UriKind.Absolute, out var uri)) return probes;
    var pairs = ParseQuery(uri.Query);
    if (pairs.Count == 0) return probes;

    void Add(string fault, string probeUrl, Dictionary<string, string>? headerOverride = null)
    {
        if (probes.Count >= MaxCasesPerEndpoint) return;
        probes.Add(new Probe
        {
            Fault = fault,
            Method = "GET",
            Url = probeUrl,
            Headers = headerOverride ?? headers,
            Body = null,
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
        if (lvl == "basic") continue;
        Add($"empty query param {key}", BuildUrl(uri, ReplaceAt(pairs, i, "")));
        Add($"whitespace query param {key}", BuildUrl(uri, ReplaceAt(pairs, i, "   ")));
        Add($"very long query param {key}", BuildUrl(uri, ReplaceAt(pairs, i, new string('A', 4096))));
    }

    if (lvl != "basic")
        AddHeaderProbes(ep, headers, hasBody: false, (fault, body, h) => Add(fault, ep.Url, h));

    if (lvl == "aggressive")
    {
        var key = pairs[0].Key;
        foreach (var (cat, name, payload) in FuzzCatalog.InjectionPayloads)
        {
            if (!techs.Contains(cat)) continue;
            if (probes.Count >= MaxCasesPerEndpoint) break;
            Add($"injection {cat}:{name} in query {key}", BuildUrl(uri, ReplaceAt(pairs, 0, payload)));
        }
    }

    return probes;
}

void AddHeaderProbes(NetworkEntry ep, Dictionary<string, string> headers, bool hasBody, Action<string, string?, Dictionary<string, string>?> add)
{
    void one(string fault, string name, string value)
    {
        var h = CopyHeaders(headers);
        h[name] = value;
        add(fault, hasBody ? ep.RequestBody : null, h);
    }

    one("unsatisfiable Accept", "Accept", "application/x-does-not-exist");
    one("oversized X-Fuzz-Overflow header", "X-Fuzz-Overflow", new string('A', 8192));
    one("X-Forwarded-For extreme", "X-Forwarded-For", "999999999999");
    one("X-Forwarded-Host", "X-Forwarded-Host", "127.0.0.1");
    one("X-Original-URL traversal", "X-Original-URL", "/../../etc/passwd");
    one("Range extreme", "Range", "bytes=0-999999999999");
}

// ---------- HTTP ----------

async Task<Sent> Send(Probe probe)
{
    try
    {
        var raw = await Fetch(probe.Url, probe.Method, probe.Headers, probe.Body, TimeoutMs);
        using var doc = System.Text.Json.JsonDocument.Parse(raw);
        var root = doc.RootElement;
        var status = root.TryGetProperty("status", out var st) && st.TryGetInt32(out var n) ? n : 0;
        var statusText = root.TryGetProperty("statusText", out var tx) ? tx.GetString() ?? "" : "";
        var body = root.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
        var error = root.TryGetProperty("error", out var err) ? err.GetString() : null;
        var duration = root.TryGetProperty("durationMs", out var d) && d.TryGetInt32(out var ms) ? ms : 0;
        if (status == 0 && IsBrowserReject(error))
            return new Sent(0, statusText, body, error, duration, browserRefused: true, dropped: false);
        var ok = root.TryGetProperty("ok", out var okEl) && okEl.ValueKind == System.Text.Json.JsonValueKind.True;
        var dropped = status == 0 && !ok;
        return new Sent(status, statusText, body, error, duration, false, dropped);
    }
    catch (Exception ex)
    {
        if (IsBrowserReject(ex.Message))
            return new Sent(0, "", "", ex.Message, 0, browserRefused: true, dropped: false);
        return new Sent(0, "", "", ex.Message, 0, browserRefused: false, dropped: true);
    }
}

static bool IsBrowserReject(string? message)
{
    if (string.IsNullOrEmpty(message)) return false;
    return message.Contains("forbidden header", StringComparison.OrdinalIgnoreCase)
        || message.Contains("invalid header", StringComparison.OrdinalIgnoreCase)
        || message.Contains("is not a valid HTTP header", StringComparison.OrdinalIgnoreCase)
        || message.Contains("Failed to execute 'set'", StringComparison.OrdinalIgnoreCase);
}

static string Describe(Sent sent)
{
    if (sent.Dropped) return "connection dropped";
    return sent.Status > 0 ? $"{sent.Status} {sent.StatusText}".Trim() : "no response";
}

Hit HitFrom(NetworkEntry ep, Probe probe, Sent sent) => new Hit
{
    Kind = sent.Status >= 500 ? "5xx" : "drop",
    Fault = probe.Fault,
    Method = probe.Method,
    Url = probe.Url,
    Headers = probe.Headers,
    Body = probe.Body,
    Status = sent.Status,
    StatusText = sent.StatusText,
    Error = sent.Error,
    DurationMs = sent.DurationMs,
    ResponseSnippet = sent.Body,
    Endpoint = $"{ep.Method} {PathOf(ep.Url)}",
};

// ---------- JSON / URL helpers ----------

static string? DuplicateFirstKey(System.Text.Json.Nodes.JsonObject obj)
{
    KeyValuePair<string, System.Text.Json.Nodes.JsonNode?>? firstPair = null;
    var parts = new List<string>();
    foreach (var kv in obj)
    {
        firstPair ??= kv;
        parts.Add(System.Text.Json.JsonSerializer.Serialize(kv.Key) + ":" + (kv.Value?.ToJsonString() ?? "null"));
    }
    if (firstPair == null) return null;
    var first = firstPair.Value;
    string dupJson;
    if (first.Value is System.Text.Json.Nodes.JsonValue jv && jv.GetValueKind() == System.Text.Json.JsonValueKind.String)
        dupJson = System.Text.Json.JsonSerializer.Serialize(jv.GetValue<string>() + "-dup");
    else
        dupJson = "\"__duplicate__\"";
    parts.Add(System.Text.Json.JsonSerializer.Serialize(first.Key) + ":" + dupJson);
    return "{" + string.Join(",", parts) + "}";
}

static System.Text.Json.Nodes.JsonNode Swapped(System.Text.Json.Nodes.JsonNode node)
{
    if (node is System.Text.Json.Nodes.JsonObject) return System.Text.Json.Nodes.JsonValue.Create("not-an-object")!;
    if (node is System.Text.Json.Nodes.JsonArray) return System.Text.Json.Nodes.JsonValue.Create("not-an-array")!;
    if (node is System.Text.Json.Nodes.JsonValue v)
    {
        var k = v.GetValueKind();
        if (k == System.Text.Json.JsonValueKind.String) return System.Text.Json.Nodes.JsonValue.Create(123456)!;
        if (k == System.Text.Json.JsonValueKind.Number) return System.Text.Json.Nodes.JsonValue.Create("not-a-number")!;
        if (k is System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False)
            return System.Text.Json.Nodes.JsonValue.Create("not-a-bool")!;
    }
    return System.Text.Json.Nodes.JsonValue.Create("x")!;
}

static string? Rewrite(System.Text.Json.Nodes.JsonNode root, List<Seg> path, System.Text.Json.Nodes.JsonNode? replacement, bool omit)
{
    var clone = System.Text.Json.Nodes.JsonNode.Parse(root.ToJsonString());
    if (clone == null || path.Count == 0) return null;
    System.Text.Json.Nodes.JsonNode parent = clone;
    for (var i = 0; i < path.Count - 1; i++)
    {
        var next = Step(parent, path[i]);
        if (next == null) return null;
        parent = next;
    }
    var last = path[^1];
    if (omit)
    {
        if (!last.IsIndex && parent is System.Text.Json.Nodes.JsonObject o)
            o.Remove(last.Prop);
        return clone.ToJsonString();
    }
    if (!last.IsIndex && parent is System.Text.Json.Nodes.JsonObject po)
        po[last.Prop] = replacement;
    else if (last.IsIndex && parent is System.Text.Json.Nodes.JsonArray a && last.Index >= 0 && last.Index < a.Count)
        a[last.Index] = replacement;
    else
        return null;
    return clone.ToJsonString();
}

static System.Text.Json.Nodes.JsonNode? Step(System.Text.Json.Nodes.JsonNode node, Seg seg)
{
    if (!seg.IsIndex && node is System.Text.Json.Nodes.JsonObject o) return o[seg.Prop];
    if (seg.IsIndex && node is System.Text.Json.Nodes.JsonArray a && seg.Index >= 0 && seg.Index < a.Count) return a[seg.Index];
    return null;
}

static string FormatPath(List<Seg> path)
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

static List<QPair> ParseQuery(string query)
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

static List<QPair> ReplaceAt(List<QPair> pairs, int index, string value)
{
    var copy = pairs.ToList();
    copy[index] = new QPair(copy[index].Key, value);
    return copy;
}

static List<QPair> Without(List<QPair> pairs, int index)
{
    var copy = pairs.ToList();
    copy.RemoveAt(index);
    return copy;
}

static string BuildUrl(Uri uri, List<QPair> pairs)
{
    var q = string.Join("&", pairs.Select(p => Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(p.Value)));
    return uri.GetLeftPart(UriPartial.Path) + (q.Length > 0 ? "?" + q : "");
}

Dictionary<string, string> HeadersFromEntry(NetworkEntry ep, bool forceJson)
{
    var h = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    foreach (var kv in ep.RequestHeaders)
    {
        if (SkipHeader(kv.Key)) continue;
        h[kv.Key] = kv.Value;
    }
    if (forceJson) h["Content-Type"] = "application/json";
    return h;
}

static Dictionary<string, string> CopyHeaders(Dictionary<string, string> headers) =>
    new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase);

static bool SkipHeader(string name)
{
    var n = name.ToLowerInvariant();
    if (n.StartsWith("sec-", StringComparison.Ordinal) || n.StartsWith("proxy-", StringComparison.Ordinal)) return true;
    return n is "cookie" or "host" or "content-length" or "connection" or "accept-encoding"
        or "origin" or "referer" or "transfer-encoding" or "keep-alive" or "te" or "upgrade"
        or "content-encoding" or "trailer";
}

static bool SameHost(NetworkEntry e, string host) =>
    Uri.TryCreate(e.Url, UriKind.Absolute, out var u) &&
    string.Equals(u.Host, host, StringComparison.OrdinalIgnoreCase);

static bool IsApiLike(NetworkEntry e)
{
    var t = e.ResourceType ?? "";
    return t is "Fetch" or "XHR" or "Other";
}

static bool LooksLikeStaticAsset(NetworkEntry e)
{
    if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var u)) return false;
    var p = u.AbsolutePath.ToLowerInvariant();
    return p.EndsWith(".js") || p.EndsWith(".css") || p.EndsWith(".png") || p.EndsWith(".jpg")
        || p.EndsWith(".jpeg") || p.EndsWith(".gif") || p.EndsWith(".webp") || p.EndsWith(".svg")
        || p.EndsWith(".woff") || p.EndsWith(".woff2") || p.EndsWith(".ico") || p.EndsWith(".map");
}

static bool EntryHasJsonBody(NetworkEntry e) =>
    !string.IsNullOrEmpty(e.RequestBody)
    && (e.ContentType.Contains("json", StringComparison.OrdinalIgnoreCase)
        || e.RequestBody!.TrimStart().StartsWith("{")
        || e.RequestBody!.TrimStart().StartsWith("["));

static string PathOf(string fullUrl) =>
    Uri.TryCreate(fullUrl, UriKind.Absolute, out var u) ? u.AbsolutePath : fullUrl;

static string PathAndQuery(string fullUrl) =>
    Uri.TryCreate(fullUrl, UriKind.Absolute, out var u) ? u.PathAndQuery : fullUrl;

static string QueryParamKeySignature(string fullUrl)
{
    if (!Uri.TryCreate(fullUrl, UriKind.Absolute, out var u)) return "";
    var keys = new SortedSet<string>(StringComparer.Ordinal);
    foreach (var pair in ParseQuery(u.Query)) keys.Add(pair.Key);
    return string.Join("&", keys);
}

void LogRepro(Hit hit)
{
    var col = hit.Kind == "5xx" ? "#F44747" : "#CCCC00";
    var statusLabel = hit.Status > 0 ? $"{hit.Status} {hit.StatusText}".Trim() : "connection dropped";
    Log($"  ▸ {statusLabel}  ({hit.DurationMs}ms)  {hit.Endpoint}", col);
    Log($"      fault:   {hit.Fault}", col);
    if (!string.IsNullOrEmpty(hit.Error))
        Log($"      error:   {OneLine(hit.Error!, 300)}", col);
    Log($"      method:  {hit.Method}");
    Log($"      url:     {OneLine(hit.Url, 400)}");
    if (hit.Headers.Count > 0)
    {
        Log("      headers:");
        foreach (var kv in hit.Headers)
            Log($"        {kv.Key}: {OneLine(kv.Value, 200)}");
    }
    if (!string.IsNullOrEmpty(hit.Body))
        Log($"      body:    {OneLine(hit.Body!, 400)}");
    if (!string.IsNullOrEmpty(hit.ResponseSnippet))
        Log($"      response:{OneLine(hit.ResponseSnippet!, 200)}");
    Log($"      curl:    {BuildCurl(hit.Method, hit.Url, hit.Headers, hit.Body)}");
    Log("");
}

static string BuildCurl(string method, string reqUrl, Dictionary<string, string> headers, string? body)
{
    string q(string v) => "\"" + Clean(v).Replace("\"", "\\\"") + "\"";
    var sb = new System.Text.StringBuilder();
    sb.Append("curl.exe -i -X ").Append(method).Append(' ').Append(q(reqUrl));
    foreach (var kv in headers)
        sb.Append(" -H ").Append(q($"{kv.Key}: {kv.Value}"));
    if (!string.IsNullOrEmpty(body))
        sb.Append(" --data-raw ").Append(q(body!));
    return sb.ToString();
}

static string Clean(string s)
{
    if (string.IsNullOrEmpty(s)) return "";
    var sb = new System.Text.StringBuilder(s.Length);
    for (var i = 0; i < s.Length; i++)
    {
        var c = s[i];
        if (c == '\r') { sb.Append("\\r"); continue; }
        if (c == '\n') { sb.Append("\\n"); continue; }
        if (c == '\t') { sb.Append("\\t"); continue; }
        if (c < 0x20 || (c >= 0x7F && c <= 0x9F)) { sb.Append("\\u").Append(((int)c).ToString("x4")); continue; }
        if (char.IsHighSurrogate(c))
        {
            if (i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) { sb.Append(c).Append(s[i + 1]); i++; continue; }
            sb.Append("\\u").Append(((int)c).ToString("x4")); continue;
        }
        if (char.IsLowSurrogate(c)) { sb.Append("\\u").Append(((int)c).ToString("x4")); continue; }
        sb.Append(c);
    }
    return sb.ToString();
}

static string OneLine(string s, int max)
{
    var t = Clean(s).Replace("\n", " ");
    return t.Length > max ? t.Substring(0, max - 3) + "..." : t;
}

static class FuzzCatalog
{
    public static readonly (string Name, string Value)[] ContentTypes =
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

    public static IEnumerable<(string Name, string Value)> NaughtyStrings()
    {
        yield return ("emoji", "😍👩🏽‍💻🏳️‍🌈");
        yield return ("rtl-override", "\u202etxet desrever");
        yield return ("zalgo", "Z\u0361\u0362a\u0334\u0356g\u0334o");
        yield return ("zero-width", "a\u200bb\u200cc\u200dd\ufeff");
        yield return ("format-string", "%s%s%s%n%x%x");
        yield return ("fullwidth", "１２３４５");
        yield return ("reserved-word", "NaN");
        yield return ("bignum-string", new string('9', 300));
        yield return ("null-char", "a\u0000b");
        yield return ("mixed-newlines", "a\r\nb\nc\rd");
        yield return ("quotes", "'\"`");
        yield return ("brace-soup", "${{{}}}");
        yield return ("huge", new string('A', 20000));
    }

    public static readonly (string Cat, string Name, string Payload)[] InjectionPayloads =
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
}

class Seg
{
    public bool IsIndex;
    public string Prop = "";
    public int Index;
    public Seg(bool isIndex, string prop, int index) { IsIndex = isIndex; Prop = prop; Index = index; }
}

class QPair
{
    public string Key = "";
    public string Value = "";
    public QPair(string key, string value) { Key = key; Value = value; }
}

class Probe
{
    public string Fault = "";
    public string Method = "GET";
    public string Url = "";
    public Dictionary<string, string> Headers = new(StringComparer.OrdinalIgnoreCase);
    public string? Body;
}

class Sent
{
    public int Status;
    public string StatusText = "";
    public string Body = "";
    public string? Error;
    public int DurationMs;
    public bool BrowserRefused;
    public bool Dropped;
    public Sent(int status, string statusText, string body, string? error, int durationMs, bool browserRefused, bool dropped)
    {
        Status = status; StatusText = statusText; Body = body; Error = error;
        DurationMs = durationMs; BrowserRefused = browserRefused; Dropped = dropped;
    }
}

class Hit
{
    public string Kind = "";
    public string Fault = "";
    public string Endpoint = "";
    public string Method = "";
    public string Url = "";
    public Dictionary<string, string> Headers = new(StringComparer.OrdinalIgnoreCase);
    public string? Body;
    public int Status;
    public string StatusText = "";
    public string? Error;
    public int DurationMs;
    public string ResponseSnippet = "";
}
