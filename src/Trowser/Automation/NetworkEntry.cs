using System.Text.RegularExpressions;

namespace Trowser.Automation;

/// <summary>
/// Represents a single captured network request/response pair.
/// </summary>
public record NetworkEntry
{
    /// <summary>Auto-incrementing ID for ordering.</summary>
    public int Id { get; init; }

    /// <summary>HTTP method (GET, POST, etc.).</summary>
    public string Method { get; init; } = "";

    /// <summary>Full request URL.</summary>
    public string Url { get; init; } = "";

    /// <summary>HTTP status code (200, 404, etc.).</summary>
    public int StatusCode { get; init; }

    /// <summary>Response reason phrase.</summary>
    public string ReasonPhrase { get; init; } = "";

    /// <summary>Resource type (Document, Script, Stylesheet, Image, XHR, Fetch, etc.).</summary>
    public string ResourceType { get; init; } = "";

    /// <summary>Request headers as a dictionary.</summary>
    public Dictionary<string, string> RequestHeaders { get; init; } = new();

    /// <summary>Response headers as a dictionary.</summary>
    public Dictionary<string, string> ResponseHeaders { get; init; } = new();

    /// <summary>Timestamp when the request was captured.</summary>
    public DateTime Timestamp { get; init; }

    /// <summary>Response time in milliseconds (from request start to response received). Null if timing unavailable.</summary>
    public double? DurationMs { get; init; }

    /// <summary>Request body (POST/PUT/PATCH/DELETE/QUERY when present, capped at 100KB, null for GET/HEAD or binary).</summary>
    public string? RequestBody { get; init; }

    /// <summary>HTTP methods that may carry a request body (QUERY is the safe, body-bearing read method — RFC 9110bis).</summary>
    public static bool MethodMayHaveRequestBody(string method) =>
        method is "POST" or "PUT" or "PATCH" or "DELETE" or "QUERY";

    /// <summary>
    /// Response body for text-like responses (document, fetch, xhr, script, stylesheet, and matching content types).
    /// Capped at 100KB. Null when the body was not captured (binary, or the stream was unavailable).
    /// </summary>
    public string? ResponseBody { get; init; }

    /// <summary>
    /// True when this request was issued by Trowser scanner or fuzzer replay rather than the page
    /// or an agent <c>POST /api/fetch</c> / <c>browser_fetch</c>. Synthetic probes stay out of
    /// endpoint discovery so scans do not feed on their own noise.
    /// </summary>
    public bool IsTrowserGenerated { get; init; }

    /// <summary>
    /// True when Chromium satisfied this response without a network round trip
    /// (HTTP disk cache, memory cache, prefetch cache, or a service worker).
    /// False when the source is unknown — callers should treat that as a network fetch.
    /// </summary>
    public bool ServedFromCache { get; init; }

    /// <summary>
    /// Provenance of the response: <c>network</c>, <c>cache</c>, <c>mock</c>, or <c>intercept-fulfill</c>.
    /// </summary>
    public string ResponseSource { get; init; } = "network";

    /// <summary>When <see cref="ResponseSource"/> is <c>mock</c>, the matched mock rule URL pattern.</summary>
    public string? MockRuleKey { get; init; }

    /// <summary>CDP frame id when the row was synthesized from DevTools (subframe traffic).</summary>
    public string? CdpFrameId { get; init; }

    /// <summary>When set, this row is a redirect hop and the browser continued to this URL.</summary>
    public string? RedirectedToUrl { get; init; }

    /// <summary>
    /// When set, Live Authz Shadow replayed registered peers against this write before the
    /// owner browser request was allowed to continue (peer-first ordering).
    /// </summary>
    public int? AuthzPeerFirstSlotId { get; init; }

    /// <summary>
    /// Content-Type from the response headers, if available.
    /// </summary>
    public string ContentType =>
        ResponseHeaders.TryGetValue("Content-Type", out var ct) ? ct :
        ResponseHeaders.TryGetValue("content-type", out var ct2) ? ct2 : "";

    /// <summary>
    /// Declared response size from Content-Length, if present. Chunked responses without
    /// that header return null (the captured body is capped and is not a substitute).
    /// </summary>
    public long? ContentLengthBytes
    {
        get
        {
            if (!ResponseHeaders.TryGetValue("Content-Length", out var raw) || string.IsNullOrWhiteSpace(raw))
                return null;
            var first = raw.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .FirstOrDefault();
            if (first != null && long.TryParse(first, out var n) && n >= 0)
                return n;
            return null;
        }
    }

    /// <summary>
    /// Returns just the path portion of the URL.
    /// </summary>
    public string Path =>
        Uri.TryCreate(Url, UriKind.Absolute, out var uri) ? uri.PathAndQuery : Url;

    /// <summary>
    /// Returns the host portion of the URL.
    /// </summary>
    public string Host =>
        Uri.TryCreate(Url, UriKind.Absolute, out var uri) ? uri.Host : "";

    /// <summary>
    /// Whether this is an error response (4xx or 5xx).
    /// </summary>
    public bool IsError => StatusCode >= 400;

    /// <summary>
    /// Whether this is a successful response (2xx).
    /// </summary>
    public bool IsSuccess => StatusCode >= 200 && StatusCode < 300;

    /// <summary>Response is <c>text/event-stream</c> (EventSource or fetch-streamed SSE).</summary>
    public bool IsEventStream =>
        ContentType.Contains("text/event-stream", StringComparison.OrdinalIgnoreCase)
        || ResponseHeaders.Values.Any(v =>
            v.Contains("text/event-stream", StringComparison.OrdinalIgnoreCase));

    public override string ToString()
    {
        return $"{Method} {StatusCode} {Path}";
    }
}

/// <summary>
/// Thread-safe collection of network entries captured by the browser, with query methods.
/// </summary>
public class NetworkLog
{
    private readonly List<NetworkEntry> _entries = new();
    private readonly object _lock = new();
    private int _nextId;
    private int _navigationBoundaryId = -1;

    /// <summary>
    /// All captured entries.
    /// </summary>
    public List<NetworkEntry> Entries
    {
        get
        {
            lock (_lock)
            {
                return new List<NetworkEntry>(_entries);
            }
        }
    }

    /// <summary>
    /// Number of captured entries.
    /// </summary>
    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _entries.Count;
            }
        }
    }

    /// <summary>Fired after a new entry is added. Subscribers must not block.</summary>
    public event Action<NetworkEntry>? EntryAdded;

    /// <summary>
    /// Add an entry to the log.
    /// </summary>
    internal int Add(NetworkEntry entry)
    {
        NetworkEntry stored;
        lock (_lock)
        {
            var id = _nextId++;
            stored = entry with { Id = id };
            _entries.Add(stored);
        }
        EntryAdded?.Invoke(stored);
        return stored.Id;
    }

    public bool TryGetEntry(int id, out NetworkEntry? entry)
    {
        lock (_lock)
        {
            foreach (var e in _entries)
            {
                if (e.Id != id) continue;
                entry = e;
                return true;
            }
        }

        entry = null;
        return false;
    }

    /// <summary>
    /// Fill a response body or request headers that were missing when the row was first logged.
    /// Does not replace a body or header that is already stored. Returns false when nothing changed.
    /// </summary>
    internal bool TrySupplement(int id, string? responseBody, IReadOnlyDictionary<string, string>? requestHeaders)
    {
        if (responseBody == null && (requestHeaders == null || requestHeaders.Count == 0))
            return false;

        lock (_lock)
        {
            var idx = -1;
            for (var i = 0; i < _entries.Count; i++)
            {
                if (_entries[i].Id == id)
                {
                    idx = i;
                    break;
                }
            }
            if (idx < 0)
                return false;

            var current = _entries[idx];
            var body = current.ResponseBody;
            var bodyChanged = false;
            if (body == null && responseBody != null)
            {
                body = responseBody;
                bodyChanged = true;
            }

            var headers = current.RequestHeaders;
            var headersChanged = false;
            if (requestHeaders != null)
            {
                foreach (var kv in requestHeaders)
                {
                    var exists = false;
                    foreach (var key in headers.Keys)
                    {
                        if (key.Equals(kv.Key, StringComparison.OrdinalIgnoreCase))
                        {
                            exists = true;
                            break;
                        }
                    }
                    if (exists)
                        continue;
                    if (!headersChanged)
                    {
                        headers = new Dictionary<string, string>(current.RequestHeaders, StringComparer.OrdinalIgnoreCase);
                        headersChanged = true;
                    }
                    headers[kv.Key] = kv.Value;
                }
            }

            if (!bodyChanged && !headersChanged)
                return false;

            _entries[idx] = current with { ResponseBody = body, RequestHeaders = headers };
            EntryBodyUpdated?.Invoke(id);
            return true;
        }
    }

    public event Action<int>? EntryBodyUpdated;

    /// <summary>Replace response body when CDP snapshot grew (live event-stream poll).</summary>
    internal bool TryGrowResponseBody(int id, string fullSnapshot, int maxChars)
    {
        if (string.IsNullOrEmpty(fullSnapshot)) return false;

        lock (_lock)
        {
            var idx = -1;
            for (var i = 0; i < _entries.Count; i++)
            {
                if (_entries[i].Id == id)
                {
                    idx = i;
                    break;
                }
            }

            if (idx < 0) return false;
            var current = _entries[idx];
            var existing = current.ResponseBody ?? "";
            var next = fullSnapshot.Length > maxChars ? fullSnapshot[..maxChars] : fullSnapshot;
            if (next.Length <= existing.Length) return false;

            _entries[idx] = current with { ResponseBody = next };
            EntryBodyUpdated?.Invoke(id);
            return true;
        }
    }

    /// <summary>Append streamed response text (e.g. SSE chunks) up to the capture cap.</summary>
    internal bool TryAppendResponseBody(int id, string chunk, int maxChars)
    {
        if (string.IsNullOrEmpty(chunk)) return false;

        lock (_lock)
        {
            var idx = -1;
            for (var i = 0; i < _entries.Count; i++)
            {
                if (_entries[i].Id == id)
                {
                    idx = i;
                    break;
                }
            }

            if (idx < 0) return false;
            var current = _entries[idx];
            var body = current.ResponseBody ?? "";
            if (body.Length >= maxChars) return false;

            var take = Math.Min(chunk.Length, maxChars - body.Length);
            var next = body + chunk[..take];
            _entries[idx] = current with { ResponseBody = next };
            EntryBodyUpdated?.Invoke(id);
            return true;
        }
    }

    /// <summary>
    /// Clear all entries.
    /// </summary>
    public void Clear()
    {
        lock (_lock)
        {
            _entries.Clear();
        }
    }

    /// <summary>
    /// Mark the current position as a navigation boundary. Entries added after this
    /// point are considered "for the current page" by FindPageErrors/PageEntries.
    /// </summary>
    internal void MarkNavigationBoundary()
    {
        lock (_lock)
        {
            _navigationBoundaryId = _nextId - 1;
        }
    }

    /// <summary>
    /// Network entries captured since the last navigation (current page only).
    /// </summary>
    public List<NetworkEntry> PageEntries
    {
        get
        {
            lock (_lock)
            {
                return _entries.Where(e => e.Id > _navigationBoundaryId).ToList();
            }
        }
    }

    /// <summary>
    /// Error responses (4xx/5xx) captured since the last navigation (current page only).
    /// </summary>
    public List<NetworkEntry> FindPageErrors()
    {
        lock (_lock)
        {
            return _entries.Where(e => e.IsError && e.Id > _navigationBoundaryId).ToList();
        }
    }

    /// <summary>
    /// Get all entries matching a URL substring.
    /// </summary>
    public List<NetworkEntry> FindByUrl(string urlSubstring)
    {
        lock (_lock)
        {
            return _entries
                .Where(e => e.Url.Contains(urlSubstring, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }
    }

    /// <summary>
    /// Get all entries matching a specific HTTP method.
    /// </summary>
    public List<NetworkEntry> FindByMethod(string method)
    {
        lock (_lock)
        {
            return _entries
                .Where(e => e.Method.Equals(method, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }
    }

    /// <summary>
    /// Get all entries with error status codes (4xx, 5xx).
    /// </summary>
    public List<NetworkEntry> FindErrors()
    {
        lock (_lock)
        {
            return _entries.Where(e => e.IsError).ToList();
        }
    }

    /// <summary>
    /// Get all entries with a specific status code.
    /// </summary>
    public List<NetworkEntry> FindByStatus(int statusCode)
    {
        lock (_lock)
        {
            return _entries.Where(e => e.StatusCode == statusCode).ToList();
        }
    }

    /// <summary>
    /// Get all entries matching a resource type (Document, Script, Stylesheet, Image, Fetch, XHR, etc.)
    /// </summary>
    public List<NetworkEntry> FindByType(string resourceType)
    {
        lock (_lock)
        {
            return _entries
                .Where(e => e.ResourceType.Equals(resourceType, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }
    }

    /// <summary>
    /// Print a formatted table of all captured requests to the log.
    /// </summary>
    public string Format(int? maxEntries = null)
    {
        List<NetworkEntry> entries;
        lock (_lock)
        {
            entries = maxEntries.HasValue
                ? _entries.TakeLast(maxEntries.Value).ToList()
                : new List<NetworkEntry>(_entries);
        }

        if (entries.Count == 0)
            return "No network requests captured.";

        var lines = new List<string>
        {
            $"{"#",-4} {"Method",-7} {"Status",-7} {"Type",-12} {"Time",-8} {"URL",-70}",
            new string('─', 110)
        };

        foreach (var e in entries)
        {
            var urlDisplay = e.Url.Length > 70 ? e.Url[..67] + "..." : e.Url;
            var timing = e.DurationMs.HasValue ? $"{e.DurationMs.Value:F0}ms" : "---";
            var cache = e.ServedFromCache ? " cache" : "";
            var src = e.ResponseSource is "network" or "" ? "" : $" [{e.ResponseSource}]";
            lines.Add($"{e.Id,-4} {e.Method,-7} {e.StatusCode,-7} {e.ResourceType,-12} {timing,-8} {urlDisplay}{cache}{src}");
        }

        lines.Add(new string('─', 110));
        lines.Add($"Total: {entries.Count} request(s)");

        return string.Join(Environment.NewLine, lines);
    }
}

/// <summary>
/// A rule for intercepting network requests and returning mock responses.
/// </summary>
public class MockRule
{
    /// <summary>URL pattern to match. Supports * wildcards (glob) or plain substring matching.</summary>
    public string UrlPattern { get; set; } = "";

    /// <summary>HTTP method to match (null = any method).</summary>
    public string? Method { get; set; }

    /// <summary>HTTP status code for the mock response.</summary>
    public int StatusCode { get; set; } = 200;

    /// <summary>Response body string.</summary>
    public string? Body { get; set; }

    /// <summary>Response headers.</summary>
    public Dictionary<string, string> Headers { get; set; } = new();

    /// <summary>Artificial delay in ms before returning the response (simulates slow APIs).</summary>
    public int DelayMs { get; set; }

    /// <summary>When false, this rule is kept but not applied (toggle off without removing).</summary>
    public bool Enabled { get; set; } = true;

    public bool Matches(string url, string method)
    {
        if (Method != null && !Method.Equals(method, StringComparison.OrdinalIgnoreCase))
            return false;

        // CORS preflights should not hit method-agnostic mocks (would break the real request).
        if (Method == null && method.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase))
            return false;

        return MatchesUrl(url);
    }

    /// <summary>URL-only match (ignores HTTP method).</summary>
    public bool MatchesUrl(string url)
    {
        if (string.IsNullOrEmpty(UrlPattern))
            return false;

        if (UrlPattern.Contains('*'))
        {
            var glob = UrlPattern;
            if (!glob.StartsWith('*'))
                glob = "*" + glob;
            var regex = "^" + Regex.Escape(glob).Replace("\\*", ".*") + "$";
            return Regex.IsMatch(url, regex, RegexOptions.IgnoreCase);
        }

        return url.Contains(UrlPattern, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Default CORS headers for cross-origin mock responses when not explicitly set.</summary>
    public void EnsureDefaultCorsHeaders()
    {
        if (!Headers.ContainsKey("Access-Control-Allow-Origin"))
            Headers["Access-Control-Allow-Origin"] = "*";
        if (!Headers.ContainsKey("Access-Control-Allow-Credentials"))
            Headers["Access-Control-Allow-Credentials"] = "true";
        if (!Headers.ContainsKey("Access-Control-Allow-Methods"))
            Headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD";
        if (!Headers.ContainsKey("Access-Control-Allow-Headers"))
            Headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With";
    }
}
