using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Windows.Threading;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Recording;
using Trowser.Security;
using Trowser.Security.Runtime;
using Trowser.Security.Sse;
using Trowser.Security.WebSocket;

namespace Trowser.Automation;

/// <summary>
/// Represents a single browser tab with its own WebView2 instance and isolated state.
/// Each tab has its own console log, network log, mock rules, and ref cache.
/// </summary>
public class BrowserTab
{
    private static int _nextId;

    public int Id { get; } = Interlocked.Increment(ref _nextId);
    public WebView2 WebView { get; }
    /// <summary>Dispatcher for <see cref="WebView"/> — safe to use from API threads; do not touch <see cref="WebView"/> off this dispatcher.</summary>
    internal Dispatcher UiDispatcher { get; }
    public ConsoleLog Console { get; } = new();
    public NetworkLog Network { get; } = new();

    internal CdpNetworkBackfillTracker CdpBackfill { get; } = new();

    /// <summary>Avoid CDP backfill duplicates when WebView2 logged the same hop. The latest match wins.</summary>
    internal NetworkEntry? FindRecentNetworkEntry(string method, string url, int statusCode, TimeSpan window)
    {
        var cutoff = DateTime.UtcNow - window;
        NetworkEntry? found = null;
        foreach (var e in Network.Entries)
        {
            if (e.Timestamp < cutoff)
                continue;
            if (!e.Method.Equals(method, StringComparison.OrdinalIgnoreCase))
                continue;
            if (!string.Equals(e.Url, url, StringComparison.OrdinalIgnoreCase))
                continue;
            if (statusCode > 0 && e.StatusCode != statusCode)
                continue;
            found = e;
        }

        return found;
    }

    /// <summary>Avoid CDP backfill duplicates when WebView2 logged the same hop.</summary>
    internal bool HasRecentNetworkEntry(string method, string url, int statusCode, TimeSpan window) =>
        FindRecentNetworkEntry(method, url, statusCode, window) != null;
    public DownloadLog Downloads { get; } = new();
    public SamlCaptureManager SamlCapture { get; } = new();
    public WebSocketManager WebSocket { get; } = new();

    public SseManager Sse { get; } = new();

    /// <summary>
    /// Log an event-stream response row without waiting for the response body (fetch-streamed SSE).
    /// Returns network entry id (new or existing recent match).
    /// </summary>
    internal int LogEventStreamNetworkRow(
        string method,
        string url,
        int statusCode,
        string reason,
        IReadOnlyDictionary<string, string> requestHeaders,
        IReadOnlyDictionary<string, string> responseHeaders,
        string? cdpRequestId = null)
    {
        var existing = FindRecentNetworkEntry(method, url, statusCode, TimeSpan.FromSeconds(30));
        if (existing != null)
        {
            if (!string.IsNullOrEmpty(cdpRequestId))
                Sse.LinkNetworkEntry(cdpRequestId, existing.Id);
            return existing.Id;
        }

        var req = new Dictionary<string, string>(requestHeaders, StringComparer.OrdinalIgnoreCase);
        var resp = new Dictionary<string, string>(responseHeaders, StringComparer.OrdinalIgnoreCase);
        var id = Network.Add(new NetworkEntry
        {
            Method = method,
            Url = url,
            StatusCode = statusCode,
            ReasonPhrase = reason,
            ResourceType = "Fetch",
            RequestHeaders = req,
            ResponseHeaders = resp,
            ResponseBody = null,
            Timestamp = DateTime.UtcNow,
            ResponseSource = "network"
        });

        if (!string.IsNullOrEmpty(cdpRequestId))
            Sse.LinkNetworkEntry(cdpRequestId, id);
        else
            TryLinkOpenSseToNetworkEntry(method, url, id);

        return id;
    }

    internal void TryLinkOpenSseToNetworkEntry(string method, string url, int networkEntryId)
    {
        foreach (var conn in Sse.GetConnections(stateFilter: "open", urlFilter: null))
        {
            if (!conn.Method.Equals(method, StringComparison.OrdinalIgnoreCase)) continue;
            if (!string.Equals(conn.Url, url, StringComparison.OrdinalIgnoreCase)) continue;
            if (conn.NetworkEntryId == null)
            {
                Sse.LinkNetworkEntry(conn.CdpRequestId, networkEntryId);
                return;
            }
        }

        foreach (var conn in Sse.GetConnections())
        {
            if (!conn.Method.Equals(method, StringComparison.OrdinalIgnoreCase)) continue;
            if (!string.Equals(conn.Url, url, StringComparison.OrdinalIgnoreCase)) continue;
            if (conn.NetworkEntryId == null)
            {
                Sse.LinkNetworkEntry(conn.CdpRequestId, networkEntryId);
                return;
            }
        }
    }

    /// <summary>
    /// Client-side runtime sensor events (sinks, source reads, listeners).
    /// Populated when the sensor is installed; page JS can forge entries — evidence only.
    /// </summary>
    public RuntimeEventLog RuntimeEvents { get; } = new();

    /// <summary>Last document scope mapped by client-surface (authority + path + fragment); used to auto-reset runtime logs on navigation.</summary>
    internal string? LastClientSurfaceScopeKey { get; set; }

    /// <summary>
    /// WebView2 frame handles (including cross-origin) for frame-scoped script and inspection.
    /// </summary>
    public FrameRegistry Frames { get; } = new();

    /// <summary>
    /// Strong refs to in-flight WebView2 download operations. Required so downloads are not
    /// garbage-collected mid-transfer (WebView2 docs).
    /// </summary>
    private readonly HashSet<Microsoft.Web.WebView2.Core.CoreWebView2DownloadOperation> _downloadOps = new();

    internal void RetainDownloadOperation(Microsoft.Web.WebView2.Core.CoreWebView2DownloadOperation op)
    {
        lock (_downloadOps) _downloadOps.Add(op);
    }

    internal void ReleaseDownloadOperation(Microsoft.Web.WebView2.Core.CoreWebView2DownloadOperation op)
    {
        lock (_downloadOps) _downloadOps.Remove(op);
    }
    /// <summary>User-Agent after the Trowser suffix, before session header overrides.</summary>
    internal string? BaselineUserAgent { get; set; }

    public string Title { get; set; } = "New Tab";
    public string Url { get; set; } = "";
    public string? DisplayUrlOverride { get; set; }

    /// <summary>Outcome of the last full-document navigation (<see cref="AutomationContext.Navigate"/>).</summary>
    public bool? LastNavigationSucceeded { get; set; }

    /// <summary>Chromium error when <see cref="LastNavigationSucceeded"/> is false.</summary>
    public string? LastNavigationWebErrorStatus { get; set; }

    /// <summary>
    /// After <c>navigationKind: fresh-get</c>, whether the document navigation timing changed
    /// (true = replaced/reloaded, false = same-URL no-op, null = not a fresh-get).
    /// </summary>
    public bool? LastSameUrlFreshGetDocumentReloaded { get; set; }

    /// <summary>
    /// Who this tab belongs to: <see cref="TabOwners.Human"/>, <see cref="TabOwners.Agent"/>,
    /// or <see cref="TabOwners.Shared"/>. Shown on the tab strip; agent automation prefers
    /// its own tab so it does not hijack the tester's page.
    /// </summary>
    public string Owner { get; set; } = TabOwners.Human;

    /// <summary>True when created via <c>window.open</c> / <c>target=_blank</c> (not Ctrl+T or API NewTab).</summary>
    public bool OpenedByPageWindow { get; set; }

    /// <summary><see cref="BrowserTab.Id"/> of the opener tab when <see cref="OpenedByPageWindow"/> is true.</summary>
    public int? OpenerTabId { get; set; }

    /// <summary>
    /// True while a full document navigation (NavigationStarting -> NavigationCompleted) is in flight.
    /// Used to distinguish real page loads from same-document SPA route changes (hash routing or the
    /// History API), which raise SourceChanged without NavigationStarting/NavigationCompleted. See
    /// the soft-navigation handling in MainWindow.xaml.Tabs.cs.
    /// </summary>
    internal bool FullNavigationInProgress { get; set; }

    /// <summary>
    /// Top-level document URL from the latest <c>NavigationStarting</c> (redirect chain updates this).
    /// Used to correlate main-frame GET responses for direct file download capture.
    /// </summary>
    internal string? CurrentMainDocumentNavigationUrl { get; set; }

    internal bool MatchesCurrentMainDocumentNavigation(string method, string requestUrl)
    {
        if (!method.Equals("GET", StringComparison.OrdinalIgnoreCase))
            return false;
        if (string.IsNullOrEmpty(CurrentMainDocumentNavigationUrl))
            return false;
        return DocumentDownloadHeuristics.UrlsEquivalent(CurrentMainDocumentNavigationUrl, requestUrl);
    }

    /// <summary>
    /// URL of the last navigation (full or soft) for which post-navigation automation features
    /// (watch mode, security shadow, etc.) were run. Used to de-duplicate SourceChanged bursts so
    /// a single logical route change does not fire those features more than once.
    /// </summary>
    internal string? LastNavigationSignalUrl { get; set; }

    /// <summary>
    /// CSS selector for the current context-menu target (see Run Script). Filled when the menu opens;
    /// not retained across navigations.
    /// </summary>
    public string? LastContextMenuSelector { get; set; }

    /// <summary>Full metadata for the current context-menu target (Send to Chat, etc.).</summary>
    public ContextMenuElementInfo? LastContextMenuElement { get; set; }

    #region Request Body Cache

    private readonly ConcurrentDictionary<string, ConcurrentQueue<string?>> _requestBodyCache = new();

    /// <summary>
    /// Store a captured request body so Tab_WebResourceResponseReceived can attach it
    /// to the NetworkEntry. Keyed by "METHOD URL" to correlate request/response events.
    /// </summary>
    internal void CacheRequestBody(string method, string url, string? body)
    {
        if (body == null) return;

        var key = $"{method} {url}";
        var queue = _requestBodyCache.GetOrAdd(key, _ => new ConcurrentQueue<string?>());

        // Non-empty bodies win (CDP postData for form POST navigations often arrives after
        // WebResourceRequested with an empty stream).
        if (!string.IsNullOrWhiteSpace(body))
        {
            while (queue.TryDequeue(out _)) { }
            queue.Enqueue(body);
            return;
        }

        if (queue.IsEmpty)
            queue.Enqueue(body);
    }

    private readonly ConcurrentDictionary<string, ConcurrentQueue<Dictionary<string, string>>> _cdpRequestHeaderCache = new();

    /// <summary>
    /// CDP <c>requestWillBeSent</c> headers. WebView2's request header bag is a subset and hides Cookie;
    /// merging the rest keeps custom headers such as <c>X-CSRF</c> on the log entry.
    /// </summary>
    internal void CacheCdpRequestHeaders(string method, string url, IReadOnlyDictionary<string, string> headers)
    {
        if (headers.Count == 0)
            return;
        var key = $"{method} {url}";
        var copy = new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase);
        var queue = _cdpRequestHeaderCache.GetOrAdd(key, _ => new ConcurrentQueue<Dictionary<string, string>>());
        queue.Enqueue(copy);
    }

    internal Dictionary<string, string>? TakeCdpRequestHeaders(string method, string url)
    {
        var key = $"{method} {url}";
        if (_cdpRequestHeaderCache.TryGetValue(key, out var queue) && queue.TryDequeue(out var headers))
        {
            if (queue.IsEmpty)
                _cdpRequestHeaderCache.TryRemove(key, out _);
            return headers;
        }
        return null;
    }

    /// <summary>
    /// Retrieve and remove a previously cached request body for a given request.
    /// Returns null if no body was cached (e.g., GET requests).
    /// </summary>
    internal string? TakeRequestBody(string method, string url)
    {
        var key = $"{method} {url}";
        if (_requestBodyCache.TryGetValue(key, out var queue) && queue.TryDequeue(out var body))
        {
            if (queue.IsEmpty)
                _requestBodyCache.TryRemove(key, out _);
            return body;
        }
        return null;
    }

    internal string? PeekRequestBody(string method, string url)
    {
        var key = $"{method} {url}";
        if (_requestBodyCache.TryGetValue(key, out var queue) && queue.TryPeek(out var body))
            return body;
        return null;
    }

    #endregion

    #region Live Authz Shadow peer-first write correlation

    private readonly ConcurrentDictionary<string, ConcurrentQueue<int>> _authzPeerFirstSlots = new();

    internal void PushAuthzPeerFirstSlot(string method, string url, int slotId)
    {
        var key = $"{method} {url}";
        var queue = _authzPeerFirstSlots.GetOrAdd(key, _ => new ConcurrentQueue<int>());
        queue.Enqueue(slotId);
    }

    internal int? TakeAuthzPeerFirstSlot(string method, string url)
    {
        var key = $"{method} {url}";
        if (_authzPeerFirstSlots.TryGetValue(key, out var queue) && queue.TryDequeue(out var slotId))
        {
            if (queue.IsEmpty)
                _authzPeerFirstSlots.TryRemove(key, out _);
            return slotId;
        }

        return null;
    }

    #endregion

    #region Request-editor header overlay (one-shot navigation)

    private Dictionary<string, string>? _overlayHeaders;
    private string? _overlayMethod;
    private string? _overlayUrl;
    private DateTime _overlayArmedUtc;

    /// <summary>
    /// Arm a one-shot header overlay for the next matching WebResourceRequested.
    /// NavigateWithWebResourceRequest ignores most CreateWebResourceRequest headers;
    /// WebView2 still lets us SetHeader on the live request in WebResourceRequested.
    /// </summary>
    internal void ArmRequestHeaderOverlay(string method, string url, Dictionary<string, string> headers)
    {
        _overlayMethod = method;
        _overlayUrl = NormalizeOverlayUrl(url);
        _overlayHeaders = new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase);
        _overlayArmedUtc = DateTime.UtcNow;
    }

    internal void ClearRequestHeaderOverlay()
    {
        _overlayHeaders = null;
        _overlayMethod = null;
        _overlayUrl = null;
    }

    internal bool TryConsumeRequestHeaderOverlay(string method, string url, bool isDocumentNavigation, out Dictionary<string, string>? headers)
    {
        headers = null;
        if (_overlayHeaders == null)
            return false;

        if (DateTime.UtcNow - _overlayArmedUtc > TimeSpan.FromSeconds(30))
        {
            ClearRequestHeaderOverlay();
            return false;
        }

        if (!string.Equals(_overlayMethod, method, StringComparison.OrdinalIgnoreCase))
            return false;

        // Prefer an exact URL match. Fall back to the first document navigation so a
        // trailing-slash / encoding difference does not silently drop the overlay.
        var urlMatch = string.Equals(_overlayUrl, NormalizeOverlayUrl(url), StringComparison.OrdinalIgnoreCase);
        if (!urlMatch && !isDocumentNavigation)
            return false;

        headers = _overlayHeaders;
        ClearRequestHeaderOverlay();
        return true;
    }

    private static string NormalizeOverlayUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url.Trim().TrimEnd('/');
        return uri.GetLeftPart(UriPartial.Query).TrimEnd('/');
    }

    #endregion

    #region Response Body Cache (for fulfilled requests)

    private readonly ConcurrentDictionary<string, ConcurrentQueue<string?>> _responseBodyCache = new();

    /// <summary>
    /// Store a fulfilled response body so Tab_WebResourceResponseReceived can use it
    /// without calling GetContentAsync (which fails with COM errors for synthetic responses).
    /// Keyed by "METHOD URL" to correlate request/response events.
    /// </summary>
    internal void CacheResponseBody(string method, string url, string? body)
    {
        var key = $"{method} {url}";
        var queue = _responseBodyCache.GetOrAdd(key, _ => new ConcurrentQueue<string?>());
        queue.Enqueue(body);
    }

    /// <summary>
    /// Retrieve and remove a previously cached response body for a fulfilled request.
    /// Returns null if no body was cached (e.g., real network response).
    /// </summary>
    internal string? TakeResponseBody(string method, string url)
    {
        var key = $"{method} {url}";
        if (_responseBodyCache.TryGetValue(key, out var queue) && queue.TryDequeue(out var body))
        {
            if (queue.IsEmpty)
                _responseBodyCache.TryRemove(key, out _);
            return body;
        }
        return null;
    }

    #endregion

    #region Fulfilled response provenance (mock / intercept)

    internal readonly record struct FulfilledResponseMarker(string ResponseSource, string? MockRuleKey);

    private readonly ConcurrentDictionary<string, ConcurrentQueue<FulfilledResponseMarker>> _fulfilledResponseCache = new();

    internal void CacheFulfilledResponse(string method, string url, FulfilledResponseMarker marker)
    {
        var key = $"{method} {url}";
        var queue = _fulfilledResponseCache.GetOrAdd(key, _ => new ConcurrentQueue<FulfilledResponseMarker>());
        queue.Enqueue(marker);
    }

    internal FulfilledResponseMarker? TakeFulfilledResponse(string method, string url)
    {
        var key = $"{method} {url}";
        if (_fulfilledResponseCache.TryGetValue(key, out var queue) && queue.TryDequeue(out var marker))
        {
            if (queue.IsEmpty)
                _fulfilledResponseCache.TryRemove(key, out _);
            return marker;
        }
        return null;
    }

    #endregion

    #region Request Timing Cache (high-resolution, for DurationMs)

    private readonly ConcurrentDictionary<string, ConcurrentStack<long>> _requestTimestampCache = new();

    internal void CacheRequestTimestamp(string method, string url)
    {
        var key = $"{method} {url}";
        var stack = _requestTimestampCache.GetOrAdd(key, _ => new ConcurrentStack<long>());
        stack.Push(Stopwatch.GetTimestamp());
    }

    internal double? TakeRequestDuration(string method, string url)
    {
        var key = $"{method} {url}";
        if (_requestTimestampCache.TryGetValue(key, out var stack) && stack.TryPop(out var startTicks))
        {
            if (stack.IsEmpty)
                _requestTimestampCache.TryRemove(key, out _);
            var elapsed = Stopwatch.GetTimestamp() - startTicks;
            var ms = Math.Round((double)elapsed / Stopwatch.Frequency * 1000, 1);
            if (ms > 120_000)
                return null;
            return ms;
        }
        return null;
    }

    #endregion

    #region Synthetic (Trowser-generated) Request Cache

    // Requests issued by Trowser's own automation fetch() (fuzzer, scanners, endpoint replay,
    // browser_fetch) are marked here so the network logger can flag them and endpoint discovery can
    // exclude the noise. Correlation is in-process by "METHOD URL" — no header is sent to the target,
    // which avoids CORS preflight and tool fingerprinting. Registrations carry a timestamp and expire
    // after a TTL so a fetch that never produced a network entry (e.g., a fetch() rejected client-side
    // for an illegal header) cannot mismark a later genuine request to the same URL.
    private static readonly long SyntheticTtlTicks = Stopwatch.Frequency * 300; // 5 minutes
    private readonly ConcurrentDictionary<string, ConcurrentQueue<long>> _syntheticRequestCache = new();

    internal void MarkSyntheticRequest(string method, string url)
    {
        var key = $"{method.ToUpperInvariant()} {url}";
        var queue = _syntheticRequestCache.GetOrAdd(key, _ => new ConcurrentQueue<long>());
        queue.Enqueue(Stopwatch.GetTimestamp());
    }

    /// <summary>Consume a pending synthetic marker for this request; true when it was Trowser-generated.</summary>
    internal bool TakeSyntheticRequest(string method, string url)
    {
        var key = $"{method.ToUpperInvariant()} {url}";
        if (!_syntheticRequestCache.TryGetValue(key, out var queue))
            return false;

        var now = Stopwatch.GetTimestamp();
        while (queue.TryDequeue(out var ticks))
        {
            if (now - ticks <= SyntheticTtlTicks)
            {
                if (queue.IsEmpty)
                    _syntheticRequestCache.TryRemove(key, out _);
                return true;
            }
            // Stale registration (leaked from a fetch that produced no network entry) — discard.
        }
        _syntheticRequestCache.TryRemove(key, out _);
        return false;
    }

    #endregion

    #region CDP Set-Cookie Header Cache

    private readonly ConcurrentDictionary<string, string> _cdpRequestIdToKey = new();
    private readonly ConcurrentDictionary<string, ConcurrentQueue<string>> _setCookieCache = new();

    internal void CacheCdpRequestMapping(string requestId, string method, string url)
    {
        _cdpRequestIdToKey[requestId] = $"{method} {url}";
    }

    internal bool TryResolveCdpRequest(string requestId, out string method, out string url)
    {
        method = "";
        url = "";
        if (!_cdpRequestIdToKey.TryGetValue(requestId, out var key))
            return false;
        var space = key.IndexOf(' ');
        if (space <= 0) return false;
        method = key[..space];
        url = key[(space + 1)..];
        return true;
    }

    internal void CacheCdpSetCookie(string requestId, string setCookieValue)
    {
        if (_cdpRequestIdToKey.TryRemove(requestId, out var key))
        {
            var queue = _setCookieCache.GetOrAdd(key, _ => new ConcurrentQueue<string>());
            queue.Enqueue(setCookieValue);
        }
    }

    internal string? TakeSetCookieHeaders(string method, string url)
    {
        var key = $"{method} {url}";
        if (!_setCookieCache.TryGetValue(key, out var queue) || queue.IsEmpty)
            return null;

        var parts = new List<string>();
        while (queue.TryDequeue(out var header))
            parts.Add(header);

        _setCookieCache.TryRemove(key, out _);
        return parts.Count == 0 ? null : string.Join("\n", parts);
    }

    #endregion

    #region CDP cache source (disk / memory / prefetch / service worker)

    private sealed class CacheFlag
    {
        public bool ServedFromCache;
        /// <summary>Queued from <c>requestServedFromCache</c> before <c>responseReceived</c> for this hop.</summary>
        public bool AwaitingResponse;
    }

    private readonly ConcurrentDictionary<string, string> _cdpCacheKey = new();
    private readonly ConcurrentDictionary<string, CacheFlag> _latestCacheFlag = new();
    private readonly ConcurrentDictionary<string, ConcurrentQueue<CacheFlag>> _cacheFlagQueue = new();

    /// <summary>Remember METHOD+URL for a CDP request id so cache events can be paired with the network log.</summary>
    internal void MapCdpCacheRequest(string requestId, string method, string url)
    {
        _cdpCacheKey[requestId] = $"{method} {url}";
    }

    /// <summary>
    /// Record <c>Network.responseReceived</c> cache flags (disk, prefetch, service worker).
    /// One flag per response so a later <see cref="TryTakeServedFromCache"/> lines up with
    /// <c>WebResourceResponseReceived</c>.
    /// </summary>
    internal void NoteCdpResponseCache(string requestId, bool servedFromCache)
    {
        if (_latestCacheFlag.TryGetValue(requestId, out var pending) && pending.AwaitingResponse)
        {
            pending.ServedFromCache |= servedFromCache;
            pending.AwaitingResponse = false;
            _cdpCacheKey.TryRemove(requestId, out _);
            return;
        }

        if (!_cdpCacheKey.TryGetValue(requestId, out var key))
            return;

        var flag = new CacheFlag { ServedFromCache = servedFromCache };
        _latestCacheFlag[requestId] = flag;
        _cacheFlagQueue.GetOrAdd(key, _ => new ConcurrentQueue<CacheFlag>()).Enqueue(flag);
        _cdpCacheKey.TryRemove(requestId, out _);
    }

    /// <summary>
    /// Record <c>Network.requestServedFromCache</c> (memory cache). Updates the response flag
    /// for this request when it already exists so the two events count as one response.
    /// </summary>
    internal void NoteCdpMemoryCache(string requestId)
    {
        if (_latestCacheFlag.TryGetValue(requestId, out var existing))
        {
            existing.ServedFromCache = true;
            return;
        }

        if (!_cdpCacheKey.TryGetValue(requestId, out var key))
            return;

        var flag = new CacheFlag { ServedFromCache = true, AwaitingResponse = true };
        _latestCacheFlag[requestId] = flag;
        _cacheFlagQueue.GetOrAdd(key, _ => new ConcurrentQueue<CacheFlag>()).Enqueue(flag);
    }

    /// <summary>
    /// Consume the next cache verdict for this request. Null when CDP has not reported it yet.
    /// </summary>
    internal bool? TryTakeServedFromCache(string method, string url)
    {
        var key = $"{method} {url}";
        if (!_cacheFlagQueue.TryGetValue(key, out var queue) || !queue.TryDequeue(out var flag))
            return null;

        if (queue.IsEmpty)
            _cacheFlagQueue.TryRemove(key, out _);
        return flag.ServedFromCache;
    }

    #endregion

    #region Mock Rules (per-tab)

    private readonly List<MockRule> _mockRules = new();
    private readonly object _mockLock = new();

    public bool HasMockRules
    {
        get { lock (_mockLock) return _mockRules.Count > 0; }
    }

    public MockRule? FindMatchingMock(string url, string method)
    {
        lock (_mockLock)
            return _mockRules.FirstOrDefault(r => r.Enabled && r.Matches(url, method));
    }

    /// <summary>
    /// When any mock targets this URL, answer OPTIONS preflights so the browser can send the real request.
    /// </summary>
    public MockRule? FindMockPreflightResponse(string url)
    {
        lock (_mockLock)
            return _mockRules.FirstOrDefault(r => r.Enabled && r.MatchesUrl(url));
    }

    public void MockResponse(string urlPattern, int statusCode = 200,
        string? body = null, string? method = null,
        Dictionary<string, string>? headers = null, int delayMs = 0)
    {
        var rule = new MockRule
        {
            UrlPattern = urlPattern,
            Method = method,
            StatusCode = statusCode,
            Body = body,
            Headers = headers ?? new Dictionary<string, string>(),
            DelayMs = delayMs
        };

        if (!rule.Headers.ContainsKey("Content-Type") && body != null)
        {
            var looksLikeJs = urlPattern.Contains(".js", StringComparison.OrdinalIgnoreCase)
                || body.Contains("window.", StringComparison.Ordinal)
                || body.TrimStart().StartsWith("(", StringComparison.Ordinal)
                || body.Contains("function", StringComparison.Ordinal);
            rule.Headers["Content-Type"] = looksLikeJs ? "application/javascript" : "application/json";
        }

        rule.EnsureDefaultCorsHeaders();

        lock (_mockLock)
        {
            _mockRules.RemoveAll(r =>
                r.UrlPattern == urlPattern &&
                string.Equals(r.Method, method, StringComparison.OrdinalIgnoreCase));
            _mockRules.Add(rule);
        }

        _ = SyncCdpFetchBridgeAsync();
    }

    public bool RemoveMock(string urlPattern)
    {
        lock (_mockLock)
        {
            var before = _mockRules.Count;
            _mockRules.RemoveAll(r => r.UrlPattern == urlPattern);
            return _mockRules.Count < before;
        }
    }

    public void ClearMocks()
    {
        lock (_mockLock)
            _mockRules.Clear();
        _ = SyncCdpFetchBridgeAsync();
    }

    public List<MockRule> GetMockRules()
    {
        lock (_mockLock)
            return new List<MockRule>(_mockRules);
    }

    /// <summary>
    /// Copy mock and intercept rules from another tab (e.g. opener → popup) so fixtures keep working.
    /// </summary>
    public void CopyNetworkRulesFrom(BrowserTab source)
    {
        if (ReferenceEquals(this, source)) return;
        lock (_mockLock)
        {
            foreach (var r in source.GetMockRules())
            {
                _mockRules.Add(new MockRule
                {
                    UrlPattern = r.UrlPattern,
                    Method = r.Method,
                    StatusCode = r.StatusCode,
                    Body = r.Body,
                    Headers = new Dictionary<string, string>(r.Headers),
                    DelayMs = r.DelayMs,
                    Enabled = r.Enabled
                });
            }
        }
        lock (_interceptLock)
        {
            foreach (var r in source.GetInterceptRules())
            {
                _interceptRules.Add(new InterceptRule
                {
                    UrlPattern = r.UrlPattern,
                    Method = r.Method,
                    Silent = r.Silent,
                    Enabled = r.Enabled,
                    AutoFulfill = r.AutoFulfill
                });
            }
        }
        _ = SyncCdpFetchBridgeAsync();
    }

    public void SetMockRuleEnabled(string urlPattern, string? method, bool enabled)
    {
        lock (_mockLock)
        {
            var r = _mockRules.FirstOrDefault(m =>
                m.UrlPattern == urlPattern &&
                string.Equals(m.Method, method, StringComparison.OrdinalIgnoreCase));
            if (r != null)
                r.Enabled = enabled;
        }
    }

    #endregion

    #region Intercept Rules / Breakpoints (per-tab)

    private readonly List<InterceptRule> _interceptRules = new();
    private readonly List<PendingRequest> _pendingRequests = new();
    private readonly object _interceptLock = new();

    public bool HasInterceptRules
    {
        get { lock (_interceptLock) return _interceptRules.Count > 0; }
    }

    public bool HasPendingRequests
    {
        get { lock (_interceptLock) return _pendingRequests.Count > 0; }
    }

    public int InterceptRuleCount
    {
        get { lock (_interceptLock) return _interceptRules.Count; }
    }

    public int PendingRequestCount
    {
        get { lock (_interceptLock) return _pendingRequests.Count; }
    }

    public InterceptRule? FindMatchingIntercept(string url, string method)
    {
        lock (_interceptLock)
            return _interceptRules.FirstOrDefault(r => r.Enabled && r.Matches(url, method));
    }

    public void AddInterceptRule(string urlPattern, string? method = null, bool silent = true)
    {
        lock (_interceptLock)
        {
            _interceptRules.RemoveAll(r =>
                r.UrlPattern == urlPattern &&
                string.Equals(r.Method, method, StringComparison.OrdinalIgnoreCase));
            _interceptRules.Add(new InterceptRule { UrlPattern = urlPattern, Method = method, Silent = silent });
        }
    }

    public void AddAutoFulfillInterceptRule(
        string urlPattern,
        int statusCode = 200,
        string? body = null,
        string? method = null,
        Dictionary<string, string>? responseHeaders = null)
    {
        var headers = responseHeaders ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!headers.ContainsKey("Content-Type") && body != null)
        {
            var looksLikeJs = urlPattern.Contains(".js", StringComparison.OrdinalIgnoreCase)
                || body.Contains("window.", StringComparison.Ordinal);
            headers["Content-Type"] = looksLikeJs ? "application/javascript" : "text/plain";
        }

        lock (_interceptLock)
        {
            _interceptRules.RemoveAll(r =>
                r.UrlPattern == urlPattern &&
                string.Equals(r.Method, method, StringComparison.OrdinalIgnoreCase));
            _interceptRules.Add(new InterceptRule
            {
                UrlPattern = urlPattern,
                Method = method,
                Silent = true,
                AutoFulfill = new InterceptDecision
                {
                    Action = InterceptAction.Fulfill,
                    StatusCode = statusCode,
                    Body = body,
                    ResponseHeaders = headers
                }
            });
        }

        _ = SyncCdpFetchBridgeAsync();
    }

    public void RemoveInterceptRule(string urlPattern, string? method = null)
    {
        lock (_interceptLock)
        {
            _interceptRules.RemoveAll(r =>
            {
                if (!string.Equals(r.UrlPattern, urlPattern, StringComparison.Ordinal))
                    return false;
                if (method == null)
                    return true;
                return string.Equals(r.Method, method, StringComparison.OrdinalIgnoreCase);
            });
        }

        _ = SyncCdpFetchBridgeAsync();
    }

    public void ClearInterceptRules()
    {
        lock (_interceptLock)
        {
            _interceptRules.Clear();
            foreach (var p in _pendingRequests)
                p.Resolve(new InterceptDecision { Action = InterceptAction.Continue });
            _pendingRequests.Clear();
        }
        _ = SyncCdpFetchBridgeAsync();
    }

    internal async Task SyncCdpFetchBridgeAsync()
    {
        var core = WebView.CoreWebView2;
        if (core == null) return;

        try
        {
            if (HasMockRules || HasInterceptRules)
            {
                await CdpFetchMockBridge.EnableAsync(core);
                await core.CallDevToolsProtocolMethodAsync("Network.enable", "{}");
                await core.CallDevToolsProtocolMethodAsync("Network.setCacheDisabled",
                    System.Text.Json.JsonSerializer.Serialize(new { cacheDisabled = true }));
            }
            else
            {
                await CdpFetchMockBridge.DisableAsync(core);
                await core.CallDevToolsProtocolMethodAsync("Network.setCacheDisabled",
                    System.Text.Json.JsonSerializer.Serialize(new { cacheDisabled = false }));
            }
        }
        catch
        {
            // best-effort
        }
    }

    public List<InterceptRule> GetInterceptRules()
    {
        lock (_interceptLock)
            return new List<InterceptRule>(_interceptRules);
    }

    public void SetInterceptRuleEnabled(string urlPattern, string? method, bool enabled)
    {
        lock (_interceptLock)
        {
            var r = _interceptRules.FirstOrDefault(i =>
                i.UrlPattern == urlPattern &&
                string.Equals(i.Method, method, StringComparison.OrdinalIgnoreCase));
            if (r != null)
                r.Enabled = enabled;
        }
    }

    public void AddPendingRequest(PendingRequest pending)
    {
        lock (_interceptLock)
            _pendingRequests.Add(pending);
    }

    public void RemovePendingRequest(int id)
    {
        lock (_interceptLock)
            _pendingRequests.RemoveAll(r => r.Id == id);
    }

    public PendingRequest? GetPendingRequest(int id)
    {
        lock (_interceptLock)
            return _pendingRequests.FirstOrDefault(r => r.Id == id);
    }

    public List<PendingRequest> GetPendingRequests()
    {
        lock (_interceptLock)
            return new List<PendingRequest>(_pendingRequests);
    }

    public bool ResolvePendingRequest(int requestId, InterceptDecision decision)
    {
        lock (_interceptLock)
        {
            var pending = _pendingRequests.FirstOrDefault(r => r.Id == requestId);
            if (pending == null) return false;
            return pending.Resolve(decision);
        }
    }

    #endregion

    #region Dialog Config (per-tab, survives navigation)

    public bool DialogAccept { get; set; } = true;
    public string? DialogPromptText { get; set; }

    /// <summary>
    /// Last dialog reported by the JS interception layer via postMessage.
    /// Readable without executing JS, so the API server can report dialog state
    /// even when the gate is held or the page is blocked.
    /// </summary>
    public DialogInfo? LastDialog { get; set; }

    /// <summary>
    /// True while a WebView2 <see cref="Microsoft.Web.WebView2.Core.CoreWebView2.ScriptDialogOpening"/>
    /// handler is dismissing a native script dialog (confirm/prompt/alert). Unlike
    /// <see cref="LastDialog"/>, this indicates the browser thread may be blocked until handled.
    /// </summary>
    public volatile bool NativeScriptDialogOpen;

    #endregion

    /// <summary>When true, the next context menu request will be suppressed (used for API-triggered right-clicks).</summary>
    public bool SuppressNextContextMenu { get; set; }

    #region Ref Cache (per-tab)

    private List<Dictionary<string, object>> _lastInteractiveElements = new();
    private int _refGeneration;

    public int RefGeneration => _refGeneration;

    public string? GetSelectorByRef(int refIndex)
    {
        foreach (var el in _lastInteractiveElements)
        {
            if (!el.TryGetValue("ref", out var refObj) || refObj is not System.Text.Json.JsonElement refJe
                || refJe.ValueKind != System.Text.Json.JsonValueKind.Number || refJe.GetInt32() != refIndex)
                continue;

            if (el.TryGetValue("selector", out var selector))
                return selector?.ToString();
        }

        return null;
    }

    /// <summary>
    /// Frame id associated with a ref from the last interactive scan (null = main frame).
    /// </summary>
    public string? GetFrameIdByRef(int refIndex)
    {
        foreach (var el in _lastInteractiveElements)
        {
            if (!el.TryGetValue("ref", out var refObj) || refObj is not System.Text.Json.JsonElement refJe
                || refJe.ValueKind != System.Text.Json.JsonValueKind.Number || refJe.GetInt32() != refIndex)
                continue;

            if (el.TryGetValue("frameId", out var frameObj) && frameObj != null)
            {
                if (frameObj is System.Text.Json.JsonElement fje)
                {
                    if (fje.ValueKind == System.Text.Json.JsonValueKind.String)
                        return fje.GetString();
                    if (fje.ValueKind == System.Text.Json.JsonValueKind.Null)
                        return null;
                }
                var s = frameObj.ToString();
                return string.IsNullOrEmpty(s) ? null : s;
            }

            return null;
        }

        return null;
    }

    public int? GetRefBySelector(string selector)
    {
        if (string.IsNullOrEmpty(selector))
            return null;

        foreach (var el in _lastInteractiveElements)
        {
            if (!el.TryGetValue("selector", out var selObj))
                continue;
            if (!string.Equals(selObj?.ToString(), selector, StringComparison.Ordinal))
                continue;

            if (el.TryGetValue("ref", out var refObj) && refObj is System.Text.Json.JsonElement refJe
                && refJe.ValueKind == System.Text.Json.JsonValueKind.Number)
                return refJe.GetInt32();
        }

        return null;
    }

    public IReadOnlyList<(int Ref, string Selector)> GetRefSelectorPairs()
    {
        var pairs = new List<(int Ref, string Selector)>();
        foreach (var el in _lastInteractiveElements)
        {
            if (!el.TryGetValue("ref", out var refObj) || refObj is not System.Text.Json.JsonElement refJe
                || refJe.ValueKind != System.Text.Json.JsonValueKind.Number)
                continue;

            var refNum = refJe.GetInt32();
            if (refNum < 0)
                continue;

            if (!el.TryGetValue("selector", out var selObj))
                continue;

            var sel = selObj?.ToString();
            if (!string.IsNullOrEmpty(sel))
                pairs.Add((refNum, sel));
        }

        return pairs;
    }

    public void UpdateInteractiveElements(List<Dictionary<string, object>> elements)
    {
        _refGeneration++;
        _lastInteractiveElements = elements
            .Where(e => e.TryGetValue("ref", out var r) &&
                        r is System.Text.Json.JsonElement je && je.GetInt32() >= 0)
            .ToList();
    }

    #endregion

    public BrowserTab(WebView2 webView)
    {
        WebView = webView ?? throw new ArgumentNullException(nameof(webView));
        UiDispatcher = webView.Dispatcher;
    }
}

/// <summary>
/// Lightweight info about a tab, returned by GetTabs() for scripts and API consumers.
/// </summary>
public class TabInfo
{
    public int Index { get; set; }
    public int Id { get; set; }
    public string Title { get; set; } = "";
    public string Url { get; set; } = "";
    public bool IsActive { get; set; }
    public string Owner { get; set; } = TabOwners.Human;
    public int NetworkEntryCount { get; set; }
    public int ConsoleEntryCount { get; set; }
}

/// <summary>
/// Information about a native browser dialog (alert, confirm, or prompt) that appeared.
/// </summary>
public class DialogInfo
{
    public string Type { get; init; } = "";
    public string Message { get; init; } = "";
    public string? DefaultValue { get; init; }
}
