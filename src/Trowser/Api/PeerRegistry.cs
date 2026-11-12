using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace Trowser.Api;

/// <summary>
/// A registered Trowser peer instance on localhost.
/// </summary>
public class PeerEntry
{
    public required string Name { get; init; }
    public required string BaseUrl { get; init; }
    public string? ApiKey { get; init; }
}

/// <summary>
/// In-memory registry of peer Trowser instances (localhost only).
/// Used for cross-instance security testing (N-body authz).
/// </summary>
public class PeerRegistry
{
    /// <summary>
    /// Set on Mirror Mode forwards so the peer does not treat the replay as agent automation
    /// (which would open a new agent-owned tab).
    /// </summary>
    public const string MirrorRequestHeader = "X-Trowser-Mirror";

    /// <summary>Default client timeout for reachability checks (dead peer, ping, short fetch).</summary>
    public const int ReachabilityTimeoutMs = 15_000;

    /// <summary>Peer WebView gate can hold up to ~60s — allow headroom for navigate/screenshot/fetch-direct.</summary>
    public const int OperationTimeoutMs = 65_000;

    private readonly ConcurrentDictionary<string, PeerEntry> _peers = new(StringComparer.OrdinalIgnoreCase);

    // HttpClient ceiling above OperationTimeoutMs and the peer gate timeout (60s).
    private static readonly HttpClient _httpClient = new() { Timeout = TimeSpan.FromSeconds(90) };

    /// <summary>Forward timeout for peer fetch-direct from a request <c>timeout</c> field (ms).</summary>
    public static int ForwardTimeoutForFetchMs(int fetchTimeoutMs) =>
        fetchTimeoutMs > 0
            ? Math.Min(fetchTimeoutMs + 5000, OperationTimeoutMs)
            : ReachabilityTimeoutMs;

    public bool Register(PeerEntry peer, out string? error)
    {
        error = null;

        if (string.IsNullOrWhiteSpace(peer.Name))
        {
            error = "Peer name is required.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(peer.BaseUrl))
        {
            error = "Peer baseUrl is required.";
            return false;
        }

        if (!IsLocalhost(peer.BaseUrl))
        {
            error = "Peer baseUrl must be http://localhost:<port>. HTTP.sys rejects Host: 127.0.0.1.";
            return false;
        }

        _peers[peer.Name] = peer;
        return true;
    }

    public bool Unregister(string name) => _peers.TryRemove(name, out _);

    public PeerEntry? Get(string name) =>
        _peers.TryGetValue(name, out var peer) ? peer : null;

    public IReadOnlyList<PeerEntry> GetAll() => _peers.Values.ToList();

    public int Count => _peers.Count;

    /// <summary>
    /// Forward an HTTP request to a peer and return the raw response body.
    /// Timeout is bounded by both the explicit <paramref name="timeoutMs"/> and the
    /// HttpClient's 90s ceiling (above the peer's 60s gate timeout).
    /// </summary>
    public async Task<PeerResponse> ForwardAsync(
        string peerName, string method, string path,
        string? jsonBody = null, int timeoutMs = ReachabilityTimeoutMs,
        IReadOnlyDictionary<string, string>? extraHeaders = null)
    {
        var peer = Get(peerName);
        if (peer == null)
            return PeerResponse.Error($"Peer \"{peerName}\" is not registered.");

        var url = peer.BaseUrl.TrimEnd('/') + path;
        using var request = new HttpRequestMessage(new HttpMethod(method), url);

        if (!string.IsNullOrEmpty(peer.ApiKey))
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", peer.ApiKey);

        if (extraHeaders != null)
        {
            foreach (var (name, value) in extraHeaders)
            {
                if (!string.IsNullOrWhiteSpace(name) && value != null)
                    request.Headers.TryAddWithoutValidation(name, value);
            }
        }

        if (jsonBody != null)
            request.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");

        try
        {
            using var cts = new CancellationTokenSource(timeoutMs);
            var response = await _httpClient.SendAsync(request, cts.Token);
            var body = await response.Content.ReadAsStringAsync(cts.Token);

            // Surface peer-side 503 (gate busy) as a clear error
            if (response.StatusCode == HttpStatusCode.ServiceUnavailable)
            {
                return new PeerResponse
                {
                    Success = false,
                    StatusCode = 503,
                    Body = body,
                    PeerBusy = true
                };
            }

            return new PeerResponse
            {
                Success = response.IsSuccessStatusCode,
                StatusCode = (int)response.StatusCode,
                Body = body
            };
        }
        catch (TaskCanceledException)
        {
            return PeerResponse.Error($"Request to peer \"{peerName}\" timed out after {timeoutMs}ms. " +
                "The peer may be busy (gate held by another operation). Try again after the peer is idle.");
        }
        catch (HttpRequestException ex)
        {
            return PeerResponse.Error($"Failed to reach peer \"{peerName}\": {ex.Message}");
        }
    }

    /// <summary>
    /// Ping a peer via GET /api/ping to check if it's alive.
    /// Returns the peer's actual bound port from /api/info when available.
    /// </summary>
    public async Task<(bool alive, string? sessionName, int? port, string? error)> PingAsync(string peerName)
    {
        var resp = await ForwardAsync(peerName, "GET", "/api/ping", timeoutMs: 5000);
        if (!resp.Success)
            return (false, null, null, FormatPeerError(resp));

        var infoResp = await ForwardAsync(peerName, "GET", "/api/info", timeoutMs: 5000);
        string? sessionName = null;
        int? port = null;
        if (infoResp.Success)
        {
            try
            {
                using var doc = JsonDocument.Parse(infoResp.Body ?? "{}");
                if (doc.RootElement.TryGetProperty("data", out var data))
                {
                    if (data.TryGetProperty("sessionName", out var sn))
                        sessionName = sn.GetString();
                    if (data.TryGetProperty("port", out var p) && p.ValueKind == JsonValueKind.Number)
                        port = p.GetInt32();
                }
            }
            catch { /* best effort */ }
        }

        return (true, sessionName, port, null);
    }

    private static string? FormatPeerError(PeerResponse resp)
    {
        if (resp.StatusCode == 0)
            return resp.Body;

        var body = resp.Body ?? "";
        if (body.Contains("Invalid Hostname", StringComparison.OrdinalIgnoreCase))
            return "Invalid hostname — peer API URLs must use http://localhost:<port>, not 127.0.0.1.";

        return body.Length > 300 ? body[..300] : body;
    }

    /// <summary>
    /// Ensure the peer's browser is on the correct origin for cookie-scoped fetches.
    /// Navigates the peer only if its current page is on a different origin.
    /// </summary>
    public async Task<(bool navigated, string? error)> EnsureOriginAsync(string peerName, string targetUrl)
    {
        if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var targetUri))
            return (false, "Invalid target URL.");

        var targetOrigin = $"{targetUri.Scheme}://{targetUri.Authority}";

        // Get peer's current URL via /api/info
        var infoResp = await ForwardAsync(peerName, "GET", "/api/info", timeoutMs: 10000);
        if (!infoResp.Success)
            return (false, $"Could not reach peer to check origin: {infoResp.Body}");

        string? currentUrl = null;
        try
        {
            using var doc = JsonDocument.Parse(infoResp.Body ?? "{}");
            if (doc.RootElement.TryGetProperty("data", out var data) &&
                data.TryGetProperty("currentUrl", out var cu))
                currentUrl = cu.GetString();
        }
        catch { /* parse error */ }

        if (!string.IsNullOrEmpty(currentUrl) && Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
        {
            var currentOrigin = $"{currentUri.Scheme}://{currentUri.Authority}";
            if (string.Equals(currentOrigin, targetOrigin, StringComparison.OrdinalIgnoreCase))
                return (false, null); // already on correct origin
        }

        // Navigate peer to the target origin root
        var navBody = JsonSerializer.Serialize(new { url = targetOrigin + "/" });
        var navResp = await ForwardAsync(peerName, "POST", "/api/navigate", navBody, timeoutMs: OperationTimeoutMs);
        if (!navResp.Success)
            return (false, $"Failed to navigate peer to {targetOrigin}: {navResp.Body}");

        return (true, null);
    }

    private static bool IsLocalhost(string baseUrl)
    {
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri))
            return false;

        return uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase);
    }
}

public class PeerResponse
{
    public bool Success { get; init; }
    public int StatusCode { get; init; }
    public string? Body { get; init; }
    public bool PeerBusy { get; init; }

    public static PeerResponse Error(string message) => new()
    {
        Success = false,
        StatusCode = 0,
        Body = message
    };
}
