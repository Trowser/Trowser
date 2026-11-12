using System.Text.Json;
using Trowser.Api;
using Trowser.Peers;
using Trowser.Security;

namespace Trowser.Automation;

public partial class AutomationContext
{
    /// <summary>Shared peer registry (same instance as REST API and GUI).</summary>
    public PeerRegistry? PeerRegistry { get; set; }

    /// <summary>GUI peer session manager (null in headless/CLI).</summary>
    public PeerSessionManager? PeerSessionManager { get; set; }

    /// <summary>Register a peer Trowser instance on localhost.</summary>
    public void RegisterPeer(string name, string baseUrl, string? apiKey = null)
    {
        var registry = PeerRegistry ?? throw new InvalidOperationException(
            "PeerRegistry is not available in this context.");
        if (!registry.Register(new PeerEntry
        {
            Name = name,
            BaseUrl = baseUrl,
            ApiKey = apiKey
        }, out var error))
        {
            throw new InvalidOperationException(error ?? "Failed to register peer.");
        }
    }

    /// <summary>Send an HTTP request through a registered peer's browser session.</summary>
    public async Task<string> PeerFetch(
        string peerName,
        string url,
        string method = "GET",
        Dictionary<string, string>? headers = null,
        string? body = null,
        int timeoutMs = 30000)
    {
        var registry = PeerRegistry ?? throw new InvalidOperationException(
            "PeerRegistry is not available in this context.");

        var payload = new Dictionary<string, object?> { ["url"] = url, ["method"] = method, ["timeout"] = timeoutMs };
        if (headers != null) payload["headers"] = headers;
        if (body != null)
        {
            var ct = headers?.GetValueOrDefault("Content-Type") ?? "";
            if (ct.Contains("json", StringComparison.OrdinalIgnoreCase))
            {
                try { payload["json"] = JsonSerializer.Deserialize<object>(body); }
                catch { payload["body"] = body; }
            }
            else payload["body"] = body;
        }

        var resp = await registry.ForwardAsync(peerName, "POST", "/api/fetch-direct",
            JsonSerializer.Serialize(payload), timeoutMs: PeerRegistry.ForwardTimeoutForFetchMs(timeoutMs));

        if (!resp.Success && resp.StatusCode != 200)
            throw new InvalidOperationException(resp.Body ?? $"Peer fetch failed (HTTP {resp.StatusCode}).");

        return resp.Body ?? "{}";
    }

    /// <summary>
    /// Cross-identity authorization comparison. Returns JSON-serializable results per peer.
    /// <paramref name="endpoints"/> may be URL strings or objects with url/method/headers/body.
    /// </summary>
    public async Task<List<AuthzComparisonResult>> AuthzDiff(
        string[] peers,
        object[] endpoints,
        bool includeBodyOnMismatch = true,
        bool ensureOrigin = false)
    {
        var registry = PeerRegistry ?? throw new InvalidOperationException(
            "PeerRegistry is not available in this context.");

        var endpointJson = JsonSerializer.Serialize(endpoints);
        using var doc = JsonDocument.Parse(endpointJson);
        var parsed = AuthzComparisonService.ParseEndpoints(doc.RootElement);

        var options = new AuthzComparisonOptions
        {
            IncludeBodyOnMismatch = includeBodyOnMismatch,
            EnsureOrigin = ensureOrigin
        };

        return await AuthzComparisonService.RunAsync(this, registry, peers, parsed, options);
    }

    /// <summary>Launch a peer Trowser instance (GUI only).</summary>
    public async Task LaunchPeer(string name, int? port = null, string? apiKey = null, string? sessionName = null)
    {
        var manager = PeerSessionManager ?? throw new InvalidOperationException(
            "LaunchPeer is only available in the Trowser GUI (PeerSessionManager not configured).");

        var state = manager.Get(name) ?? manager.AddPeer(name);
        if (port.HasValue) state.Config.Port = port.Value;
        if (!string.IsNullOrWhiteSpace(apiKey)) state.Config.ApiKey = apiKey;
        if (!string.IsNullOrWhiteSpace(sessionName)) state.Config.SessionName = sessionName;

        var (ok, error) = await manager.LaunchAsync(state);
        if (!ok)
            throw new InvalidOperationException(error ?? "Failed to launch peer.");
    }

    /// <summary>List registered peer names with alive status (GUI helper).</summary>
    public IReadOnlyList<string> GetPeerNamesForTests()
    {
        return PeerSessionManager?.GetPeersForTests() ?? Array.Empty<string>();
    }
}
