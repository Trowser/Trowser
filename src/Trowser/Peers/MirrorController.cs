using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Channels;
using Trowser.Api;
using Trowser.Recording;

namespace Trowser.Peers;

/// <summary>
/// Driver-only mirror mode: replays GUI actions from the main Trowser window
/// to all alive peer instances via their REST APIs. Cookies, storage, auth,
/// and absolute URLs remain independent per peer (path/query are rebased onto
/// each peer's origin captured at start).
/// </summary>
public sealed class MirrorController : IDisposable
{
    private static readonly TimeSpan TrailingSuppressWindow = TimeSpan.FromSeconds(1);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };
    private static readonly IReadOnlyDictionary<string, string> MirrorForwardHeaders =
        new Dictionary<string, string> { [PeerRegistry.MirrorRequestHeader] = "1" };

    private readonly PeerSessionManager _manager;

    private readonly object _gate = new();
    private Channel<MirrorWorkItem>? _channel;
    private CancellationTokenSource? _cts;
    private Task? _consumer;

    private List<MirroredPeer> _activePeers = [];
    private string? _driverOrigin;
    private readonly ConcurrentDictionary<string, PeerMirrorError> _errors = new(StringComparer.OrdinalIgnoreCase);

    private int _suppressDepth;
    private long _suppressUntilTicks;

    public MirrorController(PeerSessionManager manager)
    {
        _manager = manager ?? throw new ArgumentNullException(nameof(manager));
    }

    public bool IsActive { get; private set; }

    /// <summary>
    /// True while a REST/MCP call is in flight on the driver, or during the
    /// trailing window that covers the recorder's 500ms type debounce.
    /// </summary>
    public bool IsSuppressed =>
        Volatile.Read(ref _suppressDepth) > 0 ||
        DateTime.UtcNow.Ticks < Interlocked.Read(ref _suppressUntilTicks);

    public IReadOnlyList<MirroredPeer> ActivePeers
    {
        get { lock (_gate) return _activePeers.ToList(); }
    }

    public IReadOnlyDictionary<string, PeerMirrorError> LastErrors =>
        new Dictionary<string, PeerMirrorError>(_errors, StringComparer.OrdinalIgnoreCase);

    public string? DriverOrigin
    {
        get { lock (_gate) return _driverOrigin; }
    }

    public string? LastWarning { get; private set; }

    public event Action? MirrorStateChanged;

    /// <summary>
    /// Start mirroring. <paramref name="driverUrl"/> must be read by the caller on the UI
    /// thread — the WebView2 source is COM/UI-affinitized and cannot be touched from the
    /// thread-pool continuations this method runs on.
    /// </summary>
    public async Task<MirrorStartResult> StartAsync(string? driverUrl, CancellationToken cancellationToken = default)
    {
        if (IsActive)
            Stop();

        var driverOrigin = TryGetOrigin(driverUrl);
        if (string.IsNullOrEmpty(driverOrigin))
        {
            return new MirrorStartResult
            {
                Success = false,
                Error = "Driver has no usable page origin yet. Navigate the main window to the app first."
            };
        }

        await _manager.RefreshHealthAsync().ConfigureAwait(false);

        var alive = _manager.Sessions.Where(s => s.Alive).ToList();
        if (alive.Count == 0)
        {
            return new MirrorStartResult
            {
                Success = false,
                Error = "No alive peers. Launch at least one peer before enabling Mirror Mode."
            };
        }

        var mirrored = new List<MirroredPeer>();
        var skipped = new List<string>();

        foreach (var state in alive)
        {
            var (origin, skipReason) = await CapturePeerOriginAsync(state.Config.Name).ConfigureAwait(false);
            if (origin == null)
            {
                skipped.Add($"{state.Config.Name}: {skipReason ?? "no origin"}");
                continue;
            }

            mirrored.Add(new MirroredPeer(state.Config.Name, origin));
        }

        if (mirrored.Count == 0)
        {
            return new MirrorStartResult
            {
                Success = false,
                Error = "No peers have a usable page origin. Navigate each peer to its app version first.",
                SkippedPeers = skipped
            };
        }

        lock (_gate)
        {
            _activePeers = mirrored;
            _driverOrigin = driverOrigin;
            _errors.Clear();
            LastWarning = skipped.Count > 0
                ? "Skipped: " + string.Join("; ", skipped)
                : null;

            _cts = new CancellationTokenSource();
            var channel = Channel.CreateUnbounded<MirrorWorkItem>(new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false
            });
            _channel = channel;
            var token = _cts.Token;
            _consumer = Task.Run(() => ConsumeAsync(channel, token), CancellationToken.None);
            IsActive = true;
        }

        RaiseStateChanged();
        return new MirrorStartResult
        {
            Success = true,
            MirroredPeers = mirrored.Select(p => p.Name).ToList(),
            SkippedPeers = skipped,
            Warning = LastWarning
        };
    }

    public void Stop()
    {
        Channel<MirrorWorkItem>? channel;
        CancellationTokenSource? cts;
        Task? consumer;

        lock (_gate)
        {
            if (!IsActive && _channel == null)
                return;

            IsActive = false;
            channel = _channel;
            cts = _cts;
            consumer = _consumer;
            _channel = null;
            _cts = null;
            _consumer = null;
            _activePeers = [];
            _driverOrigin = null;
        }

        try { channel?.Writer.TryComplete(); } catch { /* ignore */ }
        try { cts?.Cancel(); } catch { /* ignore */ }

        // Never block here: Stop() runs on the UI thread (toggle button, window close).
        if (consumer != null)
        {
            _ = consumer.ContinueWith(
                _ => { try { cts?.Dispose(); } catch { /* ignore */ } },
                TaskScheduler.Default);
        }
        else
        {
            try { cts?.Dispose(); } catch { /* ignore */ }
        }

        RaiseStateChanged();
    }

    public void Dispose() => Stop();

    public void BeginApiSuppress()
    {
        Interlocked.Increment(ref _suppressDepth);
    }

    public void EndApiSuppress()
    {
        var depth = Interlocked.Decrement(ref _suppressDepth);
        if (depth <= 0)
        {
            Interlocked.Exchange(ref _suppressDepth, 0);
            Interlocked.Exchange(ref _suppressUntilTicks, DateTime.UtcNow.Add(TrailingSuppressWindow).Ticks);
        }
    }

    /// <summary>
    /// Enqueue a recorded DOM action. Clones the element because the caller's
    /// JsonDocument is typically disposed after the WebMessage handler returns.
    /// </summary>
    public void Enqueue(JsonElement action)
    {
        if (!IsActive || IsSuppressed) return;

        string type;
        try { type = action.GetProperty("type").GetString() ?? ""; }
        catch { return; }

        if (!CapturedActionRouting.Accepts(CapturedActionRouting.Sink.Mirror, type))
            return;

        var channel = _channel;
        if (channel == null) return;

        channel.Writer.TryWrite(new MirrorWorkItem
        {
            Kind = MirrorWorkKind.Action,
            ActionJson = action.Clone().GetRawText()
        });
    }

    public void EnqueueNavigation(string url)
    {
        if (!IsActive || IsSuppressed) return;
        if (string.IsNullOrWhiteSpace(url)) return;

        var channel = _channel;
        if (channel == null) return;

        channel.Writer.TryWrite(new MirrorWorkItem
        {
            Kind = MirrorWorkKind.Navigate,
            Url = url
        });
    }

    private async Task ConsumeAsync(Channel<MirrorWorkItem> channel, CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var item in channel.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                List<MirroredPeer> peers;
                string? driverOrigin;
                lock (_gate)
                {
                    peers = _activePeers.ToList();
                    driverOrigin = _driverOrigin;
                }

                if (peers.Count == 0) continue;

                try
                {
                    if (item.Kind == MirrorWorkKind.Navigate)
                        await DispatchNavigationAsync(peers, driverOrigin, item.Url!).ConfigureAwait(false);
                    else if (!string.IsNullOrEmpty(item.ActionJson))
                        await DispatchActionAsync(peers, item.ActionJson!).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    TrowserLog.Warn($"Mirror dispatch failed: {ex.Message}");
                    LastWarning = ex.Message;
                    RaiseStateChanged();
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Stop()
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Mirror consumer exited: {ex.Message}");
        }
    }

    private async Task DispatchActionAsync(List<MirroredPeer> peers, string actionJson)
    {
        using var doc = JsonDocument.Parse(actionJson);
        var action = doc.RootElement;
        var type = GetString(action, "type");
        var request = BuildPeerRequest(action, type);
        if (request == null) return;

        var tasks = peers.Select(peer => ForwardToPeerAsync(peer.Name, request.Path, request.Body));
        await Task.WhenAll(tasks).ConfigureAwait(false);
        RaiseStateChanged();
    }

    private async Task DispatchNavigationAsync(List<MirroredPeer> peers, string? driverOrigin, string url)
    {
        if (string.IsNullOrEmpty(driverOrigin))
            return;

        if (!Uri.TryCreate(url, UriKind.Absolute, out var driverUri))
            return;

        var newOrigin = $"{driverUri.Scheme}://{driverUri.Authority}";
        if (!string.Equals(newOrigin, driverOrigin, StringComparison.OrdinalIgnoreCase))
        {
            LastWarning =
                $"Skipped navigation mirror: driver left captured origin ({driverOrigin} → {newOrigin}).";
            RaiseStateChanged();
            return;
        }

        var pathAndQuery = driverUri.PathAndQuery;
        var fragment = driverUri.Fragment;

        var tasks = peers.Select(peer =>
        {
            var peerUrl = peer.Origin.TrimEnd('/') + pathAndQuery + fragment;
            var body = JsonSerializer.Serialize(new { url = peerUrl }, JsonOptions);
            return ForwardToPeerAsync(peer.Name, "/api/navigate", body);
        });
        await Task.WhenAll(tasks).ConfigureAwait(false);
        RaiseStateChanged();
    }

    private async Task ForwardToPeerAsync(string peerName, string path, string body)
    {
        var resp = await _manager.Registry.ForwardAsync(
                peerName, "POST", path, body, timeoutMs: 30000,
                extraHeaders: MirrorForwardHeaders)
            .ConfigureAwait(false);

        if (resp.Success || resp.StatusCode is >= 200 and < 300)
            return;

        var message = FormatPeerError(resp);
        _errors.AddOrUpdate(
            peerName,
            _ => new PeerMirrorError { Count = 1, LastMessage = message },
            (_, existing) => new PeerMirrorError
            {
                Count = existing.Count + 1,
                LastMessage = message
            });
    }

    private static string FormatPeerError(PeerResponse resp)
    {
        if (resp.PeerBusy)
            return "Peer busy (gate held).";
        var body = resp.Body ?? $"HTTP {resp.StatusCode}";
        if (body.Length > 200) body = body[..200] + "…";
        return body;
    }

    private async Task<(string? origin, string? skipReason)> CapturePeerOriginAsync(string peerName)
    {
        var infoResp = await _manager.Registry.ForwardAsync(peerName, "GET", "/api/info", timeoutMs: 10000)
            .ConfigureAwait(false);
        if (!infoResp.Success)
            return (null, infoResp.Body ?? "could not reach /api/info");

        string? currentUrl = null;
        try
        {
            using var doc = JsonDocument.Parse(infoResp.Body ?? "{}");
            if (doc.RootElement.TryGetProperty("data", out var data) &&
                data.TryGetProperty("currentUrl", out var cu))
                currentUrl = cu.GetString();
        }
        catch
        {
            return (null, "invalid /api/info response");
        }

        var origin = TryGetOrigin(currentUrl);
        if (origin == null)
            return (null, $"page is '{currentUrl ?? "empty"}' — navigate peer to the app first");

        return (origin, null);
    }

    private static string? TryGetOrigin(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return null;
        if (uri.Scheme is not ("http" or "https")) return null;
        return $"{uri.Scheme}://{uri.Authority}";
    }

    private static PeerRequest? BuildPeerRequest(JsonElement action, string type)
    {
        return type switch
        {
            "click" => BuildLocatorRequest("/api/click", action, isClickable: true),
            "hover" => BuildLocatorRequest("/api/hover", action, isClickable: true),
            "type" => BuildTypeRequest(action),
            "select" => BuildSelectRequest(action),
            "key" => BuildKeyRequest(action),
            "radio" => BuildRadioRequest(action),
            "scroll" => BuildScrollRequest(action),
            _ => null
        };
    }

    private static PeerRequest? BuildLocatorRequest(string path, JsonElement action, bool isClickable)
    {
        var body = new Dictionary<string, object?>();
        if (!TryAddLocator(body, action, isClickable))
            return null;
        return new PeerRequest(path, JsonSerializer.Serialize(body, JsonOptions));
    }

    private static PeerRequest? BuildTypeRequest(JsonElement action)
    {
        var body = new Dictionary<string, object?>();
        if (!TryAddLocator(body, action, isClickable: false))
            return null;
        body["value"] = GetString(action, "value");
        return new PeerRequest("/api/type", JsonSerializer.Serialize(body, JsonOptions));
    }

    private static PeerRequest? BuildSelectRequest(JsonElement action)
    {
        var body = new Dictionary<string, object?>();
        if (!TryAddLocator(body, action, isClickable: false))
            return null;
        body["value"] = GetString(action, "value");
        return new PeerRequest("/api/select", JsonSerializer.Serialize(body, JsonOptions));
    }

    private static PeerRequest? BuildScrollRequest(JsonElement action)
    {
        var body = new Dictionary<string, object?>
        {
            ["x"] = GetNumber(action, "scrollX"),
            ["y"] = GetNumber(action, "scrollY")
        };
        var selector = GetString(action, "selector");
        if (!string.IsNullOrEmpty(selector))
            body["selector"] = selector;
        return new PeerRequest("/api/scroll", JsonSerializer.Serialize(body, JsonOptions));
    }

    private static PeerRequest? BuildKeyRequest(JsonElement action)
    {
        var key = GetString(action, "key");
        if (string.IsNullOrEmpty(key)) return null;

        var body = new Dictionary<string, object?> { ["key"] = key };
        var modifiers = new List<string>();
        if (GetBool(action, "ctrlKey")) modifiers.Add("Control");
        if (GetBool(action, "altKey")) modifiers.Add("Alt");
        if (GetBool(action, "shiftKey")) modifiers.Add("Shift");
        if (GetBool(action, "metaKey")) modifiers.Add("Meta");
        if (modifiers.Count > 0)
            body["modifiers"] = modifiers;

        // Optional focus target when the recorder captured a selector
        var selector = GetString(action, "selector");
        if (!string.IsNullOrEmpty(selector))
            body["selector"] = selector;

        return new PeerRequest("/api/key", JsonSerializer.Serialize(body, JsonOptions));
    }

    private static PeerRequest? BuildRadioRequest(JsonElement action)
    {
        var radioIndex = action.TryGetProperty("radioIndex", out var idx) && idx.ValueKind == JsonValueKind.Number
            ? idx.GetInt32()
            : -1;
        if (radioIndex < 0) return null;

        var script = $"document.querySelectorAll('input[type=radio]')[{radioIndex}].click()";
        var body = JsonSerializer.Serialize(new { script }, JsonOptions);
        return new PeerRequest("/api/execute-js", body);
    }

    /// <summary>
    /// Mirrors ScriptRecorder.BuildLocator priority, emitting REST locator fields.
    /// </summary>
    private static bool TryAddLocator(Dictionary<string, object?> body, JsonElement action, bool isClickable) =>
        LocatorBuilder.TryAddToBody(body, LocatorBuilder.ChooseFromJson(action, isClickable));

    private void RaiseStateChanged()
    {
        try { MirrorStateChanged?.Invoke(); }
        catch (Exception ex) { TrowserLog.Warn($"MirrorStateChanged handler failed: {ex.Message}"); }
    }

    private static string GetString(JsonElement el, string prop)
    {
        if (el.TryGetProperty(prop, out var val) && val.ValueKind == JsonValueKind.String)
            return val.GetString() ?? "";
        return "";
    }

    private static bool GetBool(JsonElement el, string prop)
    {
        if (el.TryGetProperty(prop, out var val) && val.ValueKind == JsonValueKind.True)
            return true;
        return false;
    }

    private static double GetNumber(JsonElement el, string prop)
    {
        if (!el.TryGetProperty(prop, out var val)) return 0;
        if (val.ValueKind == JsonValueKind.Number) return val.GetDouble();
        if (val.ValueKind == JsonValueKind.String
            && double.TryParse(val.GetString(), System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var parsed))
            return parsed;
        return 0;
    }

    private enum MirrorWorkKind { Action, Navigate }

    private sealed class MirrorWorkItem
    {
        public MirrorWorkKind Kind { get; init; }
        public string? ActionJson { get; init; }
        public string? Url { get; init; }
    }

    private sealed record PeerRequest(string Path, string Body);
}

public sealed record MirroredPeer(string Name, string Origin);

public sealed class PeerMirrorError
{
    public int Count { get; init; }
    public string LastMessage { get; init; } = "";
}

public sealed class MirrorStartResult
{
    public bool Success { get; init; }
    public string? Error { get; init; }
    public string? Warning { get; init; }
    public IReadOnlyList<string> MirroredPeers { get; init; } = [];
    public IReadOnlyList<string> SkippedPeers { get; init; } = [];
}
