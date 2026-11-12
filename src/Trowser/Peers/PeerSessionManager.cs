using System.Diagnostics;
using System.Text.Json;
using Trowser.Api;

namespace Trowser.Peers;

/// <summary>
/// Manages peer Trowser instances for GUI cross-session testing (BOLA, Mirror Mode).
/// </summary>
public sealed class PeerSessionManager
{
    private readonly List<PeerSessionState> _sessions = [];

    public PeerSessionManager(PeerRegistry registry, string navigationScope)
    {
        Registry = registry ?? throw new ArgumentNullException(nameof(registry));
        NavigationScope = navigationScope ?? "*.*";
        var data = PeerSessionSettings.Load();
        foreach (var config in data.Peers)
        {
            EnsureApiKey(config);
            _sessions.Add(new PeerSessionState { Config = config });
        }
        _nextPort = data.NextPort;
    }

    public PeerRegistry Registry { get; }
    public string NavigationScope { get; set; }

    private int _nextPort;

    public IReadOnlyList<PeerSessionState> Sessions => _sessions;

    public void ReloadFromSettings()
    {
        var data = PeerSessionSettings.Load();
        _sessions.Clear();
        foreach (var config in data.Peers)
        {
            EnsureApiKey(config);
            _sessions.Add(new PeerSessionState { Config = config });
        }
        _nextPort = data.NextPort;
    }

    public void Persist()
    {
        PeerSessionSettings.Save(new PeerSessionSettingsData
        {
            Peers = _sessions.Select(s => s.Config).ToList(),
            NextPort = _nextPort
        });
    }

    public PeerSessionState AddPeer(string? name = null)
    {
        var peerName = name ?? NextPeerName();
        var port = PeerLauncher.FindFreePort(_nextPort);
        _nextPort = port + 1;
        var config = new PeerSessionConfig
        {
            Name = peerName,
            Port = port,
            SessionName = peerName,
            UseForTests = false
        };
        EnsureApiKey(config);
        var state = new PeerSessionState { Config = config };
        _sessions.Add(state);
        Persist();
        return state;
    }

    public bool RemovePeer(string name)
    {
        var idx = _sessions.FindIndex(s => s.Config.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (idx < 0) return false;
        var state = _sessions[idx];
        _ = StopAsync(state);
        Registry.Unregister(name);
        _sessions.RemoveAt(idx);
        Persist();
        return true;
    }

    public PeerSessionState? Get(string name) =>
        _sessions.FirstOrDefault(s => s.Config.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

    public async Task<(bool success, string? error)> LaunchAsync(PeerSessionState state, CancellationToken cancellationToken = default)
    {
        state.LastError = null;
        EnsureApiKey(state.Config);
        Persist();

        RegisterPeer(state);
        var (alreadyAlive, sessionName, actualPort, pingError) = await Registry.PingAsync(state.Config.Name);
        if (alreadyAlive && SessionNamesMatch(sessionName, state.Config.SessionName))
        {
            SyncPeerPort(state, actualPort);
            state.Alive = true;
            state.RemoteSessionName = sessionName;
            return (true, null);
        }

        if (alreadyAlive && !SessionNamesMatch(sessionName, state.Config.SessionName))
        {
            state.LastError =
                $"Port {state.Config.Port} is occupied by session \"{sessionName ?? "?"}\" (expected \"{state.Config.SessionName}\"). " +
                "Launching on a new port with a fresh API key.";
            state.Config.ApiKey = TrowserApiKey.Generate();
            state.Config.Port = PeerLauncher.FindFreePort(state.Config.Port + 1);
            Persist();
            RegisterPeer(state);
        }
        else if (!PeerLauncher.IsPortFree(state.Config.Port))
        {
            state.Config.Port = PeerLauncher.FindFreePort(state.Config.Port + 1);
            Persist();
            RegisterPeer(state);
        }

        var launch = PeerLauncher.Launch(
            state.Config.Port,
            state.Config.ApiKey,
            state.Config.SessionName,
            NavigationScope,
            ephemeral: false);

        if (!launch.Success)
        {
            state.Alive = false;
            state.LastError = launch.Error;
            return (false, launch.Error);
        }

        state.Process = launch.Process;
        RegisterPeer(state);

        var deadline = DateTime.UtcNow.AddSeconds(45);
        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var (alive, remoteName, boundPort, err) = await Registry.PingAsync(state.Config.Name);
            if (alive)
            {
                SyncPeerPort(state, boundPort);
                state.Alive = true;
                state.RemoteSessionName = remoteName;
                return (true, null);
            }

            if (state.Process is { HasExited: true })
            {
                state.Alive = false;
                state.LastError = $"Peer process exited (code {state.Process.ExitCode}). {err}";
                return (false, state.LastError);
            }

            await Task.Delay(500, cancellationToken);
        }

        state.Alive = false;
        state.LastError = pingError ?? "Peer did not respond within 45 seconds.";
        return (false, state.LastError);
    }

    public async Task LaunchAllAsync(CancellationToken cancellationToken = default)
    {
        foreach (var state in _sessions)
            await LaunchAsync(state, cancellationToken);
    }

    public Task StopAsync(PeerSessionState state)
    {
        Registry.Unregister(state.Config.Name);
        state.Alive = false;
        state.RemoteSessionName = null;

        if (state.Process is { HasExited: false })
        {
            try
            {
                state.Process.CloseMainWindow();
                if (!state.Process.WaitForExit(3000))
                    state.Process.Kill(entireProcessTree: true);
            }
            catch (Exception ex)
            {
                TrowserLog.Warn($"Failed to stop peer process: {ex.Message}");
            }
        }

        state.Process = null;
        return Task.CompletedTask;
    }

    public async Task RefreshHealthAsync()
    {
        foreach (var state in _sessions)
        {
            RegisterPeer(state);
            var (alive, sessionName, actualPort, _) = await Registry.PingAsync(state.Config.Name);
            SyncPeerPort(state, actualPort);
            var sessionOk = alive && SessionNamesMatch(sessionName, state.Config.SessionName);
            state.Alive = sessionOk;
            state.RemoteSessionName = sessionName;
            if (alive && !sessionOk)
            {
                state.LastError =
                    $"Session mismatch on port {state.Config.Port}: found \"{sessionName ?? "?"}\" (expected \"{state.Config.SessionName}\"). Click Launch.";
            }
            else if (sessionOk)
            {
                state.LastError = null;
            }

            if (!alive && state.Process is { HasExited: true })
                state.Process = null;
        }
    }

    public async Task<(bool success, string? error)> NavigatePeerAsync(string peerName, string url)
    {
        var body = JsonSerializer.Serialize(new { url });
        var resp = await Registry.ForwardAsync(peerName, "POST", "/api/navigate", body, timeoutMs: 30000);
        if (resp.Success || resp.StatusCode == 200)
            return (true, null);
        return (false, resp.Body ?? $"Navigate failed (HTTP {resp.StatusCode}).");
    }

    public IReadOnlyList<string> GetPeersForTests() =>
        _sessions
            .Where(s => s.Config.UseForTests && s.Alive)
            .Select(s => s.Config.Name)
            .ToList();

    /// <summary>
    /// Peers to replay when Live Authz Shadow was not given an explicit name list.
    /// Session peers count only when they are alive and marked "Use for tests".
    /// Names registered outside the session manager are kept.
    /// A null <paramref name="sessions"/> means there is no session manager.
    /// </summary>
    public static IReadOnlyList<string> SelectPeersForReplay(
        IEnumerable<string> registeredNames,
        IReadOnlyList<PeerSessionState>? sessions)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (sessions == null)
            return DistinctNames(registeredNames, seen);

        var marked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var managed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var state in sessions)
        {
            var name = state.Config.Name;
            if (string.IsNullOrWhiteSpace(name))
                continue;
            managed.Add(name);
            if (state.Config.UseForTests && state.Alive)
                marked.Add(name);
        }

        var selected = new List<string>();
        foreach (var name in registeredNames)
        {
            if (string.IsNullOrWhiteSpace(name) || !seen.Add(name))
                continue;
            if (managed.Contains(name) && !marked.Contains(name))
                continue;
            selected.Add(name);
        }

        return selected;
    }

    private static List<string> DistinctNames(IEnumerable<string> names, HashSet<string> seen)
    {
        var all = new List<string>();
        foreach (var name in names)
        {
            if (!string.IsNullOrWhiteSpace(name) && seen.Add(name))
                all.Add(name);
        }

        return all;
    }

    public IReadOnlyList<string> GetAlivePeerNames() =>
        _sessions.Where(s => s.Alive).Select(s => s.Config.Name).ToList();

    private void SyncPeerPort(PeerSessionState state, int? actualPort)
    {
        if (!actualPort.HasValue || actualPort.Value == state.Config.Port)
            return;

        state.Config.Port = actualPort.Value;
        Persist();
        RegisterPeer(state);
    }

    private void RegisterPeer(PeerSessionState state)
    {
        Registry.Register(new PeerEntry
        {
            Name = state.Config.Name,
            BaseUrl = state.BaseUrl,
            ApiKey = state.Config.ApiKey
        }, out _);
    }

    private static void EnsureApiKey(PeerSessionConfig config)
    {
        if (string.IsNullOrWhiteSpace(config.ApiKey))
            config.ApiKey = TrowserApiKey.Generate();
    }

    private string NextPeerName()
    {
        var n = 1;
        while (_sessions.Any(s => s.Config.Name.Equals($"peer{n}", StringComparison.OrdinalIgnoreCase)))
            n++;
        return $"peer{n}";
    }

    private static bool SessionNamesMatch(string? remote, string expected) =>
        !string.IsNullOrWhiteSpace(remote) &&
        remote.Equals(expected, StringComparison.OrdinalIgnoreCase);
}
