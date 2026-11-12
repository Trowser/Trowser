using Trowser.Api;
using Trowser.Automation;

namespace Trowser.Peers;

public sealed class PeerSpawnRequest
{
    public string? Name { get; init; }
    public string? Session { get; init; }
    public string? ApiKey { get; init; }
    public int? Port { get; init; }
    public bool Ephemeral { get; init; } = true;
    public bool Register { get; init; } = true;
}

public sealed class PeerSpawnResult
{
    public bool Success { get; init; }
    public string? Name { get; init; }
    public string? BaseUrl { get; init; }
    public string? ApiKey { get; init; }
    public string? SessionName { get; init; }
    public bool Alive { get; init; }
    public string? Error { get; init; }
}

/// <summary>Launch and register a localhost peer Trowser from the primary instance.</summary>
public static class PeerSpawnService
{
    public static async Task<PeerSpawnResult> SpawnAsync(
        AutomationContext context,
        PeerRegistry registry,
        PeerSpawnRequest request,
        CancellationToken ct = default)
    {
        var manager = context.PeerSessionManager;
        if (manager != null)
            return await SpawnViaManagerAsync(manager, request, ct);

        return await SpawnHeadlessAsync(context, registry, request, ct);
    }

    public static async Task<(bool stopped, string? error)> StopAsync(
        AutomationContext context,
        PeerRegistry registry,
        string peerName,
        bool unregister)
    {
        var manager = context.PeerSessionManager;
        if (manager != null)
        {
            var state = manager.Get(peerName);
            if (state != null)
                await manager.StopAsync(state);
        }
        else
        {
            PeerProcessTracker.TryStop(peerName, out var stopErr);
            if (stopErr != null)
                return (false, stopErr);
        }

        if (unregister)
            registry.Unregister(peerName);

        return (true, null);
    }

    private static async Task<PeerSpawnResult> SpawnViaManagerAsync(
        PeerSessionManager manager,
        PeerSpawnRequest request,
        CancellationToken ct)
    {
        var name = string.IsNullOrWhiteSpace(request.Name)
            ? manager.Sessions.FirstOrDefault()?.Config.Name ?? "peer1"
            : request.Name.Trim();

        var state = manager.Get(name) ?? manager.AddPeer(name);
        if (request.Port.HasValue)
            state.Config.Port = request.Port.Value;
        if (!string.IsNullOrWhiteSpace(request.Session))
            state.Config.SessionName = request.Session.Trim();
        if (!string.IsNullOrWhiteSpace(request.ApiKey))
            state.Config.ApiKey = request.ApiKey.Trim();
        else if (string.IsNullOrWhiteSpace(state.Config.ApiKey))
            state.Config.ApiKey = TrowserApiKey.Generate();

        var (ok, error) = await manager.LaunchAsync(state, ct);
        return new PeerSpawnResult
        {
            Success = ok,
            Name = state.Config.Name,
            BaseUrl = state.BaseUrl,
            ApiKey = state.Config.ApiKey,
            SessionName = state.Config.SessionName,
            Alive = state.Alive,
            Error = error
        };
    }

    private static async Task<PeerSpawnResult> SpawnHeadlessAsync(
        AutomationContext context,
        PeerRegistry registry,
        PeerSpawnRequest request,
        CancellationToken ct)
    {
        var session = string.IsNullOrWhiteSpace(request.Session)
            ? (string.IsNullOrWhiteSpace(request.Name) ? "peer" : request.Name.Trim())
            : request.Session.Trim();
        var name = string.IsNullOrWhiteSpace(request.Name) ? session : request.Name.Trim();

        var apiKey = string.IsNullOrWhiteSpace(request.ApiKey)
            ? TrowserApiKey.Generate()
            : request.ApiKey.Trim();

        var port = request.Port ?? PeerLauncher.FindFreePort(6924);
        var scope = context.NavigationGuard?.Scope ?? "*.*";

        var (alreadyAlive, remoteSession, actualPort, _) = await registry.PingAsync(name);
        if (alreadyAlive)
        {
            var peer = registry.Get(name);
            return new PeerSpawnResult
            {
                Success = true,
                Name = name,
                BaseUrl = peer?.BaseUrl ?? $"http://localhost:{actualPort ?? port}",
                ApiKey = peer?.ApiKey ?? apiKey,
                SessionName = remoteSession ?? session,
                Alive = true
            };
        }

        var launch = PeerLauncher.Launch(port, apiKey, session, scope, ephemeral: request.Ephemeral);
        if (!launch.Success)
        {
            return new PeerSpawnResult
            {
                Success = false,
                Name = name,
                Error = launch.Error ?? "Launch failed."
            };
        }

        if (launch.Process != null)
            PeerProcessTracker.Track(name, launch.Process);

        if (request.Register)
        {
            registry.Register(new PeerEntry
            {
                Name = name,
                BaseUrl = $"http://localhost:{launch.Port}",
                ApiKey = apiKey
            }, out _);
        }

        var deadline = DateTime.UtcNow.AddSeconds(45);
        while (DateTime.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            var (alive, sessionName, boundPort, pingError) = await registry.PingAsync(name);
            if (alive)
            {
                return new PeerSpawnResult
                {
                    Success = true,
                    Name = name,
                    BaseUrl = $"http://localhost:{boundPort ?? launch.Port}",
                    ApiKey = apiKey,
                    SessionName = sessionName ?? session,
                    Alive = true
                };
            }

            if (launch.Process is { HasExited: true })
            {
                return new PeerSpawnResult
                {
                    Success = false,
                    Name = name,
                    Error = $"Peer process exited (code {launch.Process.ExitCode})."
                };
            }

            await Task.Delay(500, ct);
        }

        return new PeerSpawnResult
        {
            Success = false,
            Name = name,
            BaseUrl = $"http://localhost:{launch.Port}",
            ApiKey = apiKey,
            SessionName = session,
            Alive = false,
            Error = "Peer did not respond within 45 seconds."
        };
    }
}
