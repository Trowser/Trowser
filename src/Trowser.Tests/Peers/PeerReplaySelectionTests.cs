using System.Text.Json;
using Trowser.Peers;
using Trowser.Security.Authz;
using Xunit;

namespace Trowser.Tests.Peers;

public class PeerReplaySelectionTests
{
    [Fact]
    public void NewPeer_IsNotMarkedForTests()
    {
        Assert.False(new PeerSessionConfig().UseForTests);
    }

    [Fact]
    public void MissingUseForTests_DeserializesUnchecked()
    {
        var json = """{"peers":[{"name":"peer1","port":6924,"sessionName":"peer1"}],"nextPort":6926}""";
        var data = JsonSerializer.Deserialize<PeerSessionSettingsData>(json, JsonOptions);

        Assert.NotNull(data);
        Assert.False(data.Peers[0].UseForTests);
    }

    [Fact]
    public void UseForTestsFalse_RoundTrips()
    {
        var data = new PeerSessionSettingsData
        {
            Peers = [new PeerSessionConfig { Name = "anon", UseForTests = false }],
            NextPort = 6927
        };

        var json = JsonSerializer.Serialize(data, JsonOptions);
        var loaded = JsonSerializer.Deserialize<PeerSessionSettingsData>(json, JsonOptions);

        Assert.NotNull(loaded);
        Assert.False(loaded.Peers[0].UseForTests);
        Assert.Contains("\"useForTests\": false", json, StringComparison.Ordinal);
    }

    [Fact]
    public void SelectPeersForReplay_SkipsStoppedAndUncheckedSessionPeers()
    {
        var sessions = new PeerSessionState[]
        {
            Peer("peer1", useForTests: true, alive: false),
            Peer("anon", useForTests: false, alive: true),
            Peer("bob", useForTests: true, alive: true)
        };

        var selected = PeerSessionManager.SelectPeersForReplay(
            ["peer1", "anon", "bob", "api-only"],
            sessions);

        Assert.Equal(["bob", "api-only"], selected);
    }

    [Fact]
    public void SelectPeersForReplay_WithoutSessionManager_KeepsRegisteredNames()
    {
        var selected = PeerSessionManager.SelectPeersForReplay(["peer1", "peer1", "anon"], sessions: null);

        Assert.Equal(["peer1", "anon"], selected);
    }

    [Fact]
    public void ResolveReplayPeers_ExplicitListWins()
    {
        var shadow = new LiveAuthzShadow(new Trowser.Security.Authz.AccessModelStore(
            Path.Combine(Path.GetTempPath(), "trowser-authz-" + Guid.NewGuid().ToString("n"))));
        shadow.Configure(true, "safe", ["peer1"]);

        Assert.Equal(["peer1"], shadow.ResolveReplayPeers());
    }

    private static PeerSessionState Peer(string name, bool useForTests, bool alive) =>
        new()
        {
            Config = new PeerSessionConfig { Name = name, UseForTests = useForTests },
            Alive = alive
        };

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };
}
