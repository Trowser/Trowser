using Trowser.Api;
using Trowser.Peers;
using Trowser.Security.RaceLab;
using Xunit;

namespace Trowser.Tests.Security;

public class RaceLabPeerExpansionTests
{
    [Fact]
    public void AllPeers_RespectsUseForTestsAndAlive()
    {
        var registry = new PeerRegistry();
        registry.Register(new PeerEntry { Name = "peer1", BaseUrl = "http://localhost:6924" }, out _);
        registry.Register(new PeerEntry { Name = "peer2", BaseUrl = "http://localhost:6925" }, out _);

        var sessions = new PeerSessionState[]
        {
            Peer("peer1", useForTests: true, alive: true),
            Peer("peer2", useForTests: false, alive: true),
            Peer("peer3", useForTests: true, alive: false)
        };

        var peerNames = RaceLabEngine.ResolveExpansionPeerNames(registry, sessions);
        Assert.Equal(["peer1"], peerNames);

        var requests = new[]
        {
            new RaceLabRequest
            {
                Name = "health",
                Url = "https://example.test/api/health",
                Method = "GET",
                Session = RaceLabSessions.AllPeers
            }
        };

        var expanded = RaceLabEngine.ExpandSessions(requests, peerNames);
        Assert.Equal(2, expanded.Count);
        Assert.Contains(expanded, r => r.Session == RaceLabSessions.Driver);
        Assert.Contains(expanded, r => r.Session == "peer1");
        Assert.DoesNotContain(expanded, r => r.Session == "peer2");
    }

    [Fact]
    public void ResolveExpansion_WithoutSessionManager_KeepsAllRegistered()
    {
        var registry = new PeerRegistry();
        registry.Register(new PeerEntry { Name = "peer1", BaseUrl = "http://localhost:6924" }, out _);
        registry.Register(new PeerEntry { Name = "api-only", BaseUrl = "http://localhost:6926" }, out _);

        var peerNames = RaceLabEngine.ResolveExpansionPeerNames(registry, sessions: null);
        Assert.Equal(["peer1", "api-only"], peerNames);
    }

    private static PeerSessionState Peer(string name, bool useForTests, bool alive) =>
        new()
        {
            Config = new PeerSessionConfig { Name = name, UseForTests = useForTests },
            Alive = alive
        };
}