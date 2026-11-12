// @title 4 Race Lab
// @shadow never
// @effects mutates
#r "Trowser"

using Trowser.Security.RaceLab;

// Register peers first when testing cross-identity races (GUI: Peer sessions, RegisterPeer, or POST /api/peer/register).
// Session defaults to all-peers (driver + each peer). Role defaults to observe (no duplicate-action finding).
var profile = new RaceLabProfile
{
    Name = "Hammer",
    Parameters = RaceLabParameters.ForMode(RaceLabMode.Hammer),
    Requests =
    [
        new RaceLabRequest
        {
            Name = "health",
            Url = "https://example.test/api/health",
            Method = "GET",
            Session = RaceLabSessions.AllPeers,
            Role = RaceLabRoles.Observe
        },
        new RaceLabRequest
        {
            Name = "redeem",
            Url = "https://example.test/api/redeem",
            Method = "POST",
            Body = """{"code":"PROMO-ONE-TIME"}""",
            Session = RaceLabSessions.Driver,
            Role = RaceLabRoles.Mutate
        }
    ]
};

var result = await RunRaceLabAsync(profile);
Log(result.Message);
foreach (var f in result.Findings)
    Log($"[{f.Confidence}] {f.Category}: {f.Title}");
