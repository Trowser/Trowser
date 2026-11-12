// @title 4 Bola Across Sessions
// @shadow never
// @effects mutates
// BOLA / cross-session authorization comparison
// Prerequisites: launch peer sessions (More → Peer sessions…) and log in as different users.
// Or uncomment LaunchPeer lines below to start peers from this script (GUI only).

// --- Configure peers and endpoints (edit these) ---
var peerNames = new[] { "peer1", "peer2" };

// Endpoints to compare — use objects for non-GET / captured headers:
var endpoints = new object[]
{
    // "https://example.com/api/me",
    new { url = "https://example.com/api/orders", method = "GET" },
    // new { url = "https://example.com/api/orders/123", method = "PUT", body = "{\"status\":\"shipped\"}" },
};

// Optional: auto-launch peers from script (requires GUI; peers must not already be running)
// await LaunchPeer("peer1", port: 6924, sessionName: "peer1");
// await LaunchPeer("peer2", port: 6925, sessionName: "peer2");

if (endpoints.Length == 0)
{
    Log("Edit BolaAcrossSessions.csx — add endpoints at the top.", "#CCA700");
    return;
}

Log("=== BOLA across sessions ===", "#569CD6");

var alivePeers = GetPeerNamesForTests();
if (alivePeers.Count == 0)
{
    Log("No alive peers for tests. Open More → Peer sessions, launch peers, and log in as different users.", "#F44747");
    return;
}

var usePeers = peerNames.Where(p => alivePeers.Contains(p, StringComparer.OrdinalIgnoreCase)).ToArray();
if (usePeers.Length == 0)
    usePeers = alivePeers.ToArray();

Log($"Comparing as driver vs peer(s): {string.Join(", ", usePeers)}", "#888888");

var results = await AuthzDiff(usePeers, endpoints, includeBodyOnMismatch: true, ensureOrigin: false);

foreach (var peerResult in results)
{
    Log($"Peer: {peerResult.Peer}", "#4EC9B0");
    foreach (var c in peerResult.Comparisons)
    {
        var color = c.Finding switch
        {
            "BOLA_SUSPECTED" => "#F44747",
            "FILTERED_RESPONSE" => "#CCA700",
            "PROPERLY_DENIED" or "DENIED_BOTH" or "REDIRECT_DENIED" => "#4EC9B0",
            _ => "#DCDCAA"
        };
        Log($"  [{c.Finding}] {c.Method} {c.Url}", color);
        Log($"    local {c.Local.Status} / peer {c.Peer.Status}", "#858585");
    }
}

var bola = results.Sum(r => r.Summary.BolaSuspected);
if (bola > 0)
{
    Log($"*** {bola} BOLA_SUSPECTED — identical data returned to different users ***", "#F44747");
    Assert.True(false, $"{bola} BOLA_SUSPECTED finding(s)");
}
else
{
    Log("No BOLA_SUSPECTED findings.", "#4EC9B0");
}
