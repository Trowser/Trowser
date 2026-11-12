using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Trowser.Automation;
using Trowser.Security;

namespace Trowser.Peers;

/// <summary>
/// Logs authz/BOLA comparison results to the script console with verdict colors.
/// </summary>
public static class BolaResultLogger
{
    public static void LogResults(AutomationContext context, IReadOnlyList<AuthzComparisonResult> results)
    {
        context.Log("=== BOLA / Authz comparison ===", "#569CD6");
        context.Log("", "#CCCCCC");

        foreach (var peerResult in results)
        {
            context.Log($"Peer: {peerResult.Peer}", "#4EC9B0");
            context.Log(
                $"  Summary: {peerResult.Summary.TotalEndpoints} endpoints — " +
                $"BOLA_SUSPECTED={peerResult.Summary.BolaSuspected}, " +
                $"FILTERED={peerResult.Summary.FilteredResponse}, " +
                $"PROPERLY_DENIED={peerResult.Summary.ProperlyDenied}, " +
                $"DENIED_BOTH={peerResult.Summary.DeniedBoth}, " +
                $"ERRORS={peerResult.Summary.Errors + peerResult.Summary.ErrorBeforeAuth}",
                "#888888");

            foreach (var c in peerResult.Comparisons)
            {
                var color = FindingColor(c.Finding);
                context.Log($"  [{c.Finding}] {c.Method} {c.Url}", color);
                context.Log(
                    $"    local {c.Local.Status} (hash {c.Local.BodyHash}, {c.Local.BodyLength} bytes)  " +
                    $"peer {c.Peer.Status} (hash {c.Peer.BodyHash}, {c.Peer.BodyLength} bytes)",
                    "#858585");
                if (c.Local.Error != null)
                    context.Log($"    local error: {c.Local.Error}", "#F44747");
                if (c.Peer.Error != null)
                    context.Log($"    peer error: {c.Peer.Error}", "#F44747");
                if (c.Leaks is { Count: > 0 })
                    context.Log($"    leaks: {string.Join(", ", c.Leaks)}", "#CCA700");
            }

            context.Log("", "#CCCCCC");
        }

        var totalBola = results.Sum(r => r.Summary.BolaSuspected);
        if (totalBola > 0)
            context.Log($"*** {totalBola} BOLA_SUSPECTED finding(s) — identical data across identities ***", "#F44747");
        else
            context.Log("No BOLA_SUSPECTED findings (no byte-identical successful responses across peers).", "#4EC9B0");
    }

    private static string FindingColor(string finding) => finding switch
    {
        "BOLA_SUSPECTED" => "#F44747",
        "FILTERED_RESPONSE" => "#CCA700",
        "PROPERLY_DENIED" or "REDIRECT_DENIED" or "DENIED_BOTH" => "#4EC9B0",
        "ERROR" or "ERROR_BEFORE_AUTH" or "OTHER" => "#CE9178",
        _ => "#DCDCAA"
    };
}
