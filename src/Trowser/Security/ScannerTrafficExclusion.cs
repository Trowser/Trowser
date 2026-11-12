using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// URLs and listeners that belong to Trowser itself — exclude from Shadow network hygiene,
/// attack-surface maps, and preflight traffic counts.
/// </summary>
public static class ScannerTrafficExclusion
{
    /// <summary>Probe baseline markers and canaries — self-traffic even when synthetic marking is missing.</summary>
    private static readonly string[] ScannerUrlMarkers =
    [
        "_trowser_",
        "_trowser_rc=",
        "trowser-xss-baseline",
        "trowser-csti-baseline",
        "trowser_pp_canary",
        "trowserPp",
        "__proto__[trowser",
        "constructor[prototype][trowser"
    ];

    public const string InitiatorHeaderName = "X-Trowser-Initiator";
    public const string InitiatorHeaderValue = "trowser";

    public static bool IsScannerUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return false;
        foreach (var marker in ScannerUrlMarkers)
        {
            if (url.Contains(marker, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    public static bool ShouldIgnoreNetworkHygiene(NetworkEntry entry) =>
        entry.IsTrowserGenerated || IsScannerUrl(entry.Url);

    public static bool ShouldExcludeFromAttackSurface(NetworkEntry entry) =>
        ShouldIgnoreNetworkHygiene(entry);
}
