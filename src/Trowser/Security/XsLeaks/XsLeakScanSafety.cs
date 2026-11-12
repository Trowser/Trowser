namespace Trowser.Security.XsLeaks;

internal static class XsLeakScanSafety
{
    internal static readonly HashSet<string> TopLevelNavigationTechniques =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "popup-closed",
            "window-open-length",
            "history-length-delta"
        };

    internal static void EnsureStatesAllowed(IReadOnlyList<XsLeakScanner.StateSpec> states)
    {
        foreach (var s in states)
        {
            if (SecurityUrlPolicy.IsSessionTerminationUrl(s.Url))
            {
                throw new InvalidOperationException(
                    $"XS-Leaks state URL looks like logout/session termination and is blocked: {s.Url}");
            }
        }
    }

    internal static bool StatesRiskSessionTermination(
        IReadOnlyList<XsLeakStateValidator.StateFetchSnapshot> snapshots,
        IReadOnlyList<XsLeakScanner.StateSpec> states)
    {
        foreach (var snap in snapshots)
        {
            if (SecurityUrlPolicy.IsSessionTerminationUrl(snap.FinalUrl)
                || SecurityUrlPolicy.IsSessionTerminationUrl(snap.RequestUrl))
                return true;
        }

        return states.Any(s => SecurityUrlPolicy.IsSessionTerminationUrl(s.Url));
    }
}
