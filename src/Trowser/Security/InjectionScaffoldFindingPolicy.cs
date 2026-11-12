using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Epistemic caps for sparse-traffic injection scaffolds — findings on paths not seen in the network log
/// stay hypothesis-grade until traffic or attack-surface confirms the endpoint.
/// </summary>
public static class InjectionScaffoldFindingPolicy
{
    public static bool IsPathObservedInTraffic(
        IReadOnlyList<NetworkEntry> entries,
        string endpointOrUrl,
        string origin)
    {
        if (entries.Count == 0 || string.IsNullOrWhiteSpace(origin))
            return false;

        if (!TryResolveAbsolutePath(endpointOrUrl, origin, out var path))
            return false;

        foreach (var e in entries)
        {
            if (e.StatusCode is < 200 or >= 400) continue;
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var u)) continue;
            if (!string.Equals(u.GetLeftPart(UriPartial.Authority), origin.TrimEnd('/'),
                    StringComparison.OrdinalIgnoreCase)
                && !string.Equals(u.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;
            if (string.Equals(u.AbsolutePath.TrimEnd('/'), path, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    public static (string Severity, string TitlePrefix, string? DetailSuffix) AdjustScaffoldInjectionSeverity(
        string severity,
        string titlePrefix,
        bool observedInTraffic)
    {
        if (observedInTraffic)
            return (severity, titlePrefix, null);

        var capped = CapSeverityMax(severity, "medium");
        var prefix = string.IsNullOrWhiteSpace(titlePrefix)
            ? "Hypothesis (scaffold): "
            : $"Hypothesis (scaffold): {titlePrefix}";
        return (capped, prefix,
            " Endpoint path was not observed in captured network traffic — browse or map attack-surface before filing.");
    }

    private static bool TryResolveAbsolutePath(string endpointOrUrl, string origin, out string path)
    {
        path = "";
        if (Uri.TryCreate(endpointOrUrl, UriKind.Absolute, out var abs))
        {
            path = abs.AbsolutePath.TrimEnd('/');
            return path.Length > 0;
        }

        if (endpointOrUrl.StartsWith("/", StringComparison.Ordinal)
            && Uri.TryCreate(origin.TrimEnd('/') + endpointOrUrl, UriKind.Absolute, out var rel))
        {
            path = rel.AbsolutePath.TrimEnd('/');
            return true;
        }

        return false;
    }

    private static string CapSeverityMax(string severity, string max) =>
        SeverityRank(severity) > SeverityRank(max) ? max : severity;

    private static int SeverityRank(string s) => s.ToLowerInvariant() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0
    };
}
