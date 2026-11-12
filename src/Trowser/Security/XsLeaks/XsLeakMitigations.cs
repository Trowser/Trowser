namespace Trowser.Security.XsLeaks;

/// <summary>Maps response isolation headers to expected XS-Leak technique blocks (heuristic).</summary>
internal static class XsLeakMitigations
{
    internal sealed class Parsed
    {
        public string? Coop { get; init; }
        public string? Corp { get; init; }
        public string? Coep { get; init; }
        public string? Xfo { get; init; }
        public bool HasFrameAncestors { get; init; }
    }

    public static Parsed Parse(IEnumerable<string> mitigatedBy)
    {
        string? coop = null, corp = null, coep = null, xfo = null;
        var frameAncestors = false;
        foreach (var raw in mitigatedBy)
        {
            if (raw.StartsWith("COOP:", StringComparison.OrdinalIgnoreCase))
                coop = raw["COOP:".Length..].Trim();
            else if (raw.StartsWith("CORP:", StringComparison.OrdinalIgnoreCase))
                corp = raw["CORP:".Length..].Trim();
            else if (raw.StartsWith("COEP:", StringComparison.OrdinalIgnoreCase))
                coep = raw["COEP:".Length..].Trim();
            else if (raw.StartsWith("XFO:", StringComparison.OrdinalIgnoreCase))
                xfo = raw["XFO:".Length..].Trim();
            else if (raw.Equals("CSP-frame-ancestors", StringComparison.OrdinalIgnoreCase))
                frameAncestors = true;
        }
        return new Parsed { Coop = coop, Corp = corp, Coep = coep, Xfo = xfo, HasFrameAncestors = frameAncestors };
    }

    /// <summary>
    /// True when isolation headers should prevent cross-site exploitation of this technique
    /// (downgrade tier to hygiene, not hide the differential).
    /// </summary>
    public static bool IsLikelyMitigated(
        string techniqueId,
        string category,
        Parsed p,
        IReadOnlyDictionary<string, List<string?>> valuesByState,
        out string? reason)
    {
        if (!HeadersSuggestMitigation(techniqueId, category, p, out reason))
            return false;

        if (ObservablesStillShowCrossOriginLeak(techniqueId, valuesByState))
        {
            reason =
                "Isolation headers were present on probe responses but cross-site observables still differed " +
                "(verify enforcement — WebResourceRequested mocks may not apply CORP/COOP).";
            return false;
        }

        return true;
    }

    private static bool HeadersSuggestMitigation(
        string techniqueId,
        string category,
        Parsed p,
        out string? reason)
    {
        reason = null;
        var blocksEmbed = p.Xfo is "DENY" or "SAMEORIGIN"
                          || p.HasFrameAncestors
                          || string.Equals(p.Corp, "same-origin", StringComparison.OrdinalIgnoreCase);

        if (techniqueId is "iframe-load" or "iframe-framecount" or "performance-timing" or "postmessage-listen")
        {
            if (blocksEmbed)
            {
                reason = "Cross-origin embed likely blocked (XFO / frame-ancestors / CORP)";
                return true;
            }
        }

        if (techniqueId is "script-error" or "img-error" or "link-stylesheet-error" or "object-load" or "media-dimensions"
            or "audio-error" or "track-error" or "script-module-error" or "resource-transfer-size" or "cache-prime-probe"
            or "status-bucket-oracle")
        {
            if (string.Equals(p.Corp, "same-origin", StringComparison.OrdinalIgnoreCase)
                || string.Equals(p.Corp, "same-site", StringComparison.OrdinalIgnoreCase))
            {
                reason = "CORP limits cross-origin resource observable";
                return true;
            }
        }

        if (techniqueId is "popup-closed" or "window-open-length" or "history-length-delta" or "named-window-reuse")
        {
            if (string.Equals(p.Coop, "same-origin", StringComparison.OrdinalIgnoreCase)
                || string.Equals(p.Coop, "same-origin-allow-popups", StringComparison.OrdinalIgnoreCase))
            {
                reason = "COOP severs cross-origin window relationships";
                return true;
            }
        }

        if (category == "timing" && !string.IsNullOrEmpty(p.Corp))
        {
            reason = "CORP present (timing oracle may be reduced)";
            return false;
        }

        _ = p.Coep;
        return false;
    }

    private static bool ObservablesStillShowCrossOriginLeak(
        string techniqueId,
        IReadOnlyDictionary<string, List<string?>> valuesByState)
    {
        var all = valuesByState.Values.SelectMany(v => v).Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
        if (all.Count == 0) return false;

        foreach (var raw in all)
        {
            var v = raw!.Trim();
            if (v.StartsWith("load:", StringComparison.OrdinalIgnoreCase)
                || string.Equals(v, "load", StringComparison.OrdinalIgnoreCase))
                return true;
            if (techniqueId == "iframe-framecount"
                && int.TryParse(v.Split(':')[0], System.Globalization.NumberStyles.Integer,
                    System.Globalization.CultureInfo.InvariantCulture, out var frames)
                && frames >= 0)
                return true;
            if (v.StartsWith("fetch:basic", StringComparison.OrdinalIgnoreCase)
                || v.StartsWith("fetch:cors", StringComparison.OrdinalIgnoreCase)
                || v.StartsWith("fetch:opaqueredirect", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }
}
