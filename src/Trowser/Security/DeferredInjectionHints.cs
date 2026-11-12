namespace Trowser.Security;

/// <summary>
/// Detects set-then-read injection flows (POST stores into session/cookie/DB; a sibling page renders).
/// Single-request sqli/xss scans often miss these — emit verify-workflow stubs instead of silent misses.
/// </summary>
public static class DeferredInjectionHints
{
    private static readonly string[] SetterParamHints =
    [
        "session", "store", "save", "set", "memo", "note", "preference", "profile",
        "guestbook", "comment", "message", "input", "value", "data"
    ];

    private static readonly string[] SetterPathHints =
    [
        "session", "store", "save", "set", "preference", "profile", "guestbook",
        "comment", "message", "input", "memo", "note", "persist"
    ];

    private static readonly string[] ReaderPathHints =
    [
        "view", "show", "display", "read", "list", "index", "home", "welcome",
        "render", "output", "result", "exec", "run"
    ];

    /// <summary>
    /// True when this probe likely stores input for later consumption rather than reflecting in-response.
    /// </summary>
    public static bool LooksLikeDeferredSetter(string method, string? url, string? paramName)
    {
        var isMutating = method.Equals("POST", StringComparison.OrdinalIgnoreCase)
            || method.Equals("PUT", StringComparison.OrdinalIgnoreCase)
            || method.Equals("PATCH", StringComparison.OrdinalIgnoreCase);
        if (!isMutating) return false;

        var path = "";
        if (!string.IsNullOrWhiteSpace(url) && Uri.TryCreate(url, UriKind.Absolute, out var uri))
            path = uri.AbsolutePath;
        else if (!string.IsNullOrWhiteSpace(url))
            path = url;

        var pathLower = path.ToLowerInvariant();
        var paramLower = (paramName ?? "").ToLowerInvariant();

        var pathHit = SetterPathHints.Any(h => pathLower.Contains(h, StringComparison.Ordinal));
        var paramHit = SetterParamHints.Any(h => paramLower.Contains(h, StringComparison.Ordinal));

        // Strong signal: path or param mentions session/store/save/set
        if (pathHit && (paramHit || paramLower is "ip" or "name" or "text" or "html" or "cmd" or "command"))
            return true;
        if (paramLower.Contains("session", StringComparison.Ordinal)
            || paramLower is "session-input" or "session_input" or "sessioninput")
            return true;
        if (pathLower.Contains("session", StringComparison.Ordinal) && isMutating)
            return true;

        return pathHit && paramHit;
    }

    /// <summary>
    /// Find likely consumer/render URLs on the same origin from the attack surface.
    /// </summary>
    public static string? SuggestReadUrl(
        string setUrl,
        IEnumerable<AttackSurfaceEndpoint> endpoints)
    {
        if (!Uri.TryCreate(setUrl, UriKind.Absolute, out var setUri))
            return null;

        var origin = setUri.GetLeftPart(UriPartial.Authority);
        var setDir = setUri.AbsolutePath;
        var slash = setDir.LastIndexOf('/');
        if (slash > 0) setDir = setDir[..(slash + 1)];

        string? best = null;
        var bestScore = -1;
        foreach (var ep in endpoints)
        {
            if (!Uri.TryCreate(ep.Url, UriKind.Absolute, out var epUri))
                continue;
            if (!string.Equals(epUri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;
            if (string.Equals(epUri.AbsolutePath, setUri.AbsolutePath, StringComparison.OrdinalIgnoreCase))
                continue;

            var path = epUri.AbsolutePath.ToLowerInvariant();
            var score = 0;
            if (path.StartsWith(setDir, StringComparison.OrdinalIgnoreCase)) score += 2;
            if (ReaderPathHints.Any(h => path.Contains(h, StringComparison.Ordinal))) score += 3;
            if (ep.Methods.Any(m => m.Equals("GET", StringComparison.OrdinalIgnoreCase))) score += 1;
            // Prefer same directory / feature area
            if (score > bestScore)
            {
                bestScore = score;
                best = epUri.GetLeftPart(UriPartial.Path);
            }
        }

        return bestScore >= 2 ? best : null;
    }

    public static AutoScanPipeline.AutoScanFinding BuildHintFinding(
        string setUrl,
        string method,
        string paramName,
        string? readUrl)
    {
        return new AutoScanPipeline.AutoScanFinding
        {
            Scanner = "deferred-injection",
            Severity = "info",
            Endpoint = setUrl,
            Method = method,
            Title = $"Possible deferred injection via '{paramName}' (set-then-read)",
            Detail =
                "This endpoint looks like it stores input (session/cookie/DB) for later rendering. " +
                "Single-request injection scans may miss it — confirm with a verify-workflow that POSTs a payload then GETs the consumer page.",
            Evidence = readUrl != null ? $"Suggested read URL: {readUrl}" : "No sibling read URL inferred — browse for the render page.",
            NextActions =
            [
                SecurityNextActions.VerifyWorkflow,
                SecurityNextActions.VerifyDeferredInjectionStub(setUrl, method, paramName, readUrl)
            ]
        };
    }
}
