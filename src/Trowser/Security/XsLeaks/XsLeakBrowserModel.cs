namespace Trowser.Security.XsLeaks;

/// <summary>Documents browser/runtime assumptions for XS-Leak verdict interpretation.</summary>
public sealed class XsLeakBrowserModel
{
    public string Engine { get; init; } = "WebView2 (Chromium)";
    public string AttackerSiteMode { get; init; } = "cross-site";
    public string AttackerOrigin { get; init; } = AttackerPageBuilder.AttackerOrigin;
    public bool CrossSiteFixturesRequireMockCopy { get; init; } = true;
    public string CookiePartitioning { get; init; } =
        "Chromium third-party cookie restrictions apply; SameSite rules govern authenticated subresource probes.";
    public string CachePartitioning { get; init; } =
        "Cache keys are partitioned by top-level site; cross-site cache oracles may not observe hits from another site.";
    public string IsolationEnforcement { get; init; } =
        "COOP/CORP/COEP are enforced by Chromium when responses are real network/CDP paths; WebResourceRequested mocks may not fully replicate isolation.";

    public object ToApiObject() => new
    {
        engine = Engine,
        attackerSiteMode = AttackerSiteMode,
        attackerOrigin = AttackerOrigin,
        crossSiteFixturesRequireMockCopy = CrossSiteFixturesRequireMockCopy,
        cookiePartitioning = CookiePartitioning,
        cachePartitioning = CachePartitioning,
        isolationEnforcement = IsolationEnforcement
    };

    public static XsLeakBrowserModel ForRun(string attackerOrigin, string? attackerSiteMode) => new()
    {
        AttackerOrigin = attackerOrigin,
        AttackerSiteMode = string.IsNullOrWhiteSpace(attackerSiteMode) ? "cross-site" : attackerSiteMode.Trim()
    };

    public static XsLeakBrowserModel Current() => new();
}
