namespace Trowser.Security.XsLeaks;

public static class XsLeakTechniques
{
    public enum CredentialContext
    {
        None,
        Subresource,
        TopLevel
    }

    public sealed class TechniqueDef
    {
        public string Id { get; init; } = "";
        public string Category { get; init; } = "";
        public bool RequiresActive { get; init; }
        public bool IsTiming { get; init; }
        public int DefaultTrials { get; init; } = 3;
        public CredentialContext CredentialContext { get; init; } = CredentialContext.Subresource;
        public bool RequiresTimingAllowOrigin { get; init; }
        public bool Experimental { get; init; }
    }

    public static readonly TechniqueDef[] Catalog =
    [
        new() { Id = "iframe-load", Category = "load-error", CredentialContext = CredentialContext.Subresource },
        new() { Id = "iframe-framecount", Category = "frame-count", CredentialContext = CredentialContext.Subresource },
        new() { Id = "script-error", Category = "load-error", CredentialContext = CredentialContext.Subresource },
        new() { Id = "img-error", Category = "load-error", CredentialContext = CredentialContext.Subresource },
        new() { Id = "link-stylesheet-error", Category = "load-error", CredentialContext = CredentialContext.Subresource },
        new() { Id = "object-load", Category = "load-error", CredentialContext = CredentialContext.Subresource },
        new() { Id = "media-dimensions", Category = "media", DefaultTrials = 2, CredentialContext = CredentialContext.Subresource },
        new() { Id = "performance-timing", Category = "timing", IsTiming = true, DefaultTrials = 5, CredentialContext = CredentialContext.Subresource },
        new() { Id = "postmessage-listen", Category = "postmessage", DefaultTrials = 2, CredentialContext = CredentialContext.Subresource },
        new() { Id = "fetch-redirect-type", Category = "redirect", CredentialContext = CredentialContext.Subresource },
        new() { Id = "resource-transfer-size", Category = "cache", RequiresTimingAllowOrigin = true, CredentialContext = CredentialContext.Subresource },
        new() { Id = "audio-error", Category = "load-error", CredentialContext = CredentialContext.Subresource },
        new() { Id = "broadcast-channel-probe", Category = "postmessage", DefaultTrials = 2, CredentialContext = CredentialContext.None },
        new() { Id = "cache-prime-probe", Category = "cache", RequiresActive = true, IsTiming = true, DefaultTrials = 4, Experimental = true, CredentialContext = CredentialContext.Subresource },
        new() { Id = "connection-pool-exhaustion", Category = "timing", RequiresActive = true, IsTiming = true, DefaultTrials = 4, CredentialContext = CredentialContext.Subresource },
        new() { Id = "popup-closed", Category = "popup", RequiresActive = true, CredentialContext = CredentialContext.TopLevel },
        new() { Id = "form-post-frame", Category = "navigation", CredentialContext = CredentialContext.TopLevel, DefaultTrials = 2 },
        new() { Id = "status-bucket-oracle", Category = "status", CredentialContext = CredentialContext.Subresource },
        new() { Id = "script-module-error", Category = "load-error", CredentialContext = CredentialContext.Subresource },
        new() { Id = "track-error", Category = "load-error", CredentialContext = CredentialContext.Subresource },
        new() { Id = "csp-violation-probe", Category = "csp", DefaultTrials = 2, CredentialContext = CredentialContext.Subresource },
        new() { Id = "redirect-count-oracle", Category = "redirect", CredentialContext = CredentialContext.Subresource },
        new() { Id = "window-open-length", Category = "popup", RequiresActive = true, CredentialContext = CredentialContext.TopLevel },
        new() { Id = "named-window-reuse", Category = "popup", RequiresActive = true, DefaultTrials = 2, CredentialContext = CredentialContext.TopLevel },
        new() { Id = "history-length-delta", Category = "popup", RequiresActive = true, CredentialContext = CredentialContext.TopLevel },
        new() { Id = "event-loop-blocking", Category = "timing", RequiresActive = true, IsTiming = true, DefaultTrials = 5, CredentialContext = CredentialContext.Subresource },
        new() { Id = "cache-timing", Category = "cache", RequiresActive = true, IsTiming = true, DefaultTrials = 4, Experimental = true, CredentialContext = CredentialContext.Subresource },
    ];

    /// <summary>Default when <c>techniques</c> is omitted — fast representative subset (not the full catalog).</summary>
    public static readonly string[] DefaultQuickCatalogIds =
    [
        "img-error",
        "script-error",
        "iframe-load",
        "status-bucket-oracle",
        "form-post-frame"
    ];

    /// <summary>When all victim states are JSON APIs, prefer status oracles over subresource load probes.</summary>
    public static readonly string[] JsonApiQuickCatalogIds =
    [
        "status-bucket-oracle",
        "fetch-redirect-type"
    ];

    public static IEnumerable<TechniqueDef> ForMode(bool active, IReadOnlyList<string>? filter, bool fullCatalog = false)
    {
        IReadOnlyList<string>? effective = filter;
        if (effective is null or { Count: 0 } && !fullCatalog)
            effective = DefaultQuickCatalogIds;

        foreach (var t in Catalog)
        {
            if (t.RequiresActive && !active) continue;
            if (effective is { Count: > 0 }
                && !effective.Any(f => t.Id.Equals(f, StringComparison.OrdinalIgnoreCase)
                                        || t.Category.Equals(f, StringComparison.OrdinalIgnoreCase)))
                continue;
            yield return t;
        }
    }
}
