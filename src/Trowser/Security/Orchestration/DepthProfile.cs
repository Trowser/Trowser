namespace Trowser.Security.Orchestration;

/// <summary>
/// Controls scan breadth/depth for playbook orchestration.
/// Maps to per-scanner caps, wordlist sizes, and identity counts.
/// </summary>
public enum PlaybookDepth
{
    Quick,
    /// <summary>Agent/LLM sessions: short wall-clock, top-N endpoints, core scanners only where applicable.</summary>
    Llm,
    Standard,
    Deep
}

public sealed class PlaybookDepthProfile
{
    public PlaybookDepth Depth { get; init; }

    /// <summary>Max endpoints fed to each sub-scanner (passive steps; probe steps use <see cref="EndpointScopeHelper.CapProbeEndpoints"/>).</summary>
    public int MaxEndpointsPerScanner { get; init; }

    /// <summary>Max identities to test (beyond anon).</summary>
    public int MaxIdentities { get; init; }

    /// <summary>Wordlist tier for discovery probes.</summary>
    public string WordlistSize { get; init; } = "small";

    /// <summary>Max pages for light crawl before scans (0 = skip crawl).</summary>
    public int MaxCrawlPages { get; init; }

    /// <summary>Rough wall-clock hint for UI progress display.</summary>
    public int TimeHintSeconds { get; init; }

    /// <summary>Maps to AutoScanDepthProfile name.</summary>
    public string AutoScanDepthName { get; init; } = AutoScanDepthProfile.Standard;

    public static PlaybookDepth Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return PlaybookDepth.Standard;
        return value.Trim().ToLowerInvariant() switch
        {
            "quick" or "fast" or "light" => PlaybookDepth.Quick,
            "llm" or "agent" or "ai" => PlaybookDepth.Llm,
            "deep" or "thorough" or "full" => PlaybookDepth.Deep,
            _ => PlaybookDepth.Standard
        };
    }

    public static PlaybookDepthProfile Resolve(PlaybookDepth depth) => depth switch
    {
        PlaybookDepth.Quick => new PlaybookDepthProfile
        {
            Depth = PlaybookDepth.Quick,
            MaxEndpointsPerScanner = 5,
            MaxIdentities = 0,
            WordlistSize = "tiny",
            MaxCrawlPages = 5,
            TimeHintSeconds = 30,
            AutoScanDepthName = AutoScanDepthProfile.Quick
        },
        PlaybookDepth.Llm => new PlaybookDepthProfile
        {
            Depth = PlaybookDepth.Llm,
            MaxEndpointsPerScanner = 3,
            MaxIdentities = 0,
            WordlistSize = "tiny",
            MaxCrawlPages = 5,
            TimeHintSeconds = 180,
            AutoScanDepthName = AutoScanDepthProfile.Quick
        },
        PlaybookDepth.Deep => new PlaybookDepthProfile
        {
            Depth = PlaybookDepth.Deep,
            MaxEndpointsPerScanner = 100,
            MaxIdentities = 3,
            WordlistSize = "medium",
            MaxCrawlPages = 50,
            TimeHintSeconds = 600,
            AutoScanDepthName = AutoScanDepthProfile.Thorough
        },
        _ => new PlaybookDepthProfile
        {
            Depth = PlaybookDepth.Standard,
            MaxEndpointsPerScanner = 20,
            MaxIdentities = 1,
            WordlistSize = "small",
            MaxCrawlPages = 15,
            TimeHintSeconds = 120,
            AutoScanDepthName = AutoScanDepthProfile.Standard
        }
    };

    public string ToLabel() => Depth switch
    {
        PlaybookDepth.Quick => "quick",
        PlaybookDepth.Llm => "llm",
        PlaybookDepth.Deep => "deep",
        _ => "standard"
    };
}
