namespace Trowser.Security;

public enum TraceSourceType
{
    Form,
    UrlQuery,
    UrlHash,
    UrlPath,
    WindowName,
    Storage,
    PostMessage,
    Referrer
}

public sealed record TraceInputOptions
{
    public TraceSourceType Source { get; init; } = TraceSourceType.Form;
    public string Payload { get; init; } = XssBypassProbes.DefaultPrimaryPayload;

    // Form source
    public string? TargetSelector { get; init; }
    public string? SubmitSelector { get; init; }
    public string SubmitAction { get; init; } = "click";

    // URL sources — baseUrl defaults to current page when omitted
    public string? BaseUrl { get; init; }
    public string? QueryParam { get; init; } = "q";
    public string? HashParam { get; init; }
    /// <summary>Storage key for source=storage (default trowser_probe).</summary>
    public string? StorageKey { get; init; } = "trowser_probe";
    /// <summary>local | session — for source=storage.</summary>
    public string StorageKind { get; init; } = "local";
    /// <summary>
    /// Query encoding for url-query traces. Default <see cref="UrlPayloadEncodeMode.None"/> —
    /// DOM XSS sinks often read via decodeURI/decodeURIComponent; component encoding breaks injection.
    /// Use component/form when testing server-side reflection.
    /// </summary>
    public UrlPayloadEncodeMode QueryEncode { get; init; } = UrlPayloadEncodeMode.None;
    public UrlPayloadEncodeMode FragmentEncode { get; init; } = UrlPayloadEncodeMode.None;
    public UrlPayloadEncodeMode PathEncode { get; init; } = UrlPayloadEncodeMode.Component;

    /// <summary>After form input is filtered/constrained, automatically probe URL query and hash vectors.</summary>
    public bool ProbeUrlSources { get; init; } = true;

    public int TimeoutMs { get; init; } = 10_000;
    public bool CheckCsp { get; init; } = true;
    public bool DetectSqli { get; init; }
    public bool MonitorSinks { get; init; } = true;
    /// <summary>Reach canary first, then context-aware confirmation payload (when <see cref="MonitorSinks"/>).</summary>
    public bool TwoPhase { get; init; } = true;
    /// <summary>For url-query: inject reach canary into every discovered query parameter.</summary>
    public bool ProbeAllUrlParams { get; init; }
    /// <summary>After navigation, click first same-page anchor (helps window.open / click-gated flows).</summary>
    public bool FireEvents { get; init; }
    public bool AutoBypass { get; init; } = true;
    /// <summary>
    /// When true, phase-2 / single-shot traces may embed the <c>__trowser_exec</c> oracle (active proof).
    /// Default false — reach maps and sink taint still run; use true or <c>safetyMode: aggressive</c> for execution proof.
    /// </summary>
    public bool ConfirmExecution { get; init; }
    /// <summary>Canary id embedded via <see cref="TraceInputPayloadPrep"/> when <see cref="ConfirmExecution"/> is on.</summary>
    internal string? ExecCanary { get; init; }
    internal bool SkipExecCanary { get; init; }
    internal bool ReachPhaseOnly { get; init; }
    public int MaxBypassAttempts { get; init; } = 10;
    /// <summary>Additional query parameters merged into url-query traces (e.g. gated redirect flags).</summary>
    public Dictionary<string, string>? ExtraQuery { get; init; }

    public static string SourceTypeName(TraceSourceType source) => source switch
    {
        TraceSourceType.Form => "form",
        TraceSourceType.UrlQuery => "url-query",
        TraceSourceType.UrlHash => "url-hash",
        TraceSourceType.UrlPath => "url-path",
        TraceSourceType.WindowName => "window-name",
        TraceSourceType.Storage => "storage",
        TraceSourceType.PostMessage => "post-message",
        TraceSourceType.Referrer => "referrer",
        _ => "unknown"
    };

    public static bool IsUrlSource(TraceSourceType source) =>
        source is TraceSourceType.UrlQuery or TraceSourceType.UrlHash or TraceSourceType.UrlPath;

    public static bool IsClientRuntimeSource(TraceSourceType source) =>
        source is TraceSourceType.WindowName or TraceSourceType.Storage
            or TraceSourceType.PostMessage or TraceSourceType.Referrer;

    public static bool IsUrlSource(string sourceTypeName) =>
        sourceTypeName.StartsWith("url-", StringComparison.OrdinalIgnoreCase);
}
