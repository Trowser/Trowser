using System.Diagnostics;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Standalone SSTI scan — discovers injectable parameters from network log or accepts explicit template.
/// </summary>
public sealed class SstiScanRunner
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public SstiScanRunner(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class SstiScanOptions
    {
        public string? UrlTemplate { get; set; }
        public string? Method { get; set; }
        public Dictionary<string, string>? Headers { get; set; }
        public string? BodyTemplate { get; set; }
        public string? ParamName { get; set; }
        public int MaxCandidates { get; set; } = 10;
        public int TimeoutMs { get; set; } = 15000;
        /// <summary>quick | standard | deep</summary>
        public string? Depth { get; set; }
    }

    public sealed class SstiScanBatchResult
    {
        public string Message { get; init; } = "";
        public string Depth { get; init; } = SecurityScanDepth.Standard;
        public int CandidatesProbed { get; init; }
        public int ElapsedMs { get; init; }
        public List<SstiScanEntry> Entries { get; init; } = [];
        public List<UnifiedSecurityFinding> Findings { get; init; } = [];
        public bool HasFindings => Findings.Count > 0 || Entries.Any(e => e.HasFindings);

        public SecurityScanResult ToSecurityScanResult() => new()
        {
            Message = Message,
            Depth = Depth,
            CandidatesProbed = CandidatesProbed,
            ElapsedMs = ElapsedMs,
            Findings = Findings,
            Details = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["entries"] = Entries.Select(e => new
                {
                    e.Url,
                    e.Method,
                    e.ParamName,
                    hasFindings = e.HasFindings,
                    rows = e.Result.Rows
                }).ToList()
            }
        };
    }

    public sealed class SstiScanEntry
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "";
        public string ParamName { get; init; } = "";
        public SstiScanner.SstiScanResult Result { get; init; } = new();
        public bool HasFindings => Result.HasFindings;
    }

    public async Task<SstiScanBatchResult> RunAsync(SstiScanOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running ssti-scan.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var points = BuildPoints(options, origin);
        if (points.Count == 0)
        {
            return new SstiScanBatchResult
            {
                Message = "No injectable parameter candidates found. Browse the app or pass request template with §INJECT§ marker.",
                ElapsedMs = (int)sw.ElapsedMilliseconds
            };
        }

        var depthProfile = InjectionScanDepth.Resolve(options.Depth, options.MaxCandidates);
        var entries = new List<SstiScanEntry>();
        var timeout = options.TimeoutMs > 0 ? options.TimeoutMs : 15000;
        _log($"SstiScan: {points.Count} candidate(s) (depth={depthProfile.Name})", "#888888");

        foreach (var pt in points.Take(depthProfile.MaxCandidates))
        {
            ct.ThrowIfCancellationRequested();
            var urlTemplate = pt.UrlTemplate ?? pt.Url;
            if (RequestMarkerSubstitute.ListMarkers(urlTemplate, pt.BodyTemplate, pt.Headers).Count == 0)
                continue;

            try
            {
                var result = await SstiScanner.RunAsync(
                    _ctx, urlTemplate, pt.Method, pt.Headers, pt.BodyTemplate,
                    pt.ParamName, timeout, ct, depthProfile.Name);

                if (result.HasFindings)
                    _log($"  FLAG SSTI: {pt.ParamName} on {pt.Url}", "#F44747");

                entries.Add(new SstiScanEntry
                {
                    Url = pt.Url,
                    Method = pt.Method,
                    ParamName = pt.ParamName,
                    Result = result
                });
            }
            catch (Exception ex)
            {
                _log($"  SSTI skip {pt.Url}: {ex.Message}", "#888888");
            }
        }

        var allFindings = entries.SelectMany(e => e.Result.Findings).ToList();
        return new SstiScanBatchResult
        {
            Message = allFindings.Count > 0
                ? $"{allFindings.Count} SSTI finding(s) across {entries.Count} candidate(s)."
                : $"No SSTI indicators across {entries.Count} candidate(s).",
            Depth = depthProfile.Name,
            CandidatesProbed = entries.Count,
            Entries = entries,
            Findings = allFindings,
            ElapsedMs = (int)sw.ElapsedMilliseconds
        };
    }

    private List<InjectionPointDiscovery.InjectionPoint> BuildPoints(SstiScanOptions options, string origin)
    {
        if (!string.IsNullOrWhiteSpace(options.UrlTemplate))
        {
            var urlTemplate = options.UrlTemplate;
            var markers = RequestMarkerSubstitute.ListMarkers(urlTemplate, options.BodyTemplate, options.Headers);
            if (markers.Count == 0)
                throw new ArgumentException(InjectionRequestErrors.WithRequestExample(
                    "urlTemplate/body/headers must contain §INJECT§ or {{INJECT}} marker."));

            return
            [
                new InjectionPointDiscovery.InjectionPoint
                {
                    Url = urlTemplate,
                    Method = (options.Method ?? "GET").ToUpperInvariant(),
                    ParamName = options.ParamName ?? markers[0],
                    UrlTemplate = urlTemplate,
                    BodyTemplate = options.BodyTemplate,
                    Headers = options.Headers,
                    Source = "explicit"
                }
            ];
        }

        var max = options.MaxCandidates > 0 ? options.MaxCandidates : 10;
        return InjectionPointDiscovery.DiscoverFromNetwork(_ctx, origin, max, prioritizeCmdParams: false);
    }
}
