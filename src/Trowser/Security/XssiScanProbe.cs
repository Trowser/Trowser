using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Cross-Site Script Inclusion (JSONP / classic script / missing nosniff) assessment from network log + optional URLs.
/// </summary>
public sealed class XssiScanProbe
{
    private static readonly Regex JsonpCallback = new(
        @"[?&](?:callback|jsonp|cb|jsoncallback|_callback|CORS)\=",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly AutomationContext _ctx;

    public XssiScanProbe(AutomationContext ctx) => _ctx = ctx;

    public sealed class XssiOptions
    {
        public IReadOnlyList<string>? Urls { get; init; }
        public int MaxUrls { get; init; } = 12;
        public int TimeoutMs { get; init; } = 12_000;
        public bool IncludeNetworkLog { get; init; } = true;
    }

    public sealed class XssiScanResult
    {
        public string Message { get; init; } = "";
        public List<UnifiedSecurityFinding> Findings { get; init; } = [];
        public int UrlsProbed { get; init; }
        public List<string> NextActions { get; init; } = [];

        public object ToApiResponse() => new
        {
            message = Message,
            urlsProbed = UrlsProbed,
            findings = Findings.Select(SecurityScanResult.ToApiFinding).ToList(),
            nextActions = NextActions
        };
    }

    public async Task<XssiScanResult> RunAsync(XssiOptions options, CancellationToken ct = default)
    {
        var pageUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(pageUrl) || !Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri))
            throw new InvalidOperationException("Navigate to a page before running XSSI scan.");

        var origin = pageUri.GetLeftPart(UriPartial.Authority);
        var urls = CollectUrls(options, origin);
        var findings = new List<UnifiedSecurityFinding>();
        var probed = 0;

        foreach (var url in urls)
        {
            ct.ThrowIfCancellationRequested();
            probed++;
            var f = await ProbeUrlAsync(url, options.TimeoutMs, ct);
            if (f != null)
                findings.Add(f);
        }

        var next = new List<string>();
        if (findings.Count > 0)
        {
            next.Add("POST /api/security/headers with urls[] for each flagged script/JSON endpoint");
            next.Add(SecurityNextActions.ClientSurface);
        }

        return new XssiScanResult
        {
            Message = findings.Count > 0
                ? $"{findings.Count} XSSI-related issue(s) across {probed} URL(s)."
                : $"No XSSI indicators across {probed} URL(s).",
            Findings = findings,
            UrlsProbed = probed,
            NextActions = next
        };
    }

    private List<string> CollectUrls(XssiOptions options, string documentOrigin)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<string>();

        void Add(string? u)
        {
            if (string.IsNullOrWhiteSpace(u)) return;
            if (!Uri.TryCreate(u, UriKind.Absolute, out _)) return;
            if (seen.Add(u))
                list.Add(u);
        }

        if (options.Urls is { Count: > 0 })
        {
            foreach (var u in options.Urls)
                Add(u);
            return list.Take(Math.Clamp(options.MaxUrls, 1, 30)).ToList();
        }

        if (options.IncludeNetworkLog)
        {
            foreach (var e in _ctx.Network.Entries)
            {
                if (e.IsTrowserGenerated) continue;
                if (e.StatusCode is < 200 or >= 400) continue;
                var ct = e.ContentType;
                var isScript = e.ResourceType.Equals("Script", StringComparison.OrdinalIgnoreCase)
                               || ct.Contains("javascript", StringComparison.OrdinalIgnoreCase)
                               || ct.Contains("json", StringComparison.OrdinalIgnoreCase);
                var jsonpHint = JsonpCallback.IsMatch(e.Url);
                if (isScript || jsonpHint)
                    Add(e.Url);
            }
        }

        return list.Take(Math.Clamp(options.MaxUrls, 1, 30)).ToList();
    }

    private async Task<UnifiedSecurityFinding?> ProbeUrlAsync(string url, int timeoutMs, CancellationToken ct)
    {
        var resp = await SecurityProbeHttp.FetchAsync(
            _ctx, url, "GET", null, null, timeoutMs, includeBrowserCookies: true, ct);
        if (resp.Status == 0)
            return null;

        var body = resp.Body ?? "";
        var contentType = SecurityProbeHttp.GetResponseHeader(resp, "Content-Type") ?? "";
        var nosniff = SecurityProbeHttp.GetResponseHeader(resp, "X-Content-Type-Options") ?? "";
        if (!XssiBodySignals.IsIncludable(contentType, body, nosniff, url, out var shape))
            return null;

        var missingNosniff = !XssiBodySignals.HasNosniff(nosniff);
        var evidence = shape switch
        {
            "array" => "JavaScript response body is an array"
                       + (missingNosniff ? " and X-Content-Type-Options: nosniff is absent." : "."),
            "assignment" => "JavaScript response assigns data to a global"
                            + (missingNosniff ? " and X-Content-Type-Options: nosniff is absent." : "."),
            "jsonp" or "callback" => "Response is a callback wrapper"
                                     + (XssiBodySignals.CallbackName(url) is { Length: > 0 } name
                                         ? $" and '{name}' reflects into the body."
                                         : "."),
            _ => "JSON array is served without X-Content-Type-Options: nosniff."
        };
        var jsonp = shape is "jsonp" or "callback";
        var severity = shape is "array" or "json-array" or "callback" or "jsonp" ? "high" : "medium";

        return UnifiedSecurityFinding.Create(
            category: "xssi",
            title: jsonp ? "JSONP / script-includable endpoint" : "Script-includable data response (XSSI)",
            severity: severity,
            confidence: SecurityConfidence.Likely,
            endpoint: url,
            method: "GET",
            evidence: evidence,
            proofHint: "Confirm with a cross-origin script include. Arrays and assignments served as text/javascript are readable without a callback parameter.",
            nextActions: ["POST /api/security/headers", "POST /api/security/xssi-scan"],
            tier: SecurityFindingTier.Hygiene);
    }
}
