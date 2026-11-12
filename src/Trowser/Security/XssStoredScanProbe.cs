using System.Diagnostics;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Stored XSS probe — POST comment/message fields, then GET readback for unencoded payload persistence.
/// </summary>
public sealed class XssStoredScanProbe
{
    public const string Marker = "trowser-xss-stored";
    public const string DefaultPayload = "<iframe src=\"javascript:alert('" + Marker + "')\"></iframe>";

    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public XssStoredScanProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class XssStoredScanOptions
    {
        public int MaxCandidates { get; set; } = 8;
        public int TimeoutMs { get; set; } = 15000;
    }

    public sealed class XssStoredFinding
    {
        public string Category { get; init; } = "xss-stored";
        public string Severity { get; init; } = "high";
        public string PostUrl { get; init; } = "";
        public string ReadUrl { get; init; } = "";
        public string FieldName { get; init; } = "";
        public string Payload { get; init; } = DefaultPayload;
        public string Detail { get; init; } = "";
        public string Evidence { get; init; } = "";
        public string Source { get; init; } = "scaffold";
    }

    public sealed class XssStoredScanResult
    {
        public string Message { get; init; } = "";
        public int CandidatesProbed { get; init; }
        public int ElapsedMs { get; init; }
        public List<XssStoredFinding> Findings { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;
    }

    public static readonly string[] DefaultPostPaths =
    [
        "/api/Feedbacks",
        "/api/ProductReviews",
        "/api/feedback",
        "/api/reviews",
        "/api/comments",
        "/api/messages"
    ];

    public static readonly string[] TextFields =
    [
        "comment", "message", "text", "body", "content", "review", "feedback", "description"
    ];

    public static readonly string[] ReadPaths =
    [
        "/api/Feedbacks",
        "/api/ProductReviews",
        "/rest/products/search?q=" + Marker,
        "/api/feedback",
        "/api/reviews"
    ];

    public async Task<XssStoredScanResult> RunAsync(
        XssStoredScanOptions options,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running xss-stored-scan.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var findings = new List<XssStoredFinding>();
        var probed = 0;

        foreach (var path in DefaultPostPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (probed >= options.MaxCandidates) break;

            var postUrl = origin.TrimEnd('/') + path;
            foreach (var field in TextFields)
            {
                ct.ThrowIfCancellationRequested();
                probed++;
                var body = JsonSerializer.Serialize(new Dictionary<string, string> { [field] = DefaultPayload });
                var headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" };
                var postJson = await _ctx.Fetch(postUrl, "POST", headers, body, options.TimeoutMs);
                var (postStatus, _, _) = HttpSecurityProbes.ParseFetchJson(postJson);
                if (postStatus is < 200 or >= 400) continue;

                foreach (var readPath in ReadPaths)
                {
                    ct.ThrowIfCancellationRequested();
                    var readUrl = readPath.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                        ? readPath
                        : origin.TrimEnd('/') + readPath;
                    var readJson = await _ctx.Fetch(readUrl, "GET", null, null, options.TimeoutMs);
                    var (_, readText, _) = HttpSecurityProbes.ParseFetchJson(readJson);
                    if (string.IsNullOrEmpty(readText)) continue;

                    foreach (var variant in XssReflectionAnalyzer.GetPayloadReflectionVariants(DefaultPayload))
                    {
                        if (!readText.Contains(variant, StringComparison.OrdinalIgnoreCase)) continue;
                        var analysis = XssReflectionAnalyzer.AnalyzeReflection(
                            readText, DefaultPayload, variant,
                            encoded: !string.Equals(variant, DefaultPayload, StringComparison.Ordinal),
                            contentType: null);
                        if (!analysis.Dangerous && !readText.Contains(Marker, StringComparison.OrdinalIgnoreCase))
                            continue;

                        _log($"  FLAG stored XSS: {field} via {postUrl}", "#F44747");
                        findings.Add(new XssStoredFinding
                        {
                            PostUrl = postUrl,
                            ReadUrl = readUrl,
                            FieldName = field,
                            Detail = analysis.Reason ?? "Stored payload persisted in readback response.",
                            Evidence = analysis.Surrounding
                        });
                        goto nextPostPath;
                    }
                }
            }

            nextPostPath: ;
        }

        sw.Stop();
        return new XssStoredScanResult
        {
            Message = findings.Count > 0
                ? $"{findings.Count} stored XSS finding(s)."
                : "No stored XSS indicators.",
            CandidatesProbed = probed,
            Findings = findings,
            ElapsedMs = (int)sw.ElapsedMilliseconds
        };
    }
}
