using System.Diagnostics;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// File upload validation probes (oversize, wrong type, polyglot, SPA-shell sinks) with persistence-oriented oracles.
/// Inspired by OWASP WSTG file-upload testing; also influenced by pentest-ai <c>web.file_upload_validation</c>.
/// Mutates upload endpoints under active mode; optional XXE child probe.
/// </summary>
public sealed class FileUploadScanProbe
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public FileUploadScanProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class FileUploadScanOptions
    {
        public int MaxCandidates { get; set; } = 10;
        public int TimeoutMs { get; set; } = 12000;
        public bool IncludeXxe { get; set; } = true;
        public bool IncludeBrowserCookies { get; set; } = true;
        public bool TryDomReplayWhenSpaShell { get; set; }
        public IReadOnlyList<string>? Urls { get; set; }
    }

    public sealed class FileUploadFinding
    {
        public string Category { get; init; } = "";
        public string Severity { get; init; } = "medium";
        public string Signal { get; init; } = "";
        public string Url { get; init; } = "";
        public string Variant { get; init; } = "";
        public int Status { get; init; }
        public string Detail { get; init; } = "";
    }

    public sealed class FileUploadScanResult
    {
        public string Message { get; init; } = "";
        public int CandidatesProbed { get; init; }
        public int ProbesSent { get; init; }
        public int ElapsedMs { get; init; }
        public List<FileUploadFinding> Findings { get; init; } = [];
        public List<UploadXxeProbe.UploadXxeFinding> XxeFindings { get; init; } = [];
        public bool HasFindings => Findings.Count > 0 || XxeFindings.Count > 0;
    }

    public async Task<FileUploadScanResult> RunAsync(FileUploadScanOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running file-upload-scan.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var urls = options.Urls?.ToList()
                   ?? UploadProbeSupport.DiscoverUploadEndpoints(_ctx, origin, options.MaxCandidates);
        urls = urls.Distinct(StringComparer.OrdinalIgnoreCase).Take(options.MaxCandidates).ToList();

        var spaShell = await UploadProbeSupport.CaptureSpaShellFingerprintAsync(_ctx, origin, options.TimeoutMs, ct);
        var findings = new List<FileUploadFinding>();
        var probesSent = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        _log($"FileUploadScan: {urls.Count} candidate(s)", "#888888");

        foreach (var url in urls)
        {
            ct.ThrowIfCancellationRequested();

            if (UploadProbeSupport.LooksLikeNonUploadSink(url))
            {
                _log($"  skip non-upload sink: {url}", "#888888");
                continue;
            }

            var observedMultipart = NetworkSawMultipart(url);
            var baseline = await PostMultipartAsync(url, "baseline.pdf", "application/pdf",
                UploadProbeSupport.BaselinePdf, options, ct);
            probesSent++;
            if (baseline.Status is 0 or 404) continue;

            if (UploadProbeSupport.LooksLikeSpaShell(baseline.Body, spaShell))
            {
                if (options.TryDomReplayWhenSpaShell)
                {
                    var domNote = await TryDomFileInputHintAsync(options);
                    if (domNote != null)
                    {
                        findings.Add(new FileUploadFinding
                        {
                            Category = "file-upload-spa-shell",
                            Severity = "info",
                            Signal = "spa-shell-dedup",
                            Url = url,
                            Variant = "dom-replay-suggested",
                            Status = baseline.Status,
                            Detail = domNote
                        });
                    }
                }
                continue;
            }

            var oversize = await PostMultipartAsync(url, "oversized.pdf", "application/pdf",
                UploadProbeSupport.OversizedPdf, options, ct);
            probesSent++;
            if (TryRecordUploadFinding(findings, seen, url, "file-upload-oversize", "oversized",
                    oversize.Status, oversize.Body, observedMultipart,
                    preferSeverity: "medium",
                    detailAccepted: "Server accepted 200 KB upload; size validation missing.",
                    detailStatusOnly: "HTTP accepted 200 KB multipart body but no upload persistence oracle — treat as hygiene, not confirmed bypass."))
                _log($"  FLAG oversize upload: {url}", "#F44747");

            var exe = await PostMultipartAsync(url, "exploit.exe", "application/octet-stream",
                UploadProbeSupport.ExePayload, options, ct);
            probesSent++;
            if (TryRecordUploadFinding(findings, seen, url, "file-upload-wrong-type", "wrong_type",
                    exe.Status, exe.Body, observedMultipart,
                    preferSeverity: "high",
                    detailAccepted: "Server accepted .exe upload with persistence indicators; extension/type allowlist missing.",
                    detailStatusOnly: "HTTP accepted .exe multipart body without persistence/readback proof — not confirmed upload RCE."))
                _log($"  FLAG wrong-type upload: {url}", "#F44747");

            var polyglot = await PostMultipartAsync(url, "polyglot.jpg", "image/jpeg",
                UploadProbeSupport.PolyglotJpegPhp, options, ct);
            probesSent++;
            // Persistence alone is unrestricted upload (HIGH). CRITICAL requires an execution/readback oracle.
            var polyglotExecuted = await TryPolyglotExecutionOracleAsync(
                url, polyglot.Body, options, ct);
            if (TryRecordUploadFinding(findings, seen, url, "file-upload-polyglot", "polyglot",
                    polyglot.Status, polyglot.Body, observedMultipart,
                    preferSeverity: polyglotExecuted ? "critical" : "high",
                    detailAccepted: polyglotExecuted
                        ? "Server accepted JPEG/PHP polyglot and execution/readback oracle confirmed (polyglot marker served)."
                        : "Server accepted JPEG/PHP polyglot with persistence indicators — unrestricted upload. RCE not confirmed (no execution/readback oracle).",
                    detailStatusOnly: "HTTP accepted polyglot multipart body without stored-readback proof — demoted (not confirmed upload RCE)."))
                _log($"  FLAG polyglot upload ({(polyglotExecuted ? "RCE oracle" : "persist only")}): {url}", "#F44747");
        }

        List<UploadXxeProbe.UploadXxeFinding> xxeFindings = [];
        if (options.IncludeXxe)
        {
            var xxe = await UploadXxeProbe.RunAsync(_ctx, new UploadXxeProbe.UploadXxeOptions
            {
                MaxCandidates = options.MaxCandidates,
                TimeoutMs = options.TimeoutMs,
                IncludeBrowserCookies = options.IncludeBrowserCookies,
                Urls = urls
            }, _log, ct);
            xxeFindings = xxe.Findings;
            probesSent += xxe.ProbesSent;
        }

        return new FileUploadScanResult
        {
            Message = findings.Count + xxeFindings.Count > 0
                ? $"{findings.Count} upload validation + {xxeFindings.Count} XXE finding(s) across {urls.Count} endpoint(s)."
                : $"No upload validation issues across {urls.Count} endpoint(s), {probesSent} probe(s).",
            CandidatesProbed = urls.Count,
            ProbesSent = probesSent,
            Findings = findings,
            XxeFindings = xxeFindings,
            ElapsedMs = (int)sw.ElapsedMilliseconds
        };
    }

    private async Task<(int Status, string Body)> PostMultipartAsync(
        string url,
        string filename,
        string contentType,
        byte[] payload,
        FileUploadScanOptions options,
        CancellationToken ct)
    {
        foreach (var field in UploadProbeSupport.MultipartFieldNames)
        {
            var body = UploadProbeSupport.BuildMultipart(payload, field, filename, contentType);
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Content-Type"] = $"multipart/form-data; boundary={UploadProbeSupport.DefaultBoundary}"
            };
            var fetch = await SecurityProbeHttp.FetchRawAsync(
                _ctx, url, "POST", headers, body, options.TimeoutMs, options.IncludeBrowserCookies, ct);
            if (UploadProbeSupport.IsAccepted(fetch.Status))
                return (fetch.Status, fetch.Body);
        }

        var fallback = UploadProbeSupport.BuildMultipart(payload, "file", filename, contentType);
        var fallbackHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = $"multipart/form-data; boundary={UploadProbeSupport.DefaultBoundary}"
        };
        var last = await SecurityProbeHttp.FetchRawAsync(
            _ctx, url, "POST", fallbackHeaders, fallback, options.TimeoutMs, options.IncludeBrowserCookies, ct);
        return (last.Status, last.Body);
    }

    private static Task<string?> TryDomFileInputHintAsync(FileUploadScanOptions options)
    {
        _ = options;
        return Task.FromResult<string?>(
            "Multipart POST returned SPA shell; navigate to the upload form and use browser_upload with a base64 polyglot payload.");
    }

    private bool NetworkSawMultipart(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var target))
            return false;
        var path = target.GetLeftPart(UriPartial.Path);
        foreach (var entry in _ctx.Network.Entries)
        {
            if (!entry.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Path), path, StringComparison.OrdinalIgnoreCase))
                continue;
            var ct = entry.RequestHeaders.TryGetValue("Content-Type", out var ctVal) ? ctVal
                : entry.RequestHeaders.GetValueOrDefault("content-type") ?? "";
            if (ct.Contains("multipart", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static bool TryRecordUploadFinding(
        List<FileUploadFinding> findings,
        HashSet<string> seen,
        string url,
        string category,
        string variant,
        int status,
        string body,
        bool observedMultipart,
        string preferSeverity,
        string detailAccepted,
        string detailStatusOnly)
    {
        if (!UploadProbeSupport.IsAccepted(status) || !seen.Add($"{url}|{variant}"))
            return false;

        var persistent = UploadProbeSupport.LooksLikeUploadPersistence(body);
        var eligible = UploadProbeSupport.IsUploadFindingEligible(url, status, body, observedMultipart);
        if (!eligible && !persistent)
        {
            // Status-only accept on a plausible upload path → info/hygiene, never CRITICAL/HIGH.
            findings.Add(MakeFinding(category, "info", variant + "-status-only", url, detailStatusOnly, status));
            return true;
        }

        var severity = persistent ? preferSeverity : DowngradeWithoutPersistence(preferSeverity);
        var detail = persistent ? detailAccepted : detailStatusOnly;
        findings.Add(MakeFinding(category, severity, variant, url, detail, status));
        return severity is "critical" or "high" or "medium";
    }

    private static string DowngradeWithoutPersistence(string severity) => severity switch
    {
        "critical" => "medium",
        "high" => "low",
        _ => "info"
    };

    private async Task<bool> TryPolyglotExecutionOracleAsync(
        string uploadUrl, string responseBody, FileUploadScanOptions options, CancellationToken ct)
    {
        foreach (var candidate in UploadProbeSupport.ExtractLikelyUploadUrls(uploadUrl, responseBody).Take(4))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var fetch = await SecurityProbeHttp.FetchAsync(
                    _ctx, candidate, "GET", null, null, options.TimeoutMs,
                    includeBrowserCookies: options.IncludeBrowserCookies, ct);
                if (fetch.Status is < 200 or >= 400) continue;
                var body = fetch.Body ?? "";
                if (!body.Contains("trowser-polyglot", StringComparison.OrdinalIgnoreCase))
                    continue;

                fetch.ResponseHeaders.TryGetValue("Content-Type", out var ctHeader);
                ctHeader ??= "";
                // Served as image/octet-stream without HTML/PHP execution context → not RCE.
                if (ctHeader.Contains("image/", StringComparison.OrdinalIgnoreCase)
                    || ctHeader.Contains("octet-stream", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (ctHeader.Contains("text/html", StringComparison.OrdinalIgnoreCase)
                    || ctHeader.Contains("php", StringComparison.OrdinalIgnoreCase)
                    || ctHeader.Contains("x-httpd", StringComparison.OrdinalIgnoreCase)
                    || body.TrimStart().StartsWith('<'))
                    return true;
            }
            catch
            {
                /* best-effort oracle */
            }
        }

        return false;
    }

    private static FileUploadFinding MakeFinding(
        string category, string severity, string variant, string url, string detail, int status) =>
        new()
        {
            Category = category,
            Severity = severity,
            Signal = variant,
            Url = url,
            Variant = variant,
            Detail = detail,
            Status = status
        };
}
