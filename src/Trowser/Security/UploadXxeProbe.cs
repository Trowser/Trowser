using System.Diagnostics;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// XXE via file-upload: crafted XML/SVG uploads looking for file disclosure, entity errors, or corroborated DoS timing.
/// Inspired by OWASP WSTG-INPV-07 and the OWASP XXE Prevention Cheat Sheet; also influenced by pentest-ai <c>web.xxe_upload</c>.
/// DoS timing alone is not sufficient — requires status/body corroboration. Mutates upload sinks under active mode.
/// </summary>
public static class UploadXxeProbe
{
    private const double DosDeltaS = 5.0;

    public sealed class UploadXxeOptions
    {
        public int MaxCandidates { get; set; } = 10;
        public int TimeoutMs { get; set; } = 12000;
        public int DosTimeoutMs { get; set; } = 15000;
        public bool IncludeBrowserCookies { get; set; } = true;
        public IReadOnlyList<string>? Urls { get; set; }
    }

    public sealed class UploadXxeFinding
    {
        public string Category { get; init; } = "xxe-upload";
        public string Severity { get; init; } = "high";
        public string Signal { get; init; } = "";
        public string Url { get; init; } = "";
        public string Shape { get; init; } = "";
        public int Status { get; init; }
        public string Detail { get; init; } = "";
    }

    public sealed class UploadXxeResult
    {
        public string Message { get; init; } = "";
        public int CandidatesProbed { get; init; }
        public int ProbesSent { get; init; }
        public int ElapsedMs { get; init; }
        public List<UploadXxeFinding> Findings { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;
    }

    public static async Task<UploadXxeResult> RunAsync(
        AutomationContext ctx,
        UploadXxeOptions options,
        Action<string, string>? log = null,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running upload XXE probe.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var urls = options.Urls?.ToList()
                   ?? UploadProbeSupport.DiscoverUploadEndpoints(ctx, origin, options.MaxCandidates);
        foreach (var p in UploadProbeSupport.AlwaysProbedXxePaths)
        {
            var u = origin.TrimEnd('/') + UploadProbeSupport.NormalizePathForProbe(p);
            if (!urls.Contains(u, StringComparer.OrdinalIgnoreCase))
                urls.Add(u);
        }

        urls = urls.Distinct(StringComparer.OrdinalIgnoreCase).Take(options.MaxCandidates).ToList();
        var findings = new List<UploadXxeFinding>();
        var probesSent = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        log?.Invoke($"UploadXxe: {urls.Count} candidate(s)", "#888888");

        foreach (var url in urls)
        {
            ct.ThrowIfCancellationRequested();
            foreach (var shape in new[] { "multipart", "raw" })
            {
                var baseline = await PostXmlAsync(ctx, url, UploadProbeSupport.BaselineXml, shape,
                    options.TimeoutMs, options.IncludeBrowserCookies, ct);
                probesSent++;
                if (baseline.Status is 0 or 404) continue;

                var attack = await PostXmlAsync(ctx, url, UploadProbeSupport.XxePasswdPayload, shape,
                    options.TimeoutMs, options.IncludeBrowserCookies, ct);
                probesSent++;
                var classified = Classify(attack.Status, attack.Body, attack.ElapsedSeconds, baseline.ElapsedSeconds);
                if (classified != null)
                {
                    var key = $"{url}|{classified.Value.variant}|{shape}";
                    if (seen.Add(key))
                    {
                        findings.Add(MakeFinding(url, classified.Value.severity, classified.Value.variant, shape,
                            attack.Status, classified.Value.detail, attack.Body));
                        log?.Invoke($"  FLAG XXE {classified.Value.variant}: {url} ({shape})", "#F44747");
                    }
                    if (classified.Value.variant.StartsWith("file_disclosure", StringComparison.Ordinal))
                        continue;
                }

                var dos = await PostXmlAsync(ctx, url, UploadProbeSupport.XxeDosPayload, shape,
                    options.DosTimeoutMs, options.IncludeBrowserCookies, ct);
                probesSent++;
                var dosClass = Classify(dos.Status, dos.Body, dos.ElapsedSeconds, baseline.ElapsedSeconds);
                if (dosClass != null)
                {
                    var key = $"{url}|{dosClass.Value.variant}|{shape}";
                    if (seen.Add(key))
                    {
                        findings.Add(MakeFinding(url, dosClass.Value.severity, dosClass.Value.variant, shape,
                            dos.Status, dosClass.Value.detail, dos.Body));
                        log?.Invoke($"  FLAG XXE {dosClass.Value.variant}: {url} ({shape})", "#F44747");
                    }
                }
            }
        }

        return new UploadXxeResult
        {
            Message = findings.Count > 0
                ? $"{findings.Count} upload XXE finding(s) across {urls.Count} endpoint(s)."
                : $"No upload XXE indicators across {urls.Count} endpoint(s), {probesSent} probe(s).",
            CandidatesProbed = urls.Count,
            ProbesSent = probesSent,
            Findings = findings,
            ElapsedMs = (int)sw.ElapsedMilliseconds
        };
    }

    private sealed record XmlPostResult(int Status, string Body, double ElapsedSeconds);

    private static async Task<XmlPostResult> PostXmlAsync(
        AutomationContext ctx,
        string url,
        byte[] xmlBytes,
        string shape,
        int timeoutMs,
        bool includeCookies,
        CancellationToken ct)
    {
        if (shape == "multipart")
        {
            foreach (var field in UploadProbeSupport.MultipartFieldNames)
            {
                var body = UploadProbeSupport.BuildMultipart(
                    xmlBytes, field, "payload.xml", "application/xml", UploadProbeSupport.XxeBoundary);
                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Content-Type"] = $"multipart/form-data; boundary={UploadProbeSupport.XxeBoundary}"
                };
                var timed = await SecurityProbeHttp.FetchTimedRawAsync(
                    ctx, url, "POST", headers, body, timeoutMs, includeCookies, ct);
                if (UploadProbeSupport.IsAccepted(timed.Result.Status))
                    return new XmlPostResult(timed.Result.Status, timed.Result.Body, timed.ElapsedSeconds);
            }

            var fallbackBody = UploadProbeSupport.BuildMultipart(
                xmlBytes, "file", "payload.xml", "application/xml", UploadProbeSupport.XxeBoundary);
            var fallbackHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Content-Type"] = $"multipart/form-data; boundary={UploadProbeSupport.XxeBoundary}"
            };
            var fallback = await SecurityProbeHttp.FetchTimedRawAsync(
                ctx, url, "POST", fallbackHeaders, fallbackBody, timeoutMs, includeCookies, ct);
            return new XmlPostResult(fallback.Result.Status, fallback.Result.Body, fallback.ElapsedSeconds);
        }

        var rawHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "application/xml"
        };
        var raw = await SecurityProbeHttp.FetchTimedRawAsync(
            ctx, url, "POST", rawHeaders, xmlBytes, timeoutMs, includeCookies, ct);
        return new XmlPostResult(raw.Result.Status, raw.Result.Body, raw.ElapsedSeconds);
    }

    private static (string severity, string variant, string detail)? Classify(
        int status, string body, double elapsed, double baselineElapsed)
    {
        if (LooksLikePasswdDisclosure(body))
            return ("critical", "file_disclosure_passwd", "Linux /etc/passwd disclosed (multiple passwd lines including root:x:0:).");
        if (LooksLikeSystemIniDisclosure(body))
            return ("critical", "file_disclosure_systemini", "Windows system.ini disclosed in response.");

        var bodyLc = body.ToLowerInvariant();
        var entityOrDoctypeError = bodyLc.Contains("doctype", StringComparison.Ordinal)
            || bodyLc.Contains("entity", StringComparison.Ordinal);
        var timingHit = elapsed - baselineElapsed >= DosDeltaS;
        if (timingHit && (status >= 500 || entityOrDoctypeError))
            return ("high", "billion_laughs_dos",
                $"Entity expansion DoS corroborated: attack {elapsed:F2}s vs baseline {baselineElapsed:F2}s, status={status}.");
        if (timingHit)
            return ("medium", "billion_laughs_timing",
                $"Uncorroborated timing delay only: attack {elapsed:F2}s vs baseline {baselineElapsed:F2}s (no 5xx/entity error).");

        if (status == 500 && bodyLc.Contains("doctype") && bodyLc.Contains("entity"))
            return ("medium", "parser_reachable", "XML parser reachable; DOCTYPE/entity error in 500 response.");
        return null;
    }

    /// <summary>True when body looks like a real /etc/passwd dump (not HTML-escaped XXE payload echo).</summary>
    internal static bool LooksLikePasswdDisclosure(string body)
    {
        if (string.IsNullOrEmpty(body) || !body.Contains("root:x:0:", StringComparison.Ordinal))
            return false;

        // Prefer unescaped text; HTML-escaped error pages that echo the XXE payload alone are FPs.
        var text = System.Net.WebUtility.HtmlDecode(body);
        var matches = System.Text.RegularExpressions.Regex.Matches(
            text,
            @"(?:^|[\r\n])([a-z_][a-z0-9_-]{0,31}:[^:\r\n]*:\d+:\d+:[^\r\n]*)",
            System.Text.RegularExpressions.RegexOptions.Multiline | System.Text.RegularExpressions.RegexOptions.IgnoreCase,
            matchTimeout: TimeSpan.FromSeconds(1));
        if (matches.Count < 2)
            return false;

        // At least one line should look like a real shell account, not XML residue.
        foreach (System.Text.RegularExpressions.Match m in matches)
        {
            var line = m.Groups[1].Value;
            if (line.Contains("root:x:0:", StringComparison.Ordinal)
                && (line.Contains("/bin/", StringComparison.Ordinal) || line.Contains("/usr/", StringComparison.Ordinal)
                    || line.EndsWith(":", StringComparison.Ordinal) || line.Contains(":/", StringComparison.Ordinal)))
                return true;
        }

        return matches.Count >= 3;
    }

    private static bool LooksLikeSystemIniDisclosure(string body)
    {
        if (string.IsNullOrEmpty(body)) return false;
        var text = System.Net.WebUtility.HtmlDecode(body);
        var hasBoot = text.Contains("[boot loader]", StringComparison.OrdinalIgnoreCase);
        var hasMail = text.Contains("[mail]", StringComparison.OrdinalIgnoreCase);
        if (!hasBoot && !hasMail) return false;
        // Require both classic system.ini sections — a single bracket token in HTML noise is weak.
        return hasBoot && hasMail;
    }

    private static UploadXxeFinding MakeFinding(
        string url, string severity, string variant, string shape, int status, string detail, string evidence) =>
        new()
        {
            Category = "xxe-upload",
            Severity = severity,
            Signal = variant,
            Url = url,
            Shape = shape,
            Status = status,
            Detail = $"{detail} Evidence: {Truncate(evidence, 200)}"
        };

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
