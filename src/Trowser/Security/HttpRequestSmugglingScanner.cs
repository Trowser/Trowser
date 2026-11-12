using System.Diagnostics;
using System.Linq;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// HTTP Request Smuggling detection via raw TCP probing.
/// Inspired by PortSwigger HTTP request smuggling / CL.TE–TE.CL differential confirmation
/// (James Kettle) and RFC 9110 / 9112 framing rules.
/// Combines (1) timing probes on incomplete CL/TE framing, (2) PortSwigger-style
/// differential-response confirmation that prefixes a unique canary request onto the
/// next connection's request, and (3) TE obfuscation / CL-CL / header checks.
/// Act only on <c>confirmationMethod: differential-response</c> — timing, TE body
/// churn, duplicate CL, and proxy headers are architecture notes, not confirmed desync.
/// Does not implement HTTP/2 H2.CL/H2.TE, h2c, CL.0, or Request Smuggler mutation catalogs.
/// </summary>
public static class HttpRequestSmugglingScanner
{
    public const string VerdictConfirmed = "confirmed";
    public const string VerdictUnconfirmed = "unconfirmed-architecture";
    public const string VerdictClean = "clean";

    #region Result Types

    public sealed class SmugglingResult
    {
        /// <summary>confirmed | unconfirmed-architecture | clean</summary>
        public string Verdict { get; init; } = VerdictClean;
        public string Url { get; init; } = "";
        public long ElapsedMs { get; init; }
        public string Summary { get; init; } = "";
        public int ProbesRun { get; init; }
        public List<SmugglingFinding> Findings { get; init; } = [];
        public HeaderNormalizationResult HeaderNormalization { get; init; } = new();
        public InfrastructureInfo Infrastructure { get; init; } = new();

        public IEnumerable<SmugglingFinding> ConfirmedFindings =>
            Findings.Where(IsConfirmedDesync);

        public IEnumerable<SmugglingFinding> NoteFindings =>
            Findings.Where(f => !IsConfirmedDesync(f));

        public string Format()
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== HTTP Request Smuggling Scan ===");
            sb.AppendLine($"Verdict: {Verdict}");
            sb.AppendLine($"URL: {Url}");
            sb.AppendLine($"Probes: {ProbesRun} | Elapsed: {ElapsedMs}ms");
            sb.AppendLine($"Confirmed: {ConfirmedFindings.Count()} | Notes (not bugs): {NoteFindings.Count()}");
            sb.AppendLine();
            sb.AppendLine(Summary);
            sb.AppendLine();

            var confirmed = ConfirmedFindings.ToList();
            if (confirmed.Count > 0)
            {
                sb.AppendLine("--- Confirmed (act on these) ---");
                foreach (var f in confirmed)
                    AppendFindingBlock(sb, f);
            }

            var notes = NoteFindings.ToList();
            if (notes.Count > 0)
            {
                sb.AppendLine("--- Notes (not bugs) ---");
                sb.AppendLine("Timing stalls, duplicate Content-Length acceptance, HEADER hygiene, and TE obfuscation");
                sb.AppendLine("are architecture signals. Do not file these as request smuggling without differential 404.");
                sb.AppendLine();
                foreach (var f in notes)
                    AppendFindingBlock(sb, f);
            }

            if (Infrastructure.ProxyLikely || !string.IsNullOrEmpty(Infrastructure.HttpVersion))
            {
                sb.AppendLine("--- Infrastructure ---");
                sb.AppendLine($"HTTP version: {Infrastructure.HttpVersion}");
                if (!string.IsNullOrEmpty(Infrastructure.Alpn))
                    sb.AppendLine($"ALPN: {Infrastructure.Alpn}");
                sb.AppendLine($"Server: {Infrastructure.ServerHeader ?? "(not disclosed)"}");
                sb.AppendLine($"Proxy detected: {Infrastructure.ProxyLikely}");
                foreach (var ev in Infrastructure.ProxyEvidence)
                    sb.AppendLine($"  - {ev}");
                sb.AppendLine();
            }

            if (HeaderNormalization.ObfuscationsAccepted.Count > 0 || HeaderNormalization.ObfuscationsAcceptedRfcCompliant.Count > 0)
            {
                sb.AppendLine("--- TE Obfuscation ---");
                sb.AppendLine($"Accepted non-RFC / high-variance TE: {HeaderNormalization.ObfuscationsAccepted.Count}");
                foreach (var o in HeaderNormalization.ObfuscationsAccepted)
                    sb.AppendLine($"  - {o}");
                if (HeaderNormalization.ObfuscationsAcceptedRfcCompliant.Count > 0)
                {
                    sb.AppendLine($"RFC-compliant TE variants accepted (informational): {HeaderNormalization.ObfuscationsAcceptedRfcCompliant.Count}");
                    foreach (var o in HeaderNormalization.ObfuscationsAcceptedRfcCompliant)
                        sb.AppendLine($"  - {o}");
                }

                if (!string.IsNullOrEmpty(HeaderNormalization.RiskNote))
                    sb.AppendLine($"Note: {HeaderNormalization.RiskNote}");
                sb.AppendLine();
            }

            sb.AppendLine("====================================");
            return sb.ToString();
        }

        private static void AppendFindingBlock(StringBuilder sb, SmugglingFinding f)
        {
            sb.AppendLine($"[{f.Severity.ToUpperInvariant()}] {f.Technique} [{f.FindingCategory}] (confidence: {f.Confidence})" +
                (string.IsNullOrEmpty(f.ConfirmationMethod) ? "" : $", confirmation: {f.ConfirmationMethod}"));
            sb.AppendLine($"  {f.Description}");
            sb.AppendLine($"  Evidence: {f.Evidence}");
            sb.AppendLine($"  Remediation: {f.Remediation}");
            if (f.MitigatingFactors.Count > 0)
                sb.AppendLine($"  Mitigating factors: {string.Join("; ", f.MitigatingFactors)}");
            AppendRawHttpReproduction(sb, f);
            sb.AppendLine();
        }
    }

    public sealed class SmugglingFinding
    {
        public string Technique { get; init; } = "";
        public string Severity { get; init; } = "";
        public string Confidence { get; init; } = "";
        public string Evidence { get; init; } = "";
        public string Description { get; init; } = "";
        public string Remediation { get; init; } = "";
        /// <summary>vulnerability | observation | informational</summary>
        public string FindingCategory { get; init; } = "vulnerability";
        /// <summary>Whether the pattern is directly exploitable as smuggling; null if not assessed.</summary>
        public bool? Exploitable { get; init; }
        public List<string> MitigatingFactors { get; init; } = [];
        /// <summary>How this finding was confirmed (e.g. timing-differential vs canonical TE response).</summary>
        public string? ConfirmationMethod { get; init; }
        public ProbeDetails? Probe { get; init; }
        /// <summary>Raw HTTP message sent for this finding (TLS: plaintext form sent on the wire).</summary>
        public string? RawProbeRequest { get; init; }
        /// <summary>Baseline GET used for timing comparison (when applicable).</summary>
        public string? RawTimingBaselineRequest { get; init; }
        /// <summary>Canonical chunked POST used as TE-TE reference (when applicable).</summary>
        public string? RawCanonicalReferenceRequest { get; init; }
    }

    internal static bool IsConfirmedDesync(SmugglingFinding f) =>
        string.Equals(f.ConfirmationMethod, "differential-response", StringComparison.OrdinalIgnoreCase);

    public sealed class ProbeDetails
    {
        public long BaselineMs { get; init; }
        public long ProbeMs { get; init; }
        public long DeltaMs { get; init; }
        public int BaselineStatus { get; init; }
        public int ProbeStatus { get; init; }
        public string? Obfuscation { get; init; }
    }

    public sealed class HeaderNormalizationResult
    {
        public bool AcceptsDuplicateCL { get; set; }
        /// <summary>True if any TE mutation (RFC-compliant or not) was accepted like canonical chunked.</summary>
        public bool AcceptsObfuscatedTE { get; set; }
        /// <summary>Non-RFC or high-variance Transfer-Encoding mutations accepted (meaningful for smuggling research).</summary>
        public List<string> ObfuscationsAccepted { get; set; } = [];
        /// <summary>CASE / OWS variants that are RFC-allowed; informational only.</summary>
        public List<string> ObfuscationsAcceptedRfcCompliant { get; set; } = [];
        /// <summary>Null if HEADER probe was not run (see techniques).</summary>
        public bool? RejectsBothCLAndTE { get; set; }
        /// <summary>Set when TE acceptance is recorded but not elevated to a vulnerability finding.</summary>
        public string? RiskNote { get; set; }
    }

    public sealed class InfrastructureInfo
    {
        public string HttpVersion { get; set; } = "unknown";
        /// <summary>Negotiated TLS ALPN (h2 / http/1.1) when fingerprinting succeeded.</summary>
        public string? Alpn { get; set; }
        public string? ServerHeader { get; set; }
        public List<string> ViaHeaders { get; set; } = [];
        public bool ProxyLikely { get; set; }
        public List<string> ProxyEvidence { get; set; } = [];
    }

    #endregion

    private static void AppendRawHttpReproduction(StringBuilder sb, SmugglingFinding f)
    {
        if (string.IsNullOrEmpty(f.RawProbeRequest) &&
            string.IsNullOrEmpty(f.RawTimingBaselineRequest) &&
            string.IsNullOrEmpty(f.RawCanonicalReferenceRequest))
            return;

        sb.AppendLine("  --- Reproduce (raw HTTP on TCP; wrap with TLS for https URLs) ---");
        if (!string.IsNullOrEmpty(f.RawProbeRequest))
        {
            sb.AppendLine("  Probe request:");
            foreach (var line in f.RawProbeRequest.Replace("\r\n", "\n", StringComparison.Ordinal)
                         .Split('\n', StringSplitOptions.None))
                sb.AppendLine("    " + line);
        }

        if (!string.IsNullOrEmpty(f.RawTimingBaselineRequest))
        {
            sb.AppendLine("  Timing baseline GET:");
            foreach (var line in f.RawTimingBaselineRequest.Replace("\r\n", "\n", StringComparison.Ordinal)
                         .Split('\n', StringSplitOptions.None))
                sb.AppendLine("    " + line);
        }

        if (!string.IsNullOrEmpty(f.RawCanonicalReferenceRequest))
        {
            sb.AppendLine("  Canonical chunked reference:");
            foreach (var line in f.RawCanonicalReferenceRequest.Replace("\r\n", "\n", StringComparison.Ordinal)
                         .Split('\n', StringSplitOptions.None))
                sb.AppendLine("    " + line);
        }
    }

    #region TE Obfuscation Mutations

    private readonly record struct TeMutation(string HeaderValue, string Label, bool RfcCompliant);

    /// <summary>RfcCompliant: CASE/OWS-only variants per RFC 9110. Others are parser-dependent / legacy folding / invalid codings.</summary>
    private static readonly TeMutation[] TeObfuscationMutations =
    [
        new("chunked ", "trailing space", true),
        new(" chunked", "leading space", true),
        new("Chunked", "capitalized", true),
        new("CHUNKED", "uppercase", true),
        new(" chunked ", "padded spaces", true),
        new("\tchunked", "leading tab", false),
        new("chunked\t", "trailing tab", false),
        new("chunked, identity", "chunked with identity", false),
        new("identity, chunked", "identity before chunked", false),
        new("xchunked", "prefixed with x", false),
        new("chunked1", "suffixed with 1", false),
        new("chunk", "truncated", false),
        new("chunked\r\n", "trailing CRLF in value", false),
        new("chunked; ext=1", "with extension", false),
    ];

    #endregion

    #region Public API

    public static async Task<SmugglingResult> RunAsync(
        string url,
        IReadOnlyList<string>? techniques = null,
        int timeoutMs = 10000,
        int delayThresholdMs = 3000,
        bool teObfuscations = true,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var uri = new Uri(url);
        var findings = new List<SmugglingFinding>();
        var headerNorm = new HeaderNormalizationResult();
        var infra = new InfrastructureInfo();
        int probesRun = 0;

        var enabledTechniques = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (techniques == null || techniques.Count == 0 || techniques.Any(t => t.Equals("all", StringComparison.OrdinalIgnoreCase)))
        {
            enabledTechniques.UnionWith(["CL-TE", "TE-CL", "TE-TE", "CL-CL", "HEADER"]);
        }
        else
        {
            enabledTechniques.UnionWith(techniques);
        }

        timeoutMs = Math.Clamp(timeoutMs, 2000, 30000);
        delayThresholdMs = Math.Clamp(delayThresholdMs, 1000, timeoutMs - 1000);

        // Infrastructure fingerprinting (baseline request + optional ALPN)
        var alpn = await ProbeAlpnAsync(uri, timeoutMs, ct);
        if (alpn != null)
        {
            probesRun++;
            infra.Alpn = alpn;
        }

        var baseline = await SendRawRequestAsync(uri, BuildBaselineRequest(uri), timeoutMs, ct);
        probesRun++;

        if (baseline.Error != null)
        {
            sw.Stop();
            return new SmugglingResult
            {
                Verdict = VerdictClean,
                Url = url,
                ElapsedMs = sw.ElapsedMilliseconds,
                Summary = $"Could not connect: {baseline.Error}",
                ProbesRun = probesRun,
                Findings = findings,
                HeaderNormalization = headerNorm,
                Infrastructure = infra,
            };
        }

        ParseInfrastructure(baseline, infra);
        ApplyAlpnNote(infra);

        string? canaryPath = null;
        if (enabledTechniques.Contains("CL-TE") || enabledTechniques.Contains("TE-CL"))
        {
            var (resolved, canaryProbes) = await ResolveCanaryPathAsync(uri, baseline, timeoutMs, ct);
            probesRun += canaryProbes;
            canaryPath = resolved;
        }

        // CL-TE then TE-CL (PortSwigger order). Prefer differential-response
        // confirmation over timing-only stalls — timing alone cannot distinguish front-end
        // TE hang from true front/back desync (see ReconcileTimingFindings).
        if (enabledTechniques.Contains("CL-TE"))
        {
            var (timingFinding, timingProbes) = await ProbeCLTE(uri, baseline, timeoutMs, delayThresholdMs, ct);
            probesRun += timingProbes;
            if (canaryPath != null)
            {
                var (diffFinding, diffProbes) = await ProbeClTeDifferential(uri, baseline, canaryPath, timeoutMs, ct);
                probesRun += diffProbes;
                if (diffFinding != null)
                    findings.Add(diffFinding);
                else if (timingFinding != null)
                    findings.Add(timingFinding);
            }
            else if (timingFinding != null)
            {
                findings.Add(timingFinding);
            }
        }

        if (enabledTechniques.Contains("TE-CL"))
        {
            var (timingFinding, timingProbes) = await ProbeTECL(uri, baseline, timeoutMs, delayThresholdMs, ct);
            probesRun += timingProbes;
            if (canaryPath != null)
            {
                var (diffFinding, diffProbes) = await ProbeTeClDifferential(uri, baseline, canaryPath, timeoutMs, ct);
                probesRun += diffProbes;
                if (diffFinding != null)
                    findings.Add(diffFinding);
                else if (timingFinding != null)
                    findings.Add(timingFinding);
            }
            else if (timingFinding != null)
            {
                findings.Add(timingFinding);
            }
        }

        // TE-TE obfuscation testing
        if (enabledTechniques.Contains("TE-TE") && teObfuscations)
        {
            var (obfFindings, obfProbes) = await ProbeTeObfuscations(uri, baseline, timeoutMs, delayThresholdMs, headerNorm, infra, ct);
            probesRun += obfProbes;
            findings.AddRange(obfFindings);
        }

        // CL-CL duplicate Content-Length
        if (enabledTechniques.Contains("CL-CL"))
        {
            var (finding, probes) = await ProbeDuplicateCL(uri, baseline, timeoutMs, headerNorm, ct);
            probesRun += probes;
            if (finding != null)
                findings.Add(finding);
        }

        // Header normalization (both CL and TE present → should be rejected)
        if (enabledTechniques.Contains("HEADER"))
        {
            var (finding, probes) = await ProbeHeaderNormalization(uri, baseline, timeoutMs, headerNorm, ct);
            probesRun += probes;
            if (finding != null)
                findings.Add(finding);
        }

        bool ranTeTeProbes = enabledTechniques.Contains("TE-TE") && teObfuscations;
        ReconcileTimingFindings(findings, infra, ranTeTeProbes);

        sw.Stop();

        var verdict = ComputeVerdict(findings);
        var summary = BuildScanSummary(verdict, findings, infra, headerNorm, ranTeTeProbes);

        return new SmugglingResult
        {
            Verdict = verdict,
            Url = url,
            ElapsedMs = sw.ElapsedMilliseconds,
            Summary = summary,
            ProbesRun = probesRun,
            Findings = findings,
            HeaderNormalization = headerNorm,
            Infrastructure = infra,
        };
    }

    /// <summary>
    /// Passive smuggling indicator analysis from response headers — no active probing.
    /// Safe to call in passive/safe mode (used by audit-all/quicktest).
    /// Proxy/CDN presence is context (risk none/low). Elevated risk only for ambiguous
    /// response framing (both TE and CL, or conflicting Content-Length values).
    /// </summary>
    public static PassiveSmugglingResult AnalyzePassive(
        Dictionary<string, string> responseHeaders,
        string httpVersion,
        string? serverHeader)
    {
        var indicators = new List<string>();
        var context = new List<string>();
        var risk = "none";

        if (IsUnambiguousHttp1(httpVersion))
            context.Add("HTTP/1.1 in use (smuggling-susceptible protocol when a proxy is in path)");

        if (responseHeaders.TryGetValue("Via", out var via) && !string.IsNullOrWhiteSpace(via))
            context.Add($"Via header detected — reverse proxy in path: {via}");

        if (responseHeaders.TryGetValue("X-Forwarded-For", out _))
            context.Add("X-Forwarded-For present — request passed through proxy");

        if (responseHeaders.TryGetValue("X-Forwarded-Host", out _))
            context.Add("X-Forwarded-Host present — reverse proxy is rewriting Host");

        if (ResponseHasBothTeAndCl(responseHeaders))
        {
            indicators.Add("Response contains BOTH Transfer-Encoding and Content-Length — ambiguous framing");
            risk = "high";
        }

        bool hasMultipleCL = ResponseHasConflictingContentLength(responseHeaders);
        if (hasMultipleCL)
        {
            indicators.Add("Multiple Content-Length values detected in response");
            risk = "high";
        }

        if (serverHeader != null)
        {
            var proxyServers = new[]
            {
                "nginx", "apache", "haproxy", "varnish", "squid", "envoy", "traefik",
                "cloudflare", "cloudfront", "akamai", "fastly",
            };
            foreach (var ps in proxyServers)
            {
                if (serverHeader.Contains(ps, StringComparison.OrdinalIgnoreCase))
                {
                    context.Add($"Server header indicates {ps} — commonly used as reverse proxy");
                    break;
                }
            }
        }

        bool proxyDetectedFromHeaders = HeaderPresent(responseHeaders, "Via") ||
                                        HeaderPresent(responseHeaders, "X-Forwarded-For");
        bool proxyDetectedFromServer = serverHeader != null &&
                                       new[]
                                       {
                                           "nginx", "apache", "haproxy", "varnish", "squid", "envoy", "traefik",
                                           "cloudflare", "cloudfront", "akamai", "fastly",
                                       }.Any(ps => serverHeader.Contains(ps, StringComparison.OrdinalIgnoreCase));

        bool proxyDetected = proxyDetectedFromHeaders || proxyDetectedFromServer;

        if (indicators.Count == 0 && context.Count == 0)
            context.Add("No smuggling risk indicators detected in response headers");

        return new PassiveSmugglingResult
        {
            Risk = risk,
            Indicators = indicators,
            Context = context,
            HasMultipleContentLength = hasMultipleCL,
            HasAmbiguousFraming = ResponseHasBothTeAndCl(responseHeaders),
            ProxyDetected = proxyDetected,
            Recommendation = risk switch
            {
                "high" => "Critical: ambiguous framing headers detected in the response. Run POST /api/security/smuggling with safetyMode: active. Act only on confirmed differential-response (canary 404).",
                _ when proxyDetected => "Proxy/CDN in path (context, not a finding). Run POST /api/security/smuggling with safetyMode: active once per origin; confirmed = differential 404 — everything else is informational.",
                _ => "No response-framing issues in headers. Active testing is still useful once per origin if a reverse proxy sits in front of HTTP/1.1."
            }
        };
    }

    public sealed class PassiveSmugglingResult
    {
        public string Risk { get; init; } = "none";
        /// <summary>Framing issues that can elevate risk (TE+CL, conflicting CL).</summary>
        public List<string> Indicators { get; init; } = [];
        /// <summary>Proxy/CDN/HTTP version notes — not findings.</summary>
        public List<string> Context { get; init; } = [];
        public bool HasMultipleContentLength { get; init; }
        public bool HasAmbiguousFraming { get; init; }
        public bool ProxyDetected { get; init; }
        public string Recommendation { get; init; } = "";
        public bool IsClean => Risk is "none" or "low";
    }

    /// <summary>
    /// True when response headers show both Transfer-Encoding and Content-Length, or
    /// conflicting Content-Length values. Proxy/CDN product headers are not framing bugs.
    /// </summary>
    public static bool ResponseHasAmbiguousFraming(IReadOnlyDictionary<string, string>? headers)
    {
        if (headers == null || headers.Count == 0)
            return false;
        return ResponseHasBothTeAndCl(headers) || ResponseHasConflictingContentLength(headers);
    }

    /// <summary>
    /// TE-TE desync oracle: status-class change (2xx vs 4xx/5xx). Body equality is ignored —
    /// HTML churn (CSRF tokens, timestamps, A/B) is not desync.
    /// </summary>
    public static bool TeTeResponsesIndicateDesync(int canonicalStatus, int obfuscatedStatus)
    {
        if (canonicalStatus <= 0 || obfuscatedStatus <= 0)
            return false;
        return (Is2xx(canonicalStatus) && Is45xx(obfuscatedStatus)) ||
               (Is45xx(canonicalStatus) && Is2xx(obfuscatedStatus));
    }

    private static bool Is2xx(int status) => status >= 200 && status < 300;
    private static bool Is45xx(int status) => status >= 400 && status < 600;

    /// <summary>
    /// "HTTP/2 or HTTP/1.1" must not count as HTTP/1.1 — that string is used when version is unknown.
    /// </summary>
    public static bool IsUnambiguousHttp1(string? httpVersion)
    {
        if (string.IsNullOrWhiteSpace(httpVersion))
            return false;
        var v = httpVersion.Trim();
        if (v.Contains(" or ", StringComparison.OrdinalIgnoreCase))
            return false;
        if (v.Contains("h2", StringComparison.OrdinalIgnoreCase) &&
            !v.Contains("1.1", StringComparison.OrdinalIgnoreCase) &&
            !v.Contains("1.0", StringComparison.OrdinalIgnoreCase))
            return false;
        return v.Contains("1.1", StringComparison.OrdinalIgnoreCase) ||
               v.Contains("1.0", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HeaderPresent(IReadOnlyDictionary<string, string> headers, string name) =>
        headers.Keys.Any(k => k.Equals(name, StringComparison.OrdinalIgnoreCase));

    private static bool ResponseHasBothTeAndCl(IReadOnlyDictionary<string, string> headers)
    {
        bool te = false, cl = false;
        foreach (var kv in headers)
        {
            if (string.IsNullOrWhiteSpace(kv.Value)) continue;
            if (kv.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
                te = true;
            else if (kv.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                cl = true;
        }
        return te && cl;
    }

    private static bool ResponseHasConflictingContentLength(IReadOnlyDictionary<string, string> headers)
    {
        foreach (var kv in headers)
        {
            if (!kv.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) || string.IsNullOrWhiteSpace(kv.Value))
                continue;
            if (kv.Value.Contains(','))
                return true;
        }
        return false;
    }

    private static string ComputeVerdict(IReadOnlyList<SmugglingFinding> findings)
    {
        if (findings.Any(IsConfirmedDesync))
            return VerdictConfirmed;
        if (findings.Count > 0)
            return VerdictUnconfirmed;
        return VerdictClean;
    }

    private static string BuildScanSummary(
        string verdict,
        IReadOnlyList<SmugglingFinding> findings,
        InfrastructureInfo infra,
        HeaderNormalizationResult headerNorm,
        bool ranTeTeProbes)
    {
        bool knownCdn = InfrastructureHasKnownCdn(infra);

        if (verdict == VerdictConfirmed)
            return "HTTP request smuggling confirmed via differential responses (CL-TE/TE.CL prefix desync). " +
                   "A canary request was applied to a subsequent client request (unexpected 404, repeated). " +
                   "Hand the raw HTTP to infrastructure. Do not spend triage time on TE obfuscation or duplicate CL." +
                   ExploitSeveritySuffix(knownCdn);

        if (verdict == VerdictUnconfirmed)
        {
            bool hasTimingClTe = findings.Any(f =>
                (f.Technique.Equals("CL-TE", StringComparison.OrdinalIgnoreCase) ||
                 f.Technique.Equals("TE-CL", StringComparison.OrdinalIgnoreCase)) &&
                f.FindingCategory == "informational");

            if (hasTimingClTe)
                return "No confirmed request smuggling. Ambiguous framing caused a timing stall (CL-TE/TE-CL) — " +
                       "timing-only probes cannot distinguish front-end TE handling from front/back desync. Architecture note only." +
                       (knownCdn ? " CDN layers often normalize framing." : "");

            return "No confirmed request smuggling. Architecture notes recorded (timing / CL-CL / HEADER / TE) — not bugs." +
                   (knownCdn ? " CDN layers often normalize framing." : "");
        }

        if (ranTeTeProbes && knownCdn &&
            (headerNorm.ObfuscationsAccepted.Count > 0 || headerNorm.ObfuscationsAcceptedRfcCompliant.Count > 0))
            return "No smuggling detected. TE header normalization observation only (CDN mitigates).";

        if (ranTeTeProbes && !knownCdn &&
            headerNorm.AcceptsObfuscatedTE && headerNorm.ObfuscationsAccepted.Count == 0 &&
            headerNorm.ObfuscationsAcceptedRfcCompliant.Count > 0)
            return "No smuggling detected. TE probes recorded RFC-compliant Transfer-Encoding tolerance only (informational).";

        if (ranTeTeProbes && !knownCdn && headerNorm.ObfuscationsAccepted.Count > 0)
            return "No confirmed smuggling. Server accepts obfuscated TE without a differential 404 — architecture note, not a bug ticket.";

        if (knownCdn)
            return "No smuggling detected. CDN layer provides additional protection.";

        return "No smuggling detected.";
    }

    private static string ExploitSeveritySuffix(bool knownCdn)
    {
        return knownCdn
            ? " Treat as high priority — CDN presence does not eliminate timing/divergence signals on these probes."
            : " Reverse-proxy or multi-hop topology increases desync impact — prioritize remediation.";
    }

    #endregion

    #region Probes

    /// <summary>
    /// CL-TE timing probe: send a request with Content-Length covering only part of the body,
    /// and Transfer-Encoding: chunked. A timeout means some layer is waiting for a chunk
    /// terminator — but that layer may be the front-end (RFC 7230 TE preference), not a
    /// front/back desync. Final severity is set in <see cref="ReconcileTimingFindings"/>.
    /// </summary>
    private static async Task<(SmugglingFinding?, int probes)> ProbeCLTE(
        Uri uri, RawResponse baseline, int timeoutMs, int delayThresholdMs, CancellationToken ct)
    {
        var body = "1\r\nZ\r\nQ";  // incomplete chunk — any TE parser waits for the next chunk-size line
        var cl = body.Length.ToString();

        var request = $"POST {uri.PathAndQuery} HTTP/1.1\r\n" +
                      $"Host: {uri.Host}\r\n" +
                      $"Content-Type: application/x-www-form-urlencoded\r\n" +
                      $"Content-Length: {cl}\r\n" +
                      $"Transfer-Encoding: chunked\r\n" +
                      $"Connection: close\r\n" +
                      $"\r\n" +
                      body;

        var probeResult = await SendRawRequestAsync(uri, request, timeoutMs, ct);

        if (probeResult.TimedOut || (probeResult.DurationMs - baseline.DurationMs) > delayThresholdMs)
        {
            var delta = probeResult.TimedOut ? timeoutMs : probeResult.DurationMs - baseline.DurationMs;
            return (new SmugglingFinding
            {
                Technique = "CL-TE",
                Severity = "informational",
                Confidence = "low",
                FindingCategory = "informational",
                Exploitable = false,
                ConfirmationMethod = "timing-only-incomplete-chunk",
                Evidence = probeResult.TimedOut
                    ? $"Request timed out ({timeoutMs}ms) when sending ambiguous CL+TE with incomplete chunked body (baseline: {baseline.DurationMs}ms) — a layer is waiting for a chunk terminator; this alone does not prove front-end/back-end desync"
                    : $"Response delayed {probeResult.DurationMs}ms when sending ambiguous CL+TE with incomplete chunked body (baseline: {baseline.DurationMs}ms, delta: {delta}ms) — timing-only signal; does not demonstrate smuggling",
                Description = "Ambiguous CL+TE framing with an incomplete chunked body caused a stall. " +
                    "This is expected when any RFC 7230-compliant layer prefers Transfer-Encoding and waits for " +
                    "the missing chunk terminator — including the front-end proxy itself. Actual CL-TE desync " +
                    "requires evidence that the front-end and back-end disagree on framing (see TE-TE reconciliation).",
                Remediation = "Reject requests containing both Content-Length and Transfer-Encoding headers, " +
                    "or normalize to a single framing method. Ensure HTTP/2 end-to-end where possible.",
                RawProbeRequest = request,
                RawTimingBaselineRequest = BuildBaselineRequest(uri),
                Probe = new ProbeDetails
                {
                    BaselineMs = baseline.DurationMs,
                    ProbeMs = probeResult.DurationMs,
                    DeltaMs = delta,
                    BaselineStatus = baseline.StatusCode,
                    ProbeStatus = probeResult.StatusCode,
                },
            }, 1);
        }

        return (null, 1);
    }

    /// <summary>
    /// TE-CL timing probe: send a request where Transfer-Encoding says chunked (with early terminator)
    /// but Content-Length is larger. A timeout means some layer is waiting for more CL bytes —
    /// but that may be the front-end (CL preference) rather than a front/back desync.
    /// Note: only run after CL-TE to avoid cross-contamination (per PortSwigger guidance).
    /// </summary>
    private static async Task<(SmugglingFinding?, int probes)> ProbeTECL(
        Uri uri, RawResponse baseline, int timeoutMs, int delayThresholdMs, CancellationToken ct)
    {
        var chunkedBody = "0\r\n\r\n";
        var fakeCL = (chunkedBody.Length + 64).ToString();

        var request = $"POST {uri.PathAndQuery} HTTP/1.1\r\n" +
                      $"Host: {uri.Host}\r\n" +
                      $"Content-Type: application/x-www-form-urlencoded\r\n" +
                      $"Transfer-Encoding: chunked\r\n" +
                      $"Content-Length: {fakeCL}\r\n" +
                      $"Connection: close\r\n" +
                      $"\r\n" +
                      chunkedBody;

        var probeResult = await SendRawRequestAsync(uri, request, timeoutMs, ct);

        if (probeResult.TimedOut || (probeResult.DurationMs - baseline.DurationMs) > delayThresholdMs)
        {
            var delta = probeResult.TimedOut ? timeoutMs : probeResult.DurationMs - baseline.DurationMs;
            return (new SmugglingFinding
            {
                Technique = "TE-CL",
                Severity = "informational",
                Confidence = "low",
                FindingCategory = "informational",
                Exploitable = false,
                ConfirmationMethod = "timing-only-incomplete-cl",
                Evidence = probeResult.TimedOut
                    ? $"Request timed out ({timeoutMs}ms) when sending ambiguous TE+CL (baseline: {baseline.DurationMs}ms) — a layer is waiting for Content-Length bytes; this alone does not prove front-end/back-end desync"
                    : $"Response delayed {probeResult.DurationMs}ms when sending ambiguous TE+CL (baseline: {baseline.DurationMs}ms, delta: {delta}ms) — timing-only signal; does not demonstrate smuggling",
                Description = "Ambiguous TE+CL framing with a complete chunked body but inflated Content-Length " +
                    "caused a stall. This may be normal when a layer prefers Content-Length and waits for " +
                    "missing body bytes. Actual TE-CL desync requires evidence that layers disagree on framing " +
                    "(see TE-TE reconciliation).",
                Remediation = "Reject requests with ambiguous framing. Configure both layers to agree on " +
                    "Transfer-Encoding handling, or strip TE headers at the edge and use Content-Length only.",
                RawProbeRequest = request,
                RawTimingBaselineRequest = BuildBaselineRequest(uri),
                Probe = new ProbeDetails
                {
                    BaselineMs = baseline.DurationMs,
                    ProbeMs = probeResult.DurationMs,
                    DeltaMs = delta,
                    BaselineStatus = baseline.StatusCode,
                    ProbeStatus = probeResult.StatusCode,
                },
            }, 1);
        }

        return (null, 1);
    }

    /// <summary>
    /// CL.TE differential-response confirmation (PortSwigger): complete chunked body with
    /// Content-Length covering only through the chunk terminator, leaving
    /// <c>GET {canary} ... X-Ignore: X</c> in the FE→BE pipe. Requires a proven 404 canary
    /// and a repeated 404 on a second round before HIGH.
    /// </summary>
    private static async Task<(SmugglingFinding?, int probes)> ProbeClTeDifferential(
        Uri uri, RawResponse baseline, string canaryPath, int timeoutMs, CancellationToken ct)
    {
        var request = BuildClTeDifferentialRequest(uri, canaryPath);
        return await RunDifferentialConfirmationAsync(
            uri, baseline, timeoutMs, ct,
            technique: "CL-TE",
            request: request,
            canaryPath: canaryPath,
            description:
                "Front-end used Content-Length while the back-end used Transfer-Encoding (CL.TE). " +
                "A complete ambiguous request left a canary GET prefixed onto the next request " +
                "on the shared front-end→back-end connection — confirmed by repeated differential 404s.",
            remediation:
                "Reject requests containing both Content-Length and Transfer-Encoding, or normalize " +
                "framing at the edge. Prefer HTTP/2 end-to-end. Do not reuse back-end connections " +
                "across clients when absolute framing agreement cannot be guaranteed.");
    }

    /// <summary>
    /// TE.CL differential-response confirmation (PortSwigger): chunked request whose
    /// Content-Length covers only the chunk-size line so the back-end treats the rest as
    /// the next request. Repeated unexpected 404 confirms desync.
    /// </summary>
    private static async Task<(SmugglingFinding?, int probes)> ProbeTeClDifferential(
        Uri uri, RawResponse baseline, string canaryPath, int timeoutMs, CancellationToken ct)
    {
        var request = BuildTeClDifferentialRequest(uri, canaryPath);
        return await RunDifferentialConfirmationAsync(
            uri, baseline, timeoutMs, ct,
            technique: "TE-CL",
            request: request,
            canaryPath: canaryPath,
            description:
                "Front-end used Transfer-Encoding while the back-end used Content-Length (TE.CL). " +
                "A canary request was smuggled ahead of the next client request on the shared " +
                "front-end→back-end connection — confirmed by repeated differential 404s.",
            remediation:
                "Reject ambiguous CL+TE framing. Ensure both tiers agree on Transfer-Encoding " +
                "handling, or strip TE at the edge and use Content-Length only. Prefer HTTP/2 end-to-end.");
    }

    private static async Task<(SmugglingFinding?, int probes)> RunDifferentialConfirmationAsync(
        Uri uri,
        RawResponse baseline,
        int timeoutMs,
        CancellationToken ct,
        string technique,
        string request,
        string canaryPath,
        string description,
        string remediation)
    {
        int probes = 0;

        var (round1, p1) = await TryDifferentialRoundAsync(uri, baseline, request, timeoutMs, ct);
        probes += p1;
        if (!round1.Confirmed)
            return (null, probes);

        await Task.Delay(300, ct);
        var (round2, p2) = await TryDifferentialRoundAsync(uri, baseline, request, timeoutMs, ct);
        probes += p2;
        if (!round2.Confirmed)
            return (null, probes);

        var evidenceParts = new List<string>
        {
            $"Repeatable differential 404 on canary {canaryPath}: baseline HTTP {baseline.StatusCode}",
            $"round1 smuggle#1 HTTP {StatusLabel(round1.First)}, smuggle#2 HTTP {StatusLabel(round1.Second)}" +
            (round1.FollowUp != null ? $", follow-up GET HTTP {StatusLabel(round1.FollowUp)}" : ""),
            $"round2 smuggle#1 HTTP {StatusLabel(round2.First)}, smuggle#2 HTTP {StatusLabel(round2.Second)}" +
            (round2.FollowUp != null ? $", follow-up GET HTTP {StatusLabel(round2.FollowUp)}" : ""),
            round1.Classic
                ? "second request returned canary 404 on both rounds — demonstrates real request smuggling"
                : "follow-up request returned canary 404 after smuggle prefix on both rounds — demonstrates real request smuggling",
        };

        return (new SmugglingFinding
        {
            Technique = technique,
            Severity = "high",
            Confidence = "high",
            FindingCategory = "vulnerability",
            Exploitable = true,
            ConfirmationMethod = "differential-response",
            Evidence = string.Join("; ", evidenceParts),
            Description = description,
            Remediation = remediation,
            RawProbeRequest = request,
            RawTimingBaselineRequest = BuildBaselineRequest(uri),
            Probe = new ProbeDetails
            {
                BaselineMs = baseline.DurationMs,
                ProbeMs = round2.Second.DurationMs,
                DeltaMs = Math.Abs(round2.Second.DurationMs - baseline.DurationMs),
                BaselineStatus = baseline.StatusCode,
                ProbeStatus = round1.Classic ? round2.Second.StatusCode : (round2.FollowUp?.StatusCode ?? round2.Second.StatusCode),
            },
        }, probes);
    }

    private readonly record struct DifferentialRound(
        bool Confirmed,
        bool Classic,
        RawResponse First,
        RawResponse Second,
        RawResponse? FollowUp);

    private static async Task<(DifferentialRound Round, int Probes)> TryDifferentialRoundAsync(
        Uri uri, RawResponse baseline, string request, int timeoutMs, CancellationToken ct)
    {
        int probes = 0;
        var first = await SendRawRequestAsync(uri, request, timeoutMs, ct);
        probes++;
        await Task.Delay(300, ct);

        var second = await SendRawRequestAsync(uri, request, timeoutMs, ct);
        probes++;

        bool classic =
            !first.TimedOut && first.StatusCode > 0 && first.StatusCode != 404 &&
            !second.TimedOut && second.StatusCode == 404 &&
            baseline.StatusCode != 404;

        RawResponse? followUp = null;
        if (!classic)
        {
            await Task.Delay(200, ct);
            followUp = await SendRawRequestAsync(uri, BuildBaselineRequest(uri), timeoutMs, ct);
            probes++;
        }

        bool followUpConfirm =
            followUp != null &&
            !followUp.TimedOut &&
            followUp.StatusCode == 404 &&
            baseline.StatusCode != 404 &&
            baseline.StatusCode > 0;

        bool smuggleLanded = (!first.TimedOut && first.StatusCode > 0) || (!second.TimedOut && second.StatusCode > 0);
        bool confirmed = smuggleLanded && (classic || followUpConfirm);
        return (new DifferentialRound(confirmed, classic, first, second, followUp), probes);
    }

    private static string StatusLabel(RawResponse r) =>
        r.TimedOut ? "timeout" : r.StatusCode.ToString();

    /// <summary>
    /// Prove a unique (or fallback /404) path actually 404s and the homepage is not 404.
    /// Returns null when differential confirmation cannot run.
    /// </summary>
    private static async Task<(string? Path, int Probes)> ResolveCanaryPathAsync(
        Uri uri, RawResponse baseline, int timeoutMs, CancellationToken ct)
    {
        int probes = 0;
        if (baseline.StatusCode == 404 || baseline.StatusCode <= 0)
            return (null, probes);

        var token = Guid.NewGuid().ToString("N")[..12];
        var unique = $"/trowser-smuggle-{token}";
        var uniqueResp = await SendRawRequestAsync(uri, BuildGetRequest(uri, unique), timeoutMs, ct);
        probes++;
        if (!uniqueResp.TimedOut && uniqueResp.StatusCode == 404)
            return (unique, probes);

        var fallback = await SendRawRequestAsync(uri, BuildGetRequest(uri, "/404"), timeoutMs, ct);
        probes++;
        if (!fallback.TimedOut && fallback.StatusCode == 404)
            return ("/404", probes);

        return (null, probes);
    }

    /// <summary>
    /// PortSwigger CL.TE prefix: CL covers <c>0\r\n\r\n</c> only; from the back-end's TE view
    /// the front-end consumes through the end of <c>X-Ignore: X</c> (no trailing CRLF).
    /// Poison request omits Connection: close so the prefix can sit on a reused back-end socket.
    /// </summary>
    public static string BuildClTeDifferentialRequest(Uri uri, string canaryPath = "/404")
    {
        // Exact PortSwigger body: no CRLF after "X" — next request's start merges into X-Ignore.
        var prefix = $"0\r\n\r\nGET {canaryPath} HTTP/1.1\r\nX-Ignore: X";
        return $"POST {uri.PathAndQuery} HTTP/1.1\r\n" +
               $"Host: {uri.Host}\r\n" +
               $"Content-Type: application/x-www-form-urlencoded\r\n" +
               $"Content-Length: {prefix.Length}\r\n" +
               $"Transfer-Encoding: chunked\r\n" +
               $"\r\n" +
               prefix;
    }

    /// <summary>
    /// PortSwigger TE.CL prefix: outer Content-Length is 4 (the chunk-size line);
    /// the rest of the chunked message is treated as the next request by a CL-only back-end.
    /// </summary>
    public static string BuildTeClDifferentialRequest(Uri uri, string canaryPath = "/404")
    {
        // Chunk-data length must be 16–255 so the size line is exactly 2 hex digits + CRLF (= 4 bytes).
        var smuggled =
            $"POST {canaryPath} HTTP/1.1\r\n" +
            "Content-Type: application/x-www-form-urlencoded\r\n" +
            "Content-Length: 15\r\n" +
            "\r\n" +
            "x=1";

        if (smuggled.Length < 16)
            smuggled += new string(' ', 16 - smuggled.Length);
        else if (smuggled.Length > 255)
            smuggled = smuggled[..255];

        var chunkSizeHex = smuggled.Length.ToString("x");
        var chunkSizeLine = $"{chunkSizeHex}\r\n";
        // Back-end (CL) reads exactly these 4 bytes as the body of the first request.
        if (chunkSizeLine.Length != 4)
            chunkSizeHex = smuggled.Length.ToString("x2");

        var body = $"{chunkSizeHex}\r\n{smuggled}\r\n0\r\n\r\n";
        return $"POST {uri.PathAndQuery} HTTP/1.1\r\n" +
               $"Host: {uri.Host}\r\n" +
               $"Content-Type: application/x-www-form-urlencoded\r\n" +
               $"Content-Length: 4\r\n" +
               $"Transfer-Encoding: chunked\r\n" +
               $"\r\n" +
               body;
    }

    /// <summary>
    /// TE-TE obfuscation: record how non-canonical Transfer-Encoding values are handled.
    /// RFC CASE/OWS variants go to <see cref="HeaderNormalizationResult.ObfuscationsAcceptedRfcCompliant"/> only.
    /// Vulnerability findings require timing differential or response divergence on non-RFC mutations.
    /// </summary>
    private static async Task<(List<SmugglingFinding>, int probes)> ProbeTeObfuscations(
        Uri uri,
        RawResponse baseline,
        int timeoutMs,
        int delayThresholdMs,
        HeaderNormalizationResult headerNorm,
        InfrastructureInfo infra,
        CancellationToken ct)
    {
        var findings = new List<SmugglingFinding>();
        int probeCount = 0;
        bool knownCdn = InfrastructureHasKnownCdn(infra);

        var validChunkedBody = "1\r\nX\r\n0\r\n\r\n";
        var validRequest = $"POST {uri.PathAndQuery} HTTP/1.1\r\n" +
                           $"Host: {uri.Host}\r\n" +
                           $"Content-Type: application/x-www-form-urlencoded\r\n" +
                           $"Transfer-Encoding: chunked\r\n" +
                           $"Connection: close\r\n" +
                           $"\r\n" +
                           validChunkedBody;

        var validRef = await SendRawRequestAsync(uri, validRequest, timeoutMs, ct);
        probeCount++;

        RawResponse? firstNonRfcAcceptedProbe = null;
        string firstNonRfcAcceptedLabel = "";
        string? firstNonRfcAcceptedRawRequest = null;

        RawResponse? framingProbe = null;
        string framingLabel = "";
        string? framingRawRequest = null;
        RawResponse? timingProbe = null;
        string timingLabel = "";
        string? timingRawRequest = null;
        long bestTimingDelta = -1;

        foreach (var mutation in TeObfuscationMutations)
        {
            if (ct.IsCancellationRequested) break;

            var teValue = mutation.HeaderValue;
            var label = mutation.Label;

            var request = $"POST {uri.PathAndQuery} HTTP/1.1\r\n" +
                          $"Host: {uri.Host}\r\n" +
                          $"Content-Type: application/x-www-form-urlencoded\r\n" +
                          $"Transfer-Encoding: {teValue}\r\n" +
                          $"Connection: close\r\n" +
                          $"\r\n" +
                          validChunkedBody;

            var probeResult = await SendRawRequestAsync(uri, request, timeoutMs, ct);
            probeCount++;

            bool accepted = !probeResult.TimedOut
                && probeResult.StatusCode > 0
                && probeResult.StatusCode == validRef.StatusCode
                && Math.Abs(probeResult.DurationMs - validRef.DurationMs) < 2000;

            if (accepted)
            {
                headerNorm.AcceptsObfuscatedTE = true;
                var line = FormatAcceptedTeLine(teValue, label);
                if (mutation.RfcCompliant)
                    headerNorm.ObfuscationsAcceptedRfcCompliant.Add(line);
                else
                    headerNorm.ObfuscationsAccepted.Add(line);
            }

            if (mutation.RfcCompliant)
                continue;

            if (accepted && firstNonRfcAcceptedProbe == null)
            {
                firstNonRfcAcceptedProbe = probeResult;
                firstNonRfcAcceptedLabel = label;
                firstNonRfcAcceptedRawRequest = request;
            }

            // Timing vs canonical chunked POST (not vs GET baseline — POST vs GET is not desync).
            long deltaVsCanonical = probeResult.TimedOut && !validRef.TimedOut
                ? timeoutMs
                : probeResult.DurationMs - validRef.DurationMs;
            bool timingVsCanonical = (probeResult.TimedOut && !validRef.TimedOut) ||
                                     (!probeResult.TimedOut && !validRef.TimedOut && deltaVsCanonical > delayThresholdMs);
            if (timingVsCanonical && deltaVsCanonical > bestTimingDelta)
            {
                bestTimingDelta = deltaVsCanonical;
                timingProbe = probeResult;
                timingLabel = label;
                timingRawRequest = request;
            }

            if (framingProbe == null &&
                TeTeResponsesIndicateDesync(validRef.StatusCode, probeResult.StatusCode))
            {
                var again = await SendRawRequestAsync(uri, request, timeoutMs, ct);
                probeCount++;
                if (again.StatusCode == probeResult.StatusCode &&
                    TeTeResponsesIndicateDesync(validRef.StatusCode, again.StatusCode))
                {
                    framingProbe = again;
                    framingLabel = label;
                    framingRawRequest = request;
                }
            }
        }

        bool hasNonRfcAccepts = headerNorm.ObfuscationsAccepted.Count > 0;
        bool hasFraming = framingProbe != null;
        bool hasTiming = timingProbe != null;

        if (!hasNonRfcAccepts && headerNorm.ObfuscationsAcceptedRfcCompliant.Count > 0)
        {
            headerNorm.RiskNote =
                "Only RFC-allowed Transfer-Encoding variants (case / optional whitespace) matched canonical chunked behavior — expected for standards-compliant stacks.";
        }
        else if (hasNonRfcAccepts && !hasFraming && !hasTiming && knownCdn)
        {
            headerNorm.RiskNote =
                "Non-RFC TE mutations were normalized like canonical chunked without a status-class change or timing stall vs the canonical POST; " +
                "a known CDN/proxy layer typically sanitizes Transfer-Encoding before origin — architecture note only.";
        }
        else if (hasNonRfcAccepts && !hasFraming && !hasTiming && !knownCdn && firstNonRfcAcceptedProbe != null)
        {
            long deltaMs = firstNonRfcAcceptedProbe.DurationMs - validRef.DurationMs;
            findings.Add(new SmugglingFinding
            {
                Technique = "TE-TE",
                Severity = "informational",
                Confidence = "low",
                FindingCategory = "informational",
                Exploitable = false,
                ConfirmationMethod = "header-acceptance",
                Evidence = $"Server accepts non-RFC Transfer-Encoding variants ({headerNorm.ObfuscationsAccepted.Count}) without timing stall vs canonical chunked POST or a repeating 2xx↔4xx/5xx status-class change. Example: {firstNonRfcAcceptedLabel}.",
                Description = "The origin accepts unusual Transfer-Encoding codings but probes did not show a framing signal versus canonical chunked encoding. " +
                    "This is not request smuggling.",
                Remediation = "Prefer rejecting non-canonical Transfer-Encoding at the edge; confirm architecture does not mix parsers that disagree on TE framing.",
                RawProbeRequest = firstNonRfcAcceptedRawRequest,
                RawCanonicalReferenceRequest = validRequest,
                Probe = new ProbeDetails
                {
                    BaselineMs = validRef.DurationMs,
                    ProbeMs = firstNonRfcAcceptedProbe.DurationMs,
                    DeltaMs = deltaMs,
                    BaselineStatus = validRef.StatusCode,
                    ProbeStatus = firstNonRfcAcceptedProbe.StatusCode,
                    Obfuscation = firstNonRfcAcceptedLabel,
                },
            });
        }

        if (hasFraming && framingProbe != null)
        {
            findings.Add(new SmugglingFinding
            {
                Technique = "TE-TE",
                Severity = "low",
                Confidence = "medium",
                FindingCategory = "observation",
                Exploitable = false,
                ConfirmationMethod = "response-divergence",
                Evidence = $"Repeated status-class change vs canonical chunked POST on obfuscation '{framingLabel}': canonical HTTP {validRef.StatusCode}, obfuscated HTTP {framingProbe.StatusCode}. Body differences are ignored.",
                Description = "Non-RFC Transfer-Encoding produced a stable 2xx vs 4xx/5xx status-class change versus the canonical chunked POST. " +
                    "This is an architecture note, not confirmed request smuggling — act only on differential-response 404.",
                Remediation = "Reject malformed Transfer-Encoding values at the edge; align chunked parsing across proxies and origin.",
                RawProbeRequest = framingRawRequest,
                RawCanonicalReferenceRequest = validRequest,
                Probe = new ProbeDetails
                {
                    BaselineMs = validRef.DurationMs,
                    ProbeMs = framingProbe.DurationMs,
                    DeltaMs = framingProbe.DurationMs - validRef.DurationMs,
                    BaselineStatus = validRef.StatusCode,
                    ProbeStatus = framingProbe.StatusCode,
                    Obfuscation = framingLabel,
                },
            });
        }

        if (hasTiming && timingProbe != null && !hasFraming)
        {
            findings.Add(new SmugglingFinding
            {
                Technique = "TE-TE",
                Severity = "informational",
                Confidence = "low",
                FindingCategory = "informational",
                Exploitable = false,
                ConfirmationMethod = "timing-differential",
                Evidence = $"Obfuscated TE '{timingLabel}' stalled {bestTimingDelta}ms vs canonical chunked POST ({validRef.DurationMs}ms). GET baseline is not used for TE-TE timing.",
                Description = "Obfuscated Transfer-Encoding was slower than the canonical chunked POST. Timing vs GET is not treated as desync. Architecture note only.",
                Remediation = "Reject malformed Transfer-Encoding at the edge. Confirm with a differential-response scan before filing a smuggling bug.",
                RawProbeRequest = timingRawRequest,
                RawCanonicalReferenceRequest = validRequest,
                Probe = new ProbeDetails
                {
                    BaselineMs = validRef.DurationMs,
                    ProbeMs = timingProbe.DurationMs,
                    DeltaMs = bestTimingDelta,
                    BaselineStatus = validRef.StatusCode,
                    ProbeStatus = timingProbe.StatusCode,
                    Obfuscation = timingLabel,
                },
            });
        }

        return (findings, probeCount);
    }

    private static string FormatAcceptedTeLine(string teValue, string label)
    {
        var safe = teValue.Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t");
        return $"Transfer-Encoding: {safe} ({label})";
    }

    /// <summary>Known CDN / edge fingerprints likely to normalize TE before origin.</summary>
    private static bool InfrastructureHasKnownCdn(InfrastructureInfo infra)
    {
        foreach (var ev in infra.ProxyEvidence)
        {
            if (ev.Contains("Cloudflare", StringComparison.OrdinalIgnoreCase) ||
                ev.Contains("cloudfront", StringComparison.OrdinalIgnoreCase) ||
                ev.Contains("Fastly", StringComparison.OrdinalIgnoreCase) ||
                ev.Contains("Akamai", StringComparison.OrdinalIgnoreCase) ||
                ev.Contains("AWS infrastructure", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        if (infra.ServerHeader != null)
        {
            var s = infra.ServerHeader;
            if (s.Contains("cloudflare", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("cloudfront", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("fastly", StringComparison.OrdinalIgnoreCase) ||
                s.Contains("akamai", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>
    /// CL-CL: send a request with two Content-Length headers with different values.
    /// RFC 9110 mandates 400; accepting this is a configuration weakness.
    /// </summary>
    private static async Task<(SmugglingFinding?, int probes)> ProbeDuplicateCL(
        Uri uri, RawResponse baseline, int timeoutMs, HeaderNormalizationResult headerNorm, CancellationToken ct)
    {
        var body = "ABCDEFGHIJ"; // 10 bytes
        var request = $"POST {uri.PathAndQuery} HTTP/1.1\r\n" +
                      $"Host: {uri.Host}\r\n" +
                      $"Content-Type: application/x-www-form-urlencoded\r\n" +
                      $"Content-Length: 10\r\n" +
                      $"Content-Length: 5\r\n" +
                      $"Connection: close\r\n" +
                      $"\r\n" +
                      body;

        var probeResult = await SendRawRequestAsync(uri, request, timeoutMs, ct);

        bool accepted = !probeResult.TimedOut && probeResult.StatusCode >= 200 && probeResult.StatusCode < 400;
        headerNorm.AcceptsDuplicateCL = accepted;

        if (accepted)
        {
            return (new SmugglingFinding
            {
                Technique = "CL-CL",
                Severity = "low",
                Confidence = "high",
                FindingCategory = "observation",
                Exploitable = false,
                ConfirmationMethod = "duplicate-cl-accepted",
                Evidence = $"Server returned {probeResult.StatusCode} for a request with duplicate Content-Length headers (10 and 5). " +
                    $"RFC 9110 requires 400 on conflicting Content-Length. Many CDNs still answer 2xx — hygiene, not proven front/back disagreement.",
                Description = "Server accepts requests with multiple Content-Length headers containing " +
                    "different values. That is an RFC 9110 violation, not confirmed request smuggling. " +
                    "Act only if a differential-response canary 404 also fires.",
                Remediation = "Configure the server to reject requests with duplicate or conflicting " +
                    "Content-Length headers with HTTP 400, as required by RFC 9110.",
                RawProbeRequest = request,
                Probe = new ProbeDetails
                {
                    BaselineMs = baseline.DurationMs,
                    ProbeMs = probeResult.DurationMs,
                    DeltaMs = probeResult.DurationMs - baseline.DurationMs,
                    BaselineStatus = baseline.StatusCode,
                    ProbeStatus = probeResult.StatusCode,
                },
            }, 1);
        }

        return (null, 1);
    }

    /// <summary>
    /// Header normalization: test whether the server rejects requests that contain
    /// both Content-Length and Transfer-Encoding (which it should per RFC 9110 §6.3).
    /// </summary>
    private static async Task<(SmugglingFinding?, int probes)> ProbeHeaderNormalization(
        Uri uri, RawResponse baseline, int timeoutMs, HeaderNormalizationResult headerNorm, CancellationToken ct)
    {
        var body = "0\r\n\r\n";
        var request = $"POST {uri.PathAndQuery} HTTP/1.1\r\n" +
                      $"Host: {uri.Host}\r\n" +
                      $"Content-Type: application/x-www-form-urlencoded\r\n" +
                      $"Content-Length: {body.Length}\r\n" +
                      $"Transfer-Encoding: chunked\r\n" +
                      $"Connection: close\r\n" +
                      $"\r\n" +
                      body;

        var probeResult = await SendRawRequestAsync(uri, request, timeoutMs, ct);

        if (!probeResult.TimedOut && probeResult.StatusCode > 0)
        {
            bool rejected = probeResult.StatusCode == 400 || probeResult.StatusCode == 501;
            headerNorm.RejectsBothCLAndTE = rejected;
            if (!rejected)
            {
                return (new SmugglingFinding
                {
                    Technique = "HEADER",
                    Severity = "low",
                    Confidence = "high",
                    FindingCategory = "observation",
                    Exploitable = false,
                    Evidence = $"Server returned {probeResult.StatusCode} (not 400) when both Content-Length and " +
                        $"Transfer-Encoding were present. Proper behavior is to reject ambiguous framing.",
                    Description = "Server accepts requests containing both Content-Length and Transfer-Encoding " +
                        "headers without rejecting them. While this alone is not exploitable, it indicates that " +
                        "the infrastructure does not strictly enforce RFC 9110 framing rules — a prerequisite " +
                        "for CL-TE and TE-CL smuggling attacks.",
                    Remediation = "Configure servers and proxies to reject requests that include both " +
                        "Content-Length and Transfer-Encoding headers. The proxy should strip one before " +
                        "forwarding, or return 400.",
                    RawProbeRequest = request,
                    Probe = new ProbeDetails
                    {
                        BaselineMs = baseline.DurationMs,
                        ProbeMs = probeResult.DurationMs,
                        DeltaMs = probeResult.DurationMs - baseline.DurationMs,
                        BaselineStatus = baseline.StatusCode,
                        ProbeStatus = probeResult.StatusCode,
                    },
                }, 1);
            }

            return (null, 1);
        }

        return (null, 1);
    }

    /// <summary>
    /// Adjust CL-TE/TE-CL timing-only findings. Timing on incomplete chunked data is
    /// insufficient to confirm front/back desync. TE-TE body/timing signals must not
    /// promote these to vulnerabilities. Differential-response findings are left unchanged.
    /// </summary>
    private static void ReconcileTimingFindings(
        List<SmugglingFinding> findings,
        InfrastructureInfo infra,
        bool ranTeTeProbes)
    {
        bool prefersTeProxy = InfrastructurePrefersTeOverCl(infra);
        bool hasDifferentialClTe = findings.Exists(f =>
            f.Technique.Equals("CL-TE", StringComparison.OrdinalIgnoreCase) &&
            IsConfirmedDesync(f));
        bool hasDifferentialTeCl = findings.Exists(f =>
            f.Technique.Equals("TE-CL", StringComparison.OrdinalIgnoreCase) &&
            IsConfirmedDesync(f));

        for (int i = 0; i < findings.Count; i++)
        {
            var f = findings[i];
            if (!IsTimingOnlyClTeTeClFinding(f))
                continue;

            if ((f.Technique.Equals("CL-TE", StringComparison.OrdinalIgnoreCase) && hasDifferentialClTe) ||
                (f.Technique.Equals("TE-CL", StringComparison.OrdinalIgnoreCase) && hasDifferentialTeCl))
            {
                findings.RemoveAt(i);
                i--;
                continue;
            }

            var mitigating = new List<string>(f.MitigatingFactors);

            if (ranTeTeProbes)
            {
                mitigating.Add(
                    "TE-TE probes are not used to corroborate CL-TE/TE-CL timing — only a repeated differential 404 confirms desync");
            }

            if (prefersTeProxy)
            {
                mitigating.Add(
                    "Detected proxy stack typically prefers Transfer-Encoding over Content-Length per RFC 7230 — timeout on incomplete chunked body is expected edge behavior, not demonstrated smuggling");
            }

            findings[i] = CopyTimingFinding(f,
                mitigatingFactors: mitigating,
                evidence: mitigating.Count > 0
                    ? f.Evidence + " — not elevated: timing-only, no differential 404"
                    : f.Evidence);
        }
    }

    private static SmugglingFinding CopyTimingFinding(
        SmugglingFinding source,
        string? severity = null,
        string? confidence = null,
        string? findingCategory = null,
        bool? exploitable = null,
        string? confirmationMethod = null,
        string? description = null,
        string? evidence = null,
        List<string>? mitigatingFactors = null)
    {
        return new SmugglingFinding
        {
            Technique = source.Technique,
            Severity = severity ?? source.Severity,
            Confidence = confidence ?? source.Confidence,
            FindingCategory = findingCategory ?? source.FindingCategory,
            Exploitable = exploitable ?? source.Exploitable,
            ConfirmationMethod = confirmationMethod ?? source.ConfirmationMethod,
            Description = description ?? source.Description,
            Evidence = evidence ?? source.Evidence,
            Remediation = source.Remediation,
            MitigatingFactors = mitigatingFactors ?? source.MitigatingFactors,
            Probe = source.Probe,
            RawProbeRequest = source.RawProbeRequest,
            RawTimingBaselineRequest = source.RawTimingBaselineRequest,
            RawCanonicalReferenceRequest = source.RawCanonicalReferenceRequest,
        };
    }

    private static bool IsTimingOnlyClTeTeClFinding(SmugglingFinding f)
    {
        if (!f.Technique.Equals("CL-TE", StringComparison.OrdinalIgnoreCase) &&
            !f.Technique.Equals("TE-CL", StringComparison.OrdinalIgnoreCase))
            return false;

        return f.ConfirmationMethod is "timing-only-incomplete-chunk" or "timing-only-incomplete-cl";
    }

    /// <summary>Proxies and load balancers that prefer TE over CL when both headers are present (RFC 7230).</summary>
    private static bool InfrastructurePrefersTeOverCl(InfrastructureInfo infra)
    {
        foreach (var ev in infra.ProxyEvidence)
        {
            if (ev.Contains("BigIP", StringComparison.OrdinalIgnoreCase) ||
                ev.Contains("BIG-IP", StringComparison.OrdinalIgnoreCase) ||
                ev.Contains("F5", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        if (infra.ServerHeader == null)
            return false;

        var s = infra.ServerHeader;
        var tePreferring = new[]
        {
            "nginx", "apache", "haproxy", "varnish", "envoy", "traefik", "squid",
            "BigIP", "BIG-IP", "F5",
        };

        return tePreferring.Any(marker => s.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }

    #endregion

    #region Raw TCP Communication

    private sealed class RawResponse
    {
        public int StatusCode { get; init; }
        public string StatusLine { get; init; } = "";
        public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        public string Body { get; init; } = "";
        public long DurationMs { get; init; }
        public bool TimedOut { get; init; }
        public string? Error { get; init; }
        public string RawResponse_ { get; init; } = "";
    }

    private static string BuildBaselineRequest(Uri uri) =>
        BuildGetRequest(uri, uri.PathAndQuery);

    private static string BuildGetRequest(Uri uri, string pathAndQuery)
    {
        if (string.IsNullOrEmpty(pathAndQuery))
            pathAndQuery = "/";
        return $"GET {pathAndQuery} HTTP/1.1\r\n" +
               $"Host: {uri.Host}\r\n" +
               $"Connection: close\r\n" +
               $"User-Agent: Trowser/1.0 Security-Scanner\r\n" +
               $"\r\n";
    }

    private static void ApplyAlpnNote(InfrastructureInfo infra)
    {
        if (string.IsNullOrEmpty(infra.Alpn))
            return;
        var alpn = infra.Alpn;
        bool prefersH2 = alpn.Contains("h2", StringComparison.OrdinalIgnoreCase) &&
                         !alpn.Contains("http/1.1", StringComparison.OrdinalIgnoreCase);
        if (prefersH2)
        {
            infra.HttpVersion = string.IsNullOrEmpty(infra.HttpVersion) || infra.HttpVersion == "unknown"
                ? "h2 (ALPN; HTTP/1.1 desync may not apply)"
                : $"{infra.HttpVersion} (ALPN: {alpn}; HTTP/1.1 desync may not apply)";
        }
        else if (!infra.HttpVersion.Contains(alpn, StringComparison.OrdinalIgnoreCase))
        {
            infra.HttpVersion = string.IsNullOrEmpty(infra.HttpVersion) || infra.HttpVersion == "unknown"
                ? alpn
                : $"{infra.HttpVersion} (ALPN: {alpn})";
        }
    }

    /// <summary>Fingerprint TLS ALPN without sending HTTP — probes themselves stay HTTP/1.1 (no ALPN).</summary>
    private static async Task<string?> ProbeAlpnAsync(Uri uri, int timeoutMs, CancellationToken ct)
    {
        if (!uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            return null;

        try
        {
            var host = uri.Host;
            var port = uri.Port > 0 ? uri.Port : 443;
            using var tcp = new TcpClient();
            tcp.SendTimeout = timeoutMs;
            tcp.ReceiveTimeout = timeoutMs;
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(timeoutMs);
            await tcp.ConnectAsync(host, port, connectCts.Token);
            await using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 |
                                      System.Security.Authentication.SslProtocols.Tls13,
                ApplicationProtocols =
                [
                    SslApplicationProtocol.Http2,
                    SslApplicationProtocol.Http11
                ]
            }, connectCts.Token);
            var negotiated = ssl.NegotiatedApplicationProtocol;
            if (negotiated.Protocol.Length == 0)
                return null;
            return Encoding.ASCII.GetString(negotiated.Protocol.Span);
        }
        catch
        {
            return null;
        }
    }

    private static async Task<RawResponse> SendRawRequestAsync(Uri uri, string request, int timeoutMs, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var host = uri.Host;
            var port = uri.Port > 0 ? uri.Port : (uri.Scheme == "https" ? 443 : 80);
            var isHttps = uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);

            using var tcp = new TcpClient();
            tcp.SendTimeout = timeoutMs;
            tcp.ReceiveTimeout = timeoutMs;

            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(timeoutMs);
            await tcp.ConnectAsync(host, port, connectCts.Token);

            Stream stream = tcp.GetStream();

            if (isHttps)
            {
                var sslStream = new SslStream(stream, false, (_, _, _, _) => true);
                await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = host,
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                }, connectCts.Token);
                stream = sslStream;
            }

            var requestBytes = Encoding.ASCII.GetBytes(request);
            await stream.WriteAsync(requestBytes, ct);
            await stream.FlushAsync(ct);

            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            readCts.CancelAfter(timeoutMs);

            var rawBytes = await ReadHttpMessageBytesAsync(stream, readCts.Token);
            sw.Stop();

            if (rawBytes.Length == 0)
            {
                return new RawResponse
                {
                    TimedOut = readCts.IsCancellationRequested || ct.IsCancellationRequested,
                    DurationMs = sw.ElapsedMilliseconds,
                };
            }

            return ParseRawResponse(Encoding.ASCII.GetString(rawBytes), sw.ElapsedMilliseconds);
        }
        catch (OperationCanceledException)
        {
            sw.Stop();
            return new RawResponse { TimedOut = true, DurationMs = sw.ElapsedMilliseconds };
        }
        catch (Exception ex)
        {
            sw.Stop();
            return new RawResponse { Error = ex.Message, DurationMs = sw.ElapsedMilliseconds };
        }
    }

    /// <summary>
    /// Read one HTTP response: headers, then Content-Length / chunked / until close.
    /// Stops after a complete message so keep-alive origins do not hang until timeoutMs.
    /// </summary>
    private static async Task<byte[]> ReadHttpMessageBytesAsync(Stream stream, CancellationToken ct)
    {
        const int cap = 128 * 1024;
        var ms = new MemoryStream();
        var buffer = new byte[8192];

        try
        {
            while (ms.Length < cap)
            {
                int n = await stream.ReadAsync(buffer, ct);
                if (n == 0) break;
                ms.Write(buffer, 0, n);
                if (IndexOfHeaderEnd(ms) >= 0) break;
            }

            int headerEnd = IndexOfHeaderEnd(ms);
            if (headerEnd < 0)
                return ms.ToArray();

            int bodyStart = headerEnd + 4;
            var headerText = Encoding.ASCII.GetString(ms.GetBuffer(), 0, headerEnd);
            bool chunked = HeaderBlockHasChunked(headerText);
            long? contentLength = TryHeaderBlockContentLength(headerText);

            if (chunked)
            {
                while (ms.Length < cap && !ChunkedBodyComplete(ms, bodyStart))
                {
                    int n = await stream.ReadAsync(buffer, ct);
                    if (n == 0) break;
                    ms.Write(buffer, 0, n);
                }
            }
            else if (contentLength is long cl && cl >= 0)
            {
                long need = bodyStart + cl;
                while (ms.Length < need && ms.Length < cap)
                {
                    int n = await stream.ReadAsync(buffer, ct);
                    if (n == 0) break;
                    ms.Write(buffer, 0, n);
                }
            }
            else
            {
                while (ms.Length < cap)
                {
                    int n = await stream.ReadAsync(buffer, ct);
                    if (n == 0) break;
                    ms.Write(buffer, 0, n);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Partial response — caller decides TimedOut vs parse.
        }

        return ms.ToArray();
    }

    private static int IndexOfHeaderEnd(MemoryStream ms)
    {
        var buf = ms.GetBuffer();
        int len = (int)ms.Length;
        for (int i = 0; i <= len - 4; i++)
        {
            if (buf[i] == (byte)'\r' && buf[i + 1] == (byte)'\n' &&
                buf[i + 2] == (byte)'\r' && buf[i + 3] == (byte)'\n')
                return i;
        }
        return -1;
    }

    private static bool HeaderBlockHasChunked(string headerBlock)
    {
        foreach (var line in headerBlock.Split("\r\n"))
        {
            var colon = line.IndexOf(':');
            if (colon <= 0) continue;
            var name = line[..colon].Trim();
            if (!name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
                continue;
            return line[(colon + 1)..].Contains("chunked", StringComparison.OrdinalIgnoreCase);
        }
        return false;
    }

    private static long? TryHeaderBlockContentLength(string headerBlock)
    {
        foreach (var line in headerBlock.Split("\r\n"))
        {
            var colon = line.IndexOf(':');
            if (colon <= 0) continue;
            var name = line[..colon].Trim();
            if (!name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                continue;
            var raw = line[(colon + 1)..].Trim();
            var comma = raw.IndexOf(',');
            if (comma >= 0)
                raw = raw[..comma].Trim();
            if (long.TryParse(raw, out var n) && n >= 0)
                return n;
        }
        return null;
    }

    private static bool ChunkedBodyComplete(MemoryStream ms, int bodyStart)
    {
        var buf = ms.GetBuffer();
        int len = (int)ms.Length;
        if (len - bodyStart < 5)
            return false;
        // Last-chunk is 0\r\n\r\n (optionally after previous chunk CRLF).
        for (int i = Math.Max(bodyStart, len - 16); i <= len - 5; i++)
        {
            if (buf[i] == (byte)'0' && buf[i + 1] == (byte)'\r' && buf[i + 2] == (byte)'\n' &&
                buf[i + 3] == (byte)'\r' && buf[i + 4] == (byte)'\n')
                return true;
        }
        return false;
    }

    private static RawResponse ParseRawResponse(string raw, long durationMs)
    {
        if (string.IsNullOrEmpty(raw))
            return new RawResponse { Error = "Empty response", DurationMs = durationMs };

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var statusCode = 0;
        var statusLine = "";
        var body = "";

        var headerEnd = raw.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var headerSection = headerEnd >= 0 ? raw[..headerEnd] : raw;
        body = headerEnd >= 0 ? raw[(headerEnd + 4)..] : "";

        var lines = headerSection.Split("\r\n");
        if (lines.Length > 0)
        {
            statusLine = lines[0];
            var statusMatch = Regex.Match(statusLine, @"HTTP/[\d.]+\s+(\d+)");
            if (statusMatch.Success)
                statusCode = int.Parse(statusMatch.Groups[1].Value);
        }

        for (int i = 1; i < lines.Length; i++)
        {
            var colonIdx = lines[i].IndexOf(':');
            if (colonIdx <= 0) continue;
            var name = lines[i][..colonIdx].Trim();
            var value = lines[i][(colonIdx + 1)..].Trim();
            if (headers.ContainsKey(name))
                headers[name] += ", " + value;
            else
                headers[name] = value;
        }

        return new RawResponse
        {
            StatusCode = statusCode,
            StatusLine = statusLine,
            Headers = headers,
            Body = body.Length > 8192 ? body[..8192] : body,
            DurationMs = durationMs,
            RawResponse_ = raw.Length > 16384 ? raw[..16384] : raw,
        };
    }

    private static void ParseInfrastructure(RawResponse baseline, InfrastructureInfo infra)
    {
        var versionMatch = Regex.Match(baseline.StatusLine, @"HTTP/([\d.]+)");
        infra.HttpVersion = versionMatch.Success ? versionMatch.Groups[1].Value : "unknown";

        if (baseline.Headers.TryGetValue("Server", out var server))
            infra.ServerHeader = server;

        if (baseline.Headers.TryGetValue("Via", out var via))
        {
            infra.ViaHeaders.Add(via);
            infra.ProxyLikely = true;
            infra.ProxyEvidence.Add($"Via header: {via}");
        }

        if (baseline.Headers.TryGetValue("X-Forwarded-For", out _))
        {
            infra.ProxyLikely = true;
            infra.ProxyEvidence.Add("X-Forwarded-For header present");
        }

        if (baseline.Headers.TryGetValue("X-Forwarded-Host", out _))
        {
            infra.ProxyLikely = true;
            infra.ProxyEvidence.Add("X-Forwarded-Host header present");
        }

        if (baseline.Headers.TryGetValue("X-Cache", out var xcache))
        {
            infra.ProxyLikely = true;
            infra.ProxyEvidence.Add($"X-Cache header: {xcache}");
        }

        if (baseline.Headers.TryGetValue("CF-RAY", out _))
        {
            infra.ProxyLikely = true;
            infra.ProxyEvidence.Add("Cloudflare detected (CF-RAY header)");
        }

        if (baseline.Headers.TryGetValue("X-Amzn-RequestId", out _) ||
            baseline.Headers.TryGetValue("X-Amz-Cf-Id", out _))
        {
            infra.ProxyLikely = true;
            infra.ProxyEvidence.Add("AWS infrastructure detected");
        }

        if (infra.ServerHeader != null)
        {
            var cdnMarkers = new[] { "cloudflare", "cloudfront", "fastly", "akamai" };
            foreach (var c in cdnMarkers)
            {
                if (!infra.ServerHeader.Contains(c, StringComparison.OrdinalIgnoreCase))
                    continue;
                infra.ProxyLikely = true;
                infra.ProxyEvidence.Add($"Server header indicates CDN / edge ({c})");
                break;
            }
        }

        if (infra.ServerHeader != null)
        {
            var proxyIndicators = new[] { "nginx", "apache", "haproxy", "varnish", "squid", "envoy", "traefik", "BigIP", "BIG-IP", "F5" };
            foreach (var indicator in proxyIndicators)
            {
                if (infra.ServerHeader.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                {
                    if (!infra.ProxyLikely)
                    {
                        infra.ProxyLikely = true;
                        infra.ProxyEvidence.Add($"Server header ({infra.ServerHeader}) commonly used as reverse proxy");
                    }
                    break;
                }
            }
        }

        if (baseline.Headers.TryGetValue("Set-Cookie", out var setCookie) &&
            setCookie.Contains("TS01", StringComparison.OrdinalIgnoreCase))
        {
            infra.ProxyLikely = true;
            infra.ProxyEvidence.Add("F5 BIG-IP detected (TS01* session cookie)");
        }
    }

    #endregion
}
