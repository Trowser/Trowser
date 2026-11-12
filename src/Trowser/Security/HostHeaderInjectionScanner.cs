using System.Diagnostics;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Host header injection detection via raw TCP HTTP probing.
/// Tests Host override, X-Forwarded-Host, duplicate Host, port manipulation, and absolute-URL requests.
/// Compares poisoned responses against a baseline for reflected host values in redirects, links, and body text.
/// </summary>
public static class HostHeaderInjectionScanner
{
    public const string DefaultEvilHost = "evil.trowser.test";

    private static readonly string[] DefaultProbes =
    [
        "host-override",
        "x-forwarded-host",
        "x-original-host",
        "forwarded",
        "duplicate-host",
        "host-port",
        "absolute-url",
    ];

    private static readonly Regex ResetUrlPattern = new(
        @"(?i)(forgot|reset.?password|password.?reset|recover.?password|/reset|invite|magic.?link|verify.?email|send.?link|account.?recover)",
        RegexOptions.Compiled);

    #region Result types

    public sealed class HostHeaderScanResult
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public string EvilHost { get; init; } = DefaultEvilHost;
        public string CanonicalHost { get; init; } = "";
        public long ElapsedMs { get; init; }
        public string Summary { get; init; } = "";
        public int ProbesRun { get; init; }
        /// <summary>Total HTTP requests including baseline.</summary>
        public int RequestsRun { get; init; }
        public HostHeaderProbeRow Baseline { get; init; } = new();
        public List<HostHeaderProbeRow> Probes { get; init; } = [];
        public List<HostHeaderFinding> Findings { get; init; } = [];

        public string Format()
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== Host Header Injection Scan ===");
            sb.AppendLine($"URL: {Url}");
            sb.AppendLine($"Method: {Method}");
            sb.AppendLine($"Evil host marker: {EvilHost}");
            sb.AppendLine($"Canonical host: {CanonicalHost}");
            sb.AppendLine($"Probes: {ProbesRun} | Requests: {RequestsRun} (incl. baseline) | Elapsed: {ElapsedMs}ms");
            sb.AppendLine($"Findings: {Findings.Count}");
            sb.AppendLine();

            if (Findings.Count > 0)
            {
                sb.AppendLine("--- Findings ---");
                foreach (var f in Findings)
                {
                    sb.AppendLine($"[{f.Severity.ToUpperInvariant()}] {f.Probe} — {f.ReflectionType}");
                    sb.AppendLine($"  {f.Description}");
                    sb.AppendLine($"  Evidence: {f.Evidence}");
                    if (!string.IsNullOrEmpty(f.Remediation))
                        sb.AppendLine($"  Remediation: {f.Remediation}");
                    sb.AppendLine();
                }
            }

            sb.AppendLine("--- Probes ---");
            sb.AppendLine($"baseline  HTTP {Baseline.Status}  {Baseline.DurationMs}ms" +
                          (Baseline.Error != null ? $"  error: {Baseline.Error}" : ""));
            foreach (var p in Probes)
            {
                var flag = p.Reflected ? " REFLECTED" : "";
                sb.AppendLine($"{p.Probe,-18} HTTP {p.Status,-5} {p.DurationMs,5}ms  severity={p.Severity}{flag}");
                if (p.ReflectionLocations.Count > 0)
                    sb.AppendLine($"  locations: {string.Join(", ", p.ReflectionLocations)}");
                if (p.Error != null)
                    sb.AppendLine($"  error: {p.Error}");
            }

            sb.AppendLine();
            sb.AppendLine(Summary);
            sb.AppendLine("==================================");
            return sb.ToString();
        }
    }

    public sealed class HostHeaderProbeRow
    {
        public string Probe { get; init; } = "baseline";
        public int Status { get; init; }
        public long DurationMs { get; init; }
        public bool Reflected { get; init; }
        public string Severity { get; init; } = "none";
        public List<string> ReflectionLocations { get; init; } = [];
        public string? LocationHeader { get; init; }
        public string? EvidenceSnippet { get; init; }
        public string? Error { get; init; }
        public string? RawRequest { get; init; }
    }

    public sealed class HostHeaderFinding
    {
        public string Probe { get; init; } = "";
        public string Severity { get; init; } = "";
        public string ReflectionType { get; init; } = "";
        public string Description { get; init; } = "";
        public string Evidence { get; init; } = "";
        public string Remediation { get; init; } = "";
    }

    public sealed class DiscoveredTarget
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public string? Body { get; init; }
        public string? ContentType { get; init; }
        public string Reason { get; init; } = "";
        public DateTime Timestamp { get; init; }
    }

    public sealed class HostHeaderScanOptions
    {
        public required string Url { get; init; }
        public string Method { get; init; } = "GET";
        public string? Body { get; init; }
        public string? ContentType { get; init; }
        public string EvilHost { get; init; } = DefaultEvilHost;
        public IReadOnlyList<string>? Probes { get; init; }
        public string? CookieHeader { get; init; }
        public Dictionary<string, string>? ExtraHeaders { get; init; }
        public int TimeoutMs { get; init; } = 15000;
        public int MaxBodyChars { get; init; } = 32768;
    }

    #endregion

    #region Public API

    public static string GetTargetDedupKey(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url.Trim().ToLowerInvariant();

        var authority = uri.IsDefaultPort ? uri.Host : $"{uri.Host}:{uri.Port}";
        return $"{uri.Scheme}://{authority}{uri.AbsolutePath}".ToLowerInvariant();
    }

    public static List<DiscoveredTarget> DiscoverTargetsFromNetwork(
        IEnumerable<NetworkEntry> entries,
        string? scopeHost = null,
        int maxTargets = 5)
    {
        maxTargets = Math.Clamp(maxTargets, 1, 20);
        var byPath = new Dictionary<string, DiscoveredTarget>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries.OrderByDescending(e => e.Timestamp))
        {
            if (string.IsNullOrWhiteSpace(entry.Url) || !Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri))
                continue;

            if (!string.IsNullOrEmpty(scopeHost) &&
                !uri.Host.Equals(scopeHost, StringComparison.OrdinalIgnoreCase))
                continue;

            var pathQuery = uri.PathAndQuery;
            if (!ResetUrlPattern.IsMatch(pathQuery) && !ResetUrlPattern.IsMatch(entry.Url))
                continue;

            var key = GetTargetDedupKey(entry.Url);
            var contentType = entry.RequestHeaders
                .FirstOrDefault(h => h.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)).Value;

            var candidate = new DiscoveredTarget
            {
                Url = entry.Url,
                Method = string.IsNullOrWhiteSpace(entry.Method) ? "GET" : entry.Method.ToUpperInvariant(),
                Body = entry.RequestBody,
                ContentType = contentType,
                Reason = "Network log match (password-reset / invite / recovery pattern)",
                Timestamp = entry.Timestamp,
            };

            if (!byPath.TryGetValue(key, out var existing) || PreferDiscoveredTarget(candidate, existing))
                byPath[key] = candidate;
        }

        return byPath.Values
            .OrderByDescending(t => t.Timestamp)
            .Take(maxTargets)
            .ToList();
    }

    private static int MethodRank(string method) => method.ToUpperInvariant() switch
    {
        "POST" => 4,
        "PUT" or "PATCH" => 3,
        "DELETE" => 2,
        "GET" => 1,
        _ => 0,
    };

    private static bool PreferDiscoveredTarget(DiscoveredTarget candidate, DiscoveredTarget existing)
    {
        var cm = MethodRank(candidate.Method);
        var em = MethodRank(existing.Method);
        if (cm != em)
            return cm > em;

        var cHasBody = !string.IsNullOrEmpty(candidate.Body);
        var eHasBody = !string.IsNullOrEmpty(existing.Body);
        if (cHasBody != eHasBody)
            return cHasBody;

        return candidate.Timestamp > existing.Timestamp;
    }

    public static async Task<HostHeaderScanResult> RunAsync(
        HostHeaderScanOptions options,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var uri = new Uri(options.Url);
        var method = string.IsNullOrWhiteSpace(options.Method) ? "GET" : options.Method.Trim().ToUpperInvariant();
        var evilHost = string.IsNullOrWhiteSpace(options.EvilHost) ? DefaultEvilHost : options.EvilHost.Trim();
        var canonicalHost = FormatHostHeader(uri);
        var timeoutMs = Math.Clamp(options.TimeoutMs, 3000, 30000);
        var maxBody = Math.Clamp(options.MaxBodyChars, 4096, 131072);

        var enabledProbes = ResolveProbes(options.Probes);
        var isResetLike = ResetUrlPattern.IsMatch(uri.PathAndQuery) || ResetUrlPattern.IsMatch(options.Url);

        var baselineRequest = BuildRequest(uri, method, canonicalHost, canonicalHost, "baseline",
            options.Body, options.ContentType, options.CookieHeader, options.ExtraHeaders, evilHost);
        var baselineResp = await SendRawRequestAsync(uri, baselineRequest, timeoutMs, ct);

        var baselineRow = new HostHeaderProbeRow
        {
            Probe = "baseline",
            Status = baselineResp.StatusCode,
            DurationMs = baselineResp.DurationMs,
            Error = baselineResp.Error,
            LocationHeader = baselineResp.Headers.GetValueOrDefault("Location"),
            RawRequest = baselineRequest,
        };

        var probes = new List<HostHeaderProbeRow>();
        var findings = new List<HostHeaderFinding>();

        if (baselineResp.Error != null)
        {
            sw.Stop();
            return new HostHeaderScanResult
            {
                Url = options.Url,
                Method = method,
                EvilHost = evilHost,
                CanonicalHost = canonicalHost,
                ElapsedMs = sw.ElapsedMilliseconds,
                Summary = $"Could not connect for baseline request: {baselineResp.Error}",
                ProbesRun = 0,
                RequestsRun = 1,
                Baseline = baselineRow,
                Probes = probes,
                Findings = findings,
            };
        }

        foreach (var probeId in enabledProbes)
        {
            ct.ThrowIfCancellationRequested();
            var rawRequest = BuildRequest(uri, method, canonicalHost, canonicalHost, probeId,
                options.Body, options.ContentType, options.CookieHeader, options.ExtraHeaders, evilHost);
            var resp = await SendRawRequestAsync(uri, rawRequest, timeoutMs, ct);

            var hits = AnalyzeReflection(baselineResp, resp, evilHost, canonicalHost, isResetLike);
            var row = new HostHeaderProbeRow
            {
                Probe = probeId,
                Status = resp.StatusCode,
                DurationMs = resp.DurationMs,
                Error = resp.Error,
                Reflected = hits.Count > 0,
                Severity = hits.Count > 0 ? hits.Max(h => SeverityRank(h.Severity)) switch
                {
                    >= 3 => "high",
                    2 => "medium",
                    _ => "low",
                } : "none",
                ReflectionLocations = hits.Select(h => h.ReflectionType).Distinct().ToList(),
                LocationHeader = resp.Headers.GetValueOrDefault("Location"),
                EvidenceSnippet = hits.FirstOrDefault()?.Evidence,
                RawRequest = rawRequest,
            };
            probes.Add(row);

            foreach (var hit in hits)
            {
                findings.Add(new HostHeaderFinding
                {
                    Probe = probeId,
                    Severity = hit.Severity,
                    ReflectionType = hit.ReflectionType,
                    Description = hit.Description,
                    Evidence = hit.Evidence,
                    Remediation = hit.Remediation,
                });
            }
        }

        sw.Stop();
        var summary = BuildSummary(findings, evilHost);

        return new HostHeaderScanResult
        {
            Url = options.Url,
            Method = method,
            EvilHost = evilHost,
            CanonicalHost = canonicalHost,
            ElapsedMs = sw.ElapsedMilliseconds,
            Summary = summary,
            ProbesRun = probes.Count,
            RequestsRun = probes.Count + 1,
            Baseline = baselineRow,
            Probes = probes,
            Findings = findings,
        };
    }

    #endregion

    #region Probe construction

    private static HashSet<string> ResolveProbes(IReadOnlyList<string>? probes)
    {
        if (probes == null || probes.Count == 0 ||
            probes.Any(p => p.Equals("all", StringComparison.OrdinalIgnoreCase)))
            return DefaultProbes.ToHashSet(StringComparer.OrdinalIgnoreCase);

        return probes.ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    private static string FormatHostHeader(Uri uri) =>
        uri.IsDefaultPort ? uri.Host : $"{uri.Host}:{uri.Port}";

    private static string BuildRequest(
        Uri uri,
        string method,
        string connectHost,
        string canonicalHost,
        string probeId,
        string? body,
        string? contentType,
        string? cookieHeader,
        Dictionary<string, string>? extraHeaders,
        string evilHost)
    {
        var pathAndQuery = uri.PathAndQuery;
        var requestLine = probeId.Equals("absolute-url", StringComparison.OrdinalIgnoreCase)
            ? $"{method} {uri.Scheme}://{connectHost}{pathAndQuery} HTTP/1.1"
            : $"{method} {pathAndQuery} HTTP/1.1";

        var sb = new StringBuilder();
        sb.Append(requestLine).Append("\r\n");

        ApplyHostHeaders(sb, probeId, canonicalHost, evilHost, uri);

        sb.Append("Connection: close\r\n");
        sb.Append("User-Agent: Trowser/1.0 Host-Header-Scanner\r\n");
        sb.Append("Accept: */*\r\n");

        if (!string.IsNullOrEmpty(cookieHeader))
            sb.Append("Cookie: ").Append(cookieHeader).Append("\r\n");

        if (extraHeaders != null)
        {
            foreach (var kv in extraHeaders)
            {
                if (IsForbiddenExtraHeader(kv.Key))
                    continue;
                sb.Append(kv.Key).Append(": ").Append(kv.Value).Append("\r\n");
            }
        }

        if (!string.IsNullOrEmpty(body))
        {
            var ct = string.IsNullOrWhiteSpace(contentType) ? "application/x-www-form-urlencoded" : contentType;
            sb.Append("Content-Type: ").Append(ct).Append("\r\n");
            sb.Append("Content-Length: ").Append(Encoding.UTF8.GetByteCount(body)).Append("\r\n");
        }

        sb.Append("\r\n");
        if (!string.IsNullOrEmpty(body))
            sb.Append(body);

        return sb.ToString();
    }

    private static void ApplyHostHeaders(StringBuilder sb, string probeId, string canonicalHost, string evilHost, Uri uri)
    {
        switch (probeId.ToLowerInvariant())
        {
            case "host-override":
                sb.Append("Host: ").Append(evilHost).Append("\r\n");
                break;
            case "x-forwarded-host":
                sb.Append("Host: ").Append(canonicalHost).Append("\r\n");
                sb.Append("X-Forwarded-Host: ").Append(evilHost).Append("\r\n");
                break;
            case "x-original-host":
                sb.Append("Host: ").Append(canonicalHost).Append("\r\n");
                sb.Append("X-Original-Host: ").Append(evilHost).Append("\r\n");
                break;
            case "forwarded":
                sb.Append("Host: ").Append(canonicalHost).Append("\r\n");
                sb.Append("Forwarded: host=").Append(evilHost).Append("\r\n");
                break;
            case "duplicate-host":
                sb.Append("Host: ").Append(canonicalHost).Append("\r\n");
                sb.Append("Host: ").Append(evilHost).Append("\r\n");
                break;
            case "host-port":
                var portHost = uri.IsDefaultPort ? $"{evilHost}:9999" : $"{evilHost}:{uri.Port}";
                sb.Append("Host: ").Append(portHost).Append("\r\n");
                break;
            case "absolute-url":
                sb.Append("Host: ").Append(evilHost).Append("\r\n");
                break;
            default:
                sb.Append("Host: ").Append(canonicalHost).Append("\r\n");
                break;
        }
    }

    private static bool IsForbiddenExtraHeader(string name) =>
        name.Equals("Host", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Connection", StringComparison.OrdinalIgnoreCase);

    #endregion

    #region Reflection analysis

    private sealed class ReflectionHit
    {
        public string Severity { get; init; } = "low";
        public string ReflectionType { get; init; } = "";
        public string Description { get; init; } = "";
        public string Evidence { get; init; } = "";
        public string Remediation { get; init; } = "";
    }

    private static List<ReflectionHit> AnalyzeReflection(
        RawResponse baseline,
        RawResponse probe,
        string evilHost,
        string canonicalHost,
        bool isResetLike)
    {
        if (probe.Error != null)
            return [];

        var hits = new List<ReflectionHit>();
        var evilLower = evilHost.ToLowerInvariant();
        var baselineBody = TruncateBody(baseline.Body);
        var probeBody = TruncateBody(probe.Body);

        CheckHeaderReflection(hits, "Location", baseline.Headers, probe.Headers, evilHost, evilLower,
            isRedirect: true, isResetLike);
        CheckHeaderReflection(hits, "Content-Location", baseline.Headers, probe.Headers, evilHost, evilLower,
            isRedirect: false, isResetLike);
        CheckHeaderReflection(hits, "Refresh", baseline.Headers, probe.Headers, evilHost, evilLower,
            isRedirect: true, isResetLike);

        if (ContainsHostMarker(probeBody, evilHost) && !ContainsHostMarker(baselineBody, evilHost))
        {
            var linkMatch = Regex.Match(probeBody,
                $@"(?i)(href|src|action)\s*=\s*[""'][^""']*{Regex.Escape(evilHost)}[^""']*[""']");
            if (linkMatch.Success)
            {
                hits.Add(new ReflectionHit
                {
                    Severity = isResetLike ? "high" : "medium",
                    ReflectionType = "body-link",
                    Description = "Poisoned host appears in an HTML link or form action.",
                    Evidence = TrimSnippet(linkMatch.Value),
                    Remediation = "Build absolute URLs from a server-side allowlist; never trust Host or X-Forwarded-* headers.",
                });
            }
            else if (Regex.IsMatch(probeBody, $@"(?i)https?://{Regex.Escape(evilHost)}", RegexOptions.None))
            {
                hits.Add(new ReflectionHit
                {
                    Severity = isResetLike ? "high" : "medium",
                    ReflectionType = "body-url",
                    Description = "Poisoned host appears in response body as a URL.",
                    Evidence = TrimSnippet(ExtractUrlSnippet(probeBody, evilHost)),
                    Remediation = "Validate Host against an allowlist before generating outbound links or emails.",
                });
            }
            else
            {
                hits.Add(new ReflectionHit
                {
                    Severity = "low",
                    ReflectionType = "body-text",
                    Description = "Poisoned host string reflected in response body (may be benign echo).",
                    Evidence = TrimSnippet(ExtractContext(probeBody, evilHost)),
                    Remediation = "Confirm whether reflected host influences password-reset links, redirects, or cache keys.",
                });
            }
        }

        return hits;
    }

    private static void CheckHeaderReflection(
        List<ReflectionHit> hits,
        string headerName,
        Dictionary<string, string> baselineHeaders,
        Dictionary<string, string> probeHeaders,
        string evilHost,
        string evilLower,
        bool isRedirect,
        bool isResetLike)
    {
        if (!probeHeaders.TryGetValue(headerName, out var probeVal))
            return;

        baselineHeaders.TryGetValue(headerName, out var baselineVal);
        if (!probeVal.Contains(evilHost, StringComparison.OrdinalIgnoreCase))
            return;
        if (baselineVal != null && baselineVal.Contains(evilHost, StringComparison.OrdinalIgnoreCase))
            return;

        hits.Add(new ReflectionHit
        {
            Severity = isRedirect ? (isResetLike ? "high" : "high") : "medium",
            ReflectionType = headerName.ToLowerInvariant() + "-header",
            Description = isRedirect
                ? $"Poisoned host reflected in {headerName} header — open redirect or cache poisoning risk."
                : $"Poisoned host reflected in {headerName} header.",
            Evidence = TrimSnippet(probeVal),
            Remediation = "Reject unexpected Host / X-Forwarded-Host values; use configured canonical base URL for redirects.",
        });
    }

    private static bool ContainsHostMarker(string text, string evilHost) =>
        text.Contains(evilHost, StringComparison.OrdinalIgnoreCase);

    private static string TruncateBody(string body) =>
        body.Length <= 32768 ? body : body[..32768];

    private static string ExtractUrlSnippet(string body, string evilHost)
    {
        var match = Regex.Match(body, $@"(?i)https?://[^\s""'<>]*{Regex.Escape(evilHost)}[^\s""'<>]*");
        return match.Success ? match.Value : evilHost;
    }

    private static string ExtractContext(string body, string marker)
    {
        var idx = body.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return marker;
        var start = Math.Max(0, idx - 40);
        var len = Math.Min(body.Length - start, marker.Length + 80);
        return body.Substring(start, len);
    }

    private static string TrimSnippet(string s) =>
        s.Length <= 200 ? s : s[..197] + "...";

    private static int SeverityRank(string severity) => severity.ToLowerInvariant() switch
    {
        "high" or "critical" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    };

    private static string BuildSummary(List<HostHeaderFinding> findings, string evilHost)
    {
        if (findings.Count == 0)
            return $"No host header reflection detected for marker '{evilHost}'. Server may validate Host correctly — manual testing of password-reset email links is still recommended.";

        var high = findings.Count(f => f.Severity.Equals("high", StringComparison.OrdinalIgnoreCase));
        var medium = findings.Count(f => f.Severity.Equals("medium", StringComparison.OrdinalIgnoreCase));

        if (high > 0)
            return $"CRITICAL: {high} high-severity reflection(s) detected with marker '{evilHost}'. Likely host header injection — verify password-reset links and redirect targets.";

        if (medium > 0)
            return $"{medium} medium-severity reflection(s) detected. Review link generation and redirect logic.";

        return $"{findings.Count} low-severity reflection(s). Confirm exploitability manually.";
    }

    #endregion

    #region Raw TCP

    private sealed class RawResponse
    {
        public int StatusCode { get; init; }
        public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        public string Body { get; init; } = "";
        public long DurationMs { get; init; }
        public string? Error { get; init; }
    }

    private static async Task<RawResponse> SendRawRequestAsync(Uri uri, string request, int timeoutMs, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var host = uri.Host;
            var port = uri.Port > 0 ? uri.Port : uri.Scheme == "https" ? 443 : 80;
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
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 |
                                          System.Security.Authentication.SslProtocols.Tls13,
                }, connectCts.Token);
                stream = sslStream;
            }

            var requestBytes = Encoding.UTF8.GetBytes(request);
            await stream.WriteAsync(requestBytes, ct);
            await stream.FlushAsync(ct);

            var responseBuffer = new byte[65536];
            var responseBuilder = new StringBuilder();
            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            readCts.CancelAfter(timeoutMs);

            try
            {
                int bytesRead;
                while ((bytesRead = await stream.ReadAsync(responseBuffer, readCts.Token)) > 0)
                {
                    responseBuilder.Append(Encoding.UTF8.GetString(responseBuffer, 0, bytesRead));
                    if (responseBuilder.Length > 256 * 1024) break;
                }
            }
            catch (OperationCanceledException) when (responseBuilder.Length == 0)
            {
                sw.Stop();
                return new RawResponse { Error = "Timed out waiting for response", DurationMs = sw.ElapsedMilliseconds };
            }

            sw.Stop();
            return ParseRawResponse(responseBuilder.ToString(), sw.ElapsedMilliseconds);
        }
        catch (OperationCanceledException)
        {
            sw.Stop();
            return new RawResponse { Error = "Timed out", DurationMs = sw.ElapsedMilliseconds };
        }
        catch (Exception ex)
        {
            sw.Stop();
            return new RawResponse { Error = ex.Message, DurationMs = sw.ElapsedMilliseconds };
        }
    }

    private static RawResponse ParseRawResponse(string raw, long durationMs)
    {
        if (string.IsNullOrEmpty(raw))
            return new RawResponse { Error = "Empty response", DurationMs = durationMs };

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var statusCode = 0;
        var body = "";

        var headerEnd = raw.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var headerSection = headerEnd >= 0 ? raw[..headerEnd] : raw;
        body = headerEnd >= 0 ? raw[(headerEnd + 4)..] : "";

        var lines = headerSection.Split("\r\n");
        if (lines.Length > 0)
        {
            var statusMatch = Regex.Match(lines[0], @"HTTP/[\d.]+\s+(\d+)");
            if (statusMatch.Success)
                statusCode = int.Parse(statusMatch.Groups[1].Value);
        }

        for (var i = 1; i < lines.Length; i++)
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
            Headers = headers,
            Body = body,
            DurationMs = durationMs,
        };
    }

    #endregion
}
