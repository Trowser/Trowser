using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Forced-error / verbose-error probing: malformed requests to elicit stack traces relative to a clean baseline.
/// Framework yellow screens are verbose-error (not critical debug consoles) unless stronger console markers appear.
/// Inspired by OWASP WSTG error-handling testing; also influenced by pentest-ai <c>web.forced_error</c>.
/// </summary>
public static class ForcedErrorScanner
{
    public sealed class ScanOptions
    {
        public IReadOnlyList<string>? Urls { get; set; }
        public IReadOnlyList<string>? Payloads { get; set; }
        public int MaxEndpoints { get; set; } = 12;
        public int TimeoutMs { get; set; } = 12_000;
        public bool IncludeNetworkDiscovery { get; set; } = true;
    }

    public sealed class ScanFinding
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "POST";
        public string PayloadName { get; init; } = "";
        public string Severity { get; init; } = "medium";
        public string Category { get; init; } = "verbose-error";
        public string Marker { get; init; } = "";
        public string Title { get; init; } = "";
        public string Detail { get; init; } = "";
        public int Status { get; init; }
        public string? BodySnippet { get; init; }
    }

    public sealed class ScanResult
    {
        public List<ScanFinding> Findings { get; init; } = [];
        public List<string> Summary { get; init; } = [];
        public List<string> PayloadsUsed { get; init; } = [];
        public int EndpointsProbed { get; init; }
        public int EndpointsSkipped { get; init; }
        public bool IsClean => Findings.Count == 0;
    }

    private sealed class MalformedPayload
    {
        public string Name { get; init; } = "";
        public string? Body { get; init; }
        public IReadOnlyDictionary<string, string>? Headers { get; init; }
        public bool UseDuplicateContentType { get; init; }
    }

    private static readonly MalformedPayload[] AllPayloads =
    [
        new() { Name = "truncated_json", Body = "{\"email\":", Headers = JsonHeaders },
        new() { Name = "empty_body", Body = "", Headers = JsonHeaders },
        new() { Name = "xml_instead_of_json", Body = "<root><email>probe@example.com</email></root>", Headers = JsonHeaders },
        new() { Name = "oversized_payload", Body = "{\"data\":\"" + new string('A', 100_000) + "\"}", Headers = JsonHeaders },
        new() { Name = "invalid_charset", Body = "{}", Headers = InvalidCharsetHeaders },
        new() { Name = "null_byte_in_field", Body = "{\"email\": \"x\u0000y@example.com\"}", Headers = JsonHeaders },
        new() { Name = "duplicate_content_type", Body = "{}", UseDuplicateContentType = true },
        new() { Name = "array_instead_of_object", Body = "[1,2,3]", Headers = JsonHeaders },
        new() { Name = "nested_recursion", Body = "{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":{\"a\":1}}}}}}}", Headers = JsonHeaders },
    ];

    private static readonly Dictionary<string, string> JsonHeaders =
        new(StringComparer.OrdinalIgnoreCase) { ["Content-Type"] = "application/json" };

    private static readonly Dictionary<string, string> InvalidCharsetHeaders =
        new(StringComparer.OrdinalIgnoreCase) { ["Content-Type"] = "application/json; charset=ibm-invalid-charset" };

    private static readonly string[] GenericPostProbePaths =
    [
        "/api",
        "/api/",
        "/graphql",
        "/rest",
        "/rest/",
    ];

    public static async Task<ScanResult> RunAsync(
        AutomationContext ctx,
        ScanOptions options,
        CancellationToken ct = default)
    {
        var currentUrl = await ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var pageUri))
            throw new InvalidOperationException("Navigate to a page before running forced-error scan.");

        var origin = pageUri.GetLeftPart(UriPartial.Authority);
        var candidates = ResolveCandidates(ctx, options, origin, pageUri);
        var payloads = ResolvePayloads(options.Payloads);
        var findings = new List<ScanFinding>();
        var seenMarkers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var probed = 0;
        var skipped = 0;

        foreach (var path in candidates.Take(Math.Clamp(options.MaxEndpoints, 1, 30)))
        {
            ct.ThrowIfCancellationRequested();
            var url = path.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                ? path
                : origin + (path.StartsWith('/') ? path : "/" + path);

            var baseline = await SecurityProbeHttp.FetchAsync(
                ctx, url, "GET", null, null, options.TimeoutMs, includeBrowserCookies: true, ct);
            if (baseline.Status is 0 or 404)
            {
                skipped++;
                continue;
            }

            probed++;
            var baselineBody = baseline.Body ?? "";

            foreach (var payload in payloads)
            {
                ct.ThrowIfCancellationRequested();
                var probe = payload.UseDuplicateContentType
                    ? await SendDuplicateContentTypePostAsync(url, payload.Body ?? "{}", options.TimeoutMs, ct)
                    : await SecurityProbeHttp.FetchAsync(
                        ctx, url, "POST", payload.Headers, payload.Body, options.TimeoutMs,
                        includeBrowserCookies: true, ct);

                var classified = ClassifyTrace(probe.Body ?? "", baselineBody);
                if (classified == null)
                    continue;

                var (severity, marker) = classified.Value;
                var markerKey = $"{severity}|{marker}";
                if (!seenMarkers.Add(markerKey))
                    break;

                var isDebugConsole = severity == "critical";
                findings.Add(new ScanFinding
                {
                    Url = url,
                    Method = "POST",
                    PayloadName = payload.Name,
                    Severity = severity,
                    Category = isDebugConsole
                        ? "debug-console-leak"
                        : severity is "critical" or "high" ? "info-leak" : "verbose-error",
                    Marker = marker,
                    Title = isDebugConsole
                        ? $"Interactive debug console / SECRET leaked on {url}"
                        : $"Error handler leaks stack trace on {url}",
                    Detail = $"malformation={payload.Name} marker={Truncate(marker, 80)}",
                    Status = probe.Status,
                    BodySnippet = Truncate(probe.Body?.Replace('\r', ' ').Replace('\n', ' ') ?? "", 200)
                });
                break;
            }
        }

        var summary = new List<string>();
        if (findings.Count == 0)
            summary.Add("No stack-trace or verbose error disclosure detected on probed endpoints.");
        else
            summary.Add($"{findings.Count} verbose error / stack-trace finding(s) — review server error handling.");
        summary.Add($"Endpoints probed: {probed}, skipped (404/unreachable): {skipped}.");

        return new ScanResult
        {
            Findings = findings,
            Summary = summary,
            PayloadsUsed = payloads.Select(p => p.Name).ToList(),
            EndpointsProbed = probed,
            EndpointsSkipped = skipped
        };
    }

    private static List<MalformedPayload> ResolvePayloads(IReadOnlyList<string>? requested)
    {
        if (requested is not { Count: > 0 })
            return [.. AllPayloads];

        var wanted = new HashSet<string>(requested.Select(p => p.Trim()), StringComparer.OrdinalIgnoreCase);
        var selected = AllPayloads.Where(p => wanted.Contains(p.Name)).ToList();
        return selected.Count > 0 ? selected : [.. AllPayloads];
    }

    private static async Task<SecurityProbeHttp.FetchResult> SendDuplicateContentTypePostAsync(
        string url,
        string body,
        int timeoutMs,
        CancellationToken ct)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return new SecurityProbeHttp.FetchResult { Status = 0, Body = "" };

        var path = string.IsNullOrEmpty(uri.PathAndQuery) ? "/" : uri.PathAndQuery;
        var host = uri.Host;
        var port = uri.Port > 0 ? uri.Port : uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ? 443 : 80;
        var request =
            $"POST {path} HTTP/1.1\r\n" +
            $"Host: {host}\r\n" +
            "User-Agent: Trowser-Probe/1.0\r\n" +
            "Content-Type: application/json\r\n" +
            "Content-Type: text/plain\r\n" +
            $"Content-Length: {Encoding.UTF8.GetByteCount(body)}\r\n" +
            "Connection: close\r\n\r\n" +
            body;

        try
        {
            using var tcp = new TcpClient();
            tcp.SendTimeout = timeoutMs;
            tcp.ReceiveTimeout = timeoutMs;
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(timeoutMs);
            await tcp.ConnectAsync(host, port, connectCts.Token);

            Stream stream = tcp.GetStream();
            if (uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            {
                var ssl = new SslStream(stream, false, (_, _, _, _) => true);
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = host,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                }, connectCts.Token);
                stream = ssl;
            }

            var requestBytes = Encoding.UTF8.GetBytes(request);
            await stream.WriteAsync(requestBytes, ct);
            await stream.FlushAsync(ct);

            var buffer = new byte[65536];
            var builder = new StringBuilder();
            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            readCts.CancelAfter(timeoutMs);
            try
            {
                int read;
                while ((read = await stream.ReadAsync(buffer, readCts.Token)) > 0)
                {
                    builder.Append(Encoding.UTF8.GetString(buffer, 0, read));
                    if (builder.Length > 256 * 1024) break;
                }
            }
            catch (OperationCanceledException) when (builder.Length > 0)
            {
            }

            return ParseRawHttpResponse(builder.ToString());
        }
        catch
        {
            return new SecurityProbeHttp.FetchResult { Status = 0, Body = "" };
        }
    }

    private static SecurityProbeHttp.FetchResult ParseRawHttpResponse(string raw)
    {
        if (string.IsNullOrEmpty(raw))
            return new SecurityProbeHttp.FetchResult { Status = 0, Body = "" };

        var status = 0;
        var firstLineEnd = raw.IndexOf('\n');
        if (firstLineEnd > 0)
        {
            var parts = raw[..firstLineEnd].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2 && int.TryParse(parts[1], out var code))
                status = code;
        }

        var bodyStart = raw.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var body = bodyStart >= 0 ? raw[(bodyStart + 4)..] : "";
        return new SecurityProbeHttp.FetchResult { Status = status, Body = body };
    }

    private static List<string> ResolveCandidates(
        AutomationContext ctx,
        ScanOptions options,
        string origin,
        Uri pageUri)
    {
        var list = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string? u)
        {
            if (string.IsNullOrWhiteSpace(u)) return;
            var normalized = u.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                ? u
                : origin + (u.StartsWith('/') ? u : "/" + u);
            if (seen.Add(normalized))
                list.Add(normalized);
        }

        if (options.Urls is { Count: > 0 })
        {
            foreach (var u in options.Urls)
                Add(u);
            return list;
        }

        if (options.IncludeNetworkDiscovery)
        {
            foreach (var e in ctx.Network.Entries)
            {
                if (e.Method is not ("POST" or "PUT" or "PATCH")) continue;
                // Include 5xx — those endpoints already leak errors and are prime forced-error targets.
                if (e.StatusCode <= 0) continue;
                var ct = e.ContentType ?? "";
                var reqCt = "";
                if (e.RequestHeaders != null)
                {
                    e.RequestHeaders.TryGetValue("Content-Type", out reqCt);
                    reqCt ??= e.RequestHeaders.GetValueOrDefault("content-type") ?? "";
                }

                var isJson = ct.Contains("json", StringComparison.OrdinalIgnoreCase)
                             || reqCt.Contains("json", StringComparison.OrdinalIgnoreCase)
                             || (e.RequestBody?.TrimStart().StartsWith('{') ?? false);
                var isForm = reqCt.Contains("form-urlencoded", StringComparison.OrdinalIgnoreCase)
                             || (e.RequestBody?.Contains('=') == true && e.RequestBody.Contains('&'));
                if (!isJson && !isForm)
                    continue;
                if (!string.IsNullOrEmpty(e.Url) && Uri.TryCreate(e.Url, UriKind.Absolute, out var u)
                    && string.Equals(u.Host, pageUri.Host, StringComparison.OrdinalIgnoreCase))
                    Add(e.Url);
            }
        }

        // Also probe the current document path — MPA apps often debug-crash on the page itself.
        Add(pageUri.GetLeftPart(UriPartial.Path));

        foreach (var p in GenericPostProbePaths)
            Add(p);

        return list;
    }

    private static (string Severity, string Marker)? ClassifyTrace(string body, string baseline) =>
        StackTraceHeuristics.ClassifyRelativeToBaseline(body, baseline);

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
