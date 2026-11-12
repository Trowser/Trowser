using System.Net;
using System.Net.Http;

namespace Trowser.Security;

/// <summary>
/// One row from probing an HTTP method against a URL (same semantics as POST /api/security/methods).
/// </summary>
public sealed class HttpMethodsProbeRow
{
    public string Method { get; init; } = "";
    public int Status { get; init; }
    public string StatusText { get; init; } = "";
    public bool Allowed { get; init; }
    public string? Security { get; init; }
    public string? AllowHeader { get; init; }
    public string? Error { get; init; }
}

/// <summary>
/// Result of GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD/TRACE probes against a document URL.
/// </summary>
public sealed class HttpMethodsSecurityResult
{
    public string Url { get; init; } = "";
    public List<HttpMethodsProbeRow> Results { get; init; } = [];
    public List<string> AllowedMethods { get; init; } = [];
    public List<string> SecurityIssues { get; init; } = [];

    public int SecurityIssueCount => SecurityIssues.Count;

    public string Format(bool includeDetails = true)
    {
        var lines = new List<string>
        {
            "=== HTTP Methods Security Probe ===",
            $"URL: {Url}",
            "",
            $"Allowed methods: {(AllowedMethods.Count == 0 ? "(none)" : string.Join(", ", AllowedMethods))}",
            $"Security issues: {SecurityIssues.Count}",
        };

        if (SecurityIssues.Count > 0)
        {
            lines.Add("");
            foreach (var issue in SecurityIssues)
                lines.Add($"  ! {issue}");
        }

        if (includeDetails && Results.Count > 0)
        {
            lines.Add("");
            lines.Add("--- Per-method ---");
            foreach (var r in Results)
            {
                var extra = r.Security != null ? $" [{r.Security}]" : "";
                var err = r.Error != null ? $"  error: {r.Error}" : "";
                var allow = r.AllowHeader != null ? $"  Allow: {r.AllowHeader}" : "";
                lines.Add(
                    $"{r.Method,-8} {(r.Status == 0 ? "---" : r.Status.ToString()),-5} allowed={r.Allowed,-5}{extra}{err}");
                if (!string.IsNullOrEmpty(allow))
                    lines.Add(allow);
            }
        }

        lines.Add("===================================");
        return string.Join(Environment.NewLine, lines);
    }
}

/// <summary>
/// Server-side HTTP method probing (not browser fetch) — same behavior as the REST API handler.
/// </summary>
public static class HttpMethodsSecurityProbe
{
    private static readonly string[] Methods =
 ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"];

    public static async Task<HttpMethodsSecurityResult> RunAsync(string url, TimeSpan? timeout = null)
    {
        timeout ??= TimeSpan.FromSeconds(10);
        var results = new List<HttpMethodsProbeRow>();
        SpaShellGuard.ShellFingerprint? documentShell = null;

        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        using var client = new HttpClient(handler) { Timeout = timeout.Value };

        try
        {
            using var shellMsg = new HttpRequestMessage(HttpMethod.Get, url);
            using var shellResp = await client.SendAsync(shellMsg);
            if (shellResp.IsSuccessStatusCode)
            {
                var shellBody = await shellResp.Content.ReadAsStringAsync();
                if (!string.IsNullOrWhiteSpace(shellBody))
                {
                    documentShell = new SpaShellGuard.ShellFingerprint
                    {
                        BodyHash = ComputeBodyHashPrefix(shellBody),
                        BodyLength = shellBody.Length,
                        IsHtmlShell = SpaShellGuard.IsSpaHtmlShell(shellBody)
                    };
                }
            }
        }
        catch
        {
            // Origin shell capture is best-effort; method probes still run.
        }

        foreach (var method in Methods)
        {
            try
            {
                using var msg = new HttpRequestMessage(new HttpMethod(method), url);
                using var resp = await client.SendAsync(msg);

                var allowed = resp.StatusCode != HttpStatusCode.MethodNotAllowed
 && resp.StatusCode != HttpStatusCode.NotImplemented;

                string? security = null;
                var status = (int)resp.StatusCode;
                string? body = null;

                if (method is "PUT" or "DELETE" or "PATCH" or "POST")
                {
                    body = resp.Content != null ? await resp.Content.ReadAsStringAsync() : null;
                }

                if (method == "TRACE")
                {
                    body ??= resp.Content != null ? await resp.Content.ReadAsStringAsync() : null;
                    if (TraceMethodAnalyzer.IsTraceEnabled(status, body, url))
                        security = "TRACE enabled - Cross-Site Tracing (XST) risk. Disable TRACE on the server.";
                }

                if (method is "PUT" or "DELETE" or "PATCH" && status >= 500 && status < 600)
                {
                    if (status != 501)
                        security = $"{method} returned {status} - method is routed (not 405) but server error; may indicate broken authorization or unhandled mutating request.";
                }

                if (method is "DELETE" or "PUT" && status >= 200 && status < 300)
                {
                    var responseBody = body ?? "";
                    if (!SpaShellGuard.LooksLikeSpaShellDuplicate(responseBody, status, documentShell, requireOriginHashMatch: true))
                    {
                        if (method == "DELETE")
                            security = "DELETE allowed - verify this is intentional and requires proper authorization.";
                        else
                            security = "PUT allowed - verify this is intentional and requires proper authorization.";
                    }
                }

                string? allowHeader = null;
                if (method == "OPTIONS" && resp.Headers.TryGetValues("Allow", out var allowValues))
                    allowHeader = string.Join(", ", allowValues);

                if (method == "OPTIONS" && allowHeader != null
                    && allowHeader.Contains("TRACE", StringComparison.OrdinalIgnoreCase)
                    && security == null)
                {
                    var (traceStatus, traceBody, _) = await TraceMethodAnalyzer.ProbeTraceAsync(url, timeout);
                    if (TraceMethodAnalyzer.IsTraceEnabled(traceStatus, traceBody, url, allowHeader))
                        security = "TRACE advertised in Allow header with echo response - Cross-Site Tracing (XST) risk.";
                }

                results.Add(new HttpMethodsProbeRow
                {
                    Method = method,
                    Status = status,
                    StatusText = resp.ReasonPhrase ?? "",
                    Allowed = allowed,
                    Security = security,
                    AllowHeader = allowHeader,
                });
            }
            catch (Exception ex)
            {
                results.Add(new HttpMethodsProbeRow
                {
                    Method = method,
                    Status = 0,
                    StatusText = "",
                    Allowed = false,
                    Error = ex.Message,
                });
            }
        }

        var allowedMethods = results
            .Where(r => r.Allowed)
            .Select(r => r.Method)
            .ToList();

        var securityIssues = results
            .Where(r => r.Security != null)
            .Select(r => r.Security!)
            .ToList();

        return new HttpMethodsSecurityResult
        {
            Url = url,
            Results = results,
            AllowedMethods = allowedMethods,
            SecurityIssues = securityIssues,
        };
    }

    private static string ComputeBodyHashPrefix(string body)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(body);
        var hash = System.Security.Cryptography.SHA256.HashData(bytes);
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }
}
