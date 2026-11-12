using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Broken Function Level Authorization: probe admin-shaped paths and compare privilege differentials.
/// Critical requires evidence beyond empty 2xx (API-like body or anon/low-priv deny then session accept).
/// Inspired by OWASP API Security — API5 BFLA; also influenced by pentest-ai <c>idor_authz_differential._bfla_admin</c>.
/// Issues benign mutating canaries under active mode.
/// </summary>
public static class BflaAdminProbe
{
    public sealed class ProbeOptions
    {
        public string? BaseUrl { get; set; }
        public int TimeoutMs { get; set; } = 12000;
        public int MaxEndpoints { get; set; } = 12;
        public IReadOnlyList<string>? AdminPaths { get; set; }
        public bool DiscoverFromAttackSurface { get; set; } = true;
        public IReadOnlyList<AttackSurfaceEndpoint>? Endpoints { get; set; }
    }

    public sealed class ProbeRow
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "POST";
        public int Status { get; init; }
        public string Severity { get; init; } = "info";
        public string Category { get; init; } = "bfla";
        public string Result { get; init; } = "";
        public string? BodySnippet { get; init; }
        public int? AnonStatus { get; init; }
    }

    public sealed class ProbeResult
    {
        public List<ProbeRow> Rows { get; init; } = [];
        public List<ProbeRow> Findings { get; init; } = [];
        public List<string> EndpointsProbed { get; init; } = [];
        public List<string> Summary { get; init; } = [];
    }

    public static readonly string[] DefaultAdminPaths =
    [
        "/api/admin/users", "/api/admin/products", "/api/admin/orders", "/api/admin/roles",
        "/admin/api/users", "/api/admin", "/rest/admin/application-configuration"
    ];

    private static readonly string[] ErrorMarkers =
    [
        "forbidden", "unauthorized", "access denied", "not allowed", "permission"
    ];

    private static readonly string BenignJson = """{"name":"trowser-bfla-canary","active":false}""";

    public static async Task<ProbeResult> RunAsync(
        AutomationContext ctx,
        ProbeOptions options,
        CancellationToken ct = default)
    {
        var pageUrl = options.BaseUrl ?? await ctx.GetCurrentUrl();
        if (!Uri.TryCreate(pageUrl, UriKind.Absolute, out var baseUri))
            throw new InvalidOperationException("Navigate to a page or pass baseUrl before running BFLA probe.");

        var origin = baseUri.GetLeftPart(UriPartial.Authority);
        var shell = await SpaShellGuard.CaptureOriginShellAsync(ctx, origin, options.TimeoutMs);
        var targets = new List<string>();

        if (options.AdminPaths is { Count: > 0 })
            targets.AddRange(options.AdminPaths);
        else
            targets.AddRange(DefaultAdminPaths);

        if (options.DiscoverFromAttackSurface && options.Endpoints != null)
        {
            foreach (var ep in options.Endpoints)
            {
                if (ep.UrlTemplate.Contains("admin", StringComparison.OrdinalIgnoreCase)
                    || ep.UrlTemplate.Contains("/manage", StringComparison.OrdinalIgnoreCase))
                {
                    targets.Add(ep.Url);
                }
            }
        }

        targets = targets
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .Select(t => t.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? t : origin + (t.StartsWith('/') ? t : "/" + t))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(Math.Max(1, options.MaxEndpoints))
            .ToList();

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "application/json",
            ["Accept"] = "application/json, text/plain, */*",
        };

        var rows = new List<ProbeRow>();
        var findings = new List<ProbeRow>();

        foreach (var url in targets)
        {
            ct.ThrowIfCancellationRequested();
            foreach (var method in new[] { "POST", "PUT" })
            {
                var json = await ctx.Fetch(url, method, headers, BenignJson, options.TimeoutMs);
                var (status, body, _) = ParseFetch(json);

                var anon = await SecurityProbeHttp.FetchAsync(
                    ctx, url, method, headers, BenignJson, options.TimeoutMs,
                    includeBrowserCookies: false, ct);

                var row = Classify(url, method, status, body, shell, anon.Status);
                rows.Add(row);
                if (row.Result == "bfla")
                    findings.Add(row);
            }
        }

        var summary = new List<string>();
        if (findings.Count > 0)
            summary.Add($"{findings.Count} admin-shape endpoint(s) accepted mutating requests from the current session.");
        else
            summary.Add($"Probed {targets.Count} admin path(s); no BFLA signals from current session.");

        return new ProbeResult
        {
            Rows = rows,
            Findings = findings,
            EndpointsProbed = targets,
            Summary = summary
        };
    }

    internal static ProbeRow Classify(
        string url, string method, int status, string body,
        SpaShellGuard.ShellFingerprint? shell, int anonStatus)
    {
        body ??= "";
        if (status is not (200 or 201 or 204))
        {
            return new ProbeRow
            {
                Url = url,
                Method = method,
                Status = status,
                Severity = "info",
                Category = "bfla",
                Result = "denied",
                BodySnippet = Snip(body, 300),
                AnonStatus = anonStatus
            };
        }

        if (LooksLikeError(body))
        {
            return new ProbeRow
            {
                Url = url,
                Method = method,
                Status = status,
                Severity = "info",
                Category = "bfla",
                Result = "error-page",
                BodySnippet = Snip(body, 300),
                AnonStatus = anonStatus
            };
        }

        if (SpaShellGuard.LooksLikeSpaShellDuplicate(body, status, shell))
        {
            return new ProbeRow
            {
                Url = url,
                Method = method,
                Status = status,
                Severity = "info",
                Category = "bfla",
                Result = "spa-shell",
                BodySnippet = Snip(body, 300),
                AnonStatus = anonStatus
            };
        }

        if (!SpaShellGuard.IsApiLikeResponse(body) && SpaShellGuard.IsSpaHtmlShell(body))
        {
            return new ProbeRow
            {
                Url = url,
                Method = method,
                Status = status,
                Severity = "info",
                Category = "bfla",
                Result = "spa-shell",
                BodySnippet = Snip(body, 300),
                AnonStatus = anonStatus
            };
        }

        var hasBodyEvidence = HasNonShellSuccessEvidence(status, body);
        var anonDenied = anonStatus is 401 or 403;
        var json = SpaShellGuard.IsApiLikeResponse(body);
        // Critical only for a real JSON write that anonymous callers cannot make.
        var severity = !json
            ? "low"
            : anonDenied && hasBodyEvidence
                ? "critical"
                : "high";

        return new ProbeRow
        {
            Url = url,
            Method = method,
            Status = status,
            Severity = severity,
            Category = "bfla",
            Result = "bfla",
            BodySnippet = Snip(body, 300),
            AnonStatus = anonStatus
        };
    }

    /// <summary>
    /// Empty 204 / blank bodies are weak evidence — require API-like or non-empty success body.
    /// </summary>
    private static bool HasNonShellSuccessEvidence(int status, string body)
    {
        if (status == 204 && string.IsNullOrWhiteSpace(body))
            return false;
        if (string.IsNullOrWhiteSpace(body))
            return false;
        return SpaShellGuard.IsApiLikeResponse(body) || body.Trim().Length > 0;
    }

    private static bool LooksLikeError(string body)
    {
        var lower = body.ToLowerInvariant();
        return ErrorMarkers.Any(m => lower.Contains(m, StringComparison.Ordinal));
    }

    private static (int status, string body, bool ok) ParseFetch(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var status = root.GetProperty("status").GetInt32();
            var body = root.TryGetProperty("body", out var b)
                ? b.ValueKind == JsonValueKind.String ? b.GetString() ?? "" : b.GetRawText()
                : "";
            return (status, body, true);
        }
        catch
        {
            return (0, "", false);
        }
    }

    private static string Snip(string s, int n) => s.Length <= n ? s : s[..n] + "…";
}
