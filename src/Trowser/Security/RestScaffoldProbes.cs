using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Probes common REST collection paths for unauthenticated data leaks when traffic is sparse.
/// </summary>
public static class RestScaffoldProbes
{
    public sealed class ScaffoldOptions
    {
        public string? BaseUrl { get; set; }
        public int TimeoutMs { get; set; } = 12000;
        public int MaxPaths { get; set; } = 24;
        public IReadOnlyList<string>? Paths { get; set; }
        public bool IncludeHead { get; set; } = true;
    }

    public sealed class ScaffoldRow
    {
        public string Path { get; init; } = "";
        public string Url { get; init; } = "";
        public int Status { get; init; }
        public string Method { get; init; } = "GET";
        public string Result { get; init; } = "";
        public string Finding { get; init; } = "";
        public string Severity { get; init; } = "info";
        public string? Detail { get; init; }
        public string? BodySample { get; init; }
    }

    public sealed class ScaffoldResult
    {
        public List<ScaffoldRow> Rows { get; init; } = [];
        public List<ScaffoldRow> Findings { get; init; } = [];
        public List<string> PathsProbed { get; init; } = [];
        public List<string> Summary { get; init; } = [];
        public string BaseOrigin { get; init; } = "";
    }

    public static readonly string[] DefaultPaths =
    [
        "/api/Users", "/api/users", "/rest/user/whoami", "/rest/admin/application-configuration",
        "/api/Products", "/api/products", "/api/Feedbacks", "/api/Complaints", "/api/BasketItems",
        "/api/SecurityAnswers", "/api/PrivacyRequests", "/api/Challenges", "/api/Cards",
        "/api/Orders", "/api/accounts", "/api/admin/users", "/rest/admin", "/api/config",
        "/api/settings", "/api/profile", "/api/me", "/api/v1/users", "/api/v2/users"
    ];

    private static readonly string[] UserShapeNeedles =
    [
        "\"email\"", "\"username\"", "\"role\"", "\"userId\"", "\"user_id\"", "\"password\""
    ];

    public static async Task<ScaffoldResult> RunAsync(
        AutomationContext ctx,
        ScaffoldOptions options,
        CancellationToken ct = default)
    {
        var pageUrl = options.BaseUrl ?? await ctx.GetCurrentUrl();
        if (!Uri.TryCreate(pageUrl, UriKind.Absolute, out var baseUri))
            throw new InvalidOperationException("Navigate to a page or pass baseUrl before running REST scaffold probes.");

        var origin = baseUri.GetLeftPart(UriPartial.Authority);
        var shell = await SpaShellGuard.CaptureOriginShellAsync(ctx, origin, options.TimeoutMs);
        var paths = (options.Paths is { Count: > 0 } ? options.Paths : DefaultPaths)
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Take(Math.Max(1, options.MaxPaths))
            .ToList();

        var allRows = new List<ScaffoldRow>();
        var findings = new List<ScaffoldRow>();
        var summary = new List<string>();

        foreach (var path in paths)
        {
            ct.ThrowIfCancellationRequested();
            var url = origin + (path.StartsWith('/') ? path : "/" + path);
            var get = await SecurityProbeHttp.FetchAsync(ctx, url, "GET", null, null, options.TimeoutMs, includeBrowserCookies: false, ct);
            allRows.Add(ClassifyRow(path, url, "GET", get.Status, get.Body, shell));

            if (options.IncludeHead)
            {
                var head = await SecurityProbeHttp.FetchAsync(ctx, url, "HEAD", null, null, options.TimeoutMs, includeBrowserCookies: false, ct);
                allRows.Add(ClassifyRow(path, url, "HEAD", head.Status, head.Body, shell));
            }
        }

        foreach (var row in allRows.Where(r => r.Result is "leak" or "protected"))
        {
            if (row.Result == "leak")
                findings.Add(row);
        }

        if (findings.Count > 0)
            summary.Add($"{findings.Count} scaffold probe(s) returned unauthenticated data.");
        else if (allRows.Any(r => r.Result == "protected"))
            summary.Add($"{allRows.Count(r => r.Result == "protected")} path(s) exist but require authentication (401/403).");
        else
            summary.Add($"Probed {paths.Count} path(s); no unauthenticated REST leaks detected.");

        return new ScaffoldResult
        {
            Rows = allRows,
            Findings = findings,
            PathsProbed = paths,
            Summary = summary,
            BaseOrigin = origin
        };
    }

    private static ScaffoldRow ClassifyRow(
        string path, string url, string method, int status, string? body, SpaShellGuard.ShellFingerprint? shell)
    {
        body ??= "";
        if (status is 401 or 403)
        {
            return new ScaffoldRow
            {
                Path = path,
                Url = url,
                Status = status,
                Method = method,
                Result = "protected",
                Finding = "PROTECTED_PATH",
                Severity = "info",
                Detail = $"Path exists but returned {status} without credentials."
            };
        }

        if (status is not (>= 200 and < 300))
        {
            return new ScaffoldRow
            {
                Path = path,
                Url = url,
                Status = status,
                Method = method,
                Result = "not_found",
                Finding = "NO_RESPONSE",
                Severity = "info",
                Detail = $"HTTP {status}."
            };
        }

        if (shell != null
            && SpaShellGuard.LooksLikeSpaShellDuplicate(body, status, shell, requireOriginHashMatch: true))
        {
            return new ScaffoldRow
            {
                Path = path,
                Url = url,
                Status = status,
                Method = method,
                Result = "spa-shell",
                Finding = "SPA_SHELL",
                Severity = "info",
                Detail = "200 response matches the SPA HTML shell (catch-all route), not an unauthenticated REST API."
            };
        }

        if (shell == null
            && !SpaShellGuard.IsApiLikeResponse(body)
            && SpaShellGuard.IsSpaHtmlShell(body))
        {
            return new ScaffoldRow
            {
                Path = path,
                Url = url,
                Status = status,
                Method = method,
                Result = "spa-shell",
                Finding = "SPA_SHELL",
                Severity = "info",
                Detail = "200 HTML document response on API-shaped path (likely SPA fallback; origin shell not captured)."
            };
        }

        var jsonStructured = body.TrimStart().StartsWith('{') || body.TrimStart().StartsWith('[');

        if (!jsonStructured)
        {
            if (body.Length < 20)
            {
                return new ScaffoldRow
                {
                    Path = path,
                    Url = url,
                    Status = status,
                    Method = method,
                    Result = "empty",
                    Finding = "NO_RESPONSE",
                    Severity = "info",
                    Detail = "200 with minimal/non-JSON body."
                };
            }

            return new ScaffoldRow
            {
                Path = path,
                Url = url,
                Status = status,
                Method = method,
                Result = "not-api",
                Finding = "NON_JSON_RESPONSE",
                Severity = "info",
                Detail = "200 with non-JSON body that is not the SPA shell — not classified as REST leak."
            };
        }

        var lower = body.ToLowerInvariant();
        var userShape = UserShapeNeedles.Any(n => lower.Contains(n, StringComparison.Ordinal));
        var finding = userShape ? "UNAUTH_USER_ENUM" : "UNAUTH_REST_LEAK";
        return new ScaffoldRow
        {
            Path = path,
            Url = url,
            Status = status,
            Method = method,
            Result = "leak",
            Finding = finding,
            Severity = userShape ? "high" : "medium",
            Detail = userShape
                ? "Structured user-like JSON returned without authentication."
                : "REST resource returned JSON without authentication.",
            BodySample = body.Length <= 400 ? body : body[..400] + "…"
        };
    }
}
