using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;
using Trowser.Security.ChainEngine;

namespace Trowser.Security;

/// <summary>
/// Tries a small built-in default-credential wordlist against discovered login surfaces.
/// Complements <see cref="HttpSecurityProbes.RunBruteForceAsync"/> (lockout testing).
/// </summary>
public static class DefaultCredentialCanary
{
    public sealed class CanaryOptions
    {
        public IReadOnlyList<string>? LoginUrls { get; set; }
        public IReadOnlyList<(string User, string Pass)>? CredentialPairs { get; set; }
        public string UserPlaceholder { get; set; } = "§USER§";
        public string PassPlaceholder { get; set; } = "§PASS§";
        public string? BodyTemplate { get; set; }
        public string? ContentType { get; set; }
        public string Method { get; set; } = "POST";
        public int MaxTargets { get; set; } = 5;
        public int MaxPairs { get; set; } = 6;
        public int DelayMs { get; set; } = 400;
        public int TimeoutMs { get; set; } = 15_000;
        public bool DiscoverFromPage { get; set; } = true;
        public bool DiscoverFromNetwork { get; set; } = true;
        public bool IncludeDiscoveredCredentials { get; set; }
        public bool RegisterChainFindings { get; set; } = true;
    }

    public sealed class CanaryAttempt
    {
        public string Url { get; init; } = "";
        public string Username { get; init; } = "";
        public int Status { get; init; }
        public bool SuccessSuspected { get; init; }
        public string? Reason { get; init; }
        public string? BodySnippet { get; init; }
    }

    public sealed class CanaryFinding
    {
        public string Url { get; init; } = "";
        public string Username { get; init; } = "";
        public string Password { get; init; } = "";
        public string Severity { get; init; } = "critical";
        public string Category { get; init; } = "default-credentials";
        public string Title { get; init; } = "";
        public string Detail { get; init; } = "";
        public int Status { get; init; }
    }

    public sealed class CanaryResult
    {
        public List<CanaryFinding> Findings { get; init; } = [];
        public List<CanaryAttempt> Attempts { get; init; } = [];
        public List<string> Summary { get; init; } = [];
        public int TargetsTested { get; init; }
        public int TargetsSkippedSpaShell { get; init; }
        public int DiscoveredPairsIncluded { get; init; }
        public List<string> CredentialSources { get; init; } = [];
        public bool IsClean => Findings.Count == 0;
    }

    private static readonly (string User, string Pass)[] BuiltInPairs =
    [
        ("admin@juice-sh.op", "admin123"),
        ("admin", "admin123"),
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "Password1"),
        ("admin", "123456"),
        ("admin", "12345678"),
        ("admin", "pass"),
        ("admin", "changeme"),
        ("admin", "letmein"),
        ("administrator", "administrator"),
        ("administrator", "admin123"),
        ("administrator", "password"),
        ("root", "root"),
        ("root", "toor"),
        ("root", "admin123"),
        ("user", "user"),
        ("test", "test"),
        ("guest", "guest"),
        ("demo", "demo"),
        ("postgres", "postgres"),
        ("sa", "sa"),
    ];

    private static readonly string[] LoginPathHints =
    [
        "/rest/user/login",
        "/api/auth/login",
        "/api/Users/login",
        "/auth/login",
        "/admin", "/login", "/signin", "/wp-login.php",
    ];

    private static readonly Regex JwtPattern =
        new(@"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.", RegexOptions.Compiled, TimeSpan.FromSeconds(1));

    public static async Task<CanaryResult> RunAsync(
        AutomationContext ctx,
        CanaryOptions options,
        CancellationToken ct = default)
    {
        var currentUrl = await ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var pageUri))
            throw new InvalidOperationException("Navigate to a page before running default-credential canary.");

        var targets = await ResolveLoginTargetsAsync(ctx, options, pageUri, ct);
        var (pairs, discoveredSources) = await BuildCredentialPairsAsync(ctx, options, ct);
        var findings = new List<CanaryFinding>();
        var attempts = new List<CanaryAttempt>();
        var tested = 0;
        var skippedSpa = 0;

        foreach (var target in targets.Take(Math.Clamp(options.MaxTargets, 1, 10)))
        {
            ct.ThrowIfCancellationRequested();
            tested++;

            var failedBaseline = await TryLoginAsync(ctx, target, options, "canary-invalid-user-xyz", "canary-invalid-pass-xyz", options.TimeoutMs, ct);
            var failedBody = failedBaseline.Body ?? "";
            var failedStatus = failedBaseline.Status;

            if (IsSpaShellOnlyEndpoint(failedBody, failedStatus))
            {
                skippedSpa++;
                attempts.Add(new CanaryAttempt
                {
                    Url = target.Url,
                    Username = "(baseline)",
                    Status = failedStatus,
                    SuccessSuspected = false,
                    Reason = "Skipped — response looks like SPA shell HTML, not an API login endpoint",
                    BodySnippet = Truncate(failedBody.Replace('\r', ' ').Replace('\n', ' '), 120)
                });
                continue;
            }

            foreach (var (user, pass) in pairs)
            {
                ct.ThrowIfCancellationRequested();
                if (options.DelayMs > 0)
                    await Task.Delay(options.DelayMs, ct);

                var probe = await TryLoginAsync(ctx, target, options, user, pass, options.TimeoutMs, ct);
                var body = probe.Body ?? "";
                var success = ClassifySuccess(probe, failedStatus, failedBody);

                attempts.Add(new CanaryAttempt
                {
                    Url = target.Url,
                    Username = user,
                    Status = probe.Status,
                    SuccessSuspected = success,
                    Reason = success ? DescribeSuccessReason(probe, failedStatus, failedBody) : null,
                    BodySnippet = Truncate(body.Replace('\r', ' ').Replace('\n', ' '), 120)
                });

                if (!success) continue;

                findings.Add(new CanaryFinding
                {
                    Url = target.Url,
                    Username = user,
                    Password = pass,
                    Status = probe.Status,
                    Title = $"Default credentials may work: {user} on {target.Url}",
                    Detail = $"Login with {user}/{pass} returned authenticated-area markers (HTTP {probe.Status})."
                });
                break;
            }
        }

        if (options.RegisterChainFindings)
            RegisterFindingsForChain(ctx, findings);

        var summary = new List<string>();
        if (findings.Count == 0)
            summary.Add($"No default-credential success signal on {tested} login target(s). {skippedSpa} skipped as SPA shell.");
        else
            summary.Add($"{findings.Count} default-credential finding(s) — change default passwords immediately.");

        return new CanaryResult
        {
            Findings = findings,
            Attempts = attempts,
            Summary = summary,
            TargetsTested = tested,
            TargetsSkippedSpaShell = skippedSpa,
            DiscoveredPairsIncluded = discoveredSources.Count,
            CredentialSources = discoveredSources
        };
    }

    private static async Task<(List<(string User, string Pass)> Pairs, List<string> Sources)> BuildCredentialPairsAsync(
        AutomationContext ctx,
        CanaryOptions options,
        CancellationToken ct)
    {
        var merged = new List<(string User, string Pass)>();
        var sources = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string user, string pass, string? sourceLabel = null)
        {
            var key = $"{user}|{pass}";
            if (!seen.Add(key)) return;
            merged.Add((user, pass));
            if (!string.IsNullOrEmpty(sourceLabel) && !sources.Contains(sourceLabel))
                sources.Add(sourceLabel);
        }

        if (options.IncludeDiscoveredCredentials)
        {
            var discovered = await DiscoveredCredentialResolver.ResolveAsync(ctx, ct);
            foreach (var d in discovered)
                Add(d.User, d.Pass, $"{d.Source}:{d.Location}");
        }

        var basePairs = options.CredentialPairs ?? BuiltInPairs;
        foreach (var (user, pass) in basePairs)
            Add(user, pass, "built-in");

        var max = Math.Clamp(options.MaxPairs, 1, 25);
        return (merged.Take(max).ToList(), sources);
    }

    private static void RegisterFindingsForChain(AutomationContext ctx, List<CanaryFinding> findings)
    {
        foreach (var f in findings)
        {
            ctx.AddManualChainFinding(new ChainableFinding
            {
                Id = $"default-creds-{Math.Abs((f.Url + f.Username).GetHashCode(StringComparison.Ordinal))}",
                Source = "scan",
                Category = f.Category,
                Severity = f.Severity,
                Title = f.Title,
                Endpoint = f.Url,
                Method = "POST",
                Detail = f.Detail
            });
        }
    }

    private sealed class LoginTarget
    {
        public string Url { get; init; } = "";
        public string? BodyTemplate { get; init; }
        public string? ContentType { get; init; }
        public string Method { get; init; } = "POST";
    }

    private static async Task<List<LoginTarget>> ResolveLoginTargetsAsync(
        AutomationContext ctx,
        CanaryOptions options,
        Uri pageUri,
        CancellationToken ct)
    {
        var origin = pageUri.GetLeftPart(UriPartial.Authority);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var targets = new List<LoginTarget>();

        void Add(string url, string? bodyTemplate = null, string? contentType = null, string method = "POST")
        {
            if (!seen.Add(url)) return;
            targets.Add(new LoginTarget
            {
                Url = url,
                BodyTemplate = bodyTemplate,
                ContentType = contentType,
                Method = method
            });
        }

        if (options.LoginUrls is { Count: > 0 })
        {
            foreach (var u in options.LoginUrls)
            {
                var url = u.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                    ? u
                    : origin + (u.StartsWith('/') ? u : "/" + u);
                Add(url, options.BodyTemplate, options.ContentType, options.Method);
            }

            return targets;
        }

        if (options.DiscoverFromNetwork)
        {
            foreach (var e in ctx.Network.Entries)
            {
                if (e.Method != "POST") continue;
                var path = e.Url ?? "";
                if (!path.Contains("login", StringComparison.OrdinalIgnoreCase)
                    && !path.Contains("signin", StringComparison.OrdinalIgnoreCase)
                    && !path.Contains("auth", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (Uri.TryCreate(path, UriKind.Absolute, out var u)
                    && string.Equals(u.Host, pageUri.Host, StringComparison.OrdinalIgnoreCase))
                    Add(path, e.RequestBody, e.ContentType, "POST");
            }
        }

        foreach (var hint in LoginPathHints)
            Add(origin + hint, options.BodyTemplate, options.ContentType, options.Method);

        if (options.DiscoverFromPage)
        {
            var formJson = await ctx.ExecuteJs(
                """
                (function(){
                  var out = [];
                  try {
                    document.querySelectorAll('form').forEach(function(f) {
                      var action = f.action || location.href;
                      var hasPass = !!f.querySelector('input[type=password]');
                      if (!hasPass) return;
                      var user = f.querySelector('input[type=email],input[type=text],input[name*=user i],input[name*=email i],input[id*=user i]');
                      var pass = f.querySelector('input[type=password]');
                      out.push({
                        action: action,
                        method: (f.method || 'POST').toUpperCase(),
                        userName: user ? (user.name || user.id || 'email') : 'email',
                        passName: pass ? (pass.name || pass.id || 'password') : 'password'
                      });
                    });
                  } catch(e) {}
                  return JSON.stringify(out);
                })()
                """);
            ct.ThrowIfCancellationRequested();

            using var doc = JsonDocument.Parse(formJson);
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                var action = el.GetProperty("action").GetString() ?? "";
                var method = el.GetProperty("method").GetString() ?? "POST";
                var userName = el.GetProperty("userName").GetString() ?? "email";
                var passName = el.GetProperty("passName").GetString() ?? "password";
                if (string.IsNullOrEmpty(action)) continue;

                var body = $"{{\"{userName}\": \"{options.UserPlaceholder}\", \"{passName}\": \"{options.PassPlaceholder}\"}}";
                Add(action, body, "application/json", method);
            }
        }

        return targets;
    }

    private static async Task<SecurityProbeHttp.FetchResult> TryLoginAsync(
        AutomationContext ctx,
        LoginTarget target,
        CanaryOptions options,
        string user,
        string pass,
        int timeoutMs,
        CancellationToken ct)
    {
        var bodyTemplate = target.BodyTemplate ?? options.BodyTemplate
            ?? $"{{\"email\": \"{options.UserPlaceholder}\", \"password\": \"{options.PassPlaceholder}\"}}";

        var body = bodyTemplate
            .Replace(options.UserPlaceholder, user, StringComparison.Ordinal)
            .Replace("{{USER}}", user, StringComparison.OrdinalIgnoreCase)
            .Replace(options.PassPlaceholder, pass, StringComparison.Ordinal)
            .Replace("{{PASS}}", pass, StringComparison.OrdinalIgnoreCase);

        var contentType = target.ContentType ?? options.ContentType;
        if (string.IsNullOrWhiteSpace(contentType))
            contentType = body.TrimStart().StartsWith('{') ? "application/json" : "application/x-www-form-urlencoded";

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = contentType
        };

        if (!body.TrimStart().StartsWith('{') && bodyTemplate.Contains('='))
        {
            body = bodyTemplate
                .Replace(options.UserPlaceholder, Uri.EscapeDataString(user), StringComparison.Ordinal)
                .Replace(options.PassPlaceholder, Uri.EscapeDataString(pass), StringComparison.Ordinal);
        }

        var prepared = await LoginCsrfHelper.PrepareAsync(
            ctx, target.Url, target.Method, headers, body, timeoutMs, ct);

        return await SecurityProbeHttp.FetchAsync(
            ctx, target.Url, target.Method, prepared.Headers, prepared.Body, timeoutMs,
            includeBrowserCookies: true, ct);
    }

    private static bool IsSpaShellOnlyEndpoint(string body, int status)
    {
        if (status is not (200 or 304)) return false;
        if (string.IsNullOrWhiteSpace(body)) return false;
        var trimmed = body.TrimStart();
        if (!trimmed.StartsWith('<')) return false;
        if (IsJsonApiResponse(body)) return false;

        // Real MPA login pages are HTML documents with password fields — never skip those.
        // The old "<!doctype html" heuristic false-positived on every server-rendered login form.
        if (LooksLikeHtmlLoginForm(body))
            return false;

        return trimmed.Contains("<app-root", StringComparison.OrdinalIgnoreCase)
               || trimmed.Contains("ng-version", StringComparison.OrdinalIgnoreCase)
               || (trimmed.Contains("id=\"root\"", StringComparison.OrdinalIgnoreCase)
                   && !body.Contains("<form", StringComparison.OrdinalIgnoreCase));
    }

    private static bool LooksLikeHtmlLoginForm(string body) =>
        body.Contains("type=\"password\"", StringComparison.OrdinalIgnoreCase)
        || body.Contains("type='password'", StringComparison.OrdinalIgnoreCase)
        || body.Contains("type=password", StringComparison.OrdinalIgnoreCase)
        || (body.Contains("<form", StringComparison.OrdinalIgnoreCase)
            && body.Contains("password", StringComparison.OrdinalIgnoreCase)
            && (body.Contains("login", StringComparison.OrdinalIgnoreCase)
                || body.Contains("signin", StringComparison.OrdinalIgnoreCase)
                || body.Contains("sign-in", StringComparison.OrdinalIgnoreCase)
                || body.Contains("username", StringComparison.OrdinalIgnoreCase)
                || body.Contains("email", StringComparison.OrdinalIgnoreCase)));

    private static bool IsJsonApiResponse(string body)
    {
        var t = body.TrimStart();
        return t.StartsWith('{') || t.StartsWith('[');
    }

    private static bool ClassifySuccess(
        SecurityProbeHttp.FetchResult probe,
        int failedStatus,
        string failedBody)
    {
        var status = probe.Status;
        var body = probe.Body ?? "";

        if (status is 401 or 403) return false;
        if (status is >= 500) return false;

        var lower = body.ToLowerInvariant();
        if (lower.Contains("invalid password") || lower.Contains("login failed")
            || lower.Contains("incorrect") || lower.Contains("wrong password")
            || lower.Contains("authentication failed") || lower.Contains("invalid credentials")
            || lower.Contains("invalid csrf") || lower.Contains("csrf token"))
            return false;

        if (HasAuthTokenJson(body))
            return true;

        if (JwtPattern.IsMatch(body))
            return true;

        if (HasAuthorizationJwtHeader(probe))
            return true;

        if (HasSetCookieAuth(probe))
            return true;

        if (IsSpaShellOnlyEndpoint(body, status) && IsSpaShellOnlyEndpoint(failedBody, failedStatus))
            return false;

        if (status is 302 or 301) return true;

        // Any 2xx that diverges from a non-2xx failed baseline is a login success signal.
        if (status is >= 200 and < 300 && failedStatus is not (>= 200 and < 300))
            return true;

        if (status is >= 200 and < 300 && failedStatus is >= 200 and < 300
            && body.Length > failedBody.Length + 40)
        {
            if (lower.Contains("token") || lower.Contains("basket") || lower.Contains("dashboard")
                || lower.Contains("welcome") || lower.Contains("\"id\""))
                return true;
        }

        if (IsJsonApiResponse(body) && !IsJsonApiResponse(failedBody)
            && body.Length > 20 && body != failedBody)
            return true;

        return false;
    }

    private static bool HasAuthorizationJwtHeader(SecurityProbeHttp.FetchResult probe)
    {
        foreach (var name in new[] { "Authorization", "authorization", "X-Auth-Token", "X-Access-Token" })
        {
            var value = SecurityProbeHttp.GetResponseHeader(probe, name);
            if (string.IsNullOrWhiteSpace(value)) continue;
            if (JwtPattern.IsMatch(value)) return true;
            if (value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                && JwtPattern.IsMatch(value[7..]))
                return true;
        }
        return false;
    }

    private static bool HasAuthTokenJson(string body)
    {
        if (!IsJsonApiResponse(body)) return false;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("authentication", out var auth)
                && auth.TryGetProperty("token", out var token)
                && token.ValueKind == JsonValueKind.String
                && token.GetString()?.Length > 10)
                return true;
            if (doc.RootElement.TryGetProperty("token", out var direct)
                && direct.ValueKind == JsonValueKind.String
                && direct.GetString()?.Length > 10)
                return true;
            if (doc.RootElement.TryGetProperty("access_token", out var access)
                && access.ValueKind == JsonValueKind.String
                && access.GetString()?.Length > 10)
                return true;
        }
        catch (JsonException)
        {
        }

        return body.Contains("\"authentication\":{\"token\"", StringComparison.OrdinalIgnoreCase)
               || body.Contains("\"token\":\"eyJ", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasSetCookieAuth(SecurityProbeHttp.FetchResult probe)
    {
        var setCookie = SecurityProbeHttp.GetResponseHeader(probe, "Set-Cookie") ?? "";
        return setCookie.Contains("token", StringComparison.OrdinalIgnoreCase)
               || setCookie.Contains("session", StringComparison.OrdinalIgnoreCase)
               || setCookie.Contains("auth", StringComparison.OrdinalIgnoreCase);
    }

    private static string DescribeSuccessReason(
        SecurityProbeHttp.FetchResult probe,
        int failedStatus,
        string failedBody)
    {
        var body = probe.Body ?? "";
        if (HasAuthTokenJson(body)) return "JSON authentication token in response";
        if (JwtPattern.IsMatch(body)) return "JWT in response body";
        if (HasAuthorizationJwtHeader(probe)) return "JWT in Authorization response header";
        if (HasSetCookieAuth(probe)) return "Auth/session Set-Cookie header";
        if (probe.Status is 301 or 302) return "Redirect after login";
        if (probe.Status is >= 200 and < 300 && failedStatus is not (>= 200 and < 300))
            return $"HTTP {probe.Status} vs failed baseline {failedStatus}";
        if (IsJsonApiResponse(body) && !IsJsonApiResponse(failedBody)) return "JSON API response vs HTML baseline";
        return "Response differs from failed-login baseline";
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
