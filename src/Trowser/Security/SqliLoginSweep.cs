using System.Diagnostics;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// SQLi login bypass sweep — tautology payloads vs invalid-user baseline on login-shaped paths.
/// Critical for cookie/token/redirect signals; medium for status-flip alone (circumstantial, not confirmed SQLi).
/// Inspired by OWASP WSTG-INPV-05 and PortSwigger SQLi; also influenced by pentest-ai <c>web.sqli_login_bypass</c>.
/// </summary>
public sealed class SqliLoginSweep
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public SqliLoginSweep(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class SqliLoginSweepOptions
    {
        public int MaxLoginUrls { get; set; } = 12;
        public int TimeoutMs { get; set; } = 15000;
        public bool IncludeScaffold { get; set; } = true;
        public bool IncludeBrowserCookies { get; set; } = true;
        public List<string>? LoginUrls { get; set; }
    }

    public sealed class SqliLoginFinding
    {
        public string Category { get; init; } = "sqli-login-bypass";
        public string Severity { get; init; } = "critical";
        public string Url { get; init; } = "";
        public string UsernameField { get; init; } = "";
        public string PasswordField { get; init; } = "";
        public string Payload { get; init; } = "";
        public string Shape { get; init; } = "json";
        public string Signal { get; init; } = "";
        public string Evidence { get; init; } = "";
    }

    public sealed class SqliLoginSweepResult
    {
        public string Message { get; init; } = "";
        public int LoginUrlsProbed { get; init; }
        public List<string> UrlsProbed { get; init; } = [];
        public int PayloadsSent { get; init; }
        public int ElapsedMs { get; init; }
        public List<SqliLoginFinding> Findings { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;
    }

    public async Task<SqliLoginSweepResult> RunAsync(SqliLoginSweepOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running sqli-login-sweep.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var urls = BuildLoginUrls(origin, options);
        var findings = new List<SqliLoginFinding>();
        var payloadsSent = 0;
        var seenUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var url in urls.Take(options.MaxLoginUrls))
        {
            ct.ThrowIfCancellationRequested();
            if (!seenUrls.Add(url)) continue;

            var fired = false;
            foreach (var shape in new[] { "form", "json" })
            {
                if (fired) break;
                var baseline = await PostLoginAsync(
                    url, "email", "password", "nonexistent-trowser@invalid.local",
                    shape, options, ct);
                if (baseline.Status is 0 or 404 or 405) continue;

                foreach (var usernameField in LoginInjectionHelpers.UsernameFields)
                {
                    if (fired) break;
                    foreach (var passwordField in LoginInjectionHelpers.PasswordFields.Take(2))
                    {
                        if (fired) break;
                        foreach (var payload in LoginInjectionHelpers.SqliBypassPayloads)
                        {
                            ct.ThrowIfCancellationRequested();
                            payloadsSent++;
                            var attack = await PostLoginAsync(
                                url, usernameField, passwordField, payload, shape, options, ct);
                            var classified = LoginInjectionHelpers.ClassifyAuthBypass(attack, baseline);
                            if (classified == null) continue;

                            var (signal, evidence) = classified.Value;
                            if (options.IncludeBrowserCookies
                                && signal is "redirect_to_authed_page" or "logged_in_marker" or "session_cookie_minted"
                                && !await LoginBypassHoldsWithoutBrowserCookies(
                                    url, usernameField, passwordField, payload, shape, options, ct))
                                continue;
                            var severity = signal is "status_flip_to_200" ? "medium" : "critical";
                            findings.Add(new SqliLoginFinding
                            {
                                Category = "sqli-login-bypass",
                                Severity = severity,
                                Url = url,
                                UsernameField = usernameField,
                                PasswordField = passwordField,
                                Payload = payload,
                                Shape = shape,
                                Signal = signal,
                                Evidence = evidence
                            });
                            _log($"  FLAG SQLi login: {url} {usernameField}={payload}", "#F44747");
                            fired = true;
                            break;
                        }
                    }
                }
            }
        }

        return new SqliLoginSweepResult
        {
            Message = findings.Count > 0
                ? $"{findings.Count} SQLi login bypass indicator(s) across {seenUrls.Count} URL(s)."
                : $"No SQLi login bypass across {seenUrls.Count} URL(s), {payloadsSent} payload(s).",
            LoginUrlsProbed = seenUrls.Count,
            UrlsProbed = seenUrls.OrderBy(u => u, StringComparer.OrdinalIgnoreCase).ToList(),
            PayloadsSent = payloadsSent,
            Findings = findings,
            ElapsedMs = (int)sw.ElapsedMilliseconds
        };
    }

    /// <summary>
    /// When the browser tab is already logged in, cookie-backed probes can false-positive;
    /// require the same signal without session cookies (server-side replay).
    /// </summary>
    private async Task<bool> LoginBypassHoldsWithoutBrowserCookies(
        string url,
        string usernameField,
        string passwordField,
        string payload,
        string shape,
        SqliLoginSweepOptions options,
        CancellationToken ct)
    {
        var unauthBaseline = await PostLoginAsync(
            url, usernameField, passwordField, "nonexistent-trowser@invalid.local",
            shape, options, ct, includeBrowserCookies: false);
        if (unauthBaseline.Status is 0 or 404 or 405) return true;

        var unauthAttack = await PostLoginAsync(
            url, usernameField, passwordField, payload, shape, options, ct, includeBrowserCookies: false);
        return LoginInjectionHelpers.ClassifyAuthBypass(unauthAttack, unauthBaseline) != null;
    }

    private async Task<LoginInjectionHelpers.LoginProbeResponse> PostLoginAsync(
        string url,
        string usernameField,
        string passwordField,
        string usernameValue,
        string shape,
        SqliLoginSweepOptions options,
        CancellationToken ct,
        bool? includeBrowserCookies = null)
    {
        Dictionary<string, string> headers;
        string body;
        if (shape == "form")
        {
            body = string.Join("&", new[]
            {
                $"{Uri.EscapeDataString(usernameField)}={Uri.EscapeDataString(usernameValue)}",
                $"{Uri.EscapeDataString(passwordField)}={Uri.EscapeDataString(LoginInjectionHelpers.DummyPassword)}"
            });
            headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Content-Type"] = "application/x-www-form-urlencoded"
            };
        }
        else
        {
            body = JsonSerializer.Serialize(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [usernameField] = usernameValue,
                [passwordField] = LoginInjectionHelpers.DummyPassword
            });
            headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Content-Type"] = "application/json"
            };
        }

        var prepared = await LoginCsrfHelper.PrepareAsync(
            _ctx, url, "POST", headers, body, options.TimeoutMs, ct);
        return await LoginInjectionHelpers.SendAsync(
            _ctx, url, "POST", prepared.Headers, prepared.Body,
            options.TimeoutMs, followRedirects: false, includeBrowserCookies ?? options.IncludeBrowserCookies, ct);
    }

    private List<string> BuildLoginUrls(string origin, SqliLoginSweepOptions options)
    {
        var urls = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (options.LoginUrls is { Count: > 0 })
        {
            foreach (var u in options.LoginUrls)
            {
                if (seen.Add(u)) urls.Add(u);
            }
        }

        foreach (var entry in _ctx.Network.Entries)
        {
            if (!entry.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)) continue;
            if (!Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) continue;
            if (!string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.OrdinalIgnoreCase))
                continue;
            var path = uri.AbsolutePath.ToLowerInvariant();
            if (!LooksLikeLoginPath(path))
                continue;
            if (seen.Add(entry.Url))
                urls.Insert(0, entry.Url);
        }

        if (options.IncludeScaffold)
        {
            foreach (var u in InjectionScaffold.EnumerateLoginUrls(origin))
            {
                if (seen.Add(u))
                    urls.Add(u);
            }
        }

        return urls;
    }

    /// <summary>True for login/signin/auth session create paths; excludes testimonials/count false friends.</summary>
    internal static bool LooksLikeLoginPath(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        if (path.Contains("testimonials", StringComparison.OrdinalIgnoreCase)
            || path.Contains("/count", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith("count", StringComparison.OrdinalIgnoreCase))
            return false;

        return path.Contains("login", StringComparison.OrdinalIgnoreCase)
               || path.Contains("signin", StringComparison.OrdinalIgnoreCase)
               || path.Contains("sign-in", StringComparison.OrdinalIgnoreCase)
               || path.Contains("/auth/login", StringComparison.OrdinalIgnoreCase)
               || path.Contains("/auth/signin", StringComparison.OrdinalIgnoreCase)
               || path.EndsWith("/auth", StringComparison.OrdinalIgnoreCase)
               || path.EndsWith("/authenticate", StringComparison.OrdinalIgnoreCase)
               || path.Contains("/session", StringComparison.OrdinalIgnoreCase)
                  && (path.Contains("create", StringComparison.OrdinalIgnoreCase)
                      || path.Contains("new", StringComparison.OrdinalIgnoreCase));
    }
}
