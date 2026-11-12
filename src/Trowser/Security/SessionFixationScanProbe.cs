using System.Diagnostics;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Detects session fixation: session cookie value unchanged after successful login.
/// </summary>
public sealed class SessionFixationScanProbe
{
    private readonly AutomationContext _ctx;

    public SessionFixationScanProbe(AutomationContext context) => _ctx = context;

    public sealed class ScanOptions
    {
        public string? LoginUrl { get; set; }
        public string? Username { get; set; }
        public string? Password { get; set; }
        public string? CookieName { get; set; }
        public string? BodyTemplate { get; set; }
        public string? ContentType { get; set; }
        public string? UsernameField { get; set; }
        public string? PasswordField { get; set; }
        public int TimeoutMs { get; set; } = 15000;
        public int MaxLoginSurfaces { get; set; } = 3;
        public bool TryDefaultCredentials { get; set; } = true;
        public bool RegisterChainFindings { get; set; } = true;
        public bool PreferBrowserLogin { get; set; } = true;
    }

    public sealed class ScanFinding
    {
        public string Category { get; init; } = "session-fixation";
        public string Severity { get; init; } = "high";
        public string LoginUrl { get; init; } = "";
        public string CookieName { get; init; } = "";
        public string PreLoginValue { get; init; } = "";
        public string PostLoginValue { get; init; } = "";
        public string Detail { get; init; } = "";
    }

    public sealed class ScanResult
    {
        public string Message { get; init; } = "";
        public int ElapsedMs { get; init; }
        public List<ScanFinding> Findings { get; init; } = [];
        public List<string> Summary { get; init; } = [];
        public bool LoginSucceeded { get; init; }
        public string? CredentialsUsed { get; init; }
        public string? LoginMethod { get; init; }
    }

    public async Task<ScanResult> RunAsync(ScanOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var overrides = new AuthProbeDiscovery.LoginSurfaceOverrides
        {
            BodyTemplate = options.BodyTemplate,
            ContentType = options.ContentType,
            UsernameField = options.UsernameField,
            PasswordField = options.PasswordField
        };

        var surfaces = await AuthProbeDiscovery.DiscoverLoginSurfacesAsync(
            _ctx, options.LoginUrl, maxTargets: options.MaxLoginSurfaces, discoverFromPage: true, discoverFromNetwork: true,
            overrides, ct);

        if (surfaces.Count == 0)
            throw new InvalidOperationException("No login surface found for session-fixation-scan.");

        var currentUrl = await _ctx.GetCurrentUrl();
        Uri.TryCreate(currentUrl ?? "", UriKind.Absolute, out var pageUri);
        var credentialPairs = BuildCredentialPairs(options, pageUri);

        foreach (var surface in surfaces)
        {
            ct.ThrowIfCancellationRequested();
            foreach (var (user, pass) in credentialPairs)
            {
                ct.ThrowIfCancellationRequested();

                if (options.PreferBrowserLogin)
                {
                    try
                    {
                        var browser = await AuthBrowserLogin.TrySessionLoginAsync(
                            _ctx, surface.Url, user, pass,
                            options.UsernameField ?? surface.UserField,
                            options.PasswordField ?? surface.PassField,
                            options.TimeoutMs, ct);

                        if (browser.LoginSucceeded)
                        {
                            return BuildResult(sw, surface.Url, user, browser.PreLoginCookies,
                                browser.PostLoginCookies, options, "browser", browser.Detail);
                        }
                    }
                    catch
                    {
                        // Browser login failed unexpectedly — fall through to HTTP POST.
                    }
                }

                await _ctx.Navigate(surface.Url);
                await _ctx.WaitForFinalNavigation(400, Math.Min(options.TimeoutMs, 10_000));
                var preCookies = await AuthProbeDiscovery.GetBrowserCookiesAsync(_ctx);

                var baseline = await AuthProbeDiscovery.PostLoginAsync(
                    _ctx, surface, "invalid-trowser-user@invalid.local", "invalid-pass-xyz", options.TimeoutMs, ct);
                var login = await AuthProbeDiscovery.PostLoginAsync(_ctx, surface, user, pass, options.TimeoutMs, ct);

                if (!LoginInjectionHelpers.LooksLikeAuthenticatedLogin(login, baseline))
                    continue;

                var postCookies = await AuthProbeDiscovery.GetBrowserCookiesAsync(_ctx);
                return BuildResult(sw, surface.Url, user, preCookies, postCookies, options, "http", null);
            }
        }

        return new ScanResult
        {
            Message = "Could not authenticate — provide username/password or ensure default credentials work.",
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            Summary =
            [
                "No successful login for session rotation comparison.",
                "Browser form login is attempted first (CSRF/hidden fields/multi-step).",
                "HTTP fallback accepts body/contentType/usernameField/passwordField overrides."
            ]
        };
    }

    private ScanResult BuildResult(
        Stopwatch sw,
        string loginUrl,
        string user,
        List<(string Name, string Value)> preCookies,
        List<(string Name, string Value)> postCookies,
        ScanOptions options,
        string loginMethod,
        string? detail)
    {
        var findings = CompareCookies(preCookies, postCookies, loginUrl, options.CookieName);
        if (findings.Count == 0)
        {
            return new ScanResult
            {
                Message = "Login succeeded and session cookie rotated (no fixation signal).",
                ElapsedMs = (int)sw.ElapsedMilliseconds,
                LoginSucceeded = true,
                CredentialsUsed = $"{user}/***",
                LoginMethod = loginMethod,
                Summary = detail != null
                    ? [detail, "Session identifier changed or new session cookie issued after login."]
                    : ["Session identifier changed or new session cookie issued after login."]
            };
        }

        if (options.RegisterChainFindings)
        {
            foreach (var f in findings)
                AuthProbeDiscovery.RegisterChainFinding(_ctx, f.Category, f.Severity, f.Detail, loginUrl, "POST", f.Detail);
        }

        return new ScanResult
        {
            Message = $"{findings.Count} session fixation indicator(s) after login on {loginUrl}.",
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            Findings = findings,
            LoginSucceeded = true,
            CredentialsUsed = $"{user}/***",
            LoginMethod = loginMethod,
            Summary = findings.Select(f => f.Detail).ToList()
        };
    }

    private static List<(string User, string Pass)> BuildCredentialPairs(ScanOptions options, Uri? pageUri)
    {
        var pairs = new List<(string, string)>();
        if (!string.IsNullOrWhiteSpace(options.Username))
            pairs.Add((options.Username!, options.Password ?? "admin"));

        if (options.TryDefaultCredentials)
        {
            if (pageUri != null)
            {
                pairs.Add(("admin", "admin"));
                pairs.Add((AuthAccessHeuristics.DefaultEmailForHost(pageUri), "admin123"));
            }
            pairs.Add(("admin", "admin123"));
        }

        return pairs.Distinct().ToList();
    }

    internal static List<ScanFinding> CompareCookies(
        List<(string Name, string Value)> pre,
        List<(string Name, string Value)> post,
        string loginUrl,
        string? cookieNameFilter)
    {
        var findings = new List<ScanFinding>();
        var preNames = new HashSet<string>(pre.Select(p => p.Name), StringComparer.OrdinalIgnoreCase);
        var loginIssuedNewSession = post.Any(p =>
            AuthProbeDiscovery.MatchesSessionCookieNamePattern(p.Name) && !preNames.Contains(p.Name));

        foreach (var (name, postVal) in post)
        {
            if (!string.IsNullOrEmpty(cookieNameFilter)
                && !name.Equals(cookieNameFilter, StringComparison.OrdinalIgnoreCase))
                continue;

            if (AuthProbeDiscovery.IsExcludedFromSessionFixationCompare(name))
                continue;

            var preMatch = pre.FirstOrDefault(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (preMatch.Name == null || string.IsNullOrEmpty(preMatch.Value)) continue;
            if (!string.Equals(preMatch.Value, postVal, StringComparison.Ordinal)) continue;

            if (loginIssuedNewSession)
                continue;

            var nameMatchesSession = AuthProbeDiscovery.MatchesSessionCookieNamePattern(name);

            var severity = nameMatchesSession ? "high" : "medium";
            findings.Add(new ScanFinding
            {
                Severity = severity,
                LoginUrl = loginUrl,
                CookieName = name,
                PreLoginValue = Truncate(preMatch.Value),
                PostLoginValue = Truncate(postVal),
                Detail = nameMatchesSession
                    ? $"Session cookie '{name}' unchanged after login (pre={Truncate(preMatch.Value)} post={Truncate(postVal)})."
                    : $"Cookie '{name}' unchanged after login (non-session name; pre={Truncate(preMatch.Value)} post={Truncate(postVal)})."
            });
        }

        return findings;
    }

    private static string Truncate(string s) =>
        s.Length <= 24 ? s : s[..12] + "…" + s[^8..];
}
