using System.Diagnostics;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Account enumeration via login/register response differentials and unauthenticated user scaffolds.
/// Prefers multi-signal differentials (status + message); single-shot timing alone is informational.
/// Inspired by OWASP WSTG identification/authentication testing; also influenced by pentest-ai <c>web.user_enum</c> patterns.
/// Register probes may create accounts — active safetyMode / test environments only.
/// </summary>
public sealed class AccountEnumerationScanProbe
{
    private readonly AutomationContext _ctx;

    public AccountEnumerationScanProbe(AutomationContext context) => _ctx = context;

    public sealed class ScanOptions
    {
        public string? LoginUrl { get; set; }
        public string? ValidUsername { get; set; }
        public string? RegisterUrl { get; set; }
        public string? BodyTemplate { get; set; }
        public string? ContentType { get; set; }
        public string? UsernameField { get; set; }
        public string? PasswordField { get; set; }
        public int TimeoutMs { get; set; } = 15000;
        public int MaxRestPaths { get; set; } = 12;
        public bool IncludeRestLeak { get; set; } = true;
        public bool IncludeLoginDifferential { get; set; } = true;
        public bool IncludeRegisterProbe { get; set; } = true;
        public bool RegisterChainFindings { get; set; } = true;
    }

    public sealed class ScanFinding
    {
        public string Category { get; init; } = "account-enumeration";
        public string Severity { get; init; } = "medium";
        public string Signal { get; init; } = "";
        public string Title { get; init; } = "";
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public string Detail { get; init; } = "";
        public object? Evidence { get; init; }
    }

    public sealed class ScanResult
    {
        public string Message { get; init; } = "";
        public int ElapsedMs { get; init; }
        public int LoginDifferentialMs { get; init; }
        public List<ScanFinding> Findings { get; init; } = [];
        public List<string> Summary { get; init; } = [];
        public List<string> Warnings { get; init; } = [];
    }

    public async Task<ScanResult> RunAsync(ScanOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var findings = new List<ScanFinding>();
        var warnings = new List<string>();
        var loginDifferentialMs = 0;
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var pageUri))
            throw new InvalidOperationException("Navigate to a page before running account-enumeration-scan.");

        if (options.IncludeRestLeak)
        {
            var userPaths = AuthProbeDiscovery.CollectUserListPaths(_ctx, pageUri, options.MaxRestPaths);
            var scaffold = await RestScaffoldProbes.RunAsync(_ctx, new RestScaffoldProbes.ScaffoldOptions
            {
                MaxPaths = options.MaxRestPaths,
                TimeoutMs = options.TimeoutMs,
                Paths = userPaths
            }, ct);

            foreach (var row in scaffold.Findings.Where(r => r.Finding == "UNAUTH_USER_ENUM"))
            {
                findings.Add(new ScanFinding
                {
                    Signal = "rest-user-list-leak",
                    Severity = row.Severity,
                    Title = $"Account enumeration via user list ({row.Method} {TruncatePath(row.Url)})",
                    Url = row.Url,
                    Method = row.Method,
                    Detail = row.Detail ?? "Unauthenticated user list returned.",
                    Evidence = new { row.Status, row.BodySample }
                });
            }
        }

        if (options.IncludeLoginDifferential)
        {
            var overrides = new AuthProbeDiscovery.LoginSurfaceOverrides
            {
                BodyTemplate = options.BodyTemplate,
                ContentType = options.ContentType,
                UsernameField = options.UsernameField,
                PasswordField = options.PasswordField
            };
            var loginTimed = await ProbeLoginDifferentialAsync(options, overrides, pageUri, ct);
            loginDifferentialMs = loginTimed.ElapsedMs;
            findings.AddRange(loginTimed.Findings);
            warnings.AddRange(loginTimed.Warnings);
        }

        if (options.IncludeRegisterProbe)
        {
            var regFinding = await ProbeRegisterDuplicateAsync(options, pageUri, ct);
            if (regFinding != null) findings.Add(regFinding);
        }

        if (options.RegisterChainFindings)
        {
            foreach (var f in findings)
                AuthProbeDiscovery.RegisterChainFinding(_ctx, f.Category, f.Severity, f.Detail, f.Url, f.Method, f.Detail);
        }

        var message = findings.Count > 0
            ? $"{findings.Count} account enumeration indicator(s)."
            : warnings.Count > 0
                ? "No account enumeration signals detected (see warnings — login probe may be mis-encoded)."
                : "No account enumeration signals detected.";

        return new ScanResult
        {
            Message = message,
            ElapsedMs = (int)sw.ElapsedMilliseconds,
            LoginDifferentialMs = loginDifferentialMs,
            Findings = findings,
            Summary = findings.Select(f => f.Detail).ToList(),
            Warnings = warnings
        };
    }

    private sealed class LoginDifferentialRun
    {
        public List<ScanFinding> Findings { get; init; } = [];
        public List<string> Warnings { get; init; } = [];
        public int ElapsedMs { get; init; }
    }

    private async Task<LoginDifferentialRun> ProbeLoginDifferentialAsync(
        ScanOptions options,
        AuthProbeDiscovery.LoginSurfaceOverrides overrides,
        Uri pageUri,
        CancellationToken ct)
    {
        var probeSw = Stopwatch.StartNew();
        var findings = new List<ScanFinding>();
        var warnings = new List<string>();
        var surfaces = await AuthProbeDiscovery.DiscoverLoginSurfacesAsync(
            _ctx, options.LoginUrl, maxTargets: 3, true, true, overrides, ct);
        if (surfaces.Count == 0)
            return new LoginDifferentialRun { ElapsedMs = (int)probeSw.ElapsedMilliseconds };

        static void MaybeWarnLoginEncoding(AuthProbeDiscovery.LoginSurface surface, List<string> warn)
        {
            var ct = AuthProbeDiscovery.ResolveEffectiveContentType(surface);
            var body = AuthProbeDiscovery.BuildLoginBody(surface, "u", "p");
            if (AuthProbeDiscovery.IsFormUrlEncodedContentType(ct) && body.TrimStart().StartsWith('{'))
            {
                warn.Add(
                    $"Login differential for {surface.Url} may be mis-encoded: Content-Type is form-urlencoded but body is JSON. " +
                    "Navigate to loginUrl or pass bodyTemplate, or ensure login form hydration ran.");
            }
        }

        var validUser = options.ValidUsername
                        ?? AuthProbeDiscovery.ExtractEmailFromNetwork(_ctx)
                        ?? AuthAccessHeuristics.DefaultUsernameForHost(pageUri);
        var invalidUser = "nonexistent-trowser-" + Guid.NewGuid().ToString("N")[..8] + "@invalid.local";
        const string wrongPass = "WrongPass-Trowser-9f3b";

        foreach (var surface in surfaces)
        {
            ct.ThrowIfCancellationRequested();
            MaybeWarnLoginEncoding(surface, warnings);
            var validTimed = await SecurityProbeHttp.FetchTimedAsync(
                _ctx, surface.Url, surface.Method,
                AuthProbeDiscovery.BuildLoginHeaders(surface),
                AuthProbeDiscovery.BuildLoginBody(surface, validUser, wrongPass),
                options.TimeoutMs, true, ct);
            var invalidTimed = await SecurityProbeHttp.FetchTimedAsync(
                _ctx, surface.Url, surface.Method,
                AuthProbeDiscovery.BuildLoginHeaders(surface),
                AuthProbeDiscovery.BuildLoginBody(surface, invalidUser, wrongPass),
                options.TimeoutMs, true, ct);

            var valid = validTimed.Result;
            var invalid = invalidTimed.Result;
            var statusDiff = valid.Status != invalid.Status;
            var lengthDiff = Math.Abs(valid.Body.Length - invalid.Body.Length) > 40;
            var timingDiff = Math.Abs(validTimed.ElapsedSeconds - invalidTimed.ElapsedSeconds) > 0.35;

            var validLower = valid.Body.ToLowerInvariant();
            var invalidLower = invalid.Body.ToLowerInvariant();
            var messageDiff = EnumerationMessageLikelyDifferent(validLower, invalidLower);

            if (!statusDiff && !lengthDiff && !timingDiff && !messageDiff)
            {
                if (valid.Status == invalid.Status
                    && Math.Abs(valid.Body.Length - invalid.Body.Length) < 8
                    && AuthProbeDiscovery.PrefersFormLoginBody(surface))
                {
                    warnings.Add(
                        $"Login differential on {surface.Url}: valid and invalid username responses were identical " +
                        $"(HTTP {valid.Status}, length {valid.Body.Length}). Check form encoding (application/x-www-form-urlencoded vs JSON).");
                }

                continue;
            }

            var signalCount = (statusDiff ? 1 : 0) + (lengthDiff ? 1 : 0) + (timingDiff ? 1 : 0) + (messageDiff ? 1 : 0);
            // Timing alone is weak noise — info/low. Medium+ needs multi-signal or message/status evidence.
            var severity = timingDiff && signalCount == 1
                ? "low"
                : signalCount >= 2 || messageDiff || statusDiff
                    ? "medium"
                    : "low";

            findings.Add(new ScanFinding
            {
                Signal = "login-response-differential",
                Severity = severity,
                Title = $"Account enumeration via login differential ({TruncatePath(surface.Url)})",
                Url = surface.Url,
                Method = surface.Method,
                Detail = $"Login responses differ for valid vs invalid username on {surface.Url} " +
                         $"(status {valid.Status}/{invalid.Status}, length {valid.Body.Length}/{invalid.Body.Length}, " +
                         $"timing {validTimed.ElapsedSeconds:F2}s/{invalidTimed.ElapsedSeconds:F2}s).",
                Evidence = new
                {
                    validUser,
                    validStatus = valid.Status,
                    invalidStatus = invalid.Status,
                    validBodyLength = valid.Body.Length,
                    invalidBodyLength = invalid.Body.Length,
                    validDurationMs = (int)(validTimed.ElapsedSeconds * 1000),
                    invalidDurationMs = (int)(invalidTimed.ElapsedSeconds * 1000),
                    statusDiff,
                    lengthDiff,
                    timingDiff,
                    messageDiff
                }
            });
        }

        return new LoginDifferentialRun
        {
            Findings = findings,
            Warnings = warnings,
            ElapsedMs = (int)probeSw.ElapsedMilliseconds
        };
    }

    private async Task<ScanFinding?> ProbeRegisterDuplicateAsync(ScanOptions options, Uri pageUri, CancellationToken ct)
    {
        var registerUrls = options.RegisterUrl != null
            ? [options.RegisterUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                ? options.RegisterUrl
                : pageUri.GetLeftPart(UriPartial.Authority) + (options.RegisterUrl.StartsWith('/') ? options.RegisterUrl : "/" + options.RegisterUrl)]
            : AuthProbeDiscovery.DiscoverPaths(_ctx, pageUri, AuthProbeDiscovery.RegisterPathHints,
                AuthProbeDiscovery.LooksLikeRegisterPath, 3);

        var email = options.ValidUsername
                    ?? AuthProbeDiscovery.ExtractEmailFromNetwork(_ctx)
                    ?? AuthAccessHeuristics.DefaultEmailForHost(pageUri);
        foreach (var url in registerUrls)
        {
            ct.ThrowIfCancellationRequested();
            var body = $"{{\"email\":\"{email}\",\"password\":\"TrowserReg1!\",\"passwordRepeat\":\"TrowserReg1!\"}}";
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Content-Type"] = "application/json"
            };
            var resp = await SecurityProbeHttp.FetchAsync(_ctx, url, "POST", headers, body, options.TimeoutMs, true, ct);
            var lower = (resp.Body ?? "").ToLowerInvariant();
            if (LooksLikeExistingAccountMarker(lower))
            {
                return new ScanFinding
                {
                    Signal = "registration-email-exists",
                    Severity = "medium",
                    Title = $"Account enumeration via registration ({TruncatePath(url)})",
                    Url = url,
                    Method = "POST",
                    Detail = $"Registration reveals existing account for {email} (HTTP {resp.Status}).",
                    Evidence = new { email, resp.Status, snippet = (resp.Body ?? "").Length > 200 ? resp.Body![..200] : resp.Body }
                };
            }
        }

        return null;
    }

    /// <summary>
    /// Login failure text often differs between unknown account vs wrong password — include common phrasing
    /// beyond "invalid credentials" (school/lab apps frequently use explicit wording).
    /// </summary>
    private static bool EnumerationMessageLikelyDifferent(string validLower, string invalidLower)
    {
        static bool Has(string text, string needle) => text.Contains(needle, StringComparison.Ordinal);

        var needles = new[]
        {
            "invalid password",
            "wrong password",
            "incorrect password",
            "bad password",
            "unknown user",
            "user not found",
            "no such user",
            "no account",
            "not found",
            "invalid user",
            "unknown username",
            "invalid username"
        };

        foreach (var n in needles)
        {
            if (Has(validLower, n) != Has(invalidLower, n))
                return true;
        }

        return false;
    }

    private static bool LooksLikeExistingAccountMarker(string lower) =>
        lower.Contains("already exists", StringComparison.Ordinal)
        || lower.Contains("already registered", StringComparison.Ordinal)
        || lower.Contains("email already", StringComparison.Ordinal)
        || lower.Contains("user already", StringComparison.Ordinal)
        || lower.Contains("account already", StringComparison.Ordinal)
        || lower.Contains("account exists", StringComparison.Ordinal)
        || lower.Contains("email is taken", StringComparison.Ordinal)
        || lower.Contains("username is taken", StringComparison.Ordinal)
        || lower.Contains("duplicate email", StringComparison.Ordinal)
        || lower.Contains("duplicate user", StringComparison.Ordinal)
        || (lower.Contains("duplicate", StringComparison.Ordinal)
            && (lower.Contains("email", StringComparison.Ordinal) || lower.Contains("user", StringComparison.Ordinal)))
        || (lower.Contains("registered", StringComparison.Ordinal)
            && lower.Contains("email", StringComparison.Ordinal)
            && (lower.Contains("already", StringComparison.Ordinal) || lower.Contains("exist", StringComparison.Ordinal)));

    private static string TruncatePath(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var u))
            return u.PathAndQuery.Length > 60 ? u.PathAndQuery[..60] + "…" : u.PathAndQuery;
        return url.Length > 60 ? url[..60] + "…" : url;
    }
}
