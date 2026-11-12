using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Audits cookies for security best practices: Secure, HttpOnly, SameSite,
/// Domain/Path scoping, and excessive lifetimes for session tokens.
/// Operates on a generic cookie dictionary format so it works with
/// both the WebView2 CookieManager and the CDP Network.getCookies fallback.
/// </summary>
public class CookieAuditChecker
{
    /// <summary>
    /// Cookie name patterns that suggest session/auth tokens.
    /// These get stricter checks (must have Secure + HttpOnly).
    /// </summary>
    private static readonly string[] SessionCookiePatterns =
    [
        "session", "sess", "sid", "token", "auth", "jwt", "access",
        "refresh", "login", "shibboleth", "saml", "shib", "idp",
        "jsessionid", "phpsessid", "asp.net_sessionid", "aspsessionid",
        "connect.sid", "laravel_session", "ci_session", "_identity",
        "remember", "csrf", "xsrf", "_csrf_token",
        // Training / demo apps and generic app-named cookies (e.g. Google Gruyere)
        "gruyere", "userid", "user_id", "profile", "account", "member"
    ];

    /// <summary>
    /// First-party analytics / consent cookies — not session theft targets; skip HttpOnly audit
    /// when the cookie is non-persistent (session) but name matches these prefixes.
    /// </summary>
    private static readonly string[] BenignCookiePrefixes =
    [
        "_ga", "_gid", "_gat", "_gcl_", "_fbp", "_fbc", "__utm", "_hj", "mp_",
        "intercom", "crisp", "cookieconsent", "cconsent", "optanon", "euconsent",
        "__cf_bm", "cf_clearance", "_pk_", "matomo", "hubspot", "hs-scripts",
        "amplitude", "segment", "ajs_", "ph_", "sp_", "tk_lr", "tk_or"
    ];

    /// <summary>
    /// Known vendor analytics/RUM cookies that are designed to be JS-readable.
    /// Matched case-insensitively against the full cookie name. HttpOnly is not applicable.
    /// </summary>
    private static readonly (string Pattern, string Vendor)[] VendorAnalyticsCookies =
    [
        ("dtpc", "Dynatrace"), ("dtsa", "Dynatrace"), ("dtcookie", "Dynatrace"),
        ("dtlatc", "Dynatrace"), ("rxvt", "Dynatrace"), ("rxvisitor", "Dynatrace"),
        ("_hjsessionuser_", "Hotjar"), ("_hjsession_", "Hotjar"),
        ("_hjid", "Hotjar"), ("_hjfirstseen", "Hotjar"), ("_hjincludedindebug", "Hotjar"),
        ("_hjabsoluteviewedindex", "Hotjar"), ("_hjtldtest", "Hotjar"),
        ("_ga", "Google Analytics"), ("_gid", "Google Analytics"),
        ("_gat", "Google Analytics"), ("_gcl_", "Google Analytics"),
        ("__utm", "Google Analytics"),
        ("_fbp", "Facebook Pixel"), ("_fbc", "Facebook Pixel"),
    ];

    /// <summary>
    /// Analytics, consent, and infrastructure cookies are JS-readable by design — not session theft targets.
    /// </summary>
    public static bool IsJsReadableByDesign(string cookieName)
    {
        if (string.IsNullOrWhiteSpace(cookieName)) return false;
        if (InfrastructureCookieClassifier.IsInfrastructureCookie(cookieName)) return true;
        if (GetVendorAnalyticsOwner(cookieName) != null) return true;
        return IsBenignTrackingCookie(cookieName);
    }

    /// <summary>Max lifetime (in days) before a session-like cookie is flagged.</summary>
    private const int MaxSessionCookieLifetimeDays = 30;

    /// <summary>
    /// Reconcile cookie flags from Set-Cookie headers in the network log (authoritative for
    /// HttpOnly, Secure, SameSite). Updates matching jar rows or adds cookies only seen on the wire.
    /// </summary>
    public static List<string> MergeNetworkSetCookies(
        string pageUrl,
        List<Dictionary<string, object>> cookies,
        IEnumerable<NetworkEntry> networkEntries,
        bool pageScopeOnly = false)
    {
        var reconciled = new List<string>();
        var fromNetwork = SetCookieHeaderParser.ExtractFromNetworkEntries(networkEntries, pageUrl, pageScopeOnly);
        if (fromNetwork.Count == 0)
            return reconciled;

        foreach (var net in fromNetwork)
        {
            var name = GetStr(net, "name");
            var domain = GetStr(net, "domain");
            var path = GetStr(net, "path");
            if (string.IsNullOrEmpty(path))
                path = "/";

            var existing = cookies.FirstOrDefault(c => CookieIdentityMatches(c, name, domain, path, pageUrl));
            if (existing != null)
            {
                var changed = ApplyNetworkFlags(existing, net);
                existing["_flagsFromNetwork"] = true;
                if (changed)
                    reconciled.Add(name);
            }
            else
            {
                cookies.Add(new Dictionary<string, object>(net));
                reconciled.Add(name);
            }
        }

        return reconciled.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static bool ApplyNetworkFlags(Dictionary<string, object> target, Dictionary<string, object> fromNetwork)
    {
        var changed = false;
        foreach (var key in new[] { "secure", "httpOnly", "sameSite", "session", "expires", "domain", "path", "_sameSiteExplicit" })
        {
            if (!fromNetwork.TryGetValue(key, out var val))
                continue;
            if (!target.TryGetValue(key, out var old) || !Equals(old, val))
            {
                target[key] = val;
                changed = true;
            }
        }
        return changed;
    }

    private static bool CookieIdentityMatches(
        Dictionary<string, object> cookie,
        string name,
        string domain,
        string path,
        string pageUrl)
    {
        if (!GetStr(cookie, "name").Equals(name, StringComparison.OrdinalIgnoreCase))
            return false;

        var cookieDomain = GetStr(cookie, "domain");
        var cookiePath = GetStr(cookie, "path");
        if (string.IsNullOrEmpty(cookiePath))
            cookiePath = "/";

        if (!string.IsNullOrEmpty(domain) && !string.IsNullOrEmpty(cookieDomain)
            && !domain.TrimStart('.').Equals(cookieDomain.TrimStart('.'), StringComparison.OrdinalIgnoreCase))
            return false;

        if (!path.Equals(cookiePath, StringComparison.OrdinalIgnoreCase)
            && !cookiePath.Equals("/", StringComparison.OrdinalIgnoreCase))
            return false;

        if (Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri) && !string.IsNullOrEmpty(cookieDomain))
            return SetCookieHeaderParser.HostMatchesCookieDomain(pageUri.Host, cookieDomain);

        return true;
    }

    /// <summary>
    /// Ensures every name in <c>document.cookie</c> appears in <paramref name="cookies"/> so audits
    /// cover non-HttpOnly cookies visible to scripts when the cookie jar API omits them.
    /// Does not add names already present. Never overrides HttpOnly/Secure from network reconciliation.
    /// </summary>
    public static void MergeDocumentCookieNames(string pageUrl, List<Dictionary<string, object>> cookies, string? documentCookieLine)
    {
        if (string.IsNullOrWhiteSpace(documentCookieLine))
            return;

        Uri? pageUri = Uri.TryCreate(pageUrl, UriKind.Absolute, out var u) ? u : null;
        var host = pageUri?.Host ?? "";
        var isHttps = pageUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

        var existing = new HashSet<string>(
            cookies.Select(c => GetStr(c, "name")),
            StringComparer.OrdinalIgnoreCase);

        foreach (var part in documentCookieLine.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = part.IndexOf('=');
            var name = eq >= 0 ? part[..eq].Trim() : part.Trim();
            if (string.IsNullOrEmpty(name) || existing.Contains(name))
                continue;

            var value = eq >= 0 ? part[(eq + 1)..].Trim() : "";
            var infra = InfrastructureCookieClassifier.IsInfrastructureCookie(name);
            cookies.Add(new Dictionary<string, object>
            {
                ["name"] = name,
                ["value"] = value,
                ["domain"] = host,
                ["path"] = "/",
                ["secure"] = isHttps,
                ["httpOnly"] = false,
                ["sameSite"] = "lax",
                ["session"] = !infra,
                ["_fromDocumentCookie"] = true,
                ["_sameSiteExplicit"] = false
            });
            existing.Add(name);
        }
    }

    /// <summary>
    /// Run the cookie security audit against a pre-fetched cookie list.
    /// Each cookie is a Dictionary with keys: name, value, domain, path, secure, httpOnly, sameSite, session, expires (optional).
    /// </summary>
    public CookieAuditResult Run(
        string url,
        List<Dictionary<string, object>> cookies,
        IReadOnlyList<string>? networkReconciled = null)
    {
        var isHttps = url.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        var findings = new List<CookieFinding>();

        foreach (var cookie in cookies)
        {
            var name = GetStr(cookie, "name");
            var isSecure = GetBool(cookie, "secure");
            var isHttpOnly = GetBool(cookie, "httpOnly");
            var sameSite = GetStr(cookie, "sameSite").ToLowerInvariant();
            var sameSiteExplicit = GetBool(cookie, "_sameSiteExplicit");
            var domain = GetStr(cookie, "domain");
            var isSession = GetBool(cookie, "session");
            var isSessionCookie = IsSessionCookie(name);
            var valueStr = GetStr(cookie, "value");
            var requiresHttpOnly = RequiresHttpOnlyAudit(name, GetBool(cookie, "session"), valueStr);

            if (isHttps && !isSecure && isSessionCookie)
            {
                findings.Add(new CookieFinding
                {
                    CookieName = name,
                    Severity = Severity.High,
                    Category = "MissingSecure",
                    Description = "Session cookie is not marked Secure. It can be transmitted over unencrypted HTTP connections, allowing interception.",
                    Recommendation = "Set the Secure flag on this cookie so it is only sent over HTTPS."
                });
            }
            else if (isHttps && !isSecure
                     && !IsBenignTrackingCookie(name)
                     && GetVendorAnalyticsOwner(name) == null
                     && !InfrastructureCookieClassifier.IsInfrastructureCookie(name))
            {
                findings.Add(new CookieFinding
                {
                    CookieName = name,
                    Severity = Severity.Low,
                    Category = "MissingSecure",
                    Description = "Cookie is not marked Secure. On HTTPS sites, all cookies should use the Secure flag.",
                    Recommendation = "Set the Secure flag on this cookie."
                });
            }

            if (requiresHttpOnly && !isHttpOnly && !InfrastructureCookieClassifier.IsInfrastructureCookie(name))
            {
                var antiforgery = IsAntiForgeryTokenCookie(name);
                findings.Add(new CookieFinding
                {
                    CookieName = name,
                    Severity = antiforgery ? Severity.Low : Severity.High,
                    Category = "MissingHttpOnly",
                    Description = antiforgery
                        ? "Anti-CSRF cookie is readable by JavaScript (HttpOnly not set). Many frameworks omit HttpOnly so the SPA can mirror the token in headers; XSS can still read it — narrower impact than leaking a primary session credential."
                        : "Session or authentication cookie is accessible to JavaScript (missing HttpOnly flag). This makes it vulnerable to XSS-based session theft.",
                    Recommendation = antiforgery
                        ? "Where possible prefer patterns that avoid exposing the cookie to scripts; otherwise prioritize XSS defenses and SameSite/session hardening."
                        : "Set the HttpOnly flag so JavaScript cannot access this cookie."
                });
            }

            if (sameSite == "none" && !isSecure)
            {
                findings.Add(new CookieFinding
                {
                    CookieName = name,
                    Severity = Severity.High,
                    Category = "SameSiteNoneInsecure",
                    Description = "Cookie has SameSite=None without the Secure flag. Modern browsers will reject this cookie.",
                    Recommendation = "Either set SameSite to Lax/Strict, or add the Secure flag when using SameSite=None."
                });
            }
            else if (sameSite == "none" && (isSessionCookie || LooksLikeSessionTicketValue(valueStr)))
            {
                findings.Add(new CookieFinding
                {
                    CookieName = name,
                    Severity = Severity.Medium,
                    Category = "SameSiteNone",
                    Description = "Session cookie has SameSite=None, allowing it to be sent in cross-site requests. This weakens CSRF protection.",
                    Recommendation = "Set SameSite to Lax or Strict for session cookies unless cross-site sending is required."
                });
            }
            else if (isSessionCookie && !sameSiteExplicit)
            {
                var effective = string.IsNullOrEmpty(sameSite) ? "lax (browser default)" : $"{sameSite} (not declared on Set-Cookie)";
                findings.Add(new CookieFinding
                {
                    CookieName = name,
                    Severity = Severity.Low,
                    Category = "MissingExplicitSameSite",
                    Description =
                        $"Session cookie SameSite was not explicitly set by the application ({effective}). " +
                        "Relying on browser defaults is not an intentional CSRF policy.",
                    Recommendation = "Set an explicit SameSite attribute (Lax or Strict for session cookies) on Set-Cookie."
                });
            }

            if (!string.IsNullOrEmpty(domain) && domain.StartsWith(".") && isSessionCookie)
            {
                var parts = domain.TrimStart('.').Split('.');
                if (parts.Length <= 2)
                {
                    findings.Add(new CookieFinding
                    {
                        CookieName = name,
                        Severity = Severity.Medium,
                        Category = "BroadDomain",
                        Description = $"Session cookie domain '{domain}' is broadly scoped to the entire registered domain, sharing it with all subdomains.",
                        Recommendation = "Scope session cookies to the specific subdomain that needs them (e.g., .app.example.com instead of .example.com)."
                    });
                }
            }

            if (isSessionCookie && !isSession)
            {
                var expiresUtc = ParseExpires(cookie);
                if (expiresUtc.HasValue)
                {
                    var lifetimeDays = (expiresUtc.Value - DateTime.UtcNow).TotalDays;
                    if (lifetimeDays > MaxSessionCookieLifetimeDays)
                    {
                        findings.Add(new CookieFinding
                        {
                            CookieName = name,
                            Severity = Severity.Medium,
                            Category = "ExcessiveLifetime",
                            Description = $"Session cookie has a lifetime of {lifetimeDays:F0} days (expires {expiresUtc.Value:yyyy-MM-dd}). Long-lived session cookies increase the window for session hijacking.",
                            Recommendation = $"Reduce the cookie lifetime to {MaxSessionCookieLifetimeDays} days or less, or make it a session cookie (no Expires/Max-Age)."
                        });
                    }
                }
            }
        }

        var names = cookies.Select(c => GetStr(c, "name")).ToList();
        var checklist = BuildChecklist(cookies, findings, isHttps);

        return new CookieAuditResult
        {
            Url = url,
            Timestamp = DateTime.UtcNow,
            CookieCount = cookies.Count,
            Findings = findings,
            Checklist = checklist,
            PrimarySource = networkReconciled is { Count: > 0 }
                ? "cookieJar+networkSetCookie"
                : "cookieJar",
            NetworkReconciledCookies = networkReconciled?.ToList() ?? new List<string>()
        };
    }

    private static Dictionary<string, CookieChecklistItem> BuildChecklist(
        List<Dictionary<string, object>> cookies, List<CookieFinding> findings, bool isHttps)
    {
        var checklist = new Dictionary<string, CookieChecklistItem>();
        if (cookies.Count == 0) return checklist;

        var sessionCookieNames = cookies
            .Where(c => IsSessionCookie(GetStr(c, "name")))
            .Select(c => GetStr(c, "name"))
            .Distinct().ToList();
        var allNames = cookies.Select(c => GetStr(c, "name")).Distinct().ToList();

        if (isHttps)
        {
            var missingSecure = findings
                .Where(f => f.Category == "MissingSecure")
                .Select(f => f.CookieName).Distinct().ToList();
            checklist["Secure flag on HTTPS"] = new CookieChecklistItem
            {
                Pass = missingSecure.Count == 0,
                Issue = missingSecure.Count > 0 ? $"Missing Secure flag on {string.Join(", ", missingSecure)}" : null,
                Cookies = missingSecure.Count == 0
                    ? cookies.Where(c => GetBool(c, "secure")).Select(c => GetStr(c, "name")).Distinct().ToList()
                    : missingSecure
            };
        }
        else
        {
            checklist["Secure flag on HTTPS"] = new CookieChecklistItem
            {
                Pass = false,
                Skipped = true,
                Issue = "Page URL is not HTTPS — Secure attribute not required on this origin",
                Cookies = cookies.Select(c => GetStr(c, "name")).Distinct().ToList()
            };
        }

        var httpOnlyScopeNames = cookies
            .Where(c => RequiresHttpOnlyAudit(GetStr(c, "name"), GetBool(c, "session"), GetStr(c, "value")))
            .Select(c => GetStr(c, "name"))
            .Distinct()
            .ToList();

        if (httpOnlyScopeNames.Count > 0)
        {
            var missingHttpOnly = findings
                .Where(f => f.Category == "MissingHttpOnly")
                .Select(f => f.CookieName).Distinct().ToList();
            checklist["HttpOnly on session cookies"] = new CookieChecklistItem
            {
                Pass = missingHttpOnly.Count == 0,
                Issue = missingHttpOnly.Count > 0 ? $"Missing HttpOnly on {string.Join(", ", missingHttpOnly)}" : null,
                Cookies = missingHttpOnly.Count == 0
                    ? cookies.Where(c => RequiresHttpOnlyAudit(GetStr(c, "name"), GetBool(c, "session"), GetStr(c, "value")) && GetBool(c, "httpOnly"))
                        .Select(c => GetStr(c, "name")).Distinct().ToList()
                    : missingHttpOnly
            };
        }

        var sameSiteIssues = findings
            .Where(f => f.Category is "SameSiteNone" or "SameSiteNoneInsecure" or "MissingExplicitSameSite")
            .Select(f => f.CookieName).Distinct().ToList();
        checklist["SameSite configured"] = new CookieChecklistItem
        {
            Pass = sameSiteIssues.Count == 0,
            Issue = sameSiteIssues.Count > 0
                ? $"SameSite issues on {string.Join(", ", sameSiteIssues)}"
                : null,
            Cookies = sameSiteIssues.Count == 0 ? allNames : sameSiteIssues
        };

        var broadDomain = findings
            .Where(f => f.Category == "BroadDomain")
            .Select(f => f.CookieName).Distinct().ToList();
        checklist["No overly broad domain"] = new CookieChecklistItem
        {
            Pass = broadDomain.Count == 0,
            Issue = broadDomain.Count > 0 ? $"Broad domain on {string.Join(", ", broadDomain)}" : null,
            Cookies = broadDomain
        };

        if (sessionCookieNames.Count > 0)
        {
            var excessiveLifetime = findings
                .Where(f => f.Category == "ExcessiveLifetime")
                .Select(f => f.CookieName).Distinct().ToList();
            checklist["Session cookie lifetime"] = new CookieChecklistItem
            {
                Pass = excessiveLifetime.Count == 0,
                Issue = excessiveLifetime.Count > 0
                    ? $"Excessive lifetime on {string.Join(", ", excessiveLifetime)}"
                    : null,
                Cookies = excessiveLifetime.Count == 0 ? sessionCookieNames : excessiveLifetime
            };
        }

        return checklist;
    }

    /// <summary>
    /// Names that behave like CSRF/XSRF or anti-forgery tokens — often intentionally non-HttpOnly
    /// (double-submit, header syncing). Missing HttpOnly is informational, not equivalent to session theft.
    /// </summary>
    private static bool IsAntiForgeryTokenCookie(string name)
    {
        var lower = name.ToLowerInvariant();
        if (lower.Contains("xsrf")) return true;
        if (lower.Contains("csrf")) return true;
        if (lower.Contains("antiforgery")) return true;
        if (lower.Contains("verificationtoken")) return true;
        return false;
    }

    private static bool IsSessionCookie(string name) => SessionCookieDetector.IsSessionCookieName(name);

    private static bool IsBenignTrackingCookie(string name)
    {
        var lower = name.ToLowerInvariant();
        return BenignCookiePrefixes.Any(p => lower.StartsWith(p, StringComparison.OrdinalIgnoreCase));
    }

    private static string? GetVendorAnalyticsOwner(string name)
    {
        var lower = name.ToLowerInvariant();
        foreach (var (pattern, vendor) in VendorAnalyticsCookies)
        {
            if (lower == pattern || lower.StartsWith(pattern, StringComparison.Ordinal))
                return vendor;
        }
        return null;
    }

    /// <summary>
    /// Cookies that should enforce HttpOnly: name matches session/auth heuristics, or value shaped
    /// like a session ticket (e.g. <c>hash|user||role</c>, JWT-like).
    /// Session-by-expiry alone is not enough — counters and UX cookies often omit Expires without
    /// being auth tokens. Known vendor analytics cookies are excluded (JS-readable by design).
    /// </summary>
    private static bool RequiresHttpOnlyAudit(string name, bool sessionByExpiry, string value)
    {
        if (InfrastructureCookieClassifier.IsInfrastructureCookie(name))
            return false;
        if (GetVendorAnalyticsOwner(name) != null)
            return false;
        if (IsNonAuthUtilityCookie(name))
            return false;
        if (IsSessionCookie(name))
            return true;
        if (LooksLikeSessionTicketValue(value))
            return true;
        // session-by-expiry alone is insufficient for HIGH HttpOnly findings
        _ = sessionByExpiry;
        return false;
    }

    /// <summary>Counters, language, theme, and similar non-auth cookies — not session-theft targets.</summary>
    private static bool IsNonAuthUtilityCookie(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        var lower = name.ToLowerInvariant();
        foreach (var token in NonAuthUtilityTokens)
        {
            if (lower.Contains(token, StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    private static readonly string[] NonAuthUtilityTokens =
    [
        "counter", "count", "calls", "language", "lang", "locale", "theme", "timezone",
        "tz", "consent", "cookieconsent", "sidebar", "collapse", "preference", "prefs",
        "display", "ui-", "ux-", "continuecode"
    ];

    /// <summary>Pipe-delimited session blobs (Gruyere-style) or compact JWT-like tokens.</summary>
    private static bool LooksLikeSessionTicketValue(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length < 12)
            return false;
        if (value.Contains('<') || value.Contains('>'))
            return false;

        var pipeCount = value.Count(c => c == '|');
        if (pipeCount >= 2 && value.Length <= 2048)
        {
            if (Regex.IsMatch(value, @"^[^|\s]{6,}\|[^|]*\|"))
                return true;
        }

        if (value.StartsWith("eyJ", StringComparison.Ordinal) && value.Count(c => c == '.') == 2 && value.Length > 40)
            return true;

        return false;
    }

    private static DateTime? ParseExpires(Dictionary<string, object> cookie)
    {
        if (!cookie.TryGetValue("expires", out var val) || val == null)
            return null;
        if (val is DateTime dt) return dt;
        if (val is string s && DateTime.TryParse(s, null, System.Globalization.DateTimeStyles.RoundtripKind, out var parsed))
            return parsed;
        return null;
    }

    private static string GetStr(Dictionary<string, object> d, string key) =>
        d.TryGetValue(key, out var v) ? v?.ToString() ?? "" : "";

    private static bool GetBool(Dictionary<string, object> d, string key)
    {
        if (!d.TryGetValue(key, out var v) || v == null)
            return false;
        if (v is bool b)
            return b;
        if (v is JsonElement je)
            return je.ValueKind is JsonValueKind.True;
        return string.Equals(v.ToString(), "true", StringComparison.OrdinalIgnoreCase);
    }
}
