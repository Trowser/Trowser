using System.Net.Http;
using System.Text;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>Shared login/auth-bypass detection for SQLi login sweep and LDAP scan.</summary>
public static class LoginInjectionHelpers
{
    public const string DummyPassword = "trowser-canary-9f3b2a-not-a-real-password";

    public static readonly string[] UsernameFields =
        ["email", "username", "user", "login"];

    public static readonly string[] PasswordFields =
        ["password", "pass", "passwd"];

    public static readonly string[] SqliBypassPayloads =
    [
        "' OR 1=1--",
        "' OR '1'='1",
        "' OR 1=1 --",
        "admin' --",
        "admin' OR 1=1 --",
        "' OR 'x'='x' --",
        "') OR ('1'='1"
    ];

    public static readonly string[] SessionCookieMarkers =
    [
        "session=", "_session=", "sessionid=", "JSESSIONID=", "connect.sid=", "auth=", "token=", "access_token="
    ];

    public static readonly string[] LoggedInBodyMarkers =
        ["logout", "log out", "sign out", "sign off", "my account", "dashboard", "welcome,", "bank main", "transfer funds"];

    public static readonly string[] LoginPathFragments =
        ["/login", "/signin", "/sign_in", "/auth", "/sessions/new"];

    public sealed class LoginProbeResponse
    {
        public int Status { get; init; }
        public string Body { get; init; } = "";
        public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
        public string? Location { get; init; }
    }

    public static async Task<LoginProbeResponse> PostJsonAsync(
        AutomationContext ctx,
        string url,
        object payload,
        Dictionary<string, string>? extraHeaders,
        int timeoutMs,
        bool followRedirects,
        bool includeBrowserCookies,
        CancellationToken ct = default)
    {
        var json = JsonSerializer.Serialize(payload);
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "application/json"
        };
        if (extraHeaders != null)
        {
            foreach (var kv in extraHeaders)
                headers[kv.Key] = kv.Value;
        }

        return await SendAsync(ctx, url, "POST", headers, json, timeoutMs, followRedirects, includeBrowserCookies, ct);
    }

    public static async Task<LoginProbeResponse> PostFormAsync(
        AutomationContext ctx,
        string url,
        Dictionary<string, string> fields,
        Dictionary<string, string>? extraHeaders,
        int timeoutMs,
        bool followRedirects,
        bool includeBrowserCookies,
        CancellationToken ct = default)
    {
        var body = string.Join("&", fields.Select(kv =>
            $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "application/x-www-form-urlencoded"
        };
        if (extraHeaders != null)
        {
            foreach (var kv in extraHeaders)
                headers[kv.Key] = kv.Value;
        }

        return await SendAsync(ctx, url, "POST", headers, body, timeoutMs, followRedirects, includeBrowserCookies, ct);
    }

    public static async Task<LoginProbeResponse> SendAsync(
        AutomationContext ctx,
        string url,
        string method,
        Dictionary<string, string>? headers,
        string? body,
        int timeoutMs,
        bool followRedirects,
        bool includeBrowserCookies,
        CancellationToken ct = default)
    {
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = followRedirects,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        using var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromMilliseconds(Math.Clamp(timeoutMs, 500, 600_000))
        };

        using var msg = new HttpRequestMessage(new HttpMethod(method), url);
        msg.Content = InjectionHttpTransport.BuildContent(body, headers);

        InjectionHttpTransport.ApplyHeaders(msg, headers);

        if (includeBrowserCookies)
        {
            var ck = await ctx.GetCookieHeaderForUrl(url);
            if (!string.IsNullOrEmpty(ck))
            {
                ck = CookieHeaderSanitizer.SanitizeCookieHeader(ck);
                if (msg.Headers.TryGetValues("Cookie", out var existing))
                    msg.Headers.Remove("Cookie");
                msg.Headers.TryAddWithoutValidation("Cookie", ck);
            }
        }

        using var resp = await client.SendAsync(msg, ct).ConfigureAwait(false);
        var text = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        var hdrs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in resp.Headers)
            hdrs[h.Key] = string.Join(", ", h.Value);
        foreach (var h in resp.Content.Headers)
            hdrs[h.Key] = string.Join(", ", h.Value);

        string? location = resp.Headers.Location?.ToString();
        if (location == null && hdrs.TryGetValue("Location", out var loc))
            location = loc;

        return new LoginProbeResponse
        {
            Status = (int)resp.StatusCode,
            Body = text,
            Headers = hdrs,
            Location = location
        };
    }

    public static bool LooksLikeAuthenticatedLogin(
        SecurityProbeHttp.FetchResult login,
        SecurityProbeHttp.FetchResult baseline)
    {
        var attack = ToLoginProbeResponse(login);
        var baseR = ToLoginProbeResponse(baseline);
        if (ClassifyAuthBypass(attack, baseR) != null) return true;

        if (login.Status is 401 or 403 or >= 500) return false;
        var body = login.Body ?? "";
        var lower = body.ToLowerInvariant();
        if (lower.Contains("invalid password") || lower.Contains("login failed")
            || lower.Contains("incorrect") || lower.Contains("wrong password")
            || lower.Contains("authentication failed") || lower.Contains("invalid credentials"))
            return false;

        if (JsonTokenEmergence(baseline.Body ?? "", body)) return true;
        if (login.Status is >= 200 and < 300
            && (lower.Contains("token") || lower.Contains("authentication") || lower.Contains("basket")))
            return true;
        if (login.Status is 301 or 302) return true;
        return login.Status == 200 && baseline.Status != 200;
    }

    private static LoginProbeResponse ToLoginProbeResponse(SecurityProbeHttp.FetchResult r)
    {
        r.ResponseHeaders.TryGetValue("Location", out var location);
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in r.ResponseHeaders)
            headers[kv.Key] = kv.Value;
        return new LoginProbeResponse
        {
            Status = r.Status,
            Body = r.Body ?? "",
            Headers = headers,
            Location = location
        };
    }

    public static (string Signal, string Evidence)? ClassifyAuthBypass(
        LoginProbeResponse attack,
        LoginProbeResponse baseline)
    {
        if (attack.Status is >= 300 and < 400)
        {
            if (LocationIndicatesBypass(attack.Location))
            {
                // Already-authenticated sessions often redirect any POST on /login away from login —
                // compare to the invalid-credential baseline, not attack alone.
                if (baseline.Status is >= 300 and < 400
                    && LocationIndicatesBypass(baseline.Location)
                    && RedirectLocationsEquivalent(attack.Location, baseline.Location))
                    return null;

                return ("redirect_to_authed_page", $"Location: {attack.Location?[..Math.Min(attack.Location.Length, 200)]}");
            }
        }

        var cookieHit = HasNewSessionCookie(attack.Headers, baseline.Headers);
        if (cookieHit != null)
            return ("session_cookie_minted", $"Set-Cookie: {cookieHit}");

        if (attack.Status == 200 && baseline.Status != 200)
        {
            var marker = HasNewLoggedInMarker(attack.Body, baseline.Body);
            if (marker != null)
                return ("logged_in_marker", $"response body contained '{marker}'");
            return ("status_flip_to_200", $"baseline {baseline.Status} vs attack {attack.Status}");
        }

        if (attack.Status == 200 && baseline.Status == 200)
        {
            var marker = HasNewLoggedInMarker(attack.Body, baseline.Body);
            if (marker != null)
                return ("logged_in_marker", $"response body contained '{marker}'");
        }

        if (JsonTokenEmergence(baseline.Body, attack.Body))
            return ("json_token_emergence", "attack JSON response includes token/authentication field absent in baseline");

        return null;
    }

    public static bool LocationIndicatesBypass(string? location)
    {
        if (string.IsNullOrEmpty(location)) return false;
        var loc = location.ToLowerInvariant();
        return !LoginPathFragments.Any(frag => loc.Contains(frag, StringComparison.Ordinal));
    }

    /// <summary>True when two redirect Location values target the same landing (path + query, fragment ignored).</summary>
    public static bool RedirectLocationsEquivalent(string? a, string? b)
    {
        if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b)) return false;
        return string.Equals(NormalizeRedirectLocation(a), NormalizeRedirectLocation(b), StringComparison.OrdinalIgnoreCase);
    }

    internal static string NormalizeRedirectLocation(string location)
    {
        var trimmed = location.Trim();
        var noFragment = trimmed.Split('#')[0];
        if (Uri.TryCreate(noFragment, UriKind.Absolute, out var absolute))
            return absolute.AbsolutePath + absolute.Query;
        if (Uri.TryCreate(noFragment, UriKind.Relative, out var relative))
            return relative.OriginalString;
        return noFragment;
    }

    public static string? HasNewSessionCookie(
        IReadOnlyDictionary<string, string> attackHeaders,
        IReadOnlyDictionary<string, string> baselineHeaders)
    {
        var aCookie = GetHeader(attackHeaders, "Set-Cookie");
        var bCookie = GetHeader(baselineHeaders, "Set-Cookie");
        if (string.IsNullOrEmpty(aCookie)) return null;
        foreach (var marker in SessionCookieMarkers)
        {
            if (aCookie.Contains(marker, StringComparison.OrdinalIgnoreCase)
                && !bCookie.Contains(marker, StringComparison.OrdinalIgnoreCase))
                return aCookie.Length > 200 ? aCookie[..200] : aCookie;
        }

        return null;
    }

    public static string? HasNewLoggedInMarker(string attackBody, string baselineBody)
    {
        var a = attackBody.ToLowerInvariant();
        var b = baselineBody.ToLowerInvariant();
        foreach (var marker in LoggedInBodyMarkers)
        {
            if (a.Contains(marker, StringComparison.Ordinal) && !b.Contains(marker, StringComparison.Ordinal))
                return marker;
        }

        return null;
    }

    public static bool JsonTokenEmergence(string baselineBody, string attackBody) =>
        attackBody.Contains("\"token\"", StringComparison.OrdinalIgnoreCase)
        && !baselineBody.Contains("\"token\"", StringComparison.OrdinalIgnoreCase)
        || attackBody.Contains("\"authentication\"", StringComparison.OrdinalIgnoreCase)
        && !baselineBody.Contains("\"authentication\"", StringComparison.OrdinalIgnoreCase);

    public static bool NosqlBypassSuspected(
        LoginProbeResponse attack,
        LoginProbeResponse baseline,
        string? payload = null,
        TechStackResult? stack = null,
        bool allowSizeHeuristic = true,
        LoginProbeResponse? noParamBaseline = null)
    {
        if (attack.Status == 0) return false;

        if (noParamBaseline != null
            && attack.Status == noParamBaseline.Status
            && ResponseBodiesSimilar(attack.Body, noParamBaseline.Body))
            return false;
        if (attack.Status == 200
            && (attack.Body.Contains("\"token\"", StringComparison.OrdinalIgnoreCase)
                || attack.Body.Contains("\"authentication\"", StringComparison.OrdinalIgnoreCase))
            && !baseline.Body.Contains("\"token\"", StringComparison.OrdinalIgnoreCase)
            && !baseline.Body.Contains("\"authentication\"", StringComparison.OrdinalIgnoreCase))
            return true;

        if (attack.Status == 200
            && attack.Body.Contains("\"email\"", StringComparison.OrdinalIgnoreCase)
            && attack.Body.Contains("\"role\"", StringComparison.OrdinalIgnoreCase)
            && !(baseline.Body.Contains("\"email\"", StringComparison.OrdinalIgnoreCase)
                 && baseline.Body.Contains("\"role\"", StringComparison.OrdinalIgnoreCase)))
            return true;

        if (InjectionProbeFilters.ResponseHasNosqlErrorEvidence(attack.Body))
            return true;

        // Large SQL error pages must not become NoSQL size-heuristic hits.
        if (InjectionProbeFilters.ResponseHasRelationalSqlErrorEvidence(attack.Body))
            return false;

        if (!allowSizeHeuristic
            || !InjectionProbeFilters.NosqlSizeHeuristicAllowed(payload, stack))
            return false;

        return attack.Status == 200
               && baseline.Body.Length > 0
               && attack.Body.Length >= 3.0 * Math.Max(baseline.Body.Length, 1);
    }

    /// <summary>
    /// Burp-style paired probe: flag when false/true payloads diverge asymmetrically from baseline
    /// (avoids FPs when both sides cause the same error page or param is ignored).
    /// </summary>
    public static bool NosqlPairInjectionSuspected(
        LoginProbeResponse falseResp,
        LoginProbeResponse trueResp,
        LoginProbeResponse baseline,
        LoginProbeResponse? noParamBaseline = null,
        long falseElapsedMs = 0,
        long trueElapsedMs = 0,
        NosqlInjectionPayloads.PayloadKind kind = NosqlInjectionPayloads.PayloadKind.JsonPair)
    {
        if (falseResp.Status == 0 || trueResp.Status == 0) return false;

        if (noParamBaseline != null
            && falseResp.Status == noParamBaseline.Status
            && trueResp.Status == noParamBaseline.Status
            && ResponseBodiesSimilar(falseResp.Body, noParamBaseline.Body)
            && ResponseBodiesSimilar(trueResp.Body, noParamBaseline.Body))
            return false;

        if (NosqlBypassSuspected(trueResp, baseline, null, null, allowSizeHeuristic: false, noParamBaseline)
            && !NosqlBypassSuspected(falseResp, baseline, null, null, allowSizeHeuristic: false, noParamBaseline))
            return true;

        if (InjectionProbeFilters.ResponseHasNosqlErrorEvidence(trueResp.Body)
            && !InjectionProbeFilters.ResponseHasNosqlErrorEvidence(falseResp.Body))
            return true;

        if (kind == NosqlInjectionPayloads.PayloadKind.TimePair
            && falseElapsedMs > 0 && trueElapsedMs > 0)
        {
            var diff = trueElapsedMs - falseElapsedMs;
            if (diff >= 3500 && falseElapsedMs <= 8000)
                return true;
        }

        var pairDiffers = falseResp.Status != trueResp.Status
                          || !ResponseBodiesSimilar(falseResp.Body, trueResp.Body);
        if (!pairDiffers) return false;

        var falseDiffersFromBase = falseResp.Status != baseline.Status
                                   || !ResponseBodiesSimilar(falseResp.Body, baseline.Body);
        var trueDiffersFromBase = trueResp.Status != baseline.Status
                                  || !ResponseBodiesSimilar(trueResp.Body, baseline.Body);

        if (falseDiffersFromBase && trueDiffersFromBase
            && ResponseBodiesSimilar(falseResp.Body, trueResp.Body))
            return false;

        if (falseDiffersFromBase != trueDiffersFromBase)
            return true;

        if (falseDiffersFromBase && trueDiffersFromBase)
        {
            if (JsonTokenEmergence(baseline.Body, trueResp.Body)
                && !JsonTokenEmergence(baseline.Body, falseResp.Body))
                return true;

            if (HasNewLoggedInMarker(trueResp.Body, baseline.Body) != null
                && HasNewLoggedInMarker(falseResp.Body, baseline.Body) == null)
                return true;
        }

        return false;
    }

    public static bool NosqlErrorInjectionSuspected(LoginProbeResponse attack) =>
        attack.Status != 0 && InjectionProbeFilters.ResponseHasNosqlErrorEvidence(attack.Body);

    /// <summary>
    /// True when two bodies are close enough to treat as the same endpoint outcome
    /// (e.g. operator payload used an ignored param name and returned the default listing).
    /// </summary>
    public static bool ResponseBodiesSimilar(string a, string b)
    {
        if (string.Equals(a, b, StringComparison.Ordinal)) return true;
        if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b)) return false;
        var max = Math.Max(a.Length, b.Length);
        var min = Math.Min(a.Length, b.Length);
        if (max == 0) return true;
        return (double)max / min <= 1.12;
    }

    public static bool LdapBypassSuspected(LoginProbeResponse attack, LoginProbeResponse baseline)
    {
        if (baseline.Status is not (401 or 403)) return false;
        var statusFlip = attack.Status == 200;
        var (hasSignal, _) = ClassifyLdapAuthSignal(attack);
        if (statusFlip && hasSignal) return true;
        return statusFlip;
    }

    public static (bool HasSignal, string Detail) ClassifyLdapAuthSignal(LoginProbeResponse attack)
    {
        if (GetHeader(attack.Headers, "Set-Cookie") is { Length: > 0 } cookie)
            return (true, $"Set-Cookie issued: {cookie[..Math.Min(cookie.Length, 120)]}");

        if (!string.IsNullOrEmpty(attack.Location)
            && (attack.Location.Contains("dashboard", StringComparison.OrdinalIgnoreCase)
                || attack.Location.Contains("account", StringComparison.OrdinalIgnoreCase)
                || attack.Location.Contains("profile", StringComparison.OrdinalIgnoreCase)
                || attack.Location.Contains("home", StringComparison.OrdinalIgnoreCase)))
            return (true, $"Redirect to authenticated landing: {attack.Location[..Math.Min(attack.Location.Length, 120)]}");

        if (System.Text.RegularExpressions.Regex.IsMatch(attack.Body[..Math.Min(attack.Body.Length, 4096)],
                @"\b(token|jwt|authorization|access_token|id_token|bearer)\b", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
            return (true, "Auth token-shaped field in response body");

        return (false, "");
    }

    private static string GetHeader(IReadOnlyDictionary<string, string> headers, string name)
    {
        foreach (var kv in headers)
        {
            if (kv.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
                return kv.Value;
        }

        return "";
    }
}
