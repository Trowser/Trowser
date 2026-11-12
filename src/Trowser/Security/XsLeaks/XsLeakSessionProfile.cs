using Trowser.Automation;
using Trowser.Security;

namespace Trowser.Security.XsLeaks;

public sealed class XsLeakSessionProfile
{
    public string CookieMode { get; init; } = "unknown";
    public string AuthMechanism { get; init; } = "unknown";
    public List<AuthCookieCandidate> AuthCookies { get; init; } = [];
    public List<string> Notes { get; init; } = [];

    public sealed class AuthCookieCandidate
    {
        public string Name { get; init; } = "";
        public string Domain { get; init; } = "";
        public string SameSite { get; init; } = "lax";
        public bool Secure { get; init; }
        public bool HttpOnly { get; init; }
        public bool Partitioned { get; init; }
        public bool HostOnly { get; init; }
    }

    public static async Task<XsLeakSessionProfile> BuildAsync(
        AutomationContext ctx,
        IdentityStore identities,
        IReadOnlyList<XsLeakScanner.StateSpec> states,
        string victimHost,
        bool identifyAuthCookie = false)
    {
        var notes = new List<string>();
        if (identifyAuthCookie)
        {
            notes.Add(
                "identifyAuthCookie requested — leave-one-out cookie identification is not run yet; using name heuristics only.");
        }
        var cookies = await ctx.GetAllProfileCookiesViaCdpInternalAsync();
        var scoped = cookies
            .Where(c => BrowserSessionCookieMatching.DomainMatchesHost(c.Domain, victimHost))
            .ToList();

        var authCandidates = scoped
            .Where(c => SessionCookieDetector.IsSessionCookieName(c.Name))
            .Select(c => new AuthCookieCandidate
            {
                Name = c.Name,
                Domain = c.Domain,
                SameSite = NormalizeSameSite(c.SameSite),
                Secure = c.Secure,
                HttpOnly = c.HttpOnly,
                Partitioned = c.Name.Contains("__Secure-", StringComparison.OrdinalIgnoreCase),
                HostOnly = !c.Domain.StartsWith('.')
            })
            .ToList();

        var mechanism = InferMechanism(identities, states, notes);
        var cookieMode = DeriveCookieMode(authCandidates);

        var sortedAuth = SortAuthCookiesForDisplay(authCandidates, cookieMode);

        return new XsLeakSessionProfile
        {
            CookieMode = cookieMode,
            AuthMechanism = mechanism,
            AuthCookies = sortedAuth,
            Notes = notes
        };
    }

    /// <summary>Cookie to observe for cross-site credential delivery (not CSRF/XSRF tokens).</summary>
    public static AuthCookieCandidate? PickCredentialProbeCookie(
        IReadOnlyList<AuthCookieCandidate> authCookies,
        string cookieMode)
    {
        if (authCookies.Count == 0) return null;

        var gate = authCookies
            .Where(c => !IsLikelyCsrfCookieName(c.Name))
            .ToList();
        if (gate.Count == 0)
            gate = authCookies.ToList();

        if (cookieMode.Contains("none", StringComparison.OrdinalIgnoreCase))
        {
            var noneHttp = gate
                .Where(c => c.SameSite == "none" && c.HttpOnly)
                .OrderByDescending(c => SessionCookieDetector.IsSessionCookieName(c.Name))
                .FirstOrDefault();
            if (noneHttp != null) return noneHttp;

            var anyNone = gate.FirstOrDefault(c => c.SameSite == "none");
            if (anyNone != null) return anyNone;
        }

        return gate
            .OrderByDescending(c => c.HttpOnly)
            .ThenByDescending(c => SessionCookieDetector.IsSessionCookieName(c.Name))
            .ThenByDescending(c => c.SameSite == "none")
            .FirstOrDefault();
    }

    internal static bool IsLikelyCsrfCookieName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        var lower = name.ToLowerInvariant();
        return lower.Contains("csrf", StringComparison.Ordinal)
               || lower.Contains("xsrf", StringComparison.Ordinal)
               || lower.Contains("requestverification", StringComparison.Ordinal);
    }

    private static List<AuthCookieCandidate> SortAuthCookiesForDisplay(
        List<AuthCookieCandidate> auth,
        string cookieMode)
    {
        var probe = PickCredentialProbeCookie(auth, cookieMode);
        if (probe == null) return auth;
        return auth
            .OrderByDescending(c => string.Equals(c.Name, probe.Name, StringComparison.OrdinalIgnoreCase))
            .ThenByDescending(c => c.HttpOnly)
            .ToList();
    }

    private static string InferMechanism(
        IdentityStore identities,
        IReadOnlyList<XsLeakScanner.StateSpec> states,
        List<string> notes)
    {
        var jwtLike = false;
        var cookieSession = false;
        foreach (var s in states)
        {
            if (string.IsNullOrWhiteSpace(s.Identity)
                || string.Equals(s.Identity, "anonymous", StringComparison.OrdinalIgnoreCase))
                continue;
            var snap = identities.Load(s.Identity.Trim());
            if (snap == null) continue;
            if (snap.Metadata.CookieCount > 0
                && string.Equals(snap.Metadata.InferredMechanism, "session-cookie", StringComparison.OrdinalIgnoreCase))
                cookieSession = true;
            if (snap.Metadata.LocalStorageCount > 0
                && snap.LocalStorage.Keys.Any(k =>
                    k.Contains("token", StringComparison.OrdinalIgnoreCase)
                    || k.Contains("jwt", StringComparison.OrdinalIgnoreCase)))
                jwtLike = true;
        }

        if (jwtLike && !cookieSession)
        {
            notes.Add(
                "Auth appears JWT/localStorage-only: cross-site img/script/iframe probes do not send Authorization.");
            return "bearer-localStorage";
        }

        if (cookieSession) return "session-cookie";
        foreach (var s in states)
        {
            if (string.IsNullOrWhiteSpace(s.Identity)
                || string.Equals(s.Identity, "anonymous", StringComparison.OrdinalIgnoreCase))
                continue;
            if (identities.Load(s.Identity.Trim())?.Metadata.CookieCount > 0)
                return "session-cookie";
        }

        return "unknown";
    }

    private static string DeriveCookieMode(IReadOnlyList<AuthCookieCandidate> auth)
    {
        if (auth.Count == 0) return "no-session-cookie";
        if (auth.Any(c => c.SameSite == "none")) return "samesite-none-present";
        if (auth.Any(c => c.SameSite == "strict")) return "samesite-strict";
        return "samesite-lax-or-default";
    }

    private static string NormalizeSameSite(string? raw)
    {
        var s = (raw ?? "lax").Trim().ToLowerInvariant();
        return s switch
        {
            "none" => "none",
            "strict" => "strict",
            "unspecified" or "" => "lax",
            _ => s
        };
    }

    public static void AppendSameSiteExploitabilityNotes(
        XsLeakSessionProfile profile,
        XsLeakCredentialObservation.DeliveryResult delivery,
        string attackerSite,
        List<string> warnings,
        List<string> nextActions)
    {
        var lax = profile.CookieMode.Contains("lax", StringComparison.OrdinalIgnoreCase)
                  || profile.AuthCookies.Any(c => c.SameSite is "lax" or "" or "unspecified");
        var strict = profile.CookieMode.Contains("strict", StringComparison.OrdinalIgnoreCase)
                     || profile.AuthCookies.Any(c => c.SameSite == "strict");
        var crossSite = !string.Equals(attackerSite, "same-site", StringComparison.OrdinalIgnoreCase);

        if (crossSite && lax && delivery.Subresource.StartsWith("blocked:", StringComparison.OrdinalIgnoreCase))
        {
            var note =
                "Auth cookies appear SameSite=Lax (or default): cross-site subresource probes (img/script/iframe) " +
                "do not carry session cookies — indistinguishable on those probes is expected, not proof of safety for top-level POST navigations.";
            if (!warnings.Any(w => w.Contains("SameSite=Lax", StringComparison.Ordinal)))
                warnings.Add(note);
            nextActions.Add("Re-run with safetyMode:active for top-level probes, or attackerSite:same-site to model a sibling subdomain attacker.");
        }

        if (crossSite && strict && delivery.Subresource.StartsWith("blocked:", StringComparison.OrdinalIgnoreCase))
        {
            warnings.Add(
                "SameSite=Strict: cross-site attacker cannot send session cookies on subresource or navigation probes from evil.trowser.test.");
        }

        if (profile.CookieMode.Contains("none", StringComparison.OrdinalIgnoreCase)
            && delivery.Subresource.StartsWith("sent", StringComparison.OrdinalIgnoreCase))
        {
            warnings.Add(
                "SameSite=None session cookies were sent on cross-site subresource probes — credentialed XS-Leak oracles apply.");
        }

        if (profile.CookieMode.Contains("none", StringComparison.OrdinalIgnoreCase)
            && delivery.Subresource.StartsWith("blocked:", StringComparison.OrdinalIgnoreCase)
            && delivery.AuthCookieName != null
            && IsLikelyCsrfCookieName(delivery.AuthCookieName))
        {
            warnings.Add(
                "credentialDelivery probed a CSRF/XSRF cookie — if cookieMode is samesite-none-present, re-check after update or run " +
                "POST /api/security/auth-control-identifier on the victim API to confirm the gating cookie.");
        }
    }

    public object ToApiObject() => new
    {
        cookieMode = CookieMode,
        authMechanism = AuthMechanism,
        authCookies = AuthCookies.Select(c => new
        {
            c.Name,
            c.Domain,
            c.SameSite,
            c.Secure,
            c.HttpOnly,
            c.Partitioned,
            c.HostOnly
        }),
        notes = Notes.Count > 0 ? Notes : null
    };
}

internal static class BrowserSessionCdpExtensions
{
    public static async Task<List<BrowserSessionCookieRecord>> GetAllProfileCookiesViaCdpInternalAsync(
        this AutomationContext ctx)
    {
        var snap = await ctx.CaptureBrowserSessionSnapshotAsync(BrowserSessionScopeKind.Profile, null);
        return snap.Cookies;
    }
}
