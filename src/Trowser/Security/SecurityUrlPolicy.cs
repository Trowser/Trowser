namespace Trowser.Security;

/// <summary>Shared URL guards for security probes (logout/sign-out, session termination).</summary>
public static class SecurityUrlPolicy
{
    private static readonly string[] TerminationPathMarkers =
    [
        "/logout", "/log-out", "/logga-ut", "/signout", "/sign-out", "/sign_out",
        "/logoff", "/log-off", "/session/end", "/session/logout", "/auth/logout",
        "/account/logout", "/users/sign_out", "/users/signout"
    ];

    private static readonly string[] TerminationQueryMarkers =
    [
        "logout=", "action=logout", "signout=", "sign-out="
    ];

    public static bool IsSessionTerminationUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return false;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            var lower = url.ToLowerInvariant();
            return TerminationPathMarkers.Any(m => lower.Contains(m, StringComparison.Ordinal));
        }

        var path = uri.AbsolutePath.ToLowerInvariant();
        if (TerminationPathMarkers.Any(m => path.Contains(m, StringComparison.Ordinal)))
            return true;

        var query = uri.Query.ToLowerInvariant();
        return TerminationQueryMarkers.Any(m => query.Contains(m, StringComparison.Ordinal));
    }

    /// <summary>True when a security probe must not request this URL (default for automated scans).</summary>
    public static bool BlockSecurityProbeRequest(string? url) => IsSessionTerminationUrl(url);

    private static readonly string[] IdentityProviderHostMarkers =
    [
        "idp.", "login.", "auth.", "sso.", "sts.", "accounts.", "signin."
    ];

    private static readonly string[] IdentityProviderPathMarkers =
    [
        "/idp/", "/sso/", "/saml", "/oauth", "/authorize", "/authentication/",
        "/user-choices", "/step-up", "/stepup", "/mfa", "/siths", "/entra",
        "/adfs/", "/openid-connect", "/cas/login"
    ];

    /// <summary>
    /// True when the URL looks like an IdP / SSO step-up on a host different from the app under test.
    /// </summary>
    public static bool IsIdentityProviderStepUpUrl(string? url, string? victimHost)
    {
        if (string.IsNullOrWhiteSpace(url))
            return false;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;

        if (uri.Scheme is not "http" and not "https")
            return false;

        var host = uri.Host;
        if (!string.IsNullOrWhiteSpace(victimHost)
            && host.Equals(victimHost, StringComparison.OrdinalIgnoreCase))
            return false;

        var hostLower = host.ToLowerInvariant();
        if (IdentityProviderHostMarkers.Any(m => hostLower.Contains(m, StringComparison.Ordinal)))
            return true;

        var pathQuery = (uri.AbsolutePath + uri.Query).ToLowerInvariant();
        return IdentityProviderPathMarkers.Any(m => pathQuery.Contains(m, StringComparison.Ordinal));
    }

    /// <summary>Logout/sign-out or IdP step-up away from the victim application.</summary>
    public static bool IsSessionDisruptionUrl(string? url, string? victimHost) =>
        IsSessionTerminationUrl(url) || IsIdentityProviderStepUpUrl(url, victimHost);
}
