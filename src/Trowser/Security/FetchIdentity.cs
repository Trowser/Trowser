namespace Trowser.Security;

/// <summary>
/// Names the cookie identity that actually went on the wire. Values are never included.
/// </summary>
internal static class FetchIdentity
{
    public static string Describe(
        bool includedBrowserCookies,
        IReadOnlyCollection<string>? cookiesSent,
        string? identitySource,
        bool callerCookie)
    {
        if (string.Equals(identitySource, "anonymous", StringComparison.OrdinalIgnoreCase))
            return "anonymous";

        if (!string.IsNullOrEmpty(identitySource)
            && !identitySource.Equals("cookies", StringComparison.OrdinalIgnoreCase))
            return identitySource;

        var sent = cookiesSent is { Count: > 0 };
        if (!sent)
            return "anonymous";

        var caller = callerCookie || string.Equals(identitySource, "cookies", StringComparison.OrdinalIgnoreCase);
        if (includedBrowserCookies && caller)
            return "browser-session+caller-cookies";
        if (includedBrowserCookies)
            return "browser-session";
        return "caller-cookies";
    }
}
