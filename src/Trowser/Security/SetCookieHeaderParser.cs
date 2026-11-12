using System.Globalization;
using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Parses Set-Cookie response header values into cookie dictionaries suitable for
/// <see cref="CookieAuditChecker"/>. Network-captured Set-Cookie is authoritative for
/// HttpOnly, Secure, and SameSite (the JS cookie jar cannot see HttpOnly).
/// </summary>
public static class SetCookieHeaderParser
{
    /// <summary>Split a header value that may contain multiple Set-Cookie lines.</summary>
    public static IEnumerable<string> SplitSetCookieLines(string headerValue)
    {
        if (string.IsNullOrWhiteSpace(headerValue))
            yield break;

        foreach (var line in headerValue.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!string.IsNullOrWhiteSpace(line))
                yield return line.Trim();
        }
    }

    /// <summary>Parse one or more Set-Cookie header values (newline-separated) into cookie rows.</summary>
    public static List<Dictionary<string, object>> ParseHeaderValue(string? headerValue)
    {
        var results = new List<Dictionary<string, object>>();
        if (string.IsNullOrWhiteSpace(headerValue))
            return results;

        foreach (var line in SplitSetCookieLines(headerValue))
        {
            var parsed = ParseSingle(line);
            if (parsed != null)
                results.Add(parsed);
        }

        return results;
    }

    /// <summary>Parse a single Set-Cookie header line (name=value; attr; attr...).</summary>
    public static Dictionary<string, object>? ParseSingle(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return null;

        var parts = line.Split(';', StringSplitOptions.TrimEntries);
        if (parts.Length == 0)
            return null;

        var nameValue = parts[0];
        var eq = nameValue.IndexOf('=');
        if (eq <= 0)
            return null;

        var name = nameValue[..eq].Trim();
        var value = nameValue[(eq + 1)..].Trim();
        if (string.IsNullOrEmpty(name))
            return null;

        var secure = false;
        var httpOnly = false;
        var sameSite = "";
        var sameSiteExplicit = false;
        var domain = "";
        var path = "/";
        DateTime? expiresUtc = null;
        var isSession = true;

        for (var i = 1; i < parts.Length; i++)
        {
            var attr = parts[i].Trim();
            if (attr.Length == 0)
                continue;

            var attrEq = attr.IndexOf('=');
            var attrName = attrEq >= 0 ? attr[..attrEq].Trim() : attr;
            var attrVal = attrEq >= 0 ? attr[(attrEq + 1)..].Trim() : "";

            switch (attrName.ToLowerInvariant())
            {
                case "secure":
                    secure = true;
                    break;
                case "httponly":
                    httpOnly = true;
                    break;
                case "samesite":
                    sameSiteExplicit = true;
                    sameSite = attrVal.ToLowerInvariant() switch
                    {
                        "strict" => "strict",
                        "none" => "none",
                        _ => "lax"
                    };
                    break;
                case "domain":
                    domain = attrVal;
                    break;
                case "path":
                    if (!string.IsNullOrEmpty(attrVal))
                        path = attrVal;
                    break;
                case "expires":
                    if (DateTime.TryParse(attrVal, CultureInfo.InvariantCulture,
                            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var exp))
                    {
                        expiresUtc = exp.ToUniversalTime();
                        isSession = false;
                    }
                    break;
                case "max-age":
                    if (int.TryParse(attrVal, NumberStyles.Integer, CultureInfo.InvariantCulture, out var maxAge))
                    {
                        if (maxAge <= 0)
                        {
                            isSession = true;
                            expiresUtc = null;
                        }
                        else
                        {
                            expiresUtc = DateTime.UtcNow.AddSeconds(maxAge);
                            isSession = false;
                        }
                    }
                    break;
            }
        }

        var row = new Dictionary<string, object>
        {
            ["name"] = name,
            ["value"] = value,
            ["domain"] = domain,
            ["path"] = path,
            ["secure"] = secure,
            ["httpOnly"] = httpOnly,
            ["sameSite"] = sameSite,
            ["session"] = isSession,
            ["_fromSetCookieHeader"] = true,
            ["_sameSiteExplicit"] = sameSiteExplicit
        };

        if (expiresUtc.HasValue)
            row["expires"] = expiresUtc.Value.ToString("O");

        return row;
    }

    /// <summary>
    /// Extract all Set-Cookie cookies from network log entries, optionally scoped to the page host.
    /// Later Set-Cookie headers for the same name+domain+path win (most recent server intent).
    /// </summary>
    public static List<Dictionary<string, object>> ExtractFromNetworkEntries(
        IEnumerable<Automation.NetworkEntry> entries,
        string? pageUrl = null,
        bool pageScopeOnly = false)
    {
        var pageHost = Uri.TryCreate(pageUrl ?? "", UriKind.Absolute, out var pageUri) ? pageUri.Host : null;
        var byKey = new Dictionary<string, Dictionary<string, object>>(StringComparer.OrdinalIgnoreCase);

        IEnumerable<Automation.NetworkEntry> scoped = entries;
        if (pageScopeOnly && entries is Automation.NetworkLog log)
            scoped = log.PageEntries;

        foreach (var entry in scoped)
        {
            if (entry.ResponseHeaders == null || entry.ResponseHeaders.Count == 0)
                continue;

            if (pageHost != null && Uri.TryCreate(entry.Url, UriKind.Absolute, out var entryUri))
            {
                if (!HostMatchesCookieDomain(pageHost, entryUri.Host))
                    continue;
            }

            foreach (var h in entry.ResponseHeaders)
            {
                if (!h.Key.Equals("set-cookie", StringComparison.OrdinalIgnoreCase))
                    continue;

                foreach (var parsed in ParseHeaderValue(h.Value))
                {
                    var name = parsed["name"]?.ToString() ?? "";
                    var domain = parsed["domain"]?.ToString() ?? "";
                    if (string.IsNullOrEmpty(domain) && Uri.TryCreate(entry.Url, UriKind.Absolute, out var u))
                        domain = u.Host;

                    parsed["domain"] = domain;
                    parsed["setCookieUrl"] = entry.Url;
                    parsed["setCookieStatus"] = entry.StatusCode;

                    if (pageHost != null && !HostMatchesCookieDomain(pageHost, domain))
                        continue;

                    var path = parsed["path"]?.ToString() ?? "/";
                    var key = $"{name}|{domain}|{path}";
                    byKey[key] = parsed;
                }
            }
        }

        return byKey.Values.ToList();
    }

    internal static bool HostMatchesCookieDomain(string pageHost, string cookieDomain)
    {
        if (string.IsNullOrEmpty(pageHost) || string.IsNullOrEmpty(cookieDomain))
            return true;

        var d = cookieDomain.TrimStart('.');
        return pageHost.Equals(d, StringComparison.OrdinalIgnoreCase)
               || pageHost.EndsWith("." + d, StringComparison.OrdinalIgnoreCase);
    }
}
