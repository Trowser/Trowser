using System.Text.Json;
using Trowser.Api;

namespace Trowser.Security.Authz;

/// <summary>
/// Substitutes the peer's authenticator onto a replay. Stripping the owner's
/// <c>Authorization</c> without putting the peer's token back makes every bearer API
/// look correctly denied.
/// </summary>
public static class PeerAuthMaterial
{
    public static readonly string[] HeaderNames =
    [
        "Authorization", "Proxy-Authorization", "X-Api-Key", "X-Auth-Token", "X-Access-Token"
    ];

    public static bool IsAuthHeader(string name)
    {
        foreach (var candidate in HeaderNames)
        {
            if (candidate.Equals(name, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    public static bool RequestHasAuthHeader(IReadOnlyDictionary<string, string>? headers)
    {
        if (headers == null) return false;
        foreach (var key in headers.Keys)
        {
            if (IsAuthHeader(key) && !string.IsNullOrWhiteSpace(headers[key]))
                return true;
        }
        return false;
    }

    /// <summary>
    /// <c>cookie</c> when the peer cookie jar was sent and the owner call did not use an auth header.
    /// <c>bearer</c> when the peer's auth header was installed. <c>both</c> when both happened.
    /// <c>none</c> when the replay carried no peer credential — including a bearer call whose token
    /// could not be found. A cookie on a call the owner made with <c>Authorization</c> is not enough.
    /// </summary>
    public static string ClassifyApplied(bool ownerHadAuthHeader, bool peerHeaderApplied, bool cookiesSent)
    {
        if (ownerHadAuthHeader)
        {
            if (peerHeaderApplied && cookiesSent) return "both";
            if (peerHeaderApplied) return "bearer";
            return "none";
        }

        return cookiesSent ? "cookie" : "none";
    }

    /// <summary>
    /// Start from headers that already had the owner's credential removed, then copy the peer's
    /// current value for each auth header the owner sent.
    /// </summary>
    public static Dictionary<string, string>? MergeReplayHeaders(
        Dictionary<string, string>? sanitized,
        IReadOnlyDictionary<string, string>? ownerHeaders,
        IReadOnlyDictionary<string, string>? peerAuthHeaders,
        out bool peerHeaderApplied)
    {
        peerHeaderApplied = false;
        var result = sanitized == null
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(sanitized, StringComparer.OrdinalIgnoreCase);

        if (ownerHeaders != null && peerAuthHeaders != null)
        {
            foreach (var kv in ownerHeaders)
            {
                if (!IsAuthHeader(kv.Key) || string.IsNullOrWhiteSpace(kv.Value))
                    continue;
                if (!TryGet(peerAuthHeaders, kv.Key, out var peerValue))
                    continue;
                result[kv.Key] = peerValue;
                peerHeaderApplied = true;
            }
        }

        return result.Count == 0 ? null : result;
    }

    /// <summary>
    /// A denial is only "correctly denied" when the peer's own credential was on the replay.
    /// </summary>
    public static AuthzVerdict DemoteUnauthenticatedDeny(AuthzVerdict verdict, string? peerAuthApplied)
    {
        if (!string.Equals(peerAuthApplied, "none", StringComparison.OrdinalIgnoreCase))
            return verdict;
        if (verdict.Kind != AuthzVerdictKind.ProperlyDenied)
            return verdict;

        return new AuthzVerdict
        {
            Kind = AuthzVerdictKind.Inconclusive,
            Confidence = "low",
            Reason = "Peer replay had no credential (peerAuthApplied: none). " +
                     "A denial without the peer session applied is not a correct deny."
        };
    }

    public static string? BearerFromStorage(IEnumerable<KeyValuePair<string, string>> entries)
    {
        string? fallback = null;
        foreach (var (key, value) in entries)
        {
            if (string.IsNullOrWhiteSpace(value)) continue;
            if (SessionIdentityIntrospection.ClassifyStorageToken(key, value) == null) continue;

            var token = value.Trim();
            if (token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                token = token["Bearer ".Length..].Trim();
            if (token.Length == 0) continue;

            if (SessionIdentityIntrospection.LooksLikeJwt(token))
                return "Bearer " + token;
            fallback ??= "Bearer " + token;
        }

        return fallback;
    }

    /// <summary>
    /// Read the peer's latest auth headers for <paramref name="host"/> from its network log,
    /// then fill a missing <c>Authorization</c> from sessionStorage or localStorage.
    /// </summary>
    public static async Task<Dictionary<string, string>> LoadFromPeerAsync(
        PeerRegistry peers, string peerName, string host)
    {
        var found = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var net = await peers.ForwardAsync(
            peerName, "GET", "/api/network?includeHeaders=true&limit=40", timeoutMs: 8000);
        if (net.Success && net.Body != null)
            CollectFromNetwork(net.Body, host, found);

        if (!ContainsKey(found, "Authorization"))
        {
            var cookies = await peers.ForwardAsync(peerName, "GET", "/api/cookies", timeoutMs: 8000);
            if (cookies.Success && cookies.Body != null)
            {
                var fromCookie = BearerFromCookieJson(cookies.Body);
                if (fromCookie != null)
                    found["Authorization"] = fromCookie;
            }
        }

        if (!ContainsKey(found, "Authorization"))
        {
            foreach (var type in new[] { "session", "local" })
            {
                var storage = await peers.ForwardAsync(
                    peerName, "GET", "/api/storage?type=" + type, timeoutMs: 8000);
                if (!storage.Success || storage.Body == null) continue;
                var token = BearerFromStorageJson(storage.Body);
                if (token == null) continue;
                found["Authorization"] = token;
                break;
            }
        }

        return found;
    }

    internal static void CollectFromNetwork(string json, string host, Dictionary<string, string> found)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!TryGetData(doc.RootElement, out var data)) return;
            if (!data.TryGetProperty("entries", out var entries) || entries.ValueKind != JsonValueKind.Array)
                return;

            foreach (var entry in entries.EnumerateArray())
            {
                if (!entry.TryGetProperty("url", out var urlEl)) continue;
                var url = urlEl.GetString();
                if (!HostMatches(url, host)) continue;
                if (!entry.TryGetProperty("requestHeaders", out var headers)
                    || headers.ValueKind != JsonValueKind.Object)
                    continue;

                foreach (var header in headers.EnumerateObject())
                {
                    if (!IsAuthHeader(header.Name)) continue;
                    var value = header.Value.ValueKind == JsonValueKind.String
                        ? header.Value.GetString()
                        : null;
                    if (!string.IsNullOrWhiteSpace(value))
                        found[header.Name] = value;
                }
            }
        }
        catch (JsonException)
        {
            /* peer body was not the network log */
        }
    }

    /// <summary>
    /// A JWT sitting in a cookie named <c>token</c> is the bearer many SPAs also send as
    /// <c>Authorization</c>. Cookie-only replay gets 401 from those apps.
    /// </summary>
    internal static string? BearerFromCookieJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!TryGetData(doc.RootElement, out var data)) return null;
            if (!data.TryGetProperty("cookies", out var cookies) || cookies.ValueKind != JsonValueKind.Array)
                return null;

            string? fallback = null;
            foreach (var cookie in cookies.EnumerateArray())
            {
                if (cookie.ValueKind != JsonValueKind.Object) continue;
                var name = cookie.TryGetProperty("name", out var n) ? n.GetString() : null;
                var value = cookie.TryGetProperty("value", out var v) ? v.GetString() : null;
                if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(value)) continue;
                if (!SessionIdentityIntrospection.LooksLikeJwt(value)) continue;

                var bearer = value.Trim().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                    ? value.Trim()
                    : "Bearer " + value.Trim();
                if (name.Equals("token", StringComparison.OrdinalIgnoreCase)
                    || name.Contains("jwt", StringComparison.OrdinalIgnoreCase)
                    || name.Contains("authorization", StringComparison.OrdinalIgnoreCase)
                    || name.Contains("access", StringComparison.OrdinalIgnoreCase))
                    return bearer;
                fallback ??= bearer;
            }

            return fallback;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    internal static string? BearerFromStorageJson(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!TryGetData(doc.RootElement, out var data)) return null;
            if (!data.TryGetProperty("entries", out var entries) || entries.ValueKind != JsonValueKind.Object)
                return null;

            var pairs = new List<KeyValuePair<string, string>>();
            foreach (var prop in entries.EnumerateObject())
            {
                if (prop.Value.ValueKind == JsonValueKind.String && prop.Value.GetString() is { } value)
                    pairs.Add(new KeyValuePair<string, string>(prop.Name, value));
            }

            return BearerFromStorage(pairs);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static bool HostMatches(string? url, string host)
    {
        if (string.IsNullOrEmpty(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;
        return AuthzHostKey.FromUri(uri).Equals(AuthzHostKey.Canonical(host), StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryGetData(JsonElement root, out JsonElement data)
    {
        if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("data", out var wrapped))
        {
            data = wrapped;
            return data.ValueKind == JsonValueKind.Object;
        }

        data = root;
        return root.ValueKind == JsonValueKind.Object;
    }

    private static bool TryGet(IReadOnlyDictionary<string, string> headers, string name, out string value)
    {
        foreach (var kv in headers)
        {
            if (!kv.Key.Equals(name, StringComparison.OrdinalIgnoreCase)) continue;
            if (string.IsNullOrWhiteSpace(kv.Value)) continue;
            value = kv.Value;
            return true;
        }

        value = "";
        return false;
    }

    private static bool ContainsKey(Dictionary<string, string> headers, string name)
    {
        foreach (var key in headers.Keys)
        {
            if (key.Equals(name, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
