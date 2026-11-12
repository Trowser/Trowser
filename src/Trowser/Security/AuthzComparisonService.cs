using System.Text;
using System.Text.Json;
using Trowser.Api;
using Trowser.Automation;
using Trowser.Security.Authz;

namespace Trowser.Security;

public sealed class AuthzEndpoint
{
    public required string Url { get; init; }
    public string Method { get; init; } = "GET";
    public Dictionary<string, string>? Headers { get; init; }
    public string? Body { get; init; }
    public Dictionary<string, string>? PeerHeaders { get; init; }
}

public sealed class AuthzComparisonOptions
{
    public bool IncludeBody { get; init; }
    public bool IncludeBodyOnMismatch { get; init; } = true;
    public List<string> LeakTokens { get; init; } = [];
    public bool EnsureOrigin { get; init; }
    public int TimeoutMs { get; init; } = 30000;
    public AuthzBodyMatchOptions BodyMatch { get; init; } = new();
}

public sealed class AuthzComparisonEntry
{
    public required string Url { get; init; }
    public required string Method { get; init; }
    public required AuthzSideResult Local { get; init; }
    public required AuthzSideResult Peer { get; init; }
    public bool Match { get; init; }
    public required string Finding { get; init; }
    public List<string>? Leaks { get; init; }
    public string? LocalBody { get; init; }
    public string? PeerBody { get; init; }
}

public sealed class AuthzSideResult
{
    public int Status { get; init; }
    public int BodyLength { get; init; }
    public required string BodyHash { get; init; }
    public bool Redirected { get; init; }
    public string? FinalUrl { get; init; }
    public string? Error { get; init; }
}

public sealed class AuthzComparisonSummary
{
    public int TotalEndpoints { get; init; }
    public int BolaSuspected { get; init; }
    public int FilteredResponse { get; init; }
    public int ProperlyDenied { get; init; }
    public int DeniedBoth { get; init; }
    public int ErrorBeforeAuth { get; init; }
    public int Errors { get; init; }
}

public sealed class AuthzComparisonResult
{
    public required string Peer { get; init; }
    public required List<AuthzComparisonEntry> Comparisons { get; init; }
    public required AuthzComparisonSummary Summary { get; init; }
}

/// <summary>
/// Cross-identity authorization comparison — classifies BOLA/IDOR-style findings
/// when local and peer sessions receive the same or unexpected responses.
/// </summary>
public static class AuthzComparisonService
{
    public static List<AuthzEndpoint> ParseEndpoints(JsonElement endpoints)
    {
        var list = new List<AuthzEndpoint>();
        if (endpoints.ValueKind != JsonValueKind.Array)
            return list;

        foreach (var ep in endpoints.EnumerateArray())
        {
            if (ep.ValueKind == JsonValueKind.String)
            {
                var url = ep.GetString();
                if (!string.IsNullOrWhiteSpace(url))
                    list.Add(new AuthzEndpoint { Url = url });
                continue;
            }

            var endpointUrl = ep.TryGetProperty("url", out var u) ? u.GetString() : null;
            if (string.IsNullOrWhiteSpace(endpointUrl)) continue;

            var method = ep.TryGetProperty("method", out var m) ? m.GetString() ?? "GET" : "GET";
            Dictionary<string, string>? headers = null;
            Dictionary<string, string>? peerHeaders = null;
            string? bodyStr = null;

            if (ep.TryGetProperty("headers", out var h) && h.ValueKind == JsonValueKind.Object)
                headers = ParseHeaders(h);
            if (ep.TryGetProperty("peerHeaders", out var ph) && ph.ValueKind == JsonValueKind.Object)
                peerHeaders = ParseHeaders(ph);
            if (ep.TryGetProperty("json", out var j))
            {
                bodyStr = j.GetRawText();
                headers ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                headers.TryAdd("Content-Type", "application/json");
            }
            else if (ep.TryGetProperty("body", out var b))
            {
                bodyStr = b.GetString();
            }

            list.Add(new AuthzEndpoint
            {
                Url = endpointUrl,
                Method = method,
                Headers = headers,
                Body = bodyStr,
                PeerHeaders = peerHeaders
            });
        }

        return list;
    }

    public static List<AuthzEndpoint> FromProbeItems(IEnumerable<EndpointProbe.EndpointProbeItem> items, bool useCapturedHeadersBody)
    {
        return items.Select(item =>
        {
            Dictionary<string, string>? headers = null;
            string? body = null;
            if (useCapturedHeadersBody)
            {
                if (item.RequestHeaders.Count > 0)
                    headers = SanitizeReplayHeaders(item.RequestHeaders);
                body = item.RequestBody;
            }

            return new AuthzEndpoint
            {
                Url = item.Url,
                Method = item.Method,
                Headers = headers,
                Body = body
            };
        }).ToList();
    }

    /// <summary>
    /// Strip hop-by-hop and identity headers so direct fetch uses each session's live cookie jar.
    /// </summary>
    public static Dictionary<string, string>? SanitizeReplayHeaders(
        Dictionary<string, string> headers, bool keepAuthorization = false)
    {
        if (headers.Count == 0)
            return null;

        var cleaned = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in headers)
        {
            if (ReplayExcludedHeaders.Contains(kv.Key))
                continue;
            if (!keepAuthorization && Authz.PeerAuthMaterial.IsAuthHeader(kv.Key))
                continue;
            cleaned[kv.Key] = kv.Value;
        }

        return cleaned.Count > 0 ? cleaned : null;
    }

    private static readonly HashSet<string> ReplayExcludedHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Cookie", "Host", "Content-Length", "Connection", "Transfer-Encoding",
        "Keep-Alive", "Proxy-Connection", "TE", "Trailer", "Upgrade",
        // The browser asks for gzip/br. Direct fetch decompresses on its own; forwarding
        // Accept-Encoding makes HttpClient return compressed bytes, which then fail every
        // body comparison and hide real leaks behind "different content".
        "Accept-Encoding",
        // Conditional headers belong to the owner's cache, not the peer replay.
        "If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since", "If-Range", "Range"
        // Authorization is removed in SanitizeReplayHeaders unless keepAuthorization is set.
        // Peer replay then installs the peer's own header (see PeerAuthMaterial). Leaving the
        // owner's bearer in place would test the privileged token against itself.
    };

    public static async Task<List<AuthzComparisonResult>> RunAsync(
        AutomationContext context,
        PeerRegistry peers,
        IReadOnlyList<string> peerNames,
        IReadOnlyList<AuthzEndpoint> endpoints,
        AuthzComparisonOptions options)
    {
        var results = new List<AuthzComparisonResult>();
        foreach (var peerName in peerNames)
        {
            results.Add(await RunForPeerAsync(context, peers, peerName, endpoints, options));
        }

        return results;
    }

    public static async Task<AuthzComparisonResult> RunForPeerAsync(
        AutomationContext context,
        PeerRegistry peers,
        string peerName,
        IReadOnlyList<AuthzEndpoint> endpoints,
        AuthzComparisonOptions options)
    {
        if (endpoints.Count > 0 && options.EnsureOrigin)
        {
            var (_, originError) = await peers.EnsureOriginAsync(peerName, endpoints[0].Url);
            if (originError != null)
                TrowserLog.Warn($"authz/diff ensureOrigin ({peerName}): {originError}");
        }

        var comparisons = new List<AuthzComparisonEntry>();
        int bolaSuspected = 0, filteredResponse = 0, properlyDenied = 0, deniedBoth = 0, errorBeforeAuth = 0, errorsCount = 0;

        foreach (var ep in endpoints)
        {
            var entry = await AuthzRequestEvaluator.EvaluateAsync(context, peers, peerName, ep, options);
            comparisons.Add(entry);

            switch (entry.Finding)
            {
                case "BOLA_SUSPECTED": bolaSuspected++; break;
                case "FILTERED_RESPONSE": filteredResponse++; break;
                case "PROPERLY_DENIED": case "REDIRECT_DENIED": properlyDenied++; break;
                case "DENIED_BOTH": deniedBoth++; break;
                case "ERROR_BEFORE_AUTH": errorBeforeAuth++; break;
                default: errorsCount++; break;
            }
        }

        return new AuthzComparisonResult
        {
            Peer = peerName,
            Comparisons = comparisons,
            Summary = new AuthzComparisonSummary
            {
                TotalEndpoints = comparisons.Count,
                BolaSuspected = bolaSuspected,
                FilteredResponse = filteredResponse,
                ProperlyDenied = properlyDenied,
                DeniedBoth = deniedBoth,
                ErrorBeforeAuth = errorBeforeAuth,
                Errors = errorsCount
            }
        };
    }

    public static object ToResponseObject(AuthzComparisonResult result, AuthzBodyMatchOptions? bodyMatch = null) => new
    {
        peer = result.Peer,
        bodyMatch = bodyMatch == null ? null : new
        {
            strategy = bodyMatch.Strategy.ToString(),
            ignoreFields = bodyMatch.IgnoreFields
        },
        comparisons = result.Comparisons.Select(c => new Dictionary<string, object?>
        {
            ["url"] = c.Url,
            ["method"] = c.Method,
            ["local"] = new
            {
                status = c.Local.Status,
                bodyLength = c.Local.BodyLength,
                bodyHash = c.Local.BodyHash,
                redirected = c.Local.Redirected,
                finalUrl = c.Local.FinalUrl,
                error = c.Local.Error
            },
            ["peer"] = new
            {
                status = c.Peer.Status,
                bodyLength = c.Peer.BodyLength,
                bodyHash = c.Peer.BodyHash,
                redirected = c.Peer.Redirected,
                finalUrl = c.Peer.FinalUrl,
                error = c.Peer.Error
            },
            ["match"] = c.Match,
            ["finding"] = c.Finding,
            ["leaks"] = c.Leaks,
            ["localBody"] = c.LocalBody,
            ["peerBody"] = c.PeerBody
        }),
        summary = result.Summary
    };

    private static Dictionary<string, string> ParseHeaders(JsonElement el)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var prop in el.EnumerateObject())
            result[prop.Name] = prop.Value.GetString() ?? "";
        return result;
    }

    public static string ComputeShortHash(string input)
    {
        if (string.IsNullOrEmpty(input)) return "empty";
        var bytes = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes[..8]).ToLowerInvariant();
    }

    public static bool AuthzLooksLikeDenialRedirect(string finalUrl, string body)
    {
        var urlLower = finalUrl.ToLowerInvariant();
        if (urlLower.Contains("accessdenied") || urlLower.Contains("access-denied") ||
            urlLower.Contains("unauthorized") || urlLower.Contains("forbidden") ||
            urlLower.Contains("login") || urlLower.Contains("signin") ||
            urlLower.Contains("sign-in") || urlLower.Contains("sso") ||
            urlLower.Contains("auth") || urlLower.Contains("returnurl") ||
            urlLower.Contains("redirect"))
            return true;

        if (string.IsNullOrEmpty(body) || body.Length > 50_000) return false;
        var bodyLower = body.ToLowerInvariant();
        return bodyLower.Contains("access denied") || bodyLower.Contains("not authorized") ||
               bodyLower.Contains("you do not have permission") || bodyLower.Contains("login required") ||
               bodyLower.Contains("sign in to continue") || bodyLower.Contains("403") ||
               bodyLower.Contains("unauthorized");
    }
}
