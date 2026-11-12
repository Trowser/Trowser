using System.Text.Json;
using Trowser.Api;
using Trowser.Automation;

namespace Trowser.Security.Authz;

/// <summary>
/// Per-request core of the authz cross-identity comparison: fetch as the driver session, fetch as
/// a peer, and classify the result. Extracted from <see cref="AuthzComparisonService"/> so both the
/// on-demand <c>authz/diff</c> endpoint and <see cref="LiveAuthzShadow"/> share one code path.
/// </summary>
public static class AuthzRequestEvaluator
{
    /// <summary>Fetch as the driver session and as the named peer, then classify the pair.</summary>
    public static async Task<AuthzComparisonEntry> EvaluateAsync(
        AutomationContext context,
        PeerRegistry peers,
        string peerName,
        AuthzEndpoint ep,
        AuthzComparisonOptions options)
    {
        var local = await DirectFetchHelper.FetchAsync(
            context, ep.Url, ep.Method, ep.Headers, ep.Body, options.TimeoutMs);

        var effectivePeerHeaders = ep.PeerHeaders ?? ep.Headers;
        var peer = await FetchViaPeerAsync(peers, peerName, ep.Url, ep.Method, effectivePeerHeaders, ep.Body, options.TimeoutMs);

        return BuildEntry(ep, local, peer, options);
    }

    /// <summary>
    /// Pure classification: given the two fetch outcomes and the match options, build the
    /// comparison entry (finding, leaks, hashes, trimmed bodies). No I/O — this is what unit tests
    /// exercise directly, and it is the single place the finding taxonomy lives.
    /// </summary>
    public static AuthzComparisonEntry BuildEntry(
        AuthzEndpoint ep,
        DirectFetchHelper.DirectFetchResult local,
        DirectFetchHelper.DirectFetchResult peer,
        AuthzComparisonOptions options)
    {
        var localBody = local.Error != null ? (local.Error ?? "") : local.Body;
        var peerBody = peer.Error != null ? (peer.Error ?? "") : peer.Body;
        var localStatus = local.Error != null ? 0 : local.Status;
        var peerStatus = peer.Error != null ? 0 : peer.Status;

        var localHash = AuthzBodyMatcher.ComputeMatchHash(localBody, options.BodyMatch);
        var peerHash = AuthzBodyMatcher.ComputeMatchHash(peerBody, options.BodyMatch);
        var bodiesMatch = AuthzBodyMatcher.BodiesMatch(localBody, peerBody, options.BodyMatch);

        var localOk = localStatus >= 200 && localStatus < 300;
        var peerOk = peerStatus >= 200 && peerStatus < 300;
        // 404 is a common "hide existence" denial for owner-only resources (IDOR-safe 404).
        // Count it as properly denied when the local/owner session got an authorized success.
        var peerDenied = peerStatus is 401 or 403 or 404;
        var localDenied = localStatus is 401 or 403;
        var peerError = peerStatus >= 500;

        var peerRedirectDenied = !peerDenied && peerOk && peer.Redirected
            && peer.FinalUrl != null && !string.Equals(peer.FinalUrl, ep.Url, StringComparison.OrdinalIgnoreCase)
            && AuthzComparisonService.AuthzLooksLikeDenialRedirect(peer.FinalUrl, peerBody);
        var localRedirectDenied = !localDenied && localOk && local.Redirected
            && local.FinalUrl != null && !string.Equals(local.FinalUrl, ep.Url, StringComparison.OrdinalIgnoreCase)
            && AuthzComparisonService.AuthzLooksLikeDenialRedirect(local.FinalUrl, localBody);

        var leaks = new List<string>();
        if (peerOk && options.LeakTokens.Count > 0)
        {
            foreach (var token in options.LeakTokens)
            {
                if (peerBody.Contains(token, StringComparison.OrdinalIgnoreCase))
                    leaks.Add(token);
            }
        }

        var finding = ClassifyFinding(
            localOk, peerOk, localDenied, peerDenied, peerError,
            localRedirectDenied, peerRedirectDenied, bodiesMatch, localStatus, peerStatus);

        if (leaks.Count > 0 && localOk && peerOk && finding == "FILTERED_RESPONSE")
            finding = "BOLA_SUSPECTED";

        string? includeLocalBody = null;
        string? includePeerBody = null;
        if (options.IncludeBody || (options.IncludeBodyOnMismatch && !bodiesMatch))
        {
            includeLocalBody = localBody.Length > 5000 ? localBody[..5000] : localBody;
            includePeerBody = peerBody.Length > 5000 ? peerBody[..5000] : peerBody;
        }

        return new AuthzComparisonEntry
        {
            Url = ep.Url,
            Method = ep.Method,
            Local = new AuthzSideResult
            {
                Status = localStatus,
                BodyLength = localBody.Length,
                BodyHash = localHash,
                Redirected = local.Redirected,
                FinalUrl = local.Redirected ? local.FinalUrl : null,
                Error = local.Error
            },
            Peer = new AuthzSideResult
            {
                Status = peerStatus,
                BodyLength = peerBody.Length,
                BodyHash = peerHash,
                Redirected = peer.Redirected,
                FinalUrl = peer.Redirected ? peer.FinalUrl : null,
                Error = peer.Error
            },
            Match = bodiesMatch && localStatus == peerStatus,
            Finding = finding,
            Leaks = leaks.Count > 0 ? leaks : null,
            LocalBody = includeLocalBody,
            PeerBody = includePeerBody
        };
    }

    /// <summary>
    /// The authz/diff finding taxonomy. Pure and side-effect free so it can be unit tested without
    /// standing up an <see cref="AutomationContext"/> or <see cref="PeerRegistry"/>.
    /// </summary>
    public static string ClassifyFinding(
        bool localOk,
        bool peerOk,
        bool localDenied,
        bool peerDenied,
        bool peerError,
        bool localRedirectDenied,
        bool peerRedirectDenied,
        bool bodiesMatch,
        int localStatus,
        int peerStatus)
    {
        if (localOk && !localRedirectDenied && peerRedirectDenied)
            return "REDIRECT_DENIED";
        if (localOk && peerOk && bodiesMatch)
            return "BOLA_SUSPECTED";
        if (localOk && peerOk)
            return "FILTERED_RESPONSE";
        if (localOk && peerDenied)
            return "PROPERLY_DENIED";
        if (localOk && peerError)
            return "ERROR_BEFORE_AUTH";
        if ((localDenied || localRedirectDenied) && (peerDenied || peerRedirectDenied))
            return "DENIED_BOTH";
        if (localStatus == 0 || peerStatus == 0)
            return "ERROR";
        return "OTHER";
    }

    /// <summary>Forward a fetch through a peer's <c>/api/fetch-direct</c>, retrying while the peer gate is held.</summary>
    internal static async Task<DirectFetchHelper.DirectFetchResult> FetchViaPeerAsync(
        PeerRegistry peers,
        string peerName,
        string url,
        string method,
        Dictionary<string, string>? headers,
        string? body,
        int timeoutMs,
        bool includeBrowserCookies = true)
    {
        var peerFetchBody = new Dictionary<string, object?>
        {
            ["url"] = url,
            ["method"] = method,
            ["timeout"] = timeoutMs,
            ["includeBrowserCookies"] = includeBrowserCookies
        };
        if (headers != null) peerFetchBody["headers"] = headers;
        if (body != null)
        {
            var ct = headers?.GetValueOrDefault("Content-Type") ?? "";
            if (ct.Contains("json", StringComparison.OrdinalIgnoreCase))
            {
                try { peerFetchBody["json"] = JsonSerializer.Deserialize<object>(body); }
                catch { peerFetchBody["body"] = body; }
            }
            else
            {
                peerFetchBody["body"] = body;
            }
        }

        var json = JsonSerializer.Serialize(peerFetchBody);
        PeerResponse? peerResp = null;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            peerResp = await peers.ForwardAsync(peerName, "POST", "/api/fetch-direct", json,
                timeoutMs: PeerRegistry.ForwardTimeoutForFetchMs(timeoutMs));
            if (peerResp.PeerBusy && attempt < 2)
            {
                await Task.Delay(1500);
                continue;
            }
            break;
        }

        if (peerResp == null)
            return new DirectFetchHelper.DirectFetchResult { Error = "Peer fetch failed." };

        if (peerResp.PeerBusy)
        {
            return new DirectFetchHelper.DirectFetchResult
            {
                Error = "Peer API was busy (gate held). Retry after the peer is idle."
            };
        }

        if (!peerResp.Success && peerResp.StatusCode != 200)
        {
            return new DirectFetchHelper.DirectFetchResult
            {
                Error = peerResp.Body ?? $"Peer \"{peerName}\" request failed (HTTP {peerResp.StatusCode})."
            };
        }

        try
        {
            using var doc = JsonDocument.Parse(peerResp.Body ?? "{}");
            if (doc.RootElement.TryGetProperty("data", out var data))
            {
                var status = data.TryGetProperty("status", out var s) ? s.GetInt32() : 0;
                var respBody = data.TryGetProperty("body", out var pb) ? pb.GetString() ?? "" : "";
                var finalUrl = data.TryGetProperty("url", out var u) ? u.GetString() : url;
                var cookiesSent = new List<string>();
                if (data.TryGetProperty("cookiesSent", out var cs) && cs.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in cs.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.String && item.GetString() is { Length: > 0 } name)
                            cookiesSent.Add(name);
                    }
                }
                var respHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                if (data.TryGetProperty("headers", out var hdr) && hdr.ValueKind == JsonValueKind.Object)
                {
                    foreach (var prop in hdr.EnumerateObject())
                    {
                        if (prop.Value.ValueKind == JsonValueKind.String)
                            respHeaders[prop.Name] = prop.Value.GetString() ?? "";
                    }
                }
                return new DirectFetchHelper.DirectFetchResult
                {
                    Ok = status >= 200 && status < 300,
                    Status = status,
                    Body = respBody,
                    FinalUrl = finalUrl,
                    Headers = respHeaders,
                    Redirected = finalUrl != null && !string.Equals(finalUrl, url, StringComparison.OrdinalIgnoreCase),
                    CookiesSent = cookiesSent,
                    IncludedBrowserCookies = includeBrowserCookies
                };
            }
        }
        catch
        {
            /* fall through */
        }

        return new DirectFetchHelper.DirectFetchResult { Error = peerResp.Body ?? "Invalid peer response." };
    }
}
