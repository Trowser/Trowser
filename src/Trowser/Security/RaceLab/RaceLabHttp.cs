using System.Diagnostics;
using Trowser.Api;
using Trowser.Automation;
using Trowser.Security.Authz;

namespace Trowser.Security.RaceLab;

internal static class RaceLabHttp
{
    public sealed class TimedResponse
    {
        public int Status { get; init; }
        public string Body { get; init; } = "";
        public double LatencyMs { get; init; }
        public string? Error { get; init; }
        public bool Redirected { get; init; }
        public string? Location { get; init; }
        public List<string> CookiesSent { get; init; } = [];
        public string IdentityUsed { get; init; } = "";
    }

    public static async Task<TimedResponse> FetchAsync(
        AutomationContext ctx,
        PeerRegistry? peers,
        RaceLabRequest request,
        RaceLabParameters parameters,
        CancellationToken ct)
    {
        var session = RaceLabSessions.Normalize(request.Session);
        var method = string.IsNullOrWhiteSpace(request.Method) ? "POST" : request.Method.Trim().ToUpperInvariant();
        var headers = request.Headers != null
            ? new Dictionary<string, string>(request.Headers, StringComparer.OrdinalIgnoreCase)
            : null;

        var sw = Stopwatch.StartNew();
        try
        {
            if (string.Equals(session, RaceLabSessions.Driver, StringComparison.OrdinalIgnoreCase))
            {
                var timed = await SecurityProbeHttp.FetchTimedAsync(
                    ctx,
                    request.Url,
                    method,
                    headers,
                    request.Body,
                    parameters.TimeoutMs,
                    parameters.IncludeBrowserCookies,
                    ct);
                sw.Stop();
                var cookiesSent = await CookieNamesAsync(ctx, request.Url, headers, parameters.IncludeBrowserCookies);
                timed.Result.ResponseHeaders.TryGetValue("Location", out var location);
                return new TimedResponse
                {
                    Status = timed.Result.Status,
                    Body = timed.Result.Body,
                    LatencyMs = sw.Elapsed.TotalMilliseconds,
                    Redirected = timed.Result.Redirected,
                    Location = location,
                    CookiesSent = cookiesSent,
                    IdentityUsed = SessionIdentity(session, parameters.IncludeBrowserCookies, cookiesSent, headers)
                };
            }

            if (peers == null)
                return new TimedResponse { Error = "PeerRegistry is not available.", LatencyMs = sw.Elapsed.TotalMilliseconds };

            var peerResult = await AuthzRequestEvaluator.FetchViaPeerAsync(
                peers,
                session,
                request.Url,
                method,
                headers,
                request.Body,
                parameters.TimeoutMs,
                parameters.IncludeBrowserCookies);
            sw.Stop();
            peerResult.Headers.TryGetValue("Location", out var peerLocation);

            if (peerResult.Error != null)
            {
                return new TimedResponse
                {
                    Status = peerResult.Status,
                    Body = peerResult.Body,
                    Error = peerResult.Error,
                    LatencyMs = sw.Elapsed.TotalMilliseconds,
                    Redirected = peerResult.Redirected,
                    Location = peerLocation,
                    CookiesSent = peerResult.CookiesSent,
                    IdentityUsed = SessionIdentity(session, parameters.IncludeBrowserCookies, peerResult.CookiesSent, headers)
                };
            }

            return new TimedResponse
            {
                Status = peerResult.Status,
                Body = peerResult.Body,
                LatencyMs = sw.Elapsed.TotalMilliseconds,
                Redirected = peerResult.Redirected,
                Location = peerLocation,
                CookiesSent = peerResult.CookiesSent,
                IdentityUsed = SessionIdentity(session, parameters.IncludeBrowserCookies, peerResult.CookiesSent, headers)
            };
        }
        catch (Exception ex)
        {
            sw.Stop();
            return new TimedResponse
            {
                Error = ex.Message,
                LatencyMs = sw.Elapsed.TotalMilliseconds
            };
        }
    }

    public static async Task<double> ProbeRttAsync(
        AutomationContext ctx,
        PeerRegistry? peers,
        string session,
        string probeUrl,
        int timeoutMs,
        bool includeCookies,
        CancellationToken ct)
    {
        var probe = new RaceLabRequest
        {
            Name = "sync-probe",
            Url = probeUrl,
            Method = "HEAD",
            Session = session
        };
        var parameters = new RaceLabParameters
        {
            TimeoutMs = timeoutMs,
            IncludeBrowserCookies = includeCookies
        };

        var samples = new List<double>();
        for (var i = 0; i < 3; i++)
        {
            ct.ThrowIfCancellationRequested();
            var resp = await FetchAsync(ctx, peers, probe, parameters, ct);
            if (resp.Status == 405 || resp.Status == 501)
            {
                probe = probe.Clone();
                probe.Method = "GET";
                resp = await FetchAsync(ctx, peers, probe, parameters, ct);
            }

            if (resp.Error == null && resp.Status > 0)
                samples.Add(resp.LatencyMs);
        }

        if (samples.Count == 0)
            return 0;

        samples.Sort();
        return samples[samples.Count / 2];
    }

    public static string ProbeUrlForRequest(RaceLabRequest request)
    {
        if (Uri.TryCreate(request.Url, UriKind.Absolute, out var uri))
            return uri.GetLeftPart(UriPartial.Authority) + "/";
        return request.Url;
    }

    private static async Task<List<string>> CookieNamesAsync(
        AutomationContext ctx,
        string url,
        Dictionary<string, string>? headers,
        bool includeBrowserCookies)
    {
        var names = new List<string>();
        if (includeBrowserCookies)
            names.AddRange(CookieHeaderSanitizer.CookieNames(await ctx.GetCookieHeaderForUrl(url)));

        if (headers != null && headers.TryGetValue("Cookie", out var caller))
        {
            foreach (var name in CookieHeaderSanitizer.CookieNames(caller))
            {
                if (!names.Contains(name, StringComparer.OrdinalIgnoreCase))
                    names.Add(name);
            }
        }

        return names;
    }

    private static string SessionIdentity(
        string session,
        bool includeBrowserCookies,
        IReadOnlyCollection<string> cookiesSent,
        Dictionary<string, string>? headers)
    {
        var callerCookie = headers != null
            && headers.TryGetValue("Cookie", out var cookie)
            && !string.IsNullOrWhiteSpace(cookie);
        var identity = FetchIdentity.Describe(includeBrowserCookies, cookiesSent, identitySource: null, callerCookie);
        return session + "/" + identity;
    }
}
