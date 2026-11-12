using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security.XsLeaks;

public sealed class XsLeakStateValidator
{
    public sealed class StateFetchSnapshot
    {
        public string Label { get; init; } = "";
        public string RequestUrl { get; init; } = "";
        public int Status { get; init; }
        public string? FinalUrl { get; init; }
        public int RedirectCount { get; init; }
        public string? ContentType { get; init; }
        public long Length { get; init; }
        public string BodyHash { get; init; } = "";
        public string? Coop { get; init; }
        public string? Corp { get; init; }
        public string? Xfo { get; init; }
        public bool FrameAncestors { get; init; }
        public bool TimingAllowOrigin { get; init; }
        public int IframeCount { get; init; }
        public List<double> LatencyMs { get; init; } = [];
    }

    public sealed class ValidationResult
    {
        public List<StateFetchSnapshot> States { get; init; } = [];
        public string CredentialedDiff { get; init; } = "none";
        public string AnonymousDiff { get; init; } = "none";
        public bool LatencyGap { get; init; }
        public string? Detail { get; init; }
        public int ProbeTimeoutMs { get; init; } = 4000;

        public bool ShouldShortCircuitHypothesis =>
            CredentialedDiff == "none" && AnonymousDiff == "none" && !LatencyGap;

        public object ToApiObject() => new
        {
            credentialedDiff = CredentialedDiff,
            anonymousDiff = AnonymousDiff,
            latencyGap = LatencyGap,
            detail = Detail,
            probeTimeoutMs = ProbeTimeoutMs,
            states = States.Select(s => new
            {
                s.Label,
                s.Status,
                s.FinalUrl,
                s.RedirectCount,
                s.ContentType,
                s.Length,
                bodyHash = s.BodyHash[..Math.Min(12, s.BodyHash.Length)],
                s.IframeCount,
                latencyMs = s.LatencyMs
            })
        };
    }

    public async Task<ValidationResult> ValidateAsync(
        AutomationContext ctx,
        IdentityStore identities,
        IReadOnlyList<XsLeakScanner.StateSpec> states,
        int homeTabIdx)
    {
        var credSnapshots = new List<StateFetchSnapshot>();
        foreach (var state in states)
        {
            ctx.SwitchTab(homeTabIdx);
            await ApplyStateAsync(ctx, identities, state);
            credSnapshots.Add(await FetchSnapshotAsync(ctx, state, withCookies: true));
        }

        var credDiff = ClassifyDiffForStates(states, credSnapshots);
        var latencyGap = LatencyGapBetweenRoles(states, credSnapshots);

        var anonSnapshots = new List<StateFetchSnapshot>();
        foreach (var state in states)
        {
            ctx.SwitchTab(homeTabIdx);
            await ctx.ApplyAnonymousSiteSessionAsync(
                Uri.TryCreate(state.Url, UriKind.Absolute, out var u) ? u.Host : "",
                Uri.TryCreate(state.Url, UriKind.Absolute, out var o) ? o.GetLeftPart(UriPartial.Authority) + "/" : null);
            anonSnapshots.Add(await FetchSnapshotAsync(ctx, state, withCookies: false));
        }

        var anonDiff = ClassifyDiffForStates(states, anonSnapshots);
        var p90 = credSnapshots.SelectMany(s => s.LatencyMs).OrderBy(x => x).ToList();
        var probeTimeout = 4000;
        if (p90.Count >= 3)
        {
            var idx = (int)Math.Ceiling(p90.Count * 0.9) - 1;
            probeTimeout = Math.Clamp((int)(p90[Math.Max(0, idx)] * 3), 1500, 8000);
        }

        string? detail = null;
        if (credDiff != "none")
            detail = $"Credentialed server diff: {credDiff}.";
        else if (latencyGap)
            detail = "No content diff; latency gap between states (timing probes only).";
        else if (anonDiff != "none")
            detail = $"Anonymous diff: {anonDiff} (uncredentialed probes may apply).";

        return new ValidationResult
        {
            States = credSnapshots,
            CredentialedDiff = credDiff,
            AnonymousDiff = anonDiff,
            LatencyGap = latencyGap,
            Detail = detail,
            ProbeTimeoutMs = probeTimeout
        };
    }

    public async Task<(bool Ok, string? Message)> VerifyHitSessionStableAsync(
        AutomationContext ctx,
        IdentityStore identities,
        XsLeakScanner.StateSpec hitState,
        int homeTabIdx,
        StateFetchSnapshot baseline)
    {
        ctx.SwitchTab(homeTabIdx);
        await ApplyStateAsync(ctx, identities, hitState);
        var snap = await FetchSnapshotAsync(ctx, hitState, withCookies: true);
        if (snap.Status != baseline.Status || !string.Equals(snap.BodyHash, baseline.BodyHash, StringComparison.Ordinal))
        {
            return (false,
                "Session may have expired — hit state response changed since validation; confirmation skipped.");
        }

        return (true, null);
    }

    internal static bool ExplainsDifferential(string credDiff, string techniqueCategory, string techniqueId)
    {
        if (credDiff == "none") return false;
        if (credDiff is "status" or "length" or "body"
            && techniqueId is "status-bucket-oracle" or "fetch-redirect-type" or "img-error" or "script-error"
                or "resource-transfer-size" or "form-post-frame")
            return true;
        if (credDiff == "redirect" && techniqueCategory is "redirect" or "csp")
            return true;
        if (credDiff == "length" && techniqueId is "resource-transfer-size" or "cache-timing")
            return true;
        if (credDiff == "headers" && techniqueCategory is "load-error" or "popup")
            return true;
        return credDiff is "body" or "content-type" or "iframe";
    }

    internal static bool LatencyGapBetweenRoles(
        IReadOnlyList<XsLeakScanner.StateSpec> states,
        IReadOnlyList<StateFetchSnapshot> snaps)
    {
        if (states.Count < 2 || snaps.Count < 2) return false;
        var a = snaps[0].LatencyMs;
        var b = snaps[1].LatencyMs;
        if (a.Count < 3 || b.Count < 3) return false;
        var (_, _, _, _, pVal) = XsLeakStats.CompareTiming(a, b, minEffect: 0.8, minAbsGap: 30);
        if (pVal is < 0.05) return true;
        return ClearMedianGap(a, b);
    }

    /// <summary>
    /// A few hundred milliseconds with non-overlapping central ranges is a gap even when
    /// one noisy sample keeps the p-value above 0.05. Same-body timing is the case the
    /// hypothesis pre-check must not skip.
    /// </summary>
    internal static bool ClearMedianGap(IReadOnlyList<double> a, IReadOnlyList<double> b)
    {
        if (a.Count < 3 || b.Count < 3) return false;
        var aSorted = a.OrderBy(x => x).ToList();
        var bSorted = b.OrderBy(x => x).ToList();
        var medA = aSorted[aSorted.Count / 2];
        var medB = bSorted[bSorted.Count / 2];
        if (Math.Abs(medA - medB) < 200) return false;
        var aLow = aSorted[aSorted.Count / 4];
        var aHigh = aSorted[(aSorted.Count * 3) / 4];
        var bLow = bSorted[bSorted.Count / 4];
        var bHigh = bSorted[(bSorted.Count * 3) / 4];
        return aHigh < bLow || bHigh < aLow;
    }

    private static string ClassifyDiffForStates(
        IReadOnlyList<XsLeakScanner.StateSpec> states,
        IReadOnlyList<StateFetchSnapshot> snaps)
    {
        var hit = states.FirstOrDefault(s =>
            string.Equals(s.Role, "hit", StringComparison.OrdinalIgnoreCase));
        var miss = states.FirstOrDefault(s =>
            string.Equals(s.Role, "miss", StringComparison.OrdinalIgnoreCase));
        if (hit != null && miss != null)
        {
            var a = snaps.FirstOrDefault(s => string.Equals(s.Label, hit.Label, StringComparison.OrdinalIgnoreCase));
            var b = snaps.FirstOrDefault(s => string.Equals(s.Label, miss.Label, StringComparison.OrdinalIgnoreCase));
            if (a != null && b != null)
                return ClassifyDiffPair(a, b);
        }

        return snaps.Count >= 2 ? ClassifyDiffPair(snaps[0], snaps[1]) : "none";
    }

    private static string ClassifyDiffPair(StateFetchSnapshot a, StateFetchSnapshot b)
    {
        if (a.Status != b.Status) return "status";
        if (a.RedirectCount != b.RedirectCount) return "redirect";
        if (RedirectBehaviorDiffers(a, b)) return "redirect";
        if (!string.Equals(a.ContentType, b.ContentType, StringComparison.OrdinalIgnoreCase))
            return "content-type";
        if (a.IframeCount != b.IframeCount) return "iframe";
        if (!string.Equals(a.Coop, b.Coop, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(a.Corp, b.Corp, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(a.Xfo, b.Xfo, StringComparison.OrdinalIgnoreCase)
            || a.FrameAncestors != b.FrameAncestors)
            return "headers";
        if (a.Length != b.Length) return "length";
        if (!string.Equals(a.BodyHash, b.BodyHash, StringComparison.Ordinal))
            return "body";
        return "none";
    }

    private static bool RedirectBehaviorDiffers(StateFetchSnapshot a, StateFetchSnapshot b)
    {
        var aRedirected = RequestWasRedirected(a);
        var bRedirected = RequestWasRedirected(b);
        if (aRedirected != bRedirected) return true;
        if (!aRedirected && !bRedirected) return false;
        return !UrlsEquivalent(a.FinalUrl, b.FinalUrl);
    }

    private static bool RequestWasRedirected(StateFetchSnapshot s)
    {
        if (s.RedirectCount > 0) return true;
        if (string.IsNullOrWhiteSpace(s.RequestUrl) || string.IsNullOrWhiteSpace(s.FinalUrl))
            return false;
        return !UrlsEquivalent(s.RequestUrl, s.FinalUrl);
    }

    private static bool UrlsEquivalent(string? a, string? b)
    {
        if (string.IsNullOrWhiteSpace(a) || string.IsNullOrWhiteSpace(b)) return false;
        if (Uri.TryCreate(a, UriKind.Absolute, out var ua)
            && Uri.TryCreate(b, UriKind.Absolute, out var ub))
        {
            return string.Equals(ua.GetLeftPart(UriPartial.Path), ub.GetLeftPart(UriPartial.Path),
                       StringComparison.OrdinalIgnoreCase)
                   && string.Equals(ua.Query, ub.Query, StringComparison.OrdinalIgnoreCase);
        }

        return string.Equals(a.Trim(), b.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<StateFetchSnapshot> FetchSnapshotAsync(
        AutomationContext ctx,
        XsLeakScanner.StateSpec state,
        bool withCookies)
    {
        var url = string.IsNullOrWhiteSpace(state.SetupUrl) ? state.Url : state.SetupUrl!;
        var (method, requestBody, headers) = ResolveHttpRequest(state);
        var latencies = new List<double>();
        SecurityProbeHttp.FetchResult? last = null;
        for (var i = 0; i < 5; i++)
        {
            var timed = await SecurityProbeHttp.FetchTimedAsync(
                ctx, url, method, headers, requestBody, 8000, withCookies, CancellationToken.None);
            latencies.Add(timed.ElapsedSeconds * 1000);
            last = timed.Result;
        }

        if (last == null)
        {
            return new StateFetchSnapshot
            {
                Label = state.Label,
                RequestUrl = url,
                LatencyMs = latencies
            };
        }

        var body = last.Body ?? "";
        var ct = SecurityProbeHttp.GetResponseHeader(last, "Content-Type");
        var coop = SecurityProbeHttp.GetResponseHeader(last, "Cross-Origin-Opener-Policy");
        var corp = SecurityProbeHttp.GetResponseHeader(last, "Cross-Origin-Resource-Policy");
        var xfo = SecurityProbeHttp.GetResponseHeader(last, "X-Frame-Options");
        var csp = SecurityProbeHttp.GetResponseHeader(last, "Content-Security-Policy");
        var tao = SecurityProbeHttp.GetResponseHeader(last, "Timing-Allow-Origin");

        return new StateFetchSnapshot
        {
            Label = state.Label,
            RequestUrl = url,
            Status = last?.Status ?? 0,
            FinalUrl = last?.FinalUrl ?? url,
            RedirectCount = last?.Redirected == true ? 1 : 0,
            ContentType = ct,
            Length = Encoding.UTF8.GetByteCount(body),
            BodyHash = Hash(body),
            Coop = coop,
            Corp = corp,
            Xfo = xfo,
            FrameAncestors = csp?.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase) == true,
            TimingAllowOrigin = !string.IsNullOrWhiteSpace(tao),
            IframeCount = CountIframes(body),
            LatencyMs = latencies
        };
    }

    private static int CountIframes(string html) =>
        Regex.Matches(html, "<iframe", RegexOptions.IgnoreCase).Count;

    private static string Hash(string body)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(body));
        return Convert.ToHexString(bytes);
    }

    internal static (string Method, string? Body, Dictionary<string, string>? Headers) ResolveHttpRequest(
        XsLeakScanner.StateSpec state)
    {
        var method = string.IsNullOrWhiteSpace(state.Method) ? "GET" : state.Method.Trim().ToUpperInvariant();
        if (state.Form is { Count: > 0 })
        {
            var encoded = string.Join("&",
                state.Form.Select(kv =>
                    $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
            return ("POST", encoded,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Content-Type"] = "application/x-www-form-urlencoded"
                });
        }

        if (!string.IsNullOrWhiteSpace(state.Body))
        {
            return (method, state.Body,
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Content-Type"] = state.ContentType ?? "application/json"
                });
        }

        return (method, null, null);
    }

    internal static async Task ApplyStateAsync(AutomationContext ctx, IdentityStore identities, XsLeakScanner.StateSpec state)
    {
        if (string.Equals(state.Identity, "anonymous", StringComparison.OrdinalIgnoreCase))
        {
            if (Uri.TryCreate(state.Url, UriKind.Absolute, out var u))
                await ctx.ApplyAnonymousSiteSessionAsync(u.Host, u.GetLeftPart(UriPartial.Authority) + "/");
            else
                await ctx.ClearOriginStorageAsync();
        }
        else if (!string.IsNullOrWhiteSpace(state.Identity))
        {
            await identities.ApplyAsync(ctx, state.Identity!.Trim(), navigateTo: null);
        }

        var nav = !string.IsNullOrWhiteSpace(state.SetupUrl) ? state.SetupUrl : null;
        if (!string.IsNullOrWhiteSpace(nav))
            await ctx.ForceNavigateAsync(nav!, terminateScripts: true);
    }
}
