using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Client-side open redirect via <c>location.assign</c> / <c>location.href</c> fed from URL input (no 3xx required).
/// </summary>
internal static class OpenRedirectClientDomProbe
{
    private static readonly string[] DefaultParams =
    [
        "next", "nextUrl", "next_url", "url", "redirect", "redirectUrl", "redirect_url", "redirect_uri",
        "redirectTo", "redirect_to", "return", "returnUrl", "return_to", "dest", "destination", "continue",
        "continueUrl", "continue_url", "target", "targetUrl", "target_url", "goto", "goTo", "go_to", "back"
    ];

    public static async Task<List<OpenRedirectFinding>> ProbeAsync(
        AutomationContext ctx,
        int timeoutMs,
        CancellationToken ct = default)
    {
        var pageUrl = await ctx.GetCurrentUrl();
        if (string.IsNullOrWhiteSpace(pageUrl))
            return [];

        var paramNames = await DiscoverRedirectParamsAsync(ctx, pageUrl);
        var findings = new List<OpenRedirectFinding>();
        var tracer = new InputTracer(ctx);
        var payload = $"//{RedirectAnalysis.DefaultProbeHost}/trowser-dom-or-{Guid.NewGuid():N}"[..64];

        foreach (var param in paramNames.Take(8))
        {
            ct.ThrowIfCancellationRequested();
            var bypass = await tracer.TraceWithAutoBypassAsync(new TraceInputOptions
            {
                Source = TraceSourceType.UrlQuery,
                BaseUrl = pageUrl.Split('#')[0],
                QueryParam = param,
                Payload = payload,
                MonitorSinks = true,
                ConfirmExecution = false,
                TwoPhase = true,
                MaxBypassAttempts = 8,
                TimeoutMs = timeoutMs
            });

            var trace = bypass.EffectiveTrace;
            var effectivePayload = trace.Payload ?? payload;

            if (!IsDomOpenRedirectConfirmed(trace, effectivePayload))
            {
                foreach (var probe in TraceInputRedirectBypassProbes.GetProbes(8, sameOriginPrefix: "/"))
                {
                    ct.ThrowIfCancellationRequested();
                    trace = await tracer.TraceAsync(new TraceInputOptions
                    {
                        Source = TraceSourceType.UrlQuery,
                        BaseUrl = pageUrl.Split('#')[0],
                        QueryParam = param,
                        Payload = probe.Payload,
                        MonitorSinks = true,
                        ConfirmExecution = false,
                        TwoPhase = true,
                        TimeoutMs = timeoutMs
                    });
                    effectivePayload = probe.Payload;
                    if (IsDomOpenRedirectConfirmed(trace, effectivePayload))
                        break;
                }
            }

            if (!IsDomOpenRedirectConfirmed(trace, effectivePayload))
                continue;

            findings.Add(new OpenRedirectFinding
            {
                Title = "Client-side DOM open redirect",
                Severity = "high",
                Confidence = SecurityConfidence.Confirmed,
                Category = "open-redirect-dom",
                Url = pageUrl,
                Method = "GET",
                ParamName = param,
                Payload = effectivePayload,
                Status = trace.ServerResponse?.Status ?? 200,
                Location = trace.DocumentUrl ?? "",
                Indicator = trace.Sinks?.MostDangerousSink ?? "location.assign",
                Source = "client-dom-trace-input",
                Snippet = trace.Verdict.Summary
            });
            break;
        }

        return findings;
    }

    private static async Task<List<string>> DiscoverRedirectParamsAsync(AutomationContext ctx, string pageUrl)
    {
        var names = new List<string>();

        if (Uri.TryCreate(pageUrl, UriKind.Absolute, out var uri))
        {
            foreach (var p in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var eq = p.IndexOf('=');
                if (eq > 0)
                    Add(names, Uri.UnescapeDataString(p[..eq]));
            }
        }

        try
        {
            var discovery = await DomRuntimeInjectionDiscovery.DiscoverAsync(ctx);
            foreach (var p in discovery.QueryParams)
                Add(names, p);
        }
        catch { /* optional */ }

        foreach (var p in DefaultParams)
            Add(names, p);

        return names;
    }

    private static void Add(List<string> list, string? name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 48) return;
        if (list.Any(n => n.Equals(name, StringComparison.OrdinalIgnoreCase))) return;
        list.Add(name);
    }

    private static bool IsDomOpenRedirectConfirmed(InputTraceResult trace, string payload)
    {
        if (XssBypassProbes.IsConfirmedXss(trace))
            return true;

        if (TraceInputRedirectHelper.DocumentMatchesRedirectPayload(
                trace.DocumentUrl, payload, trace.Injection?.NavigatedUrl))
            return true;

        if (trace.ServerResponse?.OpenRedirect == true)
            return true;

        if (!TraceInputRedirectHelper.PayloadTargetsOffSiteNavigation(payload))
            return false;

        if (trace.Sinks?.PayloadReachedSink == true
            && TraceInputConfirmExecutionPolicy.TraceHasNavigationSinks(trace)
            && !string.IsNullOrWhiteSpace(trace.DocumentUrl)
            && Uri.TryCreate(trace.Injection?.NavigatedUrl ?? trace.DocumentUrl ?? "", UriKind.Absolute, out var page)
            && Uri.TryCreate(trace.DocumentUrl!, UriKind.Absolute, out var doc)
            && !string.Equals(page.Host, doc.Host, StringComparison.OrdinalIgnoreCase))
            return true;

        return false;
    }
}
