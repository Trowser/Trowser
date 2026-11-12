using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;
using Trowser.Security.Runtime;

namespace Trowser.Security;

/// <summary>
/// Browser confirmation for OAuth authorize mutations flagged by HTTP probes (redirect_uri, response_mode).
/// Bounded navigations; watches where codes/tokens land.
/// </summary>
public static class OAuthFlowBreaker
{
    public sealed class BreakerOptions
    {
        public int MaxBrowserSteps { get; init; } = 2;
        public int TimeoutMs { get; init; } = 15000;
        public IReadOnlyList<string>? Mutations { get; init; }
    }

    public sealed class LandingObservation
    {
        public string Perturbation { get; init; } = "";
        public string LandingSurface { get; init; } = "";
        public string Confidence { get; init; } = SecurityConfidence.Tentative;
        public string? Detail { get; init; }
    }

    public static async Task RunAsync(
        AutomationContext ctx,
        OAuthFlowTester.OAuthFlowResult result,
        OAuthFlowTester.CapturedOAuthFlow flow,
        BreakerOptions options,
        CancellationToken ct = default)
    {
        var steps = 0;
        var perturbations = BuildPerturbations(result, flow, options.Mutations);
        if (perturbations.Count == 0)
        {
            result.Errors.Add("flowBreaker: no HTTP-flagged mutations or explicit mutations[] to confirm in browser.");
            return;
        }

        await RuntimeSensorInstaller.InstallOnCurrentDocumentAsync(ctx, RuntimeSensorProfile.Active);

        foreach (var (name, url) in perturbations)
        {
            if (steps >= options.MaxBrowserSteps) break;
            ct.ThrowIfCancellationRequested();
            steps++;

            var mark = ctx.ActiveTab.RuntimeEvents.Mark();
            var netBefore = ctx.Network.Entries.Count;

            try
            {
                await ctx.Navigate(url);
                await ctx.WaitForIdle(options.TimeoutMs);
                await Task.Delay(500);
            }
            catch (Exception ex)
            {
                result.Findings.Add(new OAuthFlowTester.OAuthFlowFinding
                {
                    Category = "flow-breaker",
                    Severity = "info",
                    Title = $"flowBreaker navigation failed ({name})",
                    Description = ex.Message
                });
                continue;
            }

            var landing = ObserveLanding(ctx, mark, netBefore);
            if (landing.Count == 0)
                continue;

            foreach (var obs in landing)
            {
                result.Findings.Add(new OAuthFlowTester.OAuthFlowFinding
                {
                    Category = "flow-breaker",
                    Severity = obs.LandingSurface is "postMessage" or "window.name" or "fragment" ? "high" : "medium",
                    Title = $"OAuth flowBreaker: {name} landed in {obs.LandingSurface}",
                    Description = obs.Detail ?? obs.LandingSurface,
                    Recommendation = "Validate callback isolation and postMessage targetOrigin.",
                    Detail = new { obs.Perturbation, obs.LandingSurface, obs.Confidence }
                });

                if (obs.LandingSurface.Equals("postMessage", StringComparison.OrdinalIgnoreCase))
                {
                    result.NextActions.Add(
                        "browser_postmessage_audit with safetyMode active on the callback page (confirm targetOrigin on handlers)");
                }
            }
        }
    }

    private static List<(string Name, string Url)> BuildPerturbations(
        OAuthFlowTester.OAuthFlowResult result,
        OAuthFlowTester.CapturedOAuthFlow flow,
        IReadOnlyList<string>? explicitMutations)
    {
        var list = new List<(string, string)>();
        if (string.IsNullOrEmpty(flow.AuthorizationUrl))
            return list;

        if (explicitMutations != null)
        {
            foreach (var m in explicitMutations)
            {
                if (m.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                    list.Add(("explicit", m));
            }
        }

        foreach (var probe in result.Probes.Where(p => p.Verdict is "vulnerable" or "suspicious"))
        {
            if (!string.IsNullOrEmpty(probe.Url))
                list.Add((probe.Test, probe.Url));
        }

        if (list.Count == 0)
        {
            list.Add(("response_mode-query", OAuthQueryHelper.SetQueryParam(flow.AuthorizationUrl, "response_mode", "query")));
            list.Add(("response_mode-fragment", OAuthQueryHelper.SetQueryParam(flow.AuthorizationUrl, "response_mode", "fragment")));
        }

        return list.DistinctBy(x => x.Item2).Take(4).ToList();
    }

    private static List<LandingObservation> ObserveLanding(
        AutomationContext ctx, long mark, int netBefore)
    {
        var observations = new List<LandingObservation>();
        var url = ctx.ActiveTab.Url;

        if (url.Contains("code=", StringComparison.OrdinalIgnoreCase))
        {
            observations.Add(new LandingObservation
            {
                Perturbation = "browser",
                LandingSurface = "query",
                Confidence = SecurityConfidence.Confirmed,
                Detail = Truncate(url, 200)
            });
        }

        if (url.Contains('#') && (url.Contains("access_token", StringComparison.OrdinalIgnoreCase)
                                  || url.Contains("code=", StringComparison.OrdinalIgnoreCase)))
        {
            observations.Add(new LandingObservation
            {
                Perturbation = "browser",
                LandingSurface = "fragment",
                Confidence = SecurityConfidence.Confirmed,
                Detail = Truncate(url.Split('#').LastOrDefault(), 200)
            });
        }

        foreach (var ev in ctx.ActiveTab.RuntimeEvents.SliceSinceMark(mark))
        {
            if (ev.Kind.Equals("message", StringComparison.OrdinalIgnoreCase) && !ev.IsSensorInternalMessage
                && PostMessageOAuthShape.LooksLikeOAuthSecret(ev.Data))
            {
                observations.Add(new LandingObservation
                {
                    Perturbation = "browser",
                    LandingSurface = "postMessage",
                    Confidence = SecurityConfidence.Confirmed,
                    Detail = "Inbound message with OAuth-shaped data"
                });
                break;
            }

            if (ev.Kind.Equals("outbound-window-name", StringComparison.OrdinalIgnoreCase)
                && PostMessageOAuthShape.LooksLikeOAuthSecret(ev.Data))
            {
                observations.Add(new LandingObservation
                {
                    Perturbation = "browser",
                    LandingSurface = "window.name",
                    Confidence = SecurityConfidence.Likely,
                    Detail = Truncate(ev.Data, 120)
                });
            }
        }

        foreach (var entry in ctx.Network.Entries.Skip(netBefore))
        {
            if (entry.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
                && entry.RequestBody != null)
            {
                if (entry.RequestBody.Contains("code=", StringComparison.OrdinalIgnoreCase)
                    || entry.RequestBody.Contains("access_token", StringComparison.OrdinalIgnoreCase))
                {
                    observations.Add(new LandingObservation
                    {
                        Perturbation = "browser",
                        LandingSurface = "form_post",
                        Confidence = SecurityConfidence.Confirmed,
                        Detail = Truncate(entry.Url, 120)
                    });
                    break;
                }

                if (entry.RequestBody.Contains("SAMLResponse=", StringComparison.OrdinalIgnoreCase))
                {
                    observations.Add(new LandingObservation
                    {
                        Perturbation = "browser",
                        LandingSurface = "saml-acs-post",
                        Confidence = SecurityConfidence.Confirmed,
                        Detail = "SAMLResponse posted to ACS — use saml-decode/replay, not OAuth token semantics"
                    });
                    break;
                }
            }
        }

        return observations;
    }

    private static string? Truncate(string? s, int max) =>
        s == null ? null : s.Length <= max ? s : s[..max];
}
