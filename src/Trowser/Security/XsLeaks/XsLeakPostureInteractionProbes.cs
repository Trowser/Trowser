using Trowser.Automation;
using Trowser.Security.Orchestration;

namespace Trowser.Security.XsLeaks;

/// <summary>Active COOP opener and Fetch Metadata enforcement checks.</summary>
internal static class XsLeakPostureInteractionProbes
{
    public static async Task EnrichAsync(
        AutomationContext ctx,
        XsLeakPostureAnalyzer.PostureResult posture,
        string victimUrl,
        string attackerOrigin,
        SafetyMode mode)
    {
        if (mode < SafetyMode.Active) return;
        if (!Uri.TryCreate(victimUrl, UriKind.Absolute, out _)) return;

        var dedupe = posture.Controls
            .Select(c => c.Control + "|" + (c.Detail ?? ""))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        await TryCoopOpenerProbeAsync(ctx, posture.Controls, dedupe, victimUrl, attackerOrigin);
        await TryFetchMetadataEnforcementAsync(ctx, posture.Controls, dedupe, victimUrl);
    }

    private static async Task TryCoopOpenerProbeAsync(
        AutomationContext ctx,
        List<XsLeakPostureAnalyzer.ControlVerdict> controls,
        HashSet<string> dedupe,
        string victimUrl,
        string attackerOrigin)
    {
        var runId = Guid.NewGuid().ToString("N")[..8];
        var pageUrl = AttackerPageBuilder.PageUrl($"coop-probe-{runId}", attackerOrigin);
        var html = AttackerPageBuilder.BuildCoopOpenerProbeHtml(victimUrl);
        var tabIdx = ctx.GetActiveTabIndex();
        var probeIdx = -1;
        try
        {
            probeIdx = await ctx.NewTab(pageUrl, owner: "agent");
            ctx.Tabs[probeIdx].MockResponse(pageUrl, 200, html,
                headers: new Dictionary<string, string> { ["Content-Type"] = "text/html; charset=utf-8" });
            ctx.SwitchTab(probeIdx);
            await ctx.ForceNavigateAsync(pageUrl, terminateScripts: true);
            await ctx.WaitForIdle(300, 6000);

            string? value = null;
            for (var i = 0; i < 30; i++)
            {
                var title = await ctx.GetTitle();
                if (title != null && title.StartsWith("XSLEAK:", StringComparison.Ordinal))
                {
                    value = title["XSLEAK:".Length..];
                    break;
                }
                await Task.Delay(100);
            }

            if (string.IsNullOrEmpty(value)) return;
            var status = value.Contains("severed", StringComparison.OrdinalIgnoreCase)
                         || value.Contains("null", StringComparison.OrdinalIgnoreCase)
                ? "enforced"
                : value.Contains("visible", StringComparison.OrdinalIgnoreCase)
                    ? "partial"
                    : "unknown";

            Add(controls, dedupe, new XsLeakPostureAnalyzer.ControlVerdict
            {
                Control = "COOP-opener-probe",
                Status = status,
                Detail = $"Live popup opener test from attacker origin: {value.Trim().Trim('"')}"
            });
        }
        catch
        {
            /* best-effort */
        }
        finally
        {
            if (probeIdx >= 0 && ctx.Tabs.Count > 1)
            {
                try { await ctx.CloseTab(probeIdx); } catch { /* ignore */ }
            }
            if (tabIdx >= 0 && tabIdx < ctx.Tabs.Count)
                ctx.SwitchTab(tabIdx);
        }
    }

    private static async Task TryFetchMetadataEnforcementAsync(
        AutomationContext ctx,
        List<XsLeakPostureAnalyzer.ControlVerdict> controls,
        HashSet<string> dedupe,
        string victimUrl)
    {
        try
        {
            var baseline = await SecurityProbeHttp.FetchAsync(
                ctx, victimUrl, "GET", null, null, 8000, includeBrowserCookies: true);
            var crossHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Sec-Fetch-Site"] = "cross-site",
                ["Sec-Fetch-Mode"] = "cors",
                ["Sec-Fetch-Dest"] = "empty"
            };
            var cross = await SecurityProbeHttp.FetchAsync(
                ctx, victimUrl, "GET", crossHeaders, null, 8000, includeBrowserCookies: true);

            string status;
            string detail;
            if (baseline.Status is >= 200 and < 300
                && cross.Status is 401 or 403 or 405)
            {
                status = "enforced";
                detail =
                    $"Baseline {baseline.Status} vs cross-site Fetch Metadata probe {cross.Status} — server appears to reject cross-site fetches.";
            }
            else if (baseline.Status is >= 200 and < 300 && cross.Status is >= 200 and < 300)
            {
                status = "absent";
                detail =
                    $"Baseline and cross-site Sec-Fetch-Site probe both returned {cross.Status} — no Fetch Metadata enforcement detected on this URL.";
            }
            else
            {
                status = "unknown";
                detail = $"Baseline status {baseline.Status}, cross-site probe {cross.Status}.";
            }

            Add(controls, dedupe, new XsLeakPostureAnalyzer.ControlVerdict
            {
                Control = "Fetch-Metadata-enforcement",
                Status = status,
                Detail = detail
            });
        }
        catch
        {
            /* best-effort */
        }
    }

    private static void Add(
        List<XsLeakPostureAnalyzer.ControlVerdict> controls,
        HashSet<string> dedupe,
        XsLeakPostureAnalyzer.ControlVerdict verdict)
    {
        var key = verdict.Control + "|" + (verdict.Detail ?? "");
        if (!dedupe.Add(key)) return;
        controls.Add(verdict);
    }
}
