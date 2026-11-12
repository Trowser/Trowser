using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;
using Trowser.Security.Runtime;
using Trowser.XssAudit;

namespace Trowser.Security;

/// <summary>
/// Active click oracle for passive <c>dom-open-redirect</c> XSS audit hits (inline handlers that assign location from URL input).
/// </summary>
public static class DomOpenRedirectProber
{
    private static readonly string[] RedirectParamNames =
    [
        "back", "url", "next", "redirect", "return", "returnUrl", "return_to", "dest", "destination", "continue", "target"
    ];

    public static async Task<XssResult> ProbeAsync(AutomationContext ctx, XssResult audit, int maxProbes = 3)
    {
        var baselineUrl = await ProbeNavigationRestore.CaptureBaselineUrlAsync(ctx);
        try
        {
        var candidates = audit.Findings
            .Where(f => f.Category.Equals("dom-open-redirect", StringComparison.OrdinalIgnoreCase))
            .Take(Math.Clamp(maxProbes, 1, 5))
            .ToList();

        if (candidates.Count == 0)
            return audit;

        await RuntimeSensorInstaller.InstallOnCurrentDocumentAsync(ctx);

        var canaryHost = RedirectAnalysis.DefaultProbeHost;
        var canaryToken = Guid.NewGuid().ToString("N")[..10];
        var canaryUrl = $"https://{canaryHost}/trowser-or-{canaryToken}";

        var updated = new List<XssFinding>(audit.Findings);
        foreach (var finding in candidates)
        {
            var idx = updated.FindIndex(f =>
                ReferenceEquals(f, finding) ||
                (f.Category == finding.Category && f.Location == finding.Location && f.Evidence == finding.Evidence));
            if (idx < 0) continue;

            var confirmed = await TryConfirmAsync(ctx, finding, canaryUrl, canaryHost, canaryToken);
            if (!confirmed) continue;

            var prev = updated[idx];
            updated[idx] = new XssFinding
            {
                Category = prev.Category,
                Severity = prev.Severity,
                Description = "DOM open redirect confirmed — control navigated to external canary after click",
                Location = prev.Location,
                Evidence = $"{prev.Evidence} | canary={canaryUrl}",
                Recommendation = prev.Recommendation,
                Confidence = "confirmed",
                Source = prev.Source ?? "location.search",
                Sink = prev.Sink ?? "location"
            };
        }

        return new XssResult
        {
            Url = audit.Url,
            Timestamp = audit.Timestamp,
            Findings = updated
        };
        }
        finally
        {
            await ProbeNavigationRestore.TryRestoreAsync(ctx, baselineUrl);
        }
    }

    private static async Task<bool> TryConfirmAsync(
        AutomationContext ctx,
        XssFinding finding,
        string canaryUrl,
        string canaryHost,
        string canaryToken)
    {
        if (string.IsNullOrWhiteSpace(finding.Location))
            return false;

        var pageUrl = await ctx.GetCurrentUrl();
        if (string.IsNullOrWhiteSpace(pageUrl))
            return false;

        var paramNames = GuessParamNames(finding.Evidence);
        foreach (var param in paramNames)
        {
            try
            {
                var probePage = AppendQuery(stripQuery(pageUrl), $"{param}={Uri.EscapeDataString(canaryUrl)}");
                await ctx.Navigate(probePage);
                await Task.Delay(400);
                await RuntimeSensorInstaller.InstallOnCurrentDocumentAsync(ctx);
                await ClearSinkLogAsync(ctx);

                var selector = CssFromLocation(finding.Location);
                await ctx.Click(selector, timeoutMs: 4000);
                await Task.Delay(600);

                var current = await ctx.GetCurrentUrl();
                if (current.Contains(canaryHost, StringComparison.OrdinalIgnoreCase)
                    || current.Contains(canaryToken, StringComparison.OrdinalIgnoreCase))
                    return true;

                if (await SinkLogContainsCanaryAsync(ctx, canaryHost, canaryToken))
                    return true;
            }
            catch
            {
                // try next param / selector variant
            }
        }

        return false;
    }

    private static IEnumerable<string> GuessParamNames(string? evidence)
    {
        var ordered = new List<string>();
        if (!string.IsNullOrEmpty(evidence))
        {
            var m = Regex.Match(evidence, @"get\s*\(\s*['""](\w+)['""]\s*\)", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
            if (m.Success) ordered.Add(m.Groups[1].Value);
            foreach (Match pm in Regex.Matches(evidence, @"[\?&](\w+)=", RegexOptions.None, TimeSpan.FromSeconds(1)))
                ordered.Add(pm.Groups[1].Value);
        }

        foreach (var p in RedirectParamNames)
        {
            if (!ordered.Contains(p, StringComparer.OrdinalIgnoreCase))
                ordered.Add(p);
        }

        return ordered.Take(6);
    }

    private static string CssFromLocation(string location)
    {
        var s = location.Trim();
        if (s.Contains('#')) return s;
        if (s.Contains('>')) return s;
        return s;
    }

    private static string stripQuery(string url)
    {
        var q = url.IndexOf('?', StringComparison.Ordinal);
        var h = url.IndexOf('#', StringComparison.Ordinal);
        if (q < 0) return h >= 0 ? url[..h] : url;
        return h >= 0 ? url[..q] + url[h..] : url[..q];
    }

    private static string AppendQuery(string baseUrl, string query)
    {
        var sep = baseUrl.Contains('?', StringComparison.Ordinal) ? "&" : "?";
        var hashIdx = baseUrl.IndexOf('#', StringComparison.Ordinal);
        if (hashIdx >= 0)
            return baseUrl[..hashIdx] + sep + query + baseUrl[hashIdx..];
        return baseUrl + sep + query;
    }

    private static async Task ClearSinkLogAsync(AutomationContext ctx)
    {
        try { await ctx.ExecuteJs("if(window.__trowser_sink_log) window.__trowser_sink_log.length=0;"); }
        catch { }
    }

    private static async Task<bool> SinkLogContainsCanaryAsync(AutomationContext ctx, string host, string token)
    {
        try
        {
            var json = await ctx.ExecuteJs("""
                (function(){
                    var log = window.__trowser_sink_log || [];
                    return JSON.stringify(log.slice(-15));
                })()
                """);
            var raw = json.Trim();
            if (raw.Length >= 2 && raw[0] == '"')
                raw = JsonSerializer.Deserialize<string>(raw) ?? "[]";

            return raw.Contains(host, StringComparison.OrdinalIgnoreCase)
                   || raw.Contains(token, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }
}
