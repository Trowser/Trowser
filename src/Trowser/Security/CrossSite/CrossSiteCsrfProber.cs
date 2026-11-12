using System.Text.Json;
using Trowser.Automation;
using Trowser.Security.Orchestration;
using Trowser.Security.XsLeaks;

namespace Trowser.Security.CrossSite;

/// <summary>
/// Browser-faithful cross-site CSRF proof from a mocked attacker origin (evil.trowser.test pattern).
/// </summary>
public sealed class CrossSiteCsrfProber
{
    public sealed class Target
    {
        public string Url { get; init; } = "";
        public string Path { get; init; } = "";
        public string Method { get; init; } = "POST";
        public string? Body { get; init; }
        public string? ContentType { get; init; }
        public int OriginalStatus { get; init; }
        public string? OriginalBody { get; init; }
    }

    public sealed class ProofResult
    {
        public string Technique { get; init; } = "";
        public string Url { get; init; } = "";
        public string Path { get; init; } = "";
        public string Method { get; init; } = "";
        public bool Triggered { get; init; }
        public int? ObservedStatus { get; init; }
        public string? ObservedResourceType { get; init; }
        public string CookieDelivery { get; init; } = "not-run";
        public bool Vulnerable { get; init; }
        public string Severity { get; init; } = "info";
        public string Description { get; init; } = "";
        public string? PageResult { get; init; }
    }

    public sealed class RunResult
    {
        public string RunId { get; init; } = "";
        public string AttackerOrigin { get; init; } = "";
        public List<ProofResult> Proofs { get; init; } = [];
        public int ProbesRun { get; set; }
        public object? CredentialDelivery { get; set; }
        public XsLeakBrowserModel BrowserModel { get; init; } = XsLeakBrowserModel.Current();
    }

    private readonly AutomationContext _ctx;
    private readonly Action<string, string> _log;

    public CrossSiteCsrfProber(AutomationContext context, Action<string, string> log)
    {
        _ctx = context;
        _log = log;
    }

    public async Task<RunResult> RunAsync(
        IReadOnlyList<Target> targets,
        int maxProbes,
        string attackerSite = "cross-site",
        CancellationToken ct = default)
    {
        if (targets.Count == 0 || maxProbes <= 0)
        {
            return new RunResult
            {
                BrowserModel = XsLeakBrowserModel.Current()
            };
        }

        await SecurityScanHygiene.PrepareActiveScanAsync(_ctx);

        var runId = Guid.NewGuid().ToString("N")[..12];
        var firstUrl = targets[0].Url;
        var attackerOrigin = CsrfAttackerPageBuilder.ResolveAttackerOrigin(attackerSite, firstUrl);
        var victimHost = Uri.TryCreate(firstUrl, UriKind.Absolute, out var vu) ? vu.Host : "";

        var tabScope = SecurityScanTabScope.Begin(_ctx);
        var homeTabIdx = tabScope.HomeTabIndex;
        var result = new RunResult
        {
            RunId = runId,
            AttackerOrigin = attackerOrigin,
            BrowserModel = XsLeakBrowserModel.ForRun(attackerOrigin, attackerSite)
        };

        object? credentialDelivery = null;
        try
        {
            var states = new List<XsLeakScanner.StateSpec>
            {
                new() { Label = "victim", Url = firstUrl, Method = targets[0].Method, Body = targets[0].Body }
            };
            var profile = await XsLeakSessionProfile.BuildAsync(
                _ctx, _ctx.OrchestrateIdentityStore ?? new IdentityStore(),
                states, victimHost, identifyAuthCookie: false);

            var credTabIdx = await _ctx.NewTab(CsrfAttackerPageBuilder.PageUrl("cred", "probe", 0, attackerOrigin),
                owner: "agent");
            CopyNetworkRules(homeTabIdx, credTabIdx);
            _ctx.Tabs[credTabIdx].MockResponse(
                CsrfAttackerPageBuilder.PageUrl("cred", "probe", 0, attackerOrigin), 200,
                "<!DOCTYPE html><html><body></body></html>",
                headers: new Dictionary<string, string> { ["Content-Type"] = "text/html; charset=utf-8" });
            var delivery = await XsLeakCredentialObservation.ObserveAsync(
                _ctx, credTabIdx, attackerOrigin, firstUrl, profile.AuthCookies, profile.CookieMode,
                includeTopLevel: true);
            credentialDelivery = new XsLeakCredentialObservation().ToApiObject(delivery);
            try { await _ctx.CloseTab(credTabIdx); } catch { /* ignore */ }
            _ctx.SwitchTab(homeTabIdx);

            var probeTabIdx = await _ctx.NewTab(
                CsrfAttackerPageBuilder.PageUrl(runId, "session", 0, attackerOrigin), owner: "agent");
            CopyNetworkRules(homeTabIdx, probeTabIdx);

            var budget = maxProbes;
            var proofIndex = 0;
            foreach (var target in targets)
            {
                if (budget <= 0) break;
                ct.ThrowIfCancellationRequested();

                foreach (var technique in SelectTechniques(target))
                {
                    if (budget <= 0) break;

                    _log($"  [cross-site CSRF] {technique} {target.Method} {target.Path}", "#888888");
                    var proof = await RunOneProofAsync(
                        runId, probeTabIdx, attackerOrigin, target, technique, delivery, proofIndex++);
                    result.Proofs.Add(proof);
                    budget--;
                }
            }

            result.ProbesRun = result.Proofs.Count;
            result.CredentialDelivery = credentialDelivery;

            try { await _ctx.CloseTab(probeTabIdx); } catch { /* ignore */ }
        }
        finally
        {
            _ctx.SwitchTab(homeTabIdx);
            await tabScope.FinishAsync(victimHost, runId);
        }

        return result;
    }

    private async Task<ProofResult> RunOneProofAsync(
        string runId,
        int probeTabIdx,
        string attackerOrigin,
        Target target,
        string technique,
        XsLeakCredentialObservation.DeliveryResult delivery,
        int index)
    {
        _ctx.SwitchTab(probeTabIdx);
        var tab = _ctx.ActiveTab;
        var pageUrl = CsrfAttackerPageBuilder.PageUrl(runId, technique, index, attackerOrigin);
        var html = CsrfAttackerPageBuilder.BuildHtml(target, technique);
        tab.MockResponse(pageUrl, 200, html,
            headers: new Dictionary<string, string> { ["Content-Type"] = "text/html; charset=utf-8" });

        var networkMark = tab.Network.Count;
        await _ctx.ForceNavigateAsync(pageUrl, terminateScripts: true);
        await _ctx.WaitForIdle(400, 12_000);

        string? pageJson = null;
        for (var i = 0; i < 90; i++)
        {
            var title = await _ctx.GetTitle();
            if (title != null && title.StartsWith("CSRF:", StringComparison.Ordinal))
            {
                pageJson = title["CSRF:".Length..];
                break;
            }

            await Task.Delay(100);
        }

        var observed = FindVictimRequest(tab, target.Url, networkMark);
        var cookieDelivery = SummarizeCookieDelivery(delivery, target.Method);

        var eval = observed.Status is >= 200 and < 300
            ? CsrfProbeResponseEvaluator.EvaluateMissingTokenProbe(
                target.OriginalStatus, target.OriginalBody, observed.Status, observed.Body)
            : new CsrfProbeResponseEvaluator.Evaluation
            {
                Vulnerable = false,
                Severity = "info",
                Summary = observed.Status > 0
                    ? $"cross-site probe saw HTTP {observed.Status}."
                    : "no matching victim request observed in the probe tab network log (blocked by browser, CORS preflight, or SameSite)."
            };

        if (cookieDelivery.StartsWith("blocked", StringComparison.OrdinalIgnoreCase)
            && target.Method is not "GET" and not "HEAD")
        {
            eval = new CsrfProbeResponseEvaluator.Evaluation
            {
                Vulnerable = false,
                Severity = "info",
                Summary = eval.Summary + $" Session cookie delivery: {cookieDelivery}."
            };
        }

        var vulnerable = eval.Vulnerable && observed.Status > 0;
        var description =
            $"Cross-site {technique} from {attackerOrigin}: {eval.Summary} Cookie delivery hint: {cookieDelivery}.";

        return new ProofResult
        {
            Technique = technique,
            Url = target.Url,
            Path = target.Path,
            Method = target.Method,
            Triggered = pageJson != null || observed.Status > 0,
            ObservedStatus = observed.Status > 0 ? observed.Status : null,
            ObservedResourceType = observed.ResourceType,
            CookieDelivery = cookieDelivery,
            Vulnerable = vulnerable,
            Severity = vulnerable ? eval.Severity : "info",
            Description = description,
            PageResult = pageJson
        };
    }

    private static string SummarizeCookieDelivery(
        XsLeakCredentialObservation.DeliveryResult delivery,
        string method)
    {
        var isGet = method.Equals("GET", StringComparison.OrdinalIgnoreCase)
                    || method.Equals("HEAD", StringComparison.OrdinalIgnoreCase);
        if (isGet)
            return delivery.TopLevel.StartsWith("sent", StringComparison.OrdinalIgnoreCase)
                ? "top-level:sent"
                : delivery.TopLevel;

        return delivery.Subresource.StartsWith("sent", StringComparison.OrdinalIgnoreCase)
            ? "subresource:sent"
            : delivery.Subresource;
    }

    private static (int Status, string? Body, string? ResourceType) FindVictimRequest(
        BrowserTab tab, string targetUrl, int networkMark)
    {
        if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var targetUri))
            return (0, null, null);

        var entries = tab.Network.Entries;
        for (var i = entries.Count - 1; i >= networkMark && i >= 0; i--)
        {
            var e = entries[i];
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var u))
                continue;
            if (!string.Equals(u.Host, targetUri.Host, StringComparison.OrdinalIgnoreCase))
                continue;
            if (!string.Equals(u.AbsolutePath, targetUri.AbsolutePath, StringComparison.OrdinalIgnoreCase))
                continue;

            if (!string.IsNullOrEmpty(targetUri.Query)
                && !string.Equals(u.Query, targetUri.Query, StringComparison.Ordinal))
                continue;

            return (e.StatusCode, e.ResponseBody, e.ResourceType);
        }

        // Relaxed: any request to same path ignoring query
        for (var i = entries.Count - 1; i >= networkMark && i >= 0; i--)
        {
            var e = entries[i];
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var u))
                continue;
            if (!string.Equals(u.Host, targetUri.Host, StringComparison.OrdinalIgnoreCase))
                continue;
            if (!string.Equals(u.AbsolutePath, targetUri.AbsolutePath, StringComparison.OrdinalIgnoreCase))
                continue;
            return (e.StatusCode, e.ResponseBody, e.ResourceType);
        }

        return (0, null, null);
    }

    internal static IEnumerable<string> SelectTechniques(Target target)
    {
        var method = target.Method.ToUpperInvariant();
        var ct = (target.ContentType ?? "").ToLowerInvariant();
        var body = target.Body?.TrimStart() ?? "";

        if (method is "GET" or "HEAD")
        {
            yield return "top-level-get";
            yield break;
        }

        if (ct.Contains("json") || body.StartsWith('{'))
        {
            yield return "fetch-text-plain";
            yield break;
        }

        yield return "iframe-form-post";
        if (method == "POST")
            yield return "top-level-form-post";
        yield return "fetch-no-cors";
    }

    private void CopyNetworkRules(int sourceTabIdx, int destTabIdx)
    {
        if (sourceTabIdx < 0 || destTabIdx < 0
            || sourceTabIdx >= _ctx.Tabs.Count || destTabIdx >= _ctx.Tabs.Count)
            return;
        _ctx.Tabs[destTabIdx].CopyNetworkRulesFrom(_ctx.Tabs[sourceTabIdx]);
    }
}
