using Trowser.Automation;
using Trowser.Security.ChainEngine;

namespace Trowser.Security.XsLeaks;

/// <summary>
/// Correlates session CORS signals with exploitable XS-Leak differentials on the same endpoints.
/// </summary>
internal static class XsLeakCorsCorrelator
{
    public sealed class CorsSignal
    {
        public string Url { get; init; } = "";
        public string AllowOrigin { get; init; } = "";
        public bool Wildcard { get; init; }
        public bool AllowCredentials { get; init; }
    }

    public static List<CorsSignal> CollectSignals(AutomationContext ctx, IEnumerable<string> victimUrls)
    {
        var signals = new List<CorsSignal>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var victimUrl in victimUrls.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(victimUrl, UriKind.Absolute, out var victim))
                continue;

            foreach (var e in ctx.Network.Entries.Where(x => !x.IsTrowserGenerated))
            {
                if (!UrlMatchesVictim(e.Url, victim))
                    continue;

                if (!TryParseCors(e, out var acao, out var acac))
                    continue;

                var key = e.Url + "|" + acao + "|" + acac;
                if (!seen.Add(key)) continue;

                signals.Add(new CorsSignal
                {
                    Url = e.Url,
                    AllowOrigin = acao,
                    Wildcard = acao == "*",
                    AllowCredentials = acac
                });
            }
        }

        return signals;
    }

    public static void Apply(AutomationContext ctx, XsLeakScanner.XsLeakResult result, IReadOnlyList<XsLeakScanner.StateSpec> states)
    {
        var victimUrls = states.Select(s => s.Url).Where(u => !string.IsNullOrWhiteSpace(u)).ToList();
        var signals = CollectSignals(ctx, victimUrls);
        if (signals.Count == 0) return;

        var wildcard = signals.Where(s => s.Wildcard).ToList();
        var reflected = signals.Where(s =>
            !s.Wildcard
            && s.AllowOrigin.StartsWith("http", StringComparison.OrdinalIgnoreCase)).ToList();

        for (var i = 0; i < result.Findings.Count; i++)
        {
            var finding = result.Findings[i];
            if (!string.Equals(finding.Tier, SecurityFindingTier.Exploitable, StringComparison.OrdinalIgnoreCase))
                continue;
            if (string.IsNullOrWhiteSpace(finding.Endpoint))
                continue;

            if (!Uri.TryCreate(finding.Endpoint, UriKind.Absolute, out var endpointUri))
                continue;

            var endpointSignals = wildcard.Concat(reflected)
                .Where(s => UrlMatchesVictim(s.Url, endpointUri))
                .ToList();
            if (endpointSignals.Count == 0) continue;

            var worst = endpointSignals.FirstOrDefault(s => s.Wildcard && s.AllowCredentials)
                        ?? endpointSignals.FirstOrDefault(s => !s.Wildcard && s.AllowCredentials)
                        ?? endpointSignals.First();

            var chainId = finding.Id + "-cors-chain";
            var detail =
                $"XS-Leak differential on {finding.Endpoint} plus CORS Allow-Origin={worst.AllowOrigin}" +
                (worst.AllowCredentials ? " with Allow-Credentials" : "") +
                " — cross-origin fetch() may read response bytes, not only side-channel observables.";

            var severity = worst.Wildcard && worst.AllowCredentials ? "high"
                : worst.AllowCredentials ? "high"
                : worst.Wildcard ? "medium"
                : "medium";

            var nextActions = finding.NextActions
                .Append("Run browser_security_cors on this endpoint.")
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            var extra = new Dictionary<string, object?>(finding.Extra, StringComparer.OrdinalIgnoreCase)
            {
                ["corsChained"] = true,
                ["corsAllowOrigin"] = worst.AllowOrigin,
                ["corsAllowCredentials"] = worst.AllowCredentials
            };

            result.Findings[i] = UnifiedSecurityFinding.Create(
                category: finding.Category,
                title: finding.Title + " (chainable with CORS)",
                severity: severity,
                confidence: finding.Confidence,
                endpoint: finding.Endpoint,
                method: finding.Method,
                param: finding.Param,
                payload: finding.Payload,
                evidence: (finding.Evidence ?? "") + " corsChain=" + detail,
                proofHint: finding.ProofHint,
                tier: finding.Tier,
                nextActions: nextActions,
                nextActionItems: finding.NextActionItems,
                extra: extra,
                id: finding.Id);

            result.ChainFindings.Add(new ChainableFinding
            {
                Id = chainId,
                Source = "xs-leaks",
                Category = "xs-leaks+cors",
                Severity = severity,
                Title = "XS-Leak oracle chainable with CORS misconfiguration",
                Endpoint = finding.Endpoint,
                Detail = detail,
                Remediation =
                    "Fix CORS (do not reflect Origin with credentials; avoid wildcard on authenticated JSON). " +
                    "Also deploy COOP/CORP/frame-ancestors and SameSite cookies to block side-channel oracles.",
                Reference = "https://xsleaks.dev/",
                Tags = ["cors-chained", finding.Param ?? "xs-leak"]
            });
        }
    }

    private static bool UrlMatchesVictim(string entryUrl, Uri victim)
    {
        if (!Uri.TryCreate(entryUrl, UriKind.Absolute, out var u))
            return false;
        if (!string.Equals(u.Host, victim.Host, StringComparison.OrdinalIgnoreCase))
            return false;
        var victimPath = victim.AbsolutePath.TrimEnd('/');
        var entryPath = u.AbsolutePath.TrimEnd('/');
        return entryPath.Equals(victimPath, StringComparison.OrdinalIgnoreCase)
               || entryUrl.StartsWith(victim.GetLeftPart(UriPartial.Path), StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryParseCors(NetworkEntry e, out string acao, out bool credentials)
    {
        acao = "";
        credentials = false;
        foreach (var (k, v) in e.ResponseHeaders)
        {
            if (k.Equals("Access-Control-Allow-Origin", StringComparison.OrdinalIgnoreCase))
                acao = (v ?? "").Trim();
            if (k.Equals("Access-Control-Allow-Credentials", StringComparison.OrdinalIgnoreCase)
                && string.Equals(v, "true", StringComparison.OrdinalIgnoreCase))
                credentials = true;
        }
        return acao.Length > 0;
    }
}
