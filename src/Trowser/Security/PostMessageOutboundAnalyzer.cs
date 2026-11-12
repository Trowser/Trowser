using Trowser.Automation;
using Trowser.Security.Runtime;

namespace Trowser.Security;

internal static class PostMessageOutboundAnalyzer
{
    public static List<UnifiedSecurityFinding> Analyze(
        AutomationContext ctx,
        string? victimOrigin,
        bool oauthSession)
    {
        var findings = new List<UnifiedSecurityFinding>();
        var events = ctx.ActiveTab.RuntimeEvents.All()
            .Where(e => e.Kind.Equals("outbound-postmessage", StringComparison.OrdinalIgnoreCase)
                        || e.Kind.Equals("outbound-window-name", StringComparison.OrdinalIgnoreCase))
            .ToList();

        foreach (var ev in events)
        {
            var data = ev.Data ?? "";
            var wildcard = ev.Extra.TryGetValue("wildcard", out var w) && w == "true";
            var target = ev.Extra.TryGetValue("targetOrigin", out var t) ? t : "";
            var crossTarget = wildcard
                || (!string.IsNullOrEmpty(target)
                    && !string.IsNullOrEmpty(victimOrigin)
                    && !target.Equals(victimOrigin, StringComparison.OrdinalIgnoreCase)
                    && target != "*");

            var oauthShape = PostMessageOAuthShape.LooksLikeOAuthSecret(data);
            if (ev.Kind.Equals("outbound-postmessage", StringComparison.OrdinalIgnoreCase))
            {
                if (oauthShape && crossTarget && oauthSession)
                {
                    findings.Add(UnifiedSecurityFinding.Create(
                        category: "postmessage",
                        title: "OAuth-shaped data sent via postMessage to a broad origin",
                        severity: "high",
                        confidence: SecurityConfidence.Confirmed,
                        tier: SecurityFindingTier.Exploitable,
                        evidence: Redact(data),
                        proofHint: "Confirm listener on recipient and whether secret is live",
                        extra: new Dictionary<string, object?>
                        {
                            ["outbound"] = true,
                            ["targetOrigin"] = target,
                            ["wildcard"] = wildcard
                        }));
                }
                else if (wildcard && !oauthShape)
                {
                    findings.Add(UnifiedSecurityFinding.Create(
                        category: "postmessage",
                        title: "postMessage sent with targetOrigin '*'",
                        severity: "low",
                        confidence: SecurityConfidence.Likely,
                        tier: SecurityFindingTier.Hygiene,
                        evidence: Truncate(data, 120)));
                }
            }
            else if (oauthShape && oauthSession)
            {
                findings.Add(UnifiedSecurityFinding.Create(
                    category: "postmessage",
                    title: "OAuth-shaped data written to window.name",
                    severity: "medium",
                    confidence: SecurityConfidence.Likely,
                    tier: SecurityFindingTier.Exploitable,
                    evidence: Redact(data),
                    extra: new Dictionary<string, object?> { ["outbound"] = true, ["surface"] = "window.name" }));
            }
        }

        return findings;
    }

    private static string Redact(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s.Length <= 80 ? s : s[..40] + "…[redacted]…";
    }

    private static string? Truncate(string? s, int max) =>
        s == null ? null : s.Length <= max ? s : s[..max];
}
