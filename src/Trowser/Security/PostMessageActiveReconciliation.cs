namespace Trowser.Security;

/// <summary>Align static hygiene findings with active technique outcomes so reports are self-contained.</summary>
public static class PostMessageActiveReconciliation
{
    public static void Apply(
        List<UnifiedSecurityFinding> findings,
        IReadOnlyList<PostMessageTechniqueResult> techniques)
    {
        if (techniques.Count == 0)
            return;

        for (var i = 0; i < findings.Count; i++)
        {
            var f = findings[i];
            if (!IsStaticOriginHygiene(f))
                continue;

            var listenerId = f.Id;
            if (string.IsNullOrEmpty(listenerId))
                continue;

            var forListener = techniques
                .Where(t => string.Equals(t.ListenerId, listenerId, StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (forListener.Count == 0)
                continue;

            if (forListener.Any(t =>
                    t.Verdict.Equals("sink-reached", StringComparison.OrdinalIgnoreCase)
                    && t.Confidence.Equals(SecurityConfidence.Confirmed, StringComparison.OrdinalIgnoreCase)))
                continue;

            if (forListener.Any(t =>
                    t.ConfirmationStatus.Equals("delivered-shape-mismatch", StringComparison.OrdinalIgnoreCase)
                    || (t.Verdict.Equals("message-delivered", StringComparison.OrdinalIgnoreCase)
                        && !t.ConfirmationStatus.Equals("none", StringComparison.OrdinalIgnoreCase))))
                continue;

            if (!forListener.All(t =>
                    t.ConfirmationStatus.Equals("none", StringComparison.OrdinalIgnoreCase)
                    && t.Tier.Equals(SecurityFindingTier.Hygiene, StringComparison.OrdinalIgnoreCase)))
                continue;

            if (forListener.Any(t =>
                    t.Verdict is "message-delivered" or "sink-reached"))
                continue;

            var techSummary = string.Join(", ",
                forListener.Select(t => t.Topology).Distinct(StringComparer.OrdinalIgnoreCase));
            var caveat =
                $"Active confirmation attempted {forListener.Count} technique(s) ({techSummary}); " +
                "none reached a trusted sink — static grade may miss runtime origin checks (see techniques[]).";

            var extra = new Dictionary<string, object?>(f.Extra, StringComparer.OrdinalIgnoreCase)
            {
                ["activeConfirmation"] = "blocked",
                ["activeTechniqueCount"] = forListener.Count,
                ["caveat"] = caveat
            };

            var demotedSeverity = f.Severity.Equals("high", StringComparison.OrdinalIgnoreCase) ? "info" : "low";
            findings[i] = UnifiedSecurityFinding.Create(
                category: f.Category,
                title: f.Title + " (active confirmation blocked)",
                severity: demotedSeverity,
                confidence: SecurityConfidence.Tentative,
                evidence: f.Evidence,
                proofHint: caveat,
                tier: SecurityFindingTier.Hygiene,
                nextActions: f.NextActions,
                extra: extra,
                id: f.Id);
        }
    }

    /// <summary>Surface active confirmation status on hygiene findings (not only in techniques[]).</summary>
    public static void EnrichFindingEvidence(
        List<UnifiedSecurityFinding> findings,
        IReadOnlyList<PostMessageTechniqueResult> techniques)
    {
        for (var i = 0; i < findings.Count; i++)
        {
            var f = findings[i];
            if (!f.Category.Equals("postmessage", StringComparison.OrdinalIgnoreCase))
                continue;
            var listenerId = f.Id;
            if (string.IsNullOrEmpty(listenerId))
                continue;

            var forListener = techniques
                .Where(t => string.Equals(t.ListenerId, listenerId, StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (forListener.Count == 0)
                continue;

            var best = forListener
                .OrderByDescending(t => t.Verdict == "sink-reached" ? 2 : t.Verdict == "message-delivered" ? 1 : 0)
                .First();

            if (best.ConfirmationStatus.Equals("none", StringComparison.OrdinalIgnoreCase)
                && best.Verdict.Equals("blocked", StringComparison.OrdinalIgnoreCase))
                continue;

            var extra = new Dictionary<string, object?>(f.Extra, StringComparer.OrdinalIgnoreCase)
            {
                ["activeVerdict"] = best.Verdict,
                ["activeConfirmationStatus"] = best.ConfirmationStatus,
                ["activeDetail"] = best.Detail
            };

            var evidence = f.Evidence;
            if (!string.IsNullOrEmpty(best.ConfirmationStatus)
                && !best.ConfirmationStatus.Equals("confirmed", StringComparison.OrdinalIgnoreCase))
            {
                evidence = string.IsNullOrEmpty(evidence)
                    ? $"Active probe: {best.ConfirmationStatus} — {best.Detail}"
                    : $"{evidence} | Active probe: {best.ConfirmationStatus} — {best.Detail}";
            }

            findings[i] = UnifiedSecurityFinding.Create(
                category: f.Category,
                title: f.Title,
                severity: f.Severity,
                confidence: f.Confidence,
                evidence: evidence,
                proofHint: f.ProofHint,
                tier: f.Tier,
                nextActions: f.NextActions,
                extra: extra,
                id: f.Id);
        }
    }

    private static bool IsStaticOriginHygiene(UnifiedSecurityFinding f) =>
        f.Category.Equals("postmessage", StringComparison.OrdinalIgnoreCase)
        && f.Tier.Equals(SecurityFindingTier.Hygiene, StringComparison.OrdinalIgnoreCase)
        && f.Title.Contains("origin check", StringComparison.OrdinalIgnoreCase);
}
