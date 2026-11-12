using Trowser.Automation;
using Trowser.Security.Workflow;
using Trowser.SessionLog;

namespace Trowser.Security.ChainEngine;

/// <summary>
/// Shared chain discovery logic for REST and MCP endpoints.
/// </summary>
public static class ChainAnalysisService
{
        public sealed record AnalyzeOptions(
        string? MinChainedSeverity = null,
        bool IncludePartial = true,
        IdentityStore? IdentityStore = null,
        string? PageUrl = null,
        int? ThirdPartyTotalCount = null,
        int? ExternalWithoutSriCount = null,
        IReadOnlyList<string>? MissingSriScriptUrls = null);

    public static List<ChainableFinding> CollectFindings(AutomationContext context, SessionLogger? sessionLogger = null)
    {
        var shadow = context.SecurityShadow;
        var auto = context.GetAutoScanFindingsForChain();
        var manual = context.GetManualChainFindingsSnapshot();
        var journal = sessionLogger?.GetJournal();
        return FindingNormalizer.CollectAll(shadow, auto, manual, journal);
    }

    public static ChainAnalysisResult Analyze(
        ChainPatternCatalog catalog,
        List<ChainableFinding> findings,
        AnalyzeOptions? options = null)
    {
        options ??= new AnalyzeOptions();
        findings = EnrichMissingSriFindings(findings, options);
        var engine = new ChainDiscoveryEngine(
            catalog,
            options.IdentityStore,
            options.PageUrl,
            options.ThirdPartyTotalCount,
            options.ExternalWithoutSriCount);
        return engine.Analyze(findings, options.MinChainedSeverity, options.IncludePartial);
    }

    private static List<ChainableFinding> EnrichMissingSriFindings(
        List<ChainableFinding> findings,
        AnalyzeOptions options)
    {
        if (options.ExternalWithoutSriCount is not > 0
            || options.MissingSriScriptUrls is not { Count: > 0 })
            return findings;

        var hasChainableMissingSri = findings.Any(f =>
            f.Category.Equals("missing-sri", StringComparison.OrdinalIgnoreCase)
            && (ChainDiscoveryEngine.IsExternalScriptFinding(f, options.PageUrl)
                || (options.ExternalWithoutSriCount > 0 && string.IsNullOrWhiteSpace(f.Endpoint))));

        if (hasChainableMissingSri)
            return findings;

        var manualMissingSri = findings.FirstOrDefault(f =>
            f.Category.Equals("missing-sri", StringComparison.OrdinalIgnoreCase));
        if (manualMissingSri != null && string.IsNullOrWhiteSpace(manualMissingSri.Endpoint))
        {
            var enriched = findings.ToList();
            var idx = enriched.IndexOf(manualMissingSri);
            enriched[idx] = new ChainableFinding
            {
                Id = manualMissingSri.Id,
                Source = manualMissingSri.Source,
                Category = manualMissingSri.Category,
                Severity = manualMissingSri.Severity,
                Title = manualMissingSri.Title,
                Endpoint = options.MissingSriScriptUrls[0],
                Method = manualMissingSri.Method,
                Parameter = manualMissingSri.Parameter,
                Detail = manualMissingSri.Detail,
                Evidence = manualMissingSri.Evidence,
                Tags = manualMissingSri.Tags
            };
            return enriched;
        }

        return findings;
    }

    public static object BuildAnalyzePayload(ChainAnalysisResult result, string? emptyMessage = null)
    {
        if (result.FindingsAnalyzed == 0 && result.Chains.Count == 0 && result.PartialChains.Count == 0)
        {
            return new
            {
                chains = Array.Empty<object>(),
                partialChains = Array.Empty<object>(),
                message = emptyMessage ??
                          "No security findings available to analyze. Enable shadow mode, run auto-scan (POST /api/security/auto-scan), and/or add manual findings (POST /api/security/chain-findings)."
            };
        }

        return new
        {
            chains = result.Chains.Select(c => new
            {
                c.PatternId,
                c.PatternName,
                title = c.PatternName,
                name = c.PatternName,
                c.ChainedSeverity,
                severity = c.ChainedSeverity,
                c.Impact,
                c.ConfidenceScore,
                status = c.Status,
                tags = c.Tags,
                c.Narrative,
                provable = c.Provable,
                suggestedAction = BuildFullChainSuggestedAction(c),
                missingIdentities = c.MissingIdentities,
                unresolvedProofPlaceholders = c.UnresolvedProofPlaceholders,
                matchedFindings = c.MatchedFindings.Select(f => new
                {
                    f.Id,
                    f.Category,
                    f.Severity,
                    f.Title,
                    f.Endpoint
                }),
                severityUpgrade = c.SeverityUpgrade != null ? new
                {
                    from = c.SeverityUpgrade.From,
                    to = c.SeverityUpgrade.To,
                    reason = c.SeverityUpgrade.Reason
                } : null
            }),
            partialChains = result.PartialChains.Select(p => new
            {
                p.PatternId,
                p.PatternName,
                title = p.PatternName,
                name = p.PatternName,
                p.ChainedSeverity,
                severity = p.ChainedSeverity,
                p.Impact,
                p.ConfidenceScore,
                status = p.Status,
                tags = p.Tags,
                p.PresentLinkCount,
                p.RequiredLinkCount,
                p.MissingCategories,
                p.SuggestedAction,
                p.MissingIdentities,
                presentFindings = p.PresentFindings.Select(f => new
                {
                    f.Id,
                    f.Category,
                    f.Severity,
                    f.Title,
                    f.Endpoint,
                    f.Method
                }),
                p.Note,
                potentialNarrative = p.PotentialNarrative,
                narrative = p.PotentialNarrative
            }),
            findingsAnalyzed = result.FindingsAnalyzed,
            chainsFound = result.Chains.Count,
            partialChainsFound = result.PartialChains.Count
        };
    }

    public static object BuildPatternsPayload(IReadOnlyList<ChainPattern> patterns) => new
    {
        patterns = patterns.Select(p => new
        {
            p.Id,
            p.Name,
            p.Description,
            severity = p.ChainedSeverity,
            p.ChainedSeverity,
            categories = p.Links.Select(l => l.RequiredCategory).ToList(),
            p.Impact,
            proofTemplateId = p.ProofTemplateId,
            provable = ChainProvabilityHelper.HasProofTemplate(p),
            links = p.Links.Select(l => new
            {
                l.RequiredCategory,
                l.Role,
                l.Optional,
                l.Constraint,
                endpointPattern = l.EndpointPattern
            })
        }),
        count = patterns.Count
    };

    private static string? BuildFullChainSuggestedAction(CandidateChain chain)
    {
        if (chain.MissingIdentities.Count > 0)
            return ChainProvabilityHelper.SuggestIdentityCapture(chain.MissingIdentities);
        if (!chain.Provable)
            return null;
        return ChainProvabilityHelper.BuildChainProveAction(chain.PatternId, exportEvidence: true)
               + " → then POST /api/repro/verify with expect not-reproducible after patch";
    }
}
