using Trowser.Security.Workflow;
using System.Text.RegularExpressions;

namespace Trowser.Security.ChainEngine;

/// <summary>
/// Matches available findings against the chain pattern catalog to discover
/// attack chains, rank them by confidence, and generate actionable narratives.
/// </summary>
public class ChainDiscoveryEngine
{
    /// <summary>Full chains below this confidence are reported as partial/hypothesis, not confirmed.</summary>
    internal const double ConfirmedConfidenceFloor = 0.8;

    private readonly ChainPatternCatalog _catalog;
    private readonly IdentityStore? _identityStore;
    private readonly string? _pageUrl;
    private readonly int? _thirdPartyTotalCount;
    private readonly int? _externalWithoutSriCount;

    public ChainDiscoveryEngine(
        ChainPatternCatalog catalog,
        IdentityStore? identityStore = null,
        string? pageUrl = null,
        int? thirdPartyTotalCount = null,
        int? externalWithoutSriCount = null)
    {
        _catalog = catalog;
        _identityStore = identityStore;
        _pageUrl = pageUrl;
        _thirdPartyTotalCount = thirdPartyTotalCount;
        _externalWithoutSriCount = externalWithoutSriCount;
    }

    /// <summary>
    /// Analyze findings against all known patterns and return discovered chains + partial chains.
    /// </summary>
    public ChainAnalysisResult Analyze(
        List<ChainableFinding> findings,
        string? minChainedSeverity = null,
        bool includePartial = true)
    {
        var patterns = _catalog.GetAll();
        var chains = new List<CandidateChain>();
        var partials = new List<PartialChain>();

        // Build a lookup of findings by category for fast matching
        var byCategory = findings
            .GroupBy(f => f.Category.Trim(), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

        foreach (var pattern in patterns)
        {
            if (minChainedSeverity != null && SeverityRank(pattern.ChainedSeverity) < SeverityRank(minChainedSeverity))
                continue;

            if (!PassesPatternPrerequisites(pattern))
                continue;

            var matchResult = TryMatch(pattern, byCategory, findings);
            var presentRequired = CountRequiredPresent(matchResult);

            if (matchResult.IsFullMatch && presentRequired > 0)
            {
                if (!MeetsConfirmation(pattern, matchResult, findings))
                {
                    if (includePartial)
                        partials.Add(BuildHypothesisPartial(pattern, matchResult, findings));
                    continue;
                }

                var confidence = ComputeConfidence(pattern, matchResult);
                if (pattern.ConfirmationAnyCategories.Count > 0 && MeetsConfirmation(pattern, matchResult, findings))
                    confidence = Math.Max(confidence, 0.85);

                if (confidence < ConfirmedConfidenceFloor)
                {
                    if (includePartial)
                        partials.Add(BuildUnderConfirmedPartial(pattern, matchResult, confidence));
                    continue;
                }

                chains.Add(BuildCandidate(pattern, matchResult, confidence, findings));
            }
            else if (includePartial && presentRequired > 0 && matchResult.MissingRequired.Count <= 1)
            {
                partials.Add(BuildPartial(pattern, matchResult));
            }
        }

        // Sort chains by chained severity (desc), then confidence (desc)
        chains.Sort((a, b) =>
        {
            var sevCmp = SeverityRank(b.ChainedSeverity).CompareTo(SeverityRank(a.ChainedSeverity));
            return sevCmp != 0 ? sevCmp : b.ConfidenceScore.CompareTo(a.ConfidenceScore);
        });

        // Sort partial chains by chained severity (desc), then confidence (desc)
        partials.Sort((a, b) =>
        {
            var sevCmp = SeverityRank(b.ChainedSeverity).CompareTo(SeverityRank(a.ChainedSeverity));
            return sevCmp != 0 ? sevCmp : b.ConfidenceScore.CompareTo(a.ConfidenceScore);
        });

        return new ChainAnalysisResult
        {
            FindingsAnalyzed = findings.Count,
            ChainsDiscovered = chains.Count,
            Chains = chains,
            PartialChains = partials
        };
    }

    /// <summary>
    /// Try to match a pattern against available findings.
    /// </summary>
    private MatchResult TryMatch(
        ChainPattern pattern,
        Dictionary<string, List<ChainableFinding>> byCategory,
        List<ChainableFinding> allFindings)
    {
        var matched = new List<(ChainLink Link, ChainableFinding Finding)>();
        var missingRequired = new List<string>();
        var missingOptional = new List<string>();

        foreach (var link in pattern.Links)
        {
            var candidates = FindCandidatesForLink(pattern, link, byCategory, matched.Select(m => m.Finding).ToList());

            if (candidates.Count > 0)
            {
                var best = SelectBestFinding(link, pattern, candidates);
                matched.Add((link, best));
            }
            else if (link.Optional)
            {
                missingOptional.Add(link.RequiredCategory);
            }
            else
            {
                missingRequired.Add(link.RequiredCategory);
            }
        }

        var allowedCategories = pattern.Links
            .Select(l => l.RequiredCategory)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        return new MatchResult
        {
            PresentFindings = matched
                .Where(m => allowedCategories.Contains(m.Link.RequiredCategory))
                .Select(m => m.Finding)
                .ToList(),
            MatchedLinks = matched,
            MissingRequired = missingRequired,
            MissingOptional = missingOptional
        };
    }

    private static int CountRequiredPresent(MatchResult match) =>
        match.MatchedLinks.Count(m => !m.Link.Optional);

    private static bool MeetsConfirmation(
        ChainPattern pattern,
        MatchResult match,
        List<ChainableFinding> allFindings)
    {
        if (pattern.ConfirmationAnyCategories.Count == 0)
            return true;

        if (pattern.Id.Equals("missing-hsts-downgrade-risk", StringComparison.OrdinalIgnoreCase))
        {
            if (allFindings.Any(f =>
                    f.Category.Equals("http-downgrade-proven", StringComparison.OrdinalIgnoreCase)))
                return true;

            var anchor = match.PresentFindings.FirstOrDefault()?.Endpoint;
            return allFindings.Any(f =>
                (f.Category.Equals("mixed-content", StringComparison.OrdinalIgnoreCase)
                 || f.Category.Equals("missing-secure-flag", StringComparison.OrdinalIgnoreCase))
                && SeverityRank(f.Severity) >= SeverityRank("medium")
                && SameOrigin(f.Endpoint, anchor));
        }

        var pool = allFindings
            .Select(f => f.Category)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return pattern.ConfirmationAnyCategories.Any(c => pool.Contains(c));
    }

    private static string CapSeverity(string severity, string? cap)
    {
        if (string.IsNullOrWhiteSpace(cap))
            return severity;
        return SeverityRank(severity) > SeverityRank(cap) ? cap : severity;
    }

    private static ChainableFinding SelectBestFinding(
        ChainLink link,
        ChainPattern pattern,
        List<ChainableFinding> candidates) =>
        candidates
            .OrderByDescending(f => AuthRateLimitPriorityScore(f, pattern, link))
            .ThenByDescending(f => SeverityRank(f.Severity))
            .ThenByDescending(f => f.Endpoint != null ? 1 : 0)
            .First();

    /// <summary>
    /// Prefer login/auth rate-limit findings when building account-takeover chains.
    /// </summary>
    private static int AuthRateLimitPriorityScore(ChainableFinding finding, ChainPattern pattern, ChainLink link)
    {
        if (!pattern.Impact.Equals("account-takeover", StringComparison.OrdinalIgnoreCase)
            || !link.RequiredCategory.Equals("missing-rate-limit", StringComparison.OrdinalIgnoreCase))
            return 0;

        var score = 0;
        var endpoint = finding.Endpoint ?? "";

        foreach (var tag in finding.Tags)
        {
            if (!tag.StartsWith("endpoint-kind:", StringComparison.OrdinalIgnoreCase)) continue;
            score += tag["endpoint-kind:".Length..].ToLowerInvariant() switch
            {
                "login" => 100,
                "otp" => 90,
                "coupon" => 40,
                "write-api" => 35,
                "export" => 20,
                "search" => 5,
                _ => 25
            };
            break;
        }

        if (Regex.IsMatch(endpoint, @"(?i)(login|signin|sign-in|auth|token|session|oauth|password|otp|mfa|credential)", RegexOptions.None, TimeSpan.FromSeconds(1)))
            score += 80;

        if (IsStateChanging(finding.Method))
            score += 20;

        if (finding.Method?.Equals("GET", StringComparison.OrdinalIgnoreCase) == true
            && Regex.IsMatch(endpoint, @"(?i)(search|catalog|query|filter)", RegexOptions.None, TimeSpan.FromSeconds(1)))
            score -= 60;

        return score;
    }

    /// <summary>
    /// Find findings that satisfy a chain link, including constraint evaluation.
    /// </summary>
    private List<ChainableFinding> FindCandidatesForLink(
        ChainPattern pattern,
        ChainLink link,
        Dictionary<string, List<ChainableFinding>> byCategory,
        List<ChainableFinding> alreadyMatched)
    {
        if (!byCategory.TryGetValue(link.RequiredCategory, out var candidates))
            return [];

        if (link.RequiredCategory.Equals("missing-httponly", StringComparison.OrdinalIgnoreCase))
            candidates = candidates.Where(MissingHttpOnlyFindingIsChainable).ToList();

        return candidates.Where(f =>
            SatisfiesConstraint(link.Constraint, f, alreadyMatched) &&
            EndpointMatches(link.EndpointPattern, f.Endpoint) &&
            SatisfiesCategoryRules(link, f) &&
            IsConfirmedSstiFinding(f) &&
            // Login CSRF must not enable worm / self-propagating narratives.
            !(pattern.Impact.Equals("worm", StringComparison.OrdinalIgnoreCase)
              && f.Category.Equals("csrf", StringComparison.OrdinalIgnoreCase)
              && LooksLikeLoginEndpoint(f.Endpoint))).ToList();
    }

    private bool PassesPatternPrerequisites(ChainPattern pattern)
    {
        if (!pattern.Id.Equals("missing-sri-cdn-compromise", StringComparison.OrdinalIgnoreCase))
            return true;

        if (_thirdPartyTotalCount is 0)
            return false;

        if (_externalWithoutSriCount is 0)
            return false;

        return true;
    }

    private bool SatisfiesCategoryRules(ChainLink link, ChainableFinding finding)
    {
        if (!link.RequiredCategory.Equals("missing-sri", StringComparison.OrdinalIgnoreCase))
            return true;

        // When live inventory confirms external scripts/stylesheets without SRI, accept
        // category-tagged findings even without a cross-origin endpoint URL (manual chain-findings).
        if (_externalWithoutSriCount is > 0)
        {
            if (string.IsNullOrWhiteSpace(finding.Endpoint))
                return true;

            if (IsExternalScriptFinding(finding, _pageUrl))
                return true;

            return false;
        }

        return IsExternalScriptFinding(finding, _pageUrl);
    }

    /// <summary>
    /// missing-sri is only chainable when it refers to a cross-origin script/stylesheet URL.
    /// </summary>
    internal static bool IsExternalScriptFinding(ChainableFinding finding, string? pageUrl)
    {
        if (string.IsNullOrWhiteSpace(finding.Endpoint))
            return false;

        if (!Uri.TryCreate(finding.Endpoint, UriKind.Absolute, out var scriptUri)
            || scriptUri.Scheme is not ("http" or "https"))
            return false;

        if (string.IsNullOrWhiteSpace(pageUrl)
            || !Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri))
        {
            return finding.Tags.Any(t => t.Equals("external-script", StringComparison.OrdinalIgnoreCase))
                || finding.Title.Contains("Third-party", StringComparison.OrdinalIgnoreCase)
                || finding.Detail?.Contains("CDN", StringComparison.OrdinalIgnoreCase) == true;
        }

        return !string.Equals(scriptUri.Host, pageUri.Host, StringComparison.OrdinalIgnoreCase)
            || scriptUri.Port != pageUri.Port;
    }

    private static bool EndpointMatches(string? pattern, string? endpoint)
    {
        if (string.IsNullOrWhiteSpace(pattern))
            return true;
        if (string.IsNullOrWhiteSpace(endpoint))
            return false;

        try
        {
            return Regex.IsMatch(endpoint, pattern, RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
        }
        catch
        {
            return endpoint.Contains(pattern, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// Evaluate whether a finding satisfies a link's constraint relative to already-matched findings.
    /// </summary>
    private bool SatisfiesConstraint(string? constraint, ChainableFinding finding, List<ChainableFinding> others)
    {
        if (constraint == null) return true;

        return constraint switch
        {
            "external-resource" => IsExternalScriptFinding(finding, _pageUrl),
            "same-origin" when others.Count > 0 => others.Any(o => SameOrigin(finding.Endpoint, o.Endpoint)),
            "same-endpoint" when others.Count > 0 => others.Any(o =>
                finding.Endpoint != null && o.Endpoint != null &&
                finding.Endpoint.Equals(o.Endpoint, StringComparison.OrdinalIgnoreCase)),
            "state-changing" => finding.Category.Equals("csrf", StringComparison.OrdinalIgnoreCase)
                ? IsStateChangingCsrfFinding(finding)
                : IsStateChanging(finding.Method),
            "mutating-idor" => IsMutatingIdorFinding(finding),
            "stored-or-reflected-xss" => IsStoredOrReflectedXssFinding(finding),
            _ => others.Count == 0 || true
        };
    }

    /// <summary>
    /// CSRF chain links need mutating methods — not informational missing-token on GET admin pages.
    /// </summary>
    internal static bool IsStateChangingCsrfFinding(ChainableFinding finding)
    {
        if (!finding.Category.Equals("csrf", StringComparison.OrdinalIgnoreCase))
            return IsStateChanging(finding.Method);

        var method = finding.Method?.Trim();
        if (method != null)
        {
            if (method.Equals("GET", StringComparison.OrdinalIgnoreCase)
                || method.Equals("HEAD", StringComparison.OrdinalIgnoreCase)
                || method.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase))
                return false;
            return IsStateChanging(method);
        }

        var text = $"{finding.Title} {finding.Detail} {finding.Endpoint}".ToLowerInvariant();
        if (Regex.IsMatch(text, @"(?<![a-z])get(?![a-z])") && !Regex.IsMatch(text, @"(?<![a-z])post(?![a-z])"))
            return false;

        return false;
    }

    /// <summary>
    /// IDOR account-takeover chains require write/delete IDOR — not public read-by-ID calendar views.
    /// </summary>
    internal static bool IsMutatingIdorFinding(ChainableFinding finding)
    {
        if (!finding.Category.Equals("idor", StringComparison.OrdinalIgnoreCase))
            return true;

        var text = $"{finding.Title} {finding.Detail} {finding.Evidence} {string.Join(' ', finding.Tags)}"
            .ToLowerInvariant();
        var method = finding.Method?.Trim();

        if (method != null
            && (method.Equals("GET", StringComparison.OrdinalIgnoreCase)
                || method.Equals("HEAD", StringComparison.OrdinalIgnoreCase)))
        {
            if (finding.Severity is "high" or "critical"
                && MutatingIdorTextSignals(text))
                return true;
            return false;
        }

        if (method != null && IsStateChanging(method))
            return true;

        if (finding.Severity is "high" or "critical"
            && (finding.Source.Equals("autoscan", StringComparison.OrdinalIgnoreCase)
                || MutatingIdorTextSignals(text)))
            return true;

        if (text.Contains("public") && text.Contains("calendar"))
            return false;
        if (text.Contains("read-only") || text.Contains("read only"))
            return false;

        return false;
    }

    private static bool MutatingIdorTextSignals(string text) =>
        text.Contains("write") || text.Contains("delete") || text.Contains("modify")
        || text.Contains("update") || text.Contains("mutation") || text.Contains("mass assignment");

    /// <summary>
    /// ssti-confirmed chain links require arithmetic/canary-style evidence — not error-signature probes alone.
    /// </summary>
    internal static bool IsConfirmedSstiFinding(ChainableFinding finding)
    {
        if (!finding.Category.Equals("ssti-confirmed", StringComparison.OrdinalIgnoreCase))
            return true;

        var text = $"{finding.Title} {finding.Detail} {finding.Evidence} {string.Join(' ', finding.Tags)}"
            .ToLowerInvariant();

        if (text.Contains("suspected") || text.Contains("error signature") || text.Contains("template error"))
            return false;

        return text.Contains("arithmetic") || text.Contains("49") || text.Contains("56")
               || text.Contains("engine canary") || text.Contains("dual")
               || text.Contains("cmd-canary") || text.Contains("b-ssti-arithmetic");
    }

    /// <summary>
    /// Worm / CSRF×XSS chains require exploit-shaped XSS evidence — not inline-handler hygiene.
    /// </summary>
    internal static bool IsStoredOrReflectedXssFinding(ChainableFinding finding)
    {
        if (!finding.Category.Equals("xss", StringComparison.OrdinalIgnoreCase))
            return false;

        var text = $"{finding.Title} {finding.Detail} {finding.Evidence} {string.Join(' ', finding.Tags)}"
            .ToLowerInvariant();

        if (text.Contains("inline-handler") || text.Contains("javascript-url")
            || text.Contains("dom-xss-flow") || text.Contains("dangerous-sink")
            || text.Contains("xss-hygiene"))
            return false;

        // Prefer explicit stored/reflected/active signals; allow high/critical auto-scan XSS.
        if (text.Contains("stored") || text.Contains("reflected")
            || text.Contains("confirmed") || text.Contains("payload")
            || text.Contains("xss-scan") || text.Contains("executed"))
            return true;

        if (finding.Source.Equals("autoscan", StringComparison.OrdinalIgnoreCase)
            || finding.Source.Contains("orchestrate", StringComparison.OrdinalIgnoreCase))
        {
            return finding.Severity is "high" or "critical";
        }

        return false;
    }

    private static bool SameOrigin(string? url1, string? url2)
    {
        if (url1 == null || url2 == null) return true; // assume same origin if unknown
        try
        {
            var u1 = new Uri(url1, UriKind.Absolute);
            var u2 = new Uri(url2, UriKind.Absolute);
            return u1.Scheme == u2.Scheme && u1.Host == u2.Host && u1.Port == u2.Port;
        }
        catch
        {
            return true; // relative URLs → assume same origin
        }
    }

    private static bool IsStateChanging(string? method)
    {
        if (method == null) return true; // assume state-changing if unknown
        return method.Equals("POST", StringComparison.OrdinalIgnoreCase) ||
               method.Equals("PUT", StringComparison.OrdinalIgnoreCase) ||
               method.Equals("PATCH", StringComparison.OrdinalIgnoreCase) ||
               method.Equals("DELETE", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Build a candidate chain from a successful pattern match.
    /// </summary>
    private CandidateChain BuildCandidate(
        ChainPattern pattern,
        MatchResult match,
        double confidence,
        List<ChainableFinding> allFindings)
    {
        var narrative = BuildTitleQuotedNarrative(pattern, match);

        var individualSeverities = match.PresentFindings
            .Select(f => $"{f.Severity} ({f.Category})")
            .ToList();

        var canProve = ChainProvabilityHelper.CanProveWithFindings(pattern, match.PresentFindings, _identityStore, _pageUrl);
        var chainedSeverity = pattern.ChainedSeverity;
        if (SeverityRank(chainedSeverity) >= SeverityRank("critical") && !canProve)
            chainedSeverity = CapSeverity(chainedSeverity, "high");

        if (pattern.Id.Equals("missing-hsts-downgrade-risk", StringComparison.OrdinalIgnoreCase)
            && !allFindings.Any(f =>
                f.Category.Equals("http-downgrade-proven", StringComparison.OrdinalIgnoreCase)))
        {
            chainedSeverity = CapSeverity(chainedSeverity, "medium");
        }

        return new CandidateChain
        {
            PatternId = pattern.Id,
            PatternName = pattern.Name,
            ChainedSeverity = chainedSeverity,
            Impact = pattern.Impact,
            ConfidenceScore = Math.Round(confidence, 2),
            MatchedFindings = match.PresentFindings,
            Status = canProve && confidence >= ConfirmedConfidenceFloor ? "confirmed" : "matched",
            Narrative = narrative,
            Provable = canProve && confidence >= ConfirmedConfidenceFloor,
            MissingIdentities = ChainProvabilityHelper.GetMissingIdentities(pattern, _identityStore),
            UnresolvedProofPlaceholders = ChainProvabilityHelper.HasProofTemplate(pattern)
                && !ChainProvabilityHelper.CanProveWithFindings(pattern, match.PresentFindings, _identityStore, _pageUrl)
                    ? ChainProvabilityHelper.GetUnresolvedProofPlaceholders(pattern, match.PresentFindings, _pageUrl)
                    : null,
            SeverityUpgrade = new SeverityUpgrade
            {
                From = individualSeverities,
                To = chainedSeverity,
                Reason = $"Combined {string.Join(" + ", match.PresentFindings.Select(f => f.Category))} enables {pattern.Impact}"
            }
        };
    }

    /// <summary>
    /// Build a partial chain to suggest further investigation.
    /// </summary>
    private PartialChain BuildPartial(ChainPattern pattern, MatchResult match)
    {
        var missingIdentities = ChainProvabilityHelper.GetMissingIdentities(pattern, _identityStore);
        var suggestedAction = BuildPartialSuggestedAction(pattern, match, missingIdentities);
        var requiredCount = pattern.Links.Count(l => !l.Optional);
        var presentRequired = CountRequiredPresent(match);
        var confidence = ComputePartialConfidence(match, presentRequired, requiredCount);

        return new PartialChain
        {
            PatternId = pattern.Id,
            PatternName = pattern.Name,
            ChainedSeverity = pattern.ChainedSeverity,
            Impact = pattern.Impact,
            ConfidenceScore = Math.Round(confidence, 2),
            PresentFindings = match.PresentFindings,
            MissingCategories = match.MissingRequired,
            PresentLinkCount = presentRequired,
            RequiredLinkCount = requiredCount,
            Status = "partial",
            Note = $"Found {presentRequired} of {requiredCount} required links. " +
                   $"Missing: {string.Join(", ", match.MissingRequired)}. Confirm these to complete the chain.",
            PotentialNarrative = BuildPartialNarrative(pattern, match),
            SuggestedAction = suggestedAction,
            MissingIdentities = missingIdentities,
            Tags = pattern.HypothesisTags
        };
    }

    private PartialChain BuildUnderConfirmedPartial(ChainPattern pattern, MatchResult match, double confidence)
    {
        var requiredCount = pattern.Links.Count(l => !l.Optional);
        var presentRequired = CountRequiredPresent(match);
        var capped = CapSeverity(pattern.ChainedSeverity, pattern.HypothesisSeverityCap ?? "medium");
        var missingIdentities = ChainProvabilityHelper.GetMissingIdentities(pattern, _identityStore);

        return new PartialChain
        {
            PatternId = pattern.Id,
            PatternName = pattern.Name,
            ChainedSeverity = capped,
            Impact = pattern.Impact,
            ConfidenceScore = Math.Round(confidence, 2),
            PresentFindings = match.PresentFindings,
            MissingCategories = [],
            PresentLinkCount = presentRequired,
            RequiredLinkCount = requiredCount,
            Status = "partial",
            Tags = pattern.HypothesisTags,
            Note = $"All required links matched but confidence {confidence:0.##} is below {ConfirmedConfidenceFloor:0.##} — treat as hypothesis until stronger evidence.",
            PotentialNarrative = BuildTitleQuotedNarrative(pattern, match),
            SuggestedAction = BuildPartialSuggestedAction(pattern, match, missingIdentities),
            MissingIdentities = missingIdentities
        };
    }

    private PartialChain BuildHypothesisPartial(
        ChainPattern pattern,
        MatchResult match,
        List<ChainableFinding> allFindings)
    {
        var missingConfirm = pattern.ConfirmationAnyCategories
            .Where(c => !allFindings.Any(f => f.Category.Equals(c, StringComparison.OrdinalIgnoreCase)))
            .ToList();

        var missingIdentities = ChainProvabilityHelper.GetMissingIdentities(pattern, _identityStore);
        var requiredCount = pattern.Links.Count(l => !l.Optional);
        var presentRequired = CountRequiredPresent(match);
        var suggested = missingConfirm.Count > 0
            ? SuggestAction(missingConfirm[0]) ?? "Probe HTTP downgrade (http:// same host), session cookie Secure flag, or mixed content."
            : BuildPartialSuggestedAction(pattern, match, missingIdentities);

        var capped = CapSeverity(pattern.ChainedSeverity, pattern.HypothesisSeverityCap ?? "medium");
        var confidence = Math.Min(ComputePartialConfidence(match, presentRequired, requiredCount), 0.55);

        return new PartialChain
        {
            PatternId = pattern.Id,
            PatternName = pattern.Name,
            ChainedSeverity = capped,
            Impact = pattern.Impact,
            ConfidenceScore = Math.Round(confidence, 2),
            PresentFindings = match.PresentFindings,
            MissingCategories = missingConfirm,
            PresentLinkCount = presentRequired,
            RequiredLinkCount = requiredCount,
            Status = "partial",
            Tags = pattern.HypothesisTags,
            Note = $"Hypothesis only ({presentRequired}/{requiredCount} required links present). " +
                   $"Needs confirmation: {string.Join(", ", missingConfirm)}.",
            PotentialNarrative = BuildPartialNarrative(pattern, match),
            SuggestedAction = suggested,
            MissingIdentities = missingIdentities
        };
    }

    private string? BuildPartialSuggestedAction(
        ChainPattern pattern, MatchResult match, List<string> missingIdentities)
    {
        if (match.MissingRequired.Count > 0)
            return SuggestAction(match.MissingRequired.FirstOrDefault());

        if (missingIdentities.Count > 0)
            return ChainProvabilityHelper.SuggestIdentityCapture(missingIdentities);

        if (ChainProvabilityHelper.HasProofTemplate(pattern)
            && ChainProvabilityHelper.CanProveWithFindings(pattern, match.PresentFindings, _identityStore, _pageUrl))
            return ChainProvabilityHelper.BuildChainProveAction(pattern.Id, exportEvidence: true);

        return SuggestAction(match.MissingOptional.FirstOrDefault());
    }

    private static double ComputePartialConfidence(MatchResult match, int presentRequired, int requiredTotal)
    {
        if (presentRequired == 0)
            return 0.1;

        var score = requiredTotal > 0
            ? (double)presentRequired / requiredTotal
            : 0.5;

        score -= match.MissingOptional.Count * 0.05;
        score -= match.PresentFindings.Count(f => f.Endpoint == null) * 0.05;
        score += match.PresentFindings.Count(f => f.Source == "autoscan") * 0.05;

        return Math.Clamp(score, 0.1, 0.95);
    }

    private static string BuildPartialNarrative(ChainPattern pattern, MatchResult match)
    {
        var present = string.Join(", ", match.PresentFindings.Select(f =>
        {
            var loc = f.Endpoint ?? "unknown endpoint";
            return $"{f.Category} ({f.Severity}) on {loc}";
        }));
        var missing = match.MissingRequired.Count > 0
            ? string.Join(", ", match.MissingRequired.Select(CategoryDisplayName))
            : "additional required evidence";

        return $"Partial match for \"{pattern.Name}\" ({pattern.ChainedSeverity} / {pattern.Impact}). " +
               $"Confirmed so far: {present}. " +
               $"If {missing} is also confirmed, the combined impact is: {DescribeImpact(pattern.Impact)}.";
    }

    /// <summary>
    /// Session hijack chains require cookies that are actually readable from document.cookie,
    /// not jar-only HttpOnly session cookies that passed the cookie audit.
    /// </summary>
    private static bool MissingHttpOnlyFindingIsChainable(ChainableFinding finding)
    {
        var text = $"{finding.Title} {finding.Detail} {finding.Evidence}".ToLowerInvariant();

        if (finding.Category.Equals("missing-httponly", StringComparison.OrdinalIgnoreCase))
        {
            if (text.Contains("document.cookie returned 0")
                || text.Contains("returned empty")
                || text.Contains("no cookies")
                || text.Contains("empty cookie"))
                return false;

            if (!HasNamedCookieInEvidence(finding.Evidence) && !HasNamedCookieInEvidence(finding.Detail))
            {
                if (finding.Source.Equals("execute-js", StringComparison.OrdinalIgnoreCase))
                    return false;
                if (text.Contains("cookie readable") && !HasNamedCookieInEvidence(text))
                    return false;
            }
        }

        if (text.Contains("session") && text.Contains("httponly"))
        {
            if (text.Contains("session=") || text.Contains("session cookie readable"))
                return true;
            if (text.Contains("passed") || text.Contains("present") || text.Contains("configured"))
                return false;
            if (finding.Source.Equals("shadow", StringComparison.OrdinalIgnoreCase)
                && text.Contains("missing httponly"))
                return text.Contains("document.cookie") && HasNamedCookieInEvidence(text);
        }

        return true;
    }

    private static bool HasNamedCookieInEvidence(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        foreach (var part in text.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = part.IndexOf('=');
            var name = eq >= 0 ? part[..eq].Trim() : part.Trim();
            if (name.Length > 0 && !name.Contains(' ', StringComparison.Ordinal))
                return true;
        }
        return Regex.IsMatch(text, @"\b[\w.-]+\s*=", RegexOptions.None, TimeSpan.FromSeconds(1));
    }

    private static string DescribeImpact(string impact) => impact switch
    {
        "account-takeover" => "account takeover",
        "data-breach" => "mass data breach",
        "session-hijack" => "session hijacking",
        "privilege-escalation" => "privilege escalation",
        "worm" => "a self-propagating worm",
        "rce" => "remote code execution",
        "defacement" => "site-wide defacement or cache poisoning",
        "phishing" => "targeted phishing",
        "dos" => "denial of service",
        _ => impact.Replace('-', ' ')
    };

    private static string CategoryDisplayName(string category) => category switch
    {
        "missing-httponly" => "missing HttpOnly cookie flag",
        "missing-csp" => "missing Content-Security-Policy",
        "missing-samesite" => "missing SameSite cookie attribute",
        "missing-rate-limit" => "missing rate limiting",
        "cors-misconfig" => "CORS misconfiguration",
        "info-leak" => "information leak",
        "source-maps" => "exposed source maps",
        "open-redirect" => "open redirect",
        "path-traversal" => "path traversal",
        "mass-assignment" => "mass assignment",
        "session-fixation" => "session fixation",
        "timing-oracle" => "timing oracle",
        "credential-exposure" => "credential exposure",
        "sqli-indicator" => "SQL injection indicator",
        "header-injection" => "header injection",
        "weak-auth" => "weak authentication",
        "auth-bypass-pivot" => "authenticated pivot",
        "jwt-acceptance" => "JWT acceptance weakness",
        "rest-scaffold-unauth" => "unauthenticated REST leak",
        "path-filter-bypass" => "path-filter bypass",
        "shadow-api" => "shadow API (undocumented route)",
        "zombie-api" => "zombie / deprecated API",
        "auth-gated-api" => "session-only API endpoint",
        "clickjack-vulnerable" => "clickjacking exposure",
        "missing-xframe" => "missing frame protection",
        "weak-headers" => "weak security headers",
        _ => category.Replace('-', ' ')
    };

    /// <summary>
    /// Compute confidence score for a matched chain (0.0 – 1.0).
    /// </summary>
    private static double ComputeConfidence(ChainPattern pattern, MatchResult match)
    {
        var requiredLinks = pattern.Links.Count(l => !l.Optional);
        var score = requiredLinks <= 1 ? 0.65 : 1.0;

        // Deduct for missing optional links
        score -= match.MissingOptional.Count * 0.1;

        // Deduct if findings don't have endpoints (less concrete)
        var withoutEndpoint = match.PresentFindings.Count(f => f.Endpoint == null);
        score -= withoutEndpoint * 0.05;

        // Deduct for low-severity individual findings (less certain)
        var lowFindings = match.PresentFindings.Count(f => f.Severity == "low" || f.Severity == "info");
        score -= lowFindings * 0.05;

        // Boost for findings that come from active scanning (more reliable than passive)
        var activeFindings = match.PresentFindings.Count(f => f.Source == "autoscan");
        score += activeFindings * 0.05;

        // Boost when endpoint patterns explicitly matched (relevant context)
        var patternedLinks = match.MatchedLinks.Count(m => !string.IsNullOrWhiteSpace(m.Link.EndpointPattern));
        score += patternedLinks * 0.1;

        // Single-link chains without endpoint context stay conservative
        if (requiredLinks <= 1 && patternedLinks == 0)
            score = Math.Min(score, 0.55);

        // Info/low-only evidence must not look like a confirmed critical chain.
        if (match.PresentFindings.All(f => f.Severity is "info" or "low"))
            score = Math.Min(score, 0.4);

        // Login CSRF is a weak enabler for worm / takeover narratives.
        if (match.PresentFindings.Any(f =>
                f.Category.Equals("csrf", StringComparison.OrdinalIgnoreCase)
                && LooksLikeLoginEndpoint(f.Endpoint)))
            score = Math.Min(score, 0.45);

        return Math.Clamp(score, 0.1, 1.0);
    }

    private static bool LooksLikeLoginEndpoint(string? endpoint) =>
        !string.IsNullOrEmpty(endpoint)
        && Regex.IsMatch(endpoint, @"(?i)/(login|signin|sign-in|logon|auth|brute)(/|$|\?)",
            RegexOptions.None, TimeSpan.FromSeconds(1));

    /// <summary>
    /// Generate a human-readable narrative for an attack chain.
    /// </summary>
    private static string BuildTitleQuotedNarrative(ChainPattern pattern, MatchResult match)
    {
        var quoted = string.Join(" + ", match.PresentFindings.Select(f =>
        {
            var loc = f.Endpoint != null ? $" on {f.Endpoint}" : "";
            return $"\"{f.Title}\" ({f.Category}{loc})";
        }));

        return $"\"{pattern.Name}\" ({pattern.ChainedSeverity} / {pattern.Impact}): {quoted}. " +
               $"If these findings combine as intended, impact is {DescribeImpact(pattern.Impact)}.";
    }

    /// <summary>
    /// Suggest a Trowser API call that could confirm a missing finding category.
    /// </summary>
    private static string? SuggestAction(string? missingCategory)
    {
        return missingCategory switch
        {
            "missing-httponly" => "POST /api/execute-js {\"script\": \"document.cookie\"} — if non-empty, HttpOnly is missing",
            "xss" => "POST /api/security/xss — scan current page for DOM XSS patterns",
            "csrf" => "POST /api/security/csrf — check state-changing endpoints for CSRF protection",
            "missing-csp" => "POST /api/security/headers — check for Content-Security-Policy header",
            "http-downgrade-proven" => "POST /api/fetch with serverSide: true — compare https:// vs http:// document response on the same host",
            "missing-secure-flag" => "POST /api/security/cookies — check Secure on session cookies",
            "cors-misconfig" => "POST /api/security/cors with includeAttackSurfaceUrls: true — multi-endpoint CORS sweep",
            "verbose-error" => "POST /api/security/forced-error-scan — malformed JSON stack-trace probe",
            "info-leak" => "POST /api/security/forced-error-scan — verbose error disclosure",
            "auth-bypass-header-spoof" => "POST /api/security/trusted-header-bypass — proxy header spoof probe",
            "default-credentials" => "POST /api/security/default-credential-canary — built-in login wordlist",
            "missing-samesite" => "POST /api/security/cookies — check SameSite attribute on cookies",
            "sqli" => "POST /api/security/auto-scan {\"includeSqli\": true} — test for SQL injection",
            "sqli-indicator" => "POST /api/security/auto-scan {\"includeSqli\": true} — confirm SQL injection on error-reflecting endpoint",
            "idor" => "POST /api/security/auto-scan {\"includeIdor\": true} — test for IDOR vulnerabilities",
            "open-redirect" => "POST /api/security/open-redirect-scan — probe redirect/url/next parameters",
            "ssrf" => "POST /api/security/ssrf-scan — inject internal/metadata URLs into URL-like parameters",
            "weak-auth" => "POST /api/authz/diff — compare authenticated vs unauthenticated access on discovered endpoints",
            "auth-bypass-pivot" => "POST /api/security/auth-bypass-pivot — retest protected endpoints with captured token",
            "jwt-acceptance" => "POST /api/security/jwt-acceptance-sweep — test alg:none JWT and missing auth on protected endpoints",
            "jwt-alg-variant" => "POST /api/security/jwt-acceptance-sweep with includeAlgVariants — test case/whitespace alg:none variants",
            "jwt-header-abuse" => "POST /api/security/jwt-header-abuse — test jku/x5u/kid JWT header abuse",
            "cookie-prefix-bypass" => "POST /api/security/cookie-prefix-bypass — test __Host-/__Secure- prefix normalization bypass",
            "weak-tls" => "POST /api/security/tls-introspection — TLS version and certificate audit",
            "expiring-cert" => "POST /api/security/tls-introspection — certificate expiry check",
            "weak-saml-signature" => "POST /api/security/saml-decode then saml-replay with removeSignature",
            "rest-scaffold-unauth" => "POST /api/security/rest-scaffold — probe common REST paths without authentication",
            "path-filter-bypass" => "POST /api/security/path-filter-bypass — NUL/double-encoding path-filter bypass probes",
            "path-traversal" => "POST /api/security/path-traversal — test file/path parameters for directory traversal",
            "mass-assignment" => "POST /api/security/mass-assignment-scan — probe for injectable privileged fields",
            "session-fixation" => "POST /api/security/session-fixation-scan — compare session cookie before/after login",
            "password-reset-weak" => "POST /api/security/password-reset-weak-scan with confirmDestructive: true — security-question reset",
            "account-enumeration" => "POST /api/security/account-enumeration-scan — REST leak + login differential + register probe",
            "logout-invalidation" => "POST /api/security/logout-invalidation-probe — replay protected URL after logout",
            "oauth-flow-weakness" => "POST /api/security/oauth-flow-test with safetyMode: active — PKCE/state/redirect_uri tampering",
            "header-injection" => "POST /api/fuzz with header-injection payload set on injectable parameters",
            "credential-exposure" => "POST /api/security/secrets-harvest — scan JS, storage, network, and page text for leaked credentials",
            "content-type-confusion" => "POST /api/security/parser-probe — content-type matrix on JSON endpoints",
            "deserialization-suspected" => "POST /api/security/parser-probe — alternate body shapes and content-types",
            "rce-deserialization" => "POST /api/security/deserialization-scan — node-serialize timing + gadget probes",
            "deserialization-dos" => "POST /api/security/deserialization-scan — YAML billion-laughs DoS probe",
            "file-upload-oversize" or "file-upload-wrong-type" or "file-upload-polyglot" =>
                "POST /api/security/file-upload-scan — oversize, wrong-type, and polyglot multipart probes",
            "xxe-upload" => "POST /api/security/file-upload-scan {\"includeXxe\": true} or POST /api/security/ssrf-scan {\"includeUploadXxe\": true}",
            "parser-differential" => "POST /api/security/parser-probe — differential response analysis on POST/PUT/PATCH",
            "command-injection" => "POST /api/security/cmd-canary — error-based shell canaries on injectable params",
            "ssti-confirmed" => "POST /api/security/ssti-scan — template arithmetic/error canaries",
            "ssti-polyglot" => "POST /api/security/ssti-polyglot-scan — fast GET polyglot SSTI probe",
            "ssti-stored" => "POST /api/security/ssti-stored-scan — profile POST then GET readback",
            "prototype-pollution" => "POST /api/security/prototype-pollution-scan — __proto__ POST + GET verify",
            "csti-confirmed" => "POST /api/security/csti-scan — client-side template DOM evaluation probes",
            "rce-indicator" => "POST /api/security/cmd-canary {\"includeCallback\": true} — OOB/timing RCE indicators",
            "missing-rate-limit" => "POST /api/load-test — send concurrent requests to check for rate limiting",
            "source-maps" => "POST /api/security/source-maps — check for exposed source maps",
            "manifest-leak" => "POST /api/security/supply-chain-scan — fetch and parse exposed dependency manifests",
            "ci-cd-exposure" => "POST /api/security/supply-chain-scan — probe exposed CI/CD configs (.github/workflows, Jenkinsfile, etc.)",
            "vulnerable-dependency-declared" => "POST /api/security/supply-chain-scan — OSV.dev lookup on declared dependencies",
            "missing-sri" => "POST /api/security/firewall-test {\"tests\":[\"sri\"]} — third-party scripts without integrity",
            "vulnerable-component" => "POST /api/security/supply-chain-scan {\"includeCveReachability\": true, \"safetyMode\": \"active\"}",
            "timing-oracle" => "Compare response timing on login endpoint with valid vs invalid usernames",
            "shadow-api" => "POST /api/security/api-inventory or attack-surface with includeApiInventory — compare spec vs traffic",
            "zombie-api" => "POST /api/security/api-inventory — review versionClusters and zombie-candidate paths",
            "auth-gated-api" => "POST /api/security/api-inventory with includeAuthDeltaProbes and safetyMode: active — session-only endpoints",
            "clickjack-vulnerable" => "POST /api/security/clickjack-test with safetyMode: active — active iframe framing proof",
            "missing-xframe" => "POST /api/security/clickjack-test — passive + optional active framing test",
            "fail-open-unauthenticated" or "fail-open-invalid-token" =>
                "POST /api/security/fail-open-scan with safetyMode: active — strip cookies / invalid JWT on sensitive endpoints",
            "missing-parameter-crash" or "missing-parameter-error" or "missing-parameter-npe-hint" =>
                "POST /api/security/missing-parameter-scan with safetyMode: active — omit JSON fields from traffic-derived POSTs",
            _ => null
        };
    }

    private static int SeverityRank(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0
    };

    // ── Internal types ──

    private sealed class MatchResult
    {
        public List<ChainableFinding> PresentFindings { get; init; } = [];
        public List<(ChainLink Link, ChainableFinding Finding)> MatchedLinks { get; init; } = [];
        public List<string> MissingRequired { get; init; } = [];
        public List<string> MissingOptional { get; init; } = [];
        public bool IsFullMatch => MissingRequired.Count == 0 && PresentFindings.Count > 0;
    }
}

/// <summary>
/// Full result from chain analysis.
/// </summary>
public sealed class ChainAnalysisResult
{
    public int FindingsAnalyzed { get; init; }
    public int ChainsDiscovered { get; init; }
    public List<CandidateChain> Chains { get; init; } = [];
    public List<PartialChain> PartialChains { get; init; } = [];
}
