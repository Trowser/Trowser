using Trowser.Automation;
using Trowser.XssAudit;

namespace Trowser.Security;

/// <summary>
/// Deterministic cross-tool correlation for security findings (CSRF, secrets harvest, XSS).
/// </summary>
public static class SecurityFindingCorrelator
{
    public sealed class CorrelationFinding
    {
        public string Id { get; init; } = "";
        public string Severity { get; init; } = "medium";
        public string Title { get; init; } = "";
        public string Description { get; init; } = "";
        public string[] RelatedTools { get; init; } = [];
        public string? FieldName { get; init; }
        public string? Url { get; init; }
    }

    public static List<CorrelationFinding> Correlate(
        CsrfResult csrf,
        SecretsHarvestPipeline.HarvestResult? harvest = null,
        XssResult? xss = null,
        string? pageOrigin = null)
    {
        var findings = new List<CorrelationFinding>();
        findings.AddRange(CorrelateMissedCsrfTokens(csrf));
        if (harvest != null)
            findings.AddRange(CorrelateCsrfWithSecretsHarvest(csrf, harvest));
        if (xss != null)
            findings.AddRange(CorrelateCsrfWithXss(csrf, xss, pageOrigin));
        findings.AddRange(CorrelateJsonApiWithCsrf(csrf));
        return findings;
    }

    /// <summary>
    /// Flags form fields that look like CSRF tokens but were not recognized by the scanner output.
    /// </summary>
    public static List<CorrelationFinding> CorrelateMissedCsrfTokens(CsrfResult csrf)
    {
        var findings = new List<CorrelationFinding>();

        foreach (var scenario in csrf.Scenarios.Where(s =>
                     s.TokenLocation.Contains("none observed", StringComparison.OrdinalIgnoreCase)))
        {
            var missed = CsrfTokenHeuristics.ExtractMissedTokenFieldsFromSummary(scenario.FormFields);
            foreach (var field in missed)
            {
                findings.Add(new CorrelationFinding
                {
                    Id = "csrf-unrecognized-token-field",
                    Severity = "high",
                    Title = "CSRF token field not recognized by scanner",
                    Description =
                        $"Form field \"{field}\" looks like an anti-CSRF token (name/value heuristic) but the CSRF scanner reported " +
                        $"\"{scenario.TokenLocation}\". Expand token recognition or verify the field manually.",
                    RelatedTools = ["csrf"],
                    FieldName = field,
                    Url = scenario.Url,
                });
            }
        }

        return findings;
    }

    public static List<CorrelationFinding> CorrelateCsrfWithSecretsHarvest(
        CsrfResult csrf,
        SecretsHarvestPipeline.HarvestResult harvest)
    {
        var findings = new List<CorrelationFinding>();
        var noTokenScenarios = csrf.Scenarios.Where(s =>
            s.TokenLocation.Contains("none observed", StringComparison.OrdinalIgnoreCase)).ToList();
        if (noTokenScenarios.Count == 0)
            return findings;

        var tokenLikeHarvest = harvest.Findings.Where(f =>
            f.Category is "md5-hex-like" or "sha1-hex-like" or "sha256-hex-like" or "secret-assignment"
            || (f.Description.Contains("token", StringComparison.OrdinalIgnoreCase)
                && !f.Description.Contains("JWT", StringComparison.OrdinalIgnoreCase))).ToList();

        foreach (var scenario in noTokenScenarios)
        {
            var missedFields = CsrfTokenHeuristics.ExtractMissedTokenFieldsFromSummary(scenario.FormFields);
            foreach (var field in missedFields)
            {
                var harvestHit = tokenLikeHarvest.FirstOrDefault(h =>
                    h.Snippet?.Contains(field, StringComparison.OrdinalIgnoreCase) == true
                    || h.Location.Contains(field, StringComparison.OrdinalIgnoreCase)
                    || h.Description.Contains(field, StringComparison.OrdinalIgnoreCase));

                if (harvestHit == null && tokenLikeHarvest.Count > 0)
                {
                    harvestHit = tokenLikeHarvest[0];
                }

                if (harvestHit == null)
                    continue;

                findings.Add(new CorrelationFinding
                {
                    Id = "csrf-secrets-harvest-token-mismatch",
                    Severity = "high",
                    Title = "Secrets harvest found token-like values where CSRF scanner reported none",
                    Description =
                        $"CSRF scanner reported \"{scenario.TokenLocation}\" for {scenario.Method} {scenario.Path}, " +
                        $"but secrets harvest found {harvestHit.Category} ({harvestHit.Description}). " +
                        $"Review field \"{field}\" — it may be an unrecognized CSRF token.",
                    RelatedTools = ["csrf", "secrets-harvest"],
                    FieldName = field,
                    Url = scenario.Url,
                });
            }
        }

        if (noTokenScenarios.Count > 0 && tokenLikeHarvest.Count >= 3 && findings.Count == 0)
        {
            findings.Add(new CorrelationFinding
            {
                Id = "csrf-secrets-harvest-token-mismatch",
                Severity = "medium",
                Title = "Multiple token-like secrets on origin with CSRF gaps",
                Description =
                    $"CSRF scanner flagged {noTokenScenarios.Count} scenario(s) with no observed token, while secrets harvest " +
                    $"found {tokenLikeHarvest.Count} token-like value(s) on the same origin. Manual correlation recommended.",
                RelatedTools = ["csrf", "secrets-harvest"],
                Url = harvest.Url,
            });
        }

        return findings;
    }

    public static List<CorrelationFinding> CorrelateCsrfWithXss(
        CsrfResult csrf,
        XssResult xss,
        string? pageOrigin = null)
    {
        var findings = new List<CorrelationFinding>();
        if (xss.Findings.Count == 0)
            return findings;

        // Only correlate confirmed/high-signal XSS sinks — not inline-handler / javascript-url
        // hygiene or heuristic co-occurrence (dom-xss-flow) without exploit confirmation.
        var xssSurface = xss.Findings.Where(f =>
            f.Severity >= XssSeverity.High
            && f.Category is not "dom-xss-flow" and not "dangerous-sink"
                and not "inline-handler" and not "javascript-url").ToList();
        if (xssSurface.Count == 0)
            return findings;

        var csrfProtected = csrf.Scenarios.Any(s =>
            !s.TokenLocation.Contains("none observed", StringComparison.OrdinalIgnoreCase)
            && !s.TokenLocation.StartsWith("implicit:", StringComparison.OrdinalIgnoreCase));

        var exposedTokens = csrf.Scenarios.Where(s =>
            !s.TokenLocation.Contains("none observed", StringComparison.OrdinalIgnoreCase)
            || CsrfTokenHeuristics.ExtractMissedTokenFieldsFromSummary(s.FormFields).Count > 0).ToList();

        if (!csrfProtected && exposedTokens.Count == 0)
            return findings;

        var origin = pageOrigin ?? xss.Url;
        findings.Add(new CorrelationFinding
        {
            Id = "csrf-xss-token-theft-chain",
            // Medium until active XSS exploit is confirmed — passive DOM hygiene alone is not HIGH.
            Severity = "medium",
            Title = "XSS surface on CSRF-protected origin — token theft may bypass CSRF (unconfirmed)",
            Description =
                $"DOM XSS audit found {xssSurface.Count} higher-signal surface finding(s) " +
                $"(e.g. {xssSurface[0].Category}) on {origin}, while CSRF tokens are present or exposed in forms. " +
                "If XSS is exploitable, stolen CSRF tokens can bypass CSRF protection for authenticated actions. " +
                "Confirm with active xss-scan / trace-input before treating as a high-severity chain.",
            RelatedTools = ["csrf", "xss"],
            Url = origin,
        });

        return findings;
    }

    public static List<CorrelationFinding> CorrelateJsonApiWithCsrf(CsrfResult csrf)
    {
        var findings = new List<CorrelationFinding>();
        if (csrf.JsonApiHints.Count == 0)
            return findings;

        var formUrls = csrf.Scenarios
            .Where(s => s.TestType.StartsWith("get-form", StringComparison.OrdinalIgnoreCase))
            .Select(s => s.Url)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var undiscovered = csrf.JsonApiHints.Where(h =>
            !formUrls.Any(f => h.Url.StartsWith(f, StringComparison.OrdinalIgnoreCase)
                               || f.StartsWith(h.Url, StringComparison.OrdinalIgnoreCase))).ToList();

        if (undiscovered.Count > 0)
        {
            var csrfPresent = csrf.Scenarios.Any(s =>
                !s.TokenLocation.Contains("none observed", StringComparison.OrdinalIgnoreCase));

            findings.Add(new CorrelationFinding
            {
                Id = "csrf-json-api-alternate-path",
                Severity = csrfPresent ? "high" : "medium",
                Title = "JavaScript/source reveals JSON API paths not covered by form CSRF analysis",
                Description =
                    $"Found {undiscovered.Count} JSON API hint(s) from {undiscovered[0].Source} " +
                    $"(e.g. {undiscovered[0].Url}) that may accept POST application/json as an alternate to HTML forms. " +
                    (csrfPresent
                        ? "CSRF tokens protect the visible form but a separate JSON endpoint may bypass form-level checks."
                        : "Probe these paths — they may expose undocumented mutation APIs."),
                RelatedTools = ["csrf", "json-api-probe"],
                Url = undiscovered[0].Url,
            });
        }

        if (csrf.Scenarios.Any(s =>
                s.Vulnerable && s.TestType.StartsWith("json-api", StringComparison.OrdinalIgnoreCase)))
        {
            findings.Add(new CorrelationFinding
            {
                Id = "csrf-json-api-token-bypass",
                Severity = "critical",
                Title = "JSON API accepts requests without CSRF token",
                Description =
                    "A POST application/json probe succeeded without the CSRF token while the HTML form uses token protection. " +
                    "Attackers can bypass CSRF defenses via the JSON API path.",
                RelatedTools = ["csrf", "json-api-probe"],
            });
        }

        return findings;
    }

    /// <summary>
    /// Runs lightweight companion scans and returns cross-tool correlation findings for a CSRF result.
    /// </summary>
    public static async Task<List<CorrelationFinding>> CorrelateForCsrfScanAsync(
        AutomationContext ctx,
        CsrfResult csrf,
        bool includeSecretsHarvest = true,
        bool includeXss = true,
        int timeoutMs = 10000)
    {
        SecretsHarvestPipeline.HarvestResult? harvest = null;
        XssResult? xss = null;
        string? origin = null;

        var pageUrl = await ctx.GetCurrentUrl();
        if (Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri))
            origin = pageUri.GetLeftPart(UriPartial.Authority);

        if (includeSecretsHarvest)
        {
            harvest = await SecretsHarvestPipeline.RunAsync(ctx, new SecretsHarvestPipeline.HarvestOptions
            {
                IncludeJsBundles = false,
                IncludeSourceMaps = false,
                IncludeNetworkResponses = true,
                IncludePageText = true,
                IncludeCookiesAndStorage = false,
                MaxJsScripts = 0,
                MaxNetworkResponses = 50,
                TimeoutMs = timeoutMs,
            });
        }

        if (includeXss)
            xss = await ctx.CheckXss();

        return Correlate(csrf, harvest, xss, origin);
    }
}
