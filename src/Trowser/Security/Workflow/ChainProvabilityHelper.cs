using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Security.ChainEngine;

namespace Trowser.Security.Workflow;

/// <summary>
/// Resolves proof templates, required identities, and provability for chain patterns.
/// </summary>
public static class ChainProvabilityHelper
{
    private static readonly Regex IdentityNameRegex = new(
        @"""type""\s*:\s*""identity""[\s\S]*?""name""\s*:\s*""([^""]+)""",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static string? ResolveTemplateId(ChainPattern pattern)
    {
        if (!string.IsNullOrEmpty(pattern.ProofTemplateId) && ProofTemplateCatalog.HasTemplate(pattern.ProofTemplateId))
            return pattern.ProofTemplateId;
        if (ProofTemplateCatalog.HasTemplate(pattern.Id))
            return pattern.Id;
        return null;
    }

    public static bool HasProofTemplate(ChainPattern pattern) => ResolveTemplateId(pattern) != null;

    public static List<string> ExtractRequiredIdentities(string templateId)
    {
        var template = ProofTemplateCatalog.GetTemplate(templateId);
        if (template == null) return [];

        var raw = template.Value.GetRawText();
        var names = new List<string>();
        foreach (Match m in IdentityNameRegex.Matches(raw))
        {
            var name = m.Groups[1].Value;
            if (!string.IsNullOrWhiteSpace(name) && IdentityStore.IsValidName(name) && !names.Contains(name, StringComparer.OrdinalIgnoreCase))
                names.Add(name);
        }
        return names;
    }

    public static List<string> GetMissingIdentities(ChainPattern pattern, IdentityStore? identityStore)
    {
        var templateId = ResolveTemplateId(pattern);
        if (templateId == null || identityStore == null) return [];

        return ExtractRequiredIdentities(templateId)
            .Where(n => identityStore.Load(n) == null)
            .ToList();
    }

    public static bool IsProvable(ChainPattern pattern, IdentityStore? identityStore)
    {
        if (ResolveTemplateId(pattern) == null) return false;
        return GetMissingIdentities(pattern, identityStore).Count == 0;
    }

    /// <summary>
    /// True only when identities are present, template exists, and all static placeholders resolve from matched findings.
    /// </summary>
    public static bool CanProveWithFindings(
        ChainPattern pattern,
        IReadOnlyList<ChainableFinding> findings,
        IdentityStore? identityStore,
        string? currentUrl = null)
    {
        if (!IsProvable(pattern, identityStore)) return false;

        var templateId = ResolveTemplateId(pattern);
        if (templateId == null) return false;

        var template = ProofTemplateCatalog.GetTemplate(templateId);
        if (template == null) return false;

        var substitutions = ProofTemplateCatalog.BuildSubstitutionVars(findings, currentUrl);
        var unresolved = WorkflowVarSubstitution.FindUnresolvedStaticPlaceholders(
            template.Value.GetRawText(), substitutions);

        return unresolved.Count == 0;
    }

    /// <summary>Returns unresolved static template placeholders for UI/debug when provable is false.</summary>
    public static List<string> GetUnresolvedProofPlaceholders(
        ChainPattern pattern,
        IReadOnlyList<ChainableFinding> findings,
        string? currentUrl = null)
    {
        var templateId = ResolveTemplateId(pattern);
        if (templateId == null) return ["no-proof-template"];

        var template = ProofTemplateCatalog.GetTemplate(templateId);
        if (template == null) return ["missing-template"];

        var substitutions = ProofTemplateCatalog.BuildSubstitutionVars(findings, currentUrl);
        return WorkflowVarSubstitution.FindUnresolvedStaticPlaceholders(
            template.Value.GetRawText(), substitutions);
    }

    public static string BuildChainProveAction(string patternId, bool exportEvidence = true)
    {
        var export = exportEvidence ? ", \"exportEvidence\": true" : "";
        return $"POST /api/security/chain-prove {{ \"patternId\": \"{patternId}\"{export}, \"safetyMode\": \"active\" }}";
    }

    public static string BuildEvidenceRerunAction(string bundlePath, string expect = "NOT_VERIFIED") =>
        $"POST /api/repro/verify {{ \"bundlePath\": \"{bundlePath}\", \"expect\": \"{expect}\", \"safetyMode\": \"active\" }}";

    public static string? SuggestIdentityCapture(IEnumerable<string> missingIdentities)
    {
        var list = missingIdentities.ToList();
        if (list.Count == 0) return null;
        if (list.Count == 1)
        {
            var name = list[0];
            return $"Capture identity '{name}': POST /api/identity/capture {{ \"name\": \"{name}\" }} after logging in, " +
                   $"or POST /api/identity/handoff {{ \"name\": \"{name}\", \"timeoutMs\": 300000 }} for SSO/MFA handoff";
        }

        var captures = string.Join("; ", list.Select(n =>
            $"POST /api/identity/capture {{ \"name\": \"{n}\" }}"));
        return $"Capture missing identities ({string.Join(", ", list)}): {captures}. " +
               "Or use POST /api/identity/handoff per role after human login.";
    }
}
