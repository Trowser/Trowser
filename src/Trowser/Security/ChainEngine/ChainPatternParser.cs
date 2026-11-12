using System.Text.Json;

namespace Trowser.Security.ChainEngine;

/// <summary>
/// Parses rich chain pattern definitions from API/MCP JSON payloads.
/// </summary>
public static class ChainPatternParser
{
    public static List<ChainLink> ParseLinks(JsonElement linksEl)
    {
        var links = new List<ChainLink>();
        foreach (var el in linksEl.EnumerateArray())
        {
            if (el.ValueKind != JsonValueKind.Object) continue;

            var category = el.TryGetProperty("requiredCategory", out var rc) ? rc.GetString()
                : el.TryGetProperty("category", out var c) ? c.GetString()
                : null;
            if (string.IsNullOrWhiteSpace(category)) continue;

            links.Add(new ChainLink
            {
                RequiredCategory = category.Trim(),
                Role = el.TryGetProperty("role", out var role) ? role.GetString() ?? "enabler" : "enabler",
                Optional = el.TryGetProperty("optional", out var opt) && opt.ValueKind == JsonValueKind.True,
                Constraint = el.TryGetProperty("constraint", out var con) ? con.GetString() : null,
                EndpointPattern = el.TryGetProperty("endpointPattern", out var ep) ? ep.GetString()
                    : el.TryGetProperty("endpointConstraint", out var ec) ? ec.GetString() : null
            });
        }
        return links;
    }

    public static ChainPattern? TryBuildFromAddPayload(JsonElement root, out string? error)
    {
        error = null;
        var id = root.TryGetProperty("id", out var idEl) ? idEl.GetString() : null;
        var name = root.TryGetProperty("name", out var nameEl) ? nameEl.GetString() : null;
        if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(name))
        {
            error = "Required: id, name.";
            return null;
        }

        List<ChainLink> links;
        if (root.TryGetProperty("links", out var linksEl) && linksEl.ValueKind == JsonValueKind.Array)
        {
            links = ParseLinks(linksEl);
            if (links.Count < 2)
            {
                error = "links array requires at least 2 entries with requiredCategory.";
                return null;
            }
        }
        else if (root.TryGetProperty("categories", out var catsEl) && catsEl.ValueKind == JsonValueKind.Array)
        {
            links = catsEl.EnumerateArray()
                .Where(c => c.ValueKind == JsonValueKind.String)
                .Select(c => new ChainLink { RequiredCategory = c.GetString()!.Trim() })
                .ToList();
            if (links.Count < 2)
            {
                error = "Required: links (min 2) or categories (min 2).";
                return null;
            }
        }
        else
        {
            error = "Required: links[] with role/optional/constraint, or legacy categories[] (min 2).";
            return null;
        }

        foreach (var link in links)
        {
            if (!FindingNormalizer.IsKnownCategory(link.RequiredCategory))
            {
                error = $"Unknown category '{link.RequiredCategory}'. Use GET /api/security/chain-findings knownCategories.";
                return null;
            }
        }

        var proofTemplateId = root.TryGetProperty("proofTemplateId", out var ptEl) ? ptEl.GetString() : null;
        if (!string.IsNullOrWhiteSpace(proofTemplateId) &&
            !Workflow.ProofTemplateCatalog.HasTemplate(proofTemplateId!))
        {
            error = $"Unknown proofTemplateId '{proofTemplateId}'. Template must exist in ProofTemplateCatalog.";
            return null;
        }

        return new ChainPattern
        {
            Id = id.Trim(),
            Name = name.Trim(),
            Description = root.TryGetProperty("description", out var desc) ? desc.GetString() ?? "" : "",
            ChainedSeverity = root.TryGetProperty("severity", out var sev) ? sev.GetString() ?? "high"
                : root.TryGetProperty("chainedSeverity", out var cs) ? cs.GetString() ?? "high" : "high",
            Impact = root.TryGetProperty("impact", out var imp) ? imp.GetString() ?? "" : "",
            Links = links,
            ProofTemplateId = string.IsNullOrWhiteSpace(proofTemplateId) ? null : proofTemplateId.Trim()
        };
    }
}
