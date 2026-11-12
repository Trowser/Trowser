using System.Text;
using System.Text.Json;

namespace Trowser.Seo;

/// <summary>SEO signals extracted from the live DOM (meta, link, JSON-LD).</summary>
public sealed class SeoAuditResult
{
    public string Url { get; init; } = "";
    public string Title { get; init; } = "";
    public string Description { get; init; } = "";
    public string Robots { get; init; } = "";
    public string CanonicalUrl { get; init; } = "";
    public string Charset { get; init; } = "";
    public string Viewport { get; init; } = "";
    public string Language { get; init; } = "";
    public int H1Count { get; init; }
    public Dictionary<string, string> OgTags { get; init; } = new();
    public Dictionary<string, string> TwitterTags { get; init; } = new();
    public List<SeoHreflangLink> Hreflang { get; init; } = new();
    public List<SeoJsonLdBlock> StructuredData { get; init; } = new();
    /// <summary>Set when the extractor script throws before producing a full result.</summary>
    public string? Error { get; init; }

    /// <summary>Blocking issues (failed extractor, missing title, non-empty JSON-LD that does not parse).</summary>
    public IReadOnlyList<string> GetCriticalIssues()
    {
        if (!string.IsNullOrEmpty(Error))
            return new[] { $"Extractor error: {Error}" };

        var list = new List<string>();
        if (string.IsNullOrWhiteSpace(Title))
            list.Add("Missing or empty document title.");
        foreach (var b in StructuredData)
        {
            if (b.Valid) continue;
            if (string.Equals(b.Error, "empty block", StringComparison.Ordinal))
                continue;
            list.Add(string.IsNullOrEmpty(b.Error)
                ? "Invalid JSON-LD block."
                : $"Invalid JSON-LD: {b.Error}");
        }

        return list;
    }

    /// <summary>Heuristic hints (non-blocking): meta description, OG/Twitter, H1 pattern, etc.</summary>
    public IReadOnlyList<string> GetHints()
    {
        if (!string.IsNullOrEmpty(Error))
            return Array.Empty<string>();

        var list = new List<string>();
        if (string.IsNullOrWhiteSpace(Description))
            list.Add("Missing meta description (meta[name=description]).");
        if (H1Count == 0)
            list.Add("No H1 heading in the document.");
        else if (H1Count > 1)
            list.Add($"Multiple H1 headings ({H1Count}); most sites use a single H1 per page.");
        if (string.IsNullOrWhiteSpace(CanonicalUrl))
            list.Add("No canonical link (link[rel=canonical]).");
        if (string.IsNullOrWhiteSpace(Language))
            list.Add("Missing html[lang] attribute.");
        if (OgTags.Count == 0)
            list.Add("No Open Graph meta tags (property=\"og:*\").");
        if (TwitterTags.Count == 0)
            list.Add("No Twitter Card meta tags (name=\"twitter:*\").");
        if (StructuredData.Count == 0)
            list.Add("No JSON-LD blocks (script[type=application/ld+json]).");
        else if (StructuredData.Any(b => !b.Valid && !string.Equals(b.Error, "empty block", StringComparison.Ordinal)))
            list.Add("One or more JSON-LD blocks failed to parse.");
        else if (StructuredData.Any(b => !b.Valid))
            list.Add("One or more JSON-LD script tags are empty.");

        return list;
    }

    /// <summary>Critical issues plus heuristic hints (full checklist).</summary>
    public IReadOnlyList<string> GetSuggestions() =>
        GetCriticalIssues().Concat(GetHints()).ToList();

    public string Format()
    {
        var sb = new StringBuilder();
        if (!string.IsNullOrEmpty(Error))
        {
            sb.AppendLine($"SEO audit error: {Error}");
            return sb.ToString();
        }

        sb.AppendLine($"URL: {Url}");
        sb.AppendLine($"Title: {Title}");
        sb.AppendLine($"Meta description: {(string.IsNullOrEmpty(Description) ? "(none)" : Description)}");
        sb.AppendLine($"Canonical: {(string.IsNullOrEmpty(CanonicalUrl) ? "(none)" : CanonicalUrl)}");
        sb.AppendLine($"Robots: {(string.IsNullOrEmpty(Robots) ? "(none)" : Robots)}");
        sb.AppendLine($"Language (html lang): {(string.IsNullOrEmpty(Language) ? "(none)" : Language)}");
        sb.AppendLine($"Charset: {(string.IsNullOrEmpty(Charset) ? "(none)" : Charset)}");
        sb.AppendLine($"Viewport meta: {(string.IsNullOrEmpty(Viewport) ? "(none)" : Viewport)}");
        sb.AppendLine($"H1 count: {H1Count}");

        sb.AppendLine();
        sb.AppendLine("Open Graph:");
        if (OgTags.Count == 0) sb.AppendLine("  (none)");
        else foreach (var kv in OgTags.OrderBy(k => k.Key, StringComparer.Ordinal)) sb.AppendLine($"  {kv.Key}: {kv.Value}");

        sb.AppendLine();
        sb.AppendLine("Twitter / X:");
        if (TwitterTags.Count == 0) sb.AppendLine("  (none)");
        else foreach (var kv in TwitterTags.OrderBy(k => k.Key, StringComparer.Ordinal)) sb.AppendLine($"  {kv.Key}: {kv.Value}");

        sb.AppendLine();
        sb.AppendLine("hreflang:");
        if (Hreflang.Count == 0) sb.AppendLine("  (none)");
        else foreach (var h in Hreflang) sb.AppendLine($"  {h.Hreflang}: {h.Href}");

        sb.AppendLine();
        sb.AppendLine($"JSON-LD blocks: {StructuredData.Count}");
        for (var i = 0; i < StructuredData.Count; i++)
        {
            var b = StructuredData[i];
            if (b.Valid)
            {
                var preview = b.Data.ValueKind != JsonValueKind.Undefined
                    ? b.Data.ToString().Length > 400 ? b.Data.ToString()[..400] + "…" : b.Data.ToString()
                    : "";
                sb.AppendLine($"  [{i}] valid — {preview}");
            }
            else
                sb.AppendLine($"  [{i}] invalid — {b.Error ?? "parse error"}{(string.IsNullOrEmpty(b.Raw) ? "" : $" (raw length {b.Raw.Length})")}");
        }

        var critical = GetCriticalIssues();
        if (critical.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Critical:");
            foreach (var h in critical) sb.AppendLine($"  • {h}");
        }

        var hints = GetHints();
        if (hints.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Suggestions:");
            foreach (var h in hints) sb.AppendLine($"  • {h}");
        }

        return sb.ToString();
    }
}

public sealed class SeoHreflangLink
{
    public string Hreflang { get; init; } = "";
    public string Href { get; init; } = "";
}

public sealed class SeoJsonLdBlock
{
    public bool Valid { get; init; }
    public JsonElement Data { get; init; }
    public string? Raw { get; init; }
    public string? Error { get; init; }
}
