using System.IO;
using System.Reflection;
using System.Text;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Trowser.Security.LlmRedTeam;

public static class LlmProbeCorpus
{
    private static readonly Lazy<List<LlmProbeDefinition>> Cached = new(LoadEmbedded);

    /// <summary>OWASP LLM Top 10 2025 categories with corpus probes (YAML).</summary>
    public static readonly string[] CoveredCategories =
    [
        "LLM01_Prompt_Injection",
        "LLM02_Sensitive_Information_Disclosure",
        "LLM03_Supply_Chain",
        "LLM05_Improper_Output_Handling",
        "LLM06_Excessive_Agency",
        "LLM07_System_Prompt_Leakage",
        "LLM09_Misinformation"
    ];

    /// <summary>2025 categories without YAML corpus probes (may still have adjacent scanners).</summary>
    public static readonly string[] NotCoveredInCorpus =
    [
        "LLM04_Data_and_Model_Poisoning",
        "LLM08_Vector_and_Embedding_Weaknesses",
        "LLM10_Unbounded_Consumption"
    ];

    private static readonly Dictionary<string, string[]> CategoryAliases =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["LLM01"] = ["LLM01_Prompt_Injection"],
            ["LLM02"] = ["LLM02_Sensitive_Information_Disclosure"],
            ["LLM02_Insecure_Output_Handling"] = ["LLM05_Improper_Output_Handling"],
            ["LLM02_InsecureOutputHandling"] = ["LLM05_Improper_Output_Handling"],
            ["LLM03"] = ["LLM03_Supply_Chain"],
            ["LLM04"] = ["LLM04_Data_and_Model_Poisoning"],
            ["LLM04_Data_and_Model_Poisoning"] = ["LLM04_Data_and_Model_Poisoning"],
            // Legacy 2023 naming (Model DoS) → 2025 Unbounded Consumption
            ["LLM04_Model_Denial_of_Service"] = ["LLM10_Unbounded_Consumption"],
            ["LLM05"] = ["LLM05_Improper_Output_Handling"],
            ["LLM05_Insecure_Output_Handling"] = ["LLM05_Improper_Output_Handling"],
            ["LLM06"] = ["LLM06_Excessive_Agency"],
            ["LLM07"] = ["LLM07_System_Prompt_Leakage"],
            ["LLM08"] = ["LLM08_Vector_and_Embedding_Weaknesses"],
            ["LLM09"] = ["LLM09_Misinformation"],
            ["LLM10"] = ["LLM10_Unbounded_Consumption"],
            ["LLM10_Model_Denial_of_Service"] = ["LLM10_Unbounded_Consumption"]
        };

    public static object BuildCoverageMetadata()
    {
        var present = All.Select(p => p.Category).Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(c => c, StringComparer.OrdinalIgnoreCase).ToList();
        return new
        {
            claim = "OWASP LLM Top 10 application-layer coverage (corpus LLM01–03+LLM05–07+LLM09; LLM04/08/10 via adjacent scanners when enabled)",
            corpusProbeCount = All.Count,
            covered = present,
            notCoveredInCorpus = NotCoveredInCorpus,
            adjacentScanners = new[]
            {
                "indirect-injection / rag-poison (LLM01/LLM04)",
                "web-mcp-abuse (LLM06)",
                "output-sink-trace (LLM05)",
                "unbounded-consumption (LLM10)",
                "embedding-isolation peer check (LLM08)"
            }
        };
    }

    public static IReadOnlyList<LlmProbeDefinition> All => Cached.Value;

    public static List<LlmProbeDefinition> Filter(
        IEnumerable<string>? probeIds,
        IEnumerable<string>? categories,
        int maxProbes) =>
        FilterWithWarnings(probeIds, categories, maxProbes).Probes;

    public static (List<LlmProbeDefinition> Probes, List<string> Warnings) FilterWithWarnings(
        IEnumerable<string>? probeIds,
        IEnumerable<string>? categories,
        int maxProbes)
    {
        var warnings = new List<string>();
        IEnumerable<LlmProbeDefinition> q = All;

        if (probeIds != null)
        {
            var requested = probeIds.Where(id => !string.IsNullOrWhiteSpace(id)).ToList();
            if (requested.Count > 0)
            {
                var set = new HashSet<string>(requested, StringComparer.OrdinalIgnoreCase);
                foreach (var id in requested)
                {
                    if (!All.Any(p => p.Id.Equals(id, StringComparison.OrdinalIgnoreCase)))
                        warnings.Add($"Unknown probeId: {id}");
                }

                q = q.Where(p => set.Contains(p.Id));
            }
        }

        if (categories != null)
        {
            var requestedCats = categories.Where(c => !string.IsNullOrWhiteSpace(c)).ToList();
            if (requestedCats.Count > 0)
            {
                var expanded = ExpandCategories(requestedCats);
                var beforeCount = q.Count();
                q = q.Where(p => expanded.Contains(p.Category)
                                 || expanded.Contains(NormalizeCategory(p.Category)));
                if (!q.Any())
                {
                    foreach (var cat in requestedCats)
                    {
                        if (!CategoryExists(cat))
                            warnings.Add($"Unknown category: {cat}. Use GET /api/security/llm-redteam-probes for valid names.");
                    }
                }
                else if (beforeCount == 0)
                {
                    foreach (var cat in requestedCats.Where(c => !CategoryExists(c)))
                        warnings.Add($"Unknown category: {cat}");
                }
            }
        }

        return (q.Take(Math.Clamp(maxProbes, 0, 64)).ToList(), warnings);
    }

    public static IReadOnlyList<object> ListCatalog() =>
        All.Select(p => (object)new
        {
            p.Id,
            p.Category,
            normalizedCategory = NormalizeCategory(p.Category),
            p.Severity,
            p.Rationale
        }).ToList();

    public static IReadOnlyList<string> ListCategories() =>
        All.Select(p => p.Category).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(c => c).ToList();

    private static HashSet<string> ExpandCategories(IEnumerable<string> categories)
    {
        var expanded = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var cat in categories)
        {
            expanded.Add(cat);
            expanded.Add(NormalizeCategory(cat));
            if (CategoryAliases.TryGetValue(cat, out var aliases))
            {
                foreach (var alias in aliases)
                    expanded.Add(alias);
            }
        }

        return expanded;
    }

    private static bool CategoryExists(string category)
    {
        if (All.Any(p => p.Category.Equals(category, StringComparison.OrdinalIgnoreCase)
                         || NormalizeCategory(p.Category).Equals(category, StringComparison.OrdinalIgnoreCase)))
            return true;

        return CategoryAliases.ContainsKey(category);
    }

    public static string NormalizeCategory(string category)
    {
        if (string.IsNullOrWhiteSpace(category)) return category;
        var idx = category.IndexOf('_');
        return idx > 0 ? category[..idx] : category;
    }

    private static List<LlmProbeDefinition> LoadEmbedded()
    {
        var asm = typeof(LlmProbeCorpus).Assembly;
        const string resourceName = "Trowser.Security.LlmRedTeam.llm-redteam-corpus.yaml";
        using var stream = asm.GetManifestResourceStream(resourceName);
        if (stream == null)
            throw new InvalidOperationException($"Embedded LLM corpus not found: {resourceName}");

        using var reader = new StreamReader(stream, Encoding.UTF8);
        var yaml = reader.ReadToEnd();

        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        var root = deserializer.Deserialize<CorpusRoot>(yaml);
        return root.Probes ?? [];
    }

    private sealed class CorpusRoot
    {
        public List<LlmProbeDefinition> Probes { get; set; } = [];
    }
}
