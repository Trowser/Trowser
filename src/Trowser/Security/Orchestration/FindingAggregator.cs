using Trowser.Security.ChainEngine;

namespace Trowser.Security.Orchestration;

/// <summary>
/// Collects and de-duplicates findings from multiple playbook steps.
/// Scoring is based on severity with tie-breaking by endpoint specificity.
/// Cross-playbook dedup: seed with existing session findings so repeated
/// playbook runs don't duplicate header/cookie findings.
/// </summary>
public sealed class FindingAggregator
{
    private readonly List<ChainableFinding> _findings = [];
    private readonly HashSet<string> _dedup = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<SuppressedFindingInfo> _suppressed = [];

    public IReadOnlyList<ChainableFinding> All => _findings;
    public int Count => _findings.Count;

    /// <summary>
    /// Seed the dedup set with findings from previous playbook runs (or other sources)
    /// without adding them to this aggregator's output list. Prevents duplicates when
    /// chaining playbooks (e.g., A01 headers + A02 headers).
    /// </summary>
    public void SeedDedup(IEnumerable<ChainableFinding> existingFindings)
    {
        foreach (var f in existingFindings)
            _dedup.Add(DedupKey(f));
    }

    /// <summary>Number of findings that were suppressed by dedup (including cross-playbook).</summary>
    public int SuppressedCount => _suppressed.Count;

    /// <summary>Suppressed finding summaries for LLM/evaluation transparency.</summary>
    public IReadOnlyList<SuppressedFindingInfo> SuppressedFindings => _suppressed;

    /// <summary>Add findings, de-duplicating by (category, endpoint, parameter, method, title).</summary>
    public void Add(IEnumerable<ChainableFinding> findings)
    {
        foreach (var f in findings)
            Add(f);
    }

    public void Add(ChainableFinding finding)
    {
        var key = DedupKey(finding);
        if (_dedup.Add(key))
            _findings.Add(finding);
        else
        {
            _suppressed.Add(new SuppressedFindingInfo
            {
                Id = finding.Id,
                Title = finding.Title,
                Category = finding.Category,
                Severity = finding.Severity,
                Endpoint = finding.Endpoint,
                Reason = "cross-playbook-deduplication"
            });
        }
    }

    /// <summary>Get findings ordered by severity (critical first), then by title.</summary>
    public List<ChainableFinding> GetSorted()
    {
        return _findings
            .OrderByDescending(f => SeverityRank(f.Severity))
            .ThenBy(f => f.Title, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    /// <summary>Get top-N findings by severity.</summary>
    public List<ChainableFinding> GetTopN(int n)
    {
        return GetSorted().Take(n).ToList();
    }

    /// <summary>Group findings by severity and return counts.</summary>
    public Dictionary<string, int> CountBySeverity()
    {
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in _findings)
        {
            var sev = NormalizeSeverity(f.Severity);
            counts.TryGetValue(sev, out var c);
            counts[sev] = c + 1;
        }
        return counts;
    }

    private static string DedupKey(ChainableFinding f) => ChainFindingDedup.Key(f);

    private static int SeverityRank(string severity) => NormalizeSeverity(severity) switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0
    };

    private static string NormalizeSeverity(string severity) =>
        severity.ToLowerInvariant() switch
        {
            "critical" or "high" or "medium" or "low" or "info" => severity.ToLowerInvariant(),
            _ => "info"
        };
}
