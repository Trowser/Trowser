namespace Trowser.Laws;

public sealed class LawProposal
{
    public required string Id { get; init; }
    public required string Title { get; init; }
    public required string Code { get; init; }
    public string Source { get; init; } = "mining";
    public string? Kind { get; init; }
    public int Observations { get; init; }
    public int Counterexamples { get; init; }
    public DateTime CreatedUtc { get; init; } = DateTime.UtcNow;
    public string? Host { get; init; }
    public string? Rationale { get; init; }
    public IReadOnlyList<string> Evidence { get; init; } = [];
}

public sealed class LawProposalStore
{
    private readonly object _lock = new();
    private readonly List<LawProposal> _proposals = [];
    private readonly HashSet<string> _rejected = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<LawProposal> Proposals
    {
        get
        {
            lock (_lock)
                return _proposals.ToList();
        }
    }

    public void Add(LawProposal proposal)
    {
        lock (_lock)
        {
            if (_rejected.Contains(proposal.Id))
                return;
            if (_proposals.Any(p => p.Id == proposal.Id))
                return;
            _proposals.Add(proposal);
        }
    }

    public bool Reject(string id)
    {
        lock (_lock)
        {
            var removed = _proposals.RemoveAll(p => p.Id == id) > 0;
            if (removed)
                _rejected.Add(id);
            return removed;
        }
    }

    public LawProposal? Accept(string id)
    {
        lock (_lock)
        {
            var idx = _proposals.FindIndex(p => p.Id == id);
            if (idx < 0) return null;
            var p = _proposals[idx];
            _proposals.RemoveAt(idx);
            return p;
        }
    }
}
