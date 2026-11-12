using System.Reflection;

namespace Trowser.Security.Orchestration;

/// <summary>
/// Registry of all available playbooks. Discovers <see cref="IPlaybook"/> implementations
/// via reflection at startup.
/// </summary>
public sealed class PlaybookRegistry
{
    private readonly Dictionary<string, IPlaybook> _playbooks = new(StringComparer.OrdinalIgnoreCase);

    public PlaybookRegistry()
    {
        DiscoverPlaybooks();
    }

    public IPlaybook? Get(string id) =>
        _playbooks.TryGetValue(id, out var p) ? p : null;

    public IReadOnlyDictionary<string, IPlaybook> All => _playbooks;

    /// <summary>Catalog for /api/orchestrate/playbooks.</summary>
    public List<Dictionary<string, object?>> GetCatalog()
    {
        return _playbooks.Values
            .OrderBy(p => p.Id)
            .Select(p => new Dictionary<string, object?>
            {
                ["id"] = p.Id,
                ["title"] = p.Title,
                ["category"] = p.Category,
                ["endpoint"] = $"/api/orchestrate/{p.Id}"
            })
            .ToList();
    }

    private void DiscoverPlaybooks()
    {
        var iface = typeof(IPlaybook);
        var types = Assembly.GetExecutingAssembly()
            .GetTypes()
            .Where(t => t is { IsClass: true, IsAbstract: false } && iface.IsAssignableFrom(t));

        foreach (var type in types)
        {
            try
            {
                if (Activator.CreateInstance(type) is IPlaybook playbook)
                    _playbooks[playbook.Id] = playbook;
            }
            catch
            {
                // Skip types that can't be instantiated
            }
        }
    }
}
