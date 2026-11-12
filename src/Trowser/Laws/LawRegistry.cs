using System.IO;

namespace Trowser.Laws;

public sealed class LawRegistry
{
    private readonly object _lock = new();
    private readonly Dictionary<string, LawDefinition> _byId = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<string>> _idsBySource = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<LawDefinition> All
    {
        get
        {
            lock (_lock)
                return _byId.Values.ToList();
        }
    }

    public void Register(LawDefinition definition)
    {
        if (!TryRegister(definition, out var conflict))
            throw new InvalidOperationException(
                $"Duplicate Law name '{definition.Name}' (already declared in {conflict}).");
    }

    /// <summary>Register unless another loaded Law already uses the same name (case-insensitive).</summary>
    public bool TryRegister(LawDefinition definition, out string? conflictSource)
    {
        conflictSource = null;
        lock (_lock)
        {
            foreach (var existing in _byId.Values)
            {
                if (existing.Id.Equals(definition.Id, StringComparison.Ordinal))
                    continue;
                if (existing.Name.Equals(definition.Name, StringComparison.OrdinalIgnoreCase))
                {
                    conflictSource = existing.SourceFile ?? existing.Id;
                    return false;
                }
            }

            _byId[definition.Id] = definition;
            if (!string.IsNullOrEmpty(definition.SourceFile))
            {
                if (!_idsBySource.TryGetValue(definition.SourceFile, out var list))
                {
                    list = [];
                    _idsBySource[definition.SourceFile] = list;
                }
                if (!list.Contains(definition.Id))
                    list.Add(definition.Id);
            }

            return true;
        }
    }

    public void RemoveSource(string sourceFile)
    {
        lock (_lock)
        {
            if (!_idsBySource.TryGetValue(sourceFile, out var ids))
                return;
            foreach (var id in ids)
                _byId.Remove(id);
            _idsBySource.Remove(sourceFile);
        }
    }

    public IEnumerable<LawDefinition> Query(
        LawTriggerKind? trigger = null,
        LawCostClass? maxCost = null,
        IEnumerable<string>? disabledIds = null)
    {
        var disabled = disabledIds?.ToHashSet(StringComparer.OrdinalIgnoreCase) ?? [];
        lock (_lock)
        {
            foreach (var def in _byId.Values)
            {
                if (disabled.Contains(def.Id))
                    continue;
                if (trigger.HasValue && def.Trigger != trigger.Value)
                    continue;
                if (maxCost.HasValue && def.Cost > maxCost.Value)
                    continue;
                yield return def;
            }
        }
    }

    public static string MakeId(string? sourceFile, string name)
    {
        var baseName = string.IsNullOrEmpty(sourceFile)
            ? name
            : $"{sourceFile}|{name}";
        return baseName;
    }

    /// <summary>Name conflict with a Law from another source (or same source when validating a patch).</summary>
    public string? FindNameConflict(LawDefinition candidate, string? excludeSourceFile = null)
    {
        var excludeNorm = NormalizeSourcePath(excludeSourceFile);
        lock (_lock)
        {
            foreach (var existing in _byId.Values)
            {
                if (excludeNorm != null
                    && string.Equals(NormalizeSourcePath(existing.SourceFile), excludeNorm, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (existing.Id.Equals(candidate.Id, StringComparison.Ordinal))
                    continue;
                if (existing.Name.Equals(candidate.Name, StringComparison.OrdinalIgnoreCase))
                    return existing.SourceFile ?? existing.Id;
            }
        }

        return null;
    }

    internal static string? NormalizeSourcePath(string? sourceFile)
    {
        if (string.IsNullOrWhiteSpace(sourceFile))
            return sourceFile;
        if (sourceFile.StartsWith("embedded:", StringComparison.OrdinalIgnoreCase)
            || sourceFile.StartsWith('('))
            return sourceFile;
        try
        {
            return Path.GetFullPath(sourceFile);
        }
        catch
        {
            return sourceFile;
        }
    }
}
