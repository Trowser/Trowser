using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Trowser.Security.Authz;

/// <summary>
/// Persists <see cref="AccessModel"/> snapshots per host under
/// <c>%LocalAppData%\Trowser\AccessModels\{host}.json</c> — modeled on
/// <see cref="Trowser.Security.IdentityStore"/>: simple JSON-on-disk, one file per key, no
/// database. Thread-safe via a per-process lock (models are small and edits are infrequent).
/// </summary>
public sealed class AccessModelStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
        WriteIndented = true
    };

    private static readonly Regex ValidHostPattern = new(@"^[a-zA-Z0-9][a-zA-Z0-9.:_-]{0,253}$", RegexOptions.Compiled);

    private readonly string _rootDir;
    private readonly object _lock = new();

    public AccessModelStore(string? rootDir = null)
    {
        _rootDir = rootDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Trowser", "AccessModels");
    }

    public static bool IsValidHost(string? host) =>
        !string.IsNullOrWhiteSpace(host) && ValidHostPattern.IsMatch(host.Trim());

    private string GetPath(string host) => Path.Combine(_rootDir, $"{SanitizeHost(host)}.json");

    /// <summary>Load the model for a host, or an empty (unsaved) model if none exists yet.</summary>
    public AccessModel GetOrCreate(string host)
    {
        host = CanonicalHost(host);
        lock (_lock)
        {
            var loaded = LoadUnlocked(host);
            return loaded ?? new AccessModel { Host = host };
        }
    }

    /// <summary>Load the model for a host, or null if it has never been saved.</summary>
    public AccessModel? Load(string host)
    {
        host = CanonicalHost(host);
        lock (_lock)
            return LoadUnlocked(host);
    }

    private AccessModel? LoadUnlocked(string host)
    {
        var path = GetPath(host);
        if (!File.Exists(path)) return null;
        var json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<AccessModel>(json, JsonOptions);
    }

    public void Save(AccessModel model)
    {
        model.Host = CanonicalHost(model.Host);
        model.UpdatedAt = DateTime.UtcNow;
        lock (_lock)
        {
            Directory.CreateDirectory(_rootDir);
            var json = JsonSerializer.Serialize(model, JsonOptions);
            File.WriteAllText(GetPath(model.Host), json);
        }
    }

    /// <summary>
    /// Merge a resource into the model and save. Existing human/AI-sourced classifications are
    /// never silently downgraded by a heuristic write — callers seeding heuristics should check
    /// <see cref="AccessModel.FindResource"/> first (see <see cref="AccessModelSeeder"/>).
    /// </summary>
    public AccessModel UpsertResource(string host, AccessModelResource resource)
    {
        host = CanonicalHost(host);
        lock (_lock)
        {
            var model = LoadUnlocked(host) ?? new AccessModel { Host = host };
            resource.UpdatedAt = DateTime.UtcNow;
            model.Resources[resource.Key] = resource;
            model.UpdatedAt = DateTime.UtcNow;
            Directory.CreateDirectory(_rootDir);
            File.WriteAllText(GetPath(host), JsonSerializer.Serialize(model, JsonOptions));
            return model;
        }
    }

    public AccessModel UpsertIdentity(string host, AccessModelIdentity identity)
    {
        host = CanonicalHost(host);
        lock (_lock)
        {
            var model = LoadUnlocked(host) ?? new AccessModel { Host = host };
            model.Identities.RemoveAll(i => i.Name.Equals(identity.Name, StringComparison.OrdinalIgnoreCase));
            model.Identities.Add(identity);
            model.UpdatedAt = DateTime.UtcNow;
            Directory.CreateDirectory(_rootDir);
            File.WriteAllText(GetPath(host), JsonSerializer.Serialize(model, JsonOptions));
            return model;
        }
    }

    /// <summary>Hosts with a persisted model, most-recently-updated first.</summary>
    public List<string> ListHosts()
    {
        if (!Directory.Exists(_rootDir)) return [];
        return Directory.EnumerateFiles(_rootDir, "*.json")
            .Select(Path.GetFileNameWithoutExtension)
            .Where(h => !string.IsNullOrEmpty(h))
            .Select(h => h!)
            .OrderBy(h => h, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public bool Delete(string host)
    {
        host = CanonicalHost(host);
        lock (_lock)
        {
            var path = GetPath(host);
            if (!File.Exists(path)) return false;
            File.Delete(path);
            return true;
        }
    }

    private static string CanonicalHost(string? host)
    {
        var canonical = AuthzHostKey.Canonical(host);
        ValidateHost(canonical);
        return canonical;
    }

    private static void ValidateHost(string? host)
    {
        if (!IsValidHost(host))
            throw new ArgumentException("Invalid host. Use a hostname or host:port (letters, digits, dot, colon, underscore, hyphen).");
    }

    /// <summary>Windows file names cannot contain <c>:</c>. The model <see cref="AccessModel.Host"/> keeps the port.</summary>
    private static string SanitizeHost(string host) => host.Trim().Replace(":", "_", StringComparison.Ordinal);
}
