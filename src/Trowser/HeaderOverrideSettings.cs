using System.IO;
using System.Text.Json;

namespace Trowser;

/// <summary>
/// Persistent session header overrides for WebView2 browsing.
/// Stored as JSON in %APPDATA%\Trowser\header-overrides.json.
/// Does not apply to Send (Direct), Raw, or server-side HttpClient APIs.
/// </summary>
public static class HeaderOverrideSettings
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private static readonly object Gate = new();
    private static List<HeaderOverride> _items = [];
    private static bool _loaded;

    public static event Action? Changed;

    private static string SettingsPath
    {
        get
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Trowser");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "header-overrides.json");
        }
    }

    public static IReadOnlyList<HeaderOverride> GetAll()
    {
        EnsureLoaded();
        lock (Gate)
            return _items.Select(Clone).ToList();
    }

    public static IReadOnlyList<HeaderOverride> GetEnabled()
    {
        EnsureLoaded();
        lock (Gate)
            return _items.Where(i => i.Enabled && !string.IsNullOrWhiteSpace(i.Name)).Select(Clone).ToList();
    }

    public static int EnabledCount
    {
        get
        {
            EnsureLoaded();
            lock (Gate)
                return _items.Count(i => i.Enabled && !string.IsNullOrWhiteSpace(i.Name));
        }
    }

    public static string? UserAgentOverride
    {
        get
        {
            foreach (var item in GetEnabled())
            {
                if (item.Name.Equals("User-Agent", StringComparison.OrdinalIgnoreCase))
                    return item.Value;
            }
            return null;
        }
    }

    public static void Replace(IEnumerable<HeaderOverride> items)
    {
        lock (Gate)
        {
            _items = items.Select(Clone).ToList();
            _loaded = true;
            Persist_NoLock();
        }
        Changed?.Invoke();
    }

    public static void Clear()
    {
        lock (Gate)
        {
            _items = [];
            _loaded = true;
            Persist_NoLock();
        }
        Changed?.Invoke();
    }

    public static void EnsureLoaded()
    {
        lock (Gate)
        {
            if (_loaded) return;
            try
            {
                if (File.Exists(SettingsPath))
                {
                    var json = File.ReadAllText(SettingsPath);
                    var data = JsonSerializer.Deserialize<HeaderOverrideSettingsData>(json, JsonOptions);
                    _items = data?.Headers?.Select(Clone).ToList() ?? [];
                }
            }
            catch (Exception ex)
            {
                TrowserLog.Error("Failed to load header overrides", ex);
                _items = [];
            }
            _loaded = true;
        }
    }

    private static void Persist_NoLock()
    {
        try
        {
            var data = new HeaderOverrideSettingsData { Headers = _items.Select(Clone).ToList() };
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(data, JsonOptions));
        }
        catch (Exception ex)
        {
            TrowserLog.Error("Failed to save header overrides", ex);
        }
    }

    private static HeaderOverride Clone(HeaderOverride item) => new()
    {
        Name = item.Name ?? "",
        Value = item.Value ?? "",
        Enabled = item.Enabled
    };

    private sealed class HeaderOverrideSettingsData
    {
        public List<HeaderOverride>? Headers { get; set; }
    }
}

public sealed class HeaderOverride
{
    public string Name { get; set; } = "";
    public string Value { get; set; } = "";
    public bool Enabled { get; set; } = true;
}
