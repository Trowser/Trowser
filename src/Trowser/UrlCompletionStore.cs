using System.IO;
using System.Text.Json;

namespace Trowser;

/// <summary>
/// Address-bar completion from URLs the tester has typed — not bookmarks, and not
/// every navigation. Crawls, scripts, API calls, and link clicks would flood the list;
/// typed addresses are the few hosts and paths testers return to (localhost, staging, login).
/// Stored in %APPDATA%\Trowser\url-history.json, separate from WebView2 session memory.
/// </summary>
public class UrlCompletionStore
{
    /// <summary>
    /// Soft ceiling so the file cannot grow forever. Matching is a linear scan of short
    /// strings — thousands of entries are still cheap on each keystroke; this is about
    /// dropping stale typed URLs, not UI performance.
    /// </summary>
    public const int MaxEntries = 2000;
    public const int MaxSuggestions = 8;
    public const int MaxUrlLength = 2048;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private List<UrlCompletionEntry> _entries = new();

    public int Count => _entries.Count;

    private static string FilePath
    {
        get
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Trowser");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "url-history.json");
        }
    }

    public static UrlCompletionStore Load()
    {
        var store = new UrlCompletionStore();
        try
        {
            if (File.Exists(FilePath))
            {
                var json = File.ReadAllText(FilePath);
                var file = JsonSerializer.Deserialize<UrlCompletionFile>(json, JsonOptions);
                if (file?.Entries != null)
                    store._entries = file.Entries.Where(e => !string.IsNullOrWhiteSpace(e.Url)).ToList();
            }
        }
        catch (Exception ex)
        {
            TrowserLog.Error("Failed to load URL completion history", ex);
        }

        return store;
    }

    public void Save()
    {
        try
        {
            var json = JsonSerializer.Serialize(new UrlCompletionFile { Entries = _entries }, JsonOptions);
            File.WriteAllText(FilePath, json);
        }
        catch (Exception ex)
        {
            TrowserLog.Error("Failed to save URL completion history", ex);
        }
    }

    /// <summary>
    /// Record a URL submitted from the address bar. Search fallbacks and internal pages are ignored.
    /// </summary>
    public void Record(string url)
    {
        if (!ShouldRecord(url))
            return;

        url = url.Trim();
        var key = CanonicalKey(url);
        var now = DateTimeOffset.UtcNow;
        var existing = _entries.FirstOrDefault(e => CanonicalKey(e.Url) == key);
        if (existing != null)
        {
            existing.Url = url;
            existing.UseCount = Math.Max(1, existing.UseCount) + 1;
            existing.LastUsedUtc = now;
        }
        else
        {
            _entries.Add(new UrlCompletionEntry
            {
                Url = url,
                UseCount = 1,
                LastUsedUtc = now
            });
            TrimToCap();
        }

        Save();
    }

    public bool Remove(string url)
    {
        var key = CanonicalKey(url);
        var removed = _entries.RemoveAll(e => CanonicalKey(e.Url) == key) > 0;
        if (removed)
            Save();
        return removed;
    }

    public void Clear()
    {
        _entries.Clear();
        Save();
    }

    /// <summary>
    /// Ranked matches for the address bar. An empty query returns the most recently typed URLs.
    /// </summary>
    public IReadOnlyList<string> Suggest(string query)
    {
        if (_entries.Count == 0)
            return Array.Empty<string>();

        var q = (query ?? "").Trim();
        if (q.Length == 0)
        {
            return _entries
                .OrderByDescending(e => e.LastUsedUtc)
                .Take(MaxSuggestions)
                .Select(e => e.Url)
                .ToList();
        }

        var now = DateTimeOffset.UtcNow;
        return _entries
            .Select(e => (entry: e, quality: MatchQuality(q, e.Url)))
            .Where(x => x.quality > 0)
            .OrderByDescending(x => x.quality)
            .ThenByDescending(x => Frecency(x.entry, now))
            .ThenByDescending(x => x.entry.LastUsedUtc)
            .Take(MaxSuggestions)
            .Select(x => x.entry.Url)
            .ToList();
    }

    /// <summary>
    /// Best suggestion whose URL (or https:// + query) starts with what the user typed —
    /// used for inline remainder-selection, not substring hits.
    /// </summary>
    public string? BestPrefixMatch(string typed)
    {
        typed = (typed ?? "").Trim();
        if (typed.Length == 0)
            return null;

        foreach (var url in Suggest(typed))
        {
            if (url.StartsWith(typed, StringComparison.OrdinalIgnoreCase))
                return url;
            var withHttps = "https://" + typed;
            if (url.StartsWith(withHttps, StringComparison.OrdinalIgnoreCase))
                return url;
            var withHttp = "http://" + typed;
            if (url.StartsWith(withHttp, StringComparison.OrdinalIgnoreCase))
                return url;
        }

        return null;
    }

    public static bool ShouldRecord(string url)
    {
        if (string.IsNullOrWhiteSpace(url) || url.Length > MaxUrlLength)
            return false;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;
        if (uri.Scheme is not ("http" or "https" or "file"))
            return false;
        if (uri.Host.Equals("www.google.com", StringComparison.OrdinalIgnoreCase) &&
            uri.AbsolutePath.StartsWith("/search", StringComparison.OrdinalIgnoreCase))
            return false;
        return true;
    }

    internal static int MatchQuality(string query, string url)
    {
        var q = query.Trim().ToLowerInvariant();
        if (q.Length == 0)
            return 0;

        var qBare = StripScheme(q);
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            var lower = url.ToLowerInvariant();
            if (lower.StartsWith(q, StringComparison.Ordinal))
                return 80;
            return lower.Contains(q, StringComparison.Ordinal) ? 20 : 0;
        }

        var host = uri.Host.ToLowerInvariant();
        var hostNoWww = host.StartsWith("www.", StringComparison.Ordinal) ? host[4..] : host;
        var hostPort = uri.IsDefaultPort ? host : $"{host}:{uri.Port}";
        var hostPortNoWww = uri.IsDefaultPort ? hostNoWww : $"{hostNoWww}:{uri.Port}";
        var pathAndQuery = (uri.PathAndQuery ?? "/").ToLowerInvariant();
        var urlBare = StripScheme(url.ToLowerInvariant());

        if (host.StartsWith(qBare, StringComparison.Ordinal) ||
            hostNoWww.StartsWith(qBare, StringComparison.Ordinal) ||
            hostPort.StartsWith(qBare, StringComparison.Ordinal) ||
            hostPortNoWww.StartsWith(qBare, StringComparison.Ordinal))
            return 100;

        if (urlBare.StartsWith(qBare, StringComparison.Ordinal))
            return 80;

        if (host.Contains(qBare, StringComparison.Ordinal) ||
            hostPort.Contains(qBare, StringComparison.Ordinal) ||
            hostPortNoWww.Contains(qBare, StringComparison.Ordinal))
            return 60;

        if (pathAndQuery.Contains(qBare, StringComparison.Ordinal))
            return 40;

        if (urlBare.Contains(qBare, StringComparison.Ordinal))
            return 20;

        return 0;
    }

    private void TrimToCap()
    {
        if (_entries.Count <= MaxEntries)
            return;

        var now = DateTimeOffset.UtcNow;
        _entries = _entries
            .OrderByDescending(e => Frecency(e, now))
            .ThenByDescending(e => e.LastUsedUtc)
            .Take(MaxEntries)
            .ToList();
    }

    private static double Frecency(UrlCompletionEntry entry, DateTimeOffset now)
    {
        var ageHours = Math.Max(0, (now - entry.LastUsedUtc).TotalHours);
        var recency = ageHours < 24 ? 1.0
            : ageHours < 24 * 7 ? 0.7
            : ageHours < 24 * 30 ? 0.4
            : 0.2;
        return Math.Max(1, entry.UseCount) * recency;
    }

    private static string CanonicalKey(string url)
    {
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri))
            return url.Trim().ToLowerInvariant();

        var host = uri.Host.ToLowerInvariant();
        var path = uri.AbsolutePath;
        if (path == "/")
            path = "";
        var port = uri.IsDefaultPort ? "" : $":{uri.Port}";
        return $"{uri.Scheme.ToLowerInvariant()}://{host}{port}{path}{uri.Query}";
    }

    private static string StripScheme(string value)
    {
        if (value.StartsWith("https://", StringComparison.Ordinal))
            return value["https://".Length..];
        if (value.StartsWith("http://", StringComparison.Ordinal))
            return value["http://".Length..];
        if (value.StartsWith("file://", StringComparison.Ordinal))
            return value["file://".Length..];
        return value;
    }

    private sealed class UrlCompletionFile
    {
        public List<UrlCompletionEntry> Entries { get; set; } = new();
    }
}

public class UrlCompletionEntry
{
    public string Url { get; set; } = "";
    public int UseCount { get; set; }
    public DateTimeOffset LastUsedUtc { get; set; }
}
