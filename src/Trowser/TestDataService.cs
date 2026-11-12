using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Trowser;

public class TestStringEntry
{
    [JsonPropertyName("text")]
    public string Text { get; set; } = "";

    [JsonPropertyName("count")]
    public int Count { get; set; }

    [JsonPropertyName("timestamp")]
    public long Timestamp { get; set; }

    [JsonPropertyName("is_ascii")]
    public bool IsAscii { get; set; }
}

public enum TestDataKind
{
    Strings,
    Payloads
}

/// <summary>
/// Manages test data strings and security payloads: loads/saves from JSON files next to the exe,
/// fetches random strings online (strings only), and provides random selection.
/// </summary>
public class TestDataService
{
    public const string DefaultOnlineUrl = "https://thetesteye.com/blog/wp-json/test-strings-together/v1/random";
    private const string StringsFileName = "test_strings.json";
    private const string PayloadsFileName = "test_payloads.json";

    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(5) };
    private static readonly Random Rng = new();

    private readonly string _stringsFilePath;
    private readonly string _payloadsFilePath;
    private List<TestStringEntry> _stringEntries = new();
    private List<TestStringEntry> _payloadEntries = new();

    public TestDataKind ActiveKind { get; set; } = TestDataKind.Strings;
    public bool UseOnline { get; set; }
    public bool AsciiOnly { get; set; }
    public string OnlineUrl { get; set; } = DefaultOnlineUrl;

    public IReadOnlyList<TestStringEntry> StringEntries => _stringEntries;
    public IReadOnlyList<TestStringEntry> PayloadEntries => _payloadEntries;
    public IReadOnlyList<TestStringEntry> Entries => ActiveKind == TestDataKind.Strings ? _stringEntries : _payloadEntries;

    public TestDataService()
    {
        var exeDir = Path.GetDirectoryName(Environment.ProcessPath)!;
        _stringsFilePath = Path.Combine(exeDir, StringsFileName);
        _payloadsFilePath = Path.Combine(exeDir, PayloadsFileName);
        Load();
    }

    public static bool TryParseKind(string? value, out TestDataKind kind)
    {
        kind = TestDataKind.Strings;
        if (string.IsNullOrWhiteSpace(value))
            return false;

        switch (value.Trim().ToLowerInvariant())
        {
            case "strings":
            case "string":
                kind = TestDataKind.Strings;
                return true;
            case "payloads":
            case "payload":
                kind = TestDataKind.Payloads;
                return true;
            default:
                return false;
        }
    }

    public static string KindToApiValue(TestDataKind kind) =>
        kind == TestDataKind.Payloads ? "payloads" : "strings";

    public void Load()
    {
        _stringEntries = LoadFile(_stringsFilePath);
        _payloadEntries = LoadFile(_payloadsFilePath);
    }

    private static List<TestStringEntry> LoadFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                var json = File.ReadAllText(path);
                return JsonSerializer.Deserialize<List<TestStringEntry>>(json) ?? new();
            }
        }
        catch
        {
            // Fall through to empty list
        }

        return new();
    }

    public void Save()
    {
        SaveFile(_stringsFilePath, _stringEntries);
        SaveFile(_payloadsFilePath, _payloadEntries);
    }

    private static void SaveFile(string path, List<TestStringEntry> entries)
    {
        try
        {
            var options = new JsonSerializerOptions { WriteIndented = true };
            var json = JsonSerializer.Serialize(entries, options);
            File.WriteAllText(path, json);
        }
        catch
        {
            // Best effort — file may be read-only in some deployment scenarios
        }
    }

    public void AddEntry(string text)
    {
        var isAscii = text.All(c => c <= 127);
        ActiveEntries.Add(new TestStringEntry
        {
            Text = text,
            Count = 0,
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            IsAscii = isAscii
        });
    }

    public void RemoveEntry(TestStringEntry entry)
    {
        ActiveEntries.Remove(entry);
    }

    private List<TestStringEntry> ActiveEntries =>
        ActiveKind == TestDataKind.Strings ? _stringEntries : _payloadEntries;

    /// <summary>
    /// Get a random entry from the active or specified collection.
    /// Online fetch applies only to test strings. Falls back to offline on failure.
    /// When offline with AsciiOnly, only selects from entries where is_ascii is true.
    /// </summary>
    public async Task<string?> GetRandomAsync(TestDataKind? kind = null)
    {
        var useKind = kind ?? ActiveKind;

        if (useKind == TestDataKind.Strings && UseOnline)
        {
            try
            {
                var url = string.IsNullOrWhiteSpace(OnlineUrl) ? DefaultOnlineUrl : OnlineUrl;
                var result = await Http.GetStringAsync(url);
                return result.Trim().Trim('"');
            }
            catch
            {
                // Fall through to offline
            }
        }

        var entries = useKind == TestDataKind.Strings ? _stringEntries : _payloadEntries;
        var candidates = AsciiOnly
            ? entries.Where(e => e.IsAscii).ToList()
            : entries;

        if (candidates.Count == 0)
            return null;

        return candidates[Rng.Next(candidates.Count)].Text;
    }
}
