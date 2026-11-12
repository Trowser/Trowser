using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Trowser.Security.RaceLab;

namespace Trowser;

/// <summary>
/// Persistent Race Lab profiles (%APPDATA%\Trowser\race-lab-profiles.json).
/// </summary>
public static class RaceLabSettings
{
    public static readonly string[] BuiltInNames = ["Hammer", "Spike", "Sequential", "Random"];

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    private static string SettingsPath
    {
        get
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Trowser");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "race-lab-profiles.json");
        }
    }

    public static bool IsBuiltInName(string? name) =>
        !string.IsNullOrWhiteSpace(name)
        && BuiltInNames.Contains(name.Trim(), StringComparer.OrdinalIgnoreCase);

    public static List<RaceLabProfile> CreateBuiltInProfiles() =>
    [
        new RaceLabProfile
        {
            Name = "Hammer",
            Parameters = RaceLabParameters.ForMode(RaceLabMode.Hammer)
        },
        new RaceLabProfile
        {
            Name = "Spike",
            Parameters = RaceLabParameters.ForMode(RaceLabMode.Spike)
        },
        new RaceLabProfile
        {
            Name = "Sequential",
            Parameters = RaceLabParameters.ForMode(RaceLabMode.Sequential)
        },
        new RaceLabProfile
        {
            Name = "Random",
            Parameters = RaceLabParameters.ForMode(RaceLabMode.Random)
        }
    ];

    public static List<RaceLabProfile> Load()
    {
        try
        {
            if (!File.Exists(SettingsPath))
                return MergeWithBuiltIns([]);

            var json = File.ReadAllText(SettingsPath);
            var data = JsonSerializer.Deserialize<RaceLabSettingsData>(json, JsonOptions);
            return MergeWithBuiltIns(data?.Profiles ?? []);
        }
        catch (Exception ex)
        {
            TrowserLog.Error("Failed to load Race Lab profiles", ex);
            return MergeWithBuiltIns([]);
        }
    }

    public static void Save(List<RaceLabProfile> profiles)
    {
        try
        {
            var userOnly = profiles
                .Where(p => !IsBuiltInName(p.Name))
                .ToList();
            var data = new RaceLabSettingsData { Profiles = userOnly };
            var json = JsonSerializer.Serialize(data, JsonOptions);
            File.WriteAllText(SettingsPath, json);
        }
        catch (Exception ex)
        {
            TrowserLog.Error("Failed to save Race Lab profiles", ex);
        }
    }

    public static string ExportToJson(IReadOnlyList<RaceLabProfile> profiles)
    {
        var data = new RaceLabExportData
        {
            ExportedAt = DateTime.UtcNow.ToString("o"),
            Profiles = profiles.Select(p => p.Clone()).ToList()
        };
        return JsonSerializer.Serialize(data, JsonOptions);
    }

    public static List<RaceLabProfile> ImportFromJson(string json)
    {
        var data = JsonSerializer.Deserialize<RaceLabExportData>(json, JsonOptions);
        if (data?.Profiles == null || data.Profiles.Count == 0)
            throw new InvalidOperationException("Invalid Race Lab profile file.");

        foreach (var p in data.Profiles)
        {
            if (IsBuiltInName(p.Name))
                p.Name = p.Name + " (imported)";
        }

        return data.Profiles;
    }

    private static List<RaceLabProfile> MergeWithBuiltIns(List<RaceLabProfile> stored)
    {
        var result = CreateBuiltInProfiles();
        foreach (var p in stored.Where(x => !IsBuiltInName(x.Name)))
            result.Add(p);
        return result;
    }

    private sealed class RaceLabSettingsData
    {
        public List<RaceLabProfile>? Profiles { get; set; }
    }

    internal sealed class RaceLabExportData
    {
        public string Format { get; set; } = "trowser-race-lab-profiles";
        public int Version { get; set; } = 1;
        public string? ExportedAt { get; set; }
        public List<RaceLabProfile>? Profiles { get; set; }
    }
}
