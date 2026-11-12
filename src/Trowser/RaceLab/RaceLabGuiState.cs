using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Trowser.Security.RaceLab;

namespace Trowser.RaceLab;

/// <summary>Last Race Lab dialog state (%APPDATA%\Trowser\race-lab-gui.json).</summary>
public static class RaceLabGuiState
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    private static string FilePath
    {
        get
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Trowser");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "race-lab-gui.json");
        }
    }

    public sealed class State
    {
        public string SelectedPreset { get; set; } = "Hammer";
        public List<RaceLabRequest> Requests { get; set; } = [];
        public RaceLabParameters Parameters { get; set; } = RaceLabParameters.ForMode(RaceLabMode.Hammer);
    }

    public static State Load()
    {
        try
        {
            if (!File.Exists(FilePath))
                return new State();

            var json = File.ReadAllText(FilePath);
            return JsonSerializer.Deserialize<State>(json, JsonOptions) ?? new State();
        }
        catch (Exception ex)
        {
            TrowserLog.Error("Failed to load Race Lab GUI state", ex);
            return new State();
        }
    }

    public static void Save(State state)
    {
        try
        {
            var json = JsonSerializer.Serialize(state, JsonOptions);
            File.WriteAllText(FilePath, json);
        }
        catch (Exception ex)
        {
            TrowserLog.Error("Failed to save Race Lab GUI state", ex);
        }
    }
}
