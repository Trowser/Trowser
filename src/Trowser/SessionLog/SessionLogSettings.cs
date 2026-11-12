using System.IO;
using System.Text.Json;

namespace Trowser.SessionLog;

/// <summary>
/// Persists session log preferences to %APPDATA%\Trowser\session-log-settings.json.
/// </summary>
public class SessionLogSettings
{
    public string? LogFilePath { get; set; }

    /// <summary>
    /// Whether session logging should be on. Persisted so Start/Stop survives restart.
    /// Opening the Journal panel from the UI opts in; restoring a previously open panel does not.
    /// </summary>
    public bool LoggingEnabled { get; set; }

    public bool LogBrowserActions { get; set; } = true;
    public bool LogNotes { get; set; } = true;
    public bool LogScriptOutput { get; set; } = true;
    public bool LogScreenshots { get; set; } = true;
    public bool LogMessages { get; set; } = true;
    public bool LogApiUsage { get; set; } = true;
    public bool LogLlmNotes { get; set; } = true;

    /// <summary>
    /// Mirror recorder narration ("Recordings in textual format") into the journal while recording,
    /// so the human-readable steps live alongside notes and bugs. Defaults on.
    /// </summary>
    public bool LogRecordings { get; set; } = true;

    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "Trowser", "session-log-settings.json");

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public static SessionLogSettings Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                var json = File.ReadAllText(SettingsPath);
                return JsonSerializer.Deserialize<SessionLogSettings>(json, JsonOptions) ?? new();
            }
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Failed to load session log settings: {ex.Message}");
        }
        return new SessionLogSettings();
    }

    public void Save()
    {
        try
        {
            var dir = Path.GetDirectoryName(SettingsPath)!;
            Directory.CreateDirectory(dir);
            var json = JsonSerializer.Serialize(this, JsonOptions);
            File.WriteAllText(SettingsPath, json);
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"Failed to save session log settings: {ex.Message}");
        }
    }
}
