using System.IO;
using System.Text.Json;

namespace Trowser;

/// <summary>
/// Persistent GUI chrome preferences: main window placement and panel visibility.
/// Stored as JSON in %APPDATA%\Trowser\user-gui.json.
/// Deliberately separate from browser "memory" (WebView2 session folders) and from
/// feature settings (settings.json / api-user.json).
/// </summary>
public class GuiSettings
{
    /// <summary>Restored (non-maximized) window position. Null until the user has run Trowser once.</summary>
    public double? WindowLeft { get; set; }
    public double? WindowTop { get; set; }
    public double? WindowWidth { get; set; }
    public double? WindowHeight { get; set; }

    /// <summary>Whether the window should open maximized. Defaults to true to match Trowser's original behavior.</summary>
    public bool WindowMaximized { get; set; } = true;

    /// <summary>AI Assistant chat panel visibility. Defaults to on for first-time users.</summary>
    public bool ChatPanelVisible { get; set; } = true;

    /// <summary>Script console panel visibility. Defaults to on for first-time users.</summary>
    public bool ScriptPanelVisible { get; set; } = true;

    /// <summary>Left-docked Journal panel visibility. Defaults to off (opt in via Ctrl+J / View menu).</summary>
    public bool JournalPanelVisible { get; set; }

    /// <summary>
    /// Fraction of the horizontal content area given to the left-docked Journal panel (0–1).
    /// Stored as a proportion so splits scale on different screen sizes.
    /// </summary>
    public double JournalPanelFraction { get; set; } = 0.22;

    /// <summary>
    /// Fraction of the horizontal content area given to the AI chat panel (0–1).
    /// Stored as a proportion, not pixels, so splits scale on different screen sizes.
    /// Default 0.25 matches the original 3:1 browser-to-chat star ratio.
    /// </summary>
    public double ChatPanelFraction { get; set; } = 0.25;

    /// <summary>
    /// Fraction of the vertical content area given to the script console (0–1).
    /// Default 0.25 matches the original 3:1 browser-to-console star ratio.
    /// </summary>
    public double ScriptPanelFraction { get; set; } = 0.25;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private static string FilePath
    {
        get
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Trowser");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "user-gui.json");
        }
    }

    public static GuiSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                var json = File.ReadAllText(FilePath);
                return JsonSerializer.Deserialize<GuiSettings>(json, JsonOptions) ?? new GuiSettings();
            }
        }
        catch (Exception ex) { TrowserLog.Error("Failed to load GUI settings", ex); }
        return new GuiSettings();
    }

    public void Save()
    {
        try
        {
            var json = JsonSerializer.Serialize(this, JsonOptions);
            File.WriteAllText(FilePath, json);
        }
        catch (Exception ex) { TrowserLog.Error("Failed to save GUI settings", ex); }
    }
}
