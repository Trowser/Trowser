using System.IO;
using System.Text.Json;
using Trowser.Api;
using Trowser.Automation;

namespace Trowser;

/// <summary>
/// Persistent user preferences for the local REST API (MCP) server.
/// Stored as JSON in %APPDATA%\Trowser\api-user.json
/// </summary>
public class ApiUserSettings
{
    /// <summary>When true, clients must pass the bearer token to call the API (when a key is configured).</summary>
    public bool RestApiKeyRequired { get; set; } = true;

    /// <summary>When true, <see cref="RestApiKey"/> is saved and restored on the next run.</summary>
    public bool KeepApiKeyForNextSession { get; set; }

    /// <summary>Last REST API key; used only when <see cref="KeepApiKeyForNextSession"/> is true.</summary>
    public string RestApiKey { get; set; } = "";

    /// <summary>Whether the user left the status-bar REST server running (wants it on at next launch).</summary>
    public bool ApiServerEnabled { get; set; }

    /// <summary>Navigation scope patterns (comma-separated). <c>*.*</c> means no restrictions. CLI <c>--scope</c> overrides for that run.</summary>
    public string NavigationScope { get; set; } = "*.*";

    /// <summary>Allow <c>file://</c> URLs when scope permits (default false — LLM safety).</summary>
    public bool AllowFileUrls { get; set; }

    /// <summary>Whether safe mode is on. CLI <c>--safe</c> overrides for that run.</summary>
    public bool SafeMode { get; set; }

    /// <summary>REST API port. CLI <c>--api-port</c> overrides for that run.</summary>
    public int ApiPort { get; set; } = 6923;

    /// <summary>
    /// Default tool pack for external <c>POST /mcp</c> clients when no
    /// <c>?mode=</c> or <c>X-Trowser-Mcp-Mode</c> override is present.
    /// <see cref="ExternalMcpMode.Core"/> (default) is token-efficient;
    /// <see cref="ExternalMcpMode.Security"/> is the complete MCP surface
    /// (legacy <c>full</c> is an alias of security).
    /// Copied Settings configs use Core (<c>?mode=core</c>).
    /// </summary>
    public ExternalMcpMode ExternalMcpMode { get; set; } = ExternalMcpMode.Core;

    /// <summary>
    /// First REST/MCP browser mutation: stay on the active tab (handoff) or prefer a dedicated agent tab.
    /// </summary>
    public AgentTabPolicy AgentTabPolicy { get; set; } = AgentTabPolicy.StayOnActive;

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
            return Path.Combine(dir, "api-user.json");
        }
    }

    public static ApiUserSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                var json = File.ReadAllText(FilePath);
                return JsonSerializer.Deserialize<ApiUserSettings>(json, JsonOptions) ?? new ApiUserSettings();
            }
        }
        catch (Exception ex) { TrowserLog.Error("Failed to load API user settings", ex); }
        return new ApiUserSettings();
    }

    public void Save()
    {
        try
        {
            var json = JsonSerializer.Serialize(this, JsonOptions);
            File.WriteAllText(FilePath, json);
        }
        catch (Exception ex) { TrowserLog.Error("Failed to save API user settings", ex); }
    }
}
