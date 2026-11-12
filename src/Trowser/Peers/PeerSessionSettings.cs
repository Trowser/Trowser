using System.Diagnostics;
using System.IO;
using System.Text.Json;

namespace Trowser.Peers;

/// <summary>
/// Persistent peer session configuration for GUI testers.
/// Stored in %APPDATA%\Trowser\peer-sessions.json.
/// </summary>
public static class PeerSessionSettings
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private static string SettingsPath
    {
        get
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Trowser");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "peer-sessions.json");
        }
    }

    public static PeerSessionSettingsData Load()
    {
        try
        {
            if (!File.Exists(SettingsPath))
                return CreateDefault();
            var json = File.ReadAllText(SettingsPath);
            var data = JsonSerializer.Deserialize<PeerSessionSettingsData>(json, JsonOptions);
            return data ?? CreateDefault();
        }
        catch (Exception ex)
        {
            TrowserLog.Error("Failed to load peer session settings", ex);
            return CreateDefault();
        }
    }

    public static void Save(PeerSessionSettingsData data)
    {
        try
        {
            var json = JsonSerializer.Serialize(data, JsonOptions);
            File.WriteAllText(SettingsPath, json);
        }
        catch (Exception ex)
        {
            TrowserLog.Error("Failed to save peer session settings", ex);
        }
    }

    private static PeerSessionSettingsData CreateDefault() => new()
    {
        Peers =
        [
            new PeerSessionConfig { Name = "peer1", Port = 6924, SessionName = "peer1", UseForTests = false },
            new PeerSessionConfig { Name = "peer2", Port = 6925, SessionName = "peer2", UseForTests = false }
        ],
        NextPort = 6926
    };
}

public sealed class PeerSessionSettingsData
{
    public List<PeerSessionConfig> Peers { get; set; } = [];
    public int NextPort { get; set; } = 6926;
}

public sealed class PeerSessionConfig
{
    public string Name { get; set; } = "peer1";
    public int Port { get; set; } = 6924;
    public string ApiKey { get; set; } = "";
    public string SessionName { get; set; } = "peer1";
    /// <summary>When true and the peer is alive, BOLA and Live Authz Shadow replay it. Defaults to false.</summary>
    public bool UseForTests { get; set; }
}

public sealed class PeerSessionState
{
    public required PeerSessionConfig Config { get; init; }
    public Process? Process { get; set; }
    public bool Alive { get; set; }
    public string? RemoteSessionName { get; set; }
    public string? LastError { get; set; }
    public string BaseUrl => $"http://localhost:{Config.Port}";
}
