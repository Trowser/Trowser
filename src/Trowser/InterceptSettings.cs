using System.IO;
using System.Linq;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser;

/// <summary>
/// Persistent storage for mock rules and breakpoint (intercept) rules and their enabled state.
/// Stored as JSON in %APPDATA%\Trowser\intercept-settings.json.
/// Loaded into the initial tab on startup; saved whenever rules change in Network Interception dialog.
/// </summary>
public static class InterceptSettings
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
            return Path.Combine(dir, "intercept-settings.json");
        }
    }

    public static void LoadInto(BrowserTab tab)
    {
        if (tab == null) return;
        try
        {
            if (!File.Exists(SettingsPath)) return;
            var json = File.ReadAllText(SettingsPath);
            var data = JsonSerializer.Deserialize<InterceptSettingsData>(json, JsonOptions);
            if (data?.Mocks == null && data?.Breakpoints == null) return;

            if (data.Mocks != null)
            {
                foreach (var m in data.Mocks)
                {
                    tab.MockResponse(m.UrlPattern, m.StatusCode, m.Body, m.Method, m.Headers, m.DelayMs);
                    tab.SetMockRuleEnabled(m.UrlPattern, m.Method, m.Enabled);
                }
            }

            if (data.Breakpoints != null)
            {
                foreach (var b in data.Breakpoints)
                {
                    tab.AddInterceptRule(b.UrlPattern, b.Method, b.Silent);
                    tab.SetInterceptRuleEnabled(b.UrlPattern, b.Method, b.Enabled);
                }
            }
        }
        catch (Exception ex)
        {
            TrowserLog.Error("Failed to load intercept settings", ex);
        }
    }

    public static void SaveFrom(BrowserTab tab)
    {
        if (tab == null) return;
        try
        {
            var mocks = tab.GetMockRules();
            var breakpoints = tab.GetInterceptRules();
            var data = new InterceptSettingsData
            {
                Mocks = mocks.Select(m => new SavedMockRule
                {
                    UrlPattern = m.UrlPattern,
                    Method = m.Method,
                    StatusCode = m.StatusCode,
                    Body = m.Body,
                    Headers = m.Headers,
                    DelayMs = m.DelayMs,
                    Enabled = m.Enabled
                }).ToList(),
                Breakpoints = breakpoints.Select(b => new SavedInterceptRule
                {
                    UrlPattern = b.UrlPattern,
                    Method = b.Method,
                    Silent = b.Silent,
                    Enabled = b.Enabled
                }).ToList()
            };
            var json = JsonSerializer.Serialize(data, JsonOptions);
            File.WriteAllText(SettingsPath, json);
        }
        catch (Exception ex)
        {
            TrowserLog.Error("Failed to save intercept settings", ex);
        }
    }

    // ─── Import / Export ───

    internal static string ExportSingleMockToJson(Automation.MockRule rule)
    {
        var data = new InterceptExportData
        {
            ExportedAt = DateTime.UtcNow.ToString("o"),
            Mocks =
            [
                new ExportedMockRule
                {
                    UrlPattern = rule.UrlPattern,
                    Method = rule.Method,
                    StatusCode = rule.StatusCode,
                    Body = rule.Body,
                    Headers = rule.Headers?.Count > 0 ? rule.Headers : null,
                    DelayMs = rule.DelayMs,
                    Enabled = rule.Enabled
                }
            ],
            Breakpoints = []
        };
        return JsonSerializer.Serialize(data, JsonOptions);
    }

    internal static string ExportToJson(AutomationContext context)
    {
        var mocks = context.GetMockRules();
        var breakpoints = context.GetInterceptRules();
        var data = new InterceptExportData
        {
            ExportedAt = DateTime.UtcNow.ToString("o"),
            Mocks = mocks.Select(m => new ExportedMockRule
            {
                UrlPattern = m.UrlPattern,
                Method = m.Method,
                StatusCode = m.StatusCode,
                Body = m.Body,
                Headers = m.Headers?.Count > 0 ? m.Headers : null,
                DelayMs = m.DelayMs,
                Enabled = m.Enabled
            }).ToList(),
            Breakpoints = breakpoints.Select(b => new ExportedBreakpointRule
            {
                UrlPattern = b.UrlPattern,
                Method = b.Method,
                Silent = b.Silent,
                Enabled = b.Enabled
            }).ToList()
        };
        return JsonSerializer.Serialize(data, JsonOptions);
    }

    internal static (int mocks, int breakpoints) ImportFromJson(
        AutomationContext context, string json, bool clearExisting)
    {
        var data = JsonSerializer.Deserialize<InterceptExportData>(json, JsonOptions);
        if (data == null)
            throw new InvalidOperationException("Invalid intercept rules file.");

        if (clearExisting)
        {
            context.ClearMocks();
            context.ClearInterceptRules();
        }

        int mockCount = 0, bpCount = 0;

        if (data.Mocks != null)
        {
            foreach (var m in data.Mocks)
            {
                context.MockResponse(m.UrlPattern, m.StatusCode, m.Body, m.Method,
                    m.Headers, m.DelayMs);
                context.SetMockRuleEnabled(m.UrlPattern, m.Method, m.Enabled);
                mockCount++;
            }
        }

        if (data.Breakpoints != null)
        {
            foreach (var b in data.Breakpoints)
            {
                context.AddInterceptRule(b.UrlPattern, b.Method, b.Silent);
                context.SetInterceptRuleEnabled(b.UrlPattern, b.Method, b.Enabled);
                bpCount++;
            }
        }

        return (mockCount, bpCount);
    }

    // ─── Persistence (private) ───

    private class InterceptSettingsData
    {
        public List<SavedMockRule>? Mocks { get; set; }
        public List<SavedInterceptRule>? Breakpoints { get; set; }
    }

    private class SavedMockRule
    {
        public string UrlPattern { get; set; } = "";
        public string? Method { get; set; }
        public int StatusCode { get; set; }
        public string? Body { get; set; }
        public Dictionary<string, string>? Headers { get; set; }
        public int DelayMs { get; set; }
        public bool Enabled { get; set; } = true;
    }

    private class SavedInterceptRule
    {
        public string UrlPattern { get; set; } = "";
        public string? Method { get; set; }
        public bool Silent { get; set; }
        public bool Enabled { get; set; } = true;
    }

    // ─── Export data model (shared with dialog) ───

    internal class InterceptExportData
    {
        public string Format { get; set; } = "trowser-intercept-rules";
        public int Version { get; set; } = 1;
        public string? Description { get; set; }
        public string? ExportedAt { get; set; }
        public List<ExportedMockRule>? Mocks { get; set; }
        public List<ExportedBreakpointRule>? Breakpoints { get; set; }
    }

    internal class ExportedMockRule
    {
        public string UrlPattern { get; set; } = "";
        public string? Method { get; set; }
        public int StatusCode { get; set; }
        public string? Body { get; set; }
        public Dictionary<string, string>? Headers { get; set; }
        public int DelayMs { get; set; }
        public bool Enabled { get; set; } = true;
    }

    internal class ExportedBreakpointRule
    {
        public string UrlPattern { get; set; } = "";
        public string? Method { get; set; }
        public bool Silent { get; set; }
        public bool Enabled { get; set; } = true;
    }
}
