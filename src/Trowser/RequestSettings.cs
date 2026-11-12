using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Trowser;

/// <summary>
/// Persistent storage for saved HTTP requests.
/// Stored as JSON in %APPDATA%\Trowser\saved-requests.json.
/// </summary>
public static class RequestSettings
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
            return Path.Combine(dir, "saved-requests.json");
        }
    }

    public static List<SavedHttpRequest> Load()
    {
        try
        {
            if (!File.Exists(SettingsPath)) return new List<SavedHttpRequest>();
            var json = File.ReadAllText(SettingsPath);
            var data = JsonSerializer.Deserialize<RequestSettingsData>(json, JsonOptions);
            return data?.Requests ?? new List<SavedHttpRequest>();
        }
        catch (Exception ex)
        {
            TrowserLog.Error("Failed to load saved requests", ex);
            return new List<SavedHttpRequest>();
        }
    }

    public static void Save(List<SavedHttpRequest> requests)
    {
        try
        {
            var data = new RequestSettingsData { Requests = requests };
            var json = JsonSerializer.Serialize(data, JsonOptions);
            File.WriteAllText(SettingsPath, json);
        }
        catch (Exception ex)
        {
            TrowserLog.Error("Failed to save requests", ex);
        }
    }

    internal static string ExportToJson(List<SavedHttpRequest> requests)
    {
        var data = new RequestExportData
        {
            ExportedAt = DateTime.UtcNow.ToString("o"),
            Requests = requests
        };
        return JsonSerializer.Serialize(data, JsonOptions);
    }

    internal static List<SavedHttpRequest> ImportFromJson(string json)
    {
        var data = JsonSerializer.Deserialize<RequestExportData>(json, JsonOptions);
        if (data?.Requests == null)
            throw new InvalidOperationException("Invalid saved requests file.");
        return data.Requests;
    }

    // ─── Data models ───

    private class RequestSettingsData
    {
        public List<SavedHttpRequest>? Requests { get; set; }
    }

    internal class RequestExportData
    {
        public string Format { get; set; } = "trowser-saved-requests";
        public int Version { get; set; } = 1;
        public string? ExportedAt { get; set; }
        public List<SavedHttpRequest>? Requests { get; set; }
    }
}

public class SavedHttpRequest
{
    public string Name { get; set; } = "";

    /// <summary>"compose" or "raw". Missing values are compose (requests saved before the Raw tab).</summary>
    public string? EditorTab { get; set; }

    public string Url { get; set; } = "";
    public string Method { get; set; } = "GET";

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? Headers { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Body { get; set; }

    /// <summary>Raw tab only: request line as written, including the HTTP version token.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RequestLine { get; set; }

    /// <summary>Raw tab only: header block as written (duplicates and order kept).</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? HeaderText { get; set; }

    public bool IsRaw => string.Equals(EditorTab, "raw", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Maps the HTTP Request Editor between the Compose fields and the Raw fields,
/// and builds a save payload for whichever tab is active.
/// </summary>
internal static class RequestEditorMapping
{
    public static SavedHttpRequest FromCompose(
        string name, string url, string method, Dictionary<string, string> headers, string body)
    {
        return new SavedHttpRequest
        {
            Name = name,
            EditorTab = "compose",
            Url = url.Trim(),
            Method = string.IsNullOrWhiteSpace(method) ? "GET" : method.Trim().ToUpperInvariant(),
            Headers = headers.Count > 0 ? headers : null,
            Body = string.IsNullOrWhiteSpace(body) ? null : body
        };
    }

    public static SavedHttpRequest FromRaw(
        string name, string targetUrl, string requestLine, string headerText, string body)
    {
        var line = requestLine.Trim();
        return new SavedHttpRequest
        {
            Name = name,
            EditorTab = "raw",
            Url = targetUrl.Trim(),
            Method = MethodFromRequestLine(line),
            RequestLine = line.Length == 0 ? null : line,
            HeaderText = headerText.Length == 0 ? null : headerText,
            Body = body.Length == 0 ? null : body
        };
    }

    public static string ComposeUrl(string targetUrl, string requestLine)
    {
        var target = targetUrl.Trim();
        var requestTarget = RequestTarget(requestLine);
        if (string.IsNullOrEmpty(requestTarget) || requestTarget == "*")
            return target;

        if (Uri.TryCreate(requestTarget, UriKind.Absolute, out var absolute) &&
            (absolute.Scheme == Uri.UriSchemeHttp || absolute.Scheme == Uri.UriSchemeHttps))
            return absolute.ToString();

        if (requestTarget.StartsWith('/') &&
            Uri.TryCreate(target, UriKind.Absolute, out var baseUri) &&
            (baseUri.Scheme == Uri.UriSchemeHttp || baseUri.Scheme == Uri.UriSchemeHttps))
        {
            return new Uri(baseUri, requestTarget).ToString();
        }

        return target;
    }

    public static string FallbackRequestLine(string? method, string url)
    {
        var verb = string.IsNullOrWhiteSpace(method) ? "GET" : method.Trim();
        if (Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri))
            return Trowser.Security.RawHttpClient.DefaultRequestLine(verb, uri);
        return $"{verb} / HTTP/1.1";
    }

    public static string DefaultName(string method, string url, string? requestLine)
    {
        var verb = string.IsNullOrWhiteSpace(method) ? "GET" : method.Trim().ToUpperInvariant();
        if (!string.IsNullOrWhiteSpace(requestLine))
        {
            var requestTarget = RequestTarget(requestLine);
            if (!string.IsNullOrEmpty(requestTarget))
                return $"{verb} {requestTarget}";
        }

        var trimmed = url.Trim();
        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
            return $"{verb} {uri.PathAndQuery}";
        return $"{verb} {trimmed}";
    }

    public static string MethodFromRequestLine(string requestLine)
    {
        var line = requestLine.Trim();
        if (line.Length == 0) return "GET";
        var space = line.IndexOf(' ');
        var token = space > 0 ? line[..space] : line;
        return token.Length == 0 ? "GET" : token.ToUpperInvariant();
    }

    private static string RequestTarget(string requestLine)
    {
        var line = requestLine.Trim();
        if (line.Length == 0) return "";
        var first = line.IndexOf(' ');
        if (first < 0 || first == line.Length - 1) return "";
        var rest = line[(first + 1)..].Trim();
        var second = rest.IndexOf(' ');
        return second < 0 ? rest : rest[..second];
    }
}
