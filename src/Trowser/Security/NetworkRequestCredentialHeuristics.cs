using System.Text.Json;
using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Passive detection of plaintext credentials in captured HTTP request bodies (login, register, reset).
/// </summary>
public static class NetworkRequestCredentialHeuristics
{
    public sealed record RequestCredentialHit(
        string Kind,
        string FieldName,
        bool IsAuthEndpoint,
        bool IsHashed,
        string? Snippet);

    private static readonly Regex AuthUrlPattern = new(
        @"(?i)(/login|/signin|/sign-in|/auth|/register|/signup|/reset|forgot|recover|password|/session|/token|/oauth/token)",
        RegexOptions.Compiled);

    private static readonly string[] PasswordFieldNames =
    [
        "password", "passwd", "pwd", "pass", "newpassword", "new_password",
        "currentpassword", "current_password", "oldpassword", "old_password"
    ];

    public static List<RequestCredentialHit> DetectPlaintextCredentials(
        string? url,
        string? method,
        string? requestBody,
        string? contentType = null)
    {
        var hits = new List<RequestCredentialHit>();
        if (string.IsNullOrWhiteSpace(requestBody)) return hits;
        if (method is not ("POST" or "PUT" or "PATCH")) return hits;

        // LLM chat/completions bodies often embed the word "password" inside prompt text —
        // not credential submission. Skip credential heuristics for chat-shaped JSON.
        if (LooksLikeLlmChatBody(requestBody, contentType))
            return hits;

        var isAuthEndpoint = IsAuthRelatedUrl(url);
        var body = requestBody.Length > 131_072 ? requestBody[..131_072] : requestBody;

        if (body.TrimStart().StartsWith('{') || body.TrimStart().StartsWith('['))
        {
            try
            {
                using var doc = JsonDocument.Parse(body);
                CollectFromJsonElement(doc.RootElement, "", hits, isAuthEndpoint);
            }
            catch
            {
                ScanWithRegex(body, hits, isAuthEndpoint);
            }
        }
        else if (contentType?.Contains("form", StringComparison.OrdinalIgnoreCase) == true
                 || body.Contains('='))
        {
            ScanFormEncoded(body, hits, isAuthEndpoint);
        }
        else
        {
            ScanWithRegex(body, hits, isAuthEndpoint);
        }

        return hits;
    }

    /// <summary>True for OpenAI-style messages objects/arrays used by LLM red-team probes.</summary>
    public static bool LooksLikeLlmChatBody(string? body, string? contentType = null)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        var t = body.TrimStart();
        if (!(t.StartsWith('{') || t.StartsWith('['))) return false;

        var ct = contentType ?? "";
        var jsonCt = string.IsNullOrEmpty(ct) || ct.Contains("json", StringComparison.OrdinalIgnoreCase);
        if (!jsonCt) return false;

        if (body.Contains("\"messages\"", StringComparison.OrdinalIgnoreCase)
            && body.Contains("\"role\"", StringComparison.OrdinalIgnoreCase))
            return true;
        if (t.StartsWith('[')
            && body.Contains("\"role\"", StringComparison.OrdinalIgnoreCase)
            && body.Contains("\"content\"", StringComparison.OrdinalIgnoreCase))
            return true;
        if (body.Contains("\"prompt\"", StringComparison.OrdinalIgnoreCase)
            && (body.Contains("\"model\"", StringComparison.OrdinalIgnoreCase)
                || body.Contains("\"temperature\"", StringComparison.OrdinalIgnoreCase)))
            return true;
        return false;
    }

    private static void CollectFromJsonElement(
        JsonElement el,
        string path,
        List<RequestCredentialHit> hits,
        bool isAuthEndpoint)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in el.EnumerateObject())
                {
                    var childPath = string.IsNullOrEmpty(path) ? prop.Name : $"{path}.{prop.Name}";
                    if (IsPasswordFieldName(prop.Name) && prop.Value.ValueKind == JsonValueKind.String)
                        AddHit(hits, prop.Name, prop.Value.GetString(), isAuthEndpoint);
                    else if (prop.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array)
                        CollectFromJsonElement(prop.Value, childPath, hits, isAuthEndpoint);
                }
                break;
            case JsonValueKind.Array:
                var i = 0;
                foreach (var item in el.EnumerateArray())
                {
                    CollectFromJsonElement(item, $"{path}[{i}]", hits, isAuthEndpoint);
                    i++;
                }
                break;
        }
    }

    private static void ScanFormEncoded(string body, List<RequestCredentialHit> hits, bool isAuthEndpoint)
    {
        foreach (var part in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0) continue;
            var name = Uri.UnescapeDataString(part[..eq]);
            var value = Uri.UnescapeDataString(part[(eq + 1)..]);
            if (IsPasswordFieldName(name))
                AddHit(hits, name, value, isAuthEndpoint);
        }
    }

    private static void ScanWithRegex(string body, List<RequestCredentialHit> hits, bool isAuthEndpoint)
    {
        foreach (Match m in Regex.Matches(body,
                     @"""(?:password|passwd|pwd|newPassword|currentPassword)""\s*:\s*""([^""]{2,200})""",
                     RegexOptions.IgnoreCase, TimeSpan.FromSeconds(2)))
        {
            AddHit(hits, "password", m.Groups[1].Value, isAuthEndpoint);
        }
    }

    private static void AddHit(List<RequestCredentialHit> hits, string fieldName, string? value, bool isAuthEndpoint)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        var hashed = LooksLikeStoredHash(value);
        hits.Add(new RequestCredentialHit(
            hashed ? "hashed-password-field" : "plaintext-password-in-request",
            fieldName,
            isAuthEndpoint,
            hashed,
            Redact(value)));
    }

    public static bool IsAuthRelatedUrl(string? url) =>
        !string.IsNullOrEmpty(url) && AuthUrlPattern.IsMatch(url);

    private static bool IsPasswordFieldName(string name)
    {
        var lower = name.ToLowerInvariant();
        return PasswordFieldNames.Any(p => lower.Equals(p, StringComparison.OrdinalIgnoreCase)
            || lower.Contains("password", StringComparison.OrdinalIgnoreCase));
    }

    public static bool LooksLikeStoredHash(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        if (value.StartsWith("$2", StringComparison.Ordinal)
            || value.StartsWith("$argon2", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("{SHA}", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("$pbkdf2", StringComparison.OrdinalIgnoreCase))
            return true;
        return value.Length >= 32
               && Regex.IsMatch(value, @"^[0-9a-f]{32,128}$", RegexOptions.IgnoreCase);
    }

    private static string Redact(string value) =>
        value.Length <= 2 ? "**" : value[..1] + new string('*', Math.Min(value.Length - 1, 8));
}
