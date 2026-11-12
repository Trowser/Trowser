using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Trowser.Security;

public enum AuthzBodyMatchStrategy
{
    Exact,
    NormalizedJson,
    Structural,
    HtmlMain
}

public sealed class AuthzBodyMatchOptions
{
    public AuthzBodyMatchStrategy Strategy { get; init; } = AuthzBodyMatchStrategy.Exact;
    public List<string> IgnoreFields { get; init; } = [];

    public static AuthzBodyMatchOptions Parse(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
            return new AuthzBodyMatchOptions();

        var bodyMatch = root.TryGetProperty("bodyMatch", out var bodyMatchEl) ? bodyMatchEl : default;
        if (bodyMatch.ValueKind == JsonValueKind.Object)
            return ParseBodyMatchObject(bodyMatch);

        var ignoreFields = ReadStringArray(root, "ignoreFields");
        if (root.TryGetProperty("structuralMatch", out var structural) &&
            structural.ValueKind is JsonValueKind.True)
        {
            return new AuthzBodyMatchOptions
            {
                Strategy = AuthzBodyMatchStrategy.Structural,
                IgnoreFields = ignoreFields
            };
        }

        if (root.TryGetProperty("matchingStrategy", out var strategyEl) && strategyEl.ValueKind == JsonValueKind.String)
        {
            return new AuthzBodyMatchOptions
            {
                Strategy = ParseStrategy(strategyEl.GetString()),
                IgnoreFields = ignoreFields
            };
        }

        return ignoreFields.Count > 0
            ? new AuthzBodyMatchOptions
            {
                Strategy = AuthzBodyMatchStrategy.NormalizedJson,
                IgnoreFields = ignoreFields
            }
            : new AuthzBodyMatchOptions();
    }

    public static AuthzBodyMatchOptions ParseBodyMatchObject(JsonElement el)
    {
        if (el.ValueKind != JsonValueKind.Object)
            return new AuthzBodyMatchOptions();

        var strategy = AuthzBodyMatchStrategy.Exact;
        if (el.TryGetProperty("strategy", out var strategyEl) && strategyEl.ValueKind == JsonValueKind.String)
            strategy = ParseStrategy(strategyEl.GetString());
        else if (el.TryGetProperty("matchingStrategy", out var legacyStrategy) && legacyStrategy.ValueKind == JsonValueKind.String)
            strategy = ParseStrategy(legacyStrategy.GetString());
        else if (el.TryGetProperty("structuralMatch", out var structural) &&
                 structural.ValueKind is JsonValueKind.True)
            strategy = AuthzBodyMatchStrategy.Structural;

        var ignoreFields = ReadStringArray(el, "ignoreFields");

        return new AuthzBodyMatchOptions { Strategy = strategy, IgnoreFields = ignoreFields };
    }

    private static List<string> ReadStringArray(JsonElement el, string property)
    {
        var values = new List<string>();
        if (!el.TryGetProperty(property, out var arr) || arr.ValueKind != JsonValueKind.Array)
            return values;

        foreach (var item in arr.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String && item.GetString() is { } value)
                values.Add(value);
        }

        return values;
    }

    private static AuthzBodyMatchStrategy ParseStrategy(string? value) => value?.Trim().ToLowerInvariant() switch
    {
        "normalizedjson" or "normalized-json" or "normalized_json" or "intelligent" => AuthzBodyMatchStrategy.NormalizedJson,
        "structural" or "structure" => AuthzBodyMatchStrategy.Structural,
        "htmlmain" or "html-main" or "html_main" => AuthzBodyMatchStrategy.HtmlMain,
        _ => AuthzBodyMatchStrategy.Exact
    };
}

/// <summary>
/// Shared response-body comparison for authz/diff and authz/boundary.
/// </summary>
public static class AuthzBodyMatcher
{
    private static readonly string[] DefaultIgnoreFields =
    [
        "timestamp", "updatedAt", "updated_at", "createdAt", "created_at", "modifiedAt", "modified_at",
        "requestId", "request_id", "correlationId", "correlation_id", "sessionId", "session_id",
        "traceId", "trace_id", "cursor", "nextPageToken", "next_page_token", "nextToken", "next_token",
        "generatedAt", "generated_at", "date", "datetime", "serverTime", "server_time"
    ];

    public static string ComputeMatchHash(string body, AuthzBodyMatchOptions options)
    {
        var fingerprint = ComputeFingerprint(body, options);
        return AuthzComparisonService.ComputeShortHash(fingerprint);
    }

    public static bool BodiesMatch(string left, string right, AuthzBodyMatchOptions options) =>
        string.Equals(ComputeFingerprint(left, options), ComputeFingerprint(right, options), StringComparison.Ordinal);

    /// <summary>
    /// True when two JSON bodies match once volatile fields and object ids are removed.
    /// A save that echoes a new id is the same document; a create that also changes the owner is not.
    /// </summary>
    public static bool BodiesMatchIgnoringIdentityFields(string? left, string? right)
    {
        if (string.IsNullOrEmpty(left) || string.IsNullOrEmpty(right)) return false;
        if (!LooksLikeJson(left) || !LooksLikeJson(right)) return false;

        var ignore = new List<string>(DefaultIgnoreFields)
        {
            "id", "_id", "uuid", "guid", "uid"
        };
        return BodiesMatch(left, right, new AuthzBodyMatchOptions
        {
            Strategy = AuthzBodyMatchStrategy.NormalizedJson,
            IgnoreFields = ignore
        });
    }

    /// <summary>
    /// Tolerant compare for non-JSON/HTML bodies, where byte-exact comparison false-negatives on
    /// rotating nonces/CSRF tokens/timestamps embedded in markup. Treats two bodies as "the same"
    /// when their length difference is within <c>max(minToleranceBytes, ratio * longer length)</c>.
    /// Returns <c>false</c> (defer to a stricter strategy) when either body looks like JSON —
    /// this is intentionally a fallback for opaque/HTML payloads, not a replacement for
    /// <see cref="AuthzBodyMatchStrategy.NormalizedJson"/>.
    /// </summary>
    public static bool NonJsonBodiesMatchWithLengthTolerance(
        string left,
        string right,
        double toleranceRatio = 0.02,
        int minToleranceBytes = 64)
    {
        if (LooksLikeJson(left) || LooksLikeJson(right))
            return false;

        var longer = Math.Max(left.Length, right.Length);
        var tolerance = Math.Max(minToleranceBytes, (int)Math.Ceiling(longer * toleranceRatio));
        return Math.Abs(left.Length - right.Length) <= tolerance;
    }

    private static bool LooksLikeJson(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return false;
        var trimmed = body.TrimStart();
        return trimmed.Length > 0 && (trimmed[0] == '{' || trimmed[0] == '[');
    }

    public static string ComputeFingerprint(string body, AuthzBodyMatchOptions options)
    {
        if (options.Strategy == AuthzBodyMatchStrategy.HtmlMain)
            return ExtractHtmlMainFingerprint(body);

        if (options.Strategy == AuthzBodyMatchStrategy.Exact)
            return body;

        if (!TryParseJson(body, out var doc))
            return body;

        using (doc)
        {
            return options.Strategy switch
            {
                AuthzBodyMatchStrategy.NormalizedJson => CanonicalizeJson(doc.RootElement, ResolveIgnoreFields(options)),
                AuthzBodyMatchStrategy.Structural => BuildStructuralFingerprint(doc.RootElement),
                _ => body
            };
        }
    }

    private static HashSet<string> ResolveIgnoreFields(AuthzBodyMatchOptions options)
    {
        if (options.IgnoreFields.Count > 0)
            return new HashSet<string>(options.IgnoreFields, StringComparer.OrdinalIgnoreCase);

        if (options.Strategy == AuthzBodyMatchStrategy.NormalizedJson)
            return new HashSet<string>(DefaultIgnoreFields, StringComparer.OrdinalIgnoreCase);

        return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    }

    private static bool TryParseJson(string body, out JsonDocument doc)
    {
        doc = null!;
        if (string.IsNullOrWhiteSpace(body))
            return false;

        var trimmed = body.TrimStart();
        if (trimmed.Length == 0 || (trimmed[0] != '{' && trimmed[0] != '['))
            return false;

        try
        {
            doc = JsonDocument.Parse(body);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string CanonicalizeJson(JsonElement root, HashSet<string> ignoreFields)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            WriteCanonicalValue(writer, root, ignoreFields, "");
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void WriteCanonicalValue(Utf8JsonWriter writer, JsonElement element, HashSet<string> ignoreFields, string path)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
                {
                    var childPath = string.IsNullOrEmpty(path) ? property.Name : $"{path}.{property.Name}";
                    if (ShouldIgnoreField(property.Name, childPath, ignoreFields))
                        continue;

                    writer.WritePropertyName(property.Name);
                    WriteCanonicalValue(writer, property.Value, ignoreFields, childPath);
                }
                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
                writer.WriteStartArray();
                var index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    WriteCanonicalValue(writer, item, ignoreFields, $"{path}[{index}]");
                    index++;
                }
                writer.WriteEndArray();
                break;

            case JsonValueKind.String:
                writer.WriteStringValue(element.GetString());
                break;

            case JsonValueKind.Number:
                writer.WriteRawValue(element.GetRawText());
                break;

            case JsonValueKind.True:
                writer.WriteBooleanValue(true);
                break;

            case JsonValueKind.False:
                writer.WriteBooleanValue(false);
                break;

            case JsonValueKind.Null:
                writer.WriteNullValue();
                break;

            default:
                writer.WriteRawValue(element.GetRawText());
                break;
        }
    }

    private static bool ShouldIgnoreField(string name, string fullPath, HashSet<string> ignoreFields)
    {
        if (ignoreFields.Count == 0)
            return false;

        return ignoreFields.Contains(fullPath) || ignoreFields.Contains(name);
    }

    private static string BuildStructuralFingerprint(JsonElement element, string path = "")
    {
        var sb = new StringBuilder();
        AppendStructuralFingerprint(sb, element, path);
        return sb.ToString();
    }

    private static void AppendStructuralFingerprint(StringBuilder sb, JsonElement element, string path)
    {
        var label = string.IsNullOrEmpty(path) ? "$" : path;
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                sb.Append(label).Append(':').Append("object{");
                foreach (var property in element.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
                {
                    AppendStructuralFingerprint(sb, property.Value, string.IsNullOrEmpty(path) ? property.Name : $"{path}.{property.Name}");
                }
                sb.Append('}');
                break;

            case JsonValueKind.Array:
                sb.Append(label).Append(':').Append("array[");
                var index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    if (index > 0) sb.Append(',');
                    AppendStructuralFingerprint(sb, item, $"{path}[{index}]");
                    index++;
                }
                sb.Append(']');
                break;

            default:
                sb.Append(label).Append(':').Append(element.ValueKind.ToString().ToLowerInvariant()).Append(';');
                break;
        }
    }

    private static string ExtractHtmlMainFingerprint(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return body;

        var main = ExtractHtmlRegion(body, "main");
        if (!string.IsNullOrWhiteSpace(main))
            return CollapseHtmlText(main);

        var roleMain = ExtractHtmlRoleRegion(body, "main");
        if (!string.IsNullOrWhiteSpace(roleMain))
            return CollapseHtmlText(roleMain);

        return CollapseHtmlText(StripHtmlTags(body));
    }

    private static string? ExtractHtmlRegion(string html, string tagName)
    {
        var pattern = $@"<{tagName}\b[^>]*>(.*?)</{tagName}>";
        var m = Regex.Match(html, pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline);
        return m.Success ? m.Groups[1].Value : null;
    }

    private static string? ExtractHtmlRoleRegion(string html, string role)
    {
        var pattern = $@"<([a-z0-9]+)\b[^>]*\brole\s*=\s*[""']?{role}[""']?[^>]*>(.*?)</\1>";
        var m = Regex.Match(html, pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline);
        return m.Success ? m.Groups[2].Value : null;
    }

    private static string StripHtmlTags(string html) =>
        Regex.Replace(html, "<[^>]+>", " ", RegexOptions.Singleline);

    private static string CollapseHtmlText(string text) =>
        Regex.Replace(text, @"\s+", " ").Trim();
}
