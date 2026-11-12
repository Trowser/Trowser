using System.IO;
using System.Text;
using System.Text.Json;

namespace Trowser.Security;

/// <summary>
/// JSON request-body marker substitution using <see cref="Utf8JsonWriter"/> so injected
/// payloads (quotes, backslashes, SQL fragments) are serialized exactly once — avoids
/// double-escaping from <see cref="JsonNode.ToJsonString"/> re-serialization.
/// </summary>
public static class InjectionJsonBody
{
    public static string SubstituteMarkers(string? jsonTemplate, string injectValue)
    {
        if (string.IsNullOrEmpty(jsonTemplate)) return jsonTemplate ?? "";
        var trimmed = jsonTemplate.TrimStart();
        if (!trimmed.StartsWith('{') && !trimmed.StartsWith('['))
            return RequestMarkerSubstitute.ReplaceAll(jsonTemplate, injectValue);

        try
        {
            using var doc = JsonDocument.Parse(jsonTemplate);
            using var ms = new MemoryStream();
            using var writer = new Utf8JsonWriter(ms);
            WriteElement(writer, doc.RootElement, injectValue);
            writer.Flush();
            return Encoding.UTF8.GetString(ms.ToArray());
        }
        catch (JsonException)
        {
            return RequestMarkerSubstitute.ReplaceAll(jsonTemplate, injectValue);
        }
    }

    /// <summary>Replace the first injectable string field with <paramref name="marker"/>.</summary>
    public static string InjectMarkerIntoFirstStringField(string json, string marker, string? preferredField = null)
    {
        using var doc = JsonDocument.Parse(json);
        using var ms = new MemoryStream();
        using var writer = new Utf8JsonWriter(ms);
        writer.WriteStartObject();
        var replaced = false;
        foreach (var prop in doc.RootElement.EnumerateObject())
        {
            writer.WritePropertyName(prop.Name);
            if (!replaced && prop.Value.ValueKind == JsonValueKind.String
                && (preferredField == null || prop.Name.Equals(preferredField, StringComparison.OrdinalIgnoreCase)))
            {
                writer.WriteStringValue(marker);
                replaced = true;
            }
            else
                prop.Value.WriteTo(writer);
        }

        if (!replaced && preferredField != null)
        {
            writer.WriteString(preferredField, marker);
            replaced = true;
        }

        writer.WriteEndObject();
        writer.Flush();
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    private static void WriteElement(Utf8JsonWriter writer, JsonElement el, string injectValue)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var prop in el.EnumerateObject())
                {
                    writer.WritePropertyName(prop.Name);
                    WriteElement(writer, prop.Value, injectValue);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in el.EnumerateArray())
                    WriteElement(writer, item, injectValue);
                writer.WriteEndArray();
                break;
            case JsonValueKind.String:
                var s = el.GetString() ?? "";
                writer.WriteStringValue(RequestMarkerSubstitute.ReplaceAll(s, injectValue));
                break;
            default:
                el.WriteTo(writer);
                break;
        }
    }
}
