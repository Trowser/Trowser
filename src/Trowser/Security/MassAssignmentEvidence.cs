using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Body parsing and match rules for the mass-assignment probe.
/// A hit requires the injected value on that field (JSON property, form pair, or control),
/// not a short token such as "true" or "2" appearing somewhere in an HTML page.
/// </summary>
public static class MassAssignmentEvidence
{
    private static readonly Regex HtmlControl = new(
        @"<(input|textarea)\b[^>]*>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex Attr = new(
        @"\b(name|value)\s*=\s*(?:""([^""]*)""|'([^']*)'|([^\s>]+))",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public sealed class BodyModel
    {
        internal BodyModel(JsonObject? json, List<KeyValuePair<string, string>>? form)
        {
            Json = json;
            Form = form;
        }

        public JsonObject? Json { get; }
        public List<KeyValuePair<string, string>>? Form { get; }
        public string Kind => Json != null ? "json" : "form";
        public string ContentType => Json != null
            ? "application/json"
            : "application/x-www-form-urlencoded";

        public IEnumerable<string> FieldNames =>
            Json != null
                ? Json.Select(p => p.Key)
                : Form!.Select(p => p.Key);

        public string Serialize()
        {
            if (Json != null)
                return Json.ToJsonString();

            return string.Join("&", Form!.Select(p =>
                $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
        }

        public BodyModel WithInjection(string field, JsonNode jsonValue, string display)
        {
            if (Json != null)
            {
                var clone = JsonNode.Parse(Json.ToJsonString())!.AsObject();
                clone[field] = JsonNode.Parse(jsonValue.ToJsonString());
                return new BodyModel(clone, null);
            }

            var fields = new List<KeyValuePair<string, string>>(Form!);
            var replaced = false;
            for (var i = 0; i < fields.Count; i++)
            {
                if (!fields[i].Key.Equals(field, StringComparison.OrdinalIgnoreCase))
                    continue;
                fields[i] = new KeyValuePair<string, string>(fields[i].Key, display);
                replaced = true;
            }

            if (!replaced)
                fields.Add(new KeyValuePair<string, string>(field, display));
            return new BodyModel(null, fields);
        }
    }

    public static bool TryPrepare(string? raw, string? contentType, out BodyModel? model, out string? error)
    {
        model = null;
        error = null;
        if (string.IsNullOrWhiteSpace(raw))
        {
            error = "Mass assignment scan needs a JSON object or application/x-www-form-urlencoded body.";
            return false;
        }

        var media = MediaType(contentType);
        var trimmed = raw.Trim();
        if (media is "multipart/form-data" || trimmed.StartsWith("--", StringComparison.Ordinal))
        {
            error = "Multipart form bodies are not supported. Send application/x-www-form-urlencoded or a JSON object.";
            return false;
        }

        if (media == "application/json")
            return TryJson(trimmed, out model, out error);
        if (media == "application/x-www-form-urlencoded")
            return TryForm(trimmed, out model, out error);

        if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
            return TryJson(trimmed, out model, out error);
        if (LooksLikeForm(trimmed))
            return TryForm(trimmed, out model, out error);

        error = "Mass assignment scan needs a JSON object or application/x-www-form-urlencoded body.";
        return false;
    }

    /// <summary>
    /// True when <paramref name="text"/> associates <paramref name="display"/> with <paramref name="field"/>.
    /// </summary>
    public static bool Matches(string? text, string field, string display)
    {
        if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(field) || string.IsNullOrEmpty(display))
            return false;
        if (JsonFieldEquals(text, field, display))
            return true;
        if (FormPairEquals(text, field, display))
            return true;
        if (HtmlControlEquals(text, field, display))
            return true;
        if (AllowsProximity(display) && ProximityEquals(text, field, display))
            return true;
        if (display.Length >= 16 && text.Contains(display, StringComparison.Ordinal))
            return true;
        return false;
    }

    /// <summary>True when the value is associated with the field after injection and was not before.</summary>
    public static bool NewlyObserved(string? before, string? after, string field, string display) =>
        Matches(after, field, display) && !Matches(before, field, display);

    public static IEnumerable<string> HtmlControlNames(string? html)
    {
        if (string.IsNullOrEmpty(html))
            yield break;

        foreach (Match tag in HtmlControl.Matches(html))
        {
            if (TryAttr(tag.Value, "name", out var name) && !string.IsNullOrWhiteSpace(name))
                yield return name;
        }
    }

    private static bool TryJson(string trimmed, out BodyModel? model, out string? error)
    {
        model = null;
        error = null;
        try
        {
            var node = JsonNode.Parse(trimmed);
            if (node is not JsonObject obj)
            {
                error = "JSON body must be a JSON object at the top level (not an array or primitive).";
                return false;
            }

            model = new BodyModel(obj, null);
            return true;
        }
        catch (JsonException)
        {
            error = "Content-Type is JSON but the body is not a JSON object.";
            return false;
        }
    }

    private static bool TryForm(string trimmed, out BodyModel? model, out string? error)
    {
        model = null;
        var fields = new List<KeyValuePair<string, string>>();
        foreach (var pair in trimmed.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq <= 0)
                continue;
            var name = WebUtility.UrlDecode(pair[..eq]);
            var value = WebUtility.UrlDecode(pair[(eq + 1)..]);
            if (string.IsNullOrWhiteSpace(name))
                continue;
            fields.Add(new KeyValuePair<string, string>(name, value));
        }

        if (fields.Count == 0)
        {
            error = "Body is not application/x-www-form-urlencoded (expected name=value pairs).";
            return false;
        }

        error = null;
        model = new BodyModel(null, fields);
        return true;
    }

    private static bool LooksLikeForm(string trimmed) =>
        trimmed.Contains('=') && !trimmed.Contains('<');

    private static string? MediaType(string? contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
            return null;
        var semi = contentType.IndexOf(';');
        return (semi >= 0 ? contentType[..semi] : contentType).Trim().ToLowerInvariant();
    }

    private static bool JsonFieldEquals(string text, string field, string display)
    {
        JsonObject? root = null;
        try
        {
            var node = JsonNode.Parse(text);
            root = node as JsonObject;
            if (root == null && node is JsonArray { Count: > 0 } array && array[0] is JsonObject first)
                root = first;
        }
        catch (JsonException)
        {
            return false;
        }

        if (root == null)
            return false;

        foreach (var prop in root)
        {
            if (!prop.Key.Equals(field, StringComparison.OrdinalIgnoreCase) || prop.Value == null)
                continue;
            if (JsonValueEquals(prop.Value, display))
                return true;
        }

        return false;
    }

    private static bool JsonValueEquals(JsonNode value, string display)
    {
        if (value is JsonValue jv)
        {
            if (jv.TryGetValue<string>(out var s))
                return string.Equals(s, display, StringComparison.Ordinal);
            if (jv.TryGetValue<bool>(out var b))
                return bool.TryParse(display, out var expected) && b == expected;
            if (jv.TryGetValue<double>(out var d)
                && double.TryParse(display, NumberStyles.Float, CultureInfo.InvariantCulture, out var expectedNumber))
                return Math.Abs(d - expectedNumber) < 0.0000001;
        }

        return string.Equals(value.ToJsonString().Trim('"'), display, StringComparison.Ordinal);
    }

    private static bool FormPairEquals(string text, string field, string display)
    {
        if (!text.Contains('='))
            return false;

        foreach (var pair in text.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq <= 0)
                continue;
            var name = WebUtility.UrlDecode(pair[..eq].Trim());
            if (!name.Equals(field, StringComparison.OrdinalIgnoreCase))
                continue;
            var value = WebUtility.UrlDecode(pair[(eq + 1)..].Trim());
            if (string.Equals(value, display, StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    private static bool HtmlControlEquals(string html, string field, string display)
    {
        foreach (Match tag in HtmlControl.Matches(html))
        {
            if (!TryAttr(tag.Value, "name", out var name) || !name.Equals(field, StringComparison.OrdinalIgnoreCase))
                continue;
            if (TryAttr(tag.Value, "value", out var value) && string.Equals(value, display, StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    private static bool TryAttr(string tag, string attr, out string value)
    {
        value = "";
        foreach (Match match in Attr.Matches(tag))
        {
            if (!match.Groups[1].Value.Equals(attr, StringComparison.OrdinalIgnoreCase))
                continue;
            value = match.Groups[2].Success ? match.Groups[2].Value
                : match.Groups[3].Success ? match.Groups[3].Value
                : match.Groups[4].Value;
            return true;
        }

        return false;
    }

    private static bool AllowsProximity(string display)
    {
        if (display.Length >= 12)
            return true;
        if (bool.TryParse(display, out _))
            return false;
        if (display.Length <= 3)
            return false;
        if (double.TryParse(display, NumberStyles.Float, CultureInfo.InvariantCulture, out _) && display.Length < 6)
            return false;
        return true;
    }

    private static bool ProximityEquals(string text, string field, string display)
    {
        var pattern =
            $@"(?i)(?<![A-Za-z0-9_]){Regex.Escape(field)}(?![A-Za-z0-9_]).{{0,80}}?(?<![A-Za-z0-9_]){Regex.Escape(display)}(?![A-Za-z0-9_])";
        return Regex.IsMatch(text, pattern);
    }
}
