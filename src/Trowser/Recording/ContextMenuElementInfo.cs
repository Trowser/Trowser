using System.Text.Json;

namespace Trowser.Recording;

/// <summary>
/// Metadata for the element under the browser context menu, used by Run Script and Send to Chat.
/// </summary>
public sealed class ContextMenuElementInfo
{
    public string Selector { get; init; } = "";
    public string Tag { get; init; } = "";
    public string Text { get; init; } = "";
    public string Role { get; init; } = "";
    public string Label { get; init; } = "";
    public string InputType { get; init; } = "";
    public string Href { get; init; } = "";
    public string TestId { get; init; } = "";
    public string Placeholder { get; init; } = "";

    public bool HasTarget => !string.IsNullOrWhiteSpace(Selector) || !string.IsNullOrWhiteSpace(Tag);

    public static ContextMenuElementInfo? ParseFromJson(string raw)
    {
        if (raw is "null" or "undefined" or "")
            return null;

        if (raw.StartsWith('"'))
            raw = JsonSerializer.Deserialize<string>(raw) ?? "";

        try
        {
            using var doc = JsonDocument.Parse(raw);
            var root = doc.RootElement;
            var selector = GetString(root, "selector");
            var tag = GetString(root, "tag");
            if (string.IsNullOrWhiteSpace(selector) && string.IsNullOrWhiteSpace(tag))
                return null;

            return new ContextMenuElementInfo
            {
                Selector = selector,
                Tag = tag,
                Text = GetString(root, "text"),
                Role = GetString(root, "role"),
                Label = GetString(root, "label"),
                InputType = GetString(root, "inputType"),
                Href = GetString(root, "href"),
                TestId = GetString(root, "testId"),
                Placeholder = GetString(root, "placeholder")
            };
        }
        catch
        {
            return null;
        }
    }

    private static string GetString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var prop) ? prop.GetString() ?? "" : "";
}
