using System.Text.Json;

namespace Trowser.Recording;

/// <summary>
/// Turns a recorded browser action (the JSON payload posted by the recorder injection
/// script) into a short, human-readable narration line such as
/// <c>Click "Log in"</c>, <c>Type "alice@example.com" into Email</c>, or
/// <c>Navigated to /checkout</c>.
///
/// Shared by <see cref="ScriptRecorder"/> (which writes a parallel narration file
/// alongside the .csx) and the main window's recent-narration buffer (which feeds the
/// "Add to bug" repro steps). This keeps the friendly-label logic in one place.
/// </summary>
public static class ActionNarrator
{
    /// <summary>Describe a single recorded action. Returns null for actions with no useful narration.</summary>
    public static string? Describe(JsonElement action)
    {
        if (!action.TryGetProperty("type", out var typeProp) || typeProp.ValueKind != JsonValueKind.String)
            return null;

        var type = typeProp.GetString();
        return type switch
        {
            "click" => $"Click {Target(action)}",
            "hover" => $"Hover {Target(action)}",
            "type" => DescribeType(action),
            "select" => DescribeSelect(action),
            "key" => DescribeKey(action),
            "scroll" => DescribeScroll(action),
            "radio" => DescribeRadio(action),
            "assert" => DescribeAssert(action),
            "elementOfInterest" => $"Note element {Target(action)}",
            _ => null
        };
    }

    /// <summary>Describe a page navigation. <paramref name="url"/> is shown as a path when possible.</summary>
    public static string DescribeNavigation(string url) => $"Navigated to {ShortUrl(url)}";

    private static string DescribeType(JsonElement action)
    {
        var value = Str(action, "value");
        var inputType = Str(action, "inputType");
        var display = inputType == "password" ? "***" : Truncate(value, 60);
        var field = FieldName(action);
        return string.IsNullOrEmpty(field)
            ? $"Type \"{display}\""
            : $"Type \"{display}\" into {field}";
    }

    private static string DescribeSelect(JsonElement action)
    {
        var selectedText = Str(action, "selectedText");
        if (string.IsNullOrEmpty(selectedText)) selectedText = Str(action, "value");
        var field = FieldName(action);
        return string.IsNullOrEmpty(field)
            ? $"Select \"{selectedText}\""
            : $"Select \"{selectedText}\" in {field}";
    }

    private static string DescribeScroll(JsonElement action)
    {
        var y = Num(action, "scrollY");
        var selector = Str(action, "selector");
        return string.IsNullOrEmpty(selector)
            ? $"Scroll to {y:0}"
            : $"Scroll {selector} to {y:0}";
    }

    private static string DescribeKey(JsonElement action)
    {
        var key = Str(action, "key");
        var mods = new List<string>();
        if (Bool(action, "ctrlKey")) mods.Add("Ctrl");
        if (Bool(action, "altKey")) mods.Add("Alt");
        if (Bool(action, "shiftKey")) mods.Add("Shift");
        var combo = mods.Count > 0 ? $"{string.Join("+", mods)}+{key}" : key;
        return $"Press {combo}";
    }

    private static string DescribeRadio(JsonElement action)
    {
        var value = Str(action, "radioValue");
        var group = Str(action, "groupLabel");
        return string.IsNullOrEmpty(group)
            ? $"Choose \"{value}\""
            : $"Choose \"{value}\" for {group}";
    }

    private static string DescribeAssert(JsonElement action)
    {
        var text = Str(action, "text");
        return $"Assert page contains \"{Truncate(text, 60)}\"";
    }

    /// <summary>Best-effort friendly name for a clicked/hovered element: role "label", "text", or a tag.</summary>
    private static string Target(JsonElement action)
    {
        var role = Str(action, "role");
        var label = Str(action, "label");
        var text = Str(action, "text");

        if (!string.IsNullOrEmpty(label))
            return string.IsNullOrEmpty(role) ? $"\"{Truncate(label, 60)}\"" : $"{role} \"{Truncate(label, 60)}\"";
        if (!string.IsNullOrEmpty(text) && text.Length <= 60)
            return $"\"{text}\"";
        if (!string.IsNullOrEmpty(role))
            return role;

        var tag = Str(action, "tag");
        return string.IsNullOrEmpty(tag) ? "element" : $"<{tag}>";
    }

    /// <summary>Friendly field name for type/select: label, then placeholder.</summary>
    private static string FieldName(JsonElement action)
    {
        var label = Str(action, "label");
        if (!string.IsNullOrEmpty(label)) return label;
        var placeholder = Str(action, "placeholder");
        return placeholder;
    }

    private static string ShortUrl(string url)
    {
        try
        {
            var u = new Uri(url);
            var path = u.PathAndQuery;
            return string.IsNullOrEmpty(path) || path == "/" ? url : path;
        }
        catch { return url; }
    }

    private static string Truncate(string s, int max) =>
        string.IsNullOrEmpty(s) || s.Length <= max ? s : s[..max] + "…";

    private static string Str(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static bool Bool(JsonElement el, string prop) =>
        el.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.True;

    private static double Num(JsonElement el, string prop)
    {
        if (!el.TryGetProperty(prop, out var v)) return 0;
        if (v.ValueKind == JsonValueKind.Number) return v.GetDouble();
        return 0;
    }
}
