using System.Text.Json;

namespace Trowser.Api;

/// <summary>
/// Shared filtering for GET /api/state and browser_snapshot — caps element count and sorts viewport-first.
/// </summary>
internal static class InteractiveSnapshotFilter
{
    public const int DefaultElementLimit = 150;

    public sealed class Result
    {
        public required List<Dictionary<string, object>> Elements { get; init; }
        public bool Truncated { get; init; }
        public int TotalBeforeLimit { get; init; }
        public IReadOnlyList<string>? CompactLines { get; init; }
    }

    public static Result Apply(
        List<Dictionary<string, object>> elements,
        bool visibleOnly,
        int limit,
        bool fullElements,
        string? tagFilter,
        string? typeFilter,
        string? qFilter,
        string? containerSelector,
        HashSet<int>? refsInContainer,
        bool compactFormat)
    {
        IEnumerable<Dictionary<string, object>> filtered = elements;

        if (visibleOnly)
        {
            filtered = filtered.Where(e =>
            {
                if (e.TryGetValue("ref", out var r))
                {
                    if (r is JsonElement je && je.ValueKind == JsonValueKind.Number)
                        return je.GetInt32() >= 0;
                }
                if (e.TryGetValue("visible", out var v))
                    return v is true || (v is JsonElement vje && vje.ValueKind == JsonValueKind.True);
                return true;
            });
        }

        if (refsInContainer != null)
        {
            filtered = filtered.Where(e =>
                e.TryGetValue("ref", out var r)
                && r is JsonElement je
                && je.ValueKind == JsonValueKind.Number
                && refsInContainer.Contains(je.GetInt32()));
        }

        if (!string.IsNullOrEmpty(tagFilter))
        {
            filtered = filtered.Where(e =>
                e.TryGetValue("tag", out var t) && t is JsonElement te
                && te.GetString()?.Equals(tagFilter, StringComparison.OrdinalIgnoreCase) == true);
        }

        if (!string.IsNullOrEmpty(typeFilter))
        {
            filtered = filtered.Where(e =>
                e.TryGetValue("type", out var t) && t is JsonElement te
                && te.GetString()?.Equals(typeFilter, StringComparison.OrdinalIgnoreCase) == true);
        }

        if (!string.IsNullOrEmpty(qFilter))
        {
            filtered = filtered.Where(e =>
            {
                string? text = e.TryGetValue("text", out var tv) && tv is JsonElement txe
                    ? txe.GetString() : null;
                string? label = e.TryGetValue("label", out var lv) && lv is JsonElement lxe
                    ? lxe.GetString() : null;
                return (text?.Contains(qFilter, StringComparison.OrdinalIgnoreCase) == true)
                    || (label?.Contains(qFilter, StringComparison.OrdinalIgnoreCase) == true);
            });
        }

        var sorted = filtered
            .OrderByDescending(InViewport)
            .ThenBy(RefOrder)
            .ToList();

        var total = sorted.Count;
        var effectiveLimit = fullElements || limit == 0 ? int.MaxValue : (limit > 0 ? limit : DefaultElementLimit);
        var truncated = sorted.Count > effectiveLimit;
        if (truncated)
            sorted = sorted.Take(effectiveLimit).ToList();

        IReadOnlyList<string>? lines = null;
        if (compactFormat)
        {
            lines = sorted.Select(ToCompactLine).ToList();
            sorted = sorted.Select(ToCompactElement).ToList();
        }

        return new Result
        {
            Elements = sorted,
            Truncated = truncated,
            TotalBeforeLimit = total,
            CompactLines = lines
        };
    }

    private static bool InViewport(Dictionary<string, object> e)
    {
        if (e.TryGetValue("inViewport", out var v))
        {
            if (v is true) return true;
            if (v is JsonElement je && je.ValueKind == JsonValueKind.True) return true;
        }
        return false;
    }

    private static int RefOrder(Dictionary<string, object> e)
    {
        if (e.TryGetValue("ref", out var r) && r is JsonElement je && je.ValueKind == JsonValueKind.Number)
            return je.GetInt32() >= 0 ? je.GetInt32() : int.MaxValue;
        return int.MaxValue;
    }

    private static string ToCompactLine(Dictionary<string, object> e)
    {
        static string F(Dictionary<string, object> d, string key)
        {
            if (!d.TryGetValue(key, out var v)) return "";
            if (v is JsonElement je)
                return je.ValueKind == JsonValueKind.String ? je.GetString() ?? "" : je.ToString();
            return v?.ToString() ?? "";
        }

        var refStr = F(e, "ref");
        var tag = F(e, "tag");
        var label = F(e, "label");
        if (string.IsNullOrEmpty(label))
            label = F(e, "text");
        if (label.Length > 80)
            label = label[..80];
        var sel = F(e, "selector");
        if (sel.Length > 120)
            sel = sel[..120];
        return $"{refStr}|{tag}|{label}|{sel}";
    }

    private static Dictionary<string, object> ToCompactElement(Dictionary<string, object> e)
    {
        static object? Get(Dictionary<string, object> d, string key)
        {
            if (!d.TryGetValue(key, out var v)) return null;
            if (v is JsonElement je)
            {
                return je.ValueKind switch
                {
                    JsonValueKind.String => je.GetString(),
                    JsonValueKind.Number => je.TryGetInt32(out var n) ? n : je.GetDouble(),
                    JsonValueKind.True => true,
                    JsonValueKind.False => false,
                    _ => je.ToString()
                };
            }
            return v;
        }

        var slim = new Dictionary<string, object>();
        foreach (var key in new[] { "ref", "tag", "type", "label", "text", "value", "placeholder", "href", "frameId" })
        {
            var val = Get(e, key);
            if (val is string s && s.Length == 0) continue;
            if (val != null)
                slim[key] = val;
        }
        return slim;
    }
}
