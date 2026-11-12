using System.Globalization;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Laws;

public sealed class LawFactsPendingException : Exception
{
    public IReadOnlyList<string> Selectors { get; }

    public LawFactsPendingException(IEnumerable<string> selectors)
        : base("DOM facts pending")
    {
        Selectors = selectors.Distinct(StringComparer.Ordinal).ToList();
    }
}

/// <summary>Read-only page facts for Law lambdas. Selectors are fetched in batches by <see cref="LawEvaluator"/>.</summary>
public sealed class PageFacts
{
    private readonly Dictionary<string, object?> _cache;
    private readonly HashSet<string> _pending;
    private readonly List<string>? _trace;

    internal PageFacts(
        Dictionary<string, object?> cache,
        HashSet<string> pending,
        string url,
        string title,
        List<string>? trace = null)
    {
        _cache = cache;
        _pending = pending;
        Url = url;
        Title = title;
        _trace = trace;
    }

    /// <summary>When true, missing DOM keys are queued and safe defaults are returned (batch prefetch pass).</summary>
    internal bool CollectMode { get; set; }

    public string Url { get; }
    public string Title { get; }

    /// <summary>URL path (no query), e.g. <c>/cart</c>.</summary>
    public string Path => Uri.TryCreate(Url, UriKind.Absolute, out var u) ? u.AbsolutePath : "";

    /// <summary>Host of the page URL, e.g. <c>shop.example.com</c>.</summary>
    public string Host => Uri.TryCreate(Url, UriKind.Absolute, out var u) ? u.Host : "";

    public string Text(string selector) => GetString(selector, "text");
    public bool Exists(string selector) => GetBool(selector, "exists");
    public bool Visible(string selector) => GetBool(selector, "visible");
    public int Count(string selector) => GetInt(selector, "count");
    public string? Attr(string selector, string attribute) =>
        GetString(selector, "attr", attribute);

    /// <summary>Current value of the first matching input/select/textarea.</summary>
    public string Value(string selector) => GetString(selector, "value");

    /// <summary>Trimmed text of every matching element (empty texts skipped).</summary>
    public IReadOnlyList<string> Texts(string selector)
    {
        var raw = GetString(selector, "texts");
        return string.IsNullOrEmpty(raw)
            ? []
            : raw.Split(TextsSeparator, StringSplitOptions.RemoveEmptyEntries);
    }

    internal const char TextsSeparator = '\u001f';

    public double Number(string selector) =>
        ParseNumber(GetString(selector, "text"));

    public IEnumerable<double> Numbers(string selector)
    {
        var raw = GetString(selector, "numbers");
        if (string.IsNullOrWhiteSpace(raw))
            yield break;
        foreach (var part in raw.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (TryParseNumber(part, out var n))
                yield return n;
        }
    }

    private string GetString(string selector, string kind, string? extra = null)
    {
        var key = Key(selector, kind, extra);
        if (_cache.TryGetValue(key, out var v) && v != null)
        {
            var s = v.ToString() ?? "";
            RecordTrace(kind, selector, extra, s);
            return s;
        }

        _pending.Add(key);
        if (CollectMode)
            return DefaultForKind(kind);

        throw new LawFactsPendingException(_pending);
    }

    private static string DefaultForKind(string kind) =>
        kind switch
        {
            "count" => "0",
            "exists" or "visible" => "false",
            _ => ""
        };

    private bool GetBool(string selector, string kind)
    {
        var s = GetString(selector, kind);
        return bool.TryParse(s, out var b) && b;
    }

    private int GetInt(string selector, string kind)
    {
        var s = GetString(selector, kind);
        return int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : 0;
    }

    internal static string Key(string selector, string kind, string? extra = null) =>
        extra == null ? $"{kind}\0{selector}" : $"{kind}\0{selector}\0{extra}";

    internal static string? FormatEvidence(IReadOnlyList<string> trace) =>
        trace.Count == 0 ? null : string.Join("; ", trace.Take(10));

    private void RecordTrace(string kind, string selector, string? extra, string value)
    {
        if (_trace == null || CollectMode || _trace.Count >= 12)
            return;

        var label = kind switch
        {
            "attr" => $"p.Attr(\"{TrimTrace(selector)}\", \"{extra}\")",
            "text" => $"p.Text(\"{TrimTrace(selector)}\")",
            "count" => $"p.Count(\"{TrimTrace(selector)}\")",
            "exists" => $"p.Exists(\"{TrimTrace(selector)}\")",
            "visible" => $"p.Visible(\"{TrimTrace(selector)}\")",
            "numbers" => $"p.Numbers(\"{TrimTrace(selector)}\")",
            "value" => $"p.Value(\"{TrimTrace(selector)}\")",
            "texts" => $"p.Texts(\"{TrimTrace(selector)}\")",
            _ => $"p.{kind}(\"{TrimTrace(selector)}\")"
        };
        _trace.Add($"{label} = {TrimTrace(value)}");
    }

    private static string TrimTrace(string s) =>
        s.Length <= 80 ? s : s[..77] + "...";

    internal static double ParseNumber(string text)
    {
        if (TryParseNumber(text, out var n))
            return n;
        return double.NaN;
    }

    internal static bool TryParseNumber(string text, out double value)
    {
        text = text.Trim();
        if (double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out value))
            return true;

        var cleaned = new string(text.Where(c => char.IsDigit(c) || c is '.' or ',' or '-').ToArray());
        cleaned = cleaned.Replace(',', '.');
        return double.TryParse(cleaned, NumberStyles.Float, CultureInfo.InvariantCulture, out value);
    }
}

public sealed class ResponseFacts
{
    private readonly List<string>? _trace;

    public ResponseFacts(NetworkEntry entry, List<string>? trace = null)
    {
        Entry = entry;
        _trace = trace;
        Json = new JsonFacts(entry.ResponseBody, trace);
    }

    public NetworkEntry Entry { get; }

    public string Url => Entry.Url;
    public string Method => Entry.Method;
    public string ContentType => Entry.ContentType;

    public int Status
    {
        get
        {
            Record("r.Status", Entry.StatusCode.ToString(System.Globalization.CultureInfo.InvariantCulture));
            return Entry.StatusCode;
        }
    }

    public JsonFacts Json { get; }

    internal static string? FormatEvidence(IReadOnlyList<string> trace) =>
        trace.Count == 0 ? null : string.Join("; ", trace.Take(10));

    private void Record(string label, string value)
    {
        if (_trace == null || _trace.Count >= 12)
            return;
        var v = value.Length <= 80 ? value : value[..77] + "...";
        _trace.Add($"{label} = {v}");
    }

    public string? Header(string name)
    {
        foreach (var kvp in Entry.ResponseHeaders)
        {
            if (kvp.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
                return kvp.Value;
        }
        return null;
    }

    public string? Cookie(string name)
    {
        var setCookie = Header("Set-Cookie");
        if (setCookie == null) return null;
        foreach (var part in setCookie.Split(';', StringSplitOptions.TrimEntries))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0) continue;
            var n = part[..eq];
            if (n.Equals(name, StringComparison.OrdinalIgnoreCase))
                return part[(eq + 1)..];
        }
        return null;
    }

    public string? Body => Entry.ResponseBody;
}

public sealed class JsonFacts
{
    private readonly JsonDocument? _doc;
    private readonly List<string>? _trace;

    public JsonFacts(string? json, List<string>? trace = null)
    {
        _trace = trace;
        if (!string.IsNullOrWhiteSpace(json))
        {
            try { _doc = JsonDocument.Parse(json); }
            catch { /* invalid json */ }
        }
    }

    public double Number(string path)
    {
        var el = Resolve(path);
        if (el == null)
        {
            Record(path, "∅");
            return double.NaN;
        }
        if (el.Value.ValueKind == JsonValueKind.Number && el.Value.TryGetDouble(out var d))
        {
            Record(path, d.ToString(CultureInfo.InvariantCulture));
            return d;
        }
        if (el.Value.ValueKind == JsonValueKind.String
            && PageFacts.TryParseNumber(el.Value.GetString() ?? "", out var parsed))
        {
            Record(path, parsed.ToString(CultureInfo.InvariantCulture));
            return parsed;
        }
        Record(path, el.Value.GetRawText());
        return double.NaN;
    }

    public string? String(string path)
    {
        var el = Resolve(path);
        var s = el?.ValueKind switch
        {
            JsonValueKind.String => el.Value.GetString(),
            JsonValueKind.Number => el.Value.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => null
        };
        Record(path, s ?? "null");
        return s;
    }

    public bool HasValue(string path)
    {
        var el = Resolve(path);
        var ok = el != null && el.Value.ValueKind != JsonValueKind.Null;
        Record(path, ok ? "present" : "null");
        return ok;
    }

    /// <summary>True when the body parsed as JSON.</summary>
    public bool IsValid => _doc != null;

    /// <summary>Array length or object property count at <paramref name="path"/> (empty path = root); -1 when missing.</summary>
    public int Count(string path = "")
    {
        var el = string.IsNullOrWhiteSpace(path) ? _doc?.RootElement : Resolve(path);
        var n = el?.ValueKind switch
        {
            JsonValueKind.Array => el.Value.GetArrayLength(),
            JsonValueKind.Object => el.Value.EnumerateObject().Count(),
            null => -1,
            _ => -1
        };
        Record($"Count({path})", n.ToString(CultureInfo.InvariantCulture));
        return n;
    }

    /// <summary>Numbers at <paramref name="arrayPath"/>[*].<paramref name="field"/> — e.g. <c>Numbers("items", "price")</c>.</summary>
    public IReadOnlyList<double> Numbers(string arrayPath, string? field = null)
    {
        var list = new List<double>();
        var arr = string.IsNullOrWhiteSpace(arrayPath) ? _doc?.RootElement : Resolve(arrayPath);
        if (arr is not { ValueKind: JsonValueKind.Array })
        {
            Record($"Numbers({arrayPath})", "∅");
            return list;
        }

        foreach (var item in arr.Value.EnumerateArray())
        {
            var el = string.IsNullOrWhiteSpace(field) ? item : ResolveFrom(item, field);
            if (el is { ValueKind: JsonValueKind.Number } n && n.TryGetDouble(out var d))
                list.Add(d);
            else if (el is { ValueKind: JsonValueKind.String } s && PageFacts.TryParseNumber(s.GetString() ?? "", out var parsed))
                list.Add(parsed);
        }

        Record($"Numbers({arrayPath}{(field == null ? "" : ", " + field)})",
            string.Join(",", list.Take(8).Select(v => v.ToString(CultureInfo.InvariantCulture))));
        return list;
    }

    private void Record(string path, string value)
    {
        if (_trace == null || _trace.Count >= 12)
            return;
        var v = value.Length <= 80 ? value : value[..77] + "...";
        _trace.Add($"r.Json.{path} = {v}");
    }

    private JsonElement? Resolve(string path)
    {
        if (_doc == null || string.IsNullOrWhiteSpace(path))
            return null;
        return ResolveFrom(_doc.RootElement, path);
    }

    /// <summary>Dotted path with array indexes: <c>items[0].price</c>, <c>items.0.price</c>, <c>[0].id</c>.</summary>
    private static JsonElement? ResolveFrom(JsonElement current, string path)
    {
        var normalized = path.Replace("[", ".").Replace("]", "");
        foreach (var segment in normalized.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (current.ValueKind == JsonValueKind.Object)
            {
                if (!current.TryGetProperty(segment, out current))
                    return null;
            }
            else if (current.ValueKind == JsonValueKind.Array
                     && int.TryParse(segment, NumberStyles.Integer, CultureInfo.InvariantCulture, out var idx))
            {
                if (idx < 0)
                    idx += current.GetArrayLength();
                if (idx < 0 || idx >= current.GetArrayLength())
                    return null;
                current = current[idx];
            }
            else
            {
                return null;
            }
        }
        return current;
    }
}

public sealed class ConsoleFacts
{
    public ConsoleFacts(ConsoleEntry entry)
    {
        Entry = entry;
        Level = entry.Level.ToString();
        Message = entry.Message;
    }

    public ConsoleEntry Entry { get; }
    public string Level { get; }
    public string Message { get; }
}

public static class LawNumberExtensions
{
    public static bool ApproxEquals(this double a, double b, double tolerance = 0.001) =>
        double.IsNaN(a) || double.IsNaN(b)
            ? false
            : Math.Abs(a - b) <= tolerance;

    public static bool ApproxEquals(this double a, IEnumerable<double> values, double tolerance = 0.001)
    {
        var sum = values.Where(v => !double.IsNaN(v)).Sum();
        return a.ApproxEquals(sum, tolerance);
    }
}
