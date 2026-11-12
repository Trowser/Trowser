using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Resource identifiers that usually mean a new server-side object (order, charge, booking).
/// Per-request noise (trace ids, timestamps, CSRF) is ignored so idempotent replays stay quiet.
/// </summary>
public static class SideEffectIds
{
    private static readonly HashSet<string> VolatileKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "requestId", "request_id", "traceId", "trace_id", "correlationId", "correlation_id",
        "spanId", "span_id", "parentSpanId", "sessionId", "session_id",
        "nonce", "csrf", "csrfToken", "csrf_token", "xsrf", "xsrfToken",
        "timestamp", "time", "date", "createdAt", "created_at", "updatedAt", "updated_at",
        "expires", "expiresAt", "expires_at", "duration", "durationMs", "latency", "latencyMs"
    };

    private static readonly HashSet<string> GenericPathWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "new", "create", "created", "success", "ok", "index", "list", "search", "status", "health"
    };

    private static readonly Regex FormPair = new(
        @"(?:^|[&])(?<key>[A-Za-z0-9_]+)=(?<val>[^&]{1,80})",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex JsonPair = new(
        @"""(?<key>[A-Za-z0-9_]+)""\s*:\s*(?:""(?<sval>[^""\\]{1,80})""|(?<nval>-?\d{1,40}))",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(1));

    public static IReadOnlyList<string> Extract(string? body, string? location = null)
    {
        var ids = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return;
            var v = value.Trim().Trim('"');
            if (v.Length is < 1 or > 80)
                return;
            if (v.Equals("null", StringComparison.OrdinalIgnoreCase)
                || v.Equals("true", StringComparison.OrdinalIgnoreCase)
                || v.Equals("false", StringComparison.OrdinalIgnoreCase)
                || v.Equals("undefined", StringComparison.OrdinalIgnoreCase)
                || v == "0")
                return;
            if (seen.Add(v))
                ids.Add(v);
        }

        if (!string.IsNullOrEmpty(body))
        {
            var slice = body.Length > 8_000 ? body[..8_000] : body;
            if (!TryWalkJson(slice, Add))
            {
                ExtractLoose(slice, Add);
            }
        }

        Add(IdFromLocation(location));
        return ids;
    }

    /// <summary>
    /// Ids that are not present on every response. Shared ids (user, cart) drop out;
    /// a new order id on only some accepts remains.
    /// </summary>
    public static List<string> Varying(IReadOnlyList<IReadOnlyList<string>> perResponse)
    {
        if (perResponse.Count == 0)
            return [];

        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var set in perResponse)
        {
            foreach (var id in new HashSet<string>(set.Where(s => !string.IsNullOrWhiteSpace(s)), StringComparer.OrdinalIgnoreCase))
            {
                counts.TryGetValue(id, out var n);
                counts[id] = n + 1;
            }
        }

        var total = perResponse.Count;
        return counts.Where(kv => kv.Value < total).Select(kv => kv.Key).ToList();
    }

    /// <summary>
    /// Blank volatile JSON fields so request ids and timestamps do not look like a new side effect.
    /// Side-effect ids are left in place.
    /// </summary>
    public static string NormalizeForComparison(string? body)
    {
        if (string.IsNullOrEmpty(body))
            return "";

        var slice = body.Length > 32_000 ? body[..32_000] : body;
        try
        {
            using var doc = JsonDocument.Parse(slice);
            var sb = new StringBuilder(slice.Length);
            WriteNormalized(sb, doc.RootElement);
            return sb.ToString();
        }
        catch (JsonException)
        {
            return slice;
        }
    }

    public static string? IdFromLocation(string? location)
    {
        if (string.IsNullOrWhiteSpace(location))
            return null;

        var path = location.Split('?', '#')[0];
        if (Uri.TryCreate(location, UriKind.Absolute, out var absolute))
            path = absolute.AbsolutePath;

        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0)
            return null;

        var last = Uri.UnescapeDataString(parts[^1]);
        if (last.Length is < 1 or > 80)
            return null;
        if (GenericPathWords.Contains(last))
            return null;
        if (last.Any(char.IsDigit))
            return last;
        if (last.Length >= 6 && last.Any(c => c is '_' or '-'))
            return last;
        if (last.Length >= 16)
            return last;
        return null;
    }

    private static bool IsSideEffectKey(string key)
    {
        if (VolatileKeys.Contains(key))
            return false;
        if (key.Equals("id", StringComparison.OrdinalIgnoreCase)
            || key.Equals("uuid", StringComparison.OrdinalIgnoreCase)
            || key.Equals("guid", StringComparison.OrdinalIgnoreCase))
            return true;
        if (key.EndsWith("_id", StringComparison.OrdinalIgnoreCase))
            return true;
        if (key.Length > 2 && key.EndsWith("Id", StringComparison.Ordinal))
            return true;
        if (key.Length > 4 && key.EndsWith("id", StringComparison.OrdinalIgnoreCase) && HasResourceStem(key))
            return true;
        if (key.Equals("orderNumber", StringComparison.OrdinalIgnoreCase)
            || key.Equals("order_number", StringComparison.OrdinalIgnoreCase)
            || key.Equals("confirmationNumber", StringComparison.OrdinalIgnoreCase)
            || key.Equals("confirmation_number", StringComparison.OrdinalIgnoreCase)
            || key.Equals("confirmationCode", StringComparison.OrdinalIgnoreCase)
            || key.Equals("confirmation_code", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    private static readonly string[] ResourceStems =
    [
        "order", "charge", "payment", "invoice", "booking", "reservation",
        "transaction", "capture", "confirmation", "subscription", "shipment", "refund", "ticket"
    ];

    private static bool HasResourceStem(string key)
    {
        foreach (var stem in ResourceStems)
        {
            if (key.StartsWith(stem, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static bool TryWalkJson(string json, Action<string?> add)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            Walk(doc.RootElement, add);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static void Walk(JsonElement el, Action<string?> add)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in el.EnumerateObject())
                {
                    if (IsSideEffectKey(prop.Name) && prop.Value.ValueKind is JsonValueKind.String or JsonValueKind.Number)
                        add(prop.Value.ToString());
                    else if (prop.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array)
                        Walk(prop.Value, add);
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in el.EnumerateArray())
                    Walk(item, add);
                break;
        }
    }

    private static void ExtractLoose(string text, Action<string?> add)
    {
        foreach (Match m in FormPair.Matches(text))
        {
            if (IsSideEffectKey(m.Groups["key"].Value))
                add(Uri.UnescapeDataString(m.Groups["val"].Value));
        }

        try
        {
            foreach (Match m in JsonPair.Matches(text))
            {
                if (!IsSideEffectKey(m.Groups["key"].Value))
                    continue;
                add(m.Groups["sval"].Success ? m.Groups["sval"].Value : m.Groups["nval"].Value);
            }
        }
        catch (RegexMatchTimeoutException)
        {
            /* ignore a pathological body */
        }
    }

    private static void WriteNormalized(StringBuilder sb, JsonElement el)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                sb.Append('{');
                var first = true;
                foreach (var prop in el.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
                {
                    if (!first) sb.Append(',');
                    first = false;
                    sb.Append('"').Append(Escape(prop.Name)).Append("\":");
                    if (VolatileKeys.Contains(prop.Name)
                        && prop.Value.ValueKind is JsonValueKind.String or JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False)
                        sb.Append("\"*\"");
                    else
                        WriteNormalized(sb, prop.Value);
                }
                sb.Append('}');
                break;
            case JsonValueKind.Array:
                sb.Append('[');
                var af = true;
                foreach (var item in el.EnumerateArray())
                {
                    if (!af) sb.Append(',');
                    af = false;
                    WriteNormalized(sb, item);
                }
                sb.Append(']');
                break;
            default:
                sb.Append(el.GetRawText());
                break;
        }
    }

    private static string Escape(string s) => s.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal);
}
