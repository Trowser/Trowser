using System.Text.Json;

namespace Trowser.Security.Workflow;

/// <summary>
/// Resolves fetch capture mappings. Supports both conventions:
/// <list>
/// <item><c>{ "varName": "field" }</c> — plan format, e.g. <c>{ "adminBody": "body" }</c></item>
/// <item><c>{ "field": "varName" }</c> — shorthand, e.g. <c>{ "status": "sqliStatus" }</c></item>
/// </list>
/// </summary>
internal static class WorkflowCaptureHelper
{
    private static readonly HashSet<string> KnownFetchFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "body", "bodyhash", "status", "url", "ok", "statustext", "redirected", "type"
    };

    public static void ApplyCapture(JsonElement captureEl, JsonElement fetch, IDictionary<string, string> vars)
    {
        if (captureEl.ValueKind != JsonValueKind.Object) return;

        foreach (var prop in captureEl.EnumerateObject())
        {
            var (varName, field) = ResolveMapping(prop.Name, prop.Value);
            var val = ExtractFetchField(fetch, field);
            if (val != null)
                vars[varName] = val;
        }
    }

    public static (string VarName, string Field) ResolveMapping(string key, JsonElement valueEl)
    {
        var valueStr = valueEl.ValueKind == JsonValueKind.String ? valueEl.GetString() : null;
        var keyIsField = IsKnownFetchField(key);
        var valueIsField = !string.IsNullOrEmpty(valueStr) && IsKnownFetchField(valueStr);

        // { "status": "sqliStatus" } → var sqliStatus from field status
        if (keyIsField && !valueIsField && !string.IsNullOrEmpty(valueStr))
            return (valueStr, key);

        // { "adminBody": "body" } → var adminBody from field body
        if (!string.IsNullOrEmpty(valueStr))
            return (key, valueStr);

        return (key, key);
    }

    public static bool IsKnownFetchField(string name) =>
        KnownFetchFields.Contains(name);

    public static string? ExtractFetchField(JsonElement fetch, string field) => field.ToLowerInvariant() switch
    {
        "body" => fetch.TryGetProperty("body", out var b) ? b.GetString() : null,
        "bodyhash" => WorkflowVarSubstitution.BodyHash(fetch.TryGetProperty("body", out var bh) ? bh.GetString() : null),
        "status" => fetch.TryGetProperty("status", out var s) ? s.GetInt32().ToString() : null,
        "url" => fetch.TryGetProperty("url", out var u) ? u.GetString() : null,
        "ok" => fetch.TryGetProperty("ok", out var ok) ? ok.GetBoolean().ToString() : null,
        "statustext" => fetch.TryGetProperty("statusText", out var st) ? st.GetString() : null,
        "redirected" => fetch.TryGetProperty("redirected", out var rd) ? rd.GetBoolean().ToString() : null,
        _ => fetch.TryGetProperty(field, out var f) ? f.ToString() : null
    };
}
