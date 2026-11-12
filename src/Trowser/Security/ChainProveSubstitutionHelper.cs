using System.Text.Json;
using Trowser.Api;

namespace Trowser.Security;

/// <summary>
/// Parses user-supplied template variable overrides for chain-prove.
/// </summary>
public static class ChainProveSubstitutionHelper
{
    private static readonly string[] KnownTemplateKeys =
    [
        "endpoint", "endpoint0", "endpoint1", "sensitiveEndpoint", "corsEndpoint",
        "balanceUrl", "step1Url", "step1Body", "step2Url", "step2Body",
        "scriptUrl", "pageUrl", "param", "method", "payload", "origin", "host"
    ];

    internal static Dictionary<string, string>? FromJsonBody(JsonBody body)
    {
        var overrides = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        MergeDictionary(overrides, body.GetStringDictionary("vars"));
        MergeDictionary(overrides, body.GetStringDictionary("substitutions"));
        MergeDictionary(overrides, body.GetStringDictionary("templateVars"));

        foreach (var propName in new[] { "vars", "substitutions", "templateVars" })
        {
            var el = body.GetJsonElement(propName);
            if (el is { ValueKind: JsonValueKind.Object })
                MergeObject(el.Value, overrides);
        }

        foreach (var key in KnownTemplateKeys)
            Add(overrides, key, body.GetString(key));

        ApplyEndpointAliases(overrides);

        return overrides.Count > 0 ? overrides : null;
    }

    public static Dictionary<string, string>? FromJsonElement(JsonElement args)
    {
        var overrides = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (args.TryGetProperty("vars", out var vars) && vars.ValueKind == JsonValueKind.Object)
            MergeObject(vars, overrides);
        if (args.TryGetProperty("substitutions", out var subs) && subs.ValueKind == JsonValueKind.Object)
            MergeObject(subs, overrides);
        if (args.TryGetProperty("templateVars", out var tv) && tv.ValueKind == JsonValueKind.Object)
            MergeObject(tv, overrides);

        foreach (var key in KnownTemplateKeys)
        {
            if (args.TryGetProperty(key, out var el) && el.ValueKind == JsonValueKind.String)
                Add(overrides, key, el.GetString());
        }

        ApplyEndpointAliases(overrides);

        return overrides.Count > 0 ? overrides : null;
    }

    private static void ApplyEndpointAliases(Dictionary<string, string> overrides)
    {
        if (overrides.TryGetValue("sensitiveEndpoint", out var sensitive)
            && !overrides.ContainsKey("endpoint0"))
            overrides["endpoint0"] = sensitive;
        if (overrides.TryGetValue("corsEndpoint", out var cors)
            && !overrides.ContainsKey("endpoint1"))
            overrides["endpoint1"] = cors;
    }

    private static void MergeDictionary(Dictionary<string, string> overrides, Dictionary<string, string>? source)
    {
        if (source == null) return;
        foreach (var kv in source)
            Add(overrides, kv.Key, kv.Value);
    }

    private static void MergeObject(JsonElement obj, Dictionary<string, string> overrides)
    {
        foreach (var prop in obj.EnumerateObject())
        {
            var value = prop.Value.ValueKind switch
            {
                JsonValueKind.String => prop.Value.GetString(),
                JsonValueKind.Number => prop.Value.GetRawText(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                JsonValueKind.Object or JsonValueKind.Array => prop.Value.GetRawText(),
                _ => null
            };
            Add(overrides, prop.Name, value);
        }
    }

    private static void Add(Dictionary<string, string> overrides, string key, string? value)
    {
        if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value)) return;
        overrides[key.Trim()] = value.Trim();
    }
}
