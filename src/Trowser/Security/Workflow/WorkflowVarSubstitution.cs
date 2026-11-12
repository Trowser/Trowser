using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Trowser.Security.Workflow;

internal static class WorkflowVarSubstitution
{
    private static readonly Regex VarRegex = new(@"\{\{(\w+)\}\}", RegexOptions.Compiled);

    /// <summary>Vars populated at runtime by inject/verify steps — not required before chain-prove.</summary>
    private static readonly HashSet<string> InjectStepOutputVars = new(StringComparer.OrdinalIgnoreCase)
    {
        "effectObserved", "effectValue"
    };

    public static string Substitute(string? input, IReadOnlyDictionary<string, string> vars)
    {
        if (string.IsNullOrEmpty(input)) return input ?? "";
        return VarRegex.Replace(input, m =>
            vars.TryGetValue(m.Groups[1].Value, out var v) ? v : m.Value);
    }

    public static List<string> FindUnresolvedPlaceholders(string text, IReadOnlyDictionary<string, string> vars)
    {
        if (string.IsNullOrEmpty(text)) return [];
        var unresolved = new List<string>();
        foreach (Match m in VarRegex.Matches(text))
        {
            var name = m.Groups[1].Value;
            if (!vars.TryGetValue(name, out var v) || string.IsNullOrWhiteSpace(v))
            {
                if (!unresolved.Contains(name, StringComparer.OrdinalIgnoreCase))
                    unresolved.Add(name);
            }
        }

        return unresolved;
    }

    /// <summary>Placeholder names filled by workflow <c>capture</c> blocks at runtime — not pre-substitution.</summary>
    public static HashSet<string> ExtractCaptureVariableNames(string templateJson)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var doc = JsonDocument.Parse(templateJson);
            ExtractCapturesFromElement(doc.RootElement, names);
        }
        catch (JsonException) { /* ignore */ }

        return names;
    }

    /// <summary>Unresolved {{vars}} excluding runtime capture targets (two-phase substitution).</summary>
    public static List<string> FindUnresolvedStaticPlaceholders(string text, IReadOnlyDictionary<string, string> vars)
    {
        var captureVars = ExtractCaptureVariableNames(text);
        return FindUnresolvedPlaceholders(text, vars)
            .Where(n => !captureVars.Contains(n) && !InjectStepOutputVars.Contains(n))
            .ToList();
    }

    private static void ExtractCapturesFromElement(JsonElement el, HashSet<string> names)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in el.EnumerateObject())
                {
                    if (prop.NameEquals("capture") && prop.Value.ValueKind == JsonValueKind.Object)
                    {
                        foreach (var cap in prop.Value.EnumerateObject())
                            names.Add(cap.Name);
                    }
                    else
                        ExtractCapturesFromElement(prop.Value, names);
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in el.EnumerateArray())
                    ExtractCapturesFromElement(item, names);
                break;
        }
    }

    public static JsonElement SubstituteElement(JsonElement el, IReadOnlyDictionary<string, string> vars)
    {
        var raw = Substitute(el.GetRawText(), vars);
        using var doc = JsonDocument.Parse(raw);
        return doc.RootElement.Clone();
    }

    public static string BodyHash(string? body)
    {
        if (string.IsNullOrEmpty(body)) return "";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(body));
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }
}
