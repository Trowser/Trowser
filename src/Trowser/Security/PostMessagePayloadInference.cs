using System.Text.Json;
using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Infer structured postMessage bodies from listener handler source (JSON.parse, property reads).
/// </summary>
public static class PostMessagePayloadInference
{
    private static readonly Regex JsonParseProp = new(
        @"JSON\.parse\s*\(\s*(?:msg|message|event|e)\.data\s*\)[\s\S]{0,160}?\.(\w+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DirectProp = new(
        @"(?:msg|message|event|e)\.data\.(\w+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex TypeCompare = new(
        @"(?:data|msg|message|event|e|content|payload)\.(?:type|action|event)\s*(!==?|===?)\s*['""]([^'""]+)['""]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DataPropertyTypeCompare = new(
        @"(?:\w+\.)*data\.type\s*(!==?|===?)\s*['""]([^'""]+)['""]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex TypeCompareNot = new(
        @"(?:data|msg|message|event|e|content|payload)\.type\s*!==?\s*['""]([^'""]+)['""]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DirectDataToHtmlSink = new(
        @"\.innerHTML\s*=\s*(?:\w+\.)?(?:e|event|msg|message)\.data(?![.\[])",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex EvalSink = new(
        @"\b(eval|new\s+Function|setTimeout|setInterval)\s*\(\s*(?:\w+\.)?(?:e|event|msg|message)\.data",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex CodeFieldRead = new(
        @"(?:\w+\.)?(?:e|event|msg|message)\.data\.(?:code|script|expression|payload|command)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Infer message schema literals and HTML-bearing keys from handler source.</summary>
    public static PostMessageInferredSchema InferMessageSchema(string? handlerSource)
    {
        var schema = new PostMessageInferredSchema();
        if (string.IsNullOrWhiteSpace(handlerSource))
        {
            schema.HtmlKeys.Add("html");
            return schema;
        }

        foreach (Match m in TypeCompare.Matches(handlerSource))
        {
            var lit = m.Groups[2].Value;
            var prop = m.Value.Contains("type", StringComparison.OrdinalIgnoreCase) ? "type"
                : m.Value.Contains("action", StringComparison.OrdinalIgnoreCase) ? "action" : "event";
            if (prop == "type" && schema.TypeLiteral == null) schema.TypeLiteral = lit;
            else if (prop == "action" && schema.ActionLiteral == null) schema.ActionLiteral = lit;
            else if (prop == "event" && schema.EventLiteral == null) schema.EventLiteral = lit;
        }

        foreach (Match m in DataPropertyTypeCompare.Matches(handlerSource))
        {
            if (schema.TypeLiteral == null)
                schema.TypeLiteral = m.Groups[2].Value;
        }

        foreach (Match m in TypeCompareNot.Matches(handlerSource))
        {
            if (schema.TypeLiteral == null)
                schema.TypeLiteral = m.Groups[1].Value;
        }

        schema.PreferJsPayload = EvalSink.IsMatch(handlerSource) || CodeFieldRead.IsMatch(handlerSource);

        foreach (var k in InferHtmlPropertyKeys([handlerSource]))
            schema.HtmlKeys.Add(k);
        if (schema.HtmlKeys.Count == 0 && !schema.PreferJsPayload)
            schema.HtmlKeys.Add("html");
        return schema;
    }

    /// <summary>Build JSON payloads for a listener using schema + canary marker.</summary>
    public static List<string> BuildPayloadsForListener(string? handlerSource, string canaryHtml, int max = 2)
    {
        var schema = InferMessageSchema(handlerSource);
        var list = new List<string>();

        if (schema.PreferJsPayload)
        {
            var jsExpr = $"window.{TraceInputPayloadPrep.ProofGlobal}=1";
            var codeObj = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase) { ["code"] = jsExpr };
            if (!string.IsNullOrEmpty(schema.TypeLiteral)) codeObj["type"] = schema.TypeLiteral;
            if (!string.IsNullOrEmpty(schema.ActionLiteral)) codeObj["action"] = schema.ActionLiteral;
            list.Add(JsonSerializer.Serialize(codeObj));
            list.Add(JsonSerializer.Serialize(jsExpr));
        }

        if (!string.IsNullOrWhiteSpace(handlerSource) && DirectDataToHtmlSink.IsMatch(handlerSource))
            list.Add(JsonSerializer.Serialize(canaryHtml));

        var obj = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrEmpty(schema.TypeLiteral)) obj["type"] = schema.TypeLiteral;
        if (!string.IsNullOrEmpty(schema.ActionLiteral)) obj["action"] = schema.ActionLiteral;
        if (!string.IsNullOrEmpty(schema.EventLiteral)) obj["event"] = schema.EventLiteral;
        foreach (var k in schema.HtmlKeys.Take(2))
            obj[k] = canaryHtml;
        list.Add(JsonSerializer.Serialize(obj));

        return list.Distinct().Take(Math.Clamp(max, 1, 4)).ToList();
    }

    /// <summary>Shape a probe payload for dispatch via MessageEvent.</summary>
    public static string ShapeForDispatch(string rawPayload, IEnumerable<string>? handlerSources)
    {
        if (LooksLikeJsonObject(rawPayload))
            return rawPayload;

        var src = handlerSources?.FirstOrDefault(s => !string.IsNullOrWhiteSpace(s));
        var schema = InferMessageSchema(src);
        if (schema.PreferJsPayload)
        {
            var js = rawPayload.Contains('<') ? $"{TraceInputPayloadPrep.ProofGlobal}=1" : rawPayload;
            var o = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase) { ["code"] = js };
            if (!string.IsNullOrEmpty(schema.TypeLiteral)) o["type"] = schema.TypeLiteral;
            return JsonSerializer.Serialize(o);
        }

        var keys = InferHtmlPropertyKeys(handlerSources).ToList();
        if (keys.Count == 0)
            keys.Add("html");

        var html = rawPayload;
        if (!html.Contains('<', StringComparison.Ordinal))
            html = $"<img src=x onerror={ExtractOrDefaultOnerror(html)}>";

        var obj = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var k in keys.Take(3))
            obj[k] = html;

        if (!string.IsNullOrEmpty(schema.TypeLiteral))
            obj["type"] = schema.TypeLiteral;
        if (!string.IsNullOrEmpty(schema.ActionLiteral))
            obj["action"] = schema.ActionLiteral;

        return JsonSerializer.Serialize(obj);
    }

    public static IEnumerable<string> InferHtmlPropertyKeys(IEnumerable<string>? handlerSources)
    {
        if (handlerSources == null) yield break;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var src in handlerSources.Where(s => !string.IsNullOrWhiteSpace(s)))
        {
            var parsedVar = Regex.Match(src,
                @"(?:var|let|const)?\s*(\w+)\s*=\s*JSON\.parse\s*\(\s*(?:msg|message|event|e)\.data\s*\)",
                RegexOptions.IgnoreCase);
            if (parsedVar.Success)
            {
                var varName = parsedVar.Groups[1].Value;
                foreach (Match m in Regex.Matches(src, $@"\b{Regex.Escape(varName)}\.(\w+)", RegexOptions.IgnoreCase))
                    TryAdd(seen, m.Groups[1].Value);
            }

            foreach (Match m in JsonParseProp.Matches(src))
                TryAdd(seen, m.Groups[1].Value);
            foreach (Match m in DirectProp.Matches(src))
                TryAdd(seen, m.Groups[1].Value);
            foreach (Match m in Regex.Matches(src, @"content\.(\w+)", RegexOptions.IgnoreCase))
                TryAdd(seen, m.Groups[1].Value);
            if (Regex.IsMatch(src, @"\.data\.html\b", RegexOptions.IgnoreCase))
                TryAdd(seen, "html");
        }

        if (seen.Count == 0)
            yield return "html";
        else
            foreach (var k in seen)
                yield return k;
    }

    private static void TryAdd(HashSet<string> seen, string key)
    {
        if (string.IsNullOrWhiteSpace(key)) return;
        if (key.Equals("type", StringComparison.OrdinalIgnoreCase)
            || key.Equals("origin", StringComparison.OrdinalIgnoreCase))
            return;
        seen.Add(key);
    }

    private static bool LooksLikeJsonObject(string s)
    {
        s = s.Trim();
        return s.StartsWith('{') && s.EndsWith('}');
    }

    private static string ExtractOrDefaultOnerror(string raw)
    {
        if (raw.Contains("alert(", StringComparison.OrdinalIgnoreCase))
            return "alert(1)";
        if (raw.Contains("__trowser_exec", StringComparison.OrdinalIgnoreCase))
            return raw;
        return $"{TraceInputPayloadPrep.ProofGlobal}=1";
    }
}
