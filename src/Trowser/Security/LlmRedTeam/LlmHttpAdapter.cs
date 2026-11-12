using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security.LlmRedTeam;

/// <summary>
/// HTTP transport adapter for LLM red-team probes (OpenAI-compatible, form-urlencoded, and page-fetch schemas).
/// Inspired by OWASP LLM Top 10 testing patterns; layout influenced by pentest-ai
/// <c>agents/llm_redteam/adapter.py</c> — Trowser owns request/response handling.
/// Unexpected JSON shapes return empty model text (not a full dump) to avoid downstream FPs.
/// </summary>
public static class LlmHttpAdapter
{
    private static readonly string[] PromptPlaceholders = ["{{PROMPT}}", "{PROMPT}", "§PROMPT§"];
    private static readonly string[] ModelPlaceholders = ["{{MODEL}}", "{MODEL}", "§MODEL§"];

    private static readonly string[] CsrfFieldNames =
    [
        "csrfmiddlewaretoken", "csrf_token", "_csrf", "authenticity_token",
        "__RequestVerificationToken", "_token", "csrf"
    ];

    public static async Task<string> SendAsync(
        AutomationContext ctx,
        LlmHttpTargetConfig config,
        string prompt,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(config.Url))
            throw new InvalidOperationException("HTTP target requires url.");

        var headers = config.Headers != null
            ? new Dictionary<string, string>(config.Headers, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var (contentType, bodyText) = await BuildRequestContentAsync(ctx, config, prompt, ct);

        if (!headers.ContainsKey("Content-Type"))
            headers["Content-Type"] = contentType;
        else if (IsFormUrlEncoded(headers["Content-Type"]) && LooksLikeJsonObject(bodyText))
        {
            // Caller asked for form encoding but body is still JSON — rebuild as form.
            bodyText = JsonObjectToFormUrlEncoded(bodyText, prompt, config.Model);
            headers["Content-Type"] = "application/x-www-form-urlencoded";
        }

        SecurityProbeHttp.FetchResult fetch;

        if (config.UseBackendFetch)
        {
            fetch = await SecurityProbeHttp.FetchAsync(
                ctx, config.Url, "POST", headers, bodyText,
                config.TimeoutMs, config.IncludeBrowserCookies, ct);
        }
        else
        {
            var fetchJson = await ctx.Fetch(config.Url, "POST", headers, bodyText, config.TimeoutMs);
            using var doc = JsonDocument.Parse(fetchJson);
            var root = doc.RootElement;
            var status = root.TryGetProperty("status", out var st) ? st.GetInt32() : 0;
            var responseBody = root.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
            fetch = new SecurityProbeHttp.FetchResult { Status = status, Body = responseBody };
        }

        // Hard transport failures must not be scored as confident "not fired".
        if (fetch.Status >= 400)
            throw new InvalidOperationException(
                $"LLM target returned HTTP {fetch.Status}: {Truncate(fetch.Body, 200)}");

        return ExtractResponse(config, fetch.Body);
    }

    public static JsonElement BuildBody(LlmHttpTargetConfig config, string prompt)
    {
        var schema = config.Schema?.Trim().ToLowerInvariant() ?? "openai";
        return schema switch
        {
            "openai" => JsonSerializer.SerializeToElement(new
            {
                model = config.Model,
                messages = new[] { new { role = "user", content = prompt } }
            }),
            "simple" => JsonSerializer.SerializeToElement(new { prompt }),
            "custom" => BuildCustomBodyJson(config, prompt),
            _ => throw new InvalidOperationException($"Unknown LLM HTTP schema: {config.Schema}")
        };
    }

    private static async Task<(string ContentType, string Body)> BuildRequestContentAsync(
        AutomationContext ctx,
        LlmHttpTargetConfig config,
        string prompt,
        CancellationToken ct)
    {
        var requestedCt = GetHeader(config.Headers, "Content-Type");
        var preferForm = IsFormUrlEncoded(requestedCt)
                         || (!string.IsNullOrWhiteSpace(config.CustomBodyRaw)
                             && !LooksLikeJsonObject(config.CustomBodyRaw));

        var schema = config.Schema?.Trim().ToLowerInvariant() ?? "openai";

        if (schema == "custom" && !string.IsNullOrWhiteSpace(config.CustomBodyRaw))
        {
            // JSON templates: parse first, then substitute into string nodes (JSON-safe).
            // Never splice raw prompts into a JSON string — newlines/quotes break the document.
            if (LooksLikeJsonObject(config.CustomBodyRaw))
            {
                var node = JsonNode.Parse(config.CustomBodyRaw)
                           ?? throw new InvalidOperationException("customBody string is invalid JSON.");
                ReplacePlaceholders(node, prompt, config.Model);
                return ("application/json", node.ToJsonString());
            }

            var raw = ReplacePlaceholdersInString(config.CustomBodyRaw, prompt, config.Model);
            if (preferForm || IsFormUrlEncodedBody(raw))
            {
                raw = await RefreshCsrfTokensAsync(ctx, raw, ct);
                return ("application/x-www-form-urlencoded", raw);
            }

            return (string.IsNullOrWhiteSpace(requestedCt) ? "application/json" : requestedCt!, raw);
        }

        if (schema == "custom" && preferForm && config.CustomBody != null && config.CustomBody.Count > 0)
        {
            var form = EncodeDictionaryAsForm(config.CustomBody, prompt, config.Model);
            form = await RefreshCsrfTokensAsync(ctx, form, ct);
            return ("application/x-www-form-urlencoded", form);
        }

        if (schema == "custom" && preferForm && !string.IsNullOrWhiteSpace(config.CustomBodyJson))
        {
            var form = JsonObjectToFormUrlEncoded(config.CustomBodyJson, prompt, config.Model);
            form = await RefreshCsrfTokensAsync(ctx, form, ct);
            return ("application/x-www-form-urlencoded", form);
        }

        var json = BuildBody(config, prompt).GetRawText();
        return (string.IsNullOrWhiteSpace(requestedCt) ? "application/json" : requestedCt!, json);
    }

    private static JsonElement BuildCustomBodyJson(LlmHttpTargetConfig config, string prompt)
    {
        JsonNode node;
        if (!string.IsNullOrWhiteSpace(config.CustomBodyJson))
        {
            node = JsonNode.Parse(config.CustomBodyJson)
                   ?? throw new InvalidOperationException("customBodyJson is invalid JSON.");
        }
        else if (config.CustomBody != null && config.CustomBody.Count > 0)
        {
            node = JsonNode.Parse(JsonSerializer.Serialize(config.CustomBody))!;
        }
        else if (!string.IsNullOrWhiteSpace(config.CustomBodyRaw) && LooksLikeJsonObject(config.CustomBodyRaw))
        {
            node = JsonNode.Parse(config.CustomBodyRaw)
                   ?? throw new InvalidOperationException("customBody string is invalid JSON.");
            ReplacePlaceholders(node, prompt, config.Model);
            return JsonSerializer.SerializeToElement(node);
        }
        else
        {
            throw new InvalidOperationException("custom schema requires customBody or customBodyJson.");
        }

        ReplacePlaceholders(node, prompt, config.Model);
        return JsonSerializer.SerializeToElement(node);
    }

    private static void ReplacePlaceholders(JsonNode node, string prompt, string model)
    {
        switch (node)
        {
            case JsonValue val when val.TryGetValue<string>(out var s):
                var replaced = ReplacePlaceholdersInString(s, prompt, model);
                if (!ReferenceEquals(replaced, s) && replaced != s)
                    val.ReplaceWith(replaced);
                break;
            case JsonObject obj:
                foreach (var kv in obj.ToList())
                    ReplacePlaceholders(kv.Value!, prompt, model);
                break;
            case JsonArray arr:
                foreach (var item in arr)
                {
                    if (item != null) ReplacePlaceholders(item, prompt, model);
                }
                break;
        }
    }

    private static string ReplacePlaceholdersInString(string s, string prompt, string model)
    {
        var replaced = s;
        foreach (var needle in PromptPlaceholders)
            replaced = replaced.Replace(needle, prompt, StringComparison.Ordinal);
        foreach (var needle in ModelPlaceholders)
            replaced = replaced.Replace(needle, model, StringComparison.Ordinal);
        return replaced;
    }

    private static string EncodeDictionaryAsForm(
        Dictionary<string, object> fields,
        string prompt,
        string model)
    {
        var parts = new List<string>();
        foreach (var kv in fields)
        {
            var value = kv.Value?.ToString() ?? "";
            value = ReplacePlaceholdersInString(value, prompt, model);
            parts.Add($"{WebUtility.UrlEncode(kv.Key)}={WebUtility.UrlEncode(value)}");
        }

        return string.Join("&", parts);
    }

    private static string JsonObjectToFormUrlEncoded(string json, string prompt, string model)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return ReplacePlaceholdersInString(json, prompt, model);

            var parts = new List<string>();
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                var value = prop.Value.ValueKind == JsonValueKind.String
                    ? prop.Value.GetString() ?? ""
                    : prop.Value.ToString();
                value = ReplacePlaceholdersInString(value, prompt, model);
                parts.Add($"{WebUtility.UrlEncode(prop.Name)}={WebUtility.UrlEncode(value)}");
            }

            return string.Join("&", parts);
        }
        catch
        {
            return ReplacePlaceholdersInString(json, prompt, model);
        }
    }

    /// <summary>
    /// Refresh common CSRF field values from the live page (hidden inputs / meta / cookies).
    /// </summary>
    private static async Task<string> RefreshCsrfTokensAsync(
        AutomationContext ctx,
        string formBody,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(formBody)) return formBody;

        var needsRefresh = CsrfFieldNames.Any(name =>
            formBody.Contains(name + "=", StringComparison.OrdinalIgnoreCase));
        if (!needsRefresh) return formBody;

        string? pageTokensJson = null;
        try
        {
            ct.ThrowIfCancellationRequested();
            pageTokensJson = await ctx.ExecuteJs(
                "(function(){" +
                "var out={};" +
                "var names=['csrfmiddlewaretoken','csrf_token','_csrf','authenticity_token'," +
                "'__RequestVerificationToken','_token','csrf'];" +
                "for(var i=0;i<names.length;i++){" +
                "  var n=names[i];" +
                "  var el=document.querySelector('input[name=\"'+n+'\"],input[name=\"'+n.toLowerCase()+'\"]');" +
                "  if(el&&el.value) out[n]=el.value;" +
                "  var meta=document.querySelector('meta[name=\"csrf-token\"],meta[name=\"'+n+'\"]');" +
                "  if(meta){var c=meta.getAttribute('content'); if(c) out[n]=c;}" +
                "}" +
                "return JSON.stringify(out);" +
                "})()");
        }
        catch
        {
            // Best-effort only.
        }

        Dictionary<string, string>? pageTokens = null;
        if (!string.IsNullOrWhiteSpace(pageTokensJson))
        {
            try
            {
                var unwrapped = pageTokensJson.Trim();
                if (unwrapped.StartsWith('"'))
                    unwrapped = JsonSerializer.Deserialize<string>(unwrapped) ?? unwrapped;
                pageTokens = JsonSerializer.Deserialize<Dictionary<string, string>>(unwrapped);
            }
            catch
            {
                // ignore
            }
        }

        string? cookieToken = null;
        try
        {
            var cookies = await ctx.GetCookies();
            foreach (var c in cookies)
            {
                var name = c.TryGetValue("name", out var n) ? n?.ToString() ?? "" : "";
                if (name.Equals("csrftoken", StringComparison.OrdinalIgnoreCase)
                    || name.Equals("csrf_token", StringComparison.OrdinalIgnoreCase)
                    || name.Equals("XSRF-TOKEN", StringComparison.OrdinalIgnoreCase)
                    || name.Equals("__RequestVerificationToken", StringComparison.OrdinalIgnoreCase))
                {
                    cookieToken = c.TryGetValue("value", out var v) ? v?.ToString() : null;
                    if (!string.IsNullOrWhiteSpace(cookieToken)) break;
                }
            }
        }
        catch
        {
            // ignore
        }

        var updated = formBody;
        foreach (var field in CsrfFieldNames)
        {
            string? fresh = null;
            if (pageTokens != null)
            {
                foreach (var kv in pageTokens)
                {
                    if (kv.Key.Equals(field, StringComparison.OrdinalIgnoreCase)
                        && !string.IsNullOrWhiteSpace(kv.Value))
                    {
                        fresh = kv.Value;
                        break;
                    }
                }
            }

            fresh ??= cookieToken;
            if (string.IsNullOrWhiteSpace(fresh)) continue;

            updated = Regex.Replace(
                updated,
                $@"(?:^|&)({Regex.Escape(field)})=[^&]*",
                m => $"{(m.Value.StartsWith('&') ? "&" : "")}{m.Groups[1].Value}={WebUtility.UrlEncode(fresh)}",
                RegexOptions.IgnoreCase);
        }

        return updated;
    }

    public static string ExtractResponse(LlmHttpTargetConfig config, string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return "";

        if (LooksLikeSse(body))
        {
            var sseText = ExtractSseText(body);
            if (!string.IsNullOrWhiteSpace(sseText))
                return sseText;
        }

        try
        {
            using var doc = JsonDocument.Parse(body);
            var data = doc.RootElement;
            var schema = config.Schema?.Trim().ToLowerInvariant() ?? "openai";

            if (schema == "openai")
            {
                if (data.TryGetProperty("choices", out var choices)
                    && choices.ValueKind == JsonValueKind.Array
                    && choices.GetArrayLength() > 0)
                {
                    var first = choices[0];
                    if (first.TryGetProperty("message", out var msg)
                        && msg.TryGetProperty("content", out var content))
                        return content.GetString() ?? "";
                    if (first.TryGetProperty("text", out var text))
                        return text.GetString() ?? "";
                }

                // Unexpected OpenAI shape — avoid dumping full JSON into probe oracles.
                return "";
            }

            if (schema == "simple")
            {
                foreach (var key in new[] { "response", "output", "text", "message", "answer", "content" })
                {
                    if (data.TryGetProperty(key, out var val))
                        return ExtractJsonText(val);
                }

                return "";
            }

            if (schema == "custom")
            {
                if (!string.IsNullOrEmpty(config.CustomResponseKey)
                    && data.TryGetProperty(config.CustomResponseKey, out var custom))
                    return ExtractJsonText(custom);
                foreach (var key in new[] { "response", "output", "text", "message", "answer", "content", "reply" })
                {
                    if (data.TryGetProperty(key, out var val))
                        return ExtractJsonText(val);
                }

                return "";
            }
        }
        catch
        {
            return body;
        }

        return body;
    }

    /// <summary>Accumulate <c>data:</c> lines from an SSE payload into plain text.</summary>
    public static string ExtractSseText(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return "";
        var plain = SseParser.ExtractDataText(body);
        if (string.IsNullOrEmpty(plain)) return "";

        var sb = new StringBuilder();
        foreach (var chunk in plain.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                using var doc = JsonDocument.Parse(chunk);
                var extracted = TryExtractJsonContent(doc.RootElement);
                if (!string.IsNullOrEmpty(extracted))
                {
                    sb.Append(extracted);
                    continue;
                }
            }
            catch
            {
                sb.Append(chunk);
            }
        }

        return sb.Length > 0 ? sb.ToString().Trim() : plain;
    }

    private static string? TryExtractJsonContent(JsonElement data)
    {
        foreach (var key in new[] { "content", "text", "delta", "response", "message", "answer", "token" })
        {
            if (!data.TryGetProperty(key, out var val)) continue;
            if (val.ValueKind == JsonValueKind.String)
                return val.GetString();
            if (val.ValueKind == JsonValueKind.Object
                && val.TryGetProperty("content", out var nested)
                && nested.ValueKind == JsonValueKind.String)
                return nested.GetString();
        }

        if (data.TryGetProperty("choices", out var choices)
            && choices.ValueKind == JsonValueKind.Array
            && choices.GetArrayLength() > 0)
        {
            var first = choices[0];
            if (first.TryGetProperty("delta", out var delta)
                && delta.TryGetProperty("content", out var c)
                && c.ValueKind == JsonValueKind.String)
                return c.GetString();
            if (first.TryGetProperty("text", out var t) && t.ValueKind == JsonValueKind.String)
                return t.GetString();
        }

        return null;
    }

    public static bool LooksLikeSse(string body) => SseParser.LooksLikeSse(body);

    private static string ExtractJsonText(JsonElement val) =>
        val.ValueKind == JsonValueKind.String
            ? val.GetString() ?? ""
            : val.ValueKind is JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False
                ? val.ToString()
                : "";

    private static string? GetHeader(Dictionary<string, string>? headers, string name)
    {
        if (headers == null) return null;
        return headers.TryGetValue(name, out var v) ? v : null;
    }

    private static bool IsFormUrlEncoded(string? contentType) =>
        !string.IsNullOrWhiteSpace(contentType)
        && contentType.Contains("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase);

    private static bool IsFormUrlEncodedBody(string body) =>
        !LooksLikeJsonObject(body)
        && body.Contains('=')
        && (body.Contains('&') || !body.Contains('{'));

    private static bool LooksLikeJsonObject(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        var t = text.TrimStart();
        return t.StartsWith('{') || t.StartsWith('[');
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "...";
}
