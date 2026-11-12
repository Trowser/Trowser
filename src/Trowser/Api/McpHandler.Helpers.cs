using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Trowser;
using Trowser.Accessibility;
using Trowser.Automation;
using Trowser.Chat;
using Trowser.Compatibility;
using Trowser.Robustness;
using Trowser.ResourceUsage;
using Trowser.Scripting;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Vpx;
using Trowser.Security.Orchestration;
using Trowser.Security.Workflow;
using Trowser.Security.WebSocket;
using Trowser.SessionLog;

namespace Trowser.Api;

public partial class McpHandler
{
    #region Schema Helpers

    private static object Tool(string name, string description, Dictionary<string, object> inputSchema,
        string[]? required = null)
    {
        // Security scans/probes get a uniform `verbose` flag that surfaces the actual HTTP requests
        // they issue (method/URL/payload) so a human can verify exactly what was sent.
        if (IsTraceableSecurityTool(name)
            && inputSchema.TryGetValue("properties", out var propsObj)
            && propsObj is Dictionary<string, object> props
            && !props.ContainsKey("verbose"))
        {
            props["verbose"] = SBool(
                "Include a trace of the actual HTTP requests this scan issues (method, URL, payload, " +
                "status) so you can see and verify exactly what was sent (default: false).");
        }

        if (required != null)
            inputSchema["required"] = required;
        return new { name, description, inputSchema };
    }

    /// <summary>
    /// Tools that issue outbound HTTP probes and therefore support the generic <c>verbose</c>
    /// request trace. Kept in one place so schema generation and dispatch stay in sync.
    /// </summary>
    private static bool IsTraceableSecurityTool(string name) =>
        name.StartsWith("browser_security", StringComparison.Ordinal)
        || name is "browser_attack_surface"
            or "browser_firewall_test"
            or "browser_authz_role_matrix"
            or "browser_saml_replay"
            or "browser_trace_input";

    private static Dictionary<string, object> Schema(params (string name, object schema)[] properties)
    {
        var props = new Dictionary<string, object>();
        foreach (var (name, schema) in properties)
            props[name] = schema;
        return new Dictionary<string, object> { ["type"] = "object", ["properties"] = props };
    }

    /// <summary>
    /// Element targeting props for tools that need a target (click, type, hover, …).
    /// Adds <c>anyOf</c> so clients must supply at least one locator (<c>ref</c> preferred).
    /// </summary>
    private static Dictionary<string, object> ElementSchema(params (string name, object schema)[] extra)
        => BuildElementSchema(requireTarget: true, includeTextLocatorAlias: true, extra);

    /// <summary>
    /// Same locator props as <see cref="ElementSchema"/> but target is optional
    /// (scroll direction-only, press_key without focus target, full-page screenshot).
    /// </summary>
    private static Dictionary<string, object> OptionalElementSchema(params (string name, object schema)[] extra)
        => BuildElementSchema(requireTarget: false, includeTextLocatorAlias: true, extra);

    /// <summary>
    /// Locator props for <c>browser_type</c>: no <c>text</c> locator alias (text/value are typed content).
    /// Requires a target locator and one of value/text/html via <c>allOf</c>/<c>anyOf</c>.
    /// </summary>
    private static Dictionary<string, object> TypeElementSchema(params (string name, object schema)[] extra)
    {
        var schema = BuildElementSchema(requireTarget: true, includeTextLocatorAlias: false, extra);
        // Merge content requirement with existing locator anyOf.
        if (schema.TryGetValue("anyOf", out var locatorAnyOf))
        {
            schema.Remove("anyOf");
            schema["allOf"] = new object[]
            {
                new Dictionary<string, object> { ["anyOf"] = locatorAnyOf },
                new Dictionary<string, object>
                {
                    ["anyOf"] = new object[]
                    {
                        Req("value"),
                        Req("text"),
                        Req("html")
                    }
                }
            };
        }
        return schema;
    }

    private static Dictionary<string, object> BuildElementSchema(
        bool requireTarget,
        bool includeTextLocatorAlias,
        params (string name, object schema)[] extra)
    {
        var all = new List<(string, object)>
        {
            ("ref", SInt("Element ref number from browser_snapshot (preferred)")),
            ("selector", SStr("CSS selector")),
            ("role", SStr("ARIA role: button, link, textbox, heading, checkbox, radio, combobox, etc.")),
            ("name", SStr("Accessible name (combine with role for specificity)")),
            ("label", SStr("Element's associated label text")),
            ("byText", SStr("Visible text locator (REST-aligned; preferred over 'text')")),
            ("placeholder", SStr("Input placeholder text")),
            ("testId", SStr("data-testid attribute value")),
            ("frame", SStr("Same-origin iframe: frameId from snapshot frames[], iframe name, or CSS selector of the <iframe>"))
        };
        if (includeTextLocatorAlias)
        {
            // Insert after byText to keep related locators together.
            all.Insert(6, ("text", SStr("Alias for byText — visible-text locator (NOT typed content; use browser_type value/text for that)")));
        }
        all.AddRange(extra);
        var schema = Schema(all.ToArray());
        if (requireTarget)
            schema["anyOf"] = LocatorAnyOf(includeTextLocatorAlias);
        return schema;
    }

    private static object[] LocatorAnyOf(bool includeTextLocatorAlias)
    {
        var branches = new List<object>
        {
            Req("ref"),
            Req("selector"),
            Req("role"),
            Req("label"),
            Req("byText"),
            Req("placeholder"),
            Req("testId")
        };
        if (includeTextLocatorAlias)
            branches.Add(Req("text"));
        return branches.ToArray();
    }

    private static Dictionary<string, object> Req(params string[] fields) =>
        new() { ["required"] = fields };

    private static Dictionary<string, object> SStr(string desc) =>
        new() { ["type"] = "string", ["description"] = desc };

    private static Dictionary<string, object> SBool(string desc) =>
        new() { ["type"] = "boolean", ["description"] = desc };

    private static Dictionary<string, object> SInt(string desc) =>
        new() { ["type"] = "integer", ["description"] = desc };

    private static Dictionary<string, object> SNum(string desc) =>
        new() { ["type"] = "number", ["description"] = desc };

    private static Dictionary<string, object> SObj(string desc) =>
        new() { ["type"] = "object", ["description"] = desc };

    private static Dictionary<string, object> SArr(string desc) =>
        new() { ["type"] = "array", ["items"] = new Dictionary<string, object> { ["type"] = "string" }, ["description"] = desc };

    private static Dictionary<string, object> SObjArr(string desc) =>
        new()
        {
            ["type"] = "array",
            // additionalProperties helps strict clients (VS Code / Copilot) that reject bare items:{type:object}.
            ["items"] = new Dictionary<string, object>
            {
                ["type"] = "object",
                ["additionalProperties"] = true
            },
            ["description"] = desc
        };

    #endregion

    #region MCP Content Helpers

    private static object TextContent(string text) => new
    {
        content = new object[] { new { type = "text", text } }
    };

    private static object ErrorContent(string error) => new
    {
        content = new object[] { new { type = "text", text = $"Error: {error}" } },
        isError = true
    };

    private static object ErrorContent(Security.Orchestration.SafetyGateDenial denial)
        => ErrorContent(denial.ToException());

    private static object ErrorContent(ApiCommandException ex)
    {
        var text = ex.Message;
        if (ex.EffectiveSafetyMode != null)
        {
            text +=
                $"\nrequestedSafetyMode: {ex.RequestedSafetyMode}\n" +
                $"effectiveSafetyMode: {ex.EffectiveSafetyMode}\n" +
                $"cappedBy: {ex.CappedBy ?? "null"}";
        }

        return ErrorContent(text);
    }

    /// <summary>
    /// Shared MCP adapter for canonical command builders on <see cref="Host"/>. Converts the tool
    /// arguments to a <see cref="JsonBody"/>, runs the same builder the REST endpoint uses, and
    /// renders the structured result as JSON text. An <see cref="ApiCommandException"/> (e.g. a
    /// safety-gate or validation failure) becomes an <see cref="ErrorContent"/>, mirroring REST.
    /// </summary>
    private async Task<object> RenderHostAsync(JsonElement args, Func<JsonBody, Task<object>> builder)
    {
        try
        {
            var data = await builder(JsonBody.FromToolArguments(args));
            return TextContent(JsonSerializer.Serialize(data, CompactJson));
        }
        catch (ApiCommandException ex)
        {
            return ErrorContent(ex);
        }
        catch (InvalidOperationException ex)
        {
            return ErrorContent(ex.Message);
        }
    }

    /// <summary>
    /// Null-safe version: resolves the builder delegate at call time instead of at expression
    /// time, preventing "Delegate to an instance method cannot have null 'this'" when
    /// <see cref="Host"/> is not wired (e.g. Chat Panel without an API server).
    /// </summary>
    private Task<object> RenderHostSafe(JsonElement args, Func<TrowserApiServer, Func<JsonBody, Task<object>>> selector)
    {
        if (Host == null)
            return Task.FromResult(ErrorContent(
                "This tool requires the REST API server to be running. " +
                "Enable the API server in Settings or restart Trowser with --api-port."));
        return RenderHostAsync(args, selector(Host));
    }

    /// <summary>
    /// Append a verbose request-trace block to a tool result. Tool handlers return anonymous
    /// <c>{ content = object[], isError? }</c> objects (via <see cref="TextContent"/> /
    /// <see cref="ErrorContent"/>); this adds an extra text block listing the HTTP requests the
    /// scan issued. Returns the result unchanged when no requests were captured or the shape is
    /// unexpected.
    /// </summary>
    private static object AppendRequestTrace(object result, Automation.RequestTrace trace)
    {
        try
        {
            var type = result.GetType();
            if (type.GetProperty("content")?.GetValue(result) is not object[] content)
                return result;

            // Always append when verbose was requested — even with zero captures — so agents
            // can see the flag was honored (REST attaches top-level verboseTrace the same way).
            var traceBlock = new { type = "text", text = Automation.RequestTraceFormatter.ToText(trace) };
            var combined = new object[content.Length + 1];
            Array.Copy(content, combined, content.Length);
            combined[^1] = traceBlock;

            var isErrorProp = type.GetProperty("isError");
            if (isErrorProp != null)
                return new { content = combined, isError = (bool)(isErrorProp.GetValue(result) ?? false) };
            return new { content = combined };
        }
        catch
        {
            return result;
        }
    }

    #endregion

    #region JSON-RPC Helpers

    private static string RpcSuccess(object? id, object result)
    {
        var resp = new Dictionary<string, object?>
        {
            ["jsonrpc"] = "2.0", ["id"] = id, ["result"] = result
        };
        return JsonSerializer.Serialize(resp, CompactJson);
    }

    private static string RpcError(object? id, int code, string message)
    {
        var resp = new Dictionary<string, object?>
        {
            ["jsonrpc"] = "2.0",
            ["id"] = id,
            ["error"] = new { code, message }
        };
        return JsonSerializer.Serialize(resp, CompactJson);
    }

    private static object? ReadId(JsonElement el) => el.ValueKind switch
    {
        JsonValueKind.Number => el.TryGetInt64(out var l) ? l : (object)el.GetDouble(),
        JsonValueKind.String => el.GetString(),
        _ => null
    };

    #endregion

    #region Arg Helpers

    private static string? GetString(JsonElement args, string prop)
    {
        if (args.ValueKind != JsonValueKind.Object) return null;
        return args.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() : null;
    }

    private static bool GetBool(JsonElement args, string prop, bool defaultValue = false)
    {
        if (args.ValueKind != JsonValueKind.Object) return defaultValue;
        if (!args.TryGetProperty(prop, out var v)) return defaultValue;
        return v.ValueKind == JsonValueKind.True;
    }

    private static int GetInt(JsonElement args, string prop, int defaultValue = 0)
    {
        if (args.ValueKind != JsonValueKind.Object) return defaultValue;
        return args.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.Number
            ? v.GetInt32() : defaultValue;
    }

    private static double GetDouble(JsonElement args, string prop, double defaultValue = 0)
    {
        if (args.ValueKind != JsonValueKind.Object) return defaultValue;
        return args.TryGetProperty(prop, out var v) && v.ValueKind == JsonValueKind.Number
            ? v.GetDouble() : defaultValue;
    }

    private static List<string>? GetStringArray(JsonElement args, string prop)
    {
        if (args.ValueKind != JsonValueKind.Object) return null;
        if (!args.TryGetProperty(prop, out var v) || v.ValueKind != JsonValueKind.Array) return null;
        var list = new List<string>();
        foreach (var item in v.EnumerateArray())
            if (item.ValueKind == JsonValueKind.String)
                list.Add(item.GetString()!);
        return list.Count > 0 ? list : null;
    }

    private static List<string>? MergeMcpTargets(List<string>? primary, List<string>? secondary)
    {
        if (primary is not { Count: > 0 } && secondary is not { Count: > 0 })
            return null;
        var merged = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void AddRange(IEnumerable<string>? items)
        {
            if (items == null) return;
            foreach (var item in items)
            {
                if (string.IsNullOrWhiteSpace(item)) continue;
                if (seen.Add(item.Trim()))
                    merged.Add(item.Trim());
            }
        }
        AddRange(primary);
        AddRange(secondary);
        return merged;
    }

    private static List<IReadOnlyDictionary<string, string>>? ParseMcpHeaderSets(JsonElement args)
    {
        if (args.ValueKind != JsonValueKind.Object) return null;
        if (!args.TryGetProperty("headerSets", out var sets) || sets.ValueKind != JsonValueKind.Array)
            return null;

        var result = new List<IReadOnlyDictionary<string, string>>();
        foreach (var set in sets.EnumerateArray())
        {
            if (set.ValueKind != JsonValueKind.Object) continue;
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var prop in set.EnumerateObject())
            {
                if (prop.Value.ValueKind == JsonValueKind.String)
                    dict[prop.Name] = prop.Value.GetString() ?? "";
            }
            if (dict.Count > 0)
                result.Add(dict);
        }

        return result.Count > 0 ? result : null;
    }

    private static Dictionary<string, string>? BuildMcpChainProveOverrides(JsonElement args) =>
        ChainProveSubstitutionHelper.FromJsonElement(args);

    private static List<Robustness.CustomFault>? ParseCustomFaults(JsonElement args)
    {
        if (args.ValueKind != JsonValueKind.Object) return null;
        if (!args.TryGetProperty("customFaults", out var arr) || arr.ValueKind != JsonValueKind.Array) return null;
        var list = new List<Robustness.CustomFault>();
        foreach (var item in arr.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object) continue;
            var name = GetString(item, "name");
            if (string.IsNullOrWhiteSpace(name)) continue;
            Dictionary<string, string>? headers = null;
            if (item.TryGetProperty("headers", out var h) && h.ValueKind == JsonValueKind.Object)
            {
                headers = new Dictionary<string, string>();
                foreach (var prop in h.EnumerateObject())
                    headers[prop.Name] = prop.Value.GetString() ?? "";
            }
            list.Add(new Robustness.CustomFault
            {
                Name = name,
                Status = GetInt(item, "status", 500),
                Body = GetString(item, "body"),
                Headers = headers,
                DelayMs = GetInt(item, "delayMs"),
            });
        }
        return list.Count > 0 ? list : null;
    }

    private static List<Robustness.InterrupterAction>? ParseInterrupterActions(JsonElement args)
    {
        if (args.ValueKind != JsonValueKind.Object) return null;
        if (!args.TryGetProperty("actions", out var arr) || arr.ValueKind != JsonValueKind.Array) return null;
        var list = new List<Robustness.InterrupterAction>();
        foreach (var item in arr.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object) continue;
            var action = GetString(item, "action");
            if (string.IsNullOrWhiteSpace(action)) continue;
            list.Add(new Robustness.InterrupterAction
            {
                Action = action,
                Ref = item.TryGetProperty("ref", out var r) && r.ValueKind == JsonValueKind.Number ? r.GetInt32() : null,
                Selector = GetString(item, "selector"),
                ByText = GetString(item, "byText"),
                Placeholder = GetString(item, "placeholder"),
                Role = GetString(item, "role"),
                Name = GetString(item, "name"),
                Label = GetString(item, "label"),
                TestId = GetString(item, "testId"),
                Text = GetString(item, "text"),
                Value = GetString(item, "value"),
                Key = GetString(item, "key"),
                DelayMs = GetInt(item, "delayMs"),
            });
        }
        return list.Count > 0 ? list : null;
    }

    private int? ResolveTabTargetFromArgs(JsonElement args, out string? error)
    {
        error = null;
        try
        {
            int? tabIndexArg = null;
            if (args.TryGetProperty("tabIndex", out var ti) && ti.ValueKind == JsonValueKind.Number)
            {
                tabIndexArg = ti.GetInt32();
                if (tabIndexArg < 0)
                {
                    error = "tabIndex must be >= 0 when provided.";
                    return null;
                }
            }

            return _context.ResolveTabTarget(tabIndexArg, GetString(args, "urlMatch"));
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or InvalidOperationException)
        {
            error = ex.Message;
            return null;
        }
    }

    #endregion

    #region Exceptions

    private class MethodNotFoundException : Exception { }

    private class InvalidParamsException(string message) : Exception(message);

    #endregion
}
