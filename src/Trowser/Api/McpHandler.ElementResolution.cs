using System.Diagnostics;
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
    #region Element Resolution

    private string? ResolveElement(JsonElement args)
    {
        if (args.ValueKind != JsonValueKind.Object) return null;

        string? frame = GetString(args, "frame");
        string? resolved = null;

        if (args.TryGetProperty("ref", out var refProp) && refProp.ValueKind == JsonValueKind.Number)
        {
            var refIndex = refProp.GetInt32();
            resolved = _context.GetSelectorByRef(refIndex)
                ?? throw new InvalidOperationException(
                    $"Invalid ref: {refIndex}. Call browser_snapshot to get current ref numbers.");
            frame ??= _context.GetFrameIdByRef(refIndex);
        }
        else if (args.TryGetProperty("selector", out var selProp) && selProp.ValueKind == JsonValueKind.String)
        {
            var sel = selProp.GetString();
            if (!string.IsNullOrEmpty(sel)) resolved = sel;
        }
        else if (args.TryGetProperty("role", out var roleProp) && roleProp.ValueKind == JsonValueKind.String)
        {
            var role = roleProp.GetString() ?? "";
            var name = GetString(args, "name") ?? "";
            resolved = $"@role:{role}:{name}";
        }
        else if (args.TryGetProperty("label", out var lbl) && lbl.ValueKind == JsonValueKind.String)
            resolved = $"@label:{lbl.GetString()}";
        else if (args.TryGetProperty("byText", out var byTxt) && byTxt.ValueKind == JsonValueKind.String)
            resolved = $"@text:{byTxt.GetString()}";
        else if (args.TryGetProperty("text", out var txt) && txt.ValueKind == JsonValueKind.String)
            resolved = $"@text:{txt.GetString()}";
        else if (args.TryGetProperty("placeholder", out var ph) && ph.ValueKind == JsonValueKind.String)
            resolved = $"@placeholder:{ph.GetString()}";
        else if (args.TryGetProperty("testId", out var tid) && tid.ValueKind == JsonValueKind.String)
            resolved = $"@testid:{tid.GetString()}";

        if (resolved == null) return null;
        return AutomationContext.ApplyFrame(resolved, frame);
    }

    /// <summary>
    /// Resolve a target for <c>browser_type</c>. Same as <see cref="ResolveElement"/> but ignores
    /// <c>text</c> as a locator — on type, <c>text</c>/<c>value</c> are typed content; use <c>byText</c>
    /// for a visible-text locator.
    /// </summary>
    private string? ResolveTypeElement(JsonElement args)
    {
        if (args.ValueKind != JsonValueKind.Object) return null;

        string? frame = GetString(args, "frame");
        string? resolved = null;

        if (args.TryGetProperty("ref", out var refProp) && refProp.ValueKind == JsonValueKind.Number)
        {
            var refIndex = refProp.GetInt32();
            resolved = _context.GetSelectorByRef(refIndex)
                ?? throw new InvalidOperationException(
                    $"Invalid ref: {refIndex}. Call browser_snapshot to get current ref numbers.");
            frame ??= _context.GetFrameIdByRef(refIndex);
        }
        else if (args.TryGetProperty("selector", out var selProp) && selProp.ValueKind == JsonValueKind.String)
        {
            var sel = selProp.GetString();
            if (!string.IsNullOrEmpty(sel)) resolved = sel;
        }
        else if (args.TryGetProperty("role", out var roleProp) && roleProp.ValueKind == JsonValueKind.String)
        {
            var role = roleProp.GetString() ?? "";
            var name = GetString(args, "name") ?? "";
            resolved = $"@role:{role}:{name}";
        }
        else if (args.TryGetProperty("label", out var lbl) && lbl.ValueKind == JsonValueKind.String)
            resolved = $"@label:{lbl.GetString()}";
        else if (args.TryGetProperty("byText", out var byTxt) && byTxt.ValueKind == JsonValueKind.String)
            resolved = $"@text:{byTxt.GetString()}";
        else if (args.TryGetProperty("placeholder", out var ph) && ph.ValueKind == JsonValueKind.String)
            resolved = $"@placeholder:{ph.GetString()}";
        else if (args.TryGetProperty("testId", out var tid) && tid.ValueKind == JsonValueKind.String)
            resolved = $"@testid:{tid.GetString()}";

        if (resolved == null) return null;
        return AutomationContext.ApplyFrame(resolved, frame);
    }

    /// <summary>Human-readable selector description for tool output.</summary>
    private static string Fmt(string selector)
    {
        if (selector.StartsWith("@role:"))
        {
            var parts = selector[6..].Split(':', 2);
            return parts.Length >= 2 && !string.IsNullOrEmpty(parts[1])
                ? $"role={parts[0]} \"{parts[1]}\""
                : $"role={parts[0]}";
        }
        if (selector.StartsWith("@label:")) return $"label \"{selector[7..]}\"";
        if (selector.StartsWith("@text:")) return $"text \"{selector[6..]}\"";
        if (selector.StartsWith("@placeholder:")) return $"placeholder \"{selector[13..]}\"";
        if (selector.StartsWith("@testid:")) return $"testid \"{selector[8..]}\"";
        if (selector.Length > 60) return $"\"{selector[..57]}...\"";
        return $"\"{selector}\"";
    }

    private object ToolMock(JsonElement args)
    {
        var action = GetString(args, "action") ?? "list";

        switch (action.ToLowerInvariant())
        {
            case "add":
            {
                var urlPattern = GetString(args, "urlPattern");
                if (string.IsNullOrWhiteSpace(urlPattern))
                    return ErrorContent("Missing required field: urlPattern");

                var statusCode = GetInt(args, "status", 200);
                var delayMs = GetInt(args, "delay", 0);
                var body = GetString(args, "body");
                var method = GetString(args, "method");
                Dictionary<string, string>? headers = null;
                if (args.TryGetProperty("headers", out var h) && h.ValueKind == JsonValueKind.Object)
                {
                    headers = new Dictionary<string, string>();
                    foreach (var prop in h.EnumerateObject())
                        headers[prop.Name] = prop.Value.GetString() ?? "";
                }

                _context.MockResponse(urlPattern, statusCode, body, method, headers, delayMs);

                var sb = new System.Text.StringBuilder();
                sb.AppendLine($"Mock added: {urlPattern}");
                sb.AppendLine($"  Status: {statusCode}, Method: {method ?? "any"}, Delay: {delayMs}ms");
                sb.AppendLine($"  Total mock rules: {_context.GetMockRules().Count}");
                return TextContent(sb.ToString());
            }

            case "remove":
            {
                var urlPattern = GetString(args, "urlPattern");
                if (string.IsNullOrWhiteSpace(urlPattern))
                    return ErrorContent("Missing required field: urlPattern");

                _context.RemoveMock(urlPattern);
                return TextContent($"Mock removed: {urlPattern}. Total: {_context.GetMockRules().Count}");
            }

            case "clear":
                _context.ClearMocks();
                return TextContent("All mock rules cleared.");

            default: // "list"
            {
                var rules = _context.GetMockRules();
                if (rules.Count == 0)
                    return TextContent("No active mock rules.");

                var sb = new System.Text.StringBuilder();
                sb.AppendLine($"Active mock rules: {rules.Count}");
                foreach (var r in rules)
                {
                    var methodStr = r.Method ?? "any";
                    sb.AppendLine($"  [{r.StatusCode}] {methodStr} {r.UrlPattern}" +
                                  (r.DelayMs > 0 ? $" (delay {r.DelayMs}ms)" : ""));
                }
                return TextContent(sb.ToString());
            }
        }
    }

    private object ToolIntercept(JsonElement args)
    {
        var action = GetString(args, "action") ?? "list";

        switch (action.ToLowerInvariant())
        {
            case "add":
            {
                var urlPattern = GetString(args, "urlPattern");
                if (string.IsNullOrWhiteSpace(urlPattern))
                    return ErrorContent("Missing required field: urlPattern (regex)");

                var method = GetString(args, "method");
                _context.AddInterceptRule(urlPattern, method, silent: true);
                return TextContent($"Breakpoint added: /{urlPattern}/" +
                                   (method != null ? $" method={method}" : "") +
                                   $". Total: {_context.GetInterceptRules().Count}");
            }

            case "remove":
            {
                var urlPattern = GetString(args, "urlPattern");
                if (string.IsNullOrWhiteSpace(urlPattern))
                    return ErrorContent("Missing required field: urlPattern");

                var removeMethod = GetString(args, "method");
                _context.RemoveInterceptRule(urlPattern, removeMethod);
                return TextContent($"Breakpoint removed: {urlPattern}" +
                                   (removeMethod != null ? $" method={removeMethod}" : "") +
                                   $". Total: {_context.GetInterceptRules().Count}");
            }

            case "clear":
                _context.ClearInterceptRules();
                return TextContent("All breakpoints cleared and pending requests released.");

            case "continue":
            {
                var requestId = GetInt(args, "requestId", -1);
                if (requestId < 0)
                    return ErrorContent("Missing required field: requestId");

                Dictionary<string, string>? headers = null;
                if (args.TryGetProperty("headers", out var h) && h.ValueKind == JsonValueKind.Object)
                {
                    headers = new Dictionary<string, string>();
                    foreach (var prop in h.EnumerateObject())
                        headers[prop.Name] = prop.Value.GetString() ?? "";
                }

                var decision = new InterceptDecision
                {
                    Action = InterceptAction.Continue,
                    ModifiedUrl = GetString(args, "url"),
                    ModifiedMethod = GetString(args, "method"),
                    ModifiedHeaders = headers
                };

                if (!_context.ResolvePendingRequest(requestId, decision))
                    return ErrorContent($"No pending request with ID {requestId}");

                return TextContent($"Request {requestId} continued.");
            }

            case "fulfill":
            {
                var requestId = GetInt(args, "requestId", -1);
                if (requestId < 0)
                    return ErrorContent("Missing required field: requestId");

                var statusCode = GetInt(args, "status", 200);

                Dictionary<string, string>? headers = null;
                if (args.TryGetProperty("headers", out var h) && h.ValueKind == JsonValueKind.Object)
                {
                    headers = new Dictionary<string, string>();
                    foreach (var prop in h.EnumerateObject())
                        headers[prop.Name] = prop.Value.GetString() ?? "";
                }

                var decision = new InterceptDecision
                {
                    Action = InterceptAction.Fulfill,
                    StatusCode = statusCode,
                    Body = GetString(args, "body"),
                    ResponseHeaders = headers
                };

                if (!_context.ResolvePendingRequest(requestId, decision))
                    return ErrorContent($"No pending request with ID {requestId}");

                return TextContent($"Request {requestId} fulfilled with status {statusCode}.");
            }

            case "abort":
            {
                var requestId = GetInt(args, "requestId", -1);
                if (requestId < 0)
                    return ErrorContent("Missing required field: requestId");

                var decision = new InterceptDecision { Action = InterceptAction.Abort };

                if (!_context.ResolvePendingRequest(requestId, decision))
                    return ErrorContent($"No pending request with ID {requestId}");

                return TextContent($"Request {requestId} aborted.");
            }

            default: // "list"
            {
                var rules = _context.GetInterceptRules();
                var pending = _context.GetPendingRequests();

                var sb = new System.Text.StringBuilder();
                sb.AppendLine($"Breakpoint rules: {rules.Count}");
                foreach (var r in rules)
                    sb.AppendLine($"  /{r.UrlPattern}/" + (r.Method != null ? $" method={r.Method}" : ""));

                sb.AppendLine($"\nPending requests: {pending.Count}");
                foreach (var p in pending)
                    sb.AppendLine($"  [{p.Id}] {p.Method} {p.Url} (matched /{p.MatchedPattern}/)");

                return TextContent(sb.ToString());
            }
        }
    }

    private async Task<object> ToolNetworkThrottle(JsonElement args)
    {
        var action = GetString(args, "action") ?? "get";

        switch (action.ToLowerInvariant())
        {
            case "set":
            {
                var preset = GetString(args, "preset");
                if (!string.IsNullOrWhiteSpace(preset))
                {
                    await _context.SetNetworkThrottle(preset);
                    var s = _context.ThrottleState!;
                    return TextContent($"Network throttle set to {preset}: {s.DownloadKbps} KB/s down, {s.UploadKbps} KB/s up, {s.LatencyMs}ms latency" +
                                       (s.Offline ? " (offline)" : ""));
                }

                var download = GetInt(args, "downloadKbps", 0);
                var upload = GetInt(args, "uploadKbps", 0);
                var latency = GetInt(args, "latencyMs", 0);
                var offline = GetBool(args, "offline");

                if (download == 0 && upload == 0 && latency == 0 && !offline)
                    return ErrorContent("Provide 'preset' (2G, Slow3G, 3G, 4G, Offline) or custom values (downloadKbps, uploadKbps, latencyMs).");

                await _context.SetNetworkThrottle(download, upload, latency, offline);
                return TextContent($"Network throttle set: {download} KB/s down, {upload} KB/s up, {latency}ms latency" +
                                   (offline ? " (offline)" : ""));
            }

            case "clear":
                await _context.ClearNetworkThrottle();
                return TextContent("Network throttling disabled. Full speed restored.");

            default: // "get"
            {
                var state = _context.ThrottleState;
                if (state == null)
                    return TextContent("Network throttling is disabled (full speed).\n\n" +
                                       "Available presets: 2G, Slow3G, 3G, 4G, Offline");

                return TextContent($"Network throttle active: {state.DownloadKbps} KB/s down, {state.UploadKbps} KB/s up, {state.LatencyMs}ms latency" +
                                   (state.Offline ? " (offline)" : ""));
            }
        }
    }

    private async Task<object> ToolWaitForNetwork(JsonElement args)
    {
        var urlPattern = GetString(args, "urlPattern");
        if (string.IsNullOrWhiteSpace(urlPattern))
            return ErrorContent("Missing required field: urlPattern (URL substring to match).");

        var method = GetString(args, "method");
        var status = args.TryGetProperty("status", out var sp) && sp.ValueKind == JsonValueKind.Number
            ? (int?)sp.GetInt32() : null;
        var timeout = GetInt(args, "timeout", 10000);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            var entry = await _context.WaitForRequest(urlPattern, method, status, timeout);
            sw.Stop();
            return TextContent($"Matched: {entry.Method} {entry.Url} -> {entry.StatusCode} ({sw.ElapsedMilliseconds}ms)");
        }
        catch (TimeoutException)
        {
            sw.Stop();
            var desc = urlPattern;
            if (method != null) desc += $" method={method}";
            if (status != null) desc += $" status={status}";
            return TextContent($"No matching request within {timeout}ms for: {desc}");
        }
    }

    private async Task<object> ToolStorage(JsonElement args)
    {
        var tabTarget = ResolveTabTargetFromArgs(args, out var tabErr);
        if (tabErr != null)
            return ErrorContent(tabErr);

        try
        {
            return await _context.InvokeOnTabAsync(tabTarget, () => ToolStorageCore(args));
        }
        catch (InvalidOperationException ex)
        {
            return ErrorContent(ex.Message);
        }
    }

    private async Task<object> ToolStorageCore(JsonElement args)
    {
        var action = GetString(args, "action") ?? "get";
        var type = GetString(args, "type") ?? "local";
        var isIdb = type.Equals("indexeddb", StringComparison.OrdinalIgnoreCase)
                    || type.Equals("idb", StringComparison.OrdinalIgnoreCase);

        switch (action.ToLowerInvariant())
        {
            case "get":
            {
                if (isIdb)
                {
                    var db = GetString(args, "db") ?? GetString(args, "database");
                    var store = GetString(args, "store");
                    var limit = GetInt(args, "limit", 0);
                    var snap = await _context.GetIndexedDb(db, store, limit > 0 ? limit : null);
                    var key = GetString(args, "key");
                    if (!string.IsNullOrWhiteSpace(key))
                    {
                        var flat = await _context.GetIndexedDbFlat(db, store, limit > 0 ? limit : null);
                        return TextContent(flat.TryGetValue(key, out var value)
                            ? $"indexedDB[\"{key}\"] = {value}"
                            : $"indexedDB[\"{key}\"] is not set (null)");
                    }

                    if (snap.DatabaseCount == 0)
                        return TextContent("IndexedDB is empty.");

                    var sbIdb = new System.Text.StringBuilder();
                    sbIdb.AppendLine($"IndexedDB ({snap.DatabaseCount} databases, {snap.RecordCount} records, method={snap.Method}):");
                    foreach (var database in snap.Databases)
                    {
                        sbIdb.AppendLine($"  DB {database.Name} v{database.Version}:");
                        foreach (var st in database.Stores)
                        {
                            sbIdb.AppendLine($"    store {st.Name} ({st.RecordCount} records):");
                            foreach (var rec in st.Records.Take(20))
                            {
                                var display = (rec.Value ?? "").Length > 100
                                    ? (rec.Value ?? "")[..100] + "..."
                                    : rec.Value ?? "";
                                sbIdb.AppendLine($"      {rec.Key} = {display}");
                            }
                        }
                    }
                    if (snap.Truncated) sbIdb.AppendLine("  (truncated)");
                    return TextContent(sbIdb.ToString());
                }

                var keyLocal = GetString(args, "key");
                if (!string.IsNullOrWhiteSpace(keyLocal))
                {
                    var value = await _context.GetStorageItem(type, keyLocal);
                    return TextContent(value != null
                        ? $"{type}Storage[\"{keyLocal}\"] = {value}"
                        : $"{type}Storage[\"{keyLocal}\"] is not set (null)");
                }

                var all = await _context.GetAllStorage(type);
                if (all.Count == 0)
                    return TextContent($"{type}Storage is empty.");

                var sb = new System.Text.StringBuilder();
                sb.AppendLine($"{type}Storage ({all.Count} entries):");
                foreach (var (k, v) in all)
                {
                    var display = v.Length > 100 ? v[..100] + "..." : v;
                    sb.AppendLine($"  {k} = {display}");
                }
                return TextContent(sb.ToString());
            }

            case "set":
            {
                if (isIdb)
                    return ErrorContent("IndexedDB write via set is not supported. Use delete/clear.");
                var key = GetString(args, "key");
                var value = GetString(args, "value");
                if (string.IsNullOrWhiteSpace(key))
                    return ErrorContent("Missing required field: key");
                if (value == null)
                    return ErrorContent("Missing required field: value");

                await _context.SetStorageItem(type, key, value);
                return TextContent($"Set {type}Storage[\"{key}\"] = {value}");
            }

            case "delete":
            {
                if (isIdb)
                {
                    var database = GetString(args, "db") ?? GetString(args, "database") ?? GetString(args, "key");
                    var store = GetString(args, "store");
                    if (string.IsNullOrWhiteSpace(database))
                        return ErrorContent("For indexeddb delete, provide db/database (or key) and optional store.");
                    if (!string.IsNullOrWhiteSpace(store))
                    {
                        await _context.ClearIndexedDbStore(database, store);
                        return TextContent($"Cleared IndexedDB store {database}/{store}");
                    }
                    await _context.DeleteIndexedDb(database);
                    return TextContent($"Deleted IndexedDB database {database}");
                }

                var keyDel = GetString(args, "key");
                if (string.IsNullOrWhiteSpace(keyDel))
                    return ErrorContent("Missing required field: key");

                await _context.DeleteStorageItem(type, keyDel);
                return TextContent($"Deleted {type}Storage[\"{keyDel}\"]");
            }

            case "clear":
                if (isIdb)
                {
                    var database = GetString(args, "db") ?? GetString(args, "database");
                    await _context.ClearIndexedDbAsync(database);
                    return TextContent(string.IsNullOrEmpty(database)
                        ? "IndexedDB cleared."
                        : $"IndexedDB databases matching '{database}' cleared.");
                }
                await _context.ClearStorage(type);
                return TextContent($"{type}Storage cleared.");

            default:
                return ErrorContent($"Unknown action: {action}. Use: get, set, delete, clear");
        }
    }

    private async Task<object> ToolFetch(JsonElement args)
    {
        var url = GetString(args, "url");
        if (string.IsNullOrEmpty(url))
            return ErrorContent("Missing required field: url");

        var method = GetString(args, "method") ?? "GET";
        var timeout = GetInt(args, "timeout", 30000);

        Dictionary<string, string>? headers = args.TryGetProperty("headers", out var h)
            ? HttpHeaderDictionary.FromJsonObject(h)
            : null;

        string? body = GetString(args, "body");
        if (body == null && args.TryGetProperty("bodyBase64", out var b64El) && b64El.ValueKind == JsonValueKind.String)
        {
            var b64 = b64El.GetString();
            if (!string.IsNullOrEmpty(b64))
            {
                try
                {
                    body = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
                }
                catch (FormatException)
                {
                    return ErrorContent("bodyBase64 is not valid Base64.");
                }
            }
        }

        if (body == null && args.TryGetProperty("bodyFile", out var bfEl) && bfEl.ValueKind == JsonValueKind.String)
        {
            var filePath = bfEl.GetString();
            if (!string.IsNullOrEmpty(filePath))
            {
                try
                {
                    body = await ExportPathGuard.ReadLocalTextAsync(filePath);
                }
                catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
                {
                    return ErrorContent($"bodyFile not found: {filePath}");
                }
                catch (Exception ex)
                {
                    return ErrorContent($"Failed to read bodyFile: {ex.Message}");
                }
            }
        }

        if (body == null && args.TryGetProperty("json", out var jsonVal))
        {
            body = jsonVal.GetRawText();
            headers = HttpHeaderDictionary.PrepareForJsonBody(headers);
        }

        var redirect = GetString(args, "redirect");
        var serverSide = GetBool(args, "serverSide");

        if (serverSide)
            return await ToolFetchServerSide(url, method, headers, body, timeout, redirect);

        string resultJson;
        try
        {
            resultJson = await _context.Fetch(url, method, headers, body, timeout, redirect, markSynthetic: false);
        }
        catch (InvalidOperationException ex)
        {
            return ErrorContent($"Fetch failed: {ex.Message}");
        }

        using var doc = JsonDocument.Parse(resultJson);
        var root = doc.RootElement;

        var status = root.GetProperty("status").GetInt32();
        var statusText = root.GetProperty("statusText").GetString();
        var responseBody = root.TryGetProperty("body", out var bdy) ? bdy.GetString() ?? "" : "";

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"{method.Trim().ToUpperInvariant()} {url} → {status} {statusText}");
        if (root.TryGetProperty("durationMs", out var dms) && dms.TryGetInt64(out var dm))
            sb.AppendLine($"  durationMs: {dm}");

        if (root.TryGetProperty("redirected", out var rdProp) && rdProp.ValueKind == JsonValueKind.True)
            sb.AppendLine($"  Redirected: true  Final URL: {(root.TryGetProperty("url", out var uProp) ? uProp.GetString() : "?")}");
        var responseType = root.TryGetProperty("type", out var tpProp) ? tpProp.GetString() : null;
        if (responseType == "opaqueredirect")
            sb.AppendLine("  Type: opaqueredirect (redirect captured, body not readable)");
        else if (responseType == "manual-server-side")
            sb.AppendLine("  Type: manual-server-side (cross-origin redirect captured via server-side fallback)");

        sb.AppendLine();

        if (root.TryGetProperty("headers", out var respHeaders) && respHeaders.ValueKind == JsonValueKind.Object)
        {
            sb.AppendLine("Response headers:");
            foreach (var prop in respHeaders.EnumerateObject())
                sb.AppendLine($"  {prop.Name}: {prop.Value.GetString()}");
            sb.AppendLine();
        }

        sb.AppendLine("Body:");
        sb.Append(responseBody);

        return TextContent(sb.ToString());
    }

    private async Task<object> ToolFetchServerSide(string url, string method,
        Dictionary<string, string>? headers, string? body, int timeout, string? redirect)
    {
        var allowRedirect = redirect is not ("manual" or "error");

        var sw = Stopwatch.StartNew();
        var result = await Security.DirectFetchHelper.FetchAsync(
            _context, url, method, headers, body, timeout, allowRedirect);
        sw.Stop();

        if (result.Error != null)
            return ErrorContent($"Server-side fetch failed: {result.Error}");

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"{method.Trim().ToUpperInvariant()} {url} → {result.Status} {result.StatusText}");
        sb.AppendLine("  Mode: server-side (HttpClient with browser cookies — no forbidden header restrictions)");
        sb.AppendLine($"  durationMs: {sw.ElapsedMilliseconds}");

        if (result.Redirected)
            sb.AppendLine($"  Redirected: true  Final URL: {result.FinalUrl}");

        sb.AppendLine();

        if (result.Headers.Count > 0)
        {
            sb.AppendLine("Response headers:");
            foreach (var kv in result.Headers)
                sb.AppendLine($"  {kv.Key}: {kv.Value}");
            sb.AppendLine();
        }

        sb.AppendLine("Body:");
        sb.Append(result.Body);

        return TextContent(sb.ToString());
    }

    private async Task<object> ToolFetchBatch(JsonElement args)
    {
        if (!args.TryGetProperty("requests", out var reqArr) || reqArr.ValueKind != JsonValueKind.Array)
            return ErrorContent("Missing required array: requests");

        var concurrent = GetBool(args, "concurrent", true);
        var items = new List<FetchBatchRequestItem>();
        foreach (var el in reqArr.EnumerateArray())
        {
            if (el.ValueKind != JsonValueKind.Object)
                continue;
            var url = GetString(el, "url");
            if (string.IsNullOrEmpty(url))
                return ErrorContent("Each request must include a non-empty 'url'.");

            var method = GetString(el, "method") ?? "GET";
            var timeout = GetInt(el, "timeout", 30000);

            Dictionary<string, string>? headers = el.TryGetProperty("headers", out var h)
                ? HttpHeaderDictionary.FromJsonObject(h)
                : null;

            string? body = GetString(el, "body");
            if (body == null && el.TryGetProperty("bodyBase64", out var b64El) && b64El.ValueKind == JsonValueKind.String)
            {
                var b64 = b64El.GetString();
                if (!string.IsNullOrEmpty(b64))
                {
                    try
                    {
                        body = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
                    }
                    catch (FormatException)
                    {
                        return ErrorContent("Invalid bodyBase64 in requests array.");
                    }
                }
            }

            if (body == null && el.TryGetProperty("bodyFile", out var bfEl) && bfEl.ValueKind == JsonValueKind.String)
            {
                var filePath = bfEl.GetString();
                if (!string.IsNullOrEmpty(filePath))
                {
                    try
                    {
                        body = await ExportPathGuard.ReadLocalTextAsync(filePath);
                    }
                    catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
                    {
                        return ErrorContent($"bodyFile not found: {filePath}");
                    }
                    catch (Exception ex)
                    {
                        return ErrorContent($"Failed to read bodyFile: {ex.Message}");
                    }
                }
            }

            if (body == null && el.TryGetProperty("json", out var jsonVal))
            {
                body = jsonVal.GetRawText();
                headers = HttpHeaderDictionary.PrepareForJsonBody(headers);
            }

            items.Add(new FetchBatchRequestItem
            {
                Url = url,
                Method = method,
                Headers = headers,
                Body = body,
                TimeoutMs = timeout,
                Redirect = GetString(el, "redirect")
            });
        }

        if (items.Count == 0)
            return ErrorContent("Provide at least one request in 'requests'.");

        var results = await _context.FetchBatchAsync(items, concurrent);
        var includeBodies = GetBool(args, "includeBodies") || GetBool(args, "includeBody");
        var bodyMaxChars = args.TryGetProperty("bodyMaxChars", out _)
            ? GetInt(args, "bodyMaxChars", 200)
            : GetInt(args, "maxBodyChars", 200);
        var includeTiming = !args.TryGetProperty("includeTiming", out var timingProp) ||
                            timingProp.ValueKind != JsonValueKind.False;

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"Fetch batch: {results.Count} request(s), concurrent={concurrent}");
        foreach (var r in results.OrderBy(x => x.Index))
        {
            if (r.Error != null)
            {
                sb.Append($"  [{r.Index}] ERROR: {r.Error}");
                if (includeTiming) sb.Append($" durationMs={r.DurationMs}");
                sb.AppendLine();
            }
            else
            {
                sb.Append($"  [{r.Index}] {r.Status} {r.StatusText} ok={r.Ok}");
                if (includeTiming) sb.Append($" durationMs={r.DurationMs}");
                sb.Append($" bodyLen={r.Body?.Length ?? 0}");
                if (r.Redirected) sb.Append($" redirected→{r.ResponseUrl}");
                if (r.ResponseType == "opaqueredirect") sb.Append(" (opaqueredirect)");
                if (includeBodies && r.Body != null)
                {
                    var preview = bodyMaxChars <= 0 ? r.Body : Truncate(r.Body, bodyMaxChars);
                    sb.Append($" body={preview}");
                }
                sb.AppendLine();
            }
        }

        return TextContent(sb.ToString());
    }

    private object ToolGetTestHeuristics()
    {
        try
        {
            using var stream = System.Reflection.Assembly.GetExecutingAssembly()
                .GetManifestResourceStream("Trowser.Resources.test-heuristics.txt");
            if (stream == null)
                return ErrorContent("Test heuristics resource not found.");
            using var reader = new System.IO.StreamReader(stream);
            return TextContent(reader.ReadToEnd());
        }
        catch (Exception ex)
        {
            return ErrorContent($"Failed to load test heuristics: {ex.Message}");
        }
    }

    private object ToolScriptingHelp(JsonElement args)
    {
        try
        {
            var text = Scripting.ScriptingHelpCatalog.GetTopic(GetString(args, "topic"), out _, out var error);
            if (error != null)
                return ErrorContent(error);
            return TextContent(text ?? "");
        }
        catch (Exception ex)
        {
            return ErrorContent($"Failed to load scripting help: {ex.Message}");
        }
    }

    private object ToolInspiration()
    {
        if (InspirationService == null)
            return ErrorContent("Inspiration service not available.");

        var message = InspirationService.GetRandom();
        if (message == null)
            return ErrorContent("No inspiration messages available. Place inspiration_messages.txt next to Trowser.exe.");

        return TextContent(message);
    }

    private async Task<object> ToolCoverage()
    {
        if (CoverageService == null || SessionLogger == null)
            return ErrorContent("Coverage service not available.");

        string? currentUrl = null;
        try { currentUrl = await _context.GetCurrentUrl(); } catch { /* best effort */ }

        var snapshot = CoverageService.Build(SessionLogger.GetJournal(), currentUrl);

        var sb = new System.Text.StringBuilder();
        sb.AppendLine(snapshot.ToSummaryLine());
        sb.AppendLine();
        sb.AppendLine($"Pages ({snapshot.PagesVisited}):");
        foreach (var p in snapshot.Pages) sb.AppendLine($"  - {p}");
        sb.AppendLine();
        sb.AppendLine($"Interactions: {snapshot.Interactions} ({snapshot.DistinctElementsExercised} distinct elements)");
        sb.AppendLine($"Findings: {snapshot.Bugs} bugs, {snapshot.Observations} observations, {snapshot.TestIdeas} test ideas");
        sb.AppendLine();
        sb.AppendLine("Quality characteristics:");
        foreach (var q in snapshot.Quality)
            sb.AppendLine($"  [{(q.Touched ? "x" : " ")}] {q.Name}{(q.Evidence > 0 ? $" ({q.Evidence})" : "")}");
        if (snapshot.Nudges.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Nudges:");
            foreach (var n in snapshot.Nudges) sb.AppendLine($"  • {n}");
        }

        return TextContent(sb.ToString().TrimEnd());
    }

    private async Task<object> ToolTestData(JsonElement args)
    {
        if (TestDataService == null)
            return ErrorContent("Test data service not available.");

        TestDataKind? kind = null;
        var kindParam = GetString(args, "kind");
        if (!string.IsNullOrWhiteSpace(kindParam))
        {
            if (!TestDataService.TryParseKind(kindParam, out var parsed))
                return ErrorContent("Invalid kind. Use 'strings' or 'payloads'.");
            kind = parsed;
        }

        var text = await TestDataService.GetRandomAsync(kind);
        if (text == null)
        {
            var label = (kind ?? TestDataService.ActiveKind) == TestDataKind.Payloads ? "payloads" : "test data strings";
            return ErrorContent($"No {label} available.");
        }

        return TextContent(text);
    }

    private async Task<object> ToolSendMessage(JsonElement args)
    {
        var text = GetString(args, "text");
        if (string.IsNullOrWhiteSpace(text))
            return ErrorContent("Missing required parameter: text");

        var level = GetString(args, "level") ?? "info";
        var duration = GetInt(args, "duration", 8000);

        var callback = ShowMessageAsync;
        if (callback == null)
            return ErrorContent("Message display not available — no UI connected.");

        var (success, error) = await callback(text, level, duration);
        if (!success)
            return ErrorContent(error ?? "Failed to display message.");

        return TextContent($"Message displayed to tester: \"{text}\" (level: {level.ToLowerInvariant()}, duration: {duration}ms)");
    }

    private async Task<object> ToolJournalAdd(JsonElement args)
    {
        if (SessionLogger == null)
            return ErrorContent("Session logger not available.");

        var rawKind = GetString(args, "kind");
        var kind = NoteKinds.Normalize(rawKind);
        if (rawKind != null && !NoteKinds.IsKnown(kind))
            return ErrorContent($"Invalid kind '{rawKind}'. Use one of: {string.Join(", ", NoteKinds.All)}.");

        var text = GetString(args, "note") ?? GetString(args, "text") ?? GetString(args, "title");
        var details = GetString(args, "details");
        if (details == null && text != null && text.IndexOf('\n') >= 0)
            NoteKinds.SplitTitleBody(text, out text, out details);

        string? severity = null;
        var rawSeverity = GetString(args, "severity");
        if (rawSeverity != null)
        {
            if (!NoteKinds.TryNormalizeJournalSeverity(rawSeverity, out var normalizedSeverity))
                return ErrorContent($"Invalid severity. Use: {string.Join(", ", NoteKinds.JournalSeverities)}.");
            severity = normalizedSeverity;
        }

        string? evidence = null;
        var rawEvidence = GetString(args, "evidence");
        if (rawEvidence != null)
        {
            if (!NoteKinds.TryNormalizeEvidence(rawEvidence, out var normalizedEvidence))
                return ErrorContent($"Invalid evidence. Use: {string.Join(", ", NoteKinds.EvidenceLevels)}.");
            evidence = normalizedEvidence;
        }

        // Tags: normalize (trim, lowercase, dedupe, drop empties)
        List<string>? tags = null;
        if (args.TryGetProperty("tags", out var tagsEl) && tagsEl.ValueKind == JsonValueKind.Array)
        {
            tags = new List<string>();
            foreach (var t in tagsEl.EnumerateArray())
            {
                if (t.ValueKind == JsonValueKind.String)
                {
                    var normalized = t.GetString()?.Trim().ToLowerInvariant();
                    if (!string.IsNullOrEmpty(normalized) && !tags.Contains(normalized))
                        tags.Add(normalized);
                }
            }
            if (tags.Count == 0) tags = null;
        }

        // URL: prefer caller-supplied; fall back to auto-capture (best effort)
        var url = GetString(args, "url");
        if (string.IsNullOrWhiteSpace(url))
        {
            try { url = await _context.GetCurrentUrl(); } catch { /* best effort */ }
            if (string.IsNullOrWhiteSpace(url)) url = null;
        }

        Dictionary<string, string>? fields = null;
        bool isStructured = Array.IndexOf(NoteKinds.StructuredKinds, kind) >= 0;
        bool stepsIsArray = false;

        var screenshot = GetString(args, "screenshot");
        if (!string.IsNullOrWhiteSpace(screenshot))
        {
            fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["screenshot"] = screenshot.Trim()
            };
        }

        if (isStructured)
        {
            fields ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var key in NoteKinds.StructuredFieldOrder)
            {
                if (key == "steps")
                {
                    // Accept steps as either a string or a JSON array of strings
                    if (args.TryGetProperty("steps", out var stepsEl) && stepsEl.ValueKind == JsonValueKind.Array)
                    {
                        var stepsList = new List<string>();
                        foreach (var s in stepsEl.EnumerateArray())
                            if (s.ValueKind == JsonValueKind.String)
                                stepsList.Add(s.GetString()!);
                        if (stepsList.Count > 0)
                        {
                            fields["steps"] = string.Join("\n", stepsList);
                            stepsIsArray = true;
                        }
                    }
                    else
                    {
                        var v = GetString(args, key);
                        if (!string.IsNullOrWhiteSpace(v)) fields[key] = v;
                    }
                }
                else
                {
                    var v = GetString(args, key);
                    if (!string.IsNullOrWhiteSpace(v)) fields[key] = v;
                }
            }

            var priority = GetString(args, "priority");
            if (priority != null
                && priority != "low" && priority != "medium" && priority != "high" && priority != "critical")
                return ErrorContent("Invalid priority. Use: low, medium, high, or critical.");

            if (string.IsNullOrWhiteSpace(text) && fields.Count == 0)
                return ErrorContent($"A '{kind}' entry needs at least a title/text, or one of: steps, actual, expected, notes.");

            if (string.IsNullOrWhiteSpace(text))
            {
                text = fields.TryGetValue("actual", out var a) ? a
                     : fields.TryGetValue("steps", out var s) ? s
                     : fields.TryGetValue("notes", out var n) ? n
                     : $"(untitled {kind})";
                var trimmed = text!.Replace("\r", " ").Replace("\n", " ").Trim();
                if (trimmed.Length > 120) trimmed = trimmed[..117] + "...";
                text = trimmed;
            }
        }
        else if (string.IsNullOrWhiteSpace(text))
        {
            return ErrorContent("Missing required parameter: provide `note` (or `text`/`title`).");
        }

        var entry = SessionLogger.LogLlmNote(text!, severity, kind, fields, tags, url, stepsIsArray, details, evidence);
        var severityTag = !string.IsNullOrEmpty(severity) ? $" [{severity}]" : "";
        var kindLabel = NoteKinds.DisplayLabel(kind);
        var tagsNote = tags != null ? $" [tags: {string.Join(", ", tags)}]" : "";
        return TextContent($"{kindLabel} added to journal (index {entry.Index}){severityTag}{tagsNote}: {text}");
    }

    private object ToolJournalUpdate(JsonElement args)
    {
        if (SessionLogger == null)
            return ErrorContent("Session logger not available.");

        var index = GetInt(args, "index", -1);
        if (index < 0)
            return ErrorContent("Missing required parameter: index.");

        var existing = SessionLogger.GetEntry(index);
        if (existing == null)
            return ErrorContent($"No journal entry with index {index}.");

        string? kind = null;
        var rawKind = GetString(args, "kind");
        if (rawKind != null)
        {
            kind = NoteKinds.Normalize(rawKind);
            if (!NoteKinds.IsKnown(kind))
                return ErrorContent($"Invalid kind '{rawKind}'. Use one of: {string.Join(", ", NoteKinds.All)}.");
        }

        var effectiveKind = kind ?? existing.Kind ?? existing.Type;
        var text = GetString(args, "note") ?? GetString(args, "text") ?? GetString(args, "title");

        bool setSeverity = args.TryGetProperty("severity", out _);
        string? severity = null;
        if (setSeverity)
        {
            var rawSeverity = GetString(args, "severity");
            if (rawSeverity != null)
            {
                if (!NoteKinds.TryNormalizeJournalSeverity(rawSeverity, out var normalizedSeverity))
                    return ErrorContent($"Invalid severity. Use: {string.Join(", ", NoteKinds.JournalSeverities)}.");
                severity = normalizedSeverity;
            }
        }

        bool setEvidence = args.TryGetProperty("evidence", out _);
        string? evidence = null;
        if (setEvidence)
        {
            var rawEvidence = GetString(args, "evidence");
            if (rawEvidence != null)
            {
                if (!NoteKinds.TryNormalizeEvidence(rawEvidence, out var normalizedEvidence))
                    return ErrorContent($"Invalid evidence. Use: {string.Join(", ", NoteKinds.EvidenceLevels)}.");
                evidence = normalizedEvidence;
            }
        }

        bool setTags = args.TryGetProperty("tags", out var tagsEl);
        List<string>? tags = null;
        if (setTags && tagsEl.ValueKind == JsonValueKind.Array)
        {
            tags = new List<string>();
            foreach (var t in tagsEl.EnumerateArray())
            {
                if (t.ValueKind == JsonValueKind.String)
                {
                    var normalized = t.GetString()?.Trim().ToLowerInvariant();
                    if (!string.IsNullOrEmpty(normalized) && !tags.Contains(normalized))
                        tags.Add(normalized);
                }
            }
            if (tags.Count == 0) tags = null;
        }

        bool setUrl = args.TryGetProperty("url", out _);
        var url = setUrl ? GetString(args, "url") : null;

        bool setDetails = args.TryGetProperty("details", out _);
        var details = setDetails ? GetString(args, "details") : null;

        Dictionary<string, string>? fields = null;
        bool setFields = false;
        bool? stepsIsArray = null;
        bool isStructured = Array.IndexOf(NoteKinds.StructuredKinds, effectiveKind) >= 0;

        bool hasFieldUpdate = args.TryGetProperty("screenshot", out _)
            || (isStructured && NoteKinds.StructuredFieldOrder.Any(k => args.TryGetProperty(k, out _)));
        if (hasFieldUpdate)
        {
            setFields = true;
            fields = existing.Fields != null
                ? new Dictionary<string, string>(existing.Fields, StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            if (args.TryGetProperty("screenshot", out _))
            {
                var screenshot = GetString(args, "screenshot");
                if (string.IsNullOrWhiteSpace(screenshot)) fields.Remove("screenshot");
                else fields["screenshot"] = screenshot.Trim();
            }

            if (isStructured)
            {
                foreach (var key in NoteKinds.StructuredFieldOrder)
                {
                    if (!args.TryGetProperty(key, out var el)) continue;
                    if (key == "steps")
                    {
                        if (el.ValueKind == JsonValueKind.Array)
                        {
                            var stepsList = new List<string>();
                            foreach (var s in el.EnumerateArray())
                                if (s.ValueKind == JsonValueKind.String)
                                    stepsList.Add(s.GetString()!);
                            if (stepsList.Count > 0)
                            {
                                fields["steps"] = string.Join("\n", stepsList);
                                stepsIsArray = true;
                            }
                            else
                            {
                                fields.Remove("steps");
                                stepsIsArray = false;
                            }
                        }
                        else
                        {
                            var v = GetString(args, key);
                            if (string.IsNullOrWhiteSpace(v)) fields.Remove(key);
                            else fields[key] = v;
                            stepsIsArray = false;
                        }
                    }
                    else if (key == "priority")
                    {
                        var priority = GetString(args, "priority");
                        if (priority != null && priority.Length > 0
                            && priority != "low" && priority != "medium" && priority != "high" && priority != "critical")
                            return ErrorContent("Invalid priority. Use: low, medium, high, or critical.");
                        if (string.IsNullOrWhiteSpace(priority)) fields.Remove("priority");
                        else fields["priority"] = priority;
                    }
                    else
                    {
                        var v = GetString(args, key);
                        if (string.IsNullOrWhiteSpace(v)) fields.Remove(key);
                        else fields[key] = v;
                    }
                }
            }

            if (fields.Count == 0) fields = null;
        }

        var updated = SessionLogger.UpdateEntry(index, kind, text,
            details, setDetails, severity, setSeverity, fields, setFields, tags, setTags, url, setUrl, stepsIsArray,
            evidence, setEvidence);
        if (updated == null)
            return ErrorContent($"No journal entry with index {index}.");

        var kindLabel = NoteKinds.DisplayLabel(updated.Kind ?? updated.Type);
        return TextContent($"{kindLabel} #{updated.Index} updated: {updated.Summary}");
    }

    private object ToolJournalDelete(JsonElement args)
    {
        if (SessionLogger == null)
            return ErrorContent("Session logger not available.");

        var index = GetInt(args, "index", -1);
        if (index < 0)
            return ErrorContent("Missing required parameter: index.");

        if (!SessionLogger.DeleteEntry(index))
            return ErrorContent($"No journal entry with index {index}.");

        return TextContent($"Deleted journal entry #{index} (revision {SessionLogger.Revision}, {SessionLogger.JournalCount} remaining).");
    }

    private object ToolJournalGet(JsonElement args)
    {
        if (SessionLogger == null)
            return TextContent("No journal entries — session logger not available.");

        int? since = args.TryGetProperty("since", out var sp) && sp.ValueKind == JsonValueKind.Number ? sp.GetInt32() : null;
        int? last = args.TryGetProperty("last", out var lp) && lp.ValueKind == JsonValueKind.Number ? lp.GetInt32() : null;
        var type = GetString(args, "type");
        var source = GetString(args, "source");
        var tag = GetString(args, "tag");
        var evidence = GetString(args, "evidence");
        var origin = GetString(args, "origin");
        var view = GetString(args, "view");

        List<int>? indexes = null;
        if (args.TryGetProperty("indexes", out var indexesEl) && indexesEl.ValueKind == JsonValueKind.Array)
        {
            indexes = new List<int>();
            foreach (var el in indexesEl.EnumerateArray())
            {
                if (el.ValueKind == JsonValueKind.Number && el.TryGetInt32(out var idx) && idx >= 0)
                    indexes.Add(idx);
            }
            if (indexes.Count == 0) indexes = null;
        }

        List<SessionLogger.JournalEntry> entries;
        if (indexes != null)
        {
            entries = SessionLogger.GetEntriesByIndexes(indexes);
        }
        else
        {
            entries = SessionLogger.GetJournal(since, last, type, source, tag, evidence, origin);
            if (string.IsNullOrEmpty(view) && SessionLogger.JournalCount > JournalProjection.DefaultIndexViewThreshold)
                view = "index";
        }

        if (entries.Count == 0)
        {
            var filterNote = since.HasValue ? $" (since index {since.Value})" : "";
            return TextContent($"No journal entries{filterNote}.");
        }

        var useIndexView = string.Equals(view, "index", StringComparison.OrdinalIgnoreCase);
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"Journal: {entries.Count} entries (total: {SessionLogger.JournalCount}, revision: {SessionLogger.Revision}, view: {(useIndexView ? "index" : "full")})");
        var deleted = SessionLogger.DeletedIndices;
        if (deleted.Count > 0)
            sb.AppendLine($"Deleted indices: {string.Join(", ", deleted)}");
        sb.AppendLine();
        foreach (var e in entries)
        {
            if (useIndexView)
            {
                sb.AppendLine(JournalProjection.FormatIndexLine(e));
                continue;
            }

            var severityTag = !string.IsNullOrEmpty(e.Severity) ? $" [{e.Severity}]" : "";
            var detailsPart = !string.IsNullOrEmpty(e.Details) ? $" — {e.Details}" : "";
            var tagsNote = e.Tags != null && e.Tags.Count > 0 ? $" [tags: {string.Join(", ", e.Tags)}]" : "";
            var urlNote = !string.IsNullOrEmpty(e.Url) ? $" @{e.Url}" : "";
            sb.AppendLine($"[{e.Index}] {e.Timestamp:HH:mm:ss} {e.Type.ToUpperInvariant()}/{e.Evidence}{severityTag}{tagsNote} ({e.Source}) {e.Summary}{detailsPart}{urlNote}");
            if (e.Fields != null && e.Fields.Count > 0)
            {
                foreach (var key in NoteKinds.StructuredFieldOrder)
                {
                    if (e.Fields.TryGetValue(key, out var v))
                        sb.AppendLine($"    {NoteKinds.FieldLabel(key)}: {v}");
                }
                foreach (var (k, v) in e.Fields)
                {
                    if (Array.IndexOf(NoteKinds.StructuredFieldOrder, k.ToLowerInvariant()) < 0)
                        sb.AppendLine($"    {NoteKinds.FieldLabel(k)}: {v}");
                }
            }
        }
        return TextContent(sb.ToString().TrimEnd());
    }

    private object ToolCompact(JsonElement args)
    {
        if (SessionMemory == null)
            return ErrorContent("Session memory not available.");

        var summary = GetString(args, "summary");
        if (string.IsNullOrWhiteSpace(summary))
            return ErrorContent("Missing required parameter: summary.");

        var request = new PendingCompactRequest
        {
            Summary = summary.Trim(),
            KeepLastTurns = GetInt(args, "keepLastTurns", 0)
        };

        if (args.TryGetProperty("openThreads", out var threadsEl) && threadsEl.ValueKind == JsonValueKind.Array)
        {
            request.OpenThreads = new List<string>();
            foreach (var t in threadsEl.EnumerateArray())
                if (t.ValueKind == JsonValueKind.String)
                {
                    var s = t.GetString()?.Trim();
                    if (!string.IsNullOrEmpty(s)) request.OpenThreads.Add(s);
                }
        }

        if (args.TryGetProperty("nextSteps", out var stepsEl) && stepsEl.ValueKind == JsonValueKind.Array)
        {
            request.NextSteps = new List<string>();
            foreach (var t in stepsEl.EnumerateArray())
                if (t.ValueKind == JsonValueKind.String)
                {
                    var s = t.GetString()?.Trim();
                    if (!string.IsNullOrEmpty(s)) request.NextSteps.Add(s);
                }
        }

        if (args.TryGetProperty("journalIndexes", out var idxEl) && idxEl.ValueKind == JsonValueKind.Array)
        {
            request.JournalIndexes = new List<int>();
            foreach (var t in idxEl.EnumerateArray())
                if (t.ValueKind == JsonValueKind.Number && t.TryGetInt32(out var idx) && idx >= 0)
                    request.JournalIndexes.Add(idx);
        }

        if (request.KeepLastTurns <= 0)
            request.KeepLastTurns = 10;

        SessionMemory.QueueCompact(request);
        return TextContent("Context compact queued — conversation will rebuild before the next model call.");
    }

    private object ToolSessionMemory(JsonElement args)
    {
        if (SessionMemory == null)
            return ErrorContent("Session memory not available.");

        var action = (GetString(args, "action") ?? "get").ToLowerInvariant();
        switch (action)
        {
            case "get":
                return TextContent(JsonSerializer.Serialize(SessionMemory.ToApiObject(), CompactJson));
            case "set_focus":
                SessionMemory.SetFocus(GetString(args, "focus"));
                return TextContent(JsonSerializer.Serialize(SessionMemory.ToApiObject(), CompactJson));
            case "add_task":
                var text = GetString(args, "text");
                if (string.IsNullOrWhiteSpace(text))
                    return ErrorContent("Missing required parameter: text.");
                var ji = args.TryGetProperty("journalIndex", out var jel) && jel.ValueKind == JsonValueKind.Number
                    ? jel.GetInt32()
                    : (int?)null;
                if (ji < 0) ji = null;
                SessionMemory.AddTask(text, ji);
                return TextContent(JsonSerializer.Serialize(SessionMemory.ToApiObject(), CompactJson));
            case "update_task":
                var id = GetString(args, "id");
                if (string.IsNullOrWhiteSpace(id))
                    return ErrorContent("Missing required parameter: id.");
                var updated = SessionMemory.UpdateTask(id, GetString(args, "text"), GetString(args, "status"),
                    args.TryGetProperty("journalIndex", out var uel) && uel.ValueKind == JsonValueKind.Number
                        ? uel.GetInt32()
                        : null);
                if (updated == null)
                    return ErrorContent($"No task with id '{id}'.");
                return TextContent(JsonSerializer.Serialize(SessionMemory.ToApiObject(), CompactJson));
            default:
                return ErrorContent("Invalid action. Use: get, set_focus, add_task, update_task.");
        }
    }

    private object ToolJournalExport(JsonElement args)
    {
        if (SessionLogger == null)
            return ErrorContent("Session logger not available.");

        var format = (GetString(args, "format") ?? "markdown").ToLowerInvariant();
        if (format is not ("html" or "markdown" or "md" or "json"))
            return ErrorContent("Invalid format. Use: html, markdown, or json.");

        var entries = SessionLogger.GetJournal();
        var sessionFile = SessionLogger.FilePath;

        var content = format == "json"
            ? JournalBundle.Serialize(entries, Host?.PointerStore)
            : format == "html"
                ? JournalReportGenerator.GenerateHtml(entries, sessionFile)
                : JournalReportGenerator.GenerateMarkdown(entries, sessionFile);

        var path = GetString(args, "path");
        string? savedPath = null;
        if (!string.IsNullOrWhiteSpace(path))
        {
            if (!ExportPathGuard.TryResolve(path, SafeMode, out var full, out var guardError))
                return ErrorContent(guardError ?? "Export path rejected.");
            try
            {
                var dir = System.IO.Path.GetDirectoryName(full);
                if (!string.IsNullOrEmpty(dir)) System.IO.Directory.CreateDirectory(dir);
                System.IO.File.WriteAllText(full, content, new System.Text.UTF8Encoding(false));
                savedPath = full;
            }
            catch (Exception ex)
            {
                return ErrorContent($"Failed to save report: {ex.Message}");
            }
        }

        if (savedPath != null)
            return TextContent($"Report saved to {savedPath} ({entries.Count} journal entries, {content.Length} chars {format}).");

        // Inline return — prefer Markdown for LLM consumption; truncate very long HTML.
        if (format == "html" && content.Length > 20000)
            return TextContent($"HTML report generated ({content.Length} chars, {entries.Count} entries). Pass `path` to save to disk, or use format=markdown for inline output.");
        return TextContent(content);
    }

    private Task<object> ToolJournalImport(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildJournalImportAsync);

    #region SSL Manager Tools

    private object ToolSslList()
    {
        var sslManager = _context.SslManager;
        if (sslManager == null)
            return ErrorContent("SSL Manager not available.");

        var certs = sslManager.ListCertificates();
        if (certs.Count == 0)
            return TextContent("No client certificates loaded. Use browser_ssl_add to add a .pfx or .p12 certificate.");

        var lines = certs.Select(c =>
        {
            var status = c.IsActive ? " [ACTIVE]" : "";
            var expired = c.IsExpired ? " [EXPIRED]" : "";
            return $"- {c.Alias}{status}{expired}: {c.Subject} (expires {c.NotAfter:yyyy-MM-dd}, thumbprint {c.Thumbprint[..8]}…)";
        });

        var activeInfo = sslManager.ActiveAlias != null ? $"\nActive: {sslManager.ActiveAlias}" : "\nNo active certificate.";
        return TextContent($"Client certificates ({certs.Count}):\n{string.Join("\n", lines)}{activeInfo}");
    }

    private object ToolSslAdd(JsonElement args)
    {
        var sslManager = _context.SslManager;
        if (sslManager == null)
            return ErrorContent("SSL Manager not available.");

        var filePath = GetString(args, "filePath");
        var password = GetString(args, "password") ?? "";
        var alias = GetString(args, "alias");

        if (string.IsNullOrWhiteSpace(filePath))
            return ErrorContent("Missing required parameter: filePath");

        try
        {
            var info = sslManager.AddCertificate(filePath, password, alias);
            return TextContent(
                $"Certificate added successfully.\n" +
                $"Alias: {info.Alias}\n" +
                $"Subject: {info.Subject}\n" +
                $"Issuer: {info.Issuer}\n" +
                $"Thumbprint: {info.Thumbprint}\n" +
                $"Valid: {info.NotBefore:yyyy-MM-dd} to {info.NotAfter:yyyy-MM-dd}\n" +
                $"Use browser_ssl_set_active with alias \"{info.Alias}\" to activate it.");
        }
        catch (Exception ex)
        {
            return ErrorContent(ex.Message);
        }
    }

    private object ToolSslRemove(JsonElement args)
    {
        var sslManager = _context.SslManager;
        if (sslManager == null)
            return ErrorContent("SSL Manager not available.");

        var alias = GetString(args, "alias");
        if (string.IsNullOrWhiteSpace(alias))
            return ErrorContent("Missing required parameter: alias");

        try
        {
            var removed = sslManager.RemoveCertificate(alias);
            return removed
                ? TextContent($"Certificate '{alias}' removed.")
                : ErrorContent($"No certificate found with alias '{alias}'.");
        }
        catch (Exception ex)
        {
            return ErrorContent(ex.Message);
        }
    }

    private object ToolSslSetActive(JsonElement args)
    {
        var sslManager = _context.SslManager;
        if (sslManager == null)
            return ErrorContent("SSL Manager not available.");

        var alias = GetString(args, "alias");

        try
        {
            var result = sslManager.SetActive(alias);
            return result == null
                ? TextContent("Active client certificate cleared. No client certificate will be sent.")
                : TextContent($"Active certificate set to '{result.Alias}' ({result.Subject}, expires {result.NotAfter:yyyy-MM-dd}).");
        }
        catch (Exception ex)
        {
            return ErrorContent(ex.Message);
        }
    }

    private object ToolSslGetActive()
    {
        var sslManager = _context.SslManager;
        if (sslManager == null)
            return ErrorContent("SSL Manager not available.");

        var active = sslManager.GetActive();
        if (active == null)
            return TextContent("No active client certificate. Use browser_ssl_set_active to activate one.");

        return TextContent(
            $"Active client certificate:\n" +
            $"Alias: {active.Alias}\n" +
            $"Subject: {active.Subject}\n" +
            $"Issuer: {active.Issuer}\n" +
            $"Thumbprint: {active.Thumbprint}\n" +
            $"Valid: {active.NotBefore:yyyy-MM-dd} to {active.NotAfter:yyyy-MM-dd}" +
            (active.IsExpired ? "\n⚠ WARNING: This certificate has expired!" : ""));
    }

    #endregion

    #region Peer Tools

    private async Task<object> ToolPeerRegister(JsonElement args)
    {
        if (Peers == null) return ErrorContent("Peer registry not available.");

        var name = GetString(args, "name");
        var baseUrl = GetString(args, "baseUrl");
        var apiKey = GetString(args, "apiKey");

        if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(baseUrl))
            return ErrorContent("Both 'name' and 'baseUrl' are required.");

        var peer = new PeerEntry { Name = name, BaseUrl = baseUrl, ApiKey = apiKey };
        if (!Peers.Register(peer, out var error))
            return ErrorContent(error!);

        var (alive, sessionName, _, _) = await Peers.PingAsync(name);
        var status = alive ? "alive" : "unreachable (check baseUrl and apiKey)";
        var sessionInfo = sessionName != null ? $", session: {sessionName}" : "";
        return TextContent($"Peer \"{name}\" registered at {baseUrl} — {status}{sessionInfo}");
    }

    private async Task<object> ToolPeers()
    {
        if (Peers == null) return ErrorContent("Peer registry not available.");

        var peers = Peers.GetAll();
        if (peers.Count == 0)
            return TextContent("No peers registered. Use browser_peer_register to add a Trowser instance.");

        var lines = new List<string> { $"{peers.Count} peer(s):" };
        foreach (var peer in peers)
        {
            var (alive, sessionName, _, _) = await Peers.PingAsync(peer.Name);
            var status = alive ? "alive" : "down";
            var session = sessionName != null ? $" (session: {sessionName})" : "";
            lines.Add($"  {peer.Name}: {peer.BaseUrl} [{status}]{session}");
        }
        return TextContent(string.Join("\n", lines));
    }

    private async Task<object> ToolPeerFetch(JsonElement args)
    {
        if (Peers == null) return ErrorContent("Peer registry not available.");

        var peerName = GetString(args, "peer");
        var url = GetString(args, "url");
        if (string.IsNullOrWhiteSpace(peerName)) return ErrorContent("'peer' is required.");
        if (string.IsNullOrWhiteSpace(url)) return ErrorContent("'url' is required.");

        var fetchBody = new Dictionary<string, object?> { ["url"] = url };
        var method = GetString(args, "method");
        if (method != null) fetchBody["method"] = method;

        if (args.TryGetProperty("headers", out var h) && h.ValueKind == JsonValueKind.Object)
            fetchBody["headers"] = h;
        if (args.TryGetProperty("json", out var j))
            fetchBody["json"] = j;
        var body = GetString(args, "body");
        if (body != null) fetchBody["body"] = body;
        var timeout = GetInt(args, "timeout", 0);
        if (timeout > 0) fetchBody["timeout"] = timeout;

        var jsonStr = JsonSerializer.Serialize(fetchBody, CompactJson);
        var result = await Peers.ForwardAsync(peerName, "POST", "/api/fetch-direct", jsonStr,
            timeoutMs: PeerRegistry.ForwardTimeoutForFetchMs(timeout));

        if (!result.Success && result.StatusCode == 0)
            return ErrorContent(result.Body ?? "Peer unreachable.");

        return TextContent(result.Body ?? "{}");
    }

    private async Task<object> ToolPeerState(JsonElement args)
    {
        if (Peers == null) return ErrorContent("Peer registry not available.");

        var peerName = GetString(args, "peer");
        if (string.IsNullOrWhiteSpace(peerName)) return ErrorContent("'peer' is required.");

        var result = await Peers.ForwardAsync(peerName, "GET", "/api/info",
            timeoutMs: PeerRegistry.ReachabilityTimeoutMs);
        if (!result.Success && result.StatusCode == 0)
            return ErrorContent(result.Body ?? "Peer unreachable.");

        return TextContent(result.Body ?? "{}");
    }

    private async Task<object> ToolPeerNavigate(JsonElement args)
    {
        if (Peers == null) return ErrorContent("Peer registry not available.");

        var peerName = GetString(args, "peer");
        var url = GetString(args, "url");
        if (string.IsNullOrWhiteSpace(peerName)) return ErrorContent("'peer' is required.");
        if (string.IsNullOrWhiteSpace(url)) return ErrorContent("'url' is required.");

        var navBody = JsonSerializer.Serialize(new { url }, CompactJson);
        var result = await Peers.ForwardAsync(peerName, "POST", "/api/navigate", navBody,
            timeoutMs: PeerRegistry.OperationTimeoutMs);

        if (!result.Success && result.StatusCode == 0)
            return ErrorContent(result.Body ?? "Peer unreachable.");

        return TextContent(result.Body ?? "{}");
    }

    private async Task<object> ToolPeerScreenshot(JsonElement args)
    {
        if (Peers == null) return ErrorContent("Peer registry not available.");

        var peerName = GetString(args, "peer");
        if (string.IsNullOrWhiteSpace(peerName)) return ErrorContent("'peer' is required.");

        var format = GetString(args, "format") ?? "jpeg";
        var quality = GetInt(args, "quality", 60);
        var queryString = $"?format={format}&quality={quality}&base64=true";

        var result = await Peers.ForwardAsync(peerName, "GET", "/api/screenshot" + queryString,
            timeoutMs: PeerRegistry.OperationTimeoutMs);
        if (!result.Success && result.StatusCode == 0)
            return ErrorContent(result.Body ?? "Peer unreachable.");

        return TextContent(result.Body ?? "{}");
    }

    private object ToolPeerUnregister(JsonElement args)
    {
        if (Peers == null) return ErrorContent("Peer registry not available.");

        var name = GetString(args, "name");
        if (string.IsNullOrWhiteSpace(name)) return ErrorContent("'name' is required.");

        if (!Peers.Unregister(name))
            return ErrorContent($"Peer \"{name}\" is not registered.");

        return TextContent($"Peer \"{name}\" unregistered.");
    }

    #endregion

    #region AuthZ Tool Implementations

    private async Task<object> ToolAuthzProbe(JsonElement args)
    {
        if (!args.TryGetProperty("endpoints", out var endpointsEl) || endpointsEl.ValueKind != JsonValueKind.Array)
            return ErrorContent("'endpoints' array is required.");

        var classify = GetBool(args, "classify", true);

        var results = new List<object>();
        int allowed = 0, denied = 0, errors = 0;

        foreach (var ep in endpointsEl.EnumerateArray())
        {
            string? url;
            string method = "GET";
            Dictionary<string, string>? headers = null;
            string? fetchBody = null;

            if (ep.ValueKind == JsonValueKind.String)
            {
                url = ep.GetString();
            }
            else
            {
                url = GetString(ep, "url");
                method = GetString(ep, "method") ?? "GET";
                if (ep.TryGetProperty("headers", out var h) && h.ValueKind == JsonValueKind.Object)
                {
                    headers = new Dictionary<string, string>();
                    foreach (var p in h.EnumerateObject()) headers[p.Name] = p.Value.GetString() ?? "";
                }
                if (ep.TryGetProperty("json", out var j))
                {
                    fetchBody = j.GetRawText();
                    headers ??= new Dictionary<string, string>();
                    headers.TryAdd("Content-Type", "application/json");
                }
                else if (ep.TryGetProperty("body", out var b))
                {
                    fetchBody = b.GetString();
                }
            }

            if (string.IsNullOrWhiteSpace(url)) continue;

            int status = 0;
            string bodyText = "";
            try
            {
                var resultJson = await _context.Fetch(url, method, headers, fetchBody, 30000);
                using var doc = JsonDocument.Parse(resultJson);
                status = doc.RootElement.TryGetProperty("status", out var s) ? s.GetInt32() : 0;
                bodyText = doc.RootElement.TryGetProperty("body", out var bdy) ? bdy.GetString() ?? "" : "";
            }
            catch (Exception ex) { bodyText = ex.Message; }

            string? classification = null;
            if (classify)
            {
                if (status >= 200 && status < 300) { classification = "allowed"; allowed++; }
                else if (status >= 400 && status < 500) { classification = "denied"; denied++; }
                else if (status >= 500) { classification = "error"; errors++; }
                else { classification = "error"; errors++; }
            }

            var entry = new Dictionary<string, object?>
            {
                ["url"] = url, ["method"] = method, ["status"] = status,
                ["bodyLength"] = bodyText.Length,
                ["bodyHash"] = ComputeShortHash(bodyText)
            };
            if (classification != null) entry["classification"] = classification;
            if (status >= 400 || status == 0)
                entry["errorSnippet"] = bodyText.Length > 200 ? bodyText[..200] : bodyText;
            results.Add(entry);
        }

        return TextContent(JsonSerializer.Serialize(new
        {
            results, summary = new { total = results.Count, allowed, denied, errors }
        }, CompactJson));
    }

    private Task<object> ToolAuthzDiff(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildAuthzDiffAsync);

    private Task<object> ToolAuthzBoundary(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildAuthzBoundaryAsync);

    private Task<object> ToolAuthzModel(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildAuthzModelAsync);

    private Task<object> ToolAuthzShadow(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildAuthzShadowAsync);

    private Task<object> ToolAuthzCoverage(JsonElement args) =>
        RenderHostSafe(args, h => h.BuildAuthzCoverageAsync);

    private async Task<object> ToolSessionIdentity()
    {
        var payload = await SessionIdentityIntrospection.BuildLivePayloadAsync(_context, SessionName);
        return TextContent(JsonSerializer.Serialize(payload, CompactJson));
    }

    private object ToolIdentities()
    {
        if (IdentityStore == null)
            return ErrorContent("Identity store not initialized.");
        var identities = IdentityStore.List();
        return TextContent(JsonSerializer.Serialize(new { count = identities.Count, identities }, CompactJson));
    }

    private async Task<object> ToolIdentityCapture(JsonElement args)
    {
        if (IdentityStore == null)
            return ErrorContent("Identity store not initialized.");

        var name = GetString(args, "name")?.Trim();
        if (!IdentityStore.IsValidName(name))
            return ErrorContent("Required: name (1-64 chars, alphanumeric plus . _ -).");

        var includeAuthHeaders = !args.TryGetProperty("includeAuthHeaders", out var iah) || iah.ValueKind != JsonValueKind.False;
        var authHeaderMaxAgeMinutes = args.TryGetProperty("authHeaderMaxAgeMinutes", out var age) && age.ValueKind == JsonValueKind.Number
            ? Math.Clamp(age.GetInt32(), 1, 240) : 30;

        var snapshot = await IdentityStore.CaptureAsync(_context, name!, SessionName, includeAuthHeaders, authHeaderMaxAgeMinutes);
        return TextContent(JsonSerializer.Serialize(new
        {
            captured = snapshot.Name,
            metadata = snapshot.Metadata,
            cookieCount = snapshot.Cookies.Count,
            localStorageCount = snapshot.LocalStorage.Count,
            sessionStorageCount = snapshot.SessionStorage.Count,
            authHeaderCount = snapshot.AuthHeaders.Count
        }, CompactJson));
    }

    private async Task<object> ToolIdentityApply(JsonElement args)
    {
        if (IdentityStore == null)
            return ErrorContent("Identity store not initialized.");

        var name = GetString(args, "name")?.Trim();
        if (!IdentityStore.IsValidName(name))
            return ErrorContent("Required: name.");

        var target = (GetString(args, "target") ?? "self").Trim().ToLowerInvariant();
        var navigateTo = GetString(args, "navigateTo");
        var verify = ParseIdentityVerifyFromArgs(args);

        if (target == "peer")
        {
            var peer = GetString(args, "peer");
            if (string.IsNullOrWhiteSpace(peer))
                return ErrorContent("target=peer requires 'peer'.");
            if (Peers == null)
                return ErrorContent("Peer registry not available.");

            var forwardBody = new Dictionary<string, object?> { ["name"] = name, ["target"] = "self", ["navigateTo"] = navigateTo };
            if (verify != null)
                forwardBody["verify"] = new { verify.Url, verify.ExpectStatus, verify.Method, verify.Headers, verify.Body, verify.TimeoutMs };

            var peerResp = await Peers.ForwardAsync(peer, "POST", "/api/identity/apply",
                JsonSerializer.Serialize(forwardBody, CompactJson),
                timeoutMs: PeerRegistry.OperationTimeoutMs);
            if (!peerResp.Success && peerResp.StatusCode != 200)
                return ErrorContent(peerResp.Body ?? "Peer identity apply failed.");
            return TextContent(peerResp.Body ?? "{}");
        }

        try
        {
            var result = await IdentityStore.ApplyAsync(_context, name!, navigateTo, verify);
            return TextContent(JsonSerializer.Serialize(result, CompactJson));
        }
        catch (InvalidOperationException ex)
        {
            return ErrorContent(ex.Message);
        }
    }

    private async Task<object> ToolIdentityHandoff(JsonElement args)
    {
        if (IdentityHandoff == null)
            return ErrorContent("Identity handoff not initialized.");

        var action = GetString(args, "action") ?? "start";
        var name = GetString(args, "name")?.Trim();

        if (action == "cancel")
        {
            if (!IdentityStore.IsValidName(name))
                return ErrorContent("cancel requires valid 'name'.");
            var cancelled = IdentityHandoff.Cancel(name!);
            return TextContent(JsonSerializer.Serialize(new { cancelled, name }, CompactJson));
        }

        if (action == "status")
        {
            if (!IdentityStore.IsValidName(name))
                return ErrorContent("status requires valid 'name'.");
            var autoCapture = !args.TryGetProperty("autoCapture", out var ac) || ac.ValueKind != JsonValueKind.False;
            var pollState = await IdentityHandoff.PollAsync(_context, name!, SessionName, autoCapture);
            return TextContent(JsonSerializer.Serialize(new
            {
                status = pollState.Status,
                name = pollState.Name,
                capturedIdentity = pollState.CapturedIdentity,
                expiresAt = pollState.ExpiresAt == default ? null : (DateTime?)pollState.ExpiresAt,
                message = pollState.Message
            }, CompactJson));
        }

        if (!IdentityStore.IsValidName(name))
            return ErrorContent("Required: name.");

        var timeoutMs = args.TryGetProperty("timeoutMs", out var tm) && tm.ValueKind == JsonValueKind.Number
            ? tm.GetInt32() : 300_000;
        var livenessUrl = GetString(args, "livenessUrl");
        var startState = await IdentityHandoff.StartAsync(_context, name!, timeoutMs, livenessUrl);
        return TextContent(JsonSerializer.Serialize(new
        {
            status = startState.Status,
            name = startState.Name,
            expiresAt = startState.ExpiresAt,
            livenessUrl = startState.LivenessUrl,
            message = startState.Message
        }, CompactJson));
    }

    private static IdentityVerifyOptions? ParseIdentityVerifyFromArgs(JsonElement args)
    {
        if (!args.TryGetProperty("verify", out var verifyEl) || verifyEl.ValueKind != JsonValueKind.Object)
            return null;

        var url = GetString(verifyEl, "url");
        if (string.IsNullOrWhiteSpace(url)) return null;

        return new IdentityVerifyOptions
        {
            Url = url,
            ExpectStatus = verifyEl.TryGetProperty("expectStatus", out var es) && es.ValueKind == JsonValueKind.Number
                ? es.GetInt32() : 200,
            Method = GetString(verifyEl, "method") ?? "GET",
            Body = GetString(verifyEl, "body"),
            TimeoutMs = verifyEl.TryGetProperty("timeoutMs", out var t) && t.ValueKind == JsonValueKind.Number
                ? t.GetInt32() : 30_000
        };
    }

    private static readonly string[][] McpSmartFuzzPayloads =
    [
        ["", "null", "undefined", "0", "-1", "99999999", "true", "false"],
        ["[]", "{}", "[null]", "NaN", "Infinity", "-Infinity"],
        [new string('A', 1000), new string('A', 10000)],
        ["<script>alert(1)</script>", "' OR '1'='1", "{{7*7}}", "${7*7}",
         "../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
         "%00", "\0", "\r\n", "\t", "\x00"],
        ["\uFEFF", "\u0000", "\u202E", "é", "中文", "\U0001F525"],
        ["%s%s%s%s%s", "%d%d%d%d%d", "%x%x%x%x%x", "%n%n%n%n%n"],
    ];

    private async Task<object> ToolAuthzFuzz(JsonElement args)
    {
        var endpoint = GetString(args, "endpoint");
        if (string.IsNullOrWhiteSpace(endpoint)) return ErrorContent("'endpoint' is required.");

        if (!args.TryGetProperty("parameterSets", out var paramSets) || paramSets.ValueKind != JsonValueKind.Array)
            return ErrorContent("'parameterSets' array is required.");

        var method = GetString(args, "method") ?? "GET";
        var classify = GetBool(args, "classify", true);
        var detectCrash = GetBool(args, "detectCrashPattern", true);
        var bodyTemplate = GetString(args, "bodyTemplate");
        var autoPayloads = GetBool(args, "autoPayloads", false);

        Dictionary<string, string>? defaultHeaders = null;
        if (args.TryGetProperty("headers", out var hdr) && hdr.ValueKind == JsonValueKind.Object)
        {
            defaultHeaders = new Dictionary<string, string>();
            foreach (var p in hdr.EnumerateObject()) defaultHeaders[p.Name] = p.Value.GetString() ?? "";
        }

        var crashPatterns = new[] {
            "NullPointerException", "NullReferenceException", "NullPointer",
            "java.lang.NullPointerException", "500 Internal Server Error",
            "stack trace", "Traceback (most recent call last)",
            "FATAL", "Unhandled Exception", "at System.",
            "at java.", "at org.springframework",
            "ORA-", "SQL syntax", "MySQLSyntaxError"
        };

        var results = new List<object>();
        int allowed = 0, denied = 0, errors = 0, crashes = 0;

        var baselines = new List<Dictionary<string, string>>();

        foreach (var paramSet in paramSets.EnumerateArray())
        {
            var url = endpoint;
            string? fetchBody = null;
            var headers = defaultHeaders != null ? new Dictionary<string, string>(defaultHeaders) : null;

            if (paramSet.ValueKind == JsonValueKind.Object)
            {
                var substitutions = new Dictionary<string, string>();
                foreach (var prop in paramSet.EnumerateObject())
                {
                    if (prop.Name == "body")
                    {
                        fetchBody = prop.Value.ValueKind == JsonValueKind.String
                            ? prop.Value.GetString()
                            : prop.Value.GetRawText();
                        if (fetchBody != null && (fetchBody.TrimStart().StartsWith("{") || fetchBody.TrimStart().StartsWith("[")))
                        {
                            headers ??= new Dictionary<string, string>();
                            headers.TryAdd("Content-Type", "application/json");
                        }
                    }
                    else if (prop.Name == "headers" && prop.Value.ValueKind == JsonValueKind.Object)
                    {
                        headers ??= new Dictionary<string, string>();
                        foreach (var h in prop.Value.EnumerateObject())
                            headers[h.Name] = h.Value.GetString() ?? "";
                    }
                    else
                    {
                        var val = prop.Value.ValueKind == JsonValueKind.String
                            ? prop.Value.GetString() ?? ""
                            : prop.Value.GetRawText();
                        substitutions[prop.Name] = val;
                        url = url.Replace($"{{{prop.Name}}}", Uri.EscapeDataString(val));
                    }
                }

                if (autoPayloads && substitutions.Count > 0)
                    baselines.Add(substitutions);

                if (bodyTemplate != null && fetchBody == null)
                {
                    fetchBody = bodyTemplate;
                    foreach (var kv in substitutions)
                        fetchBody = fetchBody.Replace($"{{{kv.Key}}}", kv.Value);
                    if (fetchBody.TrimStart().StartsWith("{") || fetchBody.TrimStart().StartsWith("["))
                    {
                        headers ??= new Dictionary<string, string>();
                        headers.TryAdd("Content-Type", "application/json");
                    }
                }
            }

            McpFuzzClassify(url, method, headers, fetchBody, paramSet,
                classify, detectCrash, crashPatterns, results,
                ref allowed, ref denied, ref errors, ref crashes,
                await McpFuzzFetch(url, method, headers, fetchBody));
        }

        if (autoPayloads && baselines.Count > 0)
        {
            var smartSets = McpGenerateSmartPayloads(baselines);
            foreach (var paramDict in smartSets)
            {
                var url = endpoint;
                foreach (var kv in paramDict)
                    url = url.Replace($"{{{kv.Key}}}", Uri.EscapeDataString(kv.Value));

                string? fetchBody = null;
                var headers = defaultHeaders != null ? new Dictionary<string, string>(defaultHeaders) : null;
                if (bodyTemplate != null)
                {
                    fetchBody = bodyTemplate;
                    foreach (var kv in paramDict)
                        fetchBody = fetchBody.Replace($"{{{kv.Key}}}", kv.Value);
                    if (fetchBody.TrimStart().StartsWith("{") || fetchBody.TrimStart().StartsWith("["))
                    {
                        headers ??= new Dictionary<string, string>();
                        headers.TryAdd("Content-Type", "application/json");
                    }
                }

                McpFuzzClassify(url, method, headers, fetchBody, paramDict,
                    classify, detectCrash, crashPatterns, results,
                    ref allowed, ref denied, ref errors, ref crashes,
                    await McpFuzzFetch(url, method, headers, fetchBody));
            }
        }

        return TextContent(JsonSerializer.Serialize(new
        {
            endpoint, method, results,
            summary = new { total = results.Count, allowed, denied, errors, crashes }
        }, CompactJson));
    }

    private async Task<(int status, string body)> McpFuzzFetch(
        string url, string method, Dictionary<string, string>? headers, string? body)
    {
        try
        {
            var json = await _context.Fetch(url, method, headers, body, 30000);
            using var doc = JsonDocument.Parse(json);
            var status = doc.RootElement.TryGetProperty("status", out var s) ? s.GetInt32() : 0;
            var bodyText = doc.RootElement.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
            return (status, bodyText);
        }
        catch (Exception ex) { return (0, ex.Message); }
    }

    private static void McpFuzzClassify(
        string url, string method, Dictionary<string, string>? headers, string? fetchBody,
        object paramSet, bool classify, bool detectCrash, string[] crashPatterns,
        List<object> results, ref int allowed, ref int denied, ref int errors, ref int crashes,
        (int status, string bodyText) fetchResult)
    {
        var (status, bodyText) = fetchResult;

        string? classification = null;
        bool isCrash = false;
        if (classify)
        {
            if (status >= 200 && status < 300) { classification = "allowed"; allowed++; }
            else if (status >= 400 && status < 500) { classification = "denied"; denied++; }
            else { classification = "error"; errors++; }
        }
        if (detectCrash && status >= 500)
            foreach (var pat in crashPatterns)
                if (bodyText.Contains(pat, StringComparison.OrdinalIgnoreCase))
                { isCrash = true; crashes++; break; }

        var entry = new Dictionary<string, object?>
        {
            ["url"] = url, ["method"] = method, ["parameters"] = paramSet,
            ["status"] = status, ["bodyLength"] = bodyText.Length, ["bodyHash"] = ComputeShortHash(bodyText)
        };
        if (classification != null) entry["classification"] = classification;
        if (isCrash) entry["crash"] = true;
        if (status >= 400 || status == 0)
            entry["errorSnippet"] = bodyText.Length > 500 ? bodyText[..500] : bodyText;
        results.Add(entry);
    }

    private static List<Dictionary<string, string>> McpGenerateSmartPayloads(
        List<Dictionary<string, string>> baselines)
    {
        var generated = new List<Dictionary<string, string>>();
        if (baselines.Count == 0) return generated;

        var paramNames = baselines[0].Keys.Where(k => k != "body" && k != "headers").ToList();
        if (paramNames.Count == 0) return generated;

        foreach (var paramName in paramNames)
        {
            foreach (var payloadSet in McpSmartFuzzPayloads)
            {
                foreach (var payload in payloadSet)
                {
                    var set = new Dictionary<string, string>(baselines[0]);
                    set[paramName] = payload;
                    generated.Add(set);
                }
            }
        }

        return generated;
    }

    private static string ComputeShortHash(string input)
    {
        if (string.IsNullOrEmpty(input)) return "empty";
        var bytes = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes[..8]).ToLowerInvariant();
    }

    /// <summary>
    /// Heuristic: does a redirect final URL or response body look like an access-denied or login page?
    /// Catches patterns like ASP.NET WebForms redirecting to AccessDenied.aspx or Login.aspx.
    /// </summary>
    private static bool AuthzLooksLikeDenialRedirect(string finalUrl, string body)
    {
        var urlLower = finalUrl.ToLowerInvariant();
        if (urlLower.Contains("accessdenied") || urlLower.Contains("access-denied") ||
            urlLower.Contains("unauthorized") || urlLower.Contains("forbidden") ||
            urlLower.Contains("login") || urlLower.Contains("signin") ||
            urlLower.Contains("sign-in") || urlLower.Contains("sso") ||
            urlLower.Contains("auth") || urlLower.Contains("returnurl") ||
            urlLower.Contains("redirect"))
            return true;

        if (string.IsNullOrEmpty(body) || body.Length > 50_000) return false;
        var bodyLower = body.ToLowerInvariant();
        return bodyLower.Contains("access denied") || bodyLower.Contains("not authorized") ||
               bodyLower.Contains("you do not have permission") || bodyLower.Contains("login required") ||
               bodyLower.Contains("sign in to continue") || bodyLower.Contains("403") ||
               bodyLower.Contains("unauthorized");
    }

    #endregion

    #endregion
}
