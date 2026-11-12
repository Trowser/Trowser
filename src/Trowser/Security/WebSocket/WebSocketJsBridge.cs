using System.Text.Json;
using Trowser.Automation;
using Trowser.Security.WebSocket;

namespace Trowser.Security.WebSocket;

/// <summary>
/// Sends/closes WebSocket messages via injected page hook (window.__trowserWs).
/// </summary>
public static class WebSocketJsBridge
{
    public const string HookScript = """
        (function(){
          if (window.__trowserWsHook) return;
          window.__trowserWsHook = true;
          window.__trowserWsRefs = [];
          var Orig = WebSocket;
          function Patched(url, protocols) {
            var ws = protocols !== undefined ? new Orig(url, protocols) : new Orig(url);
            var entry = { id: window.__trowserWsRefs.length, url: String(url), ws: ws, state: 'connecting' };
            window.__trowserWsRefs.push(entry);
            ws.addEventListener('open', function(){ entry.state = 'open'; });
            ws.addEventListener('close', function(){ entry.state = 'closed'; });
            ws.addEventListener('message', function(ev) {
              try {
                if (typeof window.__trowser_rt_noteInboundMessage === 'function')
                  window.__trowser_rt_noteInboundMessage(ev.data);
              } catch(e) {}
            });
            return ws;
          }
          Patched.prototype = Orig.prototype;
          Patched.CONNECTING = Orig.CONNECTING;
          Patched.OPEN = Orig.OPEN;
          Patched.CLOSING = Orig.CLOSING;
          Patched.CLOSED = Orig.CLOSED;
          window.WebSocket = Patched;
          window.__trowserWsSend = function(id, data) {
            var e = window.__trowserWsRefs[id];
            if (!e || !e.ws || e.ws.readyState !== 1) return { ok: false, error: 'not-open', readyState: e && e.ws ? e.ws.readyState : -1 };
            e.ws.send(data);
            return { ok: true, id: id, url: e.url };
          };
          window.__trowserWsClose = function(id, code, reason) {
            var e = window.__trowserWsRefs[id];
            if (!e || !e.ws) return { ok: false, error: 'missing' };
            e.ws.close(code || 1000, reason || '');
            return { ok: true, id: id };
          };
          window.__trowserWsList = function() {
            return window.__trowserWsRefs.map(function(e){ return { id: e.id, url: e.url, state: e.state, readyState: e.ws ? e.ws.readyState : -1 }; });
          };
        })();
        """;

    public sealed class SendResult
    {
        public bool Ok { get; init; }
        public string? Error { get; init; }
        public int? HookId { get; init; }
        public string? Url { get; init; }
    }

    public static async Task EnsureHookAsync(AutomationContext ctx)
    {
        await ctx.ExecuteJs(HookScript);
    }

    public static async Task<SendResult> SendAsync(AutomationContext ctx, int connectionId, string message)
    {
        await EnsureHookAsync(ctx);
        var hookId = await ResolveHookIdAsync(ctx, connectionId);
        if (hookId == null)
            return new SendResult { Ok = false, Error = $"No JS hook match for connectionId {connectionId}" };

        var js = $"(function(){{ try {{ return JSON.stringify(window.__trowserWsSend({hookId.Value}, {JsonSerializer.Serialize(message)})); }} catch(e){{ return JSON.stringify({{ ok:false, error: String(e) }}); }} }})()";
        var raw = await ctx.ExecuteJs(js);
        return ParseResult(raw);
    }

    public static async Task<SendResult> CloseAsync(AutomationContext ctx, int connectionId, int? code = null, string? reason = null)
    {
        await EnsureHookAsync(ctx);
        var hookId = await ResolveHookIdAsync(ctx, connectionId);
        if (hookId == null)
            return new SendResult { Ok = false, Error = $"No JS hook match for connectionId {connectionId}" };

        var js = $"(function(){{ try {{ return JSON.stringify(window.__trowserWsClose({hookId.Value}, {code ?? 1000}, {JsonSerializer.Serialize(reason ?? "")})); }} catch(e){{ return JSON.stringify({{ ok:false, error: String(e) }}); }} }})()";
        var raw = await ctx.ExecuteJs(js);
        return ParseResult(raw);
    }

    private static async Task<int?> ResolveHookIdAsync(AutomationContext ctx, int connectionId)
    {
        var conn = ctx.ActiveTab.WebSocket.GetConnection(connectionId);
        if (conn == null) return null;

        var listJson = await ctx.ExecuteJs("(function(){ try { return JSON.stringify(window.__trowserWsList ? window.__trowserWsList() : []); } catch(e){ return '[]'; } })()");
        try
        {
            using var doc = JsonDocument.Parse(listJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return null;
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                var url = el.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";
                var id = el.TryGetProperty("id", out var i) ? i.GetInt32() : -1;
                if (id < 0) continue;
                if (UrlsMatch(url, conn.Url))
                    return id;
            }
        }
        catch { /* ignore */ }

        return connectionId - 1 >= 0 ? connectionId - 1 : null;
    }

    private static bool UrlsMatch(string a, string b) =>
        string.Equals(WebSocketAuditor.NormalizeConnectionUrl(a), WebSocketAuditor.NormalizeConnectionUrl(b),
            StringComparison.OrdinalIgnoreCase);

    private static SendResult ParseResult(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return new SendResult { Ok = false, Error = "empty response" };
        try
        {
            using var doc = JsonDocument.Parse(raw);
            var root = doc.RootElement;
            var ok = root.TryGetProperty("ok", out var o) && o.ValueKind == JsonValueKind.True;
            return new SendResult
            {
                Ok = ok,
                Error = root.TryGetProperty("error", out var e) ? e.GetString() : null,
                HookId = root.TryGetProperty("id", out var id) ? id.GetInt32() : null,
                Url = root.TryGetProperty("url", out var u) ? u.GetString() : null
            };
        }
        catch
        {
            return new SendResult { Ok = false, Error = "invalid json" };
        }
    }

    /// <summary>graphql-ws subprotocol init message preset.</summary>
    public static string GraphqlWsConnectionInit(string? payloadJson = null) =>
        payloadJson == null
            ? """{"type":"connection_init"}"""
            : "{\"type\":\"connection_init\",\"payload\":" + payloadJson + "}";
}
