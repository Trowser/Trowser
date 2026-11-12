using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;

namespace Trowser.Automation;

/// <summary>
/// Fast parse check for <see cref="AutomationContext.ExecuteJs"/> before the async Promise wrapper,
/// so syntax errors return immediately instead of waiting for the execute-js timeout.
/// </summary>
internal static class ExecuteJsSyntaxCheck
{
    private static readonly ConditionalWeakTable<CoreWebView2, RuntimeEnableGate> RuntimeGates = new();

    /// <summary>
    /// Throws <see cref="InvalidOperationException"/> with a JavaScript error prefix when the script does not parse.
    /// </summary>
    public static async Task ValidatePreparedScriptAsync(CoreWebView2 core, string preparedScript)
    {
        if (string.IsNullOrWhiteSpace(preparedScript))
            return;

        if (await TryValidateWithCompileScriptAsync(core, preparedScript))
            return;

        await ValidateWithFunctionConstructorAsync(core, preparedScript);
    }

    private static async Task<bool> TryValidateWithCompileScriptAsync(CoreWebView2 core, string preparedScript)
    {
        if (!await TryEnsureRuntimeEnabledAsync(core))
            return false;

        try
        {
            var payload = JsonSerializer.Serialize(new
            {
                expression = preparedScript,
                sourceURL = "trowser-execute-js",
                persistScript = false
            });
            var raw = await core.CallDevToolsProtocolMethodAsync("Runtime.compileScript", payload);
            if (TryGetCompileExceptionMessage(raw, out var msg))
                throw new InvalidOperationException($"JavaScript syntax error: {msg}");
            return true;
        }
        catch (InvalidOperationException)
        {
            throw;
        }
        catch
        {
            // WebView2 often rejects compileScript (domain timing, script size, build limits).
            // Function-constructor validation below is the supported fallback.
            return false;
        }
    }

    private static async Task<bool> TryEnsureRuntimeEnabledAsync(CoreWebView2 core)
    {
        var gate = RuntimeGates.GetOrCreateValue(core);
        if (gate.Enabled)
            return true;
        if (gate.EnableFailed)
            return false;

        try
        {
            await core.CallDevToolsProtocolMethodAsync("Runtime.enable", "{}");
            gate.Enabled = true;
            return true;
        }
        catch
        {
            gate.EnableFailed = true;
            return false;
        }
    }

    private sealed class RuntimeEnableGate
    {
        public bool Enabled;
        public bool EnableFailed;
    }

    private static bool TryGetCompileExceptionMessage(string rawJson, out string message)
    {
        message = "";
        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            if (!doc.RootElement.TryGetProperty("exceptionDetails", out var details)
                || details.ValueKind == JsonValueKind.Null
                || details.ValueKind == JsonValueKind.Undefined)
                return false;

            if (details.TryGetProperty("text", out var textEl) && textEl.ValueKind == JsonValueKind.String)
                message = textEl.GetString() ?? "SyntaxError";
            else
                message = "SyntaxError";

            if (details.TryGetProperty("exception", out var exEl)
                && exEl.TryGetProperty("description", out var desc)
                && desc.ValueKind == JsonValueKind.String)
            {
                var d = desc.GetString();
                if (!string.IsNullOrWhiteSpace(d))
                    message = d!;
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    private static async Task ValidateWithFunctionConstructorAsync(CoreWebView2 core, string preparedScript)
    {
        var probe = """
            (function(src){
              try {
                new Function('return (' + src + ');');
                return '';
              } catch (e) {
                return e && e.message ? String(e.message) : String(e);
              }
            })
            """;

        var arg = JsonSerializer.Serialize(preparedScript);
        var script = $"({probe})({arg})";
        var scriptResult = await core.ExecuteScriptWithResultAsync(script);
        if (!scriptResult.Succeeded)
        {
            var jsEx = scriptResult.Exception;
            if (jsEx != null && !string.IsNullOrWhiteSpace(jsEx.Message))
                throw new InvalidOperationException($"JavaScript syntax error: {jsEx.Message}");
            throw new InvalidOperationException("JavaScript syntax error: script failed to parse.");
        }

        scriptResult.TryGetResultAsString(out var errMsg, out var isString);
        if (isString != 0 && !string.IsNullOrWhiteSpace(errMsg))
            throw new InvalidOperationException($"JavaScript syntax error: {errMsg}");
    }
}
