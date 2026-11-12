using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security.LlmRedTeam;

/// <summary>
/// Lenient DOM interaction for chat widgets — avoids strict actionability checks that fail
/// inside device mockups, overflow containers, and utility-first (Tailwind) layouts.
/// Uses native value setter + InputEvent for React/Vue controlled inputs.
/// </summary>
internal static class LlmDomInteract
{
    public static async Task FillInputAsync(AutomationContext ctx, string selector, string text)
    {
        var selJs = JsonSerializer.Serialize(selector);
        var textJs = JsonSerializer.Serialize(text);
        var raw = await ctx.ExecuteJs(
            "(function(){" +
            LlmDomScripts.DeepSearchJs +
            LlmDomScripts.VisibilityJs +
            LlmDomScripts.ReactInputJs +
            "var sel=" + selJs + ";" +
            "var text=" + textJs + ";" +
            "var el=deepQueryBest(sel);" +
            "if(!el) return JSON.stringify({ok:false,error:'Input element not found: '+sel});" +
            "scrollToReachable(el);" +
            "if(!isVisibleEnough(el)){" +
            "  try{el.scrollIntoView({block:'center',behavior:'instant'});}catch(e){}" +
            "  if(!isVisibleEnough(el)&&!isDomPresent(el))" +
            "    return JSON.stringify({ok:false,error:'Input element not visible enough: '+sel});" +
            "}" +
            "try{el.focus();}catch(e){}" +
            "if(!setReactInputValue(el,text)) return JSON.stringify({ok:false,error:'Failed to set input value'});" +
            "return JSON.stringify({ok:true,area:visibleArea(el)});" +
            "})()");

        EnsureOk(raw, "fill input");
    }

    public static async Task ClickSubmitAsync(AutomationContext ctx, string selector)
    {
        var selJs = JsonSerializer.Serialize(selector);
        var raw = await ctx.ExecuteJs(
            "(function(){" +
            LlmDomScripts.DeepSearchJs +
            LlmDomScripts.VisibilityJs +
            LlmDomScripts.ReactInputJs +
            "var sel=" + selJs + ";" +
            "var el=deepQueryBest(sel);" +
            "if(!el) return JSON.stringify({ok:false,error:'Submit element not found: '+sel});" +
            "if(!clickElement(el)) return JSON.stringify({ok:false,error:'Failed to click submit'});" +
            "return JSON.stringify({ok:true});" +
            "})()");

        EnsureOk(raw, "click submit");
    }

    public static async Task SubmitViaEnterAsync(AutomationContext ctx, string inputSelector)
    {
        var selJs = JsonSerializer.Serialize(inputSelector);
        var raw = await ctx.ExecuteJs(
            "(function(){" +
            LlmDomScripts.DeepSearchJs +
            LlmDomScripts.VisibilityJs +
            LlmDomScripts.ReactInputJs +
            "var el=deepQueryBest(" + selJs + ");" +
            "if(!el) return JSON.stringify({ok:false,error:'Input not found for Enter submit'});" +
            "scrollToReachable(el);" +
            "try{el.focus();}catch(e){}" +
            "var opts={key:'Enter',code:'Enter',keyCode:13,which:13,bubbles:true,cancelable:true};" +
            "el.dispatchEvent(new KeyboardEvent('keydown',opts));" +
            "el.dispatchEvent(new KeyboardEvent('keypress',opts));" +
            "el.dispatchEvent(new KeyboardEvent('keyup',opts));" +
            "if(el.form&&el.form.requestSubmit) el.form.requestSubmit();" +
            "return JSON.stringify({ok:true});" +
            "})()");

        EnsureOk(raw, "submit via Enter");
    }

    private static void EnsureOk(string? raw, string action)
    {
        if (string.IsNullOrWhiteSpace(raw))
            throw new InvalidOperationException($"Failed to {action}: empty JS result.");

        try
        {
            if (raw.StartsWith('"'))
                raw = JsonSerializer.Deserialize<string>(raw) ?? raw;
            using var doc = JsonDocument.Parse(raw);
            if (doc.RootElement.TryGetProperty("ok", out var ok) && ok.GetBoolean())
                return;
            var err = doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : null;
            throw new InvalidOperationException(err ?? $"Failed to {action}.");
        }
        catch (InvalidOperationException)
        {
            throw;
        }
        catch
        {
            if (raw.Contains("ok", StringComparison.Ordinal) && raw.Contains("true", StringComparison.Ordinal))
                return;
            throw new InvalidOperationException($"Failed to {action}: {raw}");
        }
    }
}
