using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>Poll for delayed execution oracles (event handlers, microtasks) after sink reach.</summary>
internal static class ExecProofPoller
{
    public static async Task<bool> PollAsync(AutomationContext ctx, string payload, string? execCanary)
    {
        var proofGlobal = TraceInputPayloadPrep.ProofGlobal;
        var wantsProof = payload.Contains(proofGlobal, StringComparison.OrdinalIgnoreCase)
                         || payload.Contains(TraceInputPayloadPrep.ExecGlobal, StringComparison.OrdinalIgnoreCase);
        if (!wantsProof && string.IsNullOrEmpty(execCanary))
            return false;

        var proofJson = JsonSerializer.Serialize(proofGlobal);
        var canaryJson = JsonSerializer.Serialize(execCanary ?? "");

        for (var attempt = 0; attempt < 8; attempt++)
        {
            if (attempt > 0)
                await Task.Delay(attempt < 3 ? 40 : 120);

            try
            {
                var json = await ctx.ExecuteJs(
                    $@"(function(){{
                        return new Promise(function(resolve){{
                            function check(){{
                                try {{
                                    var canary = {canaryJson};
                                    if (canary && window.__trowser_exec_proof === canary) return true;
                                    if (window[{proofJson}] === 1 || window[{proofJson}] === '1') return true;
                                    if (window.__trowser_exec_proof && (!canary || String(window.__trowser_exec_proof) === canary))
                                        return true;
                                }} catch(e) {{}}
                                return false;
                            }}
                            if (check()) {{ resolve('true'); return; }}
                            requestAnimationFrame(function(){{
                                if (check()) {{ resolve('true'); return; }}
                                requestAnimationFrame(function(){{
                                    resolve(check() ? 'true' : 'false');
                                }});
                            }});
                        }});
                    }})()");
                if (json.Contains("true", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            catch
            {
                /* best-effort */
            }
        }

        return false;
    }
}
