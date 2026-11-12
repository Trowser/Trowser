using System.Text;
using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Result of a single firewall bypass technique test.
/// </summary>
public class FirewallTestResult
{
    public string Technique { get; init; } = "";
    public string Directive { get; init; } = "";
    public string Result { get; init; } = ""; // "blocked", "bypassed", "not-applicable", "error"
    public Severity? Severity { get; init; }
    public string Detail { get; init; } = "";
}

/// <summary>
/// Result of testing a single defense category (CSP, SRI, Sandbox, Permissions-Policy).
/// </summary>
public class DefenseResult
{
    public bool Present { get; set; }
    public string? Policy { get; set; }
    public string Verdict { get; set; } = "not-tested"; // "effective", "bypassed", "partial", "absent", "error"
    public List<FirewallTestResult> Tests { get; init; } = [];
    public List<FirewallTestResult> Findings { get; init; } = [];
}

/// <summary>
/// Overall result from a firewall test run.
/// </summary>
public class FirewallResult
{
    public long ElapsedMs { get; set; }
    public string OverallVerdict { get; set; } = "not-tested";
    public int DefensesTested { get; set; }
    public int DefensesEffective { get; set; }
    public int DefensesIneffective { get; set; }
    public int DefensesAbsent { get; set; }
    public DefenseResult? Csp { get; set; }
    public DefenseResult? Sri { get; set; }
    public DefenseResult? Sandbox { get; set; }
    public DefenseResult? PermissionsPolicy { get; set; }
    public List<string> UnknownCspProbes { get; set; } = [];

    public string Format(bool verbose = false)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== Client-Side Firewall Test ===");
        sb.AppendLine($"Overall: {OverallVerdict.ToUpperInvariant()}");
        sb.AppendLine($"Tested: {DefensesTested}, Effective: {DefensesEffective}, Ineffective: {DefensesIneffective}, Absent: {DefensesAbsent}");
        sb.AppendLine();

        FormatDefense(sb, "CSP (Content Security Policy)", Csp, verbose);
        FormatDefense(sb, "SRI (Subresource Integrity)", Sri, verbose);
        FormatDefense(sb, "Iframe Sandbox", Sandbox, verbose);
        FormatDefense(sb, "Permissions Policy", PermissionsPolicy, verbose);

        return sb.ToString();
    }

    private static void FormatDefense(StringBuilder sb, string name, DefenseResult? result, bool verbose)
    {
        if (result == null) return;
        sb.AppendLine($"--- {name} ---");
        sb.AppendLine($"  Present: {result.Present}");
        if (result.Policy != null)
            sb.AppendLine($"  Policy: {(result.Policy.Length > 200 ? result.Policy[..200] + "..." : result.Policy)}");
        sb.AppendLine($"  Verdict: {result.Verdict}");

        foreach (var f in result.Findings)
            sb.AppendLine($"  [{f.Severity}] {f.Technique}: {f.Detail}");

        if (verbose)
            foreach (var t in result.Tests.Where(t => t.Result == "blocked"))
                sb.AppendLine($"  [OK] {t.Technique}: {t.Detail}");

        sb.AppendLine();
    }
}

/// <summary>
/// Tests whether deployed client-side security defenses actually block attacks.
/// Uses the browser itself to attempt bypass techniques and observes enforcement.
/// </summary>
public class FirewallTester
{
    private readonly AutomationContext _context;

    public FirewallTester(AutomationContext context)
    {
        _context = context;
    }

    public async Task<FirewallResult> RunAsync(
        HashSet<string>? tests = null,
        bool verbose = false,
        IReadOnlyCollection<string>? cspProbes = null)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        tests ??= ["all"];
        bool runAll = tests.Contains("all");

        var result = new FirewallResult();
        var probes = FirewallCspProbes.Resolve(cspProbes, out var unknown);
        result.UnknownCspProbes = unknown;

        if (runAll || tests.Contains("csp"))
            result.Csp = await TestCsp(probes);

        if (runAll || tests.Contains("sri"))
            result.Sri = await TestSri();

        if (runAll || tests.Contains("sandbox"))
            result.Sandbox = await TestSandbox();

        if (runAll || tests.Contains("permissions-policy"))
            result.PermissionsPolicy = await TestPermissionsPolicy();

        sw.Stop();
        result.ElapsedMs = sw.ElapsedMilliseconds;

        // Tally
        foreach (var def in new[] { result.Csp, result.Sri, result.Sandbox, result.PermissionsPolicy })
        {
            if (def == null) continue;
            result.DefensesTested++;
            if (!def.Present) { result.DefensesAbsent++; def.Verdict = "absent"; }
            else if (def.Findings.Count > 0) { result.DefensesIneffective++; def.Verdict = "bypassed"; }
            else { result.DefensesEffective++; def.Verdict = "effective"; }
        }

        result.OverallVerdict = result.DefensesIneffective > 0 ? "fail"
            : result.DefensesAbsent > 0 ? "partial"
            : result.DefensesTested > 0 ? "pass"
            : "not-tested";

        return result;
    }

    #region CSP Testing

    private async Task<DefenseResult> TestCsp(IReadOnlyList<string> probes)
    {
        var def = new DefenseResult();

        try
        {
            var headersResult = await _context.CheckSecurityHeaders();
            var cspHeader = headersResult.RawHeaders
                .FirstOrDefault(h => h.Key.Equals("Content-Security-Policy", StringComparison.OrdinalIgnoreCase));

            if (string.IsNullOrEmpty(cspHeader.Value))
            {
                def.Present = false;
                return def;
            }

            def.Present = true;
            def.Policy = cspHeader.Value;

            if (FirewallCspProbes.Includes(probes, "inline-script"))
                await TestCspInlineScript(def);

            if (FirewallCspProbes.Includes(probes, "eval"))
                await TestCspEval(def);

            if (FirewallCspProbes.Includes(probes, "event-handler"))
                await TestCspEventHandler(def);

            if (FirewallCspProbes.Includes(probes, "nonce-reuse"))
                await TestCspNonceReuse(def);

            if (FirewallCspProbes.Includes(probes, "base-uri-injection"))
                await TestCspBaseUri(def);

            if (FirewallCspProbes.Includes(probes, "script-src-data"))
                await TestCspScriptSource(def, "script-src-data", "data");

            if (FirewallCspProbes.Includes(probes, "script-src-blob"))
                await TestCspScriptSource(def, "script-src-blob", "blob");

            if (FirewallCspProbes.Includes(probes, "javascript-url"))
                await TestCspJavascriptUrl(def);

            if (FirewallCspProbes.Includes(probes, "form-action"))
                await TestCspFormAction(def);

            if (FirewallCspProbes.Includes(probes, "frame-src"))
                await TestCspFrameSrc(def);

            if (FirewallCspProbes.Includes(probes, "worker-blob"))
                await TestCspWorkerBlob(def);

            await CleanupTestElements();
        }
        catch (Exception ex)
        {
            def.Verdict = "error";
            def.Tests.Add(new FirewallTestResult
            {
                Technique = "csp-test-error",
                Directive = "script-src",
                Result = "error",
                Detail = $"CSP testing failed: {ex.Message}"
            });
        }

        return def;
    }

    private async Task TestCspInlineScript(DefenseResult def)
    {
        var marker = $"__cspTest_{Guid.NewGuid():N}";
        try
        {
            await _context.ExecuteJs(
                $"try {{ var s=document.createElement('script'); s.setAttribute('data-trowser-test','1'); " +
                $"s.textContent='window.{marker}=1'; document.body.appendChild(s); }} catch(e){{}}");

            await Task.Delay(200);

            var executed = await _context.ExecuteJs($"typeof window.{marker} !== 'undefined' ? 'yes' : 'no'");

            if (executed.Contains("yes"))
            {
                def.Findings.Add(new FirewallTestResult
                {
                    Technique = "inline-script",
                    Directive = "script-src",
                    Result = "bypassed",
                    Severity = Severity.High,
                    Detail = "Injected inline <script> executed successfully. CSP does not block inline scripts (likely 'unsafe-inline' is set or no script-src directive)."
                });
            }
            else
            {
                def.Tests.Add(new FirewallTestResult
                {
                    Technique = "inline-script",
                    Directive = "script-src",
                    Result = "blocked",
                    Detail = "CSP blocked inline script execution."
                });
            }

            await _context.ExecuteJs($"try {{ delete window.{marker}; }} catch(e){{}}");
        }
        catch
        {
            def.Tests.Add(new FirewallTestResult
            {
                Technique = "inline-script",
                Directive = "script-src",
                Result = "blocked",
                Detail = "CSP blocked inline script execution (exception thrown)."
            });
        }
    }

    private async Task TestCspEval(DefenseResult def)
    {
        var scriptMarker = $"__cspEvalScript_{Guid.NewGuid():N}";
        var evalMarker = $"__cspEval_{Guid.NewGuid():N}";
        try
        {
            await _context.ExecuteJs(
                $"try {{ var s=document.createElement('script'); s.setAttribute('data-trowser-test','1'); " +
                $"s.textContent='window.{scriptMarker}=1; try{{eval(\"window.{evalMarker}=1\")}}catch(e){{window.{scriptMarker}=2}}'; " +
                $"document.body.appendChild(s); }} catch(e){{}}");

            await Task.Delay(200);

            var state = await _context.ExecuteJs(
                $"(function(){{ var s=window.{scriptMarker}; var e=window.{evalMarker}; " +
                "if(!s) return 'script-blocked'; if(e) return 'eval-ran'; return 'eval-blocked'; })()");

            if (state.Contains("eval-ran"))
            {
                def.Findings.Add(new FirewallTestResult
                {
                    Technique = "eval",
                    Directive = "script-src",
                    Result = "bypassed",
                    Severity = Severity.Medium,
                    Detail = "eval() inside an injected <script> ran in page context. CSP allows 'unsafe-eval'."
                });
            }
            else if (state.Contains("script-blocked"))
            {
                def.Tests.Add(new FirewallTestResult
                {
                    Technique = "eval",
                    Directive = "script-src",
                    Result = "not-applicable",
                    Detail = "Inline script did not execute, so unsafe-eval was not reached. This is not proof that eval() is blocked."
                });
            }
            else
            {
                def.Tests.Add(new FirewallTestResult
                {
                    Technique = "eval",
                    Directive = "script-src",
                    Result = "blocked",
                    Detail = "The injected script ran, and eval() inside it did not. CSP blocks 'unsafe-eval'."
                });
            }

            await _context.ExecuteJs($"try {{ delete window.{scriptMarker}; delete window.{evalMarker}; }} catch(e){{}}");
        }
        catch
        {
            def.Tests.Add(new FirewallTestResult
            {
                Technique = "eval",
                Directive = "script-src",
                Result = "not-applicable",
                Detail = "eval() probe did not complete, so unsafe-eval was not measured."
            });
        }
    }

    private async Task TestCspScriptSource(DefenseResult def, string technique, string kind)
    {
        var marker = $"__cspSrc_{Guid.NewGuid():N}";
        try
        {
            string createSrc = kind == "data"
                ? $"'data:text/javascript,'+encodeURIComponent('window.{marker}=1')"
                : $"(function(){{ var b=new Blob(['window.{marker}=1'],{{type:'text/javascript'}}); return URL.createObjectURL(b); }})()";

            await _context.ExecuteJs(
                $"try {{ var s=document.createElement('script'); s.setAttribute('data-trowser-test','1'); " +
                $"s.src={createSrc}; document.body.appendChild(s); }} catch(e){{}}");

            await Task.Delay(250);
            var executed = await _context.ExecuteJs($"typeof window.{marker} !== 'undefined' ? 'yes' : 'no'");
            if (executed.Contains("yes"))
            {
                def.Findings.Add(new FirewallTestResult
                {
                    Technique = technique,
                    Directive = "script-src",
                    Result = "bypassed",
                    Severity = Severity.High,
                    Detail = kind == "data"
                        ? "A script loaded from a data: URL executed. script-src allows data:."
                        : "A script loaded from a blob: URL executed. script-src allows blob:."
                });
            }
            else
            {
                def.Tests.Add(new FirewallTestResult
                {
                    Technique = technique,
                    Directive = "script-src",
                    Result = "blocked",
                    Detail = kind == "data"
                        ? "CSP blocked a data: script URL."
                        : "CSP blocked a blob: script URL."
                });
            }

            await _context.ExecuteJs($"try {{ delete window.{marker}; }} catch(e){{}}");
        }
        catch
        {
            def.Tests.Add(new FirewallTestResult
            {
                Technique = technique,
                Directive = "script-src",
                Result = "blocked",
                Detail = "Script source probe was blocked."
            });
        }
    }

    private async Task TestCspJavascriptUrl(DefenseResult def)
    {
        var marker = $"__cspJsUrl_{Guid.NewGuid():N}";
        try
        {
            await _context.ExecuteJs(
                $"var a=document.createElement('a'); a.setAttribute('data-trowser-test','1'); " +
                $"a.href='javascript:window.{marker}=1'; document.body.appendChild(a); a.click();");
            await Task.Delay(200);
            var executed = await _context.ExecuteJs($"typeof window.{marker} !== 'undefined' ? 'yes' : 'no'");
            if (executed.Contains("yes"))
            {
                def.Findings.Add(new FirewallTestResult
                {
                    Technique = "javascript-url",
                    Directive = "script-src",
                    Result = "bypassed",
                    Severity = Severity.High,
                    Detail = "A javascript: URL ran. script-src does not block javascript: URLs."
                });
            }
            else
            {
                def.Tests.Add(new FirewallTestResult
                {
                    Technique = "javascript-url",
                    Directive = "script-src",
                    Result = "blocked",
                    Detail = "CSP blocked a javascript: URL."
                });
            }

            await _context.ExecuteJs($"try {{ delete window.{marker}; }} catch(e){{}}");
        }
        catch
        {
            def.Tests.Add(new FirewallTestResult
            {
                Technique = "javascript-url",
                Directive = "script-src",
                Result = "blocked",
                Detail = "javascript: URL probe was blocked."
            });
        }
    }

    private async Task TestCspFormAction(DefenseResult def)
    {
        try
        {
            await _context.ExecuteJs(
                "window.__trowserCspForm='pending';" +
                "document.addEventListener('securitypolicyviolation',function(e){" +
                " var d=(e.effectiveDirective||e.violatedDirective||'');" +
                " if(d.indexOf('form-action')>=0&&String(e.blockedURI||'').indexOf('trowser-csp-probe.invalid')>=0) window.__trowserCspForm='blocked'; });" +
                "var iframe=document.createElement('iframe'); iframe.name='trowserCspForm'; iframe.setAttribute('data-trowser-test','1'); iframe.style.display='none'; document.body.appendChild(iframe);" +
                "var f=document.createElement('form'); f.setAttribute('data-trowser-test','1'); f.method='GET'; f.target='trowserCspForm'; f.action='https://trowser-csp-probe.invalid/form'; document.body.appendChild(f); f.submit();");
            await Task.Delay(350);
            var state = await _context.ExecuteJs("window.__trowserCspForm||'pending'");
            if (state.Contains("blocked"))
            {
                def.Tests.Add(new FirewallTestResult
                {
                    Technique = "form-action",
                    Directive = "form-action",
                    Result = "blocked",
                    Detail = "CSP form-action blocked a cross-origin form submit."
                });
            }
            else
            {
                def.Findings.Add(new FirewallTestResult
                {
                    Technique = "form-action",
                    Directive = "form-action",
                    Result = "bypassed",
                    Severity = Severity.Medium,
                    Detail = "A cross-origin form submit was not blocked. form-action is missing or allows the target."
                });
            }

            await _context.ExecuteJs("try { delete window.__trowserCspForm; } catch(e){}");
        }
        catch
        {
            def.Tests.Add(new FirewallTestResult
            {
                Technique = "form-action",
                Directive = "form-action",
                Result = "not-applicable",
                Detail = "form-action probe did not complete."
            });
        }
    }

    private async Task TestCspFrameSrc(DefenseResult def)
    {
        try
        {
            await _context.ExecuteJs(
                "window.__trowserCspFrame='pending';" +
                "document.addEventListener('securitypolicyviolation',function(e){" +
                " var d=(e.effectiveDirective||e.violatedDirective||'');" +
                " if((d.indexOf('frame-src')>=0||d.indexOf('child-src')>=0)&&String(e.blockedURI||'').indexOf('trowser-csp-probe.invalid')>=0) window.__trowserCspFrame='blocked'; });" +
                "var iframe=document.createElement('iframe'); iframe.setAttribute('data-trowser-test','1'); iframe.style.display='none'; iframe.src='https://trowser-csp-probe.invalid/frame'; document.body.appendChild(iframe);");
            await Task.Delay(350);
            var state = await _context.ExecuteJs("window.__trowserCspFrame||'pending'");
            if (state.Contains("blocked"))
            {
                def.Tests.Add(new FirewallTestResult
                {
                    Technique = "frame-src",
                    Directive = "frame-src",
                    Result = "blocked",
                    Detail = "CSP frame-src blocked a cross-origin iframe."
                });
            }
            else
            {
                def.Findings.Add(new FirewallTestResult
                {
                    Technique = "frame-src",
                    Directive = "frame-src",
                    Result = "bypassed",
                    Severity = Severity.Low,
                    Detail = "A cross-origin iframe was not blocked. frame-src is missing or allows the target."
                });
            }

            await _context.ExecuteJs("try { delete window.__trowserCspFrame; } catch(e){}");
        }
        catch
        {
            def.Tests.Add(new FirewallTestResult
            {
                Technique = "frame-src",
                Directive = "frame-src",
                Result = "not-applicable",
                Detail = "frame-src probe did not complete."
            });
        }
    }

    private async Task TestCspWorkerBlob(DefenseResult def)
    {
        try
        {
            await _context.ExecuteJs(
                "window.__trowserCspWorker='pending';" +
                "document.addEventListener('securitypolicyviolation',function(e){" +
                " var d=(e.effectiveDirective||e.violatedDirective||'');" +
                " var uri=String(e.blockedURI||'');" +
                " if((d.indexOf('worker-src')>=0||d.indexOf('script-src')>=0)&&uri.indexOf('blob:')>=0) window.__trowserCspWorker='blocked'; });" +
                "try { var b=new Blob(['self.close()'],{type:'text/javascript'}); var w=new Worker(URL.createObjectURL(b));" +
                " w.onerror=function(){ if(window.__trowserCspWorker==='pending') window.__trowserCspWorker='blocked'; };" +
                " setTimeout(function(){ if(window.__trowserCspWorker==='pending'){ window.__trowserCspWorker='ran'; try{w.terminate()}catch(e){} } },150);" +
                "} catch(e) { window.__trowserCspWorker='blocked'; }");
            await Task.Delay(400);
            var state = await _context.ExecuteJs("window.__trowserCspWorker||'pending'");
            if (state.Contains("ran"))
            {
                def.Findings.Add(new FirewallTestResult
                {
                    Technique = "worker-blob",
                    Directive = "worker-src",
                    Result = "bypassed",
                    Severity = Severity.Medium,
                    Detail = "A blob: Worker started. worker-src (or script-src) allows blob: workers."
                });
            }
            else if (state.Contains("blocked"))
            {
                def.Tests.Add(new FirewallTestResult
                {
                    Technique = "worker-blob",
                    Directive = "worker-src",
                    Result = "blocked",
                    Detail = "CSP blocked a blob: Worker."
                });
            }
            else
            {
                def.Tests.Add(new FirewallTestResult
                {
                    Technique = "worker-blob",
                    Directive = "worker-src",
                    Result = "not-applicable",
                    Detail = "blob: Worker probe did not finish."
                });
            }

            await _context.ExecuteJs("try { delete window.__trowserCspWorker; } catch(e){}");
        }
        catch
        {
            def.Tests.Add(new FirewallTestResult
            {
                Technique = "worker-blob",
                Directive = "worker-src",
                Result = "not-applicable",
                Detail = "blob: Worker probe did not complete."
            });
        }
    }

    private async Task TestCspEventHandler(DefenseResult def)
    {
        var marker = $"__cspHandler_{Guid.NewGuid():N}";
        try
        {
            await _context.ExecuteJs(
                $"var img=document.createElement('img'); img.setAttribute('data-trowser-test','1'); " +
                $"img.src='x'; img.setAttribute('onerror','window.{marker}=1'); document.body.appendChild(img);");

            await Task.Delay(300);

            var executed = await _context.ExecuteJs($"typeof window.{marker} !== 'undefined' ? 'yes' : 'no'");

            if (executed.Contains("yes"))
            {
                def.Findings.Add(new FirewallTestResult
                {
                    Technique = "event-handler",
                    Directive = "script-src",
                    Result = "bypassed",
                    Severity = Severity.High,
                    Detail = "Inline event handler (onerror) executed. CSP does not block inline event handlers."
                });
            }
            else
            {
                def.Tests.Add(new FirewallTestResult
                {
                    Technique = "event-handler",
                    Directive = "script-src",
                    Result = "blocked",
                    Detail = "CSP blocked inline event handler execution."
                });
            }
            await _context.ExecuteJs($"try {{ delete window.{marker}; }} catch(e){{}}");
        }
        catch
        {
            def.Tests.Add(new FirewallTestResult { Technique = "event-handler", Directive = "script-src", Result = "blocked", Detail = "Event handler blocked." });
        }
    }

    private async Task TestCspNonceReuse(DefenseResult def)
    {
        try
        {
            var nonces = await _context.ExecuteJs(
                "JSON.stringify([...document.querySelectorAll('script[nonce]')].map(s=>s.nonce||s.getAttribute('nonce')).filter(Boolean))");

            if (string.IsNullOrEmpty(nonces) || nonces == "[]" || nonces == "null") return;

            var nonceList = JsonSerializer.Deserialize<List<string>>(nonces);
            if (nonceList == null || nonceList.Count == 0) return;

            var nonce = nonceList[0];
            if (string.IsNullOrEmpty(nonce)) return;

            var marker = $"__cspNonce_{Guid.NewGuid():N}";
            await _context.ExecuteJs(
                $"var s=document.createElement('script'); s.setAttribute('data-trowser-test','1'); " +
                $"s.setAttribute('nonce','{nonce}'); s.textContent='window.{marker}=1'; document.body.appendChild(s);");

            await Task.Delay(200);

            var executed = await _context.ExecuteJs($"typeof window.{marker} !== 'undefined' ? 'yes' : 'no'");

            if (executed.Contains("yes"))
            {
                def.Findings.Add(new FirewallTestResult
                {
                    Technique = "nonce-reuse",
                    Directive = "script-src",
                    Result = "bypassed",
                    Severity = Severity.High,
                    Detail = $"Injected script with reused nonce '{nonce[..Math.Min(8, nonce.Length)]}...' executed. " +
                             $"Found {nonceList.Count} script(s) with this nonce. Nonces should be unique and unpredictable per response."
                });
            }
            else
            {
                def.Tests.Add(new FirewallTestResult
                {
                    Technique = "nonce-reuse",
                    Directive = "script-src",
                    Result = "blocked",
                    Detail = "Reused nonce did not allow script execution (browser cleared nonce after use)."
                });
            }
            await _context.ExecuteJs($"try {{ delete window.{marker}; }} catch(e){{}}");
        }
        catch { }
    }

    private async Task TestCspBaseUri(DefenseResult def)
    {
        try
        {
            var originalBase = await _context.ExecuteJs("document.baseURI");
            var marker = $"__cspBase_{Guid.NewGuid():N}";

            await _context.ExecuteJs(
                $"var b=document.createElement('base'); b.setAttribute('data-trowser-test','1'); " +
                $"b.href='https://{marker}.trowser.test/'; document.head.appendChild(b);");

            await Task.Delay(100);

            var newBase = await _context.ExecuteJs("document.baseURI");

            if (newBase.Contains($"{marker}.trowser.test"))
            {
                def.Findings.Add(new FirewallTestResult
                {
                    Technique = "base-uri-injection",
                    Directive = "base-uri",
                    Result = "bypassed",
                    Severity = Severity.Medium,
                    Detail = "Injected <base> element changed document.baseURI. Missing or permissive base-uri directive allows relative URL hijacking."
                });
            }
            else
            {
                def.Tests.Add(new FirewallTestResult
                {
                    Technique = "base-uri-injection",
                    Directive = "base-uri",
                    Result = "blocked",
                    Detail = "CSP base-uri directive prevented <base> injection."
                });
            }
        }
        catch { }
    }

    #endregion

    #region SRI Testing

    private async Task<DefenseResult> TestSri()
    {
        var def = new DefenseResult();

        try
        {
            var resourcesJson = await _context.ExecuteJs(
                @"JSON.stringify([
                    ...[...document.querySelectorAll('script[src]')].map(s=>({
                        tag:'script', url:s.src, hasSri:!!s.integrity, integrity:s.integrity||null,
                        crossorigin:s.crossOrigin||null, isExternal:new URL(s.src).origin!==location.origin
                    })),
                    ...[...document.querySelectorAll('link[rel=stylesheet][href]')].map(l=>({
                        tag:'link', url:l.href, hasSri:!!l.integrity, integrity:l.integrity||null,
                        crossorigin:l.crossOrigin||null, isExternal:new URL(l.href).origin!==location.origin
                    }))
                ])");

            if (string.IsNullOrEmpty(resourcesJson) || resourcesJson == "[]" || resourcesJson == "null")
            {
                def.Present = false;
                return def;
            }

            var resources = JsonSerializer.Deserialize<List<JsonElement>>(resourcesJson);
            if (resources == null || resources.Count == 0) { def.Present = false; return def; }

            var sriCount = resources.Count(r => r.GetProperty("hasSri").GetBoolean());
            def.Present = sriCount > 0;
            def.Policy = $"{sriCount}/{resources.Count} resources have SRI";

            foreach (var res in resources)
            {
                var hasSri = res.GetProperty("hasSri").GetBoolean();
                var url = res.GetProperty("url").GetString() ?? "";
                var isExternal = res.GetProperty("isExternal").GetBoolean();
                var tag = res.GetProperty("tag").GetString() ?? "";

                if (hasSri)
                {
                    var integrity = res.GetProperty("integrity").GetString() ?? "";
                    var algorithm = integrity.Split('-')[0];
                    def.Tests.Add(new FirewallTestResult
                    {
                        Technique = "sri-present",
                        Directive = tag,
                        Result = "blocked",
                        Detail = $"SRI protection on {ShortUrl(url)} (algorithm: {algorithm})"
                    });
                }
                else if (isExternal)
                {
                    def.Findings.Add(new FirewallTestResult
                    {
                        Technique = "missing-sri-external",
                        Directive = tag,
                        Result = "bypassed",
                        Severity = Severity.Medium,
                        Detail = $"Third-party {tag} without SRI: {ShortUrl(url)}. If the CDN is compromised, arbitrary code could execute."
                    });
                }
            }
        }
        catch (Exception ex)
        {
            def.Verdict = "error";
            def.Tests.Add(new FirewallTestResult { Technique = "sri-test-error", Directive = "", Result = "error", Detail = ex.Message });
        }

        return def;
    }

    #endregion

    #region Iframe Sandbox Testing

    private async Task<DefenseResult> TestSandbox()
    {
        var def = new DefenseResult();

        try
        {
            var iframesJson = await _context.ExecuteJs(
                @"JSON.stringify([...document.querySelectorAll('iframe')].map(f=>({
                    src:f.src||'(inline)', sandbox:f.sandbox?.value||null, hasSandbox:f.hasAttribute('sandbox'),
                    isExternal:f.src?new URL(f.src,location.href).origin!==location.origin:false
                })))");

            if (string.IsNullOrEmpty(iframesJson) || iframesJson == "[]" || iframesJson == "null")
            {
                def.Present = false;
                def.Policy = "No iframes on page";
                return def;
            }

            var iframes = JsonSerializer.Deserialize<List<JsonElement>>(iframesJson);
            if (iframes == null || iframes.Count == 0) { def.Present = false; def.Policy = "No iframes"; return def; }

            def.Present = iframes.Any(f => f.GetProperty("hasSandbox").GetBoolean());
            def.Policy = $"{iframes.Count(f => f.GetProperty("hasSandbox").GetBoolean())}/{iframes.Count} iframes sandboxed";

            foreach (var iframe in iframes)
            {
                var hasSandbox = iframe.GetProperty("hasSandbox").GetBoolean();
                var src = iframe.GetProperty("src").GetString() ?? "(inline)";
                var isExternal = iframe.GetProperty("isExternal").GetBoolean();

                if (hasSandbox)
                {
                    var sandbox = iframe.GetProperty("sandbox").GetString() ?? "";
                    var flags = sandbox.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToHashSet();

                    if (flags.Contains("allow-scripts") && flags.Contains("allow-same-origin"))
                    {
                        def.Findings.Add(new FirewallTestResult
                        {
                            Technique = "sandbox-escape",
                            Directive = "iframe",
                            Result = "bypassed",
                            Severity = Severity.High,
                            Detail = $"Iframe {ShortUrl(src)} has sandbox=\"{sandbox}\". Combining allow-scripts + allow-same-origin " +
                                     "allows the embedded page to remove its own sandbox via script."
                        });
                    }
                    else
                    {
                        def.Tests.Add(new FirewallTestResult
                        {
                            Technique = "sandbox-enforced",
                            Directive = "iframe",
                            Result = "blocked",
                            Detail = $"Iframe {ShortUrl(src)} sandboxed with: {sandbox}"
                        });
                    }
                }
                else if (isExternal)
                {
                    def.Findings.Add(new FirewallTestResult
                    {
                        Technique = "missing-sandbox-external",
                        Directive = "iframe",
                        Result = "bypassed",
                        Severity = Severity.Medium,
                        Detail = $"Cross-origin iframe without sandbox: {ShortUrl(src)}. Third-party content has full script access."
                    });
                }
            }
        }
        catch (Exception ex)
        {
            def.Verdict = "error";
            def.Tests.Add(new FirewallTestResult { Technique = "sandbox-test-error", Directive = "", Result = "error", Detail = ex.Message });
        }

        return def;
    }

    #endregion

    #region Permissions Policy Testing

    private async Task<DefenseResult> TestPermissionsPolicy()
    {
        var def = new DefenseResult();

        try
        {
            var headersResult = await _context.CheckSecurityHeaders();
            var ppHeader = headersResult.RawHeaders
                .FirstOrDefault(h => h.Key.Equals("Permissions-Policy", StringComparison.OrdinalIgnoreCase)
                                  || h.Key.Equals("Feature-Policy", StringComparison.OrdinalIgnoreCase));

            if (string.IsNullOrEmpty(ppHeader.Value))
            {
                def.Present = false;
                return def;
            }

            def.Present = true;
            def.Policy = ppHeader.Value;

            // Test each restrictable API
            var apiTests = new (string feature, string jsTest, string description)[]
            {
                ("camera", "navigator.mediaDevices.getUserMedia({video:true}).then(()=>'allowed').catch(e=>e.name)",
                    "Camera access"),
                ("microphone", "navigator.mediaDevices.getUserMedia({audio:true}).then(()=>'allowed').catch(e=>e.name)",
                    "Microphone access"),
                ("geolocation", "new Promise((r,j)=>navigator.geolocation.getCurrentPosition(()=>r('allowed'),e=>r(e.code===1?'denied-by-user':'blocked')))",
                    "Geolocation access"),
                ("payment", "try{new PaymentRequest([{supportedMethods:'basic-card'}],{total:{label:'t',amount:{currency:'USD',value:'0'}}});'allowed'}catch(e){e.name}",
                    "Payment API"),
            };

            foreach (var (feature, jsTest, description) in apiTests)
            {
                if (!ppHeader.Value.Contains(feature, StringComparison.OrdinalIgnoreCase)) continue;

                try
                {
                    var result = await _context.ExecuteJs($"(async()=>{{ try {{ return await ({jsTest}); }} catch(e) {{ return e.name; }} }})()");

                    var isBlocked = result.Contains("NotAllowedError") || result.Contains("SecurityError")
                                 || result.Contains("blocked");

                    if (isBlocked)
                    {
                        def.Tests.Add(new FirewallTestResult
                        {
                            Technique = $"permissions-{feature}",
                            Directive = feature,
                            Result = "blocked",
                            Detail = $"{description} correctly blocked by Permissions-Policy."
                        });
                    }
                    else if (result.Contains("allowed"))
                    {
                        def.Findings.Add(new FirewallTestResult
                        {
                            Technique = $"permissions-{feature}",
                            Directive = feature,
                            Result = "bypassed",
                            Severity = Severity.Low,
                            Detail = $"{description} was not blocked despite Permissions-Policy mentioning '{feature}'."
                        });
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            def.Verdict = "error";
            def.Tests.Add(new FirewallTestResult { Technique = "permissions-policy-error", Directive = "", Result = "error", Detail = ex.Message });
        }

        return def;
    }

    #endregion

    #region Helpers

    private async Task CleanupTestElements()
    {
        try
        {
            await _context.ExecuteJs(
                "document.querySelectorAll('[data-trowser-test]').forEach(e=>e.remove())");
        }
        catch { }
    }

    private static string ShortUrl(string url)
    {
        if (url.Length <= 80) return url;
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return $"{uri.Host}{(uri.AbsolutePath.Length > 40 ? uri.AbsolutePath[..40] + "..." : uri.AbsolutePath)}";
        return url[..77] + "...";
    }

    #endregion
}
