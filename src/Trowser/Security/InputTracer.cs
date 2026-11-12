using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Web;
using Trowser.Automation;
using Trowser.Security.Runtime;

namespace Trowser.Security;

/// <summary>
/// Result from tracing a single payload through the input→network→DOM pipeline.
/// </summary>
public class InputTraceResult
{
    public string Payload { get; init; } = "";
    /// <summary>Page URL (location.href) when the trace finished.</summary>
    public string DocumentUrl { get; init; } = "";
    public long ElapsedMs { get; init; }

    public InjectionTrace Injection { get; init; } = new();
    public NetworkTrace? Network { get; init; }
    public ServerResponseTrace? ServerResponse { get; init; }
    public DomTrace? Dom { get; init; }
    public CspTrace? Csp { get; init; }
    public SinkTrace? Sinks { get; init; }
    public List<ResponseBodySecurityHeuristics.SqlSignatureHit>? SqliIndicators { get; init; }
    /// <summary>Phase-1 reach map (canary in sink argument) when twoPhase tracing is enabled.</summary>
    public List<ReachMapEntry>? ReachMap { get; init; }
    /// <summary>Vectors tried after reach phase (two-phase / confirmation).</summary>
    public List<InputTraceBypassAttempt> ConfirmationAttempts { get; init; } = [];
    public TraceVerdict Verdict { get; init; } = new();

    public sealed class ReachMapEntry
    {
        public string Sink { get; init; } = "";
        public bool ContainsReachCanary { get; init; }
        public string? Snippet { get; init; }
        public string? PageStack { get; init; }
        public string? Consequence { get; init; }
        /// <summary>Known benign pattern (e.g. nav-active-link) — not exploit evidence.</summary>
        public string? KnownBenign { get; init; }
    }

    public class InjectionTrace
    {
        /// <summary>form | url-query | url-hash | url-path</summary>
        public string SourceType { get; init; } = "form";
        public bool InputAccepted { get; init; }
        public string? DomValueBeforeSubmit { get; init; }
        /// <summary>none | encoded | filtered | constrained</summary>
        public string Treatment { get; init; } = "none";
        public string? ConstraintType { get; init; }
        public string Encoding { get; init; } = "none";
        public string? NavigatedUrl { get; init; }
        public string? Notes { get; init; }
        /// <summary>True when the form target selector matched no interactable control.</summary>
        public bool FormInteractionFailed { get; init; }
        /// <summary>e.g. selector matched 0 elements</summary>
        public string? FormInteractionFailureReason { get; init; }
        public int TargetElementsMatched { get; init; }
    }

    public class NetworkTrace
    {
        public bool RequestFound { get; init; }
        public string? Method { get; init; }
        public string? Url { get; init; }
        public string? PayloadLocation { get; init; }
        public string? PayloadInRequest { get; init; }
        public string? ContentType { get; init; }
        public string? ParameterName { get; init; }
    }

    public class ServerResponseTrace
    {
        public int Status { get; init; }
        public string? ContentType { get; init; }
        public bool PayloadReflected { get; init; }
        public int ReflectionCount { get; init; }
        public List<ReflectionInfo> Reflections { get; init; } = [];
        public bool OpenRedirect { get; init; }
        public string? RedirectLocation { get; init; }
        public string? RedirectHost { get; init; }
    }

    public class ReflectionInfo
    {
        public string Context { get; init; } = "";
        public bool Encoded { get; init; }
        public string? Surrounding { get; init; }
        public bool Dangerous { get; init; }
        public string? Reason { get; init; }
    }

    public class DomTrace
    {
        public bool PayloadRendered { get; init; }
        public int RenderedCount { get; init; }
        public string? Context { get; init; }
        public bool Dangerous { get; init; }
        public string? Reason { get; init; }
    }

    public class CspTrace
    {
        public bool Present { get; init; }
        public string? RelevantDirective { get; init; }
        public bool WouldBlock { get; init; }
        public string? Reason { get; init; }
    }

    public class SinkTrace
    {
        public bool Monitored { get; init; }
        public int HitCount { get; init; }
        public List<SinkHit> Hits { get; init; } = [];
        public bool PayloadReachedSink { get; init; }
        public string? MostDangerousSink { get; init; }
        /// <summary>Sinks the sensor instruments (always listed when monitoring is on).</summary>
        public List<string> Instrumented { get; init; } = [];
        /// <summary>Sink names observed during this trace (even if payload did not match).</summary>
        public List<string> SinksSeen { get; init; } = [];
        /// <summary>Source reads observed during this trace.</summary>
        public List<string> SourcesSeen { get; init; } = [];
        public string? ZeroResultReason { get; init; }
        /// <summary>__trowser_exec oracle fired for this probe canary.</summary>
        public bool ExecutionConfirmed { get; init; }
        /// <summary>alert/confirm/prompt observed while probing an alert-style payload.</summary>
        public bool DialogEffectConfirmed { get; init; }
    }

    public class SinkHit
    {
        public string Sink { get; init; } = "";
        public bool ContainsPayload { get; set; }
        public string? Snippet { get; set; }
        public string? Stack { get; init; }
        /// <summary>dom-open-redirect | client-request-forgery when canary reached a navigation/URL sink.</summary>
        public string? Classification { get; set; }
    }

    public class TraceVerdict
    {
        public Severity Severity { get; init; }
        public string Summary { get; init; } = "";
        public string? Recommendation { get; init; }
    }

    public string Format()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"--- Trace: {Payload} ({ElapsedMs}ms) ---");

        sb.AppendLine($"  Injection ({Injection.SourceType}):");
        if (Injection.NavigatedUrl != null)
            sb.AppendLine($"    Navigated URL: {Truncate(Injection.NavigatedUrl, 120)}");
        sb.AppendLine($"    Input accepted: {Injection.InputAccepted}");
        if (Injection.DomValueBeforeSubmit != null)
            sb.AppendLine($"    Value before submit: {Truncate(Injection.DomValueBeforeSubmit, 100)}");
        sb.AppendLine($"    Treatment: {Injection.Treatment}, Encoding: {Injection.Encoding}");
        if (Injection.ConstraintType != null) sb.AppendLine($"    Constraint: {Injection.ConstraintType}");
        if (Injection.Notes != null) sb.AppendLine($"    Notes: {Injection.Notes}");

        if (Network != null)
        {
            sb.AppendLine($"  Network:");
            sb.AppendLine($"    Request found: {Network.RequestFound}");
            if (Network.RequestFound)
            {
                sb.AppendLine($"    {Network.Method} {Network.Url}");
                sb.AppendLine($"    Payload location: {Network.PayloadLocation}, Content-Type: {Network.ContentType}");
                if (Network.PayloadInRequest != null) sb.AppendLine($"    Payload in request: {Truncate(Network.PayloadInRequest, 120)}");
            }
        }

        if (ServerResponse != null)
        {
            sb.AppendLine($"  Server response:");
            sb.AppendLine($"    Status: {ServerResponse.Status}, Content-Type: {ServerResponse.ContentType}");
            if (ServerResponse.OpenRedirect)
                sb.AppendLine($"    Open redirect: Location → {Truncate(ServerResponse.RedirectLocation ?? "", 120)}");
            sb.AppendLine($"    Payload reflected: {ServerResponse.PayloadReflected} ({ServerResponse.ReflectionCount} occurrence(s))");
            foreach (var r in ServerResponse.Reflections)
            {
                sb.AppendLine($"    - Context: {r.Context}, Encoded: {r.Encoded}, Dangerous: {r.Dangerous}");
                if (r.Surrounding != null) sb.AppendLine($"      Surrounding: {Truncate(r.Surrounding, 150)}");
                if (r.Reason != null) sb.AppendLine($"      Reason: {r.Reason}");
            }
        }

        if (Dom != null)
        {
            sb.AppendLine($"  DOM:");
            sb.AppendLine($"    Payload rendered: {Dom.PayloadRendered} ({Dom.RenderedCount} occurrence(s))");
            sb.AppendLine($"    Context: {Dom.Context}, Dangerous: {Dom.Dangerous}");
            if (Dom.Reason != null) sb.AppendLine($"    {Dom.Reason}");
        }

        if (Csp != null)
        {
            sb.AppendLine($"  CSP:");
            sb.AppendLine($"    Present: {Csp.Present}");
            if (Csp.RelevantDirective != null) sb.AppendLine($"    Directive: {Csp.RelevantDirective}");
            sb.AppendLine($"    Would block: {Csp.WouldBlock}");
            if (Csp.Reason != null) sb.AppendLine($"    {Csp.Reason}");
        }

        if (Sinks is { Monitored: true })
        {
            sb.AppendLine($"  Sink monitoring:");
            sb.AppendLine($"    Sinks hit: {Sinks.HitCount}");
            sb.AppendLine($"    Payload reached sink: {Sinks.PayloadReachedSink}");
            if (Sinks.ExecutionConfirmed)
                sb.AppendLine("    Execution confirmed: __trowser_exec oracle fired");
            if (Sinks.MostDangerousSink != null)
                sb.AppendLine($"    Most dangerous: {Sinks.MostDangerousSink}");
            var displayHits = Sinks.Hits
                .Where(h => h.ContainsPayload || !RuntimeInstrumentationFilter.IsToolArtifactSink(h.Sink, h.Stack, h.Snippet))
                .OrderByDescending(h => h.ContainsPayload)
                .Take(10);
            foreach (var hit in displayHits)
            {
                sb.AppendLine($"    - {hit.Sink}: payload={hit.ContainsPayload}");
                if (hit.Snippet != null) sb.AppendLine($"      Data: {Truncate(hit.Snippet, 120)}");
                if (hit.Stack != null) sb.AppendLine($"      Stack: {Truncate(hit.Stack, 150)}");
            }
        }

        if (SqliIndicators is { Count: > 0 })
        {
            sb.AppendLine($"  SQLi indicators (response body):");
            foreach (var h in SqliIndicators)
                sb.AppendLine($"    [{h.Engine}] {h.Pattern}: {Truncate(h.Snippet, 120)}");
        }

        sb.AppendLine($"  VERDICT [{Verdict.Severity}]: {Verdict.Summary}");
        if (Verdict.Recommendation != null) sb.AppendLine($"    Recommendation: {Verdict.Recommendation}");
        sb.AppendLine();
        return sb.ToString();
    }

    private static string? Truncate(string? s, int max) =>
        s == null ? null : s.Length <= max ? s : s[..max] + "...";
}

/// <summary>
/// Batch result from tracing multiple payloads.
/// </summary>
public class InputTraceBatchResult
{
    public int TotalPayloads { get; init; }
    public int Reflected { get; init; }
    public int RenderedInDom { get; init; }
    public int BlockedByCsp { get; init; }
    public int ServerErrors { get; init; }
    public int SqliIndicatorsDetected { get; init; }
    public int SinkHits { get; init; }
    public Severity WorstVerdict { get; init; }
    public long ElapsedMs { get; init; }
    public List<InputTraceResult> Traces { get; init; } = [];

    public string Format()
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== Input Trace Batch Result ===");
        sb.AppendLine($"Payloads: {TotalPayloads}, Reflected: {Reflected}, Rendered: {RenderedInDom}, " +
                      $"Blocked by CSP: {BlockedByCsp}, Server errors: {ServerErrors}, SQLi indicator traces: {SqliIndicatorsDetected}" +
                      (SinkHits > 0 ? $", Sink hits: {SinkHits}" : ""));
        sb.AppendLine($"Worst severity: {WorstVerdict}, Elapsed: {ElapsedMs}ms");
        sb.AppendLine();
        foreach (var t in Traces)
            sb.Append(t.Format());
        return sb.ToString();
    }
}

/// <summary>
/// Result from auto-bypass XSS tracing: primary probe plus automatic alternative vector attempts.
/// </summary>
public class InputTraceAutoBypassResult
{
    public string PrimaryPayload { get; init; } = "";
    public InputTraceResult PrimaryTrace { get; init; } = new();
    public List<InputTraceBypassAttempt> BypassAttempts { get; init; } = [];
    public List<InputTraceBypassAttempt> UrlProbeAttempts { get; init; } = [];
    public InputTraceResult? SuccessfulBypass { get; init; }
    public string? BypassSummary { get; init; }
    public bool BypassConfirmed => SuccessfulBypass != null;
    public long ElapsedMs { get; init; }
    public Severity WorstVerdict { get; init; }

    /// <summary>The trace that should drive remediation — successful bypass or primary.</summary>
    public InputTraceResult EffectiveTrace => SuccessfulBypass ?? PrimaryTrace;

    public string Format()
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== Input Trace (Auto-Bypass XSS) ===");
        sb.AppendLine($"Primary probe: {PrimaryPayload}");
        sb.AppendLine($"Primary outcome: {XssBypassProbes.DescribePrimaryOutcome(PrimaryTrace)} [{PrimaryTrace.Verdict.Severity}]");
        sb.AppendLine();

        if (BypassConfirmed)
        {
            sb.AppendLine($"BYPASS CONFIRMED: {BypassSummary}");
            sb.AppendLine();
            sb.AppendLine("--- Successful bypass trace ---");
            sb.Append(SuccessfulBypass!.Format());
        }
        else if (BypassAttempts.Count > 0 || UrlProbeAttempts.Count > 0)
        {
            if (BypassAttempts.Count > 0)
            {
                sb.AppendLine($"Form bypass exploration: {BypassAttempts.Count} alternative vector(s) tried — none confirmed XSS.");
                foreach (var attempt in BypassAttempts)
                    sb.AppendLine($"  [{attempt.Vector}] {Truncate(attempt.Payload, 80)} — [{attempt.Trace.Verdict.Severity}] {attempt.Trace.Verdict.Summary}");
                sb.AppendLine();
            }
            if (UrlProbeAttempts.Count > 0)
            {
                sb.AppendLine($"URL-source probes: {UrlProbeAttempts.Count} vector(s) tried.");
                foreach (var attempt in UrlProbeAttempts)
                    sb.AppendLine($"  [{attempt.Vector}] {Truncate(attempt.Payload, 80)} — [{attempt.Trace.Verdict.Severity}] {attempt.Trace.Verdict.Summary}");
                sb.AppendLine();
            }
            sb.AppendLine("--- Primary trace (detail) ---");
            sb.Append(PrimaryTrace.Format());
        }
        else if (XssBypassProbes.IsConfirmedXss(PrimaryTrace))
        {
            sb.AppendLine("Primary probe confirmed XSS — bypass exploration not needed.");
            sb.AppendLine();
            sb.Append(PrimaryTrace.Format());
        }
        else
        {
            sb.Append(PrimaryTrace.Format());
        }

        sb.AppendLine($"Overall worst severity: {WorstVerdict}, Elapsed: {ElapsedMs}ms");
        return sb.ToString();
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "...";
}

public class InputTraceBypassAttempt
{
    public string Vector { get; init; } = "";
    public string Payload { get; init; } = "";
    public InputTraceResult Trace { get; init; } = new();
    public bool ConfirmedXss { get; init; }
}

/// <summary>
/// Traces user input from form field through network request and server response into the DOM.
/// Identifies security-relevant transformations (or lack thereof) at each step.
/// </summary>
public class InputTracer
{
    private readonly AutomationContext _context;

    public InputTracer(AutomationContext context)
    {
        _context = context;
    }

    public async Task<InputTraceResult> TraceAsync(TraceInputOptions options, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var baselineUrl = await ProbeNavigationRestore.CaptureBaselineUrlAsync(_context);
        try
        {
        if (options.ProbeAllUrlParams && options.Source == TraceSourceType.UrlQuery)
            return await TraceAllQueryParamsAsync(options, ct);

        if (options.TwoPhase && options.MonitorSinks && !options.ReachPhaseOnly && !options.SkipExecCanary)
        {
            var reachCanary = "trwR_" + Guid.NewGuid().ToString("N")[..10];
            var reachOpts = PrepareTraceOptions(options with
            {
                Payload = reachCanary,
                SkipExecCanary = true,
                ExecCanary = null,
                TwoPhase = false
            });
            var reachTrace = await TraceCoreAsync(reachOpts, ct);
            var confirmExecution = TraceInputConfirmExecutionPolicy.EffectiveConfirmExecution(options, reachTrace);
            if (!confirmExecution)
            {
                var map = BuildReachMap(reachTrace, reachCanary);
                return CopyTrace(reachTrace, map.Count > 0 ? map : null,
                    AppendInjectionNotes(reachTrace.Injection,
                        "Two-phase reach complete; execution confirmation skipped (no confirmable sink reach). " +
                        "Set confirmExecution:true for forced oracle, or safetyMode:aggressive."));
            }

            var confirmPayload = TraceInputConfirmationPayload.Pick(reachTrace, reachCanary, options);
            var confirmOpts = PrepareTraceOptions(options with
            {
                Payload = confirmPayload,
                TwoPhase = false,
                SkipExecCanary = false,
                ConfirmExecution = true
            });
            var confirmTrace = await TraceCoreAsync(confirmOpts, ct);
            InputTraceResult? redirectTrace = null;
            if (TraceInputRedirectHelper.PayloadTargetsOffSiteNavigation(options.Payload)
                && !TraceInputReachCanary.IsReachCanary(options.Payload)
                && !string.Equals(options.Payload, confirmPayload, StringComparison.OrdinalIgnoreCase))
            {
                redirectTrace = await TraceCoreAsync(PrepareTraceOptions(options with
                {
                    Payload = options.Payload,
                    TwoPhase = false,
                    SkipExecCanary = !options.ConfirmExecution,
                    ConfirmExecution = options.ConfirmExecution
                }), ct);
            }

            InputTraceResult? literalFallback = null;
            if (redirectTrace == null
                && !Phase1ReachSucceeded(reachTrace)
                && !string.IsNullOrWhiteSpace(options.Payload)
                && !TraceInputReachCanary.IsReachCanary(options.Payload)
                && !string.Equals(options.Payload, confirmPayload, StringComparison.OrdinalIgnoreCase))
            {
                literalFallback = await TraceCoreAsync(PrepareTraceOptions(options with
                {
                    Payload = options.Payload,
                    TwoPhase = false,
                    SkipExecCanary = !options.ConfirmExecution,
                    ConfirmExecution = options.ConfirmExecution
                }), ct);
            }

            return MergeReachAndConfirm(reachTrace, confirmTrace, reachCanary, options.Payload,
                redirectTrace ?? literalFallback);
        }

        return await TraceCoreAsync(PrepareTraceOptions(options), ct);
        }
        finally
        {
            await ProbeNavigationRestore.TryRestoreAsync(_context, baselineUrl);
        }
    }

    private async Task<InputTraceResult> TraceCoreAsync(TraceInputOptions options, CancellationToken ct = default)
    {
        if (TraceInputOptions.IsUrlSource(options.Source))
            return await TraceUrlSourceAsync(options, ct);
        if (TraceInputOptions.IsClientRuntimeSource(options.Source))
            return await TraceClientRuntimeSourceAsync(options, ct);

        return await TraceFormAsync(options, ct);
    }

    /// <summary>
    /// Seed a client-side source (window.name, storage, postMessage, referrer) and watch sinks.
    /// </summary>
    public async Task<InputTraceResult> TraceClientRuntimeSourceAsync(TraceInputOptions options, CancellationToken ct = default)
    {
        options = PrepareTraceOptions(options);
        var sw = Stopwatch.StartNew();
        var payload = options.Payload;
        var sourceType = TraceInputOptions.SourceTypeName(options.Source);
        var monitorSinks = options.MonitorSinks;

        string? docScriptId = null;
        if (monitorSinks)
            docScriptId = await BeginNavigationSensorAsync();

        var networkBefore = _context.Network.Entries.Count;
        long runtimeMark = 0;
        string? notes;

        try
        {
            switch (options.Source)
            {
                case TraceSourceType.WindowName:
                    await _context.ExecuteJs(
                        $"(function(){{ window.name = {JsonEscape(payload)}; return 'ok'; }})()");
                    notes = "Set window.name then reloaded so page scripts re-read it.";
                    if (monitorSinks)
                        runtimeMark = await MarkSinkObservationAsync();
                    await _context.ExecuteJs("location.reload()");
                    break;

                case TraceSourceType.Storage:
                {
                    var kind = (options.StorageKind ?? "local").Equals("session", StringComparison.OrdinalIgnoreCase)
                        ? "sessionStorage" : "localStorage";
                    var key = options.StorageKey ?? "trowser_probe";
                    await _context.ExecuteJs(
                        $"(function(){{ {kind}.setItem({JsonEscape(key)}, {JsonEscape(payload)}); return 'ok'; }})()");
                    notes = $"Wrote {kind} key '{key}' then reloaded.";
                    if (monitorSinks)
                        runtimeMark = await MarkSinkObservationAsync();
                    await _context.ExecuteJs("location.reload()");
                    break;
                }

                case TraceSourceType.PostMessage:
                {
                    if (monitorSinks)
                    {
                        await RuntimeSensorInstaller.InstallOnCurrentDocumentAsync(_context);
                        runtimeMark = await MarkSinkObservationAsync();
                    }

                    var handlerSources = await GetPostMessageHandlerSourcesAsync();
                    var shaped = PostMessagePayloadInference.ShapeForDispatch(payload, handlerSources);
                    if (!string.Equals(shaped, payload, StringComparison.Ordinal))
                        notes = "Dispatched structured postMessage inferred from listener (JSON property keys).";
                    else
                        notes = "Dispatched synthetic MessageEvent (isTrusted=false) from https://evil.trowser.test.";

                    await DispatchPostMessageAsync(shaped);
                    break;
                }

                case TraceSourceType.Referrer:
                {
                    var target = options.BaseUrl ?? await _context.GetCurrentUrl();
                    var attackerUrl = "https://evil.trowser.test/referrer-seed";
                    var attackerHtml =
                        $"<!DOCTYPE html><html><body><a id='go' href=\"{System.Net.WebUtility.HtmlEncode(target)}\">go</a>" +
                        "<script>location=document.getElementById('go').href</script></body></html>";
                    _context.ActiveTab.MockResponse(attackerUrl, 200, attackerHtml,
                        headers: new Dictionary<string, string> { ["Content-Type"] = "text/html; charset=utf-8" });
                    notes = $"Navigated via mocked attacker page ({attackerUrl}) so document.referrer is set.";
                    if (monitorSinks)
                        runtimeMark = await MarkSinkObservationAsync();
                    await _context.Navigate(attackerUrl);
                    break;
                }

                default:
                    return MakeErrorResult(payload, sw, $"Unsupported client runtime source: {sourceType}", sourceType);
            }
        }
        catch (Exception ex)
        {
            sw.Stop();
            await EndNavigationSensorAsync(docScriptId);
            return MakeErrorResult(payload, sw, $"Client runtime seed failed: {ex.Message}", sourceType);
        }

        await WaitForTraceIdleAsync(options.TimeoutMs, ct);
        await EndNavigationSensorAsync(docScriptId);

        var injection = new InputTraceResult.InjectionTrace
        {
            SourceType = sourceType,
            InputAccepted = true,
            Treatment = "none",
            Encoding = "none",
            Notes = notes
        };

        return await FinishTraceAsync(sw, payload, injection, networkBefore, options.TimeoutMs,
            options.CheckCsp, options.DetectSqli, monitorSinks, sourceType, runtimeMark, options.ExecCanary);
    }

    public async Task<InputTraceResult> TraceFormAsync(TraceInputOptions options, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(options.TargetSelector))
            return MakeErrorResult(options.Payload, Stopwatch.StartNew(), "Missing target selector for form trace.");

        var sw = Stopwatch.StartNew();
        var targetSelector = options.TargetSelector;
        var payload = options.Payload;
        var submitSelector = options.SubmitSelector;
        var submitAction = options.SubmitAction;
        var timeoutMs = options.TimeoutMs;
        var checkCsp = options.CheckCsp;
        var detectSqli = options.DetectSqli;
        var monitorSinks = options.MonitorSinks;
        var sourceType = TraceInputOptions.SourceTypeName(TraceSourceType.Form);

        options = PrepareTraceOptions(options);
        payload = options.Payload;
        string? docScriptId = null;
        long runtimeMark = 0;
        if (monitorSinks)
            docScriptId = await BeginNavigationSensorAsync();

        var networkBefore = _context.Network.Entries.Count;

        var matchCountJson = await _context.ExecuteJs(
            $"(function(){{ return document.querySelectorAll({JsonEscape(targetSelector)}).length; }})()");
        var targetElementsMatched = int.TryParse(matchCountJson?.Trim('"'), out var mc) ? mc : 0;
        var formInteractionFailed = targetElementsMatched == 0;
        string? formFailureReason = formInteractionFailed
            ? $"selector matched 0 elements ({targetSelector})"
            : null;

        if (!formInteractionFailed)
        {
            try { await _context.Type(targetSelector, payload); }
            catch
            {
                sw.Stop();
                return MakeErrorResult(payload, sw, "Failed to type payload into target element.", sourceType);
            }
        }

        await Task.Delay(200);

        var domValueAfterType = formInteractionFailed
            ? ""
            : await _context.ExecuteJs(
                $"(function(){{ var el=document.querySelector({JsonEscape(targetSelector)}); return el ? el.value||el.textContent||'' : ''; }})()");

        var injection = AnalyzeFormInjection(payload, domValueAfterType, targetSelector,
            targetElementsMatched, formInteractionFailed, formFailureReason);

        if (submitAction != "none" && !formInteractionFailed)
        {
            if (monitorSinks)
                runtimeMark = await MarkSinkObservationAsync();

            if (submitSelector != null && submitAction == "click")
            {
                try { await _context.Click(submitSelector); }
                catch { /* continue */ }
            }
            else
            {
                try
                {
                    await _context.ExecuteJs(
                        $"document.querySelector({JsonEscape(targetSelector)})?.form?.submit() || document.querySelector({JsonEscape(targetSelector)})?.dispatchEvent(new KeyboardEvent('keydown',{{key:'Enter',keyCode:13,bubbles:true}}))");
                }
                catch { }
            }
        }

        await WaitForTraceIdleAsync(timeoutMs, ct);
        await EndNavigationSensorAsync(docScriptId);

        return await FinishTraceAsync(sw, payload, injection, networkBefore, timeoutMs, checkCsp, detectSqli, monitorSinks, sourceType, runtimeMark, options.ExecCanary);
    }

    public async Task<InputTraceResult> TraceUrlSourceAsync(TraceInputOptions options, CancellationToken ct = default)
    {
        options = PrepareTraceOptions(options);
        var sw = Stopwatch.StartNew();
        var payload = options.Payload;
        var sourceType = TraceInputOptions.SourceTypeName(options.Source);

        var baseUrl = options.BaseUrl;
        if (string.IsNullOrWhiteSpace(baseUrl))
            baseUrl = await _context.GetCurrentUrl();

        var hashParam = options.HashParam;
        var queryParam = options.QueryParam;
        string? discoveryNote = null;

        if (options.Source == TraceSourceType.UrlHash && string.IsNullOrEmpty(hashParam))
        {
            await EnsureBasePageForDiscoveryAsync(baseUrl!);
            var discovered = await DomUrlParamDiscovery.DiscoverAsync(_context);
            if (discovered?.PreferredHashParam != null)
            {
                hashParam = discovered.PreferredHashParam;
                discoveryNote = $"Auto-discovered hash parameter '{hashParam}' from inline script analysis" +
                                (discovered.SourceHint != null ? $" ({discovered.SourceHint})." : ".");
            }
        }

        var effectiveOptions = options with { HashParam = hashParam, QueryParam = queryParam };

        string navigatedUrl;
        try
        {
            navigatedUrl = BuildUrlForSource(baseUrl!, effectiveOptions, payload);
            if (options.Source == TraceSourceType.UrlHash)
                navigatedUrl = UrlPayloadInjector.EnsureFullNavigation(navigatedUrl);
        }
        catch (Exception ex)
        {
            sw.Stop();
            return MakeErrorResult(payload, sw, $"Failed to build injection URL: {ex.Message}", sourceType);
        }

        string? docScriptId = null;
        long runtimeMark = 0;
        if (options.MonitorSinks)
        {
            docScriptId = await RuntimeSensorInstaller.InstallDocumentCreatedAsync(_context);
            if (docScriptId == null)
                await RuntimeSensorInstaller.InstallOnCurrentDocumentAsync(_context);
            runtimeMark = _context.ActiveTab.RuntimeEvents.Mark();
        }

        var networkBefore = _context.Network.Entries.Count;

        try { await _context.Navigate(navigatedUrl); }
        catch (Exception ex)
        {
            sw.Stop();
            await RuntimeSensorInstaller.RemoveDocumentCreatedAsync(_context, docScriptId);
            return MakeErrorResult(payload, sw, $"Navigation failed: {ex.Message}", sourceType);
        }
        finally
        {
            await RuntimeSensorInstaller.RemoveDocumentCreatedAsync(_context, docScriptId);
        }

        await WaitForTraceIdleAsync(options.TimeoutMs, ct);
        if (options.FireEvents)
            await TryFireClickGatedSinksAsync();

        var encoding = options.Source switch
        {
            TraceSourceType.UrlQuery => effectiveOptions.QueryEncode.ToString().ToLowerInvariant(),
            TraceSourceType.UrlHash => effectiveOptions.FragmentEncode.ToString().ToLowerInvariant(),
            TraceSourceType.UrlPath => effectiveOptions.PathEncode.ToString().ToLowerInvariant(),
            _ => "none"
        };

        var notes = $"Payload delivered via URL {sourceType.Replace("url-", "")} — no form interaction.";
        if (options.Source == TraceSourceType.UrlHash)
            notes += " Full document reload forced (hash-only navigation does not re-run inline scripts).";
        if (discoveryNote != null)
            notes += " " + discoveryNote;
        if (options.Source == TraceSourceType.UrlQuery && effectiveOptions.QueryEncode == UrlPayloadEncodeMode.None)
            notes += " queryEncode=none (default for DOM XSS — use component/form for server-side reflection).";

        var injection = new InputTraceResult.InjectionTrace
        {
            SourceType = sourceType,
            InputAccepted = true,
            Treatment = "none",
            Encoding = encoding,
            NavigatedUrl = navigatedUrl,
            Notes = notes
        };

        return await FinishTraceAsync(sw, payload, injection, networkBefore, options.TimeoutMs,
            options.CheckCsp, options.DetectSqli, options.MonitorSinks, sourceType, runtimeMark, options.ExecCanary);
    }

    private async Task<InputTraceResult> FinishTraceAsync(
        Stopwatch sw,
        string payload,
        InputTraceResult.InjectionTrace injection,
        int networkBefore,
        int timeoutMs,
        bool checkCsp,
        bool detectSqli,
        bool monitorSinks,
        string sourceType,
        long runtimeMark = 0,
        string? execCanary = null)
    {
        var allEntries = _context.Network.Entries;
        var newEntries = allEntries.Skip(networkBefore).ToList();
        var networkTrace = AnalyzeNetworkRequest(newEntries, payload);
        var responseTrace = AnalyzeServerResponse(newEntries, payload);
        var sqliIndicators = detectSqli ? CollectSqliIndicators(newEntries) : null;
        var domTrace = await AnalyzeDom(payload);
        InputTraceResult.CspTrace? cspTrace = null;
        if (checkCsp)
            cspTrace = await AnalyzeCsp(payload);
        InputTraceResult.SinkTrace? sinkTrace = null;
        if (monitorSinks)
            sinkTrace = await CollectSinkData(payload, runtimeMark, execCanary);

        domTrace = ReconcileDomWithServer(domTrace, responseTrace, sinkTrace, sourceType);
        domTrace = ReconcileDomFromSinkHits(domTrace, sinkTrace, payload);
        if (responseTrace?.Status >= 500 && TargetAppearsUnavailable(newEntries))
            injection = AppendInjectionNotes(injection,
                "Target returned 5xx on multiple requests — likely site outage, not payload-induced.");

        sw.Stop();
        string documentUrl;
        try { documentUrl = await _context.GetCurrentUrl() ?? ""; }
        catch { documentUrl = injection.NavigatedUrl ?? ""; }

        var verdict = CompileVerdict(payload, injection, networkTrace, responseTrace, domTrace, cspTrace, sqliIndicators, sinkTrace, documentUrl);

        return new InputTraceResult
        {
            Payload = payload,
            DocumentUrl = documentUrl,
            ElapsedMs = sw.ElapsedMilliseconds,
            Injection = injection,
            Network = networkTrace,
            ServerResponse = responseTrace,
            Dom = domTrace,
            Csp = cspTrace,
            Sinks = sinkTrace,
            SqliIndicators = sqliIndicators,
            Verdict = verdict
        };
    }

    public async Task<InputTraceBatchResult> TraceBatchAsync(
        List<string> payloads, TraceInputOptions template)
    {
        var sw = Stopwatch.StartNew();
        var traces = new List<InputTraceResult>();
        var pageUrl = await _context.GetCurrentUrl();

        foreach (var payload in payloads)
        {
            var opts = template with { Payload = payload, AutoBypass = false };
            var trace = await TraceAsync(opts);
            traces.Add(trace);

            var currentUrl = await _context.GetCurrentUrl();
            if (currentUrl != pageUrl)
            {
                await _context.Navigate(pageUrl);
                await Task.Delay(500);
            }
        }

        sw.Stop();

        return new InputTraceBatchResult
        {
            TotalPayloads = payloads.Count,
            Reflected = traces.Count(t => t.ServerResponse?.PayloadReflected == true),
            RenderedInDom = traces.Count(t => t.Dom?.PayloadRendered == true),
            BlockedByCsp = traces.Count(t => t.Csp?.WouldBlock == true),
            ServerErrors = traces.Count(t => t.ServerResponse?.Status >= 500),
            SqliIndicatorsDetected = traces.Count(t => t.SqliIndicators is { Count: > 0 }),
            SinkHits = traces.Sum(t => t.Sinks?.HitCount ?? 0),
            WorstVerdict = traces.Count > 0 ? traces.Max(t => t.Verdict.Severity) : Severity.Low,
            ElapsedMs = sw.ElapsedMilliseconds,
            Traces = traces
        };
    }

    public async Task<InputTraceAutoBypassResult> TraceWithAutoBypassAsync(TraceInputOptions options)
    {
        var sw = Stopwatch.StartNew();
        var wallBudgetMs = Math.Clamp(options.TimeoutMs * 2L + options.MaxBypassAttempts * 3_000L, 12_000, 90_000);
        var pageUrl = await _context.GetCurrentUrl();
        try
        {
        var primary = string.IsNullOrWhiteSpace(options.Payload)
            ? XssBypassProbes.DefaultPrimaryPayload
            : options.Payload;

        if (TraceInputOptions.IsClientRuntimeSource(options.Source))
        {
            var runtimeOpts = PrepareTraceOptions(options with { Payload = primary, AutoBypass = false, TwoPhase = false });
            var runtimeTrace = await TraceClientRuntimeSourceAsync(runtimeOpts);
            sw.Stop();
            return new InputTraceAutoBypassResult
            {
                PrimaryPayload = primary,
                PrimaryTrace = runtimeTrace,
                ElapsedMs = sw.ElapsedMilliseconds,
                WorstVerdict = runtimeTrace.Verdict.Severity
            };
        }

        if (TraceInputOptions.IsUrlSource(options.Source))
        {
            var urlOpts = PrepareTraceOptions(options with { Payload = primary, AutoBypass = false });
            var urlPrimary = await TraceAsync(urlOpts);
            var urlBypassAttempts = new List<InputTraceBypassAttempt>();
            InputTraceResult? urlSuccess = null;
            var includeJs = UrlTraceNeedsJsBypass(urlPrimary);

            if (!XssBypassProbes.IsConfirmedXss(urlPrimary))
            {
                foreach (var probe in XssBypassProbes.GetBypassCandidatesForUrlDom(primary, options.MaxBypassAttempts, includeJs))
                {
                    if (sw.ElapsedMilliseconds >= wallBudgetMs) break;
                    await ResetToFormPageAsync(pageUrl, forceReload: true);
                    var trace = await TraceAsync(PrepareTraceOptions(urlOpts with
                    {
                        Payload = probe.Payload,
                        TimeoutMs = RemainingTraceTimeoutMs(sw, options.TimeoutMs, wallBudgetMs)
                    }));
                    if (trace.ServerResponse?.Status == 400)
                        continue;
                    var confirmed = XssBypassProbes.IsConfirmedXss(trace);
                    urlBypassAttempts.Add(new InputTraceBypassAttempt
                    {
                        Vector = probe.Vector,
                        Payload = probe.Payload,
                        Trace = trace,
                        ConfirmedXss = confirmed
                    });
                    if (confirmed)
                    {
                        urlSuccess = trace;
                        break;
                    }
                }
            }

            if (urlSuccess == null && TraceInputConfirmExecutionPolicy.TraceHasNavigationSinks(urlPrimary))
            {
                var redirectAttempts = Math.Min(options.MaxBypassAttempts, 8);
                foreach (var probe in TraceInputRedirectBypassProbes.GetProbes(redirectAttempts, sameOriginPrefix: "/"))
                {
                    if (sw.ElapsedMilliseconds >= wallBudgetMs) break;
                    await ResetToFormPageAsync(pageUrl, forceReload: true);
                    var trace = await TraceAsync(PrepareTraceOptions(urlOpts with
                    {
                        Payload = probe.Payload,
                        TimeoutMs = RemainingTraceTimeoutMs(sw, options.TimeoutMs, wallBudgetMs)
                    }));
                    if (trace.ServerResponse?.Status == 400)
                        continue;
                    var confirmed = XssBypassProbes.IsConfirmedXss(trace);
                    urlBypassAttempts.Add(new InputTraceBypassAttempt
                    {
                        Vector = probe.Vector,
                        Payload = probe.Payload,
                        Trace = trace,
                        ConfirmedXss = confirmed
                    });
                    if (confirmed)
                    {
                        urlSuccess = trace;
                        break;
                    }
                }
            }

            sw.Stop();
            var urlTraces = new List<InputTraceResult> { urlPrimary };
            urlTraces.AddRange(urlBypassAttempts.Select(a => a.Trace));
            var urlBest = PickBestExploitTrace(urlTraces) ?? urlSuccess;
            return new InputTraceAutoBypassResult
            {
                PrimaryPayload = primary,
                PrimaryTrace = urlPrimary,
                BypassAttempts = urlBypassAttempts,
                SuccessfulBypass = urlBest,
                BypassSummary = urlBest != null && urlBest != urlPrimary
                    ? XssBypassProbes.BuildBypassSummary(primary, urlBest)
                    : null,
                ElapsedMs = sw.ElapsedMilliseconds,
                WorstVerdict = urlTraces.Max(t => t.Verdict.Severity)
            };
        }

        var formOpts = PrepareTraceOptions(options with { Payload = primary, AutoBypass = false });
        var primaryTrace = await TraceAsync(formOpts with { TimeoutMs = RemainingTraceTimeoutMs(sw, options.TimeoutMs, wallBudgetMs) });

        var bypassAttempts = new List<InputTraceBypassAttempt>();
        var urlProbeAttempts = new List<InputTraceBypassAttempt>();
        InputTraceResult? successfulBypass = null;
        string? bypassSummary = null;

        if (!primaryTrace.Injection.FormInteractionFailed
            && !XssBypassProbes.IsConfirmedXss(primaryTrace)
            && XssBypassProbes.ShouldAttemptBypass(primaryTrace, primary))
        {
            foreach (var probe in XssBypassProbes.GetBypassCandidates(primary, options.MaxBypassAttempts))
            {
                if (sw.ElapsedMilliseconds >= wallBudgetMs) break;
                await ResetToFormPageAsync(pageUrl, forceReload: true);

                var trace = await TraceAsync(formOpts with
                {
                    Payload = probe.Payload,
                    TimeoutMs = RemainingTraceTimeoutMs(sw, options.TimeoutMs, wallBudgetMs)
                });
                if (trace.ServerResponse?.Status == 400)
                    continue;
                var confirmed = XssBypassProbes.IsConfirmedXss(trace);
                bypassAttempts.Add(new InputTraceBypassAttempt
                {
                    Vector = probe.Vector,
                    Payload = probe.Payload,
                    Trace = trace,
                    ConfirmedXss = confirmed
                });

                if (confirmed)
                {
                    successfulBypass = trace;
                    bypassSummary = XssBypassProbes.BuildBypassSummary(primary, trace);
                    break;
                }
            }
        }

        if (successfulBypass == null && options.ProbeUrlSources
            && (primaryTrace.Injection.FormInteractionFailed
                || FormInputWasLimited(primaryTrace)
                || !XssBypassProbes.IsConfirmedXss(primaryTrace)))
        {
            foreach (var urlProbe in await BuildUrlProbeOptionsAsync(pageUrl, primary, options))
            {
                if (sw.ElapsedMilliseconds >= wallBudgetMs) break;
                await ResetToFormPageAsync(pageUrl, forceReload: true);
                var trace = await TraceUrlSourceAsync(urlProbe with
                {
                    TimeoutMs = RemainingTraceTimeoutMs(sw, options.TimeoutMs, wallBudgetMs)
                });
                var confirmed = XssBypassProbes.IsConfirmedXss(trace);
                urlProbeAttempts.Add(new InputTraceBypassAttempt
                {
                    Vector = TraceInputOptions.SourceTypeName(urlProbe.Source),
                    Payload = primary,
                    Trace = trace,
                    ConfirmedXss = confirmed
                });
                if (confirmed)
                {
                    successfulBypass = trace;
                    bypassSummary = $"Form input was {primaryTrace.Injection.Treatment}; " +
                                    $"{TraceInputOptions.SourceTypeName(urlProbe.Source)} confirmed DOM XSS.";
                    break;
                }

                if (!TraceInputOptions.IsUrlSource(urlProbe.Source))
                    continue;

                var includeJs = UrlTraceNeedsJsBypass(trace);
                foreach (var probe in XssBypassProbes.GetBypassCandidatesForUrlDom(primary, options.MaxBypassAttempts, includeJs))
                {
                    if (sw.ElapsedMilliseconds >= wallBudgetMs) break;
                    await ResetToFormPageAsync(pageUrl, forceReload: true);
                    var bypassTrace = await TraceUrlSourceAsync(urlProbe with
                    {
                        Payload = probe.Payload,
                        TimeoutMs = RemainingTraceTimeoutMs(sw, options.TimeoutMs, wallBudgetMs)
                    });
                    if (bypassTrace.ServerResponse?.Status == 400)
                        continue;
                    confirmed = XssBypassProbes.IsConfirmedXss(bypassTrace);
                    urlProbeAttempts.Add(new InputTraceBypassAttempt
                    {
                        Vector = $"{TraceInputOptions.SourceTypeName(urlProbe.Source)}:{probe.Vector}",
                        Payload = probe.Payload,
                        Trace = bypassTrace,
                        ConfirmedXss = confirmed
                    });
                    if (confirmed)
                    {
                        successfulBypass = bypassTrace;
                        bypassSummary = $"Form input was {primaryTrace.Injection.Treatment}; " +
                                        $"{TraceInputOptions.SourceTypeName(urlProbe.Source)} bypass ({probe.Vector}) confirmed DOM XSS.";
                        break;
                    }
                }

                if (successfulBypass != null)
                    break;
            }
        }

        sw.Stop();

        var allTraces = new List<InputTraceResult> { primaryTrace };
        allTraces.AddRange(bypassAttempts.Select(a => a.Trace));
        allTraces.AddRange(urlProbeAttempts.Select(a => a.Trace));

        var bestTrace = PickBestExploitTrace(allTraces);
        if (bestTrace != null
            && (successfulBypass == null
                || bestTrace.Verdict.Severity > successfulBypass.Verdict.Severity
                || (bestTrace.Sinks?.ExecutionConfirmed == true && successfulBypass.Sinks?.ExecutionConfirmed != true)))
        {
            successfulBypass = bestTrace;
            if (string.IsNullOrEmpty(bypassSummary) && bestTrace != primaryTrace)
                bypassSummary = XssBypassProbes.BuildBypassSummary(primary, bestTrace);
        }

        return new InputTraceAutoBypassResult
        {
            PrimaryPayload = primary,
            PrimaryTrace = primaryTrace,
            BypassAttempts = bypassAttempts,
            UrlProbeAttempts = urlProbeAttempts,
            SuccessfulBypass = successfulBypass,
            BypassSummary = bypassSummary,
            ElapsedMs = sw.ElapsedMilliseconds,
            WorstVerdict = allTraces.Max(t => t.Verdict.Severity)
        };
        }
        finally
        {
            await RestorePageUrlAfterProbeAsync(pageUrl);
        }
    }

    private async Task RestorePageUrlAfterProbeAsync(string? baselineUrl)
    {
        if (string.IsNullOrWhiteSpace(baselineUrl)) return;
        try
        {
            var now = await _context.GetCurrentUrl();
            if (string.Equals(now, baselineUrl, StringComparison.OrdinalIgnoreCase))
                return;
            await _context.Navigate(baselineUrl);
            await Task.Delay(300);
        }
        catch
        {
            // Best-effort restore after URL injection probes.
        }
    }

    private async Task<List<TraceInputOptions>> BuildUrlProbeOptionsAsync(
        string pageUrl, string payload, TraceInputOptions template)
    {
        var list = new List<TraceInputOptions>();
        IReadOnlyList<string> queryParams = [];
        try
        {
            var discovery = await DomRuntimeInjectionDiscovery.DiscoverAsync(_context);
            queryParams = discovery.QueryParams;
        }
        catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }

        var keys = queryParams.Count > 0
            ? queryParams.Take(8).Distinct(StringComparer.OrdinalIgnoreCase)
            : new[] { template.QueryParam ?? "q" };

        foreach (var key in keys)
        {
            list.Add(template with
            {
                Source = TraceSourceType.UrlQuery,
                Payload = payload,
                BaseUrl = pageUrl,
                QueryParam = key,
                MonitorSinks = template.MonitorSinks,
                AutoBypass = false
            });
        }

        list.Add(template with
        {
            Source = TraceSourceType.UrlHash,
            Payload = payload,
            BaseUrl = pageUrl,
            HashParam = null,
            FragmentEncode = UrlPayloadEncodeMode.None,
            MonitorSinks = template.MonitorSinks,
            AutoBypass = false
        });
        list.Add(template with
        {
            Source = TraceSourceType.UrlHash,
            Payload = payload,
            BaseUrl = pageUrl,
            HashParam = template.HashParam ?? "q",
            FragmentEncode = UrlPayloadEncodeMode.None,
            MonitorSinks = template.MonitorSinks,
            AutoBypass = false
        });
        return list;
    }

    private static int RemainingTraceTimeoutMs(Stopwatch sw, int perTraceTimeoutMs, long wallBudgetMs)
    {
        var wallLeft = (int)Math.Max(2000, wallBudgetMs - sw.ElapsedMilliseconds);
        return Math.Min(perTraceTimeoutMs, wallLeft);
    }

    private static InputTraceResult? PickBestExploitTrace(IEnumerable<InputTraceResult> traces)
    {
        var list = traces.ToList();
        if (list.Count == 0) return null;
        var confirmed = list
            .Where(t => XssBypassProbes.IsConfirmedXss(t) || t.Sinks?.ExecutionConfirmed == true)
            .OrderByDescending(t => t.Verdict.Severity)
            .ThenByDescending(t => t.Sinks?.ExecutionConfirmed == true)
            .FirstOrDefault();
        if (confirmed != null)
            return confirmed;

        var sinkReach = list
            .Where(XssBypassProbes.IsSinkReachConfirmed)
            .MaxBy(t => t.Verdict.Severity);
        if (sinkReach != null)
            return sinkReach;

        return list.MaxBy(t => t.Verdict.Severity);
    }

    private static bool FormInputWasLimited(InputTraceResult trace) =>
        trace.Injection.SourceType == "form"
        && trace.Injection.Treatment is "filtered" or "constrained";

    private async Task EnsureBasePageForDiscoveryAsync(string baseUrl)
    {
        var clean = UrlPayloadInjector.StripFragment(baseUrl);
        var current = await _context.GetCurrentUrl();
        if (!string.Equals(
                UrlPayloadInjector.StripFragment(current),
                clean,
                StringComparison.OrdinalIgnoreCase))
        {
            await _context.Navigate(clean);
            await Task.Delay(300);
        }
    }

    private static string BuildUrlForSource(string baseUrl, TraceInputOptions options, string payload)
    {
        var spec = options.Source switch
        {
            TraceSourceType.UrlQuery => new UrlInjectionSpec
            {
                Part = UrlInjectionPart.Query,
                Param = options.QueryParam ?? "q",
                Encode = options.QueryEncode
            },
            TraceSourceType.UrlHash => new UrlInjectionSpec
            {
                Part = UrlInjectionPart.Hash,
                Param = options.HashParam,
                Encode = options.FragmentEncode
            },
            TraceSourceType.UrlPath => new UrlInjectionSpec
            {
                Part = UrlInjectionPart.Path,
                Encode = options.PathEncode
            },
            _ => throw new InvalidOperationException("Not a URL source type.")
        };
        var built = UrlPayloadInjector.Build(baseUrl, spec, payload);
        if (options.ExtraQuery is not { Count: > 0 })
            return built;
        if (!Uri.TryCreate(built, UriKind.Absolute, out var uri))
            return built;

        var qb = System.Web.HttpUtility.ParseQueryString(uri.Query);
        foreach (var (k, v) in options.ExtraQuery)
        {
            if (string.IsNullOrEmpty(k)) continue;
            qb[k] = v;
        }

        var ub = new UriBuilder(uri) { Query = qb.ToString() ?? "" };
        return ub.Uri.ToString();
    }

    private async Task ResetToFormPageAsync(string pageUrl, bool forceReload = false)
    {
        var currentUrl = await _context.GetCurrentUrl();
        if (forceReload || currentUrl != pageUrl)
        {
            await _context.Navigate(pageUrl);
            await Task.Delay(500);
        }
    }

    #region Analysis

    private static InputTraceResult.InjectionTrace AnalyzeFormInjection(
        string payload,
        string domValue,
        string targetSelector,
        int targetElementsMatched = 1,
        bool formInteractionFailed = false,
        string? formInteractionFailureReason = null)
    {
        var accepted = !formInteractionFailed && !string.IsNullOrEmpty(domValue);
        var treatment = "none";
        var encoding = "none";
        string? constraintType = null;
        string? notes = null;

        if (formInteractionFailed)
        {
            treatment = "filtered";
            notes = formInteractionFailureReason
                    ?? "Form target selector did not match any element — no typing or submit was performed.";
        }
        else if (accepted && domValue != payload)
        {
            if (domValue.Length < payload.Length)
            {
                treatment = "filtered";
                notes = "Form control shortened or stripped the payload before submit — this is input filtering, not security sanitization. URL-based DOM XSS may still be reachable.";
            }
            else if (HttpUtility.HtmlDecode(domValue) == payload)
            {
                encoding = "html-encoded";
                treatment = "encoded";
            }
            else if (HttpUtility.UrlDecode(domValue) == payload)
            {
                encoding = "url-encoded";
                treatment = "encoded";
            }
            else
            {
                treatment = "constrained";
                constraintType = InferConstraintType(targetSelector);
                notes = "Form control modified the payload (select/options, maxlength, pattern, etc.) — does not prove URL/hash vectors are safe.";
            }
        }
        else if (!accepted)
        {
            treatment = "filtered";
            notes = "Input was rejected or element value is empty after typing. Probe url-query and url-hash sources.";
        }
        else
        {
            notes = "Form accepted payload as-is. No client-side filtering detected on this control.";
        }

        return new InputTraceResult.InjectionTrace
        {
            SourceType = "form",
            InputAccepted = accepted,
            DomValueBeforeSubmit = domValue,
            Treatment = treatment,
            ConstraintType = constraintType,
            Encoding = encoding,
            Notes = notes,
            FormInteractionFailed = formInteractionFailed,
            FormInteractionFailureReason = formInteractionFailureReason,
            TargetElementsMatched = targetElementsMatched
        };
    }

    private static string? InferConstraintType(string targetSelector)
    {
        // Heuristic label only — detailed DOM inspection would require JS round-trip
        if (targetSelector.Contains("select", StringComparison.OrdinalIgnoreCase))
            return "select-options";
        return "unknown";
    }

    private static InputTraceResult.NetworkTrace? AnalyzeNetworkRequest(List<NetworkEntry> entries, string payload)
    {
        if (entries.Count == 0) return new InputTraceResult.NetworkTrace { RequestFound = false };

        var variants = BuildRequestMatchVariants(payload);

        foreach (var entry in entries.Where(e => e.Method is "POST" or "PUT" or "PATCH"))
        {
            if (entry.RequestBody != null)
            {
                foreach (var variant in variants)
                {
                    if (entry.RequestBody.Contains(variant, StringComparison.OrdinalIgnoreCase))
                    {
                        return new InputTraceResult.NetworkTrace
                        {
                            RequestFound = true,
                            Method = entry.Method,
                            Url = entry.Url,
                            PayloadLocation = "body",
                            PayloadInRequest = variant,
                            ContentType = entry.ContentType,
                            ParameterName = ExtractParamName(entry.RequestBody, variant)
                        };
                    }
                }
            }
        }

        // Check GET requests with payload in URL
        foreach (var entry in entries)
        {
            foreach (var variant in variants)
            {
                if (entry.Url.Contains(variant, StringComparison.OrdinalIgnoreCase))
                {
                    return new InputTraceResult.NetworkTrace
                    {
                        RequestFound = true,
                        Method = entry.Method,
                        Url = entry.Url,
                        PayloadLocation = "url",
                        PayloadInRequest = variant,
                        ContentType = entry.ContentType
                    };
                }
            }
        }

        return new InputTraceResult.NetworkTrace { RequestFound = false };
    }

    private static HashSet<string> BuildRequestMatchVariants(string payload)
    {
        var variants = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var v in XssReflectionAnalyzer.GetPayloadReflectionVariants(payload))
            variants.Add(v);
        foreach (var m in XssReflectionAnalyzer.BuildPayloadMarkers(payload))
            variants.Add(m);

        var jsonEscaped = payload.Replace("\\", "\\\\").Replace("\"", "\\\"");
        if (jsonEscaped != payload)
            variants.Add(jsonEscaped);

        return variants;
    }

    private static InputTraceResult.ServerResponseTrace? AnalyzeServerResponse(List<NetworkEntry> entries, string payload)
    {
        InputTraceResult.ServerResponseTrace? best = null;
        var bestScore = int.MinValue;

        foreach (var entry in entries.Where(e => e.StatusCode > 0))
        {
            var location = RedirectAnalysis.TryGetLocation(entry.ResponseHeaders);
            if (RedirectAnalysis.IsRedirectStatus(entry.StatusCode) && !string.IsNullOrEmpty(location) &&
                Uri.TryCreate(entry.Url, UriKind.Absolute, out var reqUri))
            {
                var external = RedirectAnalysis.IsExternalRedirect(reqUri, location) ||
                               RedirectAnalysis.IsDangerousRedirectScheme(location);
                if (external)
                {
                    var resolved = RedirectAnalysis.ResolveLocation(location, reqUri);
                    return new InputTraceResult.ServerResponseTrace
                    {
                        Status = entry.StatusCode,
                        ContentType = entry.ContentType,
                        OpenRedirect = true,
                        RedirectLocation = location,
                        RedirectHost = resolved?.Host
                    };
                }
            }

            if (entry.ResponseBody == null)
            {
                if (entry.StatusCode >= 400 && best == null)
                {
                    best = new InputTraceResult.ServerResponseTrace
                    {
                        Status = entry.StatusCode,
                        ContentType = entry.ContentType,
                        PayloadReflected = false,
                        ReflectionCount = 0
                    };
                }
                continue;
            }

            var reflections = new List<InputTraceResult.ReflectionInfo>();
            foreach (var variant in XssReflectionAnalyzer.GetPayloadReflectionVariants(payload))
            {
                if (!entry.ResponseBody.Contains(variant, StringComparison.OrdinalIgnoreCase)) continue;

                var encoded = !variant.Equals(payload, StringComparison.Ordinal);
                var analysis = XssReflectionAnalyzer.AnalyzeReflection(
                    entry.ResponseBody, payload, variant, encoded, entry.ContentType);

                reflections.Add(new InputTraceResult.ReflectionInfo
                {
                    Context = analysis.Context,
                    Encoded = analysis.Encoded,
                    Surrounding = analysis.Surrounding,
                    Dangerous = analysis.Dangerous,
                    Reason = analysis.Reason
                });
            }

            if (reflections.Count == 0)
            {
                if (entry.StatusCode >= 400 && bestScore < 0)
                {
                    var errScore = ScoreResponseEntry(entry) - 10;
                    if (errScore > bestScore)
                    {
                        bestScore = errScore;
                        best = new InputTraceResult.ServerResponseTrace
                        {
                            Status = entry.StatusCode,
                            ContentType = entry.ContentType,
                            PayloadReflected = false,
                            ReflectionCount = 0
                        };
                    }
                }
                continue;
            }

            var score = ScoreResponseEntry(entry);
            if (score > bestScore)
            {
                bestScore = score;
                best = new InputTraceResult.ServerResponseTrace
                {
                    Status = entry.StatusCode,
                    ContentType = entry.ContentType,
                    PayloadReflected = true,
                    ReflectionCount = reflections.Count,
                    Reflections = reflections
                };
            }
        }

        if (best != null) return best;

        return entries.Count > 0
            ? new InputTraceResult.ServerResponseTrace { Status = entries[^1].StatusCode, ContentType = entries[^1].ContentType }
            : null;
    }

    private static int ScoreResponseEntry(NetworkEntry entry)
    {
        var score = 0;
        var ct = entry.ContentType ?? "";
        if (ct.Contains("html", StringComparison.OrdinalIgnoreCase)) score += 100;
        if (string.Equals(entry.Method, "GET", StringComparison.OrdinalIgnoreCase)) score += 10;
        if (ct.Contains("javascript", StringComparison.OrdinalIgnoreCase)) score -= 60;
        if (ct.Contains("json", StringComparison.OrdinalIgnoreCase)) score -= 20;
        if (entry.Url.StartsWith("data:", StringComparison.OrdinalIgnoreCase)) score -= 80;
        return score;
    }

    private async Task<InputTraceResult.DomTrace> AnalyzeDom(string payload)
    {
        try
        {
            var markersJson = JsonSerializer.Serialize(XssReflectionAnalyzer.BuildDomMarkers(payload));
            var payloadJson = JsonSerializer.Serialize(payload);
            var result = await _context.ExecuteJs(
                $@"(function(){{
                    var markers = {markersJson};
                    var payload = {payloadJson};
                    if (markers.length === 0) {{
                        return JSON.stringify({{ found: 0, contexts: [], dangerous: false, reason: '' }});
                    }}
                    var found = 0;
                    var contexts = [];
                    var dangerous = false;
                    var reason = '';

                    function matchesAny(text) {{
                        if (!text) return false;
                        if (payload.length >= 6 && text.indexOf(payload) >= 0) return true;
                        if (payload.indexOf('<') >= 0 && text.indexOf('<') < 0
                            && (text.indexOf('&lt;') >= 0 || text.indexOf('&#') >= 0))
                            return false;
                        for (var i = 0; i < markers.length; i++) {{
                            var m = markers[i];
                            if (text.indexOf(m) < 0) continue;
                            if ((m.indexOf('<') >= 0 || m.indexOf('>') >= 0) && text.indexOf('<') < 0)
                                continue;
                            return true;
                        }}
                        return false;
                    }}

                    function note(ctx, isDangerous, msg) {{
                        found++;
                        contexts.push(ctx);
                        if (isDangerous) {{ dangerous = true; reason = msg; }}
                    }}

                    var root = document.documentElement || document.body;
                    if (!root) {{
                        return JSON.stringify({{ found: 0, contexts: [], dangerous: false, reason: '' }});
                    }}

                    function eachElement(fn) {{
                        function walk(node) {{
                            if (!node) return;
                            if (node.nodeType === 1) fn(node);
                            var kids = node.children;
                            if (kids) for (var ci = 0; ci < kids.length; ci++) walk(kids[ci]);
                            if (node.shadowRoot) walk(node.shadowRoot);
                        }}
                        walk(root);
                    }}

                    // Search text nodes (exact or marker match) — include <head>
                    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
                    var node;
                    while (node = walker.nextNode()) {{
                        if (matchesAny(node.textContent)) {{
                            note('text-node', false, '');
                        }}
                    }}

                    // Dangerous elements created by XSS (survive parser even when raw payload string differs)
                    root.querySelectorAll('script:not([src])').forEach(function(el) {{
                        var text = el.textContent || '';
                        if (text.length > 300) return;
                        // Match textContent (script body) or outerHTML (full tag still in DOM)
                        if (matchesAny(text) || matchesAny(el.outerHTML || '')) {{
                            note('script-content', true, 'Payload markers found inside inline <script> element');
                        }}
                    }});
                    eachElement(function(el) {{
                        if (!el.getAttribute) return;
                        var onNames = ['onerror','onload','onfocus','ontoggle','onstart','onchange','onmouseover'];
                        for (var oi = 0; oi < onNames.length; oi++) {{
                            var oval = el.getAttribute(onNames[oi]);
                            if (oval && matchesAny(oval))
                                note('event-handler', true, 'Payload markers in event handler: ' + onNames[oi]);
                        }}
                        for (var k = 0; k < el.attributes.length; k++) {{
                            var attr = el.attributes[k];
                            if (!matchesAny(attr.value)) continue;
                            if (attr.name.indexOf('on') === 0) {{
                                note('event-handler', true, 'Payload markers in event handler: ' + attr.name);
                            }} else if (attr.name === 'href' || attr.name === 'src' || attr.name === 'action' || attr.name === 'formaction') {{
                                note('url-attribute', true, 'Payload markers in URL attribute: ' + attr.name);
                            }} else {{
                                note('attribute:' + attr.name, false, '');
                            }}
                        }}
                    }});

                    return JSON.stringify({{ found: found, contexts: [...new Set(contexts)], dangerous: dangerous, reason: reason }});
                }})()");

            var parsed = JsonSerializer.Deserialize<JsonElement>(result);
            var foundCount = parsed.GetProperty("found").GetInt32();
            var contexts = parsed.GetProperty("contexts").EnumerateArray().Select(c => c.GetString()).ToList();
            var isDangerous = parsed.GetProperty("dangerous").GetBoolean();
            var domReason = parsed.GetProperty("reason").GetString();

            return new InputTraceResult.DomTrace
            {
                PayloadRendered = foundCount > 0,
                RenderedCount = foundCount,
                Context = contexts.Count > 0 ? string.Join(", ", contexts) : "not found",
                Dangerous = isDangerous,
                Reason = isDangerous ? domReason : (foundCount > 0 ? "Payload present in DOM but in safe context." : null)
            };
        }
        catch
        {
            return new InputTraceResult.DomTrace { PayloadRendered = false, RenderedCount = 0, Context = "error" };
        }
    }

    private async Task<InputTraceResult.CspTrace> AnalyzeCsp(string payload)
    {
        try
        {
            var headers = await _context.CheckSecurityHeaders();
            var csp = headers.RawHeaders
                .FirstOrDefault(h => h.Key.Equals("Content-Security-Policy", StringComparison.OrdinalIgnoreCase));

            if (string.IsNullOrEmpty(csp.Value))
                return new InputTraceResult.CspTrace { Present = false, WouldBlock = false, Reason = "No CSP header — no script restrictions." };

            var hasScriptSrc = csp.Value.Contains("script-src", StringComparison.OrdinalIgnoreCase);
            var hasDefaultSrc = csp.Value.Contains("default-src", StringComparison.OrdinalIgnoreCase);

            var isScriptPayload = payload.Contains("<script", StringComparison.OrdinalIgnoreCase)
                               || Regex.IsMatch(payload, @"on\w+\s*=", RegexOptions.IgnoreCase);

            string? relevantDirective = null;
            bool wouldBlock = false;
            string? reason = null;

            if (isScriptPayload)
            {
                relevantDirective = hasScriptSrc
                    ? Regex.Match(csp.Value, @"(?i)script-src\s+([^;]+)").Groups[1].Value.Trim()
                    : hasDefaultSrc
                        ? Regex.Match(csp.Value, @"(?i)default-src\s+([^;]+)").Groups[1].Value.Trim()
                        : null;

                if (relevantDirective != null
                    && Regex.IsMatch(relevantDirective, @"(?i)(?:^|\s)'none'(?:\s|$)"))
                {
                    wouldBlock = true;
                    reason = "CSP script-src/default-src is 'none' — inline scripts and event handlers are blocked.";
                }
                else if (relevantDirective != null
                         && Regex.IsMatch(relevantDirective, @"(?i)'unsafe-inline'"))
                {
                    wouldBlock = false;
                    reason = "CSP allows 'unsafe-inline' — inline scripts and event handlers will execute.";
                }
                else if (relevantDirective != null)
                {
                    wouldBlock = true;
                    reason = "Inline script/handler blocked by script-src without 'unsafe-inline'.";
                }
            }

            return new InputTraceResult.CspTrace
            {
                Present = true,
                RelevantDirective = relevantDirective,
                WouldBlock = wouldBlock,
                Reason = reason ?? "CSP present but payload is not a script type."
            };
        }
        catch
        {
            return new InputTraceResult.CspTrace { Present = false, Reason = "Could not analyze CSP." };
        }
    }

    private static List<ResponseBodySecurityHeuristics.SqlSignatureHit>? CollectSqliIndicators(List<NetworkEntry> entries)
    {
        var hits = new List<ResponseBodySecurityHeuristics.SqlSignatureHit>();
        foreach (var entry in entries.Where(e => e.ResponseBody != null && e.StatusCode > 0))
        {
            hits.AddRange(ResponseBodySecurityHeuristics.DetectSqlErrorSignatures(entry.ResponseBody));
        }
        return hits.Count == 0 ? null : hits;
    }

    private static InputTraceResult.TraceVerdict CompileVerdict(
        string payload,
        InputTraceResult.InjectionTrace injection,
        InputTraceResult.NetworkTrace? network,
        InputTraceResult.ServerResponseTrace? response,
        InputTraceResult.DomTrace? dom,
        InputTraceResult.CspTrace? csp,
        List<ResponseBodySecurityHeuristics.SqlSignatureHit>? sqliIndicators,
        InputTraceResult.SinkTrace? sinks = null,
        string? documentUrl = null)
    {
        documentUrl = string.IsNullOrWhiteSpace(documentUrl)
            ? injection.NavigatedUrl ?? network?.Url
            : documentUrl;

        if (IsBrowserErrorPage(documentUrl))
        {
            return new InputTraceResult.TraceVerdict
            {
                Severity = Severity.Info,
                Summary = "Navigation landed on a browser error page — trace is inconclusive (target may be unreachable or DNS failed).",
                Recommendation = "Confirm the URL loads in a normal session, then re-run trace-input with monitorSinks."
            };
        }

        if (TraceInputRedirectHelper.DocumentMatchesRedirectPayload(documentUrl, payload)
            && sinks is not { ExecutionConfirmed: true, DialogEffectConfirmed: true })
        {
            return new InputTraceResult.TraceVerdict
            {
                Severity = Severity.High,
                Summary = "Document navigated off-site from injected input (client-side open redirect).",
                Recommendation = "Validate redirect targets; avoid assigning location.href/window.location from URL parameters without an allowlist.",
            };
        }

        if (sinks is { ExecutionConfirmed: true } && csp?.WouldBlock != true)
        {
            return new InputTraceResult.TraceVerdict
            {
                Severity = Severity.Critical,
                Summary = "Execution oracle confirmed: payload reached a sink and __trowser_exec canary fired (confirmed XSS/DOM effect).",
                Recommendation = "Fix the source→sink path; sanitize or encode before DOM APIs. Re-verify with browser_security_verify if needed."
            };
        }

        if (sinks is { DialogEffectConfirmed: true } && csp?.WouldBlock != true)
        {
            return new InputTraceResult.TraceVerdict
            {
                Severity = Severity.Critical,
                Summary = "Dialog oracle confirmed: native alert/confirm observed for this probe (confirmed script effect).",
                Recommendation = "Fix the source→sink path; sanitize or encode before DOM APIs."
            };
        }

                if (sinks is { HitCount: > 0 }
            && XssReflectionAnalyzer.SinkHitsAreDocumentUrlEchoOnly(payload, documentUrl, sinks.Hits))
        {
            return new InputTraceResult.TraceVerdict
            {
                Severity = Severity.Info,
                Summary = "Payload appears only because it is in the document URL (location.href echo) — " +
                          "not confirmed source→sink taint for this probe.",
                Recommendation = "Do not classify fetch/location hits of the current page URL as client-side request forgery. " +
                                 "Re-run trace-input with a distinct canary and monitorSinks after clearing prior state."
            };
        }

        if (TraceInputReachCanary.IsReachCanary(payload)
            && sinks is { PayloadReachedSink: true, ExecutionConfirmed: false })
        {
            var sinkName = sinks.MostDangerousSink
                           ?? sinks.Hits.FirstOrDefault(h => h.ContainsPayload)?.Sink
                           ?? "sink";
            return new InputTraceResult.TraceVerdict
            {
                Severity = Severity.Medium,
                Summary = $"Reach canary reached sink ({sinkName}) — source→sink path confirmed; confirmation phase tests exploitability.",
                Recommendation = "Review reachMap and phase-2 results. Do not treat reach-canary alone as confirmed XSS."
            };
        }

        // Sink monitoring: payload reaching a dangerous sink is critical unless neutralized / safe-context DOM contradicts.
        if (sinks is { PayloadReachedSink: true, ExecutionConfirmed: false } && csp?.WouldBlock != true)
        {
            if (XssReflectionAnalyzer.SinkHitsAreBenignSearchOrApiOnly(payload, sinks))
            {
                return new InputTraceResult.TraceVerdict
                {
                    Severity = Severity.Info,
                    Summary = "Typed input was passed into a search/API request (expected form behavior — not XSS).",
                    Recommendation = "Only escalate if the API or page reflects unsanitized HTML/JS from this parameter."
                };
            }

            if (XssReflectionAnalyzer.IsInertInnerHtmlScriptDomEvidence(payload, dom, sinks))
            {
                return new InputTraceResult.TraceVerdict
                {
                    Severity = Severity.High,
                    Summary = "Payload reached innerHTML as an inert <script> element — execution oracle did not fire.",
                    Recommendation = "Treat as unsanitized sink (HIGH). Confirm with an event-handler vector before CRITICAL."
                };
            }

            if (XssReflectionAnalyzer.SinkHitsLackExecutablePayloadContext(payload, sinks))
            {
                var sinkName = sinks.MostDangerousSink ?? sinks.Hits.FirstOrDefault(h => h.ContainsPayload)?.Sink ?? "sink";
                return new InputTraceResult.TraceVerdict
                {
                    Severity = Severity.Medium,
                    Summary = $"Payload text reached sink ({sinkName}) in a non-executable context (e.g. URL inside an attribute) — " +
                              "use attribute-breakout or event-handler confirmation payloads.",
                    Recommendation = "Enable twoPhase (default) or try payloads such as test\" onload=\"alert(1) when input is reflected into quoted attributes."
                };
            }

            var reachOnly = sinks.Hits.FirstOrDefault(h => h.ContainsPayload);
            if (reachOnly != null)
            {
                if (XssReflectionAnalyzer.SinkHitIsInertSelfReferentialPageUrl(
                        reachOnly.Sink, reachOnly.Snippet, documentUrl, payload))
                {
                    return new InputTraceResult.TraceVerdict
                    {
                        Severity = Severity.Info,
                        Summary = "Payload appears only because it is in the document URL (self-referential a.href/fetch echo) — " +
                                  "not confirmed source→sink taint for this probe.",
                        Recommendation = "Do not classify copy-link or fetch(current URL) patterns as DOM XSS. " +
                                         "Re-run with confirmExecution or a distinct canary if a real sink path is suspected."
                    };
                }

                var sev = SinkReachSeverity.ForSink(reachOnly.Sink, reachOnly.Snippet, false, payload);
                if (sev >= Severity.High)
                {
                    return new InputTraceResult.TraceVerdict
                    {
                        Severity = sev,
                        Summary = $"Reach confirmed: payload reached sink ({reachOnly.Sink}) without execution oracle — " +
                                  "source→sink path worth confirming (not execution-confirmed XSS; use browser_security_verify if needed).",
                        Recommendation = "Sanitize or encode before DOM/network APIs; avoid passing URL/storage/message data to HTML or script sinks."
                    };
                }
            }
        }

        if (sinks is { PayloadReachedSink: true } && csp?.WouldBlock != true)
        {
            if (XssReflectionAnalyzer.IsInertInnerHtmlScriptDomEvidence(payload, dom, sinks))
            {
                return new InputTraceResult.TraceVerdict
                {
                    Severity = Severity.High,
                    Summary = "Payload reached innerHTML as an inert <script> element — execution oracle did not fire.",
                    Recommendation = "Treat as unsanitized sink (HIGH). Confirm with an event-handler vector before CRITICAL."
                };
            }

            if (XssReflectionAnalyzer.IsSinkReachSafeDespiteDom(payload, sinks, dom))
            {
                return new InputTraceResult.TraceVerdict
                {
                    Severity = Severity.Low,
                    Summary = "Sink monitor reported payload reach, but DOM evidence is safe context " +
                              "(no executable markup in sink snippets / URL-encoded neutralization). " +
                              "Not confirmed XSS — do not treat as CRITICAL.",
                    Recommendation = "Source→sink path may exist; re-test with alternate encodings or confirm Dom.Dangerous=true before escalating."
                };
            }

            if (XssReflectionAnalyzer.IsSinkPayloadUrlEncodedNeutralized(sinks, dom))
            {
                return new InputTraceResult.TraceVerdict
                {
                    Severity = Severity.Low,
                    Summary = "Payload reached a dangerous sink but only in URL-encoded form (%3C/%3E) — " +
                              "browser encoding neutralized active HTML. DOM confirms safe rendering.",
                    Recommendation = "The source→sink code path exists but appears mitigated by URL encoding on this vector. " +
                                     "Re-test with trace-input queryEncode: none if the app applies decodeURI/decodeURIComponent before the sink."
                };
            }

            return new InputTraceResult.TraceVerdict
            {
                Severity = Severity.Critical,
                Summary = BuildDangerousSinkSummary(sinks, payload, csp?.WouldBlock != true),
                Recommendation = "Sanitize all user input before passing to DOM manipulation APIs. " +
                                 "Use textContent instead of innerHTML, avoid eval/Function/setTimeout with string arguments."
            };
        }

        if (sinks is { PayloadReachedSink: true } && csp?.WouldBlock == true)
        {
            if (XssReflectionAnalyzer.IsSinkPayloadUrlEncodedNeutralized(sinks, dom))
            {
                return new InputTraceResult.TraceVerdict
                {
                    Severity = Severity.Low,
                    Summary = "Payload reached a dangerous sink in URL-encoded form only — browser encoding neutralized active HTML. CSP also present.",
                    Recommendation = "Source→sink path exists but URL encoding prevented exploitation here. Fix sink usage regardless of CSP as defense-in-depth."
                };
            }

            return new InputTraceResult.TraceVerdict
            {
                Severity = Severity.High,
                Summary = $"Payload reached dangerous sink ({sinks.MostDangerousSink}) but CSP may block execution. " +
                          "The code path is still dangerous — CSP bypass or policy changes could enable exploitation.",
                Recommendation = "Fix the sink usage regardless of CSP. CSP is defense-in-depth, not primary mitigation."
            };
        }

        // Determine severity based on the combination of findings.
        // Require same-probe causality: sink hit, reflection, or (URL source + successful doc + causal DOM).
        // Never escalate to critical on residual DOM when payloadReachedSink=false and no reflection
        // (see SecurityTestingWithTrowser.md severity policy).
        var urlSource = TraceInputOptions.IsUrlSource(injection.SourceType);
        var sinkHit = sinks?.PayloadReachedSink == true;
        var reflected = response?.PayloadReflected == true;
        var causalDom = dom?.Dangerous == true
                        && (sinkHit || reflected
                            || (urlSource
                                && response is { Status: > 0 and < 400 }
                                && XssReflectionAnalyzer.DomEvidenceIsPayloadCausal(payload, dom)));

        if (causalDom && csp?.WouldBlock != true)
        {
            if (XssReflectionAnalyzer.IsInertInnerHtmlScriptDomEvidence(payload, dom, sinks))
            {
                return new InputTraceResult.TraceVerdict
                {
                    Severity = Severity.High,
                    Summary = "Unsanitized DOM sink likely (payload reached the page as an inert <script> element). " +
                              "Browsers do not execute <script> injected via innerHTML — execution oracle did not fire.",
                    Recommendation = "The source→innerHTML path is still dangerous. Re-test with an event-handler vector " +
                                     "(e.g. <img src=x onerror=…>) or enable twoPhase/monitorSinks before treating as proven XSS."
                };
            }

            if (sinks is not { ExecutionConfirmed: true })
            {
                return new InputTraceResult.TraceVerdict
                {
                    Severity = Severity.High,
                    Summary = urlSource && !reflected
                        ? "URL-sourced payload rendered in the DOM with no CSP blocking, but execution was not confirmed."
                        : "Payload rendered as active markup in the DOM without execution oracle confirmation.",
                    Recommendation = "Use browser_security_verify or an event-handler confirmation payload before filing CRITICAL. " +
                                     "Fix unsanitized URL/DOM sinks regardless."
                };
            }

            return new InputTraceResult.TraceVerdict
            {
                Severity = Severity.Critical,
                Summary = urlSource && !reflected
                    ? "URL-sourced payload rendered as active content in DOM with no CSP blocking. Confirmed DOM XSS."
                    : "Payload rendered as active content in DOM and no CSP blocks execution. Confirmed XSS vulnerability.",
                Recommendation = urlSource && !reflected
                    ? "Sanitize URL-derived data (location.search/hash/href) before writing to the DOM. Avoid document.write/innerHTML with URL input."
                    : "Server must sanitize or encode user input. Add restrictive CSP as defense-in-depth."
            };
        }

        if (causalDom && csp?.WouldBlock == true)
        {
            return new InputTraceResult.TraceVerdict
            {
                Severity = Severity.Medium,
                Summary = "Payload rendered as active content but CSP blocks execution. XSS is mitigated by CSP, but server-side encoding is still missing.",
                Recommendation = "Server should encode output regardless of CSP. CSP is defense-in-depth, not primary mitigation."
            };
        }

        // Residual / ambient DOM markers without causality — informational only.
        // May still be Dangerous=true (pre-reconcile edge) or Dangerous=false with residual Reason.
        if (!sinkHit && !reflected
            && (dom?.Dangerous == true
                || (dom?.Reason?.Contains("residual", StringComparison.OrdinalIgnoreCase) == true)
                || (dom?.Reason?.Contains("ambient", StringComparison.OrdinalIgnoreCase) == true)))
        {
            return new InputTraceResult.TraceVerdict
            {
                Severity = Severity.Info,
                Summary = response is { Status: >= 400 }
                    ? $"DOM still shows XSS-like markers after HTTP {response.Status} with no reflection and payloadReachedSink=false — " +
                      "treat as residual/ambient content, not confirmed XSS."
                    : "DOM shows XSS-like markers without reflection or sink hit for this payload — inconclusive (possible residual content).",
                Recommendation = "Re-test on a clean session/page, require payloadReachedSink=true or PayloadReflected=true before filing CRITICAL."
            };
        }

        if (sqliIndicators is { Count: > 0 })
        {
            return new InputTraceResult.TraceVerdict
            {
                Severity = Severity.High,
                Summary = $"SQL error or DB-leakage patterns detected in HTTP response ({sqliIndicators.Count} signature match(es)). May indicate SQL injection or verbose errors.",
                Recommendation = "Review server logs and error handling; test parameterized queries and suppress detailed SQL errors in production."
            };
        }

        if (response is { OpenRedirect: true })
        {
            return new InputTraceResult.TraceVerdict
            {
                Severity = Severity.Medium,
                Summary = $"Open redirect detected: HTTP {response.Status} with Location to external host " +
                          $"({response.RedirectHost ?? response.RedirectLocation}). User-controlled input can redirect victims off-site (CWE-601).",
                Recommendation = "Validate redirect targets against an allowlist of same-origin paths. Reject absolute external URLs in redirect parameters."
            };
        }

        var serverDangerous = response?.PayloadReflected == true && response.Reflections.Any(r => r.Dangerous);
        if (serverDangerous && response != null && dom != null
            && XssReflectionAnalyzer.ShouldDowngradeServerDanger(payload, response.Reflections, dom))
        {
            serverDangerous = false;
        }

        if (serverDangerous)
        {
            return new InputTraceResult.TraceVerdict
            {
                Severity = dom?.PayloadRendered == true ? Severity.High : Severity.Medium,
                Summary = "Payload reflected unencoded in server response" +
                          (dom?.PayloadRendered == true ? " and present in DOM." : " but not rendered as active content in DOM."),
                Recommendation = "Server should HTML-encode user input in response body."
            };
        }

        if (response?.PayloadReflected == true)
        {
            var safeInDom = dom is { PayloadRendered: true, Dangerous: false };
            var textNodeOnly = dom?.Context?.Contains("text-node", StringComparison.OrdinalIgnoreCase) == true
                               && dom.Dangerous == false;
            var allEncoded = response.Reflections.Count > 0 && response.Reflections.All(r => r.Encoded);
            var anyUnencoded = response.Reflections.Any(r => !r.Encoded);
            string summary;
            if (safeInDom && textNodeOnly && XssReflectionAnalyzer.ContainsHtmlMarkup(payload))
                summary = "Payload reflected in server response as plain text — DOM confirms markup was not parsed as active HTML.";
            else if (safeInDom)
                summary = "Payload reflected in server response but DOM confirms safe rendering context.";
            else if (allEncoded)
                summary = "Payload reflected in server response but encoded. Server-side encoding appears effective.";
            else if (anyUnencoded)
                summary = "Payload reflected unencoded in server response, but no dangerous execution context was confirmed.";
            else
                summary = "Payload reflected in server response; encoding/context inconclusive.";

            return new InputTraceResult.TraceVerdict
            {
                Severity = Severity.Low,
                Summary = summary,
                Recommendation = safeInDom
                    ? "No immediate action required for this reflection context. Verify the payload cannot reach URL attributes or script contexts elsewhere."
                    : allEncoded
                        ? "Verify encoding is applied consistently across all output contexts."
                        : "Re-test with alternate XSS vectors / DOM effectCheck — unencoded reflection may still be exploitable in another context."
            };
        }

        if (response?.Status >= 500)
        {
            var outage = injection.Notes?.Contains("site outage", StringComparison.OrdinalIgnoreCase) == true
                         || injection.Notes?.Contains("5xx on multiple", StringComparison.OrdinalIgnoreCase) == true;
            return new InputTraceResult.TraceVerdict
            {
                Severity = outage ? Severity.Info : Severity.Medium,
                Summary = outage
                    ? $"Server returned {response.Status} — target appears unavailable (baseline/outage), not a confirmed payload effect."
                    : $"Server returned {response.Status} error. The payload may have caused a server-side exception.",
                Recommendation = outage
                    ? "Confirm the URL loads in a normal browser session, then re-run trace-input."
                    : "Investigate server error — may indicate SQL injection, command injection, or other server-side vulnerability."
            };
        }

        if (injection.Treatment is "filtered" or "constrained" && injection.SourceType == "form"
            && !TraceInputOptions.IsUrlSource(injection.SourceType))
        {
            return new InputTraceResult.TraceVerdict
            {
                Severity = Severity.Low,
                Summary = $"Form control {injection.Treatment} the payload ({injection.ConstraintType ?? "input constraint"}) — " +
                          "this does NOT mean the app is safe. URL query/hash DOM XSS vectors may still be exploitable.",
                Recommendation = "Run trace with source url-hash or url-query and monitorSinks: true. " +
                                 "Enable probeUrlSources (default) to auto-probe after form filtering."
            };
        }

        if (injection.SourceType == "form" && injection.InputAccepted
            && sinks is { HitCount: > 0, PayloadReachedSink: true } && HasPostSubmitDangerousSink(sinks))
        {
            if (XssReflectionAnalyzer.IsSinkPayloadUrlEncodedNeutralized(sinks, dom))
            {
                return new InputTraceResult.TraceVerdict
                {
                    Severity = Severity.Low,
                    Summary = "Dangerous DOM sink fired after form submit but payload only reached the sink in URL-encoded form — " +
                              "browser encoding neutralized active HTML.",
                    Recommendation = "Source→sink path exists via AJAX-mediated submission. Verify whether decodeURI runs before the sink."
                };
            }

            var exec = sinks.ExecutionConfirmed || sinks.DialogEffectConfirmed;
            var severity = exec
                ? (csp?.WouldBlock == true ? Severity.High : Severity.Critical)
                : Severity.High;
            return new InputTraceResult.TraceVerdict
            {
                Severity = severity,
                Summary = exec
                    ? $"Payload reached dangerous sink ({sinks.MostDangerousSink}) after AJAX/form submission without HTTP reflection evidence. " +
                      "Likely stored or client-mediated XSS."
                    : $"Payload reached dangerous sink ({sinks.MostDangerousSink}) after form submit — sink reach only; use confirmExecution for effect proof.",
                Recommendation = "Sanitize user input server-side and avoid passing untrusted data to innerHTML/eval. " +
                                 "Use textContent instead of innerHTML for user-controlled content."
            };
        }

        // Ambient sink activity without payload bytes in the sink — do not escalate.
        if (injection.SourceType == "form" && injection.InputAccepted
            && sinks is { HitCount: > 0, PayloadReachedSink: false } && HasPostSubmitDangerousSink(sinks))
        {
            return new InputTraceResult.TraceVerdict
            {
                Severity = Severity.Info,
                Summary = $"Dangerous DOM sink ({sinks.MostDangerousSink ?? "innerHTML"}) fired after form submission but payloadReachedSink=false — " +
                          "ambient sink activity, not confirmed XSS for this payload.",
                Recommendation = "Ignore CRITICAL unless payload bytes appear in the sink stack. Re-test with monitorSinks after clearing residual page state."
            };
        }

        var domRenderedSafe = dom is { PayloadRendered: true, Dangerous: false };
        return new InputTraceResult.TraceVerdict
        {
            Severity = Severity.Low,
            Summary = domRenderedSafe
                ? "Payload appeared in DOM as inert text only — no reflection, sink reach, or server error for this probe."
                : "Payload was not reflected, not rendered in DOM, and did not cause errors.",
            Recommendation = "Enable autoBypass: true to automatically test alternative XSS vectors, or try different injection contexts manually."
        };
    }

    #endregion

    #region Helpers

    private static TraceInputOptions PrepareTraceOptions(TraceInputOptions options)
    {
        if (TraceInputRedirectHelper.PayloadTargetsOffSiteNavigation(options.Payload))
            return options with { SkipExecCanary = true, ConfirmExecution = false };
        if (options.SkipExecCanary || options.ReachPhaseOnly || !options.ConfirmExecution)
            return options;
        if (!options.MonitorSinks || !string.IsNullOrEmpty(options.ExecCanary))
            return options;
        var payload = TraceInputPayloadPrep.ApplyExecCanary(options.Payload, out var canary);
        return options with { Payload = payload, ExecCanary = string.IsNullOrEmpty(canary) ? null : canary };
    }

    private async Task<string?> BeginNavigationSensorAsync()
    {
        var docScriptId = await RuntimeSensorInstaller.InstallDocumentCreatedAsync(_context);
        if (docScriptId == null)
            await RuntimeSensorInstaller.InstallOnCurrentDocumentAsync(_context);
        return docScriptId;
    }

    private async Task EndNavigationSensorAsync(string? docScriptId) =>
        await RuntimeSensorInstaller.RemoveDocumentCreatedAsync(_context, docScriptId);

    private async Task<long> MarkSinkObservationAsync()
    {
        await ClearSinkLogAsync();
        return _context.ActiveTab.RuntimeEvents.Mark();
    }

    private static bool SinkDataMatchesPayload(string? data, string payload)
    {
        if (string.IsNullOrEmpty(data)) return false;
        if (payload.Length >= 6 && data.Contains(payload, StringComparison.OrdinalIgnoreCase))
            return true;
        foreach (var marker in XssReflectionAnalyzer.BuildDomMarkers(payload))
        {
            if (marker.Length < 4) continue;
            if (data.Contains(marker, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static bool DetectExecProof(IReadOnlyList<RuntimeEvent> events, string? execCanary)
    {
        if (string.IsNullOrEmpty(execCanary)) return false;
        return events.Any(e =>
            e.Kind.Equals("oracle", StringComparison.OrdinalIgnoreCase)
            && e.Name.Equals("exec", StringComparison.OrdinalIgnoreCase)
            && (e.Data?.Contains(execCanary, StringComparison.OrdinalIgnoreCase) == true
                || (e.Extra.TryGetValue("confidence", out var c) && c == "canary")));
    }

    private static bool Phase1ReachSucceeded(InputTraceResult reach) =>
        reach.Sinks is { PayloadReachedSink: true }
        || reach.ServerResponse?.PayloadReflected == true
        || reach.Dom is { Dangerous: true, PayloadRendered: true }
        || XssBypassProbes.IsSinkReachConfirmed(reach);


    /// <summary>
    /// When the server did not reflect the payload and no sink was reached, DOM marker hits are often
    /// ambient/residual page content (prior stored XSS, bundled scripts) — not confirmed injection.
    /// URL sources still allow Dom.Dangerous when the document loaded successfully (true DOM XSS),
    /// but error responses (404/5xx) without sink/reflection are never treated as causal.
    /// </summary>
    private static InputTraceResult.DomTrace ReconcileDomWithServer(
        InputTraceResult.DomTrace dom,
        InputTraceResult.ServerResponseTrace? server,
        InputTraceResult.SinkTrace? sinks,
        string sourceType)
    {
        if (!dom.Dangerous) return dom;
        if (sinks?.PayloadReachedSink == true) return dom;
        if (server?.PayloadReflected == true) return dom;

        var urlSource = TraceInputOptions.IsUrlSource(sourceType);
        if (urlSource && server is { Status: > 0 and < 400 })
            return dom;

        var reason = urlSource && server is { Status: >= 400 }
            ? $"DOM matched payload-like markers after HTTP {server.Status} with no reflection and no sink hit — " +
              "likely residual/ambient content, not same-probe XSS."
            : "DOM matched payload-like markers but server did not reflect the payload — " +
              "likely ambient page content (e.g. bundled scripts), not confirmed injection.";

        return new InputTraceResult.DomTrace
        {
            PayloadRendered = dom.PayloadRendered,
            RenderedCount = dom.RenderedCount,
            Context = dom.Context,
            Dangerous = false,
            Reason = reason
        };
    }

    private static string? ExtractParamName(string body, string payload)
    {
        var idx = body.IndexOf(payload, StringComparison.OrdinalIgnoreCase);
        if (idx <= 0) return null;

        // Look backwards for param= pattern
        var before = body[..idx];
        var eqIdx = before.LastIndexOf('=');
        if (eqIdx < 0) return null;

        var ampIdx = before.LastIndexOf('&', eqIdx);
        var start = ampIdx >= 0 ? ampIdx + 1 : 0;
        return before[start..eqIdx];
    }

    private async Task<InputTraceResult.SinkTrace> CollectSinkData(string payload, long runtimeMark = 0, string? execCanary = null)
    {
        var instrumented = RuntimeSensorScript.InstrumentedSinks.ToList();
        var sinksSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var sourcesSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var hits = new List<InputTraceResult.SinkHit>();
        var seenKeys = new HashSet<string>(StringComparer.Ordinal);

        var runtimeSlice = _context.ActiveTab.RuntimeEvents.SliceSinceMark(runtimeMark);
        var execConfirmed = DetectExecProof(runtimeSlice, execCanary);
        if (!execConfirmed)
            execConfirmed = await ExecProofPoller.PollAsync(_context, payload, execCanary);
        var dialogConfirmed = DetectDialogEffect(payload);

        void AddHit(string sink, string? data, string? stack, bool containsPayload)
        {
            if (RuntimeInstrumentationFilter.IsSanitizerSink(sink))
            {
                if (!string.IsNullOrEmpty(sink)) sinksSeen.Add(sink);
                hits.Add(new InputTraceResult.SinkHit
                {
                    Sink = sink,
                    ContainsPayload = false,
                    Snippet = data?.Length > 200 ? data[..200] : data,
                    Stack = stack,
                    Classification = "sanitizer-context"
                });
                return;
            }

            if (RuntimeInstrumentationFilter.IsToolArtifactSink(sink, stack, data))
                return;
            var stackTop = stack?.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault() ?? "";
            var key = sink + "|" + (data ?? "")[..Math.Min(data?.Length ?? 0, 80)] + "|" + stackTop;
            if (!seenKeys.Add(key)) return;
            if (!string.IsNullOrEmpty(sink)) sinksSeen.Add(sink);
            hits.Add(new InputTraceResult.SinkHit
            {
                Sink = sink,
                ContainsPayload = containsPayload,
                Snippet = data?.Length > 200 ? data[..200] : data,
                Stack = stack
            });
        }

        foreach (var evt in runtimeSlice)
        {
            if (evt.Kind.Equals("source", StringComparison.OrdinalIgnoreCase))
            {
                sourcesSeen.Add(evt.Name);
                continue;
            }
            if (!evt.Kind.Equals("sink", StringComparison.OrdinalIgnoreCase))
                continue;

            var contains = SinkDataMatchesPayload(evt.Data, payload);
            if (!contains && !string.IsNullOrEmpty(execCanary) && evt.Data?.Contains(execCanary, StringComparison.OrdinalIgnoreCase) == true)
                contains = true;
            AddHit(evt.Name, evt.Data, SinkStackAnalyzer.GetPageStack(evt.Stack), contains);
        }

        try
        {
            var markersJson = JsonSerializer.Serialize(XssReflectionAnalyzer.BuildDomMarkers(payload));
            var payloadJson = JsonSerializer.Serialize(payload);
            var json = await _context.ExecuteJs(
                $@"(function(){{
                    var log = window.__trowser_sink_log || [];
                    var markers = {markersJson};
                    var payload = {payloadJson};
                    function matchesPayload(text) {{
                        if (!text) return false;
                        if (payload.length >= 6 && text.indexOf(payload) >= 0) return true;
                        if (payload.indexOf('<') >= 0 && text.indexOf('<') < 0
                            && (text.indexOf('&lt;') >= 0 || text.indexOf('&#') >= 0))
                            return false;
                        if (markers.length === 0) return false;
                        for (var i = 0; i < markers.length; i++) {{
                            var m = markers[i];
                            if (text.indexOf(m) < 0) continue;
                            if ((m.indexOf('<') >= 0 || m.indexOf('>') >= 0) && text.indexOf('<') < 0)
                                continue;
                            return true;
                        }}
                        return false;
                    }}
                    var polled = [];
                    for (var i = 0; i < log.length; i++) {{
                        var entry = log[i];
                        polled.push({{ sink: entry.sink, containsPayload: matchesPayload(entry.data),
                                     snippet: entry.data ? entry.data.substring(0, 200) : null,
                                     stack: entry.stack || null }});
                    }}
                    if (window.__trowser_sink_log) window.__trowser_sink_log.length = 0;
                    return JSON.stringify({{ polled: polled }});
                }})()");

            var parsed = JsonSerializer.Deserialize<JsonElement>(json);
            if (parsed.TryGetProperty("polled", out var polledArr) && polledArr.ValueKind == JsonValueKind.Array)
            {
                foreach (var h in polledArr.EnumerateArray())
                {
                    var sinkName = h.TryGetProperty("sink", out var s) ? s.GetString() ?? "" : "";
                    var snippet = h.TryGetProperty("snippet", out var sn) && sn.ValueKind == JsonValueKind.String ? sn.GetString() : null;
                    var stack = h.TryGetProperty("pageStack", out var ps) && ps.ValueKind == JsonValueKind.String
                        ? ps.GetString()
                        : h.TryGetProperty("stack", out var st) && st.ValueKind == JsonValueKind.String ? st.GetString() : null;
                    var contains = h.TryGetProperty("containsPayload", out var cp) && cp.GetBoolean();
                    AddHit(sinkName, snippet ?? "", stack, contains);
                }
            }
        }
        catch
        {
            /* polled log optional */
        }

        var hitCount = hits.Count;
        var payloadReachedSink = hits.Any(h => h.ContainsPayload);
        string? mostDangerousSink = null;
        var pageUrl = await _context.GetCurrentUrl();
        ReconcileSinkHits(payload, pageUrl, hits, ref payloadReachedSink, ref mostDangerousSink);
        ClassifyClientSideInjection(hits, payload, payloadReachedSink);

        if (execConfirmed || dialogConfirmed)
            payloadReachedSink = true;

        string? zeroReason = null;
        if (hitCount == 0)
            zeroReason = execConfirmed || dialogConfirmed ? null : "no-sink-calls";
        else if (!payloadReachedSink)
            zeroReason = "sinks-fired-payload-not-matched";

        return new InputTraceResult.SinkTrace
        {
            Monitored = true,
            HitCount = hitCount,
            Hits = hits,
            PayloadReachedSink = payloadReachedSink,
            MostDangerousSink = mostDangerousSink,
            Instrumented = instrumented,
            SinksSeen = sinksSeen.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
            SourcesSeen = sourcesSeen.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
            ZeroResultReason = zeroReason,
            ExecutionConfirmed = execConfirmed,
            DialogEffectConfirmed = dialogConfirmed
        };
    }

    private bool DetectDialogEffect(string payload)
    {
        if (string.IsNullOrEmpty(payload)) return false;
        if (!payload.Contains("alert(", StringComparison.OrdinalIgnoreCase)
            && !payload.Contains("confirm(", StringComparison.OrdinalIgnoreCase))
            return false;

        var dlg = _context.ActiveTab.LastDialog;
        if (dlg == null || string.IsNullOrEmpty(dlg.Type)) return false;
        return dlg.Type.Equals("alert", StringComparison.OrdinalIgnoreCase)
               || dlg.Type.Equals("confirm", StringComparison.OrdinalIgnoreCase);
    }

    private static InputTraceResult.DomTrace? ReconcileDomFromSinkHits(
        InputTraceResult.DomTrace? dom,
        InputTraceResult.SinkTrace? sinks,
        string payload)
    {
        if (sinks == null || dom == null) return dom;
        foreach (var h in sinks.Hits.Where(h => h.ContainsPayload && !string.IsNullOrEmpty(h.Snippet)))
        {
            if (!XssReflectionAnalyzer.PayloadIntroducesEventHandler(h.Snippet!)
                && !XssReflectionAnalyzer.PayloadIntroducesEventHandler(payload))
                continue;
            if (XssReflectionAnalyzer.SinkHitsLackExecutablePayloadContext(payload, sinks))
                continue;
            if (dom.Dangerous) return dom;
            return new InputTraceResult.DomTrace
            {
                PayloadRendered = true,
                RenderedCount = Math.Max(1, dom.RenderedCount),
                Context = "sink-snippet",
                Dangerous = true,
                Reason = "Sink hook snippet contains executable event-handler markup for this payload."
            };
        }

        return dom;
    }

    /// <summary>
    /// Annotate hits that prove DOM open redirect or client-side request forgery (canary taint).
    /// </summary>
    private static void ClassifyClientSideInjection(
        List<InputTraceResult.SinkHit> hits,
        string payload,
        bool payloadReached)
    {
        if (!payloadReached) return;
        foreach (var h in hits.Where(h => h.ContainsPayload))
        {
            if (h.Snippet != null
                && !XssReflectionAnalyzer.SinkOrDomTextContainsExecutablePayload(payload, h.Snippet))
            {
                h.ContainsPayload = false;
                h.Classification = null;
                continue;
            }

            if (XssReflectionAnalyzer.IsBenignHttpApiQuerySink(h.Sink, h.Snippet, payload))
            {
                h.Classification = "intended-search-request";
                continue;
            }

            if (h.Sink is "location.assign" or "location.replace" or "location.href" or "window.open")
                h.Classification = "dom-open-redirect";
            else if (h.Sink is "fetch" or "xhr.open")
                h.Classification = "client-request-forgery";
        }
    }

    private static void ReconcileSinkHits(
        string payload,
        string? pageUrl,
        List<InputTraceResult.SinkHit> hits,
        ref bool payloadReachedSink,
        ref string? mostDangerousSink)
    {
        foreach (var h in hits)
        {
            if (!h.ContainsPayload || string.IsNullOrEmpty(h.Snippet))
                continue;
            if (XssReflectionAnalyzer.SnippetIsDocumentUrlEcho(payload, pageUrl ?? "", h.Snippet)
                || XssReflectionAnalyzer.SinkHitIsInertSelfReferentialPageUrl(h.Sink, h.Snippet, pageUrl, payload))
            {
                h.ContainsPayload = false;
                continue;
            }
            if (XssReflectionAnalyzer.IsPayloadOnlyInJsStringLiteral(h.Sink, h.Snippet, payload))
                h.ContainsPayload = false;
            else if (XssReflectionAnalyzer.IsBenignAbsoluteUrlAttributeWrite(h.Sink, h.Snippet, payload))
                h.ContainsPayload = false;
            else if (!TraceInputReachCanary.IsReachCanary(payload)
                     && XssReflectionAnalyzer.IsPayloadTrappedInNonExecutableHtmlSink(payload, h.Sink, h.Snippet))
                h.ContainsPayload = false;
            else if (!XssReflectionAnalyzer.SinkOrDomTextContainsExecutablePayload(payload, h.Snippet))
                h.ContainsPayload = false;
            else if (XssReflectionAnalyzer.IsBenignHttpApiQuerySink(h.Sink, h.Snippet, payload))
                h.ContainsPayload = false;
        }

        payloadReachedSink = hits.Any(h => h.ContainsPayload);
        if (!payloadReachedSink)
        {
            mostDangerousSink = null;
            return;
        }

        var dangerRank = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["eval"] = 6, ["Function"] = 5, ["document.write"] = 4, ["document.writeln"] = 4,
            ["innerHTML"] = 3, ["outerHTML"] = 3, ["insertAdjacentHTML"] = 3,
            ["setAttribute"] = 3, ["iframe.srcdoc"] = 3, ["script.src"] = 3,
            ["location.assign"] = 4, ["location.replace"] = 4, ["location.href"] = 4, ["window.open"] = 4,
        };
        var best = -1;
        foreach (var h in hits.Where(h => h.ContainsPayload))
        {
            var rank = dangerRank.GetValueOrDefault(h.Sink, 0);
            if (rank > best)
            {
                best = rank;
                mostDangerousSink = h.Sink;
            }
        }
    }

    private static string BuildDangerousSinkSummary(
        InputTraceResult.SinkTrace sinks,
        string payload,
        bool noCspBlock)
    {
        var sinkName = sinks.MostDangerousSink ?? "unknown";
        var hit = sinks.Hits.FirstOrDefault(h =>
            h.ContainsPayload && !string.IsNullOrEmpty(h.Snippet)
            && XssReflectionAnalyzer.SinkOrDomTextContainsExecutablePayload(payload, h.Snippet!));
        if (hit?.Snippet != null)
        {
            var snip = hit.Snippet.Length > 120 ? hit.Snippet[..120] + "…" : hit.Snippet;
            return noCspBlock
                ? $"Payload reached dangerous sink ({sinkName}) — sink argument contains executable payload bytes: {snip}"
                : $"Payload reached dangerous sink ({sinkName}) (CSP may block execution): {snip}";
        }

        return noCspBlock
            ? $"Payload reached dangerous sink ({sinkName}) without CSP blocking."
            : $"Payload reached dangerous sink ({sinkName}) but CSP may block execution.";
    }

    private static bool HasPostSubmitDangerousSink(InputTraceResult.SinkTrace sinks)
    {
        var dangerous = new HashSet<string>(StringComparer.Ordinal)
        {
            "innerHTML", "outerHTML", "insertAdjacentHTML",
            "eval", "Function", "document.write", "document.writeln",
            "setTimeout(string)", "setInterval(string)",
            "setAttribute", "iframe.srcdoc", "script.src",
            "location.assign", "location.replace", "location.href", "window.open",
            "createContextualFragment", "jquery.html", "jquery.append"
        };

        return sinks.Hits.Any(h => dangerous.Contains(h.Sink));
    }

    private async Task WaitForTraceIdleAsync(int timeoutMs, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var idleTimeout = Math.Clamp(timeoutMs, 2000, 15_000);
        try { await _context.WaitForIdle(300, idleTimeout); }
        catch (OperationCanceledException) { throw; }
        catch { await Task.Delay(Math.Min(timeoutMs / 3, 2000), ct); }
        ct.ThrowIfCancellationRequested();
    }

    private async Task ClearSinkLogAsync()
    {
        try
        {
            await _context.ExecuteJs(
                "if (window.__trowser_sink_log) window.__trowser_sink_log.length = 0;");
        }
        catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }
    }

    private async Task<InputTraceResult> TraceAllQueryParamsAsync(TraceInputOptions options, CancellationToken ct = default)
    {
        var discovery = await DomRuntimeInjectionDiscovery.DiscoverAsync(_context);
        var canary = "trwR_" + Guid.NewGuid().ToString("N")[..10];
        InputTraceResult? bestReach = null;
        string? bestParam = null;
        var allReach = new List<InputTraceResult.ReachMapEntry>();

        foreach (var param in discovery.QueryParams.Take(12))
        {
            ct.ThrowIfCancellationRequested();
            var reachOpts = PrepareTraceOptions(options with
            {
                QueryParam = param,
                Payload = canary,
                SkipExecCanary = true,
                TwoPhase = false,
                ProbeAllUrlParams = false
            });
            var trace = await TraceCoreAsync(reachOpts, ct);
            allReach.AddRange(BuildReachMap(trace, canary));
            var score = trace.Sinks?.HitCount ?? 0;
            if (bestReach == null || score > (bestReach.Sinks?.HitCount ?? 0))
            {
                bestReach = trace;
                bestParam = param;
            }
        }

        if (bestParam == null)
            bestParam = options.QueryParam ?? "q";

        var confirmExecution = TraceInputConfirmExecutionPolicy.EffectiveConfirmExecution(options, bestReach);
        if (!confirmExecution && bestReach != null)
        {
            var reachOnlyMap = allReach.Count > 0 ? allReach : BuildReachMap(bestReach, canary);
            return CopyTrace(bestReach, reachOnlyMap,
                AppendInjectionNotes(bestReach.Injection,
                    $"probeAllUrlParams tested {discovery.QueryParams.Count} query key(s); best reach on '{bestParam}'. " +
                    "No confirmable sink reach — execution oracle skipped."));
        }

        var confirmPayload = bestReach != null
            ? TraceInputConfirmationPayload.Pick(bestReach, canary, options)
            : options.Payload;
        ct.ThrowIfCancellationRequested();
        var confirm = await TraceCoreAsync(PrepareTraceOptions(options with
        {
            QueryParam = bestParam,
            Payload = confirmPayload,
            TwoPhase = false,
            SkipExecCanary = !confirmExecution,
            ConfirmExecution = confirmExecution,
            ProbeAllUrlParams = false
        }), ct);

        var reachMap = allReach.Count > 0 ? allReach : BuildReachMap(bestReach ?? confirm, canary);
        var notes = AppendInjectionNotes(confirm.Injection,
            $"probeAllUrlParams tested {discovery.QueryParams.Count} query key(s); best reach on '{bestParam}'.");
        return CopyTrace(confirm, reachMap, notes);
    }

    private static InputTraceResult MergeReachAndConfirm(
        InputTraceResult reach,
        InputTraceResult confirm,
        string reachCanary,
        string? templatePayload = null,
        InputTraceResult? redirectTrace = null)
    {
        var map = BuildReachMap(reach, reachCanary);
        var best = PickBestExploitTrace(new[] { confirm, redirectTrace }.Where(t => t != null).Cast<InputTraceResult>()) ?? confirm;
        var attempts = new List<InputTraceBypassAttempt>();
        if (!string.Equals(confirm.Payload, reach.Payload, StringComparison.OrdinalIgnoreCase))
        {
            attempts.Add(new InputTraceBypassAttempt
            {
                Vector = "phase-2-confirmation",
                Payload = confirm.Payload,
                Trace = confirm,
                ConfirmedXss = XssBypassProbes.IsConfirmedXss(confirm)
            });
        }

        if (redirectTrace != null
            && !string.Equals(redirectTrace.Payload, confirm.Payload, StringComparison.OrdinalIgnoreCase))
        {
            attempts.Add(new InputTraceBypassAttempt
            {
                Vector = "caller-payload",
                Payload = redirectTrace.Payload,
                Trace = redirectTrace,
                ConfirmedXss = XssBypassProbes.IsConfirmedXss(redirectTrace)
            });
        }

        return CopyTrace(best, map.Count > 0 ? map : null, verdict: best.Verdict, confirmationAttempts: attempts);
    }

    private static InputTraceResult.InjectionTrace AppendInjectionNotes(
        InputTraceResult.InjectionTrace injection,
        string extra)
    {
        var sep = string.IsNullOrEmpty(injection.Notes) ? "" : " ";
        return new InputTraceResult.InjectionTrace
        {
            SourceType = injection.SourceType,
            InputAccepted = injection.InputAccepted,
            DomValueBeforeSubmit = injection.DomValueBeforeSubmit,
            Treatment = injection.Treatment,
            ConstraintType = injection.ConstraintType,
            Encoding = injection.Encoding,
            FormInteractionFailed = injection.FormInteractionFailed,
            FormInteractionFailureReason = injection.FormInteractionFailureReason,
            TargetElementsMatched = injection.TargetElementsMatched,
            NavigatedUrl = injection.NavigatedUrl,
            Notes = (injection.Notes ?? "") + sep + extra
        };
    }

    private static InputTraceResult CopyTrace(
        InputTraceResult t,
        List<InputTraceResult.ReachMapEntry>? reachMap = null,
        InputTraceResult.InjectionTrace? injection = null,
        InputTraceResult.TraceVerdict? verdict = null,
        List<InputTraceBypassAttempt>? confirmationAttempts = null) =>
        new()
        {
            Payload = t.Payload,
            DocumentUrl = t.DocumentUrl,
            ElapsedMs = t.ElapsedMs,
            Injection = injection ?? t.Injection,
            Network = t.Network,
            ServerResponse = t.ServerResponse,
            Dom = t.Dom,
            Csp = t.Csp,
            Sinks = t.Sinks,
            SqliIndicators = t.SqliIndicators,
            ReachMap = reachMap ?? t.ReachMap,
            ConfirmationAttempts = confirmationAttempts ?? t.ConfirmationAttempts,
            Verdict = verdict ?? t.Verdict
        };

    private static List<InputTraceResult.ReachMapEntry> BuildReachMap(InputTraceResult trace, string reachCanary)
    {
        if (trace.Sinks == null) return [];
        return trace.Sinks.Hits
            .Where(h => !RuntimeInstrumentationFilter.IsSanitizerSink(h.Sink))
            .Select(h =>
            {
                var benign = XssReflectionAnalyzer.IsNavActiveLinkEcho(h.Snippet, trace.DocumentUrl, reachCanary)
                    ? "nav-active-link"
                    : null;
                return new InputTraceResult.ReachMapEntry
                {
                    Sink = h.Sink,
                    ContainsReachCanary = benign == null
                        && (h.ContainsPayload || (h.Snippet?.Contains(reachCanary, StringComparison.OrdinalIgnoreCase) == true)),
                    Snippet = h.Snippet,
                    PageStack = h.Stack,
                    Consequence = h.Classification,
                    KnownBenign = benign
                };
            })
            .ToList();
    }

    private static bool UrlTraceNeedsJsBypass(InputTraceResult primary) =>
        primary.Sinks?.SinksSeen.Any(s => s is "eval" or "Function" or "setTimeout(string)" or "Function.constructor") == true
        || primary.Injection.SourceType.StartsWith("url-", StringComparison.OrdinalIgnoreCase);

    private static bool TargetAppearsUnavailable(List<NetworkEntry> entries) =>
        entries.Count(e => e.StatusCode is >= 500 and < 600) >= 2
        || entries.Any(e => e.StatusCode is 503 or 502);

    private async Task<List<string>> GetPostMessageHandlerSourcesAsync()
    {
        var sources = new List<string>();
        try
        {
            var cdp = await RuntimeCdpMessageListeners.TryEnumerateWindowAsync(_context);
            sources.AddRange(cdp.Select(c => c.HandlerSource).Where(s => !string.IsNullOrWhiteSpace(s))!);
        }
        catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }

        sources.AddRange(_context.ActiveTab.RuntimeEvents.OfKind("listener")
            .Where(e => e.Name.Equals("message", StringComparison.OrdinalIgnoreCase))
            .Select(e => e.Data)
            .Where(s => !string.IsNullOrWhiteSpace(s))!);

        return sources
            .Where(s => !RuntimeInstrumentationFilter.IsHostOrSensorListener(null, s))
            .Distinct(StringComparer.Ordinal)
            .ToList();
    }

    private async Task DispatchPostMessageAsync(string payload)
    {
        var origin = "https://evil.trowser.test";
        await _context.ExecuteJs(
            $@"(function(){{
                var origin = {JsonEscape(origin)};
                var raw = {JsonEscape(payload)};
                try {{
                    var parsed = JSON.parse(raw);
                    if (parsed !== null && typeof parsed === 'object')
                        window.dispatchEvent(new MessageEvent('message', {{ data: parsed, origin: origin, source: window }}));
                    else
                        window.dispatchEvent(new MessageEvent('message', {{ data: raw, origin: origin, source: window }}));
                }} catch(e) {{
                    window.dispatchEvent(new MessageEvent('message', {{ data: raw, origin: origin, source: window }}));
                }}
                return 'ok';
            }})()");
    }

    private async Task TryFireClickGatedSinksAsync()
    {
        try
        {
            await _context.ExecuteJs("""
                (function(){
                    var a = document.querySelector('a[href]');
                    if (a) { try { a.click(); return 'clicked'; } catch(e) {} }
                    return 'none';
                })()
                """);
            await Task.Delay(300);
        }
        catch (Exception swallowed) { TrowserLog.Swallowed(swallowed); }
    }

    private static string JsonEscape(string s) =>
        JsonSerializer.Serialize(s);

    private static bool IsBrowserErrorPage(string? url) =>
        !string.IsNullOrEmpty(url)
        && (url.StartsWith("chrome-error://", StringComparison.OrdinalIgnoreCase)
            || url.StartsWith("edge-error://", StringComparison.OrdinalIgnoreCase)
            || url.Contains("chromewebdata", StringComparison.OrdinalIgnoreCase));

    private static bool PageNavigatedToPayload(string? documentUrl, string payload)
    {
        if (string.IsNullOrWhiteSpace(documentUrl) || string.IsNullOrWhiteSpace(payload))
            return false;
        if (!Uri.TryCreate(payload, UriKind.Absolute, out _))
            return false;
        return string.Equals(documentUrl.TrimEnd('/'), payload.TrimEnd('/'), StringComparison.OrdinalIgnoreCase)
               || documentUrl.StartsWith(payload, StringComparison.OrdinalIgnoreCase);
    }

    private InputTraceResult MakeErrorResult(string payload, Stopwatch sw, string error, string sourceType = "form")
    {
        sw.Stop();
        return new InputTraceResult
        {
            Payload = payload,
            ElapsedMs = sw.ElapsedMilliseconds,
            Injection = new InputTraceResult.InjectionTrace
            {
                SourceType = sourceType,
                InputAccepted = false,
                Treatment = "filtered",
                Notes = error
            },
            Verdict = new InputTraceResult.TraceVerdict
            {
                Severity = Severity.Low,
                Summary = error,
                Recommendation = "Verify the target element exists and is interactable, or check URL injection parameters."
            }
        };
    }

    #endregion
}
