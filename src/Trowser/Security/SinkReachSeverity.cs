namespace Trowser.Security;

/// <summary>
/// Severity when attacker data reaches a sink without execution oracle proof.
/// </summary>
public static class SinkReachSeverity
{
    public static Severity ForSink(string sink, string? snippet, bool executionConfirmed, string? payload = null)
    {
        if (executionConfirmed) return Severity.Critical;

        if (!string.IsNullOrEmpty(payload)
            && (TraceInputReachCanary.IsReachCanary(payload)
                || XssReflectionAnalyzer.IsPayloadTrappedInNonExecutableHtmlSink(payload, sink, snippet)
                || XssReflectionAnalyzer.IsBenignAbsoluteUrlAttributeWrite(sink, snippet, payload)))
            return Severity.Medium;

        var s = sink ?? "";
        if (s is "eval" or "Function" or "Function.constructor" or "setTimeout(string)" or "setInterval(string)"
            or "document.write" or "document.writeln")
            return Severity.Critical;

        if (s is "innerHTML" or "outerHTML" or "insertAdjacentHTML"
            or "createContextualFragment" or "setHTMLUnsafe" or "Document.parseHTMLUnsafe" or "shadowRoot.innerHTML"
            or "iframe.srcdoc" or "script.text")
            return Severity.High;

        if (s is "script.src" or "iframe.src" or "embed.src")
            return Severity.Critical;

        if (s is "location.assign" or "location.replace" or "location.href" or "window.open"
            or "a.href" or "area.href" or "form.action" or "button.formAction" or "input.formAction")
        {
            if (snippet != null && snippet.Contains("javascript:", StringComparison.OrdinalIgnoreCase))
                return Severity.High;
            return Severity.High;
        }

        if (s is "fetch" or "xhr.open")
            return Severity.High;

        if (s is "setAttribute" or "setAttributeNS" or "Attr.value")
        {
            if (snippet != null && (snippet.Contains("javascript:", StringComparison.OrdinalIgnoreCase)
                                    || snippet.Contains("onerror", StringComparison.OrdinalIgnoreCase)))
                return Severity.High;
            return Severity.Medium;
        }

        return Severity.Medium;
    }
}
