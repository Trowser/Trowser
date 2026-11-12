namespace Trowser.Security;

/// <summary>
/// Phase-2 confirmation payloads derived from reach-canary context in sink snippets (DOM Invader-style breakout).
/// </summary>
internal static class TraceInputConfirmationPayload
{
    private static string ImgOnerrorOracle() => TraceInputPayloadPrep.DefaultImgOnerrorOracle();

    public static string Pick(InputTraceResult reach, string? reachCanary, TraceInputOptions template)
    {
        var hit = SelectBestReachHit(reach, reachCanary);
        if (hit?.Snippet != null
            && !string.IsNullOrEmpty(reachCanary)
            && hit.Snippet.Contains(reachCanary, StringComparison.OrdinalIgnoreCase))
        {
            var contextual = FromCanaryContext(hit.Sink, hit.Snippet, reachCanary);
            if (!string.IsNullOrEmpty(contextual))
                return TraceInputPayloadPrep.ApplyExecCanary(contextual, out _);
        }

        if (ShouldConfirmWithEventHandler(reach, template))
            return TraceInputPayloadPrep.ApplyExecCanary(ImgOnerrorOracle(), out _);

        return TraceInputPayloadPrep.ApplyExecCanary(PickBySinkName(reach, template), out _);
    }

    private static bool ShouldConfirmWithEventHandler(InputTraceResult reach, TraceInputOptions template)
    {
        if (reach.Dom is { Dangerous: true, Context: not null }
            && reach.Dom.Context.Contains("innerHTML", StringComparison.OrdinalIgnoreCase))
            return TemplateUsesInertScriptTag(template.Payload);

        var sinks = reach.Sinks?.Hits
            .Where(h => !RuntimeInstrumentationFilter.IsSanitizerSink(h.Sink))
            .Select(h => h.Sink) ?? [];
        if (sinks.Any(s => s.Contains("innerHTML", StringComparison.OrdinalIgnoreCase)
                            || s is "document.write" or "document.writeln" or "insertAdjacentHTML"))
            return TemplateUsesInertScriptTag(template.Payload);

        return false;
    }

    private static bool TemplateUsesInertScriptTag(string? payload) =>
        !string.IsNullOrWhiteSpace(payload)
        && payload.Contains("<script", StringComparison.OrdinalIgnoreCase);

    internal static string? FromCanaryContext(string sink, string snippet, string reachCanary)
    {
        var idx = snippet.IndexOf(reachCanary, StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
            return null;

        var before = snippet[..idx];
        var tagBefore = InferOpenTagBeforeIndex(snippet, idx);

        if (sink is "eval" or "Function" or "setTimeout(string)" or "setInterval(string)" or "Function.constructor")
            return $"{TraceInputPayloadPrep.ProofGlobal}=1";

        if (sink is "script.src" or "iframe.src" or "embed.src")
            return "https://example.test/trowser-probe.js";

        if (sink is "fetch" or "xhr.open")
            return "https://example.test/trowser-probe";

        if (IsInsideQuotedAttribute(before, '"')
            || before.Contains("searchTerms=", StringComparison.OrdinalIgnoreCase)
            || before.Contains("=\"", StringComparison.Ordinal))
            return AttributeBreakoutPayload(tagBefore, '"');

        if (IsInsideQuotedAttribute(before, '\''))
            return AttributeBreakoutPayload(tagBefore, '\'');

        if (sink.Contains("innerHTML", StringComparison.OrdinalIgnoreCase)
            || sink is "document.write" or "document.writeln" or "insertAdjacentHTML"
            or "createContextualFragment" or "setHTMLUnsafe" or "shadowRoot.innerHTML")
            return ImgOnerrorOracle();

        return null;
    }

    private static string AttributeBreakoutPayload(string? tagName, char quote)
    {
        var q = quote == '"' ? "\"" : "'";
        if (tagName is "a" or "area" or "link")
            return $"test{q} onfocus={q}{TraceInputPayloadPrep.ProofGlobal}=1{q} autofocus={q}{q}";
        if (tagName is "img" or "script" or "video" or "audio" or "source")
            return $"test{q} onerror={q}{TraceInputPayloadPrep.ProofGlobal}=1{q}";
        if (tagName is "svg" or "body" or "iframe")
            return $"test{q} onload={q}{TraceInputPayloadPrep.ProofGlobal}=1{q}";
        return $">{ImgOnerrorOracle()}";
    }

    private static string? InferOpenTagBeforeIndex(string snippet, int idx)
    {
        var before = snippet[..idx];
        var lastOpen = before.LastIndexOf('<');
        if (lastOpen < 0) return null;
        var frag = before[lastOpen..].TrimStart('<');
        var space = frag.IndexOfAny([' ', '>', '\t', '\r', '\n']);
        return space < 0 ? frag.ToLowerInvariant() : frag[..space].ToLowerInvariant();
    }

    private static InputTraceResult.SinkHit? SelectBestReachHit(InputTraceResult reach, string? reachCanary)
    {
        if (reach.Sinks == null)
            return null;

        var hits = reach.Sinks.Hits
            .Where(h => !RuntimeInstrumentationFilter.IsSanitizerSink(h.Sink))
            .ToList();
        if (hits.Count == 0)
            return null;

        return hits.FirstOrDefault(h =>
                   h.ContainsPayload
                   || (!string.IsNullOrEmpty(reachCanary)
                       && h.Snippet?.Contains(reachCanary, StringComparison.OrdinalIgnoreCase) == true))
               ?? hits[0];
    }

    private static bool IsInsideQuotedAttribute(string before, char quote)
    {
        var lastQuote = before.LastIndexOf(quote);
        if (lastQuote < 0)
            return false;
        var eq = before.LastIndexOf('=');
        return eq >= 0 && eq < lastQuote;
    }

    private static string PickBySinkName(InputTraceResult reach, TraceInputOptions template)
    {
        var sinks = reach.Sinks?.Hits
            .Where(h => h.ContainsPayload)
            .Select(h => h.Sink)
            .ToHashSet(StringComparer.OrdinalIgnoreCase) ?? [];

        if (sinks.Any(s => s is "eval" or "Function" or "setTimeout(string)" or "Function.constructor"))
            return $"{TraceInputPayloadPrep.ProofGlobal}=1";
        if (sinks.Any(s => s is "script.src" or "iframe.src" or "embed.src"))
            return "https://example.test/trowser-probe.js";
        if (sinks.Any(s => s is "fetch" or "xhr.open"))
            return "https://example.test/trowser-probe";
        if (sinks.Any(TraceInputConfirmExecutionPolicy.IsNavigationSink))
        {
            var probe = TraceInputRedirectBypassProbes.GetProbes(1, "/").FirstOrDefault();
            if (probe != null)
                return probe.Payload;
        }
        if (sinks.Any(s => s.Contains("innerHTML", StringComparison.OrdinalIgnoreCase)
                            || s.Contains("document.write", StringComparison.OrdinalIgnoreCase)))
            return ImgOnerrorOracle();

        if (ShouldConfirmWithEventHandler(reach, template))
            return ImgOnerrorOracle();

        if (!string.IsNullOrWhiteSpace(template.Payload))
            return template.Payload;
        return XssBypassProbes.DefaultPrimaryPayload;
    }
}
